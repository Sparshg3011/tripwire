"""Whether the values a call hands out were vouched for.

A flow with `unless: anchored` skips a call only when check() discharges
it, and it discharges only a tool with an argument contract (`args`)
whose every authority leaf is anchored: its normalized key comes from a
source its role accepts.

  target      task, known, trusted
  selector    task, known, trusted, self; on a destructive tool task,
              known, trusted
  credential  task, known

  task     a task segment's index anchors the key (values.TaskIndex; a
           short id only after a label, the argument's own name words
           among them), or, with match: under, a task path of 2+
           components is strictly above it
  known    the policy's `known` entry of its type holds it: as a value,
           as a domain, or with match: under as a path strictly above it
  trusted  its first trusted field counts (provenance's counting rule)
  self     it is the id this session's own create-like call minted

Leaves are every scalar under an authority argument, lists and dicts
expanded, dict keys in sorted order; null and "" are absent. Each reads
through values.normalize_all() under the argument's type, which splits
an address list so that every address must anchor. An Invalid or
Unanchorable leaf is unanchored, and an Invalid target blocks at any
taint level (invalid_target(), which stage 2 runs).

No content leaf, a dict key included, may name a control file or a
protected path either (values.forbidden_path()): a tool may take a file
name as content, and a self_scoped one would otherwise write anywhere.

A tool with a target argument is outward, and its content leaves are
checked too:

  shape     a leaf whose whole value is an email address, an IBAN or an
            http(s) URL is checked as a target
  links     every link in a leaf needs an anchored host: task (a host
            the task names only as a file name too), known or trusted.
            A link is a URL of any scheme, one with no scheme ("//host"),
            or a bare www. host or host with a pinned TLD; one that
            doesn't read as an http(s) URL fails.
  verbatim  a URL with a path, query or fragment past "/", a target's or
            a link's, must occur as written in the task or in what a
            tool, the listing or an upstream error wrote before the agent
            wrote it, so it can't carry what the session gathered. It is
            read as it is sent; a link in prose may lose one closing
            bracket and one mark of punctuation that end a sentence.
            Links are read from the content as written and again after
            C2 and C1, and both readings must pass.

The first failure decides the code, authority arguments first, in
contract order, then content:

  unanchored_argument       an authority leaf isn't anchored, or a
                            content leaf names a forbidden path
  invalid_value            a target leaf can't be read
  url_not_verbatim          a URL carries a suffix no one wrote
  link_unanchored           content links to an unvouched host
  destructive_needs_anchor  a destructive call with no authority leaf
  vacuous_write             a call with no authority leaf, on a tool
                            that isn't self_scoped
  no_contract               the tool has no `args`

Contract: pure and deterministic, like the evaluator that calls it. A
report names the agent's own values and the hashes of keys, never task
text or anything a tool returned.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import pairwise

from tripwire.policy.canonical import _clean
from tripwire.policy.schema import ArgSpec, KnownValue, Policy, Role, ToolRule, read_known
from tripwire.policy.types import (
    AnchorReport,
    FirstSeen,
    LeafReport,
    LeafStatus,
    SessionSnapshot,
    TaskView,
    ToolCall,
    Via,
    key_sha256,
)
from tripwire.policy.values import (
    MAX_FIELD_DEPTH,
    TLDS,
    TRAILING,
    Invalid,
    Key,
    Outcome,
    Unanchorable,
    detect_type,
    forbidden_path,
    is_under,
    normalize,
    normalize_all,
)
from tripwire.provenance import POISON, describe
from tripwire.recipe import words

_ACCEPTED: dict[str, tuple[Via, ...]] = {
    "target": ("task", "known", "trusted"),
    "selector": ("task", "known", "trusted", "self"),
    "credential": ("task", "known"),
}
# what a destructive tool's selectors and every link accept
_VOUCHED: tuple[Via, ...] = ("task", "known", "trusted")
# how the shape rule reads a content leaf
_AS_TARGET = ArgSpec(role="target")

_ID_WORDS = frozenset({"id", "ids", "uuid", "guid"})
# a run of text a reader takes for one token
_RUN = re.compile(r"[^\s<>\"'`]+")
_SCHEME = re.compile(r"(?i:https?)://")
# Where a link may start: a scheme a browser reads a host after however
# many slashes or backslashes follow ("https:/x.com", "https:\\x.com"),
# any other scheme followed by two, or two with no scheme before them,
# which the page's own fills in ("//x.com").
_LINK = re.compile(
    r"(?i:(?:https?|wss?|ftp|file):|[a-z][a-z0-9+.-]+:[/\\]{2})|(?<![\w:/\\])[/\\]{2}"
)
_AUTHORITY_END = re.compile(r"[/?#]")
# what a sentence may end a link with, which no one need have written
_PROSE_END = re.compile(r"[)\]}]?[.,;:!?]?\Z")


def check(
    call: ToolCall, rule: ToolRule, snapshot: SessionSnapshot, policy: Policy
) -> AnchorReport:
    """Whether every authority value of this call is anchored; see the
    module docstring. Called once a flow with `unless: anchored` applies."""
    if rule.args is None:
        return AnchorReport(
            "no_contract",
            reason=f"{call.tool} has no argument contract, so nothing sent to it can be anchored.",
        )
    return _Check(call, rule, snapshot, policy).run()


def accepted(role: Role, destructive: bool = False) -> tuple[Via, ...]:
    """The sources that anchor a value of this role on a tool, destructive
    or not; for content, those that anchor a link in it."""
    if role == "content" or (destructive and role == "selector"):
        return _VOUCHED
    return _ACCEPTED[role]


def invalid_target(
    call: ToolCall, rule: ToolRule, snapshot: SessionSnapshot
) -> AnchorReport | None:
    """The first target leaf that can't be read, as a report with code
    invalid_value; None when there is none."""
    for name, spec in (rule.args or {}).items():
        if spec.role != "target" or name not in call.args:
            continue
        for arg, value in _leaves(name, call.args[name]):
            for outcome in normalize_all(
                value, spec.type, protected_paths=snapshot.protected_paths
            ):
                if isinstance(outcome, Invalid):
                    leaf = LeafReport(
                        arg,
                        "target",
                        _read_as(value, spec.type),
                        "invalid",
                        _ACCEPTED["target"],
                        reason=outcome.reason,
                        value=_spelled(value),
                    )
                    return _report("invalid_value", call.tool, name, (leaf,), rule)
    return None


@dataclass(frozen=True, slots=True)
class _Known:
    """The policy's `known` entries, read."""

    keys: frozenset[Key]
    domains: tuple[KnownValue, ...]
    paths: tuple[str, ...]

    @classmethod
    def of(cls, policy: Policy) -> _Known:
        read = [read_known(vtype, e) for vtype, entries in policy.known.items() for e in entries]
        values = [v for v in read if v is not None]
        return cls(
            frozenset(Key(v.vtype, v.key) for v in values if not v.domain),
            tuple(v for v in values if v.domain),
            tuple(v.key for v in values if v.vtype == "path"),
        )

    def holds(self, key: Key) -> bool:
        if key in self.keys:
            return True
        if key.vtype == "email":
            domain = key.key.rpartition("@")[2]
            return any(d.vtype == "email" and d.key == domain for d in self.domains)
        if key.vtype == "host" and not key.key.startswith("["):
            name = key.key.partition(":")[0]
            return any(
                d.vtype == "host" and (name == d.key or name.endswith("." + d.key))
                for d in self.domains
            )
        return False

    def covers(self, key: Key) -> bool:
        """Whether a known path is strictly above key."""
        return key.vtype == "path" and any(is_under(key.key, prefix) for prefix in self.paths)


class _Check:
    def __init__(
        self, call: ToolCall, rule: ToolRule, snapshot: SessionSnapshot, policy: Policy
    ) -> None:
        self.tool = call.tool
        self.args = call.args
        self.rule = rule
        self.contract: dict[str, ArgSpec] = rule.args or {}
        self.task = snapshot.task if snapshot.task is not None else TaskView()
        self.provenance = snapshot.provenance
        self.protected = snapshot.protected_paths
        self.known = _Known.of(policy)

    def run(self) -> AnchorReport:
        leaves: list[LeafReport] = []

        def failed(leaf: LeafReport, name: str, code: str) -> AnchorReport:
            leaves.append(leaf)
            return _report(code, self.tool, name, tuple(leaves), self.rule)

        authority = 0
        for name, spec in self.contract.items():
            if spec.role == "content" or name not in self.args:
                continue
            sources = accepted(spec.role, self.rule.destructive)
            for arg, value in _leaves(name, self.args[name]):
                for outcome in normalize_all(value, spec.type, protected_paths=self.protected):
                    authority += 1
                    leaf = self._leaf(arg, name, spec, spec.role, sources, value, outcome)
                    if leaf.status == "invalid" and spec.role == "target":
                        return failed(leaf, name, "invalid_value")
                    if leaf.status != "anchored":
                        return failed(leaf, name, "unanchored_argument")
                    if _read_as(value, spec.type) == "url":
                        leaf = self._verbatim(leaf, value)
                        if leaf.status != "anchored":
                            return failed(leaf, name, "url_not_verbatim")
                    leaves.append(leaf)

        outward = any(spec.role == "target" for spec in self.contract.values())
        for name, spec in self.contract.items():
            if spec.role != "content" or name not in self.args:
                continue
            for arg, value in _leaves(name, self.args[name], keys=True):
                path = forbidden_path(value, protected_paths=self.protected)
                if path is not None:
                    leaf = LeafReport(
                        arg,
                        "content",
                        "path",
                        "unanchorable",
                        (),
                        reason=path.reason,
                        value=_spelled(value),
                    )
                    return failed(leaf, name, "unanchored_argument")
                if not outward or not isinstance(value, str):
                    continue
                for leaf, code in self._content(arg, name, value):
                    if leaf.status != "anchored":
                        return failed(leaf, name, code)
                    leaves.append(leaf)

        if authority == 0 and self.rule.destructive:
            return _report("destructive_needs_anchor", self.tool, None, tuple(leaves), self.rule)
        if authority == 0 and not self.rule.self_scoped:
            return _report("vacuous_write", self.tool, None, tuple(leaves), self.rule)
        return AnchorReport(None, leaves=tuple(leaves), unrestricted=_unrestricted(self.rule))

    def _leaf(
        self,
        arg: str,
        name: str,
        spec: ArgSpec,
        role: Role,
        accepted: tuple[Via, ...],
        value: object,
        outcome: Outcome,
    ) -> LeafReport:
        vtype = _read_as(value, spec.type)
        spelled = _spelled(value)
        if isinstance(outcome, Invalid):
            return LeafReport(
                arg, role, vtype, "invalid", accepted, reason=outcome.reason, value=spelled
            )
        if isinstance(outcome, Unanchorable):
            # a reserved name ("admin", "everyone") anchors only as a known one
            named = (
                normalize(value, spec.type, known=True, protected_paths=self.protected)
                if outcome.reason == "reserved"
                else None
            )
            if not (isinstance(named, Key) and self.known.holds(named)):
                return LeafReport(
                    arg, role, vtype, "unanchorable", accepted, reason=outcome.reason, value=spelled
                )
            outcome = named
        key = outcome
        via = self._via(key, _labels(name), spec.match == "under", accepted)
        if via is not None:
            return LeafReport(
                arg,
                role,
                key.vtype,
                "anchored",
                accepted,
                key_sha256=_hashed(key, role),
                via=via,
                value=spelled,
            )
        seen = self.provenance.first_seen(key)
        return LeafReport(
            arg,
            role,
            key.vtype,
            "unanchored",
            accepted,
            key_sha256=_hashed(key, role),
            first_seen=None if seen is None else FirstSeen(seen.cls, seen.tool, seen.turn),
            value=spelled,
        )

    def _via(
        self, key: Key, labels: list[str], under: bool, accepted: tuple[Via, ...]
    ) -> Via | None:
        if self.task.anchors(key, labels) or (under and self.task.covers(key)):
            return "task"
        if self.known.holds(key) or (under and self.known.covers(key)):
            return "known"
        if "trusted" in accepted and self.provenance.trusted(key) is not None:
            return "trusted"
        if "self" in accepted and self.provenance.minted(key) is not None:
            return "self"
        return None

    def _verbatim(self, leaf: LeafReport, url: object, *, prose: bool = False) -> LeafReport:
        """leaf, or leaf as not_verbatim when its URL, as it is sent,
        carries a suffix no one wrote. prose: a link found in text."""
        if not isinstance(url, str):
            return leaf
        needles = _needles(url.strip(), prose)
        if not needles or any(map(self._written, needles)):
            return leaf
        return LeafReport(
            leaf.arg,
            leaf.role,
            leaf.vtype,
            "not_verbatim",
            leaf.accepted,
            key_sha256=leaf.key_sha256,
            via=leaf.via,
            value=leaf.value,
        )

    def _written(self, text: str) -> bool:
        return self.task.verbatim(text) or self.provenance.verbatim(text)

    def _content(self, arg: str, name: str, text: str) -> Iterator[tuple[LeafReport, str]]:
        """Each check a content leaf takes, with the code it fails under."""
        target = _ACCEPTED["target"]
        for vtype in ("email", "iban"):
            outcomes = normalize_all(text, vtype, protected_paths=self.protected)
            if outcomes and all(isinstance(o, Key) for o in outcomes):
                for outcome in outcomes:
                    leaf = self._leaf(arg, name, _AS_TARGET, "target", target, text, outcome)
                    yield leaf, "unanchored_argument"
                return
        # an IDN host still makes the whole leaf a URL, one that can't anchor
        whole = normalize(text, "url", protected_paths=self.protected)
        if isinstance(whole, (Key, Unanchorable)):
            leaf = self._leaf(arg, name, _AS_TARGET, "target", target, text, whole)
            if leaf.status != "anchored":
                yield leaf, "unanchored_argument"
            else:
                yield self._verbatim(leaf, text), "url_not_verbatim"
            return

        # as written, which is what is sent, and as a reader may take it
        for link in dict.fromkeys([*_links(text), *_links(_clean(text))]):
            leaf = self._link(arg, link)
            if leaf.status != "anchored":
                yield leaf, "link_unanchored"
                continue
            yield self._verbatim(leaf, link, prose=True), "url_not_verbatim"

    def _link(self, arg: str, link: str) -> LeafReport:
        # a bare link reads as http and one with no scheme as https; of
        # the rest, only http(s) and two slashes read as a URL at all
        read = link.rstrip(TRAILING)
        if _LINK.match(read) is None:
            url = "http://" + read
        elif read[:1] in "/\\":
            url = "https:" + read
        else:
            url = read
        outcome = normalize(url, "url", protected_paths=self.protected)
        if not isinstance(outcome, Key):
            status: LeafStatus = "unanchorable" if isinstance(outcome, Unanchorable) else "invalid"
            reason = outcome.reason if outcome is not None else "empty"
            return LeafReport(arg, "content", "url", status, _VOUCHED, reason=reason, value=link)
        via: Via | None = None
        if self.task.mentions(outcome):
            via = "task"
        elif self.known.holds(outcome):
            via = "known"
        elif self.provenance.trusted(outcome) is not None:
            via = "trusted"
        seen = None if via is not None else self.provenance.first_seen(outcome)
        return LeafReport(
            arg,
            "content",
            "url",
            "anchored" if via is not None else "unanchored",
            _VOUCHED,
            key_sha256=key_sha256(outcome),
            via=via,
            first_seen=None if seen is None else FirstSeen(seen.cls, seen.tool, seen.turn),
            value=link,
        )


def _report(
    code: str, tool: str, name: str | None, leaves: tuple[LeafReport, ...], rule: ToolRule
) -> AnchorReport:
    """A failure: `name` is the argument whose last leaf failed, None when
    the call as a whole did."""
    if name is not None:
        rule_id = f"tools.{tool}.args.{name}"
        reason = _explain_leaf(code, tool, leaves[-1])
    elif code == "destructive_needs_anchor":
        rule_id = f"tools.{tool}.destructive"
        reason = (
            f"{tool} is destructive, and this call names nothing the task or policy vouches for."
        )
    else:
        rule_id = f"tools.{tool}.self_scoped"
        reason = f"{tool} was called with no argument anything could vouch for."
    return AnchorReport(code, rule_id, reason, leaves, _unrestricted(rule))


def _explain_leaf(code: str, tool: str, leaf: LeafReport) -> str:
    """Why one value failed, from fixed templates: argument and tool names,
    never a value."""
    where = f"{leaf.arg} of {tool}"
    if code == "invalid_value":
        return f"{where} can't be read as {leaf.vtype or 'a value'} ({leaf.reason})."
    if code == "url_not_verbatim":
        return f"{where} holds a URL whose path or query no tool and no task wrote."
    if code == "unanchored_argument" and leaf.role == "content":
        return f"{where} names a path nothing can vouch for ({leaf.reason})."
    if code == "link_unanchored" and leaf.status != "unanchored":
        return f"{where} holds a link that can't be read as a plain URL ({leaf.reason})."
    if code == "link_unanchored":
        subject = f"{where} links to a host"
    else:
        subject = f"{where} is a value"
    sources = "the task, a known value or a trusted tool"
    if "trusted" not in leaf.accepted:
        sources = "the task or a known value"
    reason = f"{subject} that {sources} didn't supply."
    seen = leaf.first_seen
    if leaf.status in ("invalid", "unanchorable"):
        reason += f" It can never anchor ({leaf.reason})."
    elif seen is not None and seen.cls in POISON:
        reason += f" It was first seen in {describe(seen.cls, seen.tool, seen.turn)}."
    return reason


def _unrestricted(rule: ToolRule) -> tuple[str, ...]:
    return tuple(name for name, spec in (rule.args or {}).items() if spec.role == "content")


def _leaves(name: str, value: object, *, keys: bool = False) -> Iterator[tuple[str, object]]:
    """Every scalar under an argument, with its path: list items by
    index, dict values by key in sorted order, and with keys, each dict
    key before its value, at the same path. A container past the depth
    cap, or met twice, is a leaf itself, which no normalizer reads."""
    seen: set[int] = set()
    stack: list[tuple[str, object, int]] = [(name, value, 0)]
    while stack:
        path, node, depth = stack.pop()
        if isinstance(node, (list, tuple, dict)):
            if depth >= MAX_FIELD_DEPTH or id(node) in seen:
                yield path, node
                continue
            seen.add(id(node))
        if isinstance(node, (list, tuple)):
            items = [(f"{path}[{i}]", item, depth + 1) for i, item in enumerate(node)]
            stack.extend(reversed(items))
        elif isinstance(node, dict):
            entries = sorted(node.items(), key=lambda entry: str(entry[0]))
            for key, item in reversed(entries):
                stack.append((f"{path}.{key}", item, depth + 1))
                if keys:
                    stack.append((f"{path}.{key}", str(key), depth + 1))
        else:
            yield path, node


def _labels(name: str) -> list[str]:
    """The words an argument's name gives a short id: file_id labels
    "file 13"."""
    return [w for w in words(name) if w not in _ID_WORDS and not w.isdigit()]


def _read_as(value: object, vtype: str) -> str | None:
    return detect_type(value) if vtype == "auto" else vtype


def _spelled(value: object) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError, RecursionError):
        return ""


def _hashed(key: Key, role: Role) -> str | None:
    # a short credential's hash is as good as the credential
    return None if role == "credential" else key_sha256(key)


def _needles(url: str, prose: bool) -> tuple[str, ...]:
    """What must occur verbatim for a URL to pass: nothing when it carries
    no path, query or fragment past "/"; else the URL past its scheme or
    leading "//", or, in prose, that or the same without the one closing
    bracket and one mark of punctuation a sentence may end it with."""
    scheme = _SCHEME.match(url)
    rest = url[scheme.end() :] if scheme else url.removeprefix("//")
    short = _PROSE_END.sub("", rest, count=1) if prose else rest
    end = _AUTHORITY_END.search(short)
    if end is None or short[end.start() :] == "/":
        return ()
    return tuple(dict.fromkeys((rest, short)))


def _links(text: str) -> Iterator[str]:
    """Every link a reader may follow in text, as written, sentence
    punctuation after it included: from each place a link may start
    (_LINK) to the next, when something follows its slashes, and each
    run, or start of a run before such a place, whose host part is a www.
    host or ends in a pinned TLD."""
    # a browser reads the ideographic full stop in a host as a dot
    dotted = text.replace("\u3002", ".")
    for m in _RUN.finditer(dotted):
        run, written = m.group(), text[m.start() : m.end()]
        spans = [s.span() for s in _LINK.finditer(run)]
        for (start, head), (stop, _) in pairwise([*spans, (len(run), len(run))]):
            if run[head:stop].lstrip("/\\").rstrip(TRAILING):
                yield written[start:stop]
        bare = run[: spans[0][0]] if spans else run
        lead = len(bare) - len(bare.lstrip("([{"))
        host = _AUTHORITY_END.split(bare[lead:].rstrip(TRAILING), maxsplit=1)[0]
        if "@" in host or "." not in host:
            continue
        label = host.rpartition(".")[2].partition(":")[0].casefold()
        if label in TLDS or host[:4].lower() == "www.":
            yield written[lead : len(bare)]
