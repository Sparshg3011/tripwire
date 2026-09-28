"""Where each value this session has seen was seen first.

Anchoring asks one question of a session's history: where did this value
come from? Each observation takes the next index, and every sighting in
it shares that index:

  a tool result
  the text of an upstream failure the agent was handed
  the tool listing, at startup
  the arguments of a call made after untrusted content

A sighting has a class:

  trusted_field   a whole field of a result from a `trusted` tool
  self            the one fresh id a create-like call returned
  untrusted_field a whole field of any other result, or of an error
  untrusted_text  the text of any other result, or of an error
  agent           the arguments of a call made after untrusted content,
                  content included
  listing         the tool listing
  upstream_error  the text of an upstream failure

The last five poison, and their text is scanned greedily
(values.scan_poison). The first two anchor, by the counting rule: a
sighting of key k counts only when k was not poisoned before its index
(values.is_poisoned), so a value first seen in poison is never promoted
by a trusted tool that repeats it later, the agent's own writes read
back included. Only the task and `known` override history, and neither
lives here. Arguments of a call made before untrusted content are
recorded as nothing, and an approval is not an observation.

What a result supplies:

  structure  structuredContent, when the result has no text block or
             has one that parses as strict JSON equal to it; else each
             text block that parses entirely as strict JSON. Something
             the model may never have been shown vouches for nothing.
  fields     values.whole_fields() of the structure. A field whose key
             equals a key of the same call's arguments is an echo and
             sights nothing: a tool asked about a value hasn't vouched
             for it.
  text       every text block, embedded text resource and resource
             link, and structuredContent when no text block equals it:
             poison text when the result is untrusted or an error, inert
             when trusted. Either way it is kept for the verbatim rule,
             as the listing and upstream errors are; what the agent
             wrote is not, and a kept text vouches only for what it held
             before the agent wrote it: a tool repeating what it was
             sent, in a result or an error, vouches for nothing.

A result from a tool whose name holds a create-like verb (create, new,
add, copy, make, upload) is a write. It may mint one `self` id: when it
is no error, exactly one leaf at depth 1 is keyed id, id_, uuid or
<noun>_id, is not an echo and reads as an id, and that id was never
sighted before in any class, nor held by a poison text when 6 or more
characters long. Every other leaf of a write is handled as untrusted.

Caps bound what one session keeps. An observation that poisons and
would go over a cap, or that can't be read whole (media, a scan past
MAX_SCAN_KEYS, fields past the depth cap), is dropped and sets
`degraded`, which is sticky and turns off every trusted and self anchor
and every verbatim match in kept text: poison left unrecorded can only
cost anchors. A trusted result over a cap is dropped without degrading
anything, since it only ever adds them.

view() is O(1). The tables only grow, a sighting never changes once
recorded, and every entry carries its index, so a view reads the
entries below the index it was taken at and nothing recorded since.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import takewhile
from typing import Any, Literal

from mcp import types

from tripwire.policy.canonical import _clean
from tripwire.policy.values import Key, PoisonScan, is_poisoned, scan_poison, whole_fields

SightingClass = Literal[
    "trusted_field",
    "self",
    "untrusted_field",
    "untrusted_text",
    "agent",
    "listing",
    "upstream_error",
]
POISON: frozenset[str] = frozenset(
    {"untrusted_field", "untrusted_text", "agent", "listing", "upstream_error"}
)

CREATE_VERBS = frozenset({"create", "new", "add", "copy", "make", "upload"})
_SELF_KEY = re.compile(r"id_?|uuid|\w+_id")
_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


@dataclass(frozen=True, slots=True)
class Sighting:
    idx: int
    cls: SightingClass
    tool: str  # "" for the listing
    turn: int


@dataclass(frozen=True, slots=True)
class Caps:
    """What one session keeps: typed keys sighted in all, characters of
    one observation's text, and characters of text kept in all."""

    keys: int = 200_000
    result_chars: int = 2 * 2**20
    text_chars: int = 4 * 2**20


@dataclass(frozen=True, slots=True)
class Observed:
    """What one observation added: typed keys by class, and why it
    degraded the session, when it did."""

    counts: Mapping[str, int]
    degraded_by: str | None = None


def describe(cls: str, tool: str, turn: int) -> str:
    """Where a sighting was, in words: "free text from read_email, turn 3"."""
    if cls == "listing":
        return "the tool listing"
    where = {
        "trusted_field": "a field from {tool}",
        "self": "the id {tool} created",
        "untrusted_field": "a field from {tool}",
        "untrusted_text": "free text from {tool}",
        "agent": "arguments sent to {tool} after untrusted content",
        "upstream_error": "an error from {tool}",
    }.get(cls, "{tool}")
    return f"{where.format(tool=tool)}, turn {turn}"


def is_write(tool: str) -> bool:
    """Whether a tool's name holds a create-like verb, as a word of it:
    add_contact and createEvent do, get_address_book doesn't."""
    words = {word.lower() for word in _WORDS.findall(tool)}
    return not words.isdisjoint(CREATE_VERBS)


_NOT_JSON = object()


def _refuse(constant: str) -> Any:
    raise ValueError(f"{constant} is not JSON")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # with a key given twice, which value the model read is anyone's guess
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate key")
    return dict(pairs)


def _strict_json(text: str) -> object:
    try:
        return json.loads(text, parse_constant=_refuse, object_pairs_hook=_unique)
    except (ValueError, RecursionError):
        return _NOT_JSON


def _dump(value: object) -> str | None:
    """value as JSON text to scan, keys sorted where they can be; None
    when it isn't JSON at all."""
    for sort in (True, False):
        try:
            return json.dumps(value, sort_keys=sort, ensure_ascii=False, default=str)
        except TypeError:
            continue  # keys that don't sort against each other
        except (ValueError, RecursionError):
            return None
    return None


@dataclass(frozen=True, slots=True)
class _Reading:
    texts: list[str]
    structure: list[object]
    unreadable: bool


def _read(result: types.CallToolResult) -> _Reading:
    blocks: list[str] = []
    other: list[str] = []
    unreadable = False
    for block in result.content:
        if isinstance(block, types.TextContent):
            blocks.append(block.text)
        elif isinstance(block, types.EmbeddedResource) and isinstance(
            block.resource, types.TextResourceContents
        ):
            other.append(block.resource.text)
        elif isinstance(block, types.ResourceLink):
            # its name, uri and description are the upstream's to write
            other.append(block.model_dump_json(exclude_none=True))
        else:
            unreadable = True  # an image, audio, or a blob
    parsed = [value for value in map(_strict_json, blocks) if value is not _NOT_JSON]
    structured = result.structuredContent
    texts = blocks + other
    if structured is None:
        return _Reading(texts, parsed, unreadable)
    if any(value == structured for value in parsed):
        return _Reading(texts, [structured], unreadable)
    dumped = _dump(structured)
    if dumped is None:
        return _Reading(texts, parsed, True)
    texts.append(dumped)
    return _Reading(texts, parsed if blocks else [structured], unreadable)


def _echoes(args: Mapping[str, Any]) -> frozenset[Key]:
    return frozenset(k for f in whole_fields(args) if not f.is_key for k in f.keys)


class ProvenanceRegistry:
    """One session's sightings. Append-only; see the module docstring."""

    def __init__(self, caps: Caps | None = None) -> None:
        self.caps = caps if caps is not None else Caps()
        self.degraded: str | None = None
        self._next = 0
        self._scans: list[tuple[Sighting, PoisonScan]] = []
        self._texts: list[tuple[int, str]] = []
        self._first: dict[Key, Sighting] = {}
        self._first_poison: dict[Key, Sighting] = {}
        self._counting: dict[tuple[str, Key], Sighting] = {}
        self._keys = 0
        self._chars = 0

    def view(self) -> ProvenanceView:
        return ProvenanceView(self, self._next, self.degraded is not None)

    # --- observations ---------------------------------------------------

    def observe_listing(self, text: str) -> Observed:
        return self._poison(Sighting(self._take(), "listing", "", 0), text, (), verbatim=True)

    def observe_error(self, tool: str, turn: int, text: str) -> Observed:
        sighting = Sighting(self._take(), "upstream_error", tool, turn)
        return self._poison(sighting, text, (), verbatim=True)

    def observe_arguments(self, tool: str, turn: int, args: Mapping[str, Any]) -> Observed:
        """A call's arguments, every leaf and name of them, when the agent
        wrote them after reading untrusted content."""
        sighting = Sighting(self._take(), "agent", tool, turn)
        fields = whole_fields(args)
        text = _dump(args)
        keys = [k for f in fields for k in f.keys]
        unread = "unreadable arguments" if fields.truncated or text is None else None
        return self._poison(sighting, text or "", keys, verbatim=False, unread=unread)

    def observe_result(
        self,
        tool: str,
        turn: int,
        args: Mapping[str, Any],
        result: types.CallToolResult,
        *,
        trusted: bool,
        may_mint: bool = True,
    ) -> Observed:
        """A result of `tool` called with `args`. trusted: the policy's
        class for the tool. may_mint: the call ran because the policy let
        it, not only because shadow mode did."""
        idx = self._take()
        reading = _read(result)
        echo = _echoes(args)
        write = is_write(tool)
        if trusted and not result.isError and not write:
            return self._trusted(Sighting(idx, "trusted_field", tool, turn), reading, echo)

        minted: Key | None = None
        fields: list[Key] = []
        unread = "unreadable content" if reading.unreadable else None
        candidates: list[Key] = []
        for value in reading.structure:
            found = whole_fields(value)
            if found.truncated:
                unread = "fields past the depth cap"
            for f in found:
                keys = [k for k in f.keys if k not in echo]
                id_key = next((k for k in keys if k.vtype == "id"), None)
                if (
                    len(f.path) == 1
                    and not f.is_key
                    and isinstance(f.path[0], str)
                    and _SELF_KEY.fullmatch(f.path[0])
                    and id_key is not None
                ):
                    candidates.append(id_key)
                fields.extend(keys)
        if write and may_mint and not result.isError and len(candidates) == 1:
            minted = candidates[0] if self._fresh(candidates[0]) else None

        return self._poison(
            Sighting(idx, "untrusted_text", tool, turn),
            "\n".join(reading.texts),
            [k for k in fields if k != minted],
            verbatim=True,
            unread=unread,
            fields_cls="untrusted_field",
            minted=minted,
        )

    # --- reading, for views ------------------------------------------------

    def counting(self, cls: SightingClass, key: Key, upto: int) -> Sighting | None:
        """The first `cls` sighting of key below upto, when it counts."""
        sighting = self._counting.get((cls, key))
        if sighting is None or sighting.idx >= upto:
            return None
        if self._poisoned_before(key, sighting.idx, self_key=cls == "self"):
            return None
        return sighting

    def first_seen(self, key: Key, upto: int) -> Sighting | None:
        """The first sighting of key below upto: typed, or held by a poison
        text under the text rule of values.is_poisoned()."""
        first = self._first.get(key)
        bound = first.idx if first is not None and first.idx < upto else upto
        for sighting, scan in takewhile(lambda entry: entry[0].idx < bound, self._scans):
            if is_poisoned(key, (scan,)):
                return sighting
        return first if bound < upto else None

    def verbatim(self, text: str, upto: int) -> bool:
        """Whether text occurs, case and all, in what a tool, the listing
        or an upstream error wrote below upto, before the agent wrote it
        in any case: a tool that repeats what it was sent, in a result or
        an error, vouches for nothing."""
        first = next((idx for idx, kept in self._texts if idx < upto and text in kept), None)
        if first is None:
            return False
        folded = " ".join(_clean(text).casefold().split())
        earlier = takewhile(lambda entry: entry[0].idx < first, self._scans)
        return not any(
            scan.truncated or folded in scan.folded
            for sighting, scan in earlier
            if sighting.cls == "agent"
        )

    # --- internals ---------------------------------------------------------

    def _take(self) -> int:
        idx = self._next
        self._next += 1
        return idx

    def _poisoned_before(self, key: Key, idx: int, *, self_key: bool = False) -> bool:
        first = self._first_poison.get(key)
        if first is not None and first.idx < idx:
            return True
        earlier = (scan for sighting, scan in takewhile(lambda e: e[0].idx < idx, self._scans))
        return is_poisoned(key, earlier, self_key=self_key)

    def _fresh(self, key: Key) -> bool:
        if key in self._first:
            return False
        return not is_poisoned(key, (scan for _, scan in self._scans), self_key=True)

    def _fits(self, keys: int, chars: int) -> bool:
        return self._keys + keys <= self.caps.keys and self._chars + chars <= self.caps.text_chars

    def _sight(self, sighting: Sighting, key: Key) -> None:
        self._first.setdefault(key, sighting)
        if sighting.cls in POISON:
            self._first_poison.setdefault(key, sighting)
        else:
            self._counting.setdefault((sighting.cls, key), sighting)

    def _trusted(self, sighting: Sighting, reading: _Reading, echo: frozenset[Key]) -> Observed:
        # dropped fields cost anchors and nothing else, so a trusted result
        # that can't be read whole still vouches for what could be read
        keys = [
            k
            for value in reading.structure
            for f in whole_fields(value)
            for k in f.keys
            if k not in echo
        ]
        text = _clean("\n".join(reading.texts))
        if len(text) > self.caps.result_chars or not self._fits(len(keys), len(text)):
            return Observed({})
        self._keys += len(keys)
        self._chars += len(text)
        for key in keys:
            self._sight(sighting, key)
        self._texts.append((sighting.idx, text))
        return Observed({"trusted_field": len(keys)} if keys else {})

    def _poison(
        self,
        sighting: Sighting,
        text: str,
        fields: Sequence[Key],
        *,
        verbatim: bool,
        unread: str | None = None,
        fields_cls: SightingClass | None = None,
        minted: Key | None = None,
    ) -> Observed:
        field_sighting = sighting
        if fields_cls is not None:
            field_sighting = Sighting(sighting.idx, fields_cls, sighting.tool, sighting.turn)
        if len(text) > self.caps.result_chars:
            return self._degrade("text over the per-observation cap")
        scan = scan_poison(text)
        kept = _clean(text) if verbatim else ""
        if scan.truncated:
            unread = unread or "a scan past its key cap"
        keys = len(scan.keys) + len(fields) + (minted is not None)
        if not self._fits(keys, len(text) + len(kept)):
            return self._degrade("over the session's caps")

        self._keys += keys
        self._chars += len(text) + len(kept)
        counts: dict[str, int] = {}
        if minted is not None:
            self._sight(Sighting(sighting.idx, "self", sighting.tool, sighting.turn), minted)
            counts["self"] = 1
        for key in fields:
            self._sight(field_sighting, key)
        if fields:
            counts[field_sighting.cls] = len(fields)
        self._scans.append((sighting, scan))
        for key in scan.keys:
            self._sight(sighting, key)
        if scan.keys:
            counts[sighting.cls] = counts.get(sighting.cls, 0) + len(scan.keys)
        if verbatim:
            self._texts.append((sighting.idx, kept))
        if unread is not None:
            return self._degrade(unread, counts)
        return Observed(counts)

    def _degrade(self, reason: str, counts: Mapping[str, int] | None = None) -> Observed:
        newly = self.degraded is None
        if newly:
            self.degraded = reason
        return Observed(counts or {}, reason if newly else None)


@dataclass(frozen=True, slots=True)
class ProvenanceView:
    """A registry as it stood when the view was taken: nothing at or past
    `upto` is visible, and `degraded` is the flag as it was. Anchors are
    read through trusted() and minted(), history through first_seen()
    and verbatim(). The empty view has seen nothing."""

    registry: ProvenanceRegistry | None = None
    upto: int = 0
    degraded: bool = False

    def trusted(self, key: Key) -> Sighting | None:
        """The trusted field that anchors key, if one does."""
        if self.registry is None or self.degraded:
            return None
        return self.registry.counting("trusted_field", key, self.upto)

    def minted(self, key: Key) -> Sighting | None:
        """The self id that anchors key, if one does."""
        if self.registry is None or self.degraded:
            return None
        return self.registry.counting("self", key, self.upto)

    def first_seen(self, key: Key) -> Sighting | None:
        if self.registry is None:
            return None
        return self.registry.first_seen(key, self.upto)

    def verbatim(self, text: str) -> bool:
        """Never while degraded, when what the agent wrote may have gone
        unrecorded."""
        if self.registry is None or self.degraded:
            return False
        return self.registry.verbatim(text, self.upto)
