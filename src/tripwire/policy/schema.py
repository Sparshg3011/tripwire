"""Policy file schema.

Everything here is deliberately strict (extra="forbid" throughout): a
misspelled key in a security policy must kill startup, not get silently
ignored and leave a hole. Numbers must be finite for the same reason:
every comparison with a NaN bound is False, so it would bound nothing.
An infinite bound either bounds nothing or refuses everything, and in
JSON it's null, the same as no bound at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tripwire.policy.values import Key, KeyType, VType, normalize

Action = Literal["allow", "block", "require_approval"]
TrustClass = Literal["trusted", "untrusted"]
# what an argument decides: who receives the effect (target), which
# existing object it acts on (selector), which secret it sets
# (credential); content decides none of those
Role = Literal["target", "selector", "credential", "content"]

_ARG_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# A value has to match a policy regex twice, in ASCII mode and under
# Unicode rules, because each is the strict reading somewhere. Under
# Unicode rules, ignoring case makes ı and İ cases of i, ſ of s and the
# Kelvin sign of k, so "admın" passes for "admin" (and an inline (?i)
# ignores case whether or not the constraint asks), and \d admits digits
# like "١٢" that NFKC leaves alone and int() reads as 12. In ASCII mode,
# \s knows nothing of U+2028 or U+0085, so \S and [^\s] let line breaks
# through, and \D and \W let other scripts' digits and letters through.
REGEX_MODES = (re.ASCII, re.NOFLAG)

# (?flags) for the whole pattern, or (?flags:...) and (?flags-flags:...)
# for one group
_FLAG_GROUP = re.compile(r"\(\?([a-zA-Z]*)(?:-([a-zA-Z]*))?([:)])")


def _past(pattern: str, i: int, stop: str) -> int:
    """Just past the first unescaped `stop` at or after i."""
    while i < len(pattern) and pattern[i] != stop:
        i += 2 if pattern[i] == "\\" else 1
    return i + 1


def _turns_on_unicode(pattern: str) -> bool:
    """Whether a flag group turns on u, which would read the pattern under
    Unicode rules in ASCII mode too. In a class, a comment or an escape,
    "(?u" is only text. Reads only patterns that compile."""
    verbose = [False]  # per open group: whether a # starts a comment in it
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
        elif c == "[":
            i += 2 if pattern.startswith("[^", i) else 1
            if pattern.startswith("]", i):
                i += 1  # a ] first is a member, not the end
            i = _past(pattern, i, "]")
        elif c == "#" and verbose[-1]:
            i = _past(pattern, i, "\n")
        elif pattern.startswith("(?#", i):
            i = _past(pattern, i, ")")
        elif group := _FLAG_GROUP.match(pattern, i):
            on, off, scope = group.groups()
            if "u" in on:
                return True
            x_on = (verbose[-1] or "x" in on) and "x" not in (off or "")
            if scope == ")":
                verbose[-1] = x_on  # only at the very start, so for the whole pattern
            else:
                verbose.append(x_on)
            i = group.end()
        else:
            if c == "(":
                verbose.append(verbose[-1])
            elif c == ")":
                verbose.pop()
            i += 1
    return False


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Defaults(StrictModel):
    unknown_tools: Action = "block"
    gate_timeout_seconds: int = Field(default=120, gt=0)


class Constraint(StrictModel):
    """One constraint on one argument. Any condition that doesn't hold
    blocks the call — and a constraint on an argument the call didn't
    provide also blocks (fail closed)."""

    regex: str | None = None
    case_insensitive: bool = False
    max_length: int | None = Field(default=None, ge=0)
    type: Literal["number", "string"] | None = None
    min: float | None = None
    max: float | None = None

    @field_validator("regex")
    @classmethod
    def regex_must_compile(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                re.compile(v)
            except re.error as e:
                raise ValueError(f"regex does not compile: {e}")
            # without a u flag, what compiles here compiles in ASCII mode too
            if _turns_on_unicode(v):
                raise ValueError(
                    "regex may not use the u flag; policy regexes must match in ASCII mode too"
                )
        return v

    @model_validator(mode="after")
    def must_check_something(self) -> Constraint:
        if all(v is None for v in (self.regex, self.max_length, self.type, self.min, self.max)):
            raise ValueError("constraint has no conditions")
        return self


class SumLimit(StrictModel):
    field: str
    max: float


class Limits(StrictModel):
    per_session: int | None = Field(default=None, gt=0)
    sum_per_session: SumLimit | None = None


class ArgSpec(StrictModel):
    """One argument of a tool's contract. `type` says how an authority
    value is read (auto: by its shape); `match: under` lets a path anchor
    below a task or known path as well as at one."""

    role: Role
    type: VType = "auto"
    match: Literal["exact", "under"] = "exact"

    @model_validator(mode="after")
    def fits_the_role(self) -> ArgSpec:
        if self.role == "content" and self.model_fields_set & {"type", "match"}:
            raise ValueError("a content argument is never anchored, so it takes no type or match")
        if self.match == "under" and self.type not in ("path", "auto"):
            raise ValueError("match: under compares paths, so it needs type path or auto")
        return self


class ToolRule(StrictModel):
    action: Action
    constraints: dict[str, Constraint] = {}
    # When set, an argument named neither here, nor in constraints, nor as
    # the field sum_per_session adds up blocks the call. Without it,
    # arguments nothing constrains pass unchecked.
    allowed_args: list[str] | None = None
    limits: Limits | None = None
    reason: str | None = None
    # The argument contract a flow with `unless: anchored` reads. Its keys
    # are admitted as allowed_args's are, and once it is set an argument
    # named nowhere in the rule blocks, as with allowed_args.
    args: dict[str, ArgSpec] | None = None
    # its selectors anchor only to the task, known values and trusted
    # tools, and a call naming none of those never discharges
    destructive: bool = False
    # a call with no authority argument may run after untrusted content
    self_scoped: bool = False

    @field_validator("allowed_args")
    @classmethod
    def allowed_args_are_distinct(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            repeated = sorted({name for name in v if v.count(name) > 1})
            if repeated:
                raise ValueError(
                    f"allowed_args lists {', '.join(map(repr, repeated))} more than once"
                )
        return v

    @field_validator("args", mode="before")
    @classmethod
    def bare_roles_are_specs(cls, v: Any) -> Any:
        # `to: target` is short for `to: {role: target}`
        if isinstance(v, dict):
            return {name: {"role": s} if isinstance(s, str) else s for name, s in v.items()}
        return v

    @field_validator("args")
    @classmethod
    def args_are_top_level_names(cls, v: dict[str, ArgSpec] | None) -> dict[str, ArgSpec] | None:
        for name in v or {}:
            if not _ARG_NAME.fullmatch(name):
                raise ValueError(f"args names {name!r}, which is not a top-level argument name")
        return v

    @model_validator(mode="after")
    def self_scoped_is_not_destructive(self) -> ToolRule:
        if self.self_scoped and self.destructive:
            raise ValueError("a destructive tool can't be self_scoped")
        return self


class SequenceRule(StrictModel):
    """Deny `deny` if `within_turns_after` was called in the last `turns`
    turns, or at any earlier point in the session with `turns: session`.

    Every executed call is a turn, so a numeric window can be padded: a
    caller who gets a few harmless calls allowed ages the trigger out of
    it. A session-long rule has no window to push anything out of.
    """

    deny: str
    within_turns_after: str
    turns: Annotated[int, Field(gt=0)] | Literal["session"]


class FlowRule(StrictModel):
    # No "allow" here: flows may only tighten a verdict, never relax one.
    when: Literal["context_tainted"]
    tools: list[str]
    action: Literal["block", "require_approval"]
    reason: str | None = None
    # the flow skips a call whose every authority value is anchored; it
    # never lowers what any other rule decided
    unless: Literal["anchored"] | None = None


@dataclass(frozen=True, slots=True)
class KnownValue:
    """One `known` entry, read. With `domain` set, `key` is a domain that
    stands for every address at it (email), or for it and every host
    under it (host)."""

    vtype: KeyType
    key: str
    domain: bool = False


def read_known(vtype: KeyType, entry: object) -> KnownValue | None:
    """A `known` entry as anchoring reads it; None if it doesn't normalize
    under its type. "@corp.example" under email and ".corp.example" under
    host are domains; every other entry is one value."""
    if not isinstance(entry, str):
        return None
    if vtype == "email" and entry.startswith("@"):
        address = normalize("x" + entry, "email")
        if isinstance(address, Key):
            return KnownValue("email", address.key.partition("@")[2], domain=True)
        return None
    if vtype == "host" and entry.startswith("."):
        host = normalize(entry[1:], "host")
        # a domain has no port, and an address has no subdomains
        if isinstance(host, Key) and ":" not in host.key and not host.key[-1:].isdigit():
            return KnownValue("host", host.key, domain=True)
        return None
    outcome = normalize(entry, vtype, known=True)
    return KnownValue(vtype, outcome.key) if isinstance(outcome, Key) else None


class Policy(StrictModel):
    version: Literal[1]
    enforce: bool = True
    defaults: Defaults = Defaults()
    # Operator attestations: values of each type that anchor any authority
    # argument of that type, whatever the session has seen.
    known: dict[KeyType, list[str]] = {}
    sources: dict[str, TrustClass] = {}
    tools: dict[str, ToolRule] = {}
    sequences: list[SequenceRule] = []
    flows: list[FlowRule] = []

    @field_validator("known")
    @classmethod
    def known_values_normalize(cls, v: dict[KeyType, list[str]]) -> dict[KeyType, list[str]]:
        for vtype, entries in v.items():
            for i, entry in enumerate(entries):
                if read_known(vtype, entry) is None:
                    raise ValueError(f"known.{vtype}[{i}] ({entry!r}) is not a usable {vtype}")
        return v

    def source_class(self, tool: str) -> TrustClass:
        # Unlisted tools fall back to the "*" entry, and if there isn't
        # one, they're untrusted. Strict by default.
        return self.sources.get(tool, self.sources.get("*", "untrusted"))
