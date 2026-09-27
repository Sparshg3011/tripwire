"""Policy file schema.

Everything here is deliberately strict (extra="forbid" throughout): a
misspelled key in a security policy must kill startup, not get silently
ignored and leave a hole. Numbers must be finite for the same reason:
every comparison with a NaN bound is False, so it would bound nothing.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Action = Literal["allow", "block", "require_approval"]
TrustClass = Literal["trusted", "untrusted"]

# Policy regexes match in ASCII mode. Under Unicode rules, ignoring case
# makes ı and İ cases of i, ſ of s and the Kelvin sign of k, so "admın"
# passes for "admin" — and an inline (?i) ignores case whether or not the
# constraint asks. It also keeps \d to 0-9, where Unicode rules admit
# digits like "١٢" that NFKC leaves alone and int() reads as 12.
REGEX_FLAGS = re.ASCII

# (?u) or (?u:...) would switch back to Unicode rules. Escapes are matched
# too, only so that they're skipped: \(?u is an optional paren, then a u.
_UNICODE_FLAG = re.compile(r"\\.|\(\?[a-zA-Z-]*u", re.DOTALL)


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
            if any(m[0].startswith("(") for m in _UNICODE_FLAG.finditer(v)):
                raise ValueError("regex may not use the u flag; policy regexes are ASCII-only")
            try:
                re.compile(v, REGEX_FLAGS)
            except re.error as e:
                raise ValueError(f"regex does not compile: {e}")
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


class ToolRule(StrictModel):
    action: Action
    constraints: dict[str, Constraint] = {}
    # When set, an argument named neither here, nor in constraints, nor as
    # the field sum_per_session adds up blocks the call. Without it,
    # arguments nothing constrains pass unchecked.
    allowed_args: list[str] | None = None
    limits: Limits | None = None
    reason: str | None = None

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


class Policy(StrictModel):
    version: Literal[1]
    enforce: bool = True
    defaults: Defaults = Defaults()
    sources: dict[str, TrustClass] = {}
    tools: dict[str, ToolRule] = {}
    sequences: list[SequenceRule] = []
    flows: list[FlowRule] = []

    def source_class(self, tool: str) -> TrustClass:
        # Unlisted tools fall back to the "*" entry, and if there isn't
        # one, they're untrusted. Strict by default.
        return self.sources.get(tool, self.sources.get("*", "untrusted"))
