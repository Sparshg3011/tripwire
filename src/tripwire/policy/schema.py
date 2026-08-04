"""Policy file schema.

Everything here is deliberately strict (extra="forbid" throughout): a
misspelled key in a security policy must kill startup, not get silently
ignored and leave a hole.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Action = Literal["allow", "block", "require_approval"]
TrustClass = Literal["trusted", "untrusted"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


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
    limits: Limits | None = None
    reason: str | None = None


class SequenceRule(StrictModel):
    """Deny `deny` if `within_turns_after` was called in the last `turns` turns."""

    deny: str
    within_turns_after: str
    turns: int = Field(gt=0)


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
