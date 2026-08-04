"""Load and validate a policy file.

A policy that fails to load is a fatal error — the proxy refuses to
start rather than running with rules it only half-understood.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from tripwire.policy.schema import Policy


class PolicyError(Exception):
    pass


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    try:
        text = path.read_text()
    except OSError as e:
        raise PolicyError(f"cannot read policy file {path}: {e}") from e

    try:
        # safe_load only. full_load can construct arbitrary objects.
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyError(f"{path}: invalid yaml: {e}") from e

    if not isinstance(data, dict):
        raise PolicyError(f"{path}: expected a mapping at the top level")

    try:
        return Policy.model_validate(data)
    except ValidationError as e:
        lines = [f"{path}: invalid policy:"]
        for err in e.errors():
            where = ".".join(str(p) for p in err["loc"]) or "<root>"
            lines.append(f"  {where}: {err['msg']}")
        raise PolicyError("\n".join(lines)) from e
