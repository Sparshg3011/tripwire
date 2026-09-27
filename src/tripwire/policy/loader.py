"""Load and validate a policy file.

A policy that fails to load is a fatal error — the proxy refuses to
start rather than running with rules it only half-understood.
"""

from __future__ import annotations

from collections.abc import Hashable
from pathlib import Path

import yaml
from pydantic import ValidationError

from tripwire.policy.schema import Policy


class PolicyError(Exception):
    pass


class _UniqueKeyLoader(yaml.SafeLoader):
    """safe_load, except a key given twice is an error. Plain yaml keeps
    the last one, and in a policy the last one can be the looser rule
    that nobody reading from the top expects to be in force."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._checked: set[yaml.MappingNode] = set()

    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        # Every mapping passes through here, merge sources included, which
        # yaml copies into their target without constructing them. Each is
        # checked once, before flattening rewrites it in place: after, a
        # merged key and the key overriding it would look like a repeat.
        if node not in self._checked:
            self._checked.add(node)
            self._refuse_repeats(node)
        super().flatten_mapping(node)

    def _refuse_repeats(self, node: yaml.MappingNode) -> None:
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                # keys pulled in by a merge may be overridden; that's what
                # a merge is for. But a second `<<` is a repeat like any
                # other key: yaml applies both, and the later one wins.
                key: Hashable = "<<"
            else:
                key = self.construct_object(key_node)
                if not isinstance(key, Hashable):
                    continue  # construct_mapping reports it
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            seen.add(key)


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    try:
        text = path.read_text()
    except OSError as e:
        raise PolicyError(f"cannot read policy file {path}: {e}") from e

    try:
        # a SafeLoader only. full_load can construct arbitrary objects.
        data = yaml.load(text, Loader=_UniqueKeyLoader)
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
