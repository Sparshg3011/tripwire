"""replay() has callers besides the CLI: a script that vets a candidate
policy before a rollout is one, and tooling that reads a signature at
runtime has to be able to resolve it."""

import inspect
import typing

from tripwire.replay import replay


def test_every_annotation_resolves_at_runtime():
    # a name imported for the type checker alone is a NameError here
    hints = typing.get_type_hints(replay)

    assert hints.keys() == {*inspect.signature(replay).parameters, "return"}
