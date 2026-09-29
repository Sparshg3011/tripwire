"""Print the lowest version pyproject.toml accepts for the dependency
named on the command line, such as mcp."""

import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement


def floor(name: str) -> str:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    for line in tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["dependencies"]:
        requirement = Requirement(line)
        if requirement.name == name:
            (lowest,) = [s.version for s in requirement.specifier if s.operator == ">="]
            return lowest
    raise SystemExit(f"{name} is not a dependency in {pyproject}")


if __name__ == "__main__":
    print(floor(sys.argv[1]))
