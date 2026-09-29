"""Verify release archive contents before uploading them to a package index."""

import argparse
import email
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


def check_members(names: list[str]) -> None:
    for name in names:
        parts = PurePosixPath(name).parts
        assert not any(
            part in {".env", ".git", ".venv", ".cache", "__pycache__"} for part in parts
        ), name
        assert "gym/results/" not in name, name
        assert not name.endswith((".pyc", ".db", ".log")), name


def check_description(metadata: bytes) -> None:
    """PyPI shows the README on its own: a relative link there leads
    nowhere, and it doesn't render Mermaid."""
    description = email.message_from_bytes(metadata).get_payload()
    assert isinstance(description, str) and description, "no long description"
    assert "```mermaid" not in description, "a Mermaid block reached the long description"
    relative = re.findall(r"\]\((?!https?://|#|mailto:)([^)\s]*)\)", description)
    assert not relative, f"relative links in the long description: {relative}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, default=Path("dist"), nargs="?")
    args = parser.parse_args()
    wheels = list(args.directory.glob("*.whl"))
    sources = list(args.directory.glob("*.tar.gz"))
    assert len(wheels) == len(sources) == 1, "expected one wheel and one source archive"
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        check_members(names)
        assert "tripwire/gate/exact.py" in names, "exact-approval API missing from wheel"
        assert "tripwire/py.typed" in names, "py.typed missing from wheel"
        for name in ("policy.yaml", "mailbox.py", "play.py"):
            assert f"tripwire/demo/{name}" in names, f"tripwire demo needs {name}"
        (metadata,) = [name for name in names if name.endswith(".dist-info/METADATA")]
        check_description(archive.read(metadata))
        scenarios = [
            name
            for name in names
            if name.startswith("tripwire_gym/data/scenarios/") and name.endswith(".yaml")
        ]
        assert len(scenarios) == 76, f"expected 76 shipped scenarios, found {len(scenarios)}"
        for name in (
            "policies/standard.yaml",
            "external_policies/banking.yaml",
            "recipe_policies/banking.yaml",
            "recipe_policies/strict/banking.yaml",
            "recipe_policies/taint/banking.yaml",
            "agentdojo-heldout.yaml",
            "agentdojo-protectai-heldout.yaml",
        ):
            assert f"tripwire_gym/data/{name}" in names, name
    with tarfile.open(sources[0]) as archive:
        check_members(archive.getnames())
    print("Distribution contents passed: 76 scenarios, policies, protocols; no local run data")


if __name__ == "__main__":
    main()
