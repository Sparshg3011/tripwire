"""Every relative link in the docs points at something that exists.

The docs move around more than the code does, and a dead link to the page
that holds a number is as bad as the number being missing.
"""

import re
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = sorted(
    [
        *ROOT.glob("*.md"),
        *(ROOT / "docs").rglob("*.md"),
        *(p for p in (ROOT / "gym").rglob("*.md") if p.relative_to(ROOT).parts[1] != "results"),
    ]
)
# [text](target), ![alt](target) and [label]: target
INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFERENCE = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.MULTILINE)
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*$", re.MULTILINE)
SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:", re.IGNORECASE)


def _unfenced(text: str) -> str:
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL)


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading, for the headings these docs use."""
    heading = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    heading = re.sub(r"[^\w\- ]", "", heading.replace("`", "").strip().lower())
    return heading.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    anchors, seen = set(), {}
    for heading in HEADING.findall(_unfenced(path.read_text())):
        slug = _slug(heading)
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        anchors.add(f"{slug}-{n}" if n else slug)
    return anchors


def _links(path: Path) -> list[str]:
    # a link written inside code is an example, not a link
    text = re.sub(r"`[^`\n]*`", "", _unfenced(path.read_text()))
    return [
        target
        for target in INLINE.findall(text) + REFERENCE.findall(text)
        if not SCHEME.match(target)
    ]


def _resolves(doc: Path, target: str) -> bool:
    path, _, fragment = target.partition("#")
    dest = (doc.parent / unquote(path)).resolve() if path else doc
    if not dest.exists():
        return False
    return not fragment or dest.suffix != ".md" or fragment in _anchors(dest)


def test_there_are_docs_to_check():
    assert ROOT / "EVIDENCE.md" in DOCS
    assert sum(len(_links(doc)) for doc in DOCS) > 50


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_every_relative_link_resolves(doc):
    assert [target for target in _links(doc) if not _resolves(doc, target)] == []
