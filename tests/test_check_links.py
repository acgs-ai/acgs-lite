"""Publication boundaries for offline documentation link validation."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_links.py"
_SPEC = importlib.util.spec_from_file_location("publication_check_links", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_LINKS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_LINKS)


@pytest.fixture
def published_repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text("private.md\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Project\n[Guide](guide.md)\n", encoding="utf-8")
    (tmp_path / "guide.md").write_text("# Guide\n", encoding="utf-8")
    (tmp_path / "private.md").write_text("[Broken](missing.md)\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", ".gitignore", "README.md", "guide.md"],
        check=True,
    )
    return tmp_path


def test_ignored_document_bad_links_are_not_published(published_repo: Path) -> None:
    assert _LINKS.check(published_repo) == []


@pytest.mark.parametrize(
    "target",
    [
        "private.md",
        "https://github.com/acgs-ai/acgs-lite/blob/main/private.md",
    ],
)
def test_public_link_to_ignored_local_document_fails(
    published_repo: Path, target: str
) -> None:
    (published_repo / "README.md").write_text(f"[Private]({target})\n", encoding="utf-8")
    assert (published_repo / "private.md").is_file()

    problems = _LINKS.check(published_repo)

    assert len(problems) == 1
    assert "README.md:1" in problems[0]
    assert target in problems[0]


def test_deleted_tracked_target_fails(published_repo: Path) -> None:
    (published_repo / "guide.md").unlink()

    problems = _LINKS.check(published_repo)

    assert len(problems) == 1
    assert "dead relative link -> guide.md" in problems[0]


def test_export_without_git_checks_public_files(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("[Guide](guide.md#usage)\n", encoding="utf-8")
    (tmp_path / "guide.md").write_text("# Usage\n", encoding="utf-8")

    assert _LINKS.check(tmp_path) == []

    (tmp_path / "guide.md").write_text("# Different heading\n", encoding="utf-8")
    assert "dangling anchor" in _LINKS.check(tmp_path)[0]
