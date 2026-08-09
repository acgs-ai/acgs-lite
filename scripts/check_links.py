#!/usr/bin/env python3
"""Validate documentation links across the repository without touching the network.

Three classes of rot are checked, all of them offline and therefore deterministic
in CI:

1. **Dead relative links** — a Markdown link pointing at a path that does not
   exist in the tree.
2. **Dangling in-page anchors** — ``[text](#section)`` with no matching heading
   in the same file.
3. **Stale repository URLs** — absolute ``github.com`` links to an owner other
   than the canonical one, and ``blob``/``tree`` links whose path is missing
   from the tree. GitHub silently redirects renamed owners, so these rot
   invisibly until the redirect is dropped.

Absolute links are never fetched: the goal is a fast, hermetic gate, not an
uptime monitor.

Usage::

    python3 scripts/check_links.py            # exit non-zero on any problem
    python3 scripts/check_links.py --quiet    # only print problems

Importable: :func:`check` returns a list of problem strings so callers can fold
the result into a larger report.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote

CANONICAL_REPO = "acgs-ai/acgs-lite"
_BLOB_TREE_RE = re.compile(
    rf"https://github\.com/{re.escape(CANONICAL_REPO)}/(?:blob|tree)/main/([^\s)>\"'\]#]+)"
)
_MD_LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+[\"'][^\"']*[\"'])?\s*\)")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.M)
_FENCE_RE = re.compile(r"```.*?```", re.S)

# Directories that are generated, vendored, or intentionally full of placeholders.
_SKIP_DIRS = {
    ".git",
    ".mypy_cache",
    ".omc",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "planning",  # drafts and proposals; placeholders are expected here
    "site",
    "target",
    "venv",
    ".venv",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _markdown_files(root: Path) -> list[Path]:
    out = []
    for path in root.rglob("*.md"):
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        out.append(path)
    return sorted(out)


def _slug(heading: str) -> str:
    """Approximate GitHub's heading-to-anchor slugification."""
    text = re.sub(r"`", "", heading.strip().lower())
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"\s+", "-", text).strip("-")


def _link_targets(text: str) -> list[tuple[int, str]]:
    out = []
    for match in _MD_LINK_RE.finditer(text):
        target = match.group(1).strip()
        if target.startswith("<") and target.endswith(">"):
            target = target[1:-1]
        out.append((text[: match.start()].count("\n") + 1, target))
    return out


def check(root: Path | None = None) -> list[str]:
    """Return a list of human-readable link problems. Empty means clean."""
    root = root or repo_root()
    problems: list[str] = []

    for path in _markdown_files(root):
        rel = path.relative_to(root)
        text = path.read_text(encoding="utf-8")
        prose = _FENCE_RE.sub("", text)
        anchors = {_slug(m.group(2)) for m in _HEADING_RE.finditer(prose)}

        for lineno, target in _link_targets(prose):
            where = f"{rel}:{lineno}"

            if target.startswith("#"):
                if _slug(unquote(target[1:])) not in anchors:
                    problems.append(f"{where}: dangling anchor {target}")
                continue

            if target.startswith(("mailto:", "tel:", "data:")):
                continue

            if target.startswith(("http://", "https://")):
                # Owner drift is swept repo-wide below; here we only verify that
                # canonical blob/tree URLs still point at a path that exists.
                blob = _BLOB_TREE_RE.match(target)
                if blob and not (root / unquote(blob.group(1))).exists():
                    problems.append(f"{where}: repo URL points at a missing path -> {target}")
                continue

            if "://" in target or target.startswith("{"):
                continue

            file_part, _, anchor = target.partition("#")
            if not file_part:
                continue
            resolved = (path.parent / unquote(file_part)).resolve()
            if not resolved.exists():
                problems.append(f"{where}: dead relative link -> {target}")
                continue
            if anchor and resolved.suffix == ".md":
                other = _FENCE_RE.sub("", resolved.read_text(encoding="utf-8"))
                other_anchors = {_slug(m.group(2)) for m in _HEADING_RE.finditer(other)}
                if _slug(unquote(anchor)) not in other_anchors:
                    problems.append(f"{where}: dangling anchor -> {target}")

    # Stale-owner sweep over config and source too, not just Markdown.
    for pattern in ("*.md", "*.toml", "*.yml", "*.yaml", "*.py"):
        for path in root.rglob(pattern):
            if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for match in re.finditer(r"https://github\.com/([A-Za-z0-9_.-]+)/acgs-lite", text):
                owner = match.group(1)
                if owner != "acgs-ai":
                    lineno = text[: match.start()].count("\n") + 1
                    problems.append(
                        f"{path.relative_to(root)}:{lineno}: stale repository owner "
                        f"{owner!r} -- the canonical repository is {CANONICAL_REPO}"
                    )

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="only print problems")
    args = parser.parse_args(argv)

    problems = check()
    if problems:
        print(f"{len(problems)} link problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    if not args.quiet:
        print("All documentation links resolve.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
