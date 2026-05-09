#!/usr/bin/env python3
"""Lint CLAUDE.md / AGENTS.md / docs markdown for broken refs and dup H2.

Checks:
  1. Inline-code path candidates that don't resolve on disk
  2. `bash <path>` / `python[3] <path>` command lines whose target is missing
  3. `make <target>` references absent from the repo Makefile
  4. Duplicate H2 headings within a single file

Allowlist: scripts/claude_md_lint_allowlist.txt (one entry per line; # comments).

Usage: python scripts/check_claude_md.py FILE [FILE ...]
Exit codes: 0 clean, 1 findings, 2 usage/error.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

INLINE_CODE = re.compile(r"`([^`\n]+)`")
FENCE = re.compile(r"^```")
H2 = re.compile(r"^## (.+?)\s*$")
CMD_BASH_PY = re.compile(r"^\s*(?:bash|python3?)\s+(\S+)", re.MULTILINE)
CMD_MAKE = re.compile(r"^\s*make\s+(\S+)", re.MULTILINE)
URL_SCHEME = re.compile(r"^[a-z]+://")
EXT_SUFFIX = re.compile(r"\.\w{1,5}$")
TARGET_DEF = re.compile(r"^([A-Za-z0-9_.-]+)\s*:")


def find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    for p in [cur, *cur.parents]:
        if (p / ".git").exists() or (p / "Makefile").is_file():
            return p
    return cur


def load_allowlist(repo_root: Path) -> set[str]:
    f = repo_root / "scripts" / "claude_md_lint_allowlist.txt"
    if not f.exists():
        return set()
    items: set[str] = set()
    for raw in f.read_text().splitlines():
        cleaned = raw.split("#", 1)[0].strip()
        if cleaned:
            items.add(cleaned)
    return items


def make_targets(repo_root: Path) -> set[str]:
    mk = repo_root / "Makefile"
    if not mk.is_file():
        return set()
    out: set[str] = set()
    for line in mk.read_text().splitlines():
        m = TARGET_DEF.match(line)
        if m and m.group(1) != ".PHONY":
            out.add(m.group(1))
    return out


def is_path_candidate(s: str) -> bool:
    s = s.strip()
    if not s or "<" in s or ">" in s or " " in s:
        return False
    if URL_SCHEME.match(s):
        return False
    if s.startswith(("~", "$")):
        return False
    # Slash commands like `/oh-my-claudecode:cancel`
    if s.startswith("/") and ":" in s:
        return False
    # Prose category prefix with one segment + trailing slash, no extension
    # (e.g., `feature/`, `acgs-lite/`, `govern-zone/`)
    body = s.rstrip("/")
    if body and "/" not in body and "." not in body and s.endswith("/"):
        return False
    # Bare single dot-extension example like `.dsl`, `.gitignore`
    if "/" not in s and s.startswith(".") and s.count(".") == 1:
        return False
    has_slash = "/" in s
    has_ext = bool(EXT_SUFFIX.search(s))
    starts_dotted = s.startswith(".")
    return has_slash or (has_ext and starts_dotted)


def resolve_path(repo_root: Path, md_dir: Path, raw: str) -> Path | None:
    cleaned = raw.strip().rstrip("/")
    if not cleaned:
        return None
    for base in (md_dir, repo_root):
        candidate = (base / cleaned).resolve()
        try:
            candidate.relative_to(repo_root)
        except ValueError:
            continue
        if candidate.exists():
            return candidate
    return None


def iter_inline_code(text: str):
    in_fence = False
    for line_no, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for m in INLINE_CODE.finditer(line):
            yield line_no, m.group(1)


def iter_h2(text: str):
    in_fence = False
    for line_no, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = H2.match(line)
        if m:
            yield line_no, m.group(1).strip()


def lint_file(
    path: Path,
    repo_root: Path,
    allowlist: set[str],
    targets: set[str],
) -> list[str]:
    findings: list[str] = []
    text = path.read_text()
    md_dir = path.parent

    for line_no, cand in iter_inline_code(text):
        if cand in allowlist or not is_path_candidate(cand):
            continue
        if resolve_path(repo_root, md_dir, cand) is None:
            findings.append(f"{path}:{line_no}: inline-code path not found: `{cand}`")

    for m in CMD_BASH_PY.finditer(text):
        cand = m.group(1)
        if cand.startswith("-") or cand in allowlist:
            continue
        if not (is_path_candidate(cand) or cand.endswith((".sh", ".py"))):
            continue
        if resolve_path(repo_root, md_dir, cand) is None:
            findings.append(f"{path}: command path not found: `{m.group(0).strip()}`")

    for m in CMD_MAKE.finditer(text):
        target = m.group(1)
        if target.startswith("-") or target in allowlist or not targets:
            continue
        if target not in targets:
            findings.append(f"{path}: make target not in Makefile: `make {target}`")

    seen: dict[str, list[int]] = {}
    for line_no, heading in iter_h2(text):
        seen.setdefault(heading, []).append(line_no)
    for heading, lines in seen.items():
        if len(lines) > 1:
            joined = ", ".join(str(n) for n in lines)
            findings.append(f"{path}: duplicate H2 `## {heading}` at lines {joined}")

    return findings


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_claude_md.py FILE [FILE ...]", file=sys.stderr)
        return 2

    files = [Path(a).resolve() for a in argv[1:]]
    repo_root = find_repo_root(files[0].parent if files else Path.cwd())
    allowlist = load_allowlist(repo_root)
    targets = make_targets(repo_root)

    rc = 0
    for f in files:
        if not f.exists():
            print(f"ERROR: file not found: {f}", file=sys.stderr)
            rc = 1
            continue
        findings = lint_file(f, repo_root, allowlist, targets)
        if findings:
            rc = 1
            try:
                rel = f.relative_to(repo_root)
            except ValueError:
                rel = f
            print(f"\n# {rel}")
            for line in findings:
                print(f"  - {line}")

    if rc == 0:
        print("OK: no broken refs or duplicate H2 headings")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
