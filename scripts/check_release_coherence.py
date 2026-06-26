#!/usr/bin/env python3
"""Release-coherence guard for acgs-lite.

For a governance/security package, a version that is presented as *released* but
is not actually tagged (and therefore not reproducibly installable) is a trust
defect: claims attached to that version cannot be verified through the normal
``pip install`` + tag/audit path. This guard enforces a single invariant:

    If CHANGELOG.md presents a version as released (a dated ``## [X.Y.Z] - DATE``
    heading, where DATE is not "Unreleased"), then a matching ``vX.Y.Z`` git tag
    MUST exist.

By default the guard enforces this invariant only for ``pyproject.toml``'s
*current* version -- the exact 2.11.0-style drift where the repo claims a release
that has no tag, no PyPI artifact, and no GitHub Release behind it. This keeps the
check adoptable in CI without forcing a retroactive backfill of ancient,
never-tagged changelog history. Pass ``--strict-history`` to additionally fail on
every dated-but-untagged version.

Exit codes:
    0  coherent
    1  incoherence detected (dated-as-released version missing its git tag)
    2  usage / environment error (e.g. cannot read inputs)

Usage:
    python scripts/check_release_coherence.py
    python scripts/check_release_coherence.py --json
    python scripts/check_release_coherence.py --strict-history
    python scripts/check_release_coherence.py --no-require-current-tag
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

# Matches Keep-a-Changelog style headings, capturing version and the remainder.
#   ## [2.11.0] - 2026-05-31      -> released (dated)
#   ## [2.11.0] - Unreleased      -> not released
#   ## [Unreleased]               -> ignored (no version)
_HEADING_RE = re.compile(
    r"^##\s*\[(?P<version>\d+\.\d+\.\d+)\]\s*-\s*(?P<rest>.+?)\s*$",
    re.MULTILINE,
)
_VERSION_RE = re.compile(r'^version\s*=\s*"(?P<version>[^"]+)"', re.MULTILINE)
_UNRELEASED_RE = re.compile(r"unreleased|tbd|t\.b\.d\.|pending", re.IGNORECASE)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - environment error
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _current_version() -> str:
    match = _VERSION_RE.search(_read(PYPROJECT))
    if not match:
        print("error: could not find a version in pyproject.toml", file=sys.stderr)
        raise SystemExit(2)
    return match.group("version")


def _dated_changelog_versions() -> dict[str, str]:
    """Return {version: date_text} for versions presented as released."""
    released: dict[str, str] = {}
    for match in _HEADING_RE.finditer(_read(CHANGELOG)):
        rest = match.group("rest").strip()
        if _UNRELEASED_RE.search(rest):
            continue
        released[match.group("version")] = rest
    return released


def _existing_tags() -> set[str]:
    try:
        out = subprocess.run(
            ["git", "tag", "--list"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover
        print(f"error: could not list git tags: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    return {line.strip() for line in out.splitlines() if line.strip()}


def _tag_exists(version: str, tags: set[str]) -> bool:
    # Accept both ``vX.Y.Z`` and bare ``X.Y.Z`` tag conventions.
    return f"v{version}" in tags or version in tags


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    parser.add_argument(
        "--strict-history",
        action="store_true",
        help="also fail on every dated-but-untagged version, not just the current one",
    )
    parser.add_argument(
        "--no-require-current-tag",
        action="store_true",
        help="do not require pyproject's current version to be tagged",
    )
    args = parser.parse_args(argv)

    current = _current_version()
    released = _dated_changelog_versions()
    tags = _existing_tags()

    untagged_released = sorted(
        version for version in released if not _tag_exists(version, tags)
    )

    current_dated = current in released
    current_tagged = _tag_exists(current, tags)
    current_violation = (
        not args.no_require_current_tag and current_dated and not current_tagged
    )

    # Default scope: only the current version is enforced. --strict-history widens
    # enforcement to the full dated-but-untagged set.
    history_violations = untagged_released if args.strict_history else []
    coherent = not current_violation and not history_violations

    report = {
        "current_version": current,
        "current_dated_as_released": current_dated,
        "current_tagged": current_tagged,
        "released_in_changelog": released,
        "untagged_released_versions": untagged_released,
        "strict_history": args.strict_history,
        "coherent": coherent,
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if coherent:
            note = "" if args.strict_history else " (current-version scope)"
            print(f"OK: release state is coherent{note} (current {current}).")
        else:
            print("RELEASE INCOHERENCE DETECTED:")
            if current_violation:
                print(
                    f"  - pyproject version {current} is dated-as-released in "
                    f"CHANGELOG but has no v{current} tag. Either tag+publish it "
                    f"or move it under [Unreleased]."
                )
            for version in history_violations:
                if version == current:
                    continue
                print(
                    f"  - CHANGELOG presents {version} as released "
                    f"(dated {released[version]!r}) but no v{version} tag exists."
                )
            if untagged_released and not args.strict_history:
                others = [v for v in untagged_released if v != current]
                if others:
                    print(
                        f"  note: {len(others)} older dated-but-untagged "
                        f"version(s) exist; run with --strict-history to enforce."
                    )

    return 0 if coherent else 1


if __name__ == "__main__":
    raise SystemExit(main())
