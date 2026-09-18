#!/usr/bin/env python3
"""Enforce aggregate coverage for execution-critical source paths."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "acgs_lite"


def _package_files(directory: str) -> set[str]:
    return {
        path.relative_to(PACKAGE).as_posix()
        for path in (PACKAGE / directory).rglob("*.py")
        if "__pycache__" not in path.parts
    }


CRITICAL_FILES = frozenset(
    {
        "audit.py",
        "governed.py",
        "lean_verify.py",
        "maci.py",
        "server.py",
        "trajectory.py",
        "constitution/lifecycle_service.py",
        "constitution/lifecycle_router.py",
        "constitution/sqlite_bundle_store.py",
    }
    | _package_files("engine")
    | _package_files("formal")
    | _package_files("legitimacy")
    | _package_files("maci")
)
GOVERNED_AUTH_FILES = frozenset({"governed.py"} | _package_files("legitimacy"))


def _aggregate(files: dict[str, object], required: frozenset[str]) -> tuple[int, int]:
    covered = 0
    statements = 0
    missing = []
    for relative in sorted(required):
        key = f"src/acgs_lite/{relative}"
        data = files.get(key)
        if not isinstance(data, dict) or not isinstance(data.get("summary"), dict):
            missing.append(key)
            continue
        summary = data["summary"]
        covered += int(summary.get("covered_lines", 0))
        statements += int(summary.get("num_statements", 0))
    if missing:
        raise ValueError("missing coverage data: " + ", ".join(missing))
    if statements == 0:
        raise ValueError("coverage group collected zero statements")
    return covered, statements


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: check_critical_coverage.py COVERAGE_JSON", file=sys.stderr)
        return 2
    try:
        payload = json.loads(Path(args[0]).read_text(encoding="utf-8"))
        files = payload["files"]
        if not isinstance(files, dict):
            raise ValueError("coverage report files must be an object")
        critical = _aggregate(files, CRITICAL_FILES)
        governed_auth = _aggregate(files, GOVERNED_AUTH_FILES)
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"coverage gate error: {exc}", file=sys.stderr)
        return 2

    failed = False
    for label, (covered, statements) in (
        ("critical", critical),
        ("governed+legitimacy", governed_auth),
    ):
        percent = covered * 100.0 / statements
        print(f"{label}={covered}/{statements} ({percent:.2f}%)")
        if percent < 90.0:
            print(f"{label} coverage is below 90.00%", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
