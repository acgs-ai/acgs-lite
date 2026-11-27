# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs lean-smoke — validate the configured Lean runtime."""

from __future__ import annotations

import argparse
import json
import sys

from acgs_lite.lean_verify import run_lean_runtime_smoke_check


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the lean-smoke subcommand."""
    p = sub.add_parser(
        "lean-smoke",
        help="Run a minimal theorem through the configured Lean runtime",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Lean runtime timeout in seconds (default: 30)",
    )
    p.add_argument("--json", dest="json_out", action="store_true", help="JSON output")


def handler(args: argparse.Namespace) -> int:
    """Run a live Lean runtime smoke check."""
    result = run_lean_runtime_smoke_check(timeout_s=getattr(args, "timeout", 30))
    ok = bool(result.get("ok", False))

    if getattr(args, "json_out", False):
        print(json.dumps(result, indent=2))
        return 0 if ok else 1

    output = sys.stdout if ok else sys.stderr
    status = "PASS" if ok else "FAIL"
    print(f"Lean runtime smoke check: {status}", file=output)
    command = result.get("command", [])
    workdir = result.get("workdir", "")
    timeout_s = result.get("timeout_s", 30)
    print(f"  Command: {' '.join(command) if command else '(unresolved)'}", file=output)
    print(f"  Workdir: {workdir}", file=output)
    print(f"  Timeout: {timeout_s}s", file=output)

    errors = result.get("errors", [])
    if errors:
        print("  Errors:", file=output)
        for error in errors:
            print(f"    - {error}", file=output)

    return 0 if ok else 1
