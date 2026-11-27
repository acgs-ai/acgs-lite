# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs lint — lint governance rules for quality issues."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the lint subcommand."""
    p = sub.add_parser("lint", help="Lint governance rules for quality issues")
    p.add_argument(
        "rules",
        nargs="?",
        default="rules.yaml",
        help="Path to rules YAML file (default: rules.yaml)",
    )


def handler(args: argparse.Namespace) -> int:
    """Lint governance rules for quality issues."""
    from acgs_lite.constitution import Constitution
    from acgs_lite.constitution.policy_linter import PolicyLinter

    rules_path = Path(getattr(args, "rules", "rules.yaml"))
    if not rules_path.exists():
        print(f"  ❌ {rules_path} not found. Run 'acgs init' first.", file=sys.stderr)
        return 1

    constitution = Constitution.from_yaml(str(rules_path))
    linter = PolicyLinter()
    report = linter.lint_constitution(constitution)

    print()
    print(f"  ACGS Policy Linter — {rules_path}")
    print("  " + "=" * 50)
    print(f"  Rules checked: {report.rules_checked}")
    print(f"  Issues found:  {len(report.issues)}")
    print()

    if report.issues:
        for issue in report.issues:
            icon = {"error": "❌", "warning": "⚠️ ", "info": "ℹ️ "}.get(issue.severity.value, "?")
            rule_label = f" ({issue.rule_id})" if issue.rule_id else ""
            print(f"  {icon} {issue.code.value}{rule_label}: {issue.message}")
            if issue.suggestion:
                print(f"       → {issue.suggestion}")
        print()

    if report.passed:
        print("  ✅ Lint passed — no errors found.")
    else:
        error_count = len(report.errors)
        print(f"  ❌ Lint failed — {error_count} error(s) must be fixed.")

    print()
    return 0 if report.passed else 1
