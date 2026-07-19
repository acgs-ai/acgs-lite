# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs assess — run multi-framework compliance assessment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from acgs_lite.commands._helpers import cli_bar, load_system_description


def add_parser(sub: argparse._SubParsersAction) -> None:
    """Register the assess subcommand."""
    p = sub.add_parser("assess", help="Run multi-framework compliance assessment")
    p.add_argument(
        "--system-id", default=None, help="System identifier (default: current directory name)"
    )
    p.add_argument(
        "--jurisdiction",
        default=None,
        help="Jurisdiction (european_union, united_states, international, new_york_city)",
    )
    p.add_argument("--domain", default=None, help="Application domain (healthcare, lending, ...)")
    p.add_argument(
        "--framework",
        action="append",
        default=None,
        help="Specific framework(s) to assess (repeatable)",
    )


def handler(args: argparse.Namespace) -> int:
    """Run multi-framework compliance assessment."""
    from acgs_lite.compliance import MultiFrameworkAssessor

    desc = load_system_description(args)
    requested_fws: list[str] | None = desc.pop("_frameworks", None)

    assessor = MultiFrameworkAssessor(frameworks=requested_fws)
    report = assessor.assess(desc)

    print()
    print("  ACGS Compliance Assessment")
    print("  " + "=" * 50)
    print()
    print(f"  System:              {report.system_id}")
    print(f"  Overall Score:       {report.overall_score:.0%}")
    print(f"  ACGS Auto-Coverage:  {report.acgs_lite_total_coverage:.0%}")
    print(f"  Frameworks:          {', '.join(report.frameworks_assessed)}")
    print()

    for _fw_id, assessment in report.by_framework.items():
        score_bar = cli_bar(assessment.compliance_score)
        gap_count = len(assessment.gaps)
        label = f"  {assessment.framework_name}"
        print(f"{label:<42} {score_bar}  ({gap_count} gaps)")

    print()

    if report.cross_framework_gaps:
        print("  Cross-Framework Gaps:")
        for gap in report.cross_framework_gaps:
            short = gap[:100] + "..." if len(gap) > 100 else gap
            print(f"    ⚠  {short}")
        print()

    if report.recommendations:
        top = report.recommendations[:5]
        print("  Top Recommendations:")
        for i, rec in enumerate(top, 1):
            short = rec[:100] + "..." if len(rec) > 100 else rec
            print(f"    {i}. {short}")
        if len(report.recommendations) > 5:
            print(f"    ... and {len(report.recommendations) - 5} more (see full report)")
        print()

    if report.overall_score >= 0.8:
        print("  🟢 STRONG — Address remaining gaps, then request conformity assessment.")
    elif report.overall_score >= 0.5:
        print(
            "  🟡 MODERATE — Significant work remains before December 2, 2027 "
            "(Annex III stand-alone; deferred by the 2026 Digital Omnibus)."
        )
    else:
        print("  🔴 AT RISK — Major gaps. Immediate action required.")
    print()
    print("  → Generate full report: acgs report --pdf")
    print("  Indicative self-assessment only — not legal advice or a conformity assessment.")
    print()

    cache_path = Path(".acgs_assessment.json")
    cache_path.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")

    return 0
