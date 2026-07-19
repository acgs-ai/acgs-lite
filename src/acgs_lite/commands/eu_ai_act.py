# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs eu-ai-act — one-shot EU AI Act compliance + report."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from acgs_lite.commands._helpers import cli_bar


def add_parser(sub: argparse._SubParsersAction) -> None:
    """Register the eu-ai-act subcommand."""
    p = sub.add_parser("eu-ai-act", help="One-shot EU AI Act compliance assessment + report")
    p.add_argument("--system-id", default=None, help="System identifier")
    p.add_argument("--domain", default=None, help="Application domain")
    p.add_argument("--markdown", "--md", action="store_true", help="Markdown output")
    p.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    p.add_argument("-o", "--output", default=None, help="Output file path")


def handler(args: argparse.Namespace) -> int:
    """One-shot EU AI Act compliance: assess + generate PDF report."""
    from acgs_lite.compliance import MultiFrameworkAssessor
    from acgs_lite.report import generate_report

    system_id = getattr(args, "system_id", None) or Path.cwd().name
    domain = getattr(args, "domain", None) or ""

    eu_frameworks = ["gdpr", "iso_42001", "oecd_ai"]
    if domain in ("healthcare", "medical"):
        eu_frameworks.append("hipaa_ai")

    desc: dict[str, Any] = {
        "system_id": system_id,
        "jurisdiction": "european_union",
        "domain": domain,
    }

    assessor = MultiFrameworkAssessor(frameworks=eu_frameworks)
    report = assessor.assess(desc)

    print()
    print("  EU AI Act Compliance Assessment")
    print("  " + "=" * 50)
    print(f"  System:            {report.system_id}")
    print(f"  Compliance Score:  {report.overall_score:.0%}")
    print(f"  ACGS Coverage:     {report.acgs_lite_total_coverage:.0%}")
    print(f"  Frameworks:        {', '.join(report.frameworks_assessed)}")
    print(
        "  Main obligations:  December 2, 2027 "
        "(Annex III stand-alone high-risk; deferred by the 2026 Digital Omnibus)"
    )
    print("  Max Penalty:       7% global revenue / EUR 35M")
    print()

    for _fw_id, assessment in report.by_framework.items():
        bar = cli_bar(assessment.compliance_score)
        gap_count = len(assessment.gaps)
        label = f"  {assessment.framework_name}"
        print(f"{label:<42} {bar}  ({gap_count} gaps)")

    print()

    from acgs_lite.eu_ai_act.compliance_checklist import ComplianceChecklist

    checklist = ComplianceChecklist(system_id=system_id)
    checklist.auto_populate_acgs_lite()

    print("  EU AI Act Article Checklist (High-Risk):")
    for item in checklist.items:
        icon = "✅" if item.status.value == "compliant" else "⬜"
        print(f"    {icon} {item.article_ref}: {item.requirement[:70]}...")

    print()
    print(f"  Gate Clear: {'✅ YES' if checklist.is_gate_clear else '❌ NO'}")
    print(f"  Checklist Score: {checklist.compliance_score:.0%}")
    print("  Indicative self-assessment only — not legal advice or a conformity assessment.")
    print()

    if checklist.blocking_gaps:
        print(
            "  Blocking Gaps (must resolve before December 2, 2027 main obligations — "
            "Annex III stand-alone; deferred by the 2026 Digital Omnibus):"
        )
        for gap in checklist.blocking_gaps:
            print(f"    ❌ {gap}")
        print()

    report_data = report.to_dict()
    report_data["eu_ai_act_checklist"] = checklist.generate_report()

    fmt = "pdf"
    if getattr(args, "markdown", False):
        fmt = "markdown"
    elif getattr(args, "json_out", False):
        fmt = "json"

    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in system_id)
    output_path = getattr(args, "output", None) or f"eu_ai_act_{safe_name}"

    try:
        result = generate_report(report_data, output_path, format=fmt)
        print(f"  ✅ Report generated: {result}")
        print()
        print(
            "  Attach this self-assessment to your conformity-assessment working file. "
            "It is not a compliance determination."
        )
        print()
    except ImportError as e:
        print(f"  ⚠  {e}")
        print("  Install fpdf2 for PDF: pip install acgs-lite[pdf]")
        print()

    return 0
