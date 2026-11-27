# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs report — generate auditor-ready compliance report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from acgs_lite.commands._helpers import load_system_description


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the report subcommand."""
    p = sub.add_parser("report", help="Generate auditor-ready compliance report")
    p.add_argument("--pdf", action="store_true", default=True, help="PDF output (default)")
    p.add_argument("--markdown", "--md", action="store_true", help="Markdown output")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("-o", "--output", default=None, help="Output file path")
    p.add_argument("--system-id", default=None, help="System identifier")
    p.add_argument("--jurisdiction", default=None, help="Jurisdiction")
    p.add_argument("--domain", default=None, help="Application domain")
    p.add_argument("--framework", action="append", default=None, help="Specific framework(s)")


def handler(args: argparse.Namespace) -> int:
    """Generate auditor-ready compliance report (PDF, Markdown, or JSON)."""
    from acgs_lite.report import generate_report

    cache_path = Path(".acgs_assessment.json")
    if cache_path.exists():
        with cache_path.open(encoding="utf-8") as f:
            report_data = json.load(f)
    else:
        print("  No cached assessment found. Running assessment first...")
        print()
        from acgs_lite.compliance import MultiFrameworkAssessor

        desc = load_system_description(args)
        requested_fws: list[str] | None = desc.pop("_frameworks", None)
        assessor = MultiFrameworkAssessor(frameworks=requested_fws)
        report = assessor.assess(desc)
        report_data = report.to_dict()

    fmt = "pdf"
    if getattr(args, "markdown", False) or getattr(args, "md", False):
        fmt = "markdown"
    elif getattr(args, "json", False):
        fmt = "json"

    output = getattr(args, "output", None)
    if output:
        output_path = Path(output)
    else:
        system_id = report_data.get("system_id", "system")
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in system_id)
        output_path = Path(f"acgs_compliance_{safe_name}.{fmt if fmt != 'markdown' else 'md'}")

    try:
        result_path = generate_report(report_data, output_path, format=fmt)
        print()
        print(f"  ✅ Report generated: {result_path}")
        print(f"     Format: {fmt.upper()}")
        print(f"     System: {report_data.get('system_id', 'Unknown')}")
        print(f"     Score:  {report_data.get('overall_score', 0):.0%}")
        print()

        if fmt == "pdf":
            print("  This report is ready to share with your compliance officer.")
        elif fmt == "markdown":
            print("  Commit this report to your repository for audit trail.")

        print()
        return 0

    except ImportError as e:
        print()
        print(f"  ⚠  {e}")
        print()
        print("  To generate PDF reports:")
        print("    pip install fpdf2")
        print()
        return 0
