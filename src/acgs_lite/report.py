# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""PDF and text report generation for ACGS compliance assessments.

Constitutional Hash: 608508a9bd224290

Generates auditor-ready compliance reports from MultiFrameworkReport
and EU AI Act ComplianceChecklist data. Outputs PDF (if fpdf2 is
available) or Markdown fallback.

Usage::

    from acgs_lite.report import generate_report
    generate_report(report_data, output_path="compliance_report.pdf")
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from acgs_lite._meta import CONSTITUTIONAL_HASH, VERSION
from acgs_lite.eu_ai_act import EU_AI_ACT_HIGH_RISK_DEADLINE

# Human-readable form of the canonical deadline constant, derived once so report
# text can't drift out of sync with acgs_lite.eu_ai_act.EU_AI_ACT_HIGH_RISK_DEADLINE.
_HIGH_RISK_DEADLINE_DT = datetime.strptime(EU_AI_ACT_HIGH_RISK_DEADLINE, "%Y-%m-%d")
_HIGH_RISK_DEADLINE_HUMAN = (
    f"{_HIGH_RISK_DEADLINE_DT:%B} {_HIGH_RISK_DEADLINE_DT.day}, {_HIGH_RISK_DEADLINE_DT:%Y}"
)
_HIGH_RISK_DEADLINE_NOTE = "Annex III stand-alone high-risk; deferred by the 2026 Digital Omnibus"


def _score_bar(score: float, width: int = 20) -> str:
    """Render a text progress bar for a 0.0-1.0 score."""
    filled = int(score * width)
    return f"[{'█' * filled}{'░' * (width - filled)}] {score:.0%}"


def _status_icon(status: str) -> str:
    """Map compliance status to a text icon."""
    icons = {
        "compliant": "✅",
        "partial": "🟡",
        "pending": "⬜",
        "non_compliant": "❌",
        "not_applicable": "➖",
    }
    return icons.get(status, "?")


def generate_markdown_report(report_data: dict[str, Any]) -> str:
    """Generate a Markdown compliance report from a MultiFrameworkReport dict.

    Args:
        report_data: Output of MultiFrameworkReport.to_dict().

    Returns:
        Markdown string.
    """
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append("# ACGS Compliance Assessment Report")
    lines.append("")
    lines.append(f"**System**: {report_data.get('system_id', 'Unknown')}")
    lines.append(f"**Generated**: {now}")
    lines.append(f"**Assessment Date**: {report_data.get('assessed_at', now)}")
    lines.append(f"**Constitutional Hash**: {CONSTITUTIONAL_HASH}")
    lines.append("")

    # Executive summary
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")

    overall = report_data.get("overall_score", 0.0)
    coverage = report_data.get("acgs_lite_total_coverage", 0.0)
    frameworks = report_data.get("frameworks_assessed", [])

    lines.append(f"**Overall Compliance Score**: {_score_bar(overall)}")
    lines.append(f"**ACGS Auto-Coverage**: {_score_bar(coverage)}")
    lines.append(f"**Frameworks Assessed**: {len(frameworks)}")
    lines.append("")

    if overall >= 0.8:
        lines.append(
            "> 🟢 **STRONG** — System shows strong compliance posture. "
            "Address remaining gaps before conformity assessment."
        )
    elif overall >= 0.5:
        lines.append(
            "> 🟡 **MODERATE** — System partially meets requirements. "
            "Significant work remains before the main EU AI Act high-risk obligations take effect."
        )
    else:
        lines.append(
            "> 🔴 **AT RISK** — System has major compliance gaps. "
            f"Immediate action required before {_HIGH_RISK_DEADLINE_HUMAN} "
            f"({_HIGH_RISK_DEADLINE_NOTE})."
        )
    lines.append("")

    # EU AI Act deadline warning
    lines.append("### ⚠️ Regulatory Deadline")
    lines.append("")
    lines.append(
        f"**EU AI Act main high-risk obligations take effect on {_HIGH_RISK_DEADLINE_HUMAN} "
        f"({_HIGH_RISK_DEADLINE_NOTE}).**"
    )
    lines.append(
        "Non-compliance penalties: up to **7% of global annual revenue** "
        "or **EUR 35 million**, whichever is higher."
    )
    lines.append("")

    # Framework breakdown
    lines.append("---")
    lines.append("")
    lines.append("## Framework-by-Framework Assessment")
    lines.append("")

    by_framework = report_data.get("by_framework", {})
    for fw_id, fw_data in by_framework.items():
        fw_name = fw_data.get("framework_name", fw_id)
        fw_score = fw_data.get("compliance_score", 0.0)
        fw_coverage = fw_data.get("acgs_lite_coverage", 0.0)

        lines.append(f"### {fw_name}")
        lines.append("")
        lines.append(f"**Compliance**: {_score_bar(fw_score)}")
        lines.append(f"**ACGS Auto-Coverage**: {_score_bar(fw_coverage)}")
        lines.append("")

        # Checklist items table
        items = fw_data.get("items", [])
        if items:
            lines.append("| Status | Requirement | ACGS Feature | Evidence |")
            lines.append("|--------|-------------|--------------|----------|")
            for item in items:
                status = _status_icon(item.get("status", "pending"))
                req = item.get("requirement", item.get("ref", ""))
                if len(req) > 80:
                    req = req[:77] + "..."
                feature = item.get("acgs_lite_feature") or "—"
                if len(feature) > 30:
                    feature = feature[:27] + "..."
                evidence = item.get("evidence") or "—"
                if len(evidence) > 40:
                    evidence = evidence[:37] + "..."
                lines.append(f"| {status} | {req} | {feature} | {evidence} |")
            lines.append("")

        # Gaps
        gaps = fw_data.get("gaps", [])
        if gaps:
            lines.append("**Gaps requiring attention:**")
            for gap in gaps:
                lines.append(f"- {gap}")
            lines.append("")

    # Cross-framework gaps
    cross_gaps = report_data.get("cross_framework_gaps", [])
    if cross_gaps:
        lines.append("---")
        lines.append("")
        lines.append("## Cross-Framework Gaps")
        lines.append("")
        lines.append(
            "These requirements appear across multiple frameworks. "
            "Addressing them closes compliance gaps simultaneously."
        )
        lines.append("")
        for i, gap in enumerate(cross_gaps, 1):
            lines.append(f"{i}. {gap}")
        lines.append("")

    # Recommendations
    recs = report_data.get("recommendations", [])
    if recs:
        lines.append("---")
        lines.append("")
        lines.append("## Prioritized Recommendations")
        lines.append("")
        for i, rec in enumerate(recs, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    # What ACGS covers
    lines.append("---")
    lines.append("")
    lines.append("## What ACGS Provides Automatically")
    lines.append("")
    lines.append("| Capability | EU AI Act Article | Status |")
    lines.append("|------------|-------------------|--------|")
    lines.append(
        "| Constitutional validation (optional Rust fast path)"
        " | Art. 9 Risk Management | ✅ Active |"
    )
    lines.append("| MACI separation of powers | Art. 14 Human Oversight | ✅ Active |")
    lines.append("| SHA-256 tamper-evident audit trail | Art. 12 Record-Keeping | ✅ Active |")
    lines.append("| Transparency disclosure generation | Art. 13 Transparency | ✅ Active |")
    lines.append("| Risk classification engine | Art. 9 Risk Management | ✅ Active |")
    lines.append("| Multi-framework compliance scoring | Art. 43 Conformity | ✅ Active |")
    lines.append("")

    # Disclaimer
    lines.append("---")
    lines.append("")
    lines.append("## Disclaimer")
    lines.append("")
    lines.append(
        "*This report is an indicative self-assessment generated by ACGS. "
        "It does not constitute legal advice. Consult qualified legal counsel "
        "for binding compliance opinions. The compliance scores reflect "
        "automated coverage by ACGS features and do not represent a formal "
        "conformity assessment under the EU AI Act.*"
    )
    lines.append("")
    lines.append(
        f"*Report generated by ACGS v{VERSION} — Constitutional Hash: {CONSTITUTIONAL_HASH}*"
    )
    lines.append("")

    return "\n".join(lines)


def generate_pdf_report(
    report_data: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Generate a PDF compliance report.

    Requires ``fpdf2`` (``pip install acgs-lite[pdf]`` or ``pip install fpdf2``).
    Falls back to Markdown + instruction if fpdf2 is unavailable.

    Args:
        report_data: Output of MultiFrameworkReport.to_dict().
        output_path: Path for the output PDF file.

    Returns:
        Path to the generated file.

    Raises:
        ImportError: If fpdf2 is not installed.
    """
    output = Path(output_path)

    try:
        from fpdf import FPDF  # type: ignore[import-untyped]
    except ImportError:
        # Fallback: write markdown + JSON
        md_path = output.with_suffix(".md")
        md_path.write_text(generate_markdown_report(report_data), encoding="utf-8")
        json_path = output.with_suffix(".json")
        json_path.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
        msg = (
            f"fpdf2 not installed. Written Markdown report to {md_path} "
            f"and JSON data to {json_path}.\n"
            f"Install fpdf2 for PDF output: pip install fpdf2"
        )
        raise ImportError(msg) from None

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    overall = report_data.get("overall_score", 0.0)
    coverage = report_data.get("acgs_lite_total_coverage", 0.0)
    frameworks = report_data.get("frameworks_assessed", [])
    by_framework = report_data.get("by_framework", {})

    def _safe(text: str) -> str:
        """Replace Unicode chars that Helvetica can't render."""
        return (
            text.replace("\u2014", "--")
            .replace("\u2013", "-")
            .replace("\u2018", "'")
            .replace("\u2019", "'")
            .replace("\u201c", '"')
            .replace("\u201d", '"')
            .replace("\u2026", "...")
            .replace("\u2022", "*")
            .replace("\u2713", "Y")
            .replace("\u2717", "X")
            .replace("\u2705", "[OK]")
            .replace("\u274c", "[FAIL]")
            .replace("\u2b1c", "[  ]")
            .replace("\u2796", "[-]")
            .replace("\u26a0\ufe0f", "[!]")
            .replace("\u26a0", "[!]")
            .replace("\u2728", "")
        )

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)

    # --- Cover page ---
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 28)
    pdf.cell(0, 40, text="", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 15, text="ACGS Compliance", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 15, text="Assessment Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 20, text="", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(
        0,
        8,
        text=_safe(f"System: {report_data.get('system_id', 'Unknown')}"),
        new_x="LMARGIN",
        new_y="NEXT",
        align="C",
    )
    pdf.cell(0, 8, text=f"Generated: {now}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(
        0,
        8,
        text=f"Constitutional Hash: {CONSTITUTIONAL_HASH}",
        new_x="LMARGIN",
        new_y="NEXT",
        align="C",
    )
    pdf.cell(0, 30, text="", new_x="LMARGIN", new_y="NEXT")

    # Score box
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, text="Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(
        0,
        8,
        text=f"Overall Compliance Score: {overall:.0%}",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.cell(
        0,
        8,
        text=f"ACGS Auto-Coverage: {coverage:.0%}",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.cell(
        0,
        8,
        text=f"Frameworks Assessed: {len(frameworks)} ({', '.join(frameworks)})",
        new_x="LMARGIN",
        new_y="NEXT",
    )

    pdf.cell(0, 10, text="", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 11)
    if overall >= 0.8:
        verdict = "STRONG - System shows strong compliance posture."
    elif overall >= 0.5:
        verdict = "MODERATE - Significant work remains before the main EU AI Act high-risk obligations take effect."
    else:
        verdict = "AT RISK - Major compliance gaps. Immediate action required."
    pdf.cell(0, 8, text=_safe(f"Verdict: {verdict}"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(0, 6, text="", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(
        0,
        6,
        text=(
            f"EU AI Act main high-risk obligations take effect {_HIGH_RISK_DEADLINE_HUMAN} "
            f"({_HIGH_RISK_DEADLINE_NOTE})."
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.cell(
        0,
        6,
        text="Penalties: up to 7% of global annual revenue or EUR 35M.",
        new_x="LMARGIN",
        new_y="NEXT",
    )

    # --- Framework pages ---
    for fw_id, fw_data in by_framework.items():
        pdf.add_page()
        fw_name = fw_data.get("framework_name", fw_id)
        fw_score = fw_data.get("compliance_score", 0.0)
        fw_cov = fw_data.get("acgs_lite_coverage", 0.0)

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, text=_safe(fw_name), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(
            0,
            7,
            text=f"Compliance: {fw_score:.0%}   |   ACGS Coverage: {fw_cov:.0%}",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.cell(0, 5, text="", new_x="LMARGIN", new_y="NEXT")

        # Items table
        items = fw_data.get("items", [])
        if items:
            # Header
            pdf.set_font("Helvetica", "B", 9)
            col_w = [15, 95, 40, 40]
            pdf.cell(col_w[0], 7, text="Status", border=1)
            pdf.cell(col_w[1], 7, text="Requirement", border=1)
            pdf.cell(col_w[2], 7, text="ACGS Feature", border=1)
            pdf.cell(col_w[3], 7, text="Evidence", border=1, new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Helvetica", "", 8)
            for item in items:
                status = _safe(item.get("status", "pending").upper()[:8])
                req = _safe(item.get("requirement", item.get("ref", ""))[:80])
                feature = _safe((item.get("acgs_lite_feature") or "-")[:30])
                evidence = _safe((item.get("evidence") or "-")[:30])

                # Check page break
                if pdf.get_y() > 260:
                    pdf.add_page()
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(col_w[0], 7, text="Status", border=1)
                    pdf.cell(col_w[1], 7, text="Requirement", border=1)
                    pdf.cell(col_w[2], 7, text="ACGS Feature", border=1)
                    pdf.cell(
                        col_w[3],
                        7,
                        text="Evidence",
                        border=1,
                        new_x="LMARGIN",
                        new_y="NEXT",
                    )
                    pdf.set_font("Helvetica", "", 8)

                pdf.cell(col_w[0], 6, text=status, border=1)
                pdf.cell(col_w[1], 6, text=req, border=1)
                pdf.cell(col_w[2], 6, text=feature, border=1)
                pdf.cell(
                    col_w[3],
                    6,
                    text=evidence,
                    border=1,
                    new_x="LMARGIN",
                    new_y="NEXT",
                )

        # Gaps
        gaps = fw_data.get("gaps", [])
        if gaps:
            pdf.cell(0, 5, text="", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, text="Gaps Requiring Attention:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            for gap in gaps[:10]:
                if pdf.get_y() > 270:
                    pdf.add_page()
                gap_text = gap[:120] if len(gap) > 120 else gap
                pdf.cell(0, 6, text=_safe(f"  - {gap_text}"), new_x="LMARGIN", new_y="NEXT")

    # --- Cross-framework gaps page ---
    cross_gaps = report_data.get("cross_framework_gaps", [])
    recs = report_data.get("recommendations", [])
    if cross_gaps or recs:
        pdf.add_page()
        if cross_gaps:
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(
                0,
                10,
                text="Cross-Framework Gaps",
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.set_font("Helvetica", "", 10)
            for i, gap in enumerate(cross_gaps, 1):
                gap_text = gap[:150] if len(gap) > 150 else gap
                pdf.multi_cell(0, 6, text=_safe(f"{i}. {gap_text}"))
                pdf.cell(0, 3, text="", new_x="LMARGIN", new_y="NEXT")

        if recs:
            pdf.cell(0, 8, text="", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(
                0,
                10,
                text="Prioritized Recommendations",
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.set_font("Helvetica", "", 10)
            for i, rec in enumerate(recs, 1):
                if pdf.get_y() > 265:
                    pdf.add_page()
                rec_text = rec[:180] if len(rec) > 180 else rec
                pdf.multi_cell(0, 6, text=_safe(f"{i}. {rec_text}"))
                pdf.cell(0, 2, text="", new_x="LMARGIN", new_y="NEXT")

    # --- Disclaimer page ---
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, text="Disclaimer", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "I", 9)
    pdf.multi_cell(
        0,
        5,
        text=(
            "This report is an indicative self-assessment generated by ACGS. "
            "It does not constitute legal advice. Consult qualified legal counsel "
            "for binding compliance opinions. The compliance scores reflect "
            "automated coverage by ACGS features and do not represent a formal "
            "conformity assessment under the EU AI Act.\n\n"
            "Regulation reference: Regulation (EU) 2024/1689.\n"
            f"Main high-risk obligations date: {_HIGH_RISK_DEADLINE_HUMAN} "
            f"({_HIGH_RISK_DEADLINE_NOTE}).\n"
            "Maximum penalty: 7% of global annual revenue or EUR 35 million.\n\n"
            f"Report generated by ACGS v{VERSION}\n"
            f"Constitutional Hash: {CONSTITUTIONAL_HASH}"
        ),
    )

    pdf.output(str(output))
    return output


def generate_report(
    report_data: dict[str, Any],
    output_path: str | Path = "acgs_compliance_report.pdf",
    *,
    format: str = "pdf",
) -> Path:
    """Generate a compliance report in the specified format.

    Args:
        report_data: Output of MultiFrameworkReport.to_dict().
        output_path: Destination file path.
        format: "pdf", "markdown", or "json".

    Returns:
        Path to the generated report file.
    """
    output = Path(output_path)

    if format == "json":
        output = output.with_suffix(".json")
        output.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
        return output

    if format == "markdown" or format == "md":
        output = output.with_suffix(".md")
        output.write_text(generate_markdown_report(report_data), encoding="utf-8")
        return output

    # PDF (default) — falls back to markdown+json if fpdf2 missing
    output = output.with_suffix(".pdf")
    try:
        return generate_pdf_report(report_data, output)
    except ImportError:
        # Fallback files already written by generate_pdf_report
        md_path = output.with_suffix(".md")
        if md_path.exists():
            return md_path
        # Last resort
        md_path.write_text(generate_markdown_report(report_data), encoding="utf-8")
        return md_path
