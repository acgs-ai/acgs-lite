"""Standalone compliance CLI for acgs-lite.

Run as a module::

    python -m acgs_lite.compliance assess --jurisdiction european_union
    python -m acgs_lite.compliance assess --domain hiring --format markdown
    python -m acgs_lite.compliance frameworks
    python -m acgs_lite.compliance evidence --system-id my-ai
    python -m acgs_lite.compliance frameworks --json

Subcommands:

    assess          Run multi-framework compliance assessment
    frameworks      List all available frameworks
    evidence        Collect runtime / filesystem / env-var evidence

The ``assess`` subcommand supports every system-description flag including
the EU AI Act conditional-scope flags (``--risk-tier``, ``--is-gpai``) and
jurisdiction-specific flags (``--is-significant-entity`` for DORA,
``--is-significant-data-fiduciary`` for India DPDP, etc.).

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _bar(score: float, width: int = 20) -> str:
    filled = int(score * width)
    return f"[{'█' * filled}{'░' * (width - filled)}] {score:.0%}"


def _build_system_description(args: argparse.Namespace) -> dict[str, Any]:
    """Translate parsed CLI args to a system_description dict."""
    desc: dict[str, Any] = {}

    # Core fields
    if getattr(args, "system_id", None):
        desc["system_id"] = args.system_id
    else:
        desc["system_id"] = Path.cwd().name

    if getattr(args, "jurisdiction", None):
        desc["jurisdiction"] = args.jurisdiction

    if getattr(args, "domain", None):
        desc["domain"] = args.domain

    # EU AI Act tier (explicit; auto-inferred from domain if omitted)
    if getattr(args, "risk_tier", None):
        desc["risk_tier"] = args.risk_tier

    if getattr(args, "is_gpai", False):
        desc["is_gpai"] = True

    # DORA
    if getattr(args, "is_significant_entity", False):
        desc["is_significant_entity"] = True

    # India DPDP
    if getattr(args, "is_significant_data_fiduciary", False):
        desc["is_significant_data_fiduciary"] = True

    if getattr(args, "processes_children_data", False):
        desc["processes_children_data"] = True

    # China AI
    if getattr(args, "is_generative_ai", False):
        desc["is_generative_ai"] = True

    return desc


# ---------------------------------------------------------------------------
# assess
# ---------------------------------------------------------------------------


def cmd_assess(args: argparse.Namespace) -> int:
    from acgs_lite.compliance import MultiFrameworkAssessor
    from acgs_lite.compliance.eu_ai_act import infer_risk_tier

    desc = _build_system_description(args)
    frameworks: list[str] | None = getattr(args, "framework", None) or None

    assessor = MultiFrameworkAssessor(frameworks=frameworks)
    report = assessor.assess(desc)

    fmt: str = getattr(args, "format", "text") or "text"

    if fmt == "json":
        print(json.dumps(report.to_dict(), indent=2, default=str))
        return 0

    if fmt == "markdown":
        from acgs_lite.compliance import ComplianceReportExporter

        exporter = ComplianceReportExporter(report)
        output = getattr(args, "output", None)
        if output:
            exporter.to_markdown_file(Path(output))
            print(f"Report written to {output}", file=sys.stderr)
        else:
            print(exporter.to_markdown())
        return 0

    # ------ plain text (default) ------
    inferred_tier = infer_risk_tier(desc)
    tier_note = "" if desc.get("risk_tier") else " (auto-inferred from domain)"

    print()
    print("  ACGS Compliance Assessment")
    print("  " + "=" * 52)
    print(f"  System:              {report.system_id}")
    print(f"  Jurisdiction:        {desc.get('jurisdiction', '(all)')}")
    print(f"  Domain:              {desc.get('domain', '(general)')}")
    if "eu_ai_act" in report.frameworks_assessed:
        print(f"  EU AI Act tier:      {inferred_tier}{tier_note}")
    print(f"  Overall Score:       {report.overall_score:.0%}")
    print(f"  ACGS Auto-Coverage:  {report.acgs_lite_total_coverage:.0%}")
    print(f"  Frameworks assessed: {len(report.frameworks_assessed)}")
    print()

    for fw_id in report.frameworks_assessed:
        assessment = report.by_framework[fw_id]
        bar = _bar(assessment.compliance_score)
        gap_count = len(assessment.gaps)
        label = f"  {assessment.framework_name}"
        print(f"{label:<48} {bar}  ({gap_count} gaps)")

    print()

    if report.cross_framework_gaps:
        print("  Cross-Framework Gaps:")
        for gap in report.cross_framework_gaps[:8]:
            short = gap[:96] + "…" if len(gap) > 96 else gap
            print(f"    ⚠  {short}")
        extra = len(report.cross_framework_gaps) - 8
        if extra > 0:
            print(f"    … and {extra} more (use --format markdown for full report)")
        print()

    if report.recommendations:
        top = report.recommendations[:5]
        print("  Top Recommendations:")
        for i, rec in enumerate(top, 1):
            short = rec[:96] + "…" if len(rec) > 96 else rec
            print(f"    {i}. {short}")
        if len(report.recommendations) > 5:
            print(f"    … and {len(report.recommendations) - 5} more")
        print()

    if report.overall_score >= 0.8:
        print("  🟢 STRONG — Address remaining gaps, then request conformity assessment.")
    elif report.overall_score >= 0.5:
        print("  🟡 MODERATE — Significant work remains.")
    else:
        print("  🔴 AT RISK — Major gaps. Immediate action required.")
    print("  Indicative self-assessment only — not legal advice or a conformity assessment.")
    print()

    output = getattr(args, "output", None)
    if output:
        from acgs_lite.compliance import ComplianceReportExporter

        out_path = Path(output)
        suffix = out_path.suffix.lower()
        exporter = ComplianceReportExporter(report)
        if suffix == ".md":
            exporter.to_markdown_file(out_path)
        elif suffix == ".json":
            exporter.to_json_file(out_path)
        else:
            exporter.to_text_file(out_path)
        print(f"  Report written to: {output}")
        print()

    return 0


# ---------------------------------------------------------------------------
# frameworks
# ---------------------------------------------------------------------------


def cmd_frameworks(args: argparse.Namespace) -> int:
    from acgs_lite.compliance.multi_framework import _FRAMEWORK_REGISTRY

    as_json: bool = getattr(args, "json", False)

    rows = []
    for fw_id, cls in sorted(_FRAMEWORK_REGISTRY.items()):
        instance = cls()
        rows.append(
            {
                "id": fw_id,
                "name": getattr(instance, "framework_name", fw_id),
                "jurisdiction": getattr(instance, "jurisdiction", ""),
                "status": getattr(instance, "status", ""),
                "enforcement_date": getattr(instance, "enforcement_date", None),
            }
        )

    if as_json:
        print(json.dumps(rows, indent=2))
        return 0

    print()
    print(f"  Available compliance frameworks ({len(rows)})")
    print("  " + "=" * 60)
    print(f"  {'ID':<28}  {'Status':<10}  {'Jurisdiction'}")
    print("  " + "-" * 60)
    for r in rows:
        enf = f"  [{r['enforcement_date']}]" if r["enforcement_date"] else ""
        print(f"  {r['id']:<28}  {r['status']:<10}  {r['jurisdiction']}{enf}")
    print()
    return 0


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------


def cmd_evidence(args: argparse.Namespace) -> int:
    from acgs_lite.compliance.evidence import collect_evidence

    search_root_str: str | None = getattr(args, "search_root", None)
    search_root = Path(search_root_str) if search_root_str else None
    desc: dict[str, Any] = {"system_id": getattr(args, "system_id", None) or Path.cwd().name}
    if getattr(args, "jurisdiction", None):
        desc["jurisdiction"] = args.jurisdiction

    bundle = collect_evidence(desc, search_root=search_root)

    as_json: bool = getattr(args, "json", False)
    if as_json:
        print(json.dumps(bundle.to_dict(), indent=2))
        return 0

    summary = bundle.summary()
    print()
    print(f"  Evidence Collection — {bundle.system_id}")
    print("  " + "=" * 52)
    print(f"  Collected at:  {bundle.collected_at}")
    print(f"  Total items:   {len(bundle.items)}")
    print()

    if not bundle.items:
        print("  No evidence found.")
        print("  Tips:")
        print("    • Add rules.yaml or governance.yaml to your project root")
        print("    • Set ACGS_AUDIT_ENABLED=true")
        print("    • Install acgs-lite and use AuditLog, GovernanceEngine")
        print()
        return 0

    print("  Items by framework:")
    for fw_id, count in sorted(summary.items(), key=lambda x: -x[1]):
        print(f"    {fw_id:<30} {count} item(s)")
    print()

    show_fw: str | None = getattr(args, "framework", None)
    if show_fw:
        items = bundle.for_framework(show_fw)
        print(f"  Evidence for {show_fw}:")
        for item in items:
            refs = ", ".join(item.article_refs)
            print(f"    [{item.confidence:.0%}] {item.source}")
            print(f"          {item.description[:80]}")
            print(f"          → {refs}")
        print()

    return 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m acgs_lite.compliance",
        description="ACGS compliance module — assess, list frameworks, collect evidence",
        epilog=(
            "EU AI Act main high-risk obligations: December 2, 2027 "
            "(Annex III stand-alone high-risk; deferred by the 2026 Digital Omnibus) | "
            "https://acgs.ai"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- assess ----
    p_assess = sub.add_parser(
        "assess",
        help="Run multi-framework compliance assessment",
    )
    p_assess.add_argument(
        "--system-id",
        dest="system_id",
        default=None,
        help="System identifier (default: current dir name)",
    )
    p_assess.add_argument(
        "--jurisdiction",
        default=None,
        help="Jurisdiction: european_union, united_states, "
        "canada, united_kingdom, singapore, india, "
        "australia, brazil, china, california, international",
    )
    p_assess.add_argument(
        "--domain",
        default=None,
        help="Domain: healthcare, hiring, financial, lending, "
        "education, chatbot, content_generation, ...",
    )
    p_assess.add_argument(
        "--framework",
        action="append",
        default=None,
        dest="framework",
        help="Specific framework ID (repeatable)",
    )
    p_assess.add_argument(
        "-o", "--output", default=None, help="Write report to file (.md / .json / .txt)"
    )
    p_assess.add_argument(
        "--format",
        choices=["text", "markdown", "json"],
        default="text",
        help="Output format (default: text)",
    )

    # EU AI Act flags
    eu_group = p_assess.add_argument_group("EU AI Act")
    eu_group.add_argument(
        "--risk-tier",
        dest="risk_tier",
        choices=["unacceptable", "high", "limited", "minimal"],
        default=None,
        help="Override risk tier (default: auto-inferred from domain)",
    )
    eu_group.add_argument(
        "--is-gpai",
        dest="is_gpai",
        action="store_true",
        help="System is a General-Purpose AI model (Arts. 53/55)",
    )

    # DORA flags
    dora_group = p_assess.add_argument_group("DORA")
    dora_group.add_argument(
        "--is-significant-entity",
        dest="is_significant_entity",
        action="store_true",
        help="Significant financial entity (TLPT Art.26(1) applies)",
    )

    # India DPDP flags
    dpdp_group = p_assess.add_argument_group("India DPDP")
    dpdp_group.add_argument(
        "--is-significant-data-fiduciary",
        dest="is_significant_data_fiduciary",
        action="store_true",
        help="System is a Significant Data Fiduciary (§16 applies)",
    )
    dpdp_group.add_argument(
        "--processes-children-data",
        dest="processes_children_data",
        action="store_true",
        help="System processes children's personal data (§9 applies)",
    )

    # China AI flags
    china_group = p_assess.add_argument_group("China AI")
    china_group.add_argument(
        "--is-generative-ai",
        dest="is_generative_ai",
        action="store_true",
        help="System provides generative AI (GenAI regs apply)",
    )

    # ---- frameworks ----
    p_fws = sub.add_parser(
        "frameworks",
        help="List all available compliance frameworks",
    )
    p_fws.add_argument("--json", action="store_true", help="JSON output")

    # ---- evidence ----
    p_ev = sub.add_parser(
        "evidence",
        help="Collect runtime / filesystem / environment evidence",
    )
    p_ev.add_argument("--system-id", dest="system_id", default=None, help="System identifier")
    p_ev.add_argument("--jurisdiction", default=None, help="Jurisdiction (for context)")
    p_ev.add_argument(
        "--search-root",
        dest="search_root",
        default=None,
        help="Directory to scan for artefacts (default: cwd)",
    )
    p_ev.add_argument("--framework", default=None, help="Show detailed items for this framework ID")
    p_ev.add_argument("--json", action="store_true", help="JSON output")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "assess": cmd_assess,
        "frameworks": cmd_frameworks,
        "evidence": cmd_evidence,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
