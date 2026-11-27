# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs evidence — collect and report compliance evidence.

Runs all evidence collectors (imports, filesystem, environment, audit log)
and outputs a machine-readable evidence bundle.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the evidence subcommand."""
    p = sub.add_parser(
        "evidence",
        help="Collect compliance evidence from runtime and filesystem",
    )
    p.add_argument(
        "--system-id",
        default=None,
        help="System identifier (default: current directory name)",
    )
    p.add_argument(
        "--audit-log",
        default=None,
        help="Path to JSONL audit log file for runtime evidence",
    )
    p.add_argument(
        "--format",
        choices=["json", "summary", "table"],
        default="summary",
        help="Output format (default: summary)",
    )
    p.add_argument(
        "--output",
        "-o",
        default=None,
        help="Write output to file instead of stdout",
    )


def handler(args: argparse.Namespace) -> int:
    """Collect and report compliance evidence."""
    from acgs_lite.compliance.evidence import collect_evidence

    system_id = args.system_id or Path.cwd().name
    desc = {"system_id": system_id}

    # Load audit log if specified
    audit_log = None
    if args.audit_log:
        audit_path = Path(args.audit_log)
        if not audit_path.exists():
            print(f"Audit log not found: {audit_path}", file=sys.stderr)
            return 1
        from acgs_lite.audit import AuditLog, JSONLAuditBackend

        backend = JSONLAuditBackend(audit_path)
        audit_log = AuditLog.from_backend(backend)
        print(
            f"Loaded {len(audit_log)} audit entries from {audit_path}",
            file=sys.stderr,
        )

    bundle = collect_evidence(desc, audit_log=audit_log)

    if args.format == "json":
        output = json.dumps(bundle.to_dict(), indent=2)
    elif args.format == "table":
        output = _format_table(bundle)
    else:
        output = _format_summary(bundle)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Evidence written to {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0


def _format_summary(bundle: object) -> str:
    """Format evidence bundle as human-readable summary."""
    lines = [
        f"Evidence Report: {getattr(bundle, 'system_id', 'unknown')}",
        f"Collected at: {getattr(bundle, 'collected_at', 'unknown')}",
        f"Total items: {len(getattr(bundle, 'items', ()))}",
        "",
    ]

    summary = bundle.summary() if hasattr(bundle, "summary") else {}
    if summary:
        lines.append("By framework:")
        for fw_id, count in sorted(summary.items()):
            lines.append(f"  {fw_id}: {count} items")
    else:
        lines.append("No evidence collected.")

    return "\n".join(lines)


def _format_table(bundle: object) -> str:
    """Format evidence bundle as a table."""
    items = getattr(bundle, "items", ())
    if not items:
        return "No evidence items collected."

    lines = [
        f"{'Framework':<20} {'Article':<25} {'Source':<35} {'Confidence':<10}",
        "-" * 90,
    ]
    for item in items:
        refs = ", ".join(item.article_refs) if item.article_refs else "-"
        lines.append(
            f"{item.framework_id:<20} {refs:<25} {item.source:<35} {item.confidence:<10.2f}"
        )

    return "\n".join(lines)
