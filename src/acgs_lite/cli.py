# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""CLI for ACGS — constitutional governance for AI agents.

Constitutional Hash: 608508a9bd224290

Commands:
    acgs init                   Scaffold rules.yaml + CI governance job
    acgs assess                 Run multi-framework compliance assessment
    acgs report [--pdf|--md]    Generate auditor-ready compliance report
    acgs eu-ai-act              One-shot EU AI Act compliance + PDF
    acgs lint                   Lint governance rules for quality issues
    acgs test                   Run governance test fixtures
    acgs lifecycle              Manage policy promotion lifecycle
    acgs refusal                Explain governance denials + suggest alternatives
    acgs observe                Export governance telemetry summary / Prometheus
    acgs otel                   Export OpenTelemetry-compatible governance telemetry
    acgs halt --system-id X     Halt all governed agents (Article 14 kill-switch)
    acgs resume --system-id X   Resume governed agents after halt
    acgs breaker-status --id X  Check circuit breaker status
    acgs evidence               Collect compliance evidence from runtime + filesystem
    acgs arckit                 Bridge arc-kit artifacts into ACGS governance
    acgs policygen generate     Generate adaptive governance policy YAML
    acgs policygen scan         Scan dependency manifests for governance risk evidence
    acgs lean-smoke             Validate Lean runtime/toolchain configuration
    acgs restore --bundle-id ID --backup-path PATH
                                Restore active constitution from hot-backup + re-validate
    acgs activate <key>         Store license key
    acgs status                 Show current license tier and features
    acgs verify                 Validate license key integrity only
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from acgs_lite.commands import (
    arckit,
    assess,
    capabilities,
    eu_ai_act,
    eval_cmd,
    evidence,
    halt,
    init,
    lean_smoke,
    lifecycle,
    lint,
    observe,
    observe_session,
    policygen,
    refusal,
    report,
    restore,
    test_cmd,
)
from acgs_lite.commands._helpers import cli_bar as _cli_bar  # noqa: F401
from acgs_lite.commands._helpers import (
    load_system_description as _load_system_description,  # noqa: F401
)
from acgs_lite.commands.observe import _post_otlp_json  # noqa: F401
from acgs_lite.licensing import (
    LicenseError,
    LicenseExpiredError,
    LicenseManager,
    Tier,
    _write_license_file,
    validate_license_key,
)

# ---------------------------------------------------------------------------
# Re-exports for backward compatibility (tests import from acgs_lite.cli)
# ---------------------------------------------------------------------------

cmd_init = init.handler
cmd_arckit = arckit.handler
cmd_assess = assess.handler
cmd_capabilities = capabilities.handler
cmd_eval = eval_cmd.handler
cmd_report = report.handler
cmd_eu_ai_act = eu_ai_act.handler
cmd_lint = lint.handler
cmd_test = test_cmd.handler
cmd_lifecycle = lifecycle.handler
cmd_refusal = refusal.handler
cmd_observe = observe.cmd_observe
cmd_otel = observe.cmd_otel
cmd_observe_session = observe_session.run
cmd_halt = halt.cmd_halt
cmd_resume = halt.cmd_resume
cmd_breaker_status = halt.cmd_breaker_status
cmd_evidence = evidence.handler
cmd_lean_smoke = lean_smoke.handler
cmd_restore = restore.cmd_restore
cmd_policygen = policygen.handler


# ---------------------------------------------------------------------------
# License commands (kept here because tests patch acgs_lite.cli.validate_license_key)
# ---------------------------------------------------------------------------


def cmd_activate(args: argparse.Namespace) -> int:
    """Store a license key."""
    key: str = args.key.strip()
    try:
        info = validate_license_key(key)
    except LicenseExpiredError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except LicenseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    _write_license_file(key)
    print(f"License activated: {info.tier.name}")
    _print_license_info(info)
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    """Show current license tier and features."""
    manager = LicenseManager()
    try:
        info = manager.load()
    except LicenseExpiredError as exc:
        print(f"Warning: {exc}", file=sys.stderr)
        import os

        from acgs_lite.licensing import _read_license_file

        key = os.environ.get("ACGS_LICENSE_KEY") or _read_license_file()
        if key:
            try:
                info = validate_license_key.__wrapped__(key)  # type: ignore[attr-defined]
            except (ValueError, TypeError, AttributeError):
                print("Could not parse license key.", file=sys.stderr)
                return 1
        else:
            return 1
    except LicenseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("acgs License Status")
    print("=" * 40)
    _print_license_info(info)

    if info.tier == Tier.FREE:
        print()
        print("  → Upgrade to Pro for EU AI Act compliance:")
        print("    https://acgs.ai/pricing")

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Validate a license key."""
    from acgs_lite.licensing import _read_license_file

    key_arg: str | None = getattr(args, "key", None)
    key: str | None

    if key_arg:
        key = key_arg.strip()
    else:
        import os

        env_key = os.environ.get("ACGS_LICENSE_KEY")
        key = env_key if env_key is not None else _read_license_file()

    if not key:
        print("No license key found. Run 'acgs activate <key>' first.", file=sys.stderr)
        return 1

    print(f"Verifying key: {key[:20]}...")
    try:
        info = validate_license_key(key)
        print("✓ Key is valid.")
        _print_license_info(info)
        return 0
    except LicenseExpiredError as exc:
        print(f"✗ Key is EXPIRED: {exc}", file=sys.stderr)
        return 1
    except LicenseError as exc:
        print(f"✗ Key is INVALID: {exc}", file=sys.stderr)
        return 1


def _print_license_info(info: Any) -> None:
    """Print license info in a formatted way."""
    print(f"  Tier:    {_fmt_tier_badge(info.tier)}")
    if info.expiry_date:
        print(f"  Expiry:  {info.expiry_date}")
    else:
        print("  Expiry:  none (perpetual)")
    print()
    print("  Features:")
    for feature in info.features:
        print(f"    • {feature}")


def _fmt_tier_badge(tier: Any) -> str:
    """Format a license tier as a display badge."""
    badges: dict[Tier, str] = {
        Tier.FREE: "FREE",
        Tier.PRO: "PRO ✓",
        Tier.TEAM: "TEAM ✓",
        Tier.ENTERPRISE: "ENTERPRISE ✓",
    }
    if isinstance(tier, Tier):
        return badges[tier]
    return str(getattr(tier, "name", tier))


# Backward-compat alias (used by test_coverage_batch_j.py)
_print_info = _print_license_info


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _add_license_parsers(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register activate, status, and verify subcommands."""
    p_activate = sub.add_parser("activate", help="Store a license key")
    p_activate.add_argument("key", help="License key (ACGS-{TIER}-...)")

    sub.add_parser("status", help="Show current license tier and features")

    p_verify = sub.add_parser("verify", help="Validate license key integrity only")
    p_verify.add_argument("--key", help="Key to verify (default: currently loaded key)")


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="acgs",
        description="ACGS — Constitutional governance for AI agents",
        epilog="EU AI Act main high-risk obligations: August 2, 2026 | https://acgs.ai",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init.add_parser(sub)
    arckit.add_parser(sub)
    assess.add_parser(sub)
    capabilities.add_parser(sub)
    eval_cmd.add_parser(sub)
    report.add_parser(sub)
    eu_ai_act.add_parser(sub)
    _add_license_parsers(sub)
    lint.add_parser(sub)
    test_cmd.add_parser(sub)
    lifecycle.add_parser(sub)
    refusal.add_parser(sub)
    observe.add_parser(sub)
    observe_session.add_parser(sub)
    halt.add_parser(sub)
    evidence.add_parser(sub)
    lean_smoke.add_parser(sub)
    restore.add_parser(sub)
    policygen.add_parser(sub)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_COMMAND_MAP: dict[str, str] = {
    "init": "cmd_init",
    "arckit": "cmd_arckit",
    "assess": "cmd_assess",
    "capabilities": "cmd_capabilities",
    "eval": "cmd_eval",
    "report": "cmd_report",
    "eu-ai-act": "cmd_eu_ai_act",
    "lint": "cmd_lint",
    "test": "cmd_test",
    "lifecycle": "cmd_lifecycle",
    "refusal": "cmd_refusal",
    "observe": "cmd_observe",
    "otel": "cmd_otel",
    "observe-session": "cmd_observe_session",
    "activate": "cmd_activate",
    "status": "cmd_status",
    "verify": "cmd_verify",
    "halt": "cmd_halt",
    "resume": "cmd_resume",
    "breaker-status": "cmd_breaker_status",
    "evidence": "cmd_evidence",
    "lean-smoke": "cmd_lean_smoke",
    "restore": "cmd_restore",
    "policygen": "cmd_policygen",
}


def main() -> None:
    """CLI entry point."""
    import acgs_lite.cli as _self

    parser = build_parser()
    args = parser.parse_args()

    handler_name = _COMMAND_MAP.get(args.command)
    if handler_name is None:
        parser.print_help()
        sys.exit(1)

    handler = getattr(_self, handler_name)
    sys.exit(handler(args))


if __name__ == "__main__":
    main()
