# requires: acgs-lite[gitlab], GITLAB_TOKEN, GITLAB_PROJECT_ID, --mr-iid, network
"""GitLab MR Governance Demo — ACGS + GitLab AI Hackathon

Runs constitutional governance validation on a GitLab merge request:
  1. Loads governance rules from a YAML constitution
  2. Validates MR title, description, and code diffs against every rule
  3. Posts a formatted governance report as an MR comment
  4. Posts inline comments on lines that triggered violations
  5. Enforces MACI separation of powers (author != approver)
  6. Approves or blocks the MR based on the outcome

Usage:

    # Minimal (env vars for secrets):
    export GITLAB_TOKEN="glpat-..."
    export GITLAB_PROJECT_ID="12345"
    python gitlab_mr_governance.py --mr-iid 42

    # Explicit flags:
    python gitlab_mr_governance.py \
        --gitlab-url https://gitlab.com \
        --token glpat-... \
        --project-id 12345 \
        --mr-iid 42 \
        --constitution constitution.yaml

    # Dry-run (validate only, no comments posted):
    python gitlab_mr_governance.py --mr-iid 42 --dry-run

Requirements:
    pip install acgs-lite[gitlab]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from acgs_lite import Constitution
from acgs_lite.integrations.gitlab import (
    GitLabGovernanceBot,
    GitLabMACIEnforcer,
    GovernanceReport,
    format_governance_report,
)

logger = logging.getLogger(__name__)

# Default constitution lives next to this script
_DEFAULT_CONSTITUTION = str(Path(__file__).parent / "constitution.yaml")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run ACGS constitutional governance on a GitLab merge request.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Environment variable fallbacks:\n"
            "  GITLAB_TOKEN       Personal access token (read_api + api scopes)\n"
            "  GITLAB_PROJECT_ID  Numeric project ID\n"
            "  GITLAB_URL         Base API URL (default: https://gitlab.com/api/v4)\n"
        ),
    )
    parser.add_argument(
        "--gitlab-url",
        default=os.environ.get("GITLAB_URL", "https://gitlab.com/api/v4"),
        help="GitLab API base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("GITLAB_TOKEN"),
        help="GitLab personal access token (or set GITLAB_TOKEN env var)",
    )
    parser.add_argument(
        "--project-id",
        type=int,
        default=_env_int("GITLAB_PROJECT_ID"),
        help="GitLab project ID (or set GITLAB_PROJECT_ID env var)",
    )
    parser.add_argument(
        "--mr-iid",
        type=int,
        required=True,
        help="Merge request internal ID to validate",
    )
    parser.add_argument(
        "--constitution",
        default=_DEFAULT_CONSTITUTION,
        help="Path to constitution YAML (default: %(default)s)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Strict mode: raise on any violation instead of collecting them",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate only — do not post comments or approve/block",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def _env_int(name: str) -> int | None:
    """Read an integer from an environment variable, or return None."""
    val = os.environ.get(name)
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def print_header(text: str) -> None:
    print(f"\n{'=' * 64}")
    print(f"  {text}")
    print(f"{'=' * 64}")


def print_section(text: str) -> None:
    print(f"\n--- {text} ---")


def print_report_table(report: GovernanceReport) -> None:
    """Print a compact summary table to the terminal."""
    status = "PASSED" if report.passed else "BLOCKED"
    rows = [
        ("MR", f"!{report.mr_iid} — {report.title}"),
        ("Status", status),
        ("Risk Score", f"{report.risk_score:.2f}"),
        ("Rules Checked", str(report.rules_checked)),
        ("Violations", str(len(report.violations))),
        ("Warnings", str(len(report.warnings))),
        ("Commit Violations", str(len(report.commit_violations))),
        ("Constitutional Hash", report.constitutional_hash),
    ]

    col_width = max(len(label) for label, _ in rows) + 2
    for label, value in rows:
        print(f"  {label:<{col_width}} {value}")


def print_violations(report: GovernanceReport) -> None:
    """Print detailed violation info."""
    if not report.violations:
        print("  No violations found.")
        return

    for i, v in enumerate(report.violations, 1):
        sev = v.get("severity", "unknown").upper()
        rule_id = v.get("rule_id", "?")
        rule_text = v.get("rule_text", "")
        source = v.get("source", "")
        location = ""
        if v.get("file") and v.get("line"):
            location = f" at {v['file']}:{v['line']}"

        print(f"  {i}. [{sev}] {rule_id}: {rule_text}")
        print(f"     Source: {source}{location}")
        print(f"     Matched: {v.get('matched_content', '')}")


def print_maci_result(result: dict) -> None:
    """Print MACI separation of powers check results."""
    print(f"  Author:     {result['author']}")
    print(f"  Approvers:  {', '.join(result['approvers']) or '(none)'}")
    print(f"  Valid:      {result['separation_valid']}")

    if result["violations"]:
        for v in result["violations"]:
            print(f"  VIOLATION:  {v['message']}")
    else:
        print("  No self-approval detected — separation of powers intact.")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


async def run_governance(args: argparse.Namespace) -> int:
    """Execute the governance pipeline and return an exit code (0=pass, 1=fail)."""

    # -- Load constitution --
    print_section("Loading Constitution")
    constitution_path = Path(args.constitution)
    if not constitution_path.exists():
        print(f"  ERROR: Constitution file not found: {constitution_path}")
        return 2

    constitution = Constitution.from_yaml(str(constitution_path))
    print(f"  Name:    {constitution.name}")
    print(f"  Rules:   {len(constitution.rules)}")
    print(f"  Hash:    {constitution.hash}")

    # -- Create bot --
    print_section("Connecting to GitLab")
    bot = GitLabGovernanceBot(
        token=args.token,
        project_id=args.project_id,
        base_url=args.gitlab_url,
        constitution=constitution,
        strict=args.strict,
    )
    print(f"  Project: {args.project_id}")
    print(f"  MR:      !{args.mr_iid}")
    print(f"  URL:     {args.gitlab_url}")

    # -- Validate MR --
    print_section("Validating Merge Request")
    report = await bot.validate_merge_request(args.mr_iid)
    print_report_table(report)

    # -- Show violations --
    print_section("Violations")
    print_violations(report)

    # -- Validate commit messages --
    print_section("Commit Message Validation")
    commit_violations = await bot.validate_commit_messages(args.mr_iid)
    if commit_violations:
        for cv in commit_violations:
            print(f"  {cv['sha']}: {cv['message']}")
            for v in cv["violations"]:
                print(f"    -> [{v.get('severity', '?').upper()}] {v['rule_id']}: {v['rule_text']}")
    else:
        print("  All commit messages pass governance checks.")

    # -- MACI separation of powers --
    print_section("MACI Separation of Powers")
    maci = GitLabMACIEnforcer(audit_log=bot.audit_log)
    maci_result = await maci.check_mr_separation(bot, mr_iid=args.mr_iid)
    print_maci_result(maci_result)

    # -- Post results (unless dry-run) --
    if args.dry_run:
        print_section("Dry Run — Skipping GitLab Actions")
        print("  Would post governance report comment")
        if report.violations:
            diff_violations = [v for v in report.violations if v.get("file") and v.get("line")]
            print(f"  Would post {len(diff_violations)} inline violation comment(s)")
        action = "approved" if report.passed else "blocked"
        print(f"  Would {action} the merge request")
        if maci_result["violations"]:
            print("  Would post MACI violation comment")
    else:
        print_section("Posting Results to GitLab")

        await bot.post_governance_comment(args.mr_iid, report)
        print("  Posted governance report comment.")

        diff_violations = [v for v in report.violations if v.get("file") and v.get("line")]
        if diff_violations:
            results = await bot.post_inline_violations(args.mr_iid, diff_violations)
            print(f"  Posted {len(results)} inline violation comment(s).")

        decision = await bot.approve_or_block(args.mr_iid, report)
        print(f"  Action: {decision['action'].upper()}")

        if maci_result["violations"]:
            await maci.post_maci_violation(bot, args.mr_iid, maci_result["violations"])
            print("  Posted MACI violation comment.")

    # -- Formatted report preview --
    print_section("Governance Report (Markdown Preview)")
    print(format_governance_report(report))

    # -- Audit trail --
    print_section("Audit Trail")
    stats = bot.stats
    print(f"  Total validations:  {stats['total_validations']}")
    print(f"  Compliance rate:    {stats['compliance_rate']:.1%}")
    print(f"  Audit chain valid:  {stats['audit_chain_valid']}")

    print_header("PASSED" if report.passed else "BLOCKED — violations must be resolved")
    return 0 if report.passed else 1


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Validate required args
    if not args.token:
        print("ERROR: GitLab token is required. Use --token or set GITLAB_TOKEN.", file=sys.stderr)
        return 2
    if args.project_id is None:
        print(
            "ERROR: Project ID is required. Use --project-id or set GITLAB_PROJECT_ID.",
            file=sys.stderr,
        )
        return 2

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    print_header("ACGS GitLab MR Governance")

    try:
        return asyncio.run(run_governance(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        logger.debug("Pipeline failed", exc_info=True)
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
