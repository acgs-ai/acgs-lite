"""acgs eval — offline constitution evaluation and comparison."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from acgs_lite.constitution import Constitution
from acgs_lite.constitution.drift import GovernanceDriftDetector
from acgs_lite.evals import compare_eval_reports, run_eval
from acgs_lite.formal.smt_gate import ConstitutionVerificationReport, Z3VerificationGate


def _load_jsonl(path: str) -> list[dict]:
    decisions: list[dict] = []
    with Path(path).open() as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            decisions.append(json.loads(stripped))
    return decisions


def _emit_jsonl(path: str, decisions: list[dict]) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as handle:
        for decision in decisions:
            handle.write(json.dumps(decision, sort_keys=True) + "\n")


def _print_verification_report(report: ConstitutionVerificationReport) -> None:
    """Print a verification report so that "verified nothing" cannot read as "verified".

    Exit codes: 0 verified, 1 defect found, 2 not verified. The trailing line always
    states which of the three happened, in words.
    """
    if report.results:
        print(f"{'rule_id':<16} {'status':<16} detail")
        for result in report.results:
            print(f"{result.rule_id:<16} {result.status.value:<16} {result.detail}")
            for warning in result.warnings:
                print(f"{'':<16} {'':<16} warning: {warning}")

    if report.clusters:
        print()
        print(f"{'variables':<32} {'status':<16} detail")
        for cluster in report.clusters:
            print(f"{','.join(cluster.variables):<32} {cluster.status.value:<16} {cluster.detail}")

    verdict = {
        0: "VERIFIED",
        1: "DEFECT FOUND",
        2: "NOT VERIFIED",
    }[report.exit_code]
    detail = report.detail or f"{len(report.results)} policies checked"
    print()
    print(f"{verdict} [{report.status.value}]: {detail}")


def _env_requires_provenance() -> bool:
    return os.getenv("ACGS_REQUIRE_PROVENANCE", "").strip().lower() == "true"


def add_parser(sub: argparse._SubParsersAction) -> None:
    """Register the eval subcommand."""
    parser = sub.add_parser("eval", help="Run offline constitution evaluation gates")
    eval_sub = parser.add_subparsers(dest="eval_action", required=True)

    run_parser = eval_sub.add_parser("run", help="Run a scenario suite against one constitution")
    run_parser.add_argument("constitution", help="Constitution YAML")
    run_parser.add_argument("scenarios", help="Scenario suite YAML")
    run_parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")

    compare_parser = eval_sub.add_parser(
        "compare",
        help="Compare baseline and candidate constitutions against the same scenario suite",
    )
    compare_parser.add_argument("constitution", help="Baseline constitution YAML")
    compare_parser.add_argument("candidate", help="Candidate constitution YAML")
    compare_parser.add_argument("scenarios", help="Scenario suite YAML")
    compare_parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")

    drift_parser = eval_sub.add_parser(
        "drift",
        help="Compare baseline and current decision traces for governance drift",
    )
    drift_parser.add_argument("--baseline", required=True, help="Baseline JSONL decision trace")
    drift_parser.add_argument("--current", required=True, help="Current JSONL decision trace")
    drift_parser.add_argument(
        "--emit-baseline",
        dest="emit_baseline",
        help="Write the current decision trace out as a new JSONL baseline",
    )

    verify_parser = eval_sub.add_parser(
        "verify-constitution",
        help="SMT-verify the z3:/smt: policies a constitution carries",
    )
    verify_parser.add_argument(
        "--constitution",
        help="Constitution YAML to verify (default: the built-in default constitution)",
    )

    provenance_parser = eval_sub.add_parser(
        "provenance-check",
        help="Check audit JSONL entries for training-to-inference provenance metadata",
    )
    provenance_parser.add_argument("--audit-log", required=True, help="Audit JSONL file")


def handler(args: argparse.Namespace) -> int:
    """Run or compare offline constitution eval suites."""
    json_out = getattr(args, "json_out", False)

    if args.eval_action == "run":
        report = run_eval(args.constitution, args.scenarios)
        if json_out:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(report.summary())
        return 0 if report.success else 1

    if args.eval_action == "drift":
        baseline_decisions = _load_jsonl(args.baseline)
        current_decisions = _load_jsonl(args.current)

        baseline_signals = GovernanceDriftDetector().analyze_decisions(baseline_decisions)
        current_signals = GovernanceDriftDetector().analyze_decisions(current_decisions)

        baseline_evidence_hashes = {
            hashlib.sha256(signal.evidence.encode()).hexdigest()
            for signal in baseline_signals
            if signal.severity == "high"
        }
        new_high_signals = [
            signal
            for signal in current_signals
            if signal.severity == "high"
            and hashlib.sha256(signal.evidence.encode()).hexdigest() not in baseline_evidence_hashes
        ]

        for signal in new_high_signals:
            print(json.dumps(signal.to_dict(), sort_keys=True))

        if getattr(args, "emit_baseline", None):
            _emit_jsonl(args.emit_baseline, current_decisions)

        return 1 if new_high_signals else 0

    if args.eval_action == "verify-constitution":
        source = getattr(args, "constitution", None)
        if source:
            try:
                constitution = Constitution.from_yaml(source)
            except OSError as exc:
                # Could not read the file at all. Nothing was verified, so this is a 2 —
                # a mistyped path must not surface as "your constitution is contradictory".
                print(f"NOT VERIFIED [unavailable]: {exc}")
                return 2
            except Exception as exc:  # noqa: BLE001 - a constitution that will not load is a defect
                # It read but did not parse or did not validate. A constitution that fails
                # its own model is broken in the same way a malformed policy is: exit 1.
                print(f"DEFECT FOUND [invalid_policy]: {type(exc).__name__}: {exc}")
                return 1
        else:
            constitution = Constitution.default()
        verification = Z3VerificationGate().verify_constitution(constitution)
        _print_verification_report(verification)
        return verification.exit_code

    if args.eval_action == "provenance-check":
        entries = _load_jsonl(args.audit_log)
        with_provenance = sum(
            1 for entry in entries if entry.get("metadata", {}).get("provenance") is not None
        )
        without_provenance = len(entries) - with_provenance

        print(
            f"{len(entries)} entries: {with_provenance} with provenance, "
            f"{without_provenance} without"
        )
        return 1 if _env_requires_provenance() and without_provenance else 0

    baseline_report = run_eval(args.constitution, args.scenarios)
    candidate_report = run_eval(args.candidate, args.scenarios)
    comparison = compare_eval_reports(baseline_report, candidate_report)
    if json_out:
        print(json.dumps(comparison.to_dict(), indent=2))
    else:
        print(comparison.summary())
    return 0 if comparison.success else 1
