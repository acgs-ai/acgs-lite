#!/usr/bin/env python3
"""Run governance adversarial regression cases and emit generated evidence."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.red_team.governance_fail_closed_cases import (  # noqa: E402
    EXPECTED_TRIGGER_CLASSES,
    run_governance_fail_closed_cases,
)

EVIDENCE_DIR = REPO_ROOT / "docs" / "evidence" / "governance-regression"
RESULTS_PATH = EVIDENCE_DIR / "adversarial_results.json"
SUMMARY_PATH = EVIDENCE_DIR / "summary.json"


def _generated_by() -> dict[str, Any]:
    return {
        "script": "scripts/run_governance_regression.py",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def run_regression() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    outcomes = run_governance_fail_closed_cases()
    result_items = [outcome.to_artifact() for outcome in outcomes]
    trigger_classes = sorted({outcome.trigger_class for outcome in outcomes})
    bypasses = sum(1 for outcome in outcomes if outcome.bypassed)
    denied_side_effects = sum(
        1
        for outcome in outcomes
        if outcome.expected_decision == "FAIL_CLOSED" and outcome.side_effect_count > 0
    )

    summary = {
        "generated_artifact": True,
        "not_hand_written_claim": True,
        "cases": len(outcomes),
        "bypasses": bypasses,
        "denied_cases_with_side_effects": denied_side_effects,
        "trigger_classes_covered": trigger_classes,
        "trigger_class_count": len(trigger_classes),
        "expected_trigger_classes": sorted(EXPECTED_TRIGGER_CLASSES),
        "generated_by": _generated_by(),
    }
    return result_items, summary


def write_artifacts(results: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    results_payload = {
        "generated_artifact": True,
        "not_hand_written_claim": True,
        "generated_by": summary["generated_by"],
        "results": results,
    }
    RESULTS_PATH.write_text(json.dumps(results_payload, indent=2, sort_keys=True) + "\n")
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


def check_summary(results: list[dict[str, Any]], summary: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if summary["bypasses"] != 0:
        failures.append(f"bypasses={summary['bypasses']}")
    if summary["denied_cases_with_side_effects"] != 0:
        failures.append(
            f"denied_cases_with_side_effects={summary['denied_cases_with_side_effects']}"
        )
    if summary["trigger_class_count"] < 5:
        failures.append(f"trigger_class_count={summary['trigger_class_count']}")
    side_effect_bypasses = [
        item["attack_name"]
        for item in results
        if item["expected_decision"] == "FAIL_CLOSED" and item["side_effect_count"] > 0
    ]
    if side_effect_bypasses:
        failures.append(f"side_effect_bypasses={side_effect_bypasses}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run governance fail-closed adversarial regression cases."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if bypasses, denied side effects, or class coverage gaps exist.",
    )
    args = parser.parse_args(argv)

    results, summary = run_regression()
    write_artifacts(results, summary)
    failures = check_summary(results, summary)

    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.check and failures:
        print("governance regression check failed: " + "; ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
