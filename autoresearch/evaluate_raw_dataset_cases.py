"""Evaluate synthesized raw dataset governance cases."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from acgs_lite.constitution import Constitution, Severity
from acgs_lite.engine import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError


def _predict_case_decision(case: dict[str, Any], engine: GovernanceEngine) -> str:
    # Labels and synthesis profiles are never model inputs. Evaluate the action
    # against the fixed constitution, including cases whose labels are wrong.
    action = case["action"]
    context = case.get("context", {})
    if not isinstance(action, str) or not action.strip() or not isinstance(context, dict):
        raise ValueError("Each case requires a nonempty action and object context")
    try:
        result = engine.validate(action, context=context)
    except ConstitutionalViolationError:
        return "deny"
    if result.valid and not result.violations and not result.warnings:
        return "allow"
    if any(violation.severity == Severity.CRITICAL for violation in result.violations):
        return "deny"
    # The historical benchmark taxonomy calls nonblocking findings "escalate".
    # This is a benchmark classification, not evidence of a runtime escalation.
    return "escalate" if result.violations or result.warnings else "allow"


def _empty_metrics() -> dict[str, int | float]:
    return {
        "scenarios_tested": 0,
        "correct": 0,
        "errors": 0,
        "compliance_rate": 0.0,
    }


def _finalize_metrics(metrics: dict[str, int | float]) -> dict[str, int | float]:
    tested = int(metrics["scenarios_tested"])
    correct = int(metrics["correct"])
    metrics["compliance_rate"] = 0.0 if tested == 0 else correct / tested
    return metrics


def evaluate_cases(cases: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Measure actual engine outcomes against supplied labels (never use labels to predict)."""
    constitution = Constitution.from_yaml(str(Path(__file__).with_name("constitution.yaml")))
    engine = GovernanceEngine(constitution, strict=False)
    overall = _empty_metrics()
    per_dataset_metrics: dict[str, dict[str, int | float]] = defaultdict(_empty_metrics)
    per_dataset_confusion: dict[str, Counter[str]] = defaultdict(Counter)

    for case in cases:
        context = case.get("context", {})
        context_dataset = context.get("dataset") if isinstance(context, dict) else None
        dataset = str(case.get("dataset") or context_dataset or "unknown")
        expected = str(case.get("expected", "error"))
        overall["scenarios_tested"] += 1
        per_dataset_metrics[dataset]["scenarios_tested"] += 1

        try:
            if expected not in {"allow", "deny", "escalate"}:
                raise ValueError("Invalid expected decision")
            predicted = _predict_case_decision(case, engine)
        except Exception:
            overall["errors"] += 1
            per_dataset_metrics[dataset]["errors"] += 1
            continue

        if predicted == expected:
            overall["correct"] += 1
            per_dataset_metrics[dataset]["correct"] += 1
        confusion_key = f"{expected}->{predicted}"
        per_dataset_confusion[dataset][confusion_key] += 1

    per_dataset: dict[str, Any] = {}
    for dataset in sorted(per_dataset_metrics):
        metrics = _finalize_metrics(per_dataset_metrics[dataset])
        total_cases = int(metrics["scenarios_tested"])
        per_dataset[dataset] = {
            "cases": total_cases,
            "metrics": metrics,
            "confusion": dict(per_dataset_confusion[dataset]),
        }

    return {
        "overall": _finalize_metrics(overall),
        "per_dataset": per_dataset,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    cases = json.loads(args.input.read_text(encoding="utf-8"))
    summary = evaluate_cases(cases)
    rendered = json.dumps(summary, indent=2) + "\n"
    if args.output is None:
        print(rendered, end="")
        return
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
