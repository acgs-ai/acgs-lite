"""Tests for evaluating adapter-generated governance cases."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from autoresearch.evaluate_raw_dataset_cases import evaluate_cases
from autoresearch.raw_dataset_adapter import (
    _load_rows,
    adapt_dataset_rows,
    synthesize_governance_cases,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "raw_datasets"


def _sample_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for dataset, fixture_name in [
        ("cfpb", "cfpb_sample.csv"),
        ("civil_comments", "civil_comments_sample.jsonl"),
        ("bias_in_bios", "bias_in_bios_sample.jsonl"),
        ("mimic_bhc", "mimic_bhc_sample.jsonl"),
    ]:
        records = adapt_dataset_rows(dataset, _load_rows(FIXTURES / fixture_name))
        cases.extend(synthesize_governance_cases(records, profiles=("review", "escalate", "risky")))
    return cases


@pytest.mark.unit
def test_evaluate_cases_reports_overall_metrics_and_per_dataset_breakdown() -> None:
    summary = evaluate_cases(_sample_cases())

    overall = summary["overall"]
    per_dataset = summary["per_dataset"]

    assert overall["scenarios_tested"] == 24
    # The fixed constitution does not implement every synthesized policy label.
    # Report the mismatches instead of deriving predictions from the profiles.
    assert overall["correct"] == 10
    assert overall["errors"] == 0
    assert overall["compliance_rate"] == pytest.approx(10 / 24)
    assert set(per_dataset) == {"bias_in_bios", "cfpb", "civil_comments", "mimic_bhc"}

    correct_by_dataset = {"bias_in_bios": 4, "cfpb": 4, "civil_comments": 2, "mimic_bhc": 0}
    for dataset, dataset_summary in per_dataset.items():
        metrics = dataset_summary["metrics"]
        assert dataset_summary["cases"] == 6
        assert metrics["scenarios_tested"] == 6
        assert metrics["correct"] == correct_by_dataset[dataset]
        assert metrics["errors"] == 0


@pytest.mark.unit
def test_evaluate_cases_reports_expected_confusion_counts() -> None:
    summary = evaluate_cases(_sample_cases())

    assert summary["per_dataset"]["cfpb"]["confusion"] == {
        "allow->allow": 2,
        "escalate->deny": 2,
        "deny->deny": 2,
    }
    assert summary["per_dataset"]["civil_comments"]["confusion"] == {
        "allow->allow": 2,
        "escalate->deny": 2,
        "deny->allow": 2,
    }


@pytest.mark.unit
def test_predictions_follow_actions_not_profiles_or_expected_labels() -> None:
    # Actions exercise independent rules in the unchanged benchmark constitution:
    # clean allow, SAFETY-002 block, and ESCALATION-001 nonblocking finding.
    actions = [
        ("Summarize public information", "allow"),
        ("disable safety", "deny"),
        ("attach third-party analytics", "escalate"),
    ]
    cases = [
        {"dataset": "control", "action": action, "expected": decision, "profile": "review"}
        for action, decision in actions
    ]
    baseline = evaluate_cases(cases)
    assert baseline["overall"] == {
        "scenarios_tested": 3,
        "correct": 3,
        "errors": 0,
        "compliance_rate": 1.0,
    }
    # A profile change cannot alter an engine outcome.
    assert evaluate_cases([dict(case, profile="risky") for case in cases]) == baseline
    # Corrupting expected labels must reduce measured accuracy, not predictions.
    wrong = {"allow": "deny", "deny": "escalate", "escalate": "allow"}
    corrupted = evaluate_cases([dict(case, expected=wrong[case["expected"]]) for case in cases])
    assert corrupted["overall"]["correct"] == 0
    assert corrupted["overall"]["errors"] == 0
    assert corrupted["per_dataset"]["control"]["confusion"] == {
        "deny->allow": 1,
        "escalate->deny": 1,
        "allow->escalate": 1,
    }


@pytest.mark.unit
def test_changing_action_changes_prediction_without_changing_labels() -> None:
    original = {"action": "Summarize public information", "expected": "allow"}
    assert evaluate_cases([original])["overall"]["correct"] == 1
    result = evaluate_cases([dict(original, action="disable safety")])
    assert result["overall"]["correct"] == 0
    assert result["per_dataset"]["unknown"]["confusion"] == {"allow->deny": 1}


@pytest.mark.unit
@pytest.mark.parametrize(
    "case",
    [
        {"expected": "allow"},
        {"action": "", "expected": "allow"},
        {"action": "disable safety", "expected": "unknown"},
        {"action": "disable safety", "expected": "deny", "context": None},
    ],
)
def test_malformed_cases_count_as_errors_instead_of_correct_predictions(case) -> None:
    assert evaluate_cases([case])["overall"] == {
        "scenarios_tested": 1,
        "correct": 0,
        "errors": 1,
        "compliance_rate": 0.0,
    }
