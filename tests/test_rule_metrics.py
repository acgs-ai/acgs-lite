"""Tests for per-rule precision/recall/F1 metrics.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add acgs-lite src to path
ACGS_LITE_SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(ACGS_LITE_SRC))

from acgs_lite.constitution.rule_metrics import (  # noqa: E402
    EvalReport,
    RuleMetrics,
    ScenarioOutcomeMetrics,
    compute_eval_report,
)
from acgs_lite.constitution.test_suite import (  # noqa: E402
    AssertionResult,
)
from acgs_lite.constitution.test_suite import (
    TestOutcome as GovernanceTestOutcome,
)
from acgs_lite.constitution.test_suite import (
    TestReport as GovernanceTestReport,
)

# --- Test 1: compute_rule_metrics with known TP/FP/FN/TN ---


class TestRuleMetrics:
    """Unit tests for RuleMetrics precision/recall/F1 computation."""

    def test_perfect_score(self):
        rm = RuleMetrics(
            rule_id="R1", true_positives=10, false_positives=0, false_negatives=0, true_negatives=5
        )
        assert rm.precision == 1.0
        assert rm.recall == 1.0
        assert rm.f1_score == 1.0
        assert rm.support == 10

    def test_known_values(self):
        # TP=3, FP=1, FN=1, TN=5 → P=3/4=0.75, R=3/4=0.75, F1=0.75
        rm = RuleMetrics(
            rule_id="R1", true_positives=3, false_positives=1, false_negatives=1, true_negatives=5
        )
        assert rm.precision == pytest.approx(0.75)
        assert rm.recall == pytest.approx(0.75)
        assert rm.f1_score == pytest.approx(0.75)
        assert rm.support == 4

    def test_zero_positives(self):
        """Rule with no positive samples should not crash."""
        rm = RuleMetrics(
            rule_id="R1", true_positives=0, false_positives=0, false_negatives=0, true_negatives=10
        )
        assert rm.precision == 0.0
        assert rm.recall == 0.0
        assert rm.f1_score == 0.0
        assert rm.support == 0

    def test_all_false_positives(self):
        rm = RuleMetrics(
            rule_id="R1", true_positives=0, false_positives=5, false_negatives=0, true_negatives=0
        )
        assert rm.precision == 0.0
        assert rm.recall == 0.0
        assert rm.f1_score == 0.0

    def test_all_false_negatives(self):
        rm = RuleMetrics(
            rule_id="R1", true_positives=0, false_positives=0, false_negatives=5, true_negatives=0
        )
        assert rm.precision == 0.0
        assert rm.recall == 0.0
        assert rm.f1_score == 0.0
        assert rm.support == 5

    def test_high_precision_low_recall(self):
        # TP=1, FP=0, FN=9 → P=1.0, R=0.1
        rm = RuleMetrics(
            rule_id="R1", true_positives=1, false_positives=0, false_negatives=9, true_negatives=0
        )
        assert rm.precision == 1.0
        assert rm.recall == pytest.approx(0.1)

    def test_to_dict(self):
        rm = RuleMetrics(
            rule_id="R1", true_positives=3, false_positives=1, false_negatives=1, true_negatives=5
        )
        d = rm.to_dict()
        assert d["rule_id"] == "R1"
        assert d["precision"] == pytest.approx(0.75)
        assert d["recall"] == pytest.approx(0.75)
        assert d["support"] == 4


# --- Test 2: scenario_outcome_metrics ---


class TestScenarioOutcomeMetrics:
    def test_perfect_accuracy(self):
        sm = ScenarioOutcomeMetrics(total=10, correct=10, incorrect=0, errors=0, skipped=0)
        assert sm.accuracy == 1.0
        assert sm.error_rate == 0.0

    def test_known_accuracy(self):
        sm = ScenarioOutcomeMetrics(total=10, correct=8, incorrect=2, errors=0, skipped=0)
        assert sm.accuracy == pytest.approx(0.8)

    def test_with_skipped(self):
        sm = ScenarioOutcomeMetrics(total=10, correct=8, incorrect=0, errors=0, skipped=2)
        assert sm.accuracy == pytest.approx(1.0)  # 8/8 runnable

    def test_all_skipped(self):
        sm = ScenarioOutcomeMetrics(total=5, correct=0, incorrect=0, errors=0, skipped=5)
        assert sm.accuracy == 0.0

    def test_with_errors(self):
        sm = ScenarioOutcomeMetrics(total=10, correct=7, incorrect=1, errors=2, skipped=0)
        assert sm.error_rate == pytest.approx(0.2)

    def test_to_dict(self):
        sm = ScenarioOutcomeMetrics(total=10, correct=8, incorrect=2)
        d = sm.to_dict()
        assert d["accuracy"] == pytest.approx(0.8)


# --- Test 6: compute_eval_report integration ---


class TestComputeEvalReport:
    def _make_result(
        self,
        name: str,
        outcome: GovernanceTestOutcome,
        actual_decision: str | None = None,
        actual_rules: list[str] | None = None,
    ) -> AssertionResult:
        return AssertionResult(
            case_name=name,
            outcome=outcome,
            actual_decision=actual_decision,
            actual_rules_triggered=actual_rules or [],
        )

    def test_basic_computation(self):
        """Verify compute_eval_report produces correct metrics for known data."""
        report = GovernanceTestReport(
            suite_name="test",
            results=[
                self._make_result("c1", GovernanceTestOutcome.PASS, "deny", ["R1"]),
                self._make_result("c2", GovernanceTestOutcome.PASS, "allow", []),
                self._make_result(
                    "c3", GovernanceTestOutcome.FAIL, "allow", []
                ),  # R1 should have fired
            ],
        )
        eval_report = compute_eval_report(
            report,
            all_rule_ids=["R1", "R2"],
            expected_rules_map={
                "c1": ["R1"],
                "c3": ["R1"],
            },
            not_expected_rules_map={
                "c2": ["R1"],
            },
        )
        r1 = eval_report.rule_metrics["R1"]
        assert r1.true_positives == 1  # c1: R1 fired and expected
        assert r1.false_negatives == 1  # c3: R1 not fired but expected
        assert r1.true_negatives == 1  # c2: R1 not fired and not expected

        assert eval_report.scenario_metrics.correct == 2
        assert eval_report.scenario_metrics.incorrect == 1

    def test_empty_report(self):
        report = GovernanceTestReport(suite_name="empty", results=[])
        eval_report = compute_eval_report(
            report,
            all_rule_ids=["R1"],
            expected_rules_map={},
        )
        assert eval_report.scenario_metrics.total == 0
        assert eval_report.scenario_metrics.accuracy == 0.0

    def test_skipped_scenarios(self):
        report = GovernanceTestReport(
            suite_name="test",
            results=[self._make_result("c1", GovernanceTestOutcome.SKIP)],
        )
        eval_report = compute_eval_report(report, all_rule_ids=["R1"], expected_rules_map={})
        assert eval_report.scenario_metrics.skipped == 1
        assert eval_report.scenario_metrics.accuracy == 0.0

    def test_error_scenarios(self):
        report = GovernanceTestReport(
            suite_name="test",
            results=[self._make_result("c1", GovernanceTestOutcome.ERROR)],
        )
        eval_report = compute_eval_report(report, all_rule_ids=["R1"], expected_rules_map={})
        assert eval_report.scenario_metrics.errors == 1


# --- Test 7: EvalReport markdown output ---


class TestEvalReportOutput:
    def test_to_markdown(self):
        rm = RuleMetrics(
            rule_id="R1", true_positives=5, false_positives=1, false_negatives=1, true_negatives=3
        )
        sm = ScenarioOutcomeMetrics(total=10, correct=9, incorrect=1)
        report = EvalReport(
            rule_metrics={"R1": rm},
            scenario_metrics=sm,
            suite_name="test-suite",
        )
        md = report.to_markdown()
        assert "# Eval Report: test-suite" in md
        assert "R1" in md
        assert "90.0%" in md

    def test_to_dict(self):
        rm = RuleMetrics(rule_id="R1", true_positives=5)
        sm = ScenarioOutcomeMetrics(total=10, correct=10)
        report = EvalReport(
            rule_metrics={"R1": rm},
            scenario_metrics=sm,
            suite_name="test",
        )
        d = report.to_dict()
        assert "rule_metrics" in d
        assert "scenario_metrics" in d
        assert "summary" in d

    def test_summary_text(self):
        rm = RuleMetrics(rule_id="R1", true_positives=5, false_negatives=0)
        sm = ScenarioOutcomeMetrics(total=10, correct=8, incorrect=2)
        report = EvalReport(
            rule_metrics={"R1": rm},
            scenario_metrics=sm,
        )
        s = report.summary()
        assert "80.0%" in s
        assert "1 rules" in s
