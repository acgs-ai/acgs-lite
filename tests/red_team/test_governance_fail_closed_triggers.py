"""Five-trigger adversarial fail-closed coverage for governed execution."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from tests.red_team.governance_fail_closed_cases import (
    CASE_RUNNERS,
    EXPECTED_DECISION,
    EXPECTED_TRIGGER_CLASSES,
    GovernanceBypassCaseResult,
    run_governance_fail_closed_cases,
)


@pytest.mark.red_team
@pytest.mark.parametrize("case_runner", CASE_RUNNERS, ids=lambda fn: fn.__name__)
def test_fail_closed_trigger_blocks_side_effect(
    case_runner: Callable[[], GovernanceBypassCaseResult],
) -> None:
    result = case_runner()

    assert result.expected_decision == EXPECTED_DECISION
    assert result.observed_decision == EXPECTED_DECISION
    assert result.side_effect_count == 0
    assert result.passed is True


@pytest.mark.red_team
def test_fail_closed_suite_covers_all_five_trigger_classes() -> None:
    results = run_governance_fail_closed_cases()

    assert {result.trigger_class for result in results} == EXPECTED_TRIGGER_CLASSES
    assert len({result.trigger_class for result in results}) == 5
    assert all(result.side_effect_count == 0 for result in results)
    assert all(not result.bypassed for result in results)


@pytest.mark.red_team
def test_suite_includes_ood_attack_with_provenance() -> None:
    results = run_governance_fail_closed_cases()
    ood_results = [result for result in results if result.ood_provenance]

    assert len(ood_results) == 1
    assert ood_results[0].attack_name == "ood_confused_deputy_subject_substitution"
    assert "confused-deputy" in ood_results[0].ood_provenance
