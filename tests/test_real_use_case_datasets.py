"""Regression tests for real-use-case governance fixtures.

These cases are derived from public dataset use cases so benchmark-adjacent
coverage does not drift back toward purely synthetic prompts.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from acgs_lite.constitution import Constitution, Severity
from acgs_lite.engine import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "real_use_case_datasets.json"
BENCHMARK_CONSTITUTION = REPO_ROOT / "autoresearch" / "constitution.yaml"


def _load_cases() -> list[dict[str, object]]:
    return json.loads(FIXTURE_PATH.read_text())


def _benchmark_engine() -> GovernanceEngine:
    return GovernanceEngine(Constitution.from_yaml(str(BENCHMARK_CONSTITUTION)), strict=False)


def _decision_for(engine: GovernanceEngine, action: str, context: dict[str, object]) -> str:
    try:
        result = engine.validate(action, context=context)
    except ConstitutionalViolationError:
        return "deny"

    if result.valid and not result.violations and not result.warnings:
        return "allow"
    if any(v.severity == Severity.CRITICAL for v in result.violations):
        return "deny"
    if result.violations or result.warnings:
        # Benchmark taxonomy: warnings warrant review; runtime still permits them.
        return "escalate"
    return "allow"


@pytest.mark.unit
def test_real_use_case_fixture_has_traceable_provenance() -> None:
    cases = _load_cases()

    assert len(cases) >= 20
    assert len({case["id"] for case in cases}) == len(cases)

    required_fields = {
        "id",
        "dataset",
        "dataset_url",
        "domain",
        "use_case",
        "source_note",
        "action",
        "expected",
        "context",
    }
    expected_values = {"allow", "deny", "escalate"}

    for case in cases:
        assert required_fields <= set(case)
        assert isinstance(case["dataset_url"], str) and case["dataset_url"].startswith("https://")
        assert isinstance(case["source_note"], str) and case["source_note"].strip()
        assert case["expected"] in expected_values
        assert isinstance(case["context"], dict)


@pytest.mark.unit
def test_real_use_case_fixture_covers_multiple_datasets_domains_and_decisions() -> None:
    cases = _load_cases()

    datasets = {str(case["dataset"]) for case in cases}
    domains = Counter(str(case["domain"]) for case in cases)
    decisions = Counter(str(case["expected"]) for case in cases)

    assert len(datasets) >= 4
    assert all(count >= 4 for count in domains.values())
    assert decisions["allow"] >= 6
    assert decisions["deny"] >= 8
    assert decisions["escalate"] >= 2


@pytest.mark.unit
@pytest.mark.parametrize("case", _load_cases(), ids=lambda case: str(case["id"]))
def test_benchmark_constitution_matches_real_use_case_fixture(
    case: dict[str, object],
) -> None:
    engine = _benchmark_engine()
    decision = _decision_for(
        engine,
        action=str(case["action"]),
        context=dict(case["context"]),
    )
    assert decision == case["expected"]
