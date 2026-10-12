"""Tests for adapting raw external datasets into governance-ready cases."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from autoresearch.raw_dataset_adapter import (
    _load_rows,
    adapt_dataset_rows,
    synthesize_governance_cases,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "raw_datasets"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("dataset", "fixture_name", "expected_domain"),
    [
        ("cfpb", "cfpb_sample.csv", "finance"),
        ("civil_comments", "civil_comments_sample.jsonl", "moderation"),
        ("bias_in_bios", "bias_in_bios_sample.jsonl", "hiring"),
        ("mimic_bhc", "mimic_bhc_sample.jsonl", "healthcare"),
        ("safety_prompt", "safety_prompt_sample.jsonl", "safety"),
        ("chat_log", "chat_log_sample.jsonl", "conversational"),
        ("preference_pair", "preference_pair_sample.jsonl", "alignment"),
        ("instruction_constraint", "instruction_constraint_sample.jsonl", "instruction_following"),
    ],
)
def test_adapt_dataset_rows_normalizes_raw_records(
    dataset: str,
    fixture_name: str,
    expected_domain: str,
) -> None:
    rows = _load_rows(FIXTURES / fixture_name)
    records = adapt_dataset_rows(dataset, rows)

    assert len(records) == 2
    assert all(record.dataset_slug == dataset for record in records)
    assert all(record.domain == expected_domain for record in records)
    assert all(record.text.strip() for record in records)
    assert all(record.dataset_url.startswith("https://") for record in records)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("dataset", "fixture_name"),
    [
        ("cfpb", "cfpb_sample.csv"),
        ("civil_comments", "civil_comments_sample.jsonl"),
        ("bias_in_bios", "bias_in_bios_sample.jsonl"),
        ("mimic_bhc", "mimic_bhc_sample.jsonl"),
        ("safety_prompt", "safety_prompt_sample.jsonl"),
        ("chat_log", "chat_log_sample.jsonl"),
        ("preference_pair", "preference_pair_sample.jsonl"),
        ("instruction_constraint", "instruction_constraint_sample.jsonl"),
    ],
)
def test_synthesize_governance_cases_creates_review_and_risky_profiles(
    dataset: str,
    fixture_name: str,
) -> None:
    records = adapt_dataset_rows(dataset, _load_rows(FIXTURES / fixture_name))
    cases = synthesize_governance_cases(records, profiles=("review", "escalate", "risky"))

    assert len(cases) == 6
    assert {case["profile"] for case in cases} == {"review", "escalate", "risky"}
    assert {case["expected"] for case in cases} == {"allow", "deny", "escalate"}
    assert all(case["source_record_id"] for case in cases)
    assert all(case["dataset_url"].startswith("https://") for case in cases)
    assert all(case["context"]["dataset"] == dataset for case in cases)


@pytest.mark.unit
def test_synthesize_governance_cases_can_limit_to_review_profile() -> None:
    records = adapt_dataset_rows("cfpb", _load_rows(FIXTURES / "cfpb_sample.csv"))
    cases = synthesize_governance_cases(records, profiles=("review",))

    assert len(cases) == 2
    assert all(case["profile"] == "review" for case in cases)
    assert all(case["expected"] == "allow" for case in cases)
