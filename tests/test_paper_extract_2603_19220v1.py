"""Regression test for the Nemotron-Cascade 2 paper extraction map."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
EXTRACT_PATH = REPO_ROOT / "autoresearch" / "paper_extracts" / "2603_19220v1.json"


@pytest.mark.unit
def test_paper_extract_contains_expected_candidate_and_out_of_scope_sets() -> None:
    data = json.loads(EXTRACT_PATH.read_text(encoding="utf-8"))

    candidates = data["adapter_candidates"]
    out_of_scope = data["out_of_scope"]
    candidate_names = {entry["name"] for entry in candidates}
    out_of_scope_names = {entry["name"] for entry in out_of_scope}

    assert len(candidates) == 9
    assert len(out_of_scope) == 36

    assert {
        "Nemotron Content Safety v2",
        "Gretel Safety Alignment v1",
        "Harmful Tasks",
        "Red-Team-2K",
        "LMSYS-chat-1M",
        "WildChat",
        "HelpSteer3-preference",
        "arena-human-preference-140k",
        "IF_multi_constraints_upto5",
    } <= candidate_names

    assert {
        "LiveCodeBench",
        "MMLU-Pro",
        "GPQA-Diamond",
        "ArenaHard 2.0",
        "SWE-bench Verified",
        "WMT24++",
    } <= out_of_scope_names
