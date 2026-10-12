"""Regression test for the planned adapter manifest derived from the paper extract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
EXTRACT_PATH = REPO_ROOT / "autoresearch" / "paper_extracts" / "2603_19220v1.json"
MANIFEST_PATH = REPO_ROOT / "autoresearch" / "paper_extracts" / "2603_19220v1_adapter_manifest.json"


@pytest.mark.unit
def test_paper_adapter_manifest_is_planned_and_covers_all_candidates() -> None:
    extract = json.loads(EXTRACT_PATH.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    candidate_names = {entry["name"] for entry in extract["adapter_candidates"]}
    manifest_names = {entry["source_name"] for entry in manifest["entries"]}

    assert manifest["manifest_kind"] == "planned_raw_dataset_adapter_manifest"
    assert manifest["paper"]["arxiv_id"] == "2603.19220v1"
    assert len(manifest["entries"]) == 9
    assert candidate_names == manifest_names

    adapter_slugs = {entry["adapter_slug"] for entry in manifest["entries"]}
    assert adapter_slugs == {
        "safety_prompt",
        "chat_log",
        "preference_pair",
        "instruction_constraint",
    }

    by_name = {entry["source_name"]: entry for entry in manifest["entries"]}
    assert by_name["LMSYS-chat-1M"]["recommended_profiles"] == ["review", "escalate"]
    assert by_name["Nemotron Content Safety v2"]["recommended_profiles"] == [
        "review",
        "escalate",
        "risky",
    ]
    assert by_name["WildChat"]["selection_hint"] == {"stratify_by": "role"}
    assert by_name["IF_multi_constraints_upto5"]["dataset"] == "if_multi_constraints_upto5"
