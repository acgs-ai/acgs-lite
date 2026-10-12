"""Schema and quality checks for the frozen autoresearch benchmark corpus."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = REPO_ROOT / "autoresearch" / "scenarios"
REAL_USE_CASE_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "real_use_case_datasets.json"
CANDIDATE_SCENARIOS = (
    REPO_ROOT / "autoresearch" / "candidate_scenarios" / "sourced_real_use_case_candidates.json"
)
PROMOTION_PATCH = (
    REPO_ROOT
    / "autoresearch"
    / "candidate_scenarios"
    / "promote_sourced_real_use_case_candidates.patch"
)


def _load_rows(path: Path) -> list[dict[str, object]]:
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else [data]


@pytest.mark.unit
def test_restored_research_assets_match_recorded_source_checksums() -> None:
    root = REPO_ROOT / "autoresearch"
    provenance = json.loads((root / "PROVENANCE.json").read_text())
    assert provenance["source_commit"] == "ae80b547700fcda871a26c8edff8ddf1a96034ad"
    assert len(provenance["immutable_assets_sha256"]) == 14
    for relative_path, expected in provenance["immutable_assets_sha256"].items():
        assert hashlib.sha256((root / relative_path).read_bytes()).hexdigest() == expected


@pytest.mark.unit
def test_autoresearch_scenario_files_have_valid_schema() -> None:
    expected_values = {"allow", "deny", "escalate"}
    scenario_files = sorted(SCENARIOS_DIR.glob("*.json"))

    assert scenario_files

    for scenario_file in scenario_files:
        rows = _load_rows(scenario_file)
        assert rows, f"{scenario_file.name} must not be empty"

        for row in rows:
            assert {"action", "expected"} <= set(row)
            assert isinstance(row["action"], str) and row["action"].strip()
            assert row["expected"] in expected_values
            assert isinstance(row.get("context", {}), dict)


@pytest.mark.unit
def test_autoresearch_scenario_corpus_preserves_decision_coverage() -> None:
    counts: Counter[str] = Counter()

    for scenario_file in sorted(SCENARIOS_DIR.glob("*.json")):
        counts.update(str(row["expected"]) for row in _load_rows(scenario_file))

    assert sum(counts.values()) >= 800
    assert counts["allow"] >= 300
    assert counts["deny"] >= 300
    assert counts["escalate"] >= 50


@pytest.mark.unit
def test_real_use_case_fixture_is_mostly_novel_relative_to_frozen_benchmark_corpus() -> None:
    benchmark_actions = {
        str(row["action"])
        for scenario_file in sorted(SCENARIOS_DIR.glob("*.json"))
        for row in _load_rows(scenario_file)
    }
    real_use_case_actions = {str(row["action"]) for row in _load_rows(REAL_USE_CASE_FIXTURE)}

    overlap = benchmark_actions & real_use_case_actions

    assert real_use_case_actions
    assert len(overlap) <= 1
    assert len(real_use_case_actions - benchmark_actions) >= 15


@pytest.mark.unit
def test_candidate_scenario_pack_is_balanced_and_traceable() -> None:
    rows = _load_rows(CANDIDATE_SCENARIOS)
    counts = Counter(str(row["expected"]) for row in rows)
    domains = {str(row["domain"]) for row in rows}

    assert len(rows) == 9
    assert counts == Counter({"allow": 3, "deny": 3, "escalate": 3})
    assert domains == {"healthcare", "finance", "moderation", "hiring"}

    for row in rows:
        assert isinstance(row["dataset_url"], str) and row["dataset_url"].startswith("https://")
        assert isinstance(row["source_note"], str) and row["source_note"].strip()


@pytest.mark.unit
def test_candidate_scenario_pack_is_fully_novel_relative_to_frozen_corpus() -> None:
    benchmark_actions = {
        str(row["action"])
        for scenario_file in sorted(SCENARIOS_DIR.glob("*.json"))
        for row in _load_rows(scenario_file)
    }
    candidate_actions = {str(row["action"]) for row in _load_rows(CANDIDATE_SCENARIOS)}

    assert candidate_actions
    assert benchmark_actions.isdisjoint(candidate_actions)


@pytest.mark.unit
def test_candidate_promotion_patch_targets_frozen_scenarios_path() -> None:
    patch_text = PROMOTION_PATCH.read_text()

    assert "autoresearch/scenarios/sourced_real_use_case_candidates.json" in patch_text
    assert "new file mode 100644" in patch_text
    assert '"id": "mimic_bhc_allow_review"' in patch_text
    assert '"id": "bias_in_bios_allow_fairness_review"' in patch_text
