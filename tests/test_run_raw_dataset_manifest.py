"""Tests for manifest-driven raw dataset adaptation and evaluation."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from autoresearch.run_raw_dataset_manifest import (
    build_cases_from_manifest_entries,
    load_manifest,
    run_manifest,
    select_rows,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "raw_datasets"
MANIFEST = FIXTURES / "sample_manifest.json"
BUCKET_MANIFEST = FIXTURES / "bucket_manifest.json"


@pytest.mark.unit
def test_build_cases_from_manifest_entries_builds_expected_case_volume() -> None:
    manifest = load_manifest(MANIFEST)
    cases, datasets = build_cases_from_manifest_entries(manifest, base_dir=FIXTURES)

    assert len(cases) == 24
    assert len(datasets) == 4
    assert all(entry["records"] == 2 for entry in datasets)
    assert all(entry["cases"] == 6 for entry in datasets)


@pytest.mark.unit
def test_run_manifest_reports_combined_summary_and_manifest_metadata() -> None:
    summary = run_manifest(load_manifest(MANIFEST), base_dir=FIXTURES)

    assert summary["overall"]["scenarios_tested"] == 24
    assert summary["overall"]["correct"] == 10
    assert len(summary["manifest_datasets"]) == 4
    assert summary["manifest_datasets"][0]["dataset"] == "cfpb"
    assert set(summary["per_dataset"]) == {"bias_in_bios", "cfpb", "civil_comments", "mimic_bhc"}


@pytest.mark.unit
def test_manifest_cli_runs_the_actual_evaluator(tmp_path: Path) -> None:
    output = tmp_path / "summary.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "autoresearch.run_raw_dataset_manifest",
            "--manifest",
            str(MANIFEST),
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    actual = json.loads(output.read_text())
    assert actual == run_manifest(load_manifest(MANIFEST), base_dir=FIXTURES)


@pytest.mark.unit
def test_select_rows_supports_offset_limit_and_seeded_sampling() -> None:
    rows = [
        {"id": "r1", "kind": "a"},
        {"id": "r2", "kind": "a"},
        {"id": "r3", "kind": "b"},
        {"id": "r4", "kind": "b"},
    ]

    assert [row["id"] for row in select_rows(rows, offset=1, limit=2)] == ["r2", "r3"]
    assert [row["id"] for row in select_rows(rows, offset=1, sample_size=2, seed=7)] == ["r3", "r2"]
    assert [row["id"] for row in select_rows(rows, offset=1, sample_size=2, seed=7, limit=1)] == [
        "r3"
    ]
    stratified = select_rows(rows, sample_size=2, seed=7, stratify_by="kind")
    assert {row["kind"] for row in stratified} == {"a", "b"}


@pytest.mark.unit
def test_select_rows_stratified_sampling_is_deterministic() -> None:
    rows = [
        {"id": "r1", "kind": "a"},
        {"id": "r2", "kind": "a"},
        {"id": "r3", "kind": "b"},
        {"id": "r4", "kind": "b"},
        {"id": "r5", "kind": "c"},
        {"id": "r6", "kind": "c"},
    ]

    first = [row["id"] for row in select_rows(rows, sample_size=3, seed=11, stratify_by="kind")]
    second = [row["id"] for row in select_rows(rows, sample_size=3, seed=11, stratify_by="kind")]
    assert first == second


@pytest.mark.unit
def test_build_cases_from_manifest_entries_respects_selection_controls() -> None:
    manifest = [
        {
            "dataset": "cfpb",
            "input": "cfpb_sample_large.csv",
            "profiles": ["review", "escalate", "risky"],
            "offset": 1,
            "sample_size": 2,
            "seed": 13,
            "limit": 1,
            "stratify_by": "Product",
        }
    ]

    cases, datasets = build_cases_from_manifest_entries(manifest, base_dir=FIXTURES)

    assert len(cases) == 3
    assert datasets == [
        {
            "dataset": "cfpb",
            "adapter_slug": "cfpb",
            "input": str(FIXTURES / "cfpb_sample_large.csv"),
            "records": 1,
            "cases": 3,
            "profiles": ["review", "escalate", "risky"],
            "offset": 1,
            "limit": 1,
            "sample_size": 2,
            "seed": 13,
            "stratify_by": "Product",
        }
    ]


@pytest.mark.unit
def test_build_cases_from_manifest_entries_uses_default_stratify_by(tmp_path: Path) -> None:
    raw_path = tmp_path / "civil_comments_default.jsonl"
    raw_path.write_text(
        (
            '{"id": 1, "text": "high one", "toxicity": 0.91, "split": "train"}\n'
            '{"id": 2, "text": "high two", "toxicity": 0.84, "split": "train"}\n'
            '{"id": 3, "text": "low one", "toxicity": 0.12, "split": "train"}\n'
            '{"id": 4, "text": "low two", "toxicity": 0.04, "split": "train"}\n'
        ),
        encoding="utf-8",
    )
    manifest = [
        {
            "dataset": "civil_comments",
            "input": raw_path.name,
            "profiles": ["review"],
            "sample_size": 2,
            "seed": 5,
        }
    ]

    cases, datasets = build_cases_from_manifest_entries(manifest, base_dir=tmp_path)

    assert len(cases) == 2
    assert datasets == [
        {
            "dataset": "civil_comments",
            "adapter_slug": "civil_comments",
            "input": str(raw_path),
            "records": 2,
            "cases": 2,
            "profiles": ["review"],
            "offset": 0,
            "limit": None,
            "sample_size": 2,
            "seed": 5,
            "stratify_by": "toxicity_bucket",
        }
    ]

    buckets = {
        "low"
        if float(case["source_metadata"]["toxicity"]) < 0.33
        else "medium"
        if float(case["source_metadata"]["toxicity"]) < 0.67
        else "high"
        for case in cases
    }
    assert buckets == {"low", "high"}


@pytest.mark.unit
def test_build_cases_from_bucket_manifest_uses_adapter_slugs() -> None:
    manifest = load_manifest(BUCKET_MANIFEST)
    cases, datasets = build_cases_from_manifest_entries(manifest, base_dir=FIXTURES)

    assert len(cases) == 24
    assert len(datasets) == 4
    assert all(entry["records"] == 2 for entry in datasets)
    assert all(entry["cases"] == 6 for entry in datasets)
    assert {entry["adapter_slug"] for entry in datasets} == {
        "safety_prompt",
        "chat_log",
        "preference_pair",
        "instruction_constraint",
    }


@pytest.mark.unit
def test_run_bucket_manifest_reports_bucket_adapter_metrics() -> None:
    summary = run_manifest(load_manifest(BUCKET_MANIFEST), base_dir=FIXTURES)

    assert summary["overall"]["scenarios_tested"] == 24
    assert summary["overall"]["correct"] == 10
    assert set(summary["per_dataset"]) == {
        "safety_prompt",
        "chat_log",
        "preference_pair",
        "instruction_constraint",
    }
