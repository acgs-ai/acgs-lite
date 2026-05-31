from __future__ import annotations

import json

import pytest

from research.real_llm.datasets import StaticDataset
from research.real_llm.providers import MockProvider
from research.real_llm.runner import ExperimentRunner, main


def _dataset(count: int = 3) -> StaticDataset:
    return StaticDataset(
        dataset_id="test/static",
        records=[
            {
                "id": f"sample-{index}",
                "prompt": f"Write a function for sample {index}",
                "metadata": {"index": index},
            }
            for index in range(count)
        ],
    )


def test_runner_records_audit_evidence_and_sample_count(tmp_path) -> None:
    runner = ExperimentRunner(
        providers=[
            MockProvider(provider_id="mock-a", model_id="mock-model-a"),
            MockProvider(provider_id="mock-b", model_id="mock-model-b"),
        ],
        dataset=_dataset(count=3),
        output_dir=tmp_path,
        min_sample_size=3,
    )

    artifact = runner.run(experiment_id="unit_mock", limit=3)

    assert artifact["simulated"] is True
    assert artifact["sample_count"] == 6
    assert artifact["dataset"]["id"] == "test/static"
    assert artifact["dataset"]["content_hash"]
    assert artifact["audit_log_hash"]
    assert artifact["bypass_count"] == 0

    result_path = tmp_path / "unit_mock_results.json"
    audit_path = tmp_path / "unit_mock_audit.json"
    assert result_path.exists()
    assert audit_path.exists()

    audit = json.loads(audit_path.read_text())
    assert audit["chain_valid"] is True
    assert audit["entry_count"] >= artifact["sample_count"]


def test_mock_provider_can_never_mark_artifact_as_real(tmp_path) -> None:
    runner = ExperimentRunner(
        providers=[
            MockProvider(provider_id="mock-a", model_id="mock-model-a"),
            MockProvider(provider_id="mock-b", model_id="mock-model-b"),
        ],
        dataset=_dataset(count=5),
        output_dir=tmp_path,
        min_sample_size=5,
    )

    artifact = runner.run(experiment_id="mock_guard", limit=5)

    assert artifact["simulated"] is True
    assert "provider:mock-a is simulated" in artifact["simulation_reasons"]
    assert "provider:mock-b is simulated" in artifact["simulation_reasons"]


def test_real_marking_requires_two_distinct_non_simulated_providers(tmp_path) -> None:
    provider = MockProvider(provider_id="mock-a", model_id="mock-model-a")
    runner = ExperimentRunner(
        providers=[provider],
        dataset=_dataset(count=5),
        output_dir=tmp_path,
        min_sample_size=5,
    )

    artifact = runner.run(experiment_id="one_provider", limit=5)

    assert artifact["simulated"] is True
    assert "requires >=2 distinct non-simulated providers" in artifact["simulation_reasons"]


def test_real_marking_requires_minimum_sample_size(tmp_path) -> None:
    runner = ExperimentRunner(
        providers=[
            MockProvider(provider_id="mock-a", model_id="mock-model-a"),
            MockProvider(provider_id="mock-b", model_id="mock-model-b"),
        ],
        dataset=_dataset(count=2),
        output_dir=tmp_path,
        min_sample_size=5,
    )

    artifact = runner.run(experiment_id="too_small", limit=2)

    assert artifact["simulated"] is True
    assert "sample_count 4 < min_sample_size 5" in artifact["simulation_reasons"]


def test_fail_if_simulated_exits_nonzero_for_mock_provider(tmp_path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "--provider",
                "mock:mock-a",
                "--provider",
                "mock:mock-b",
                "--dataset",
                "static",
                "--limit",
                "2",
                "--min-sample-size",
                "2",
                "--output-dir",
                str(tmp_path),
                "--fail-if-simulated",
            ]
        )

    assert exc.value.code == 2
