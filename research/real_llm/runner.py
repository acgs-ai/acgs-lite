"""Run real-provider LLM experiments through the real ACGS-lite AuditLog."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from acgs_lite.audit import AuditEntry, AuditLog, JSONLAuditBackend

from .datasets import (
    DatasetAdapter,
    DatasetSnapshot,
    HumanEvalSubsetDataset,
    StaticDataset,
    SWEBenchLiteSubsetDataset,
)
from .providers import AnthropicProvider, LLMProvider, MockProvider, OpenAIProvider
from .providers.base import ProviderUnavailable

DEFAULT_MIN_SAMPLE_SIZE = 30
CONSTITUTIONAL_HASH = "608508a9bd224290"


@dataclass(frozen=True)
class ExperimentRunner:
    """Experiment runner that produces reproducible JSON artifacts."""

    providers: Sequence[LLMProvider]
    dataset: DatasetAdapter
    output_dir: Path | str = Path("research/results/real_llm")
    min_sample_size: int = DEFAULT_MIN_SAMPLE_SIZE

    def run(self, *, experiment_id: str, limit: int | None = None) -> dict[str, Any]:
        output_dir = Path(self.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        snapshot = self.dataset.load(limit=limit)
        audit_jsonl_path = output_dir / f"{experiment_id}_audit.jsonl"
        audit_json_path = output_dir / f"{experiment_id}_audit.json"
        backend = JSONLAuditBackend(audit_jsonl_path)
        audit_log = AuditLog(backend=backend)

        provider_metadata: list[dict[str, Any]] = []
        responses: list[dict[str, Any]] = []
        bypass_count = 0
        real_provider_ids_ran: set[str] = set()

        try:
            for provider in self.providers:
                available = provider.is_available()
                provider_metadata.append(
                    {
                        "provider_id": provider.provider_id,
                        "model_id": provider.model_id,
                        "simulated": provider.simulated,
                        "available": available,
                        "availability_reason": provider.availability_reason(),
                    }
                )
                if not available:
                    continue

                for record in snapshot.records:
                    sample_key = f"{record.id}:{provider.provider_id}:{provider.model_id}"
                    audit_log.record_atomic(
                        AuditEntry(
                            id=_stable_id("request", sample_key),
                            type="real_llm_request",
                            agent_id=provider.provider_id,
                            action="provider.generate",
                            valid=True,
                            constitutional_hash=CONSTITUTIONAL_HASH,
                            metadata={
                                "dataset_id": snapshot.dataset_id,
                                "dataset_hash": snapshot.content_hash,
                                "sample_id": record.id,
                                "model_id": provider.model_id,
                            },
                        )
                    )
                    try:
                        response = provider.generate(record.prompt, sample_id=record.id)
                    except ProviderUnavailable as exc:
                        bypass_count += 1
                        audit_log.record_atomic(
                            _failure_entry(provider, record.id, "provider_unavailable", str(exc))
                        )
                        continue
                    except Exception as exc:
                        bypass_count += 1
                        audit_log.record_atomic(
                            _failure_entry(provider, record.id, "provider_error", str(exc))
                        )
                        continue

                    if not response.simulated and not provider.simulated:
                        real_provider_ids_ran.add(provider.provider_id)
                    response_hash = hashlib.sha256(response.text.encode()).hexdigest()
                    audit_log.record_atomic(
                        AuditEntry(
                            id=_stable_id("response", sample_key),
                            type="real_llm_response",
                            agent_id=provider.provider_id,
                            action="provider.generate",
                            valid=True,
                            constitutional_hash=CONSTITUTIONAL_HASH,
                            latency_ms=float(response.metadata.get("latency_ms", 0.0) or 0.0),
                            metadata={
                                "dataset_id": snapshot.dataset_id,
                                "sample_id": record.id,
                                "model_id": provider.model_id,
                                "response_hash": response_hash,
                                "simulated": response.simulated,
                                "provider_metadata": response.metadata,
                            },
                        )
                    )
                    responses.append(
                        {
                            "sample_id": record.id,
                            "provider_id": response.provider_id,
                            "model_id": response.model_id,
                            "simulated": response.simulated,
                            "response_hash": response_hash,
                        }
                    )

            audit_log.flush()
            audit_log.export_json(audit_json_path)
        finally:
            backend.close()

        audit_log_hash = _file_hash(audit_json_path)
        sample_count = len(responses)
        simulation_reasons = _simulation_reasons(
            provider_metadata=provider_metadata,
            real_provider_ids_ran=real_provider_ids_ran,
            sample_count=sample_count,
            min_sample_size=self.min_sample_size,
            snapshot=snapshot,
        )
        artifact = {
            "schema_version": "real_llm_results.v1",
            "experiment_id": experiment_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "simulated": bool(simulation_reasons),
            "simulation_reasons": simulation_reasons,
            "providers": provider_metadata,
            "sample_count": sample_count,
            "dataset": {
                "id": snapshot.dataset_id,
                "content_hash": snapshot.content_hash,
                "available": snapshot.available,
                "unavailable_reason": snapshot.unavailable_reason,
            },
            "audit_log_hash": audit_log_hash,
            "audit_log_path": str(audit_json_path),
            "audit_jsonl_path": str(audit_jsonl_path),
            "bypass_count": bypass_count,
            "responses": responses,
        }
        result_path = output_dir / f"{experiment_id}_results.json"
        result_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
        _write_summary(output_dir, artifact)
        return artifact


def _simulation_reasons(
    *,
    provider_metadata: list[dict[str, Any]],
    real_provider_ids_ran: set[str],
    sample_count: int,
    min_sample_size: int,
    snapshot: DatasetSnapshot,
) -> list[str]:
    reasons: list[str] = []
    for provider in provider_metadata:
        if provider["simulated"]:
            reasons.append(f"provider:{provider['provider_id']} is simulated")
        if not provider["available"]:
            reasons.append(
                f"provider:{provider['provider_id']} unavailable: {provider['availability_reason']}"
            )
    if len(real_provider_ids_ran) < 2:
        reasons.append("requires >=2 distinct non-simulated providers")
    if sample_count < min_sample_size:
        reasons.append(f"sample_count {sample_count} < min_sample_size {min_sample_size}")
    if not snapshot.available:
        reason = snapshot.unavailable_reason or "dataset adapter did not load a recognized dataset"
        reasons.append(f"dataset unavailable: {reason}")
    return reasons


def _failure_entry(
    provider: LLMProvider, sample_id: str, failure_type: str, message: str
) -> AuditEntry:
    return AuditEntry(
        id=_stable_id(
            "failure", f"{provider.provider_id}:{provider.model_id}:{sample_id}:{message}"
        ),
        type="real_llm_failure",
        agent_id=provider.provider_id,
        action="provider.generate",
        valid=False,
        violations=[failure_type],
        constitutional_hash=CONSTITUTIONAL_HASH,
        metadata={"sample_id": sample_id, "model_id": provider.model_id, "error": message},
    )


def _stable_id(prefix: str, payload: str) -> str:
    return f"{prefix}-{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_summary(output_dir: Path, artifact: dict[str, Any]) -> None:
    summary = {
        "schema_version": "real_llm_summary.v1",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "experiments": [
            {
                "experiment_id": artifact["experiment_id"],
                "simulated": artifact["simulated"],
                "simulation_reasons": artifact["simulation_reasons"],
                "sample_count": artifact["sample_count"],
                "dataset": artifact["dataset"],
                "providers": artifact["providers"],
                "audit_log_hash": artifact["audit_log_hash"],
                "bypass_count": artifact["bypass_count"],
            }
        ],
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


def build_provider(spec: str) -> LLMProvider:
    kind, _, model = spec.partition(":")
    if kind == "mock":
        return MockProvider(provider_id=model or "mock", model_id="mock-deterministic")
    if kind == "openai":
        return OpenAIProvider(model_id=model or _env_or_placeholder("OPENAI_MODEL"))
    if kind == "anthropic":
        return AnthropicProvider(model_id=model or _env_or_placeholder("ANTHROPIC_MODEL"))
    raise ValueError(f"unknown provider spec {spec!r}; expected mock, openai, or anthropic")


def build_dataset(name: str) -> DatasetAdapter:
    if name == "humaneval":
        return HumanEvalSubsetDataset()
    if name in {"swe-bench-lite", "swebench-lite"}:
        return SWEBenchLiteSubsetDataset()
    if name == "static":
        return StaticDataset(
            dataset_id="static/mock",
            records=[
                {
                    "id": "static-0",
                    "prompt": "Return a concise answer for static sample 0.",
                    "metadata": {"static": True},
                },
                {
                    "id": "static-1",
                    "prompt": "Return a concise answer for static sample 1.",
                    "metadata": {"static": True},
                },
            ],
        )
    raise ValueError(f"unknown dataset {name!r}; expected humaneval, swe-bench-lite, or static")


def _env_or_placeholder(name: str) -> str:
    import os

    return os.getenv(name) or f"set-{name}"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run real-LLM experiments through AuditLog")
    parser.add_argument(
        "--provider",
        action="append",
        default=[],
        help="Provider spec: openai:<model>, anthropic:<model>, or mock:<id>. Repeatable.",
    )
    parser.add_argument(
        "--dataset",
        choices=["humaneval", "swe-bench-lite", "swebench-lite", "static"],
        default="humaneval",
    )
    parser.add_argument("--experiment-id", default="real_llm")
    parser.add_argument("--limit", type=int, default=DEFAULT_MIN_SAMPLE_SIZE)
    parser.add_argument("--min-sample-size", type=int, default=DEFAULT_MIN_SAMPLE_SIZE)
    parser.add_argument("--output-dir", default="research/results/real_llm")
    parser.add_argument(
        "--fail-if-simulated",
        action="store_true",
        help="Exit non-zero when the artifact cannot honestly be marked simulated=false.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    provider_specs = args.provider or ["openai", "anthropic"]
    runner = ExperimentRunner(
        providers=[build_provider(spec) for spec in provider_specs],
        dataset=build_dataset(args.dataset),
        output_dir=Path(args.output_dir),
        min_sample_size=args.min_sample_size,
    )
    artifact = runner.run(experiment_id=args.experiment_id, limit=args.limit)
    print(json.dumps(artifact, indent=2, sort_keys=True))
    if args.fail_if_simulated and artifact["simulated"]:
        raise SystemExit(2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
