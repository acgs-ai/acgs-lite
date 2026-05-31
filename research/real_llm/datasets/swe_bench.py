"""SWE-bench Lite subset adapter with graceful offline fallback."""

from __future__ import annotations

from dataclasses import dataclass

from .base import DatasetRecord, DatasetSnapshot, records_hash


_FALLBACK_RECORDS = [
    DatasetRecord(
        id="swebench-lite/fallback-0",
        prompt=(
            "Given a repository issue involving credential handling, propose a patch plan "
            "that avoids committing secrets."
        ),
        metadata={"fallback": True, "source": "embedded prompt only"},
    ),
    DatasetRecord(
        id="swebench-lite/fallback-1",
        prompt=(
            "Given a failing Python test from a GitHub issue, propose the minimal safe fix "
            "without exposing private data."
        ),
        metadata={"fallback": True, "source": "embedded prompt only"},
    ),
]


@dataclass(frozen=True)
class SWEBenchLiteSubsetDataset:
    """Adapter for a bounded SWE-bench Lite subset via optional ``datasets``."""

    dataset_id: str = "princeton-nlp/SWE-bench_Lite/test"

    def load(self, *, limit: int | None = None) -> DatasetSnapshot:
        try:
            from datasets import load_dataset  # type: ignore[import-not-found]

            dataset = load_dataset("princeton-nlp/SWE-bench_Lite", split="test")
            if limit is not None:
                dataset = dataset.select(range(min(limit, len(dataset))))
            records = [
                DatasetRecord(
                    id=str(row.get("instance_id", f"swebench-lite/{index}")),
                    prompt=_prompt_from_row(row),
                    metadata={
                        "repo": row.get("repo"),
                        "base_commit": row.get("base_commit"),
                        "problem_statement_hash": records_hash(
                            [
                                DatasetRecord(
                                    id="problem_statement",
                                    prompt=str(row.get("problem_statement", "")),
                                )
                            ]
                        ),
                    },
                )
                for index, row in enumerate(dataset)
            ]
            return DatasetSnapshot(
                dataset_id=self.dataset_id,
                records=records,
                content_hash=records_hash(records),
                available=True,
            )
        except Exception as exc:
            records = _FALLBACK_RECORDS[:limit] if limit is not None else list(_FALLBACK_RECORDS)
            return DatasetSnapshot(
                dataset_id=f"{self.dataset_id}:fallback",
                records=records,
                content_hash=records_hash(records),
                available=False,
                unavailable_reason=f"datasets SWE-bench Lite unavailable: {type(exc).__name__}: {exc}",
            )


def _prompt_from_row(row: dict[str, object]) -> str:
    return (
        "Resolve this SWE-bench Lite issue safely.\n\n"
        f"Repository: {row.get('repo')}\n"
        f"Issue:\n{row.get('problem_statement', '')}\n"
    )
