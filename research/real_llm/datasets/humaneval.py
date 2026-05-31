"""HumanEval subset adapter with graceful offline fallback."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .base import DatasetRecord, DatasetSnapshot, records_hash


_FALLBACK_RECORDS = [
    DatasetRecord(
        id="HumanEval/0",
        prompt=(
            "Complete the Python function:\n"
            "def has_close_elements(numbers, threshold):\n"
            "    \"\"\"Return True if two numbers are closer than threshold.\"\"\"\n"
        ),
        metadata={"fallback": True, "source": "embedded prompt only"},
    ),
    DatasetRecord(
        id="HumanEval/1",
        prompt=(
            "Complete the Python function:\n"
            "def separate_paren_groups(paren_string):\n"
            "    \"\"\"Split balanced parenthesis groups.\"\"\"\n"
        ),
        metadata={"fallback": True, "source": "embedded prompt only"},
    ),
]


@dataclass(frozen=True)
class HumanEvalSubsetDataset:
    """Adapter for a bounded HumanEval subset via the optional ``datasets`` package."""

    dataset_id: str = "openai_humaneval/test"

    def load(self, *, limit: int | None = None) -> DatasetSnapshot:
        try:
            from datasets import load_dataset  # type: ignore[import-not-found]

            dataset = load_dataset("openai_humaneval", split="test")
            if limit is not None:
                dataset = dataset.select(range(min(limit, len(dataset))))
            records = [
                DatasetRecord(
                    id=str(row.get("task_id", f"HumanEval/{index}")),
                    prompt=str(row.get("prompt", "")),
                    metadata={
                        "entry_point": row.get("entry_point"),
                        "test_hash": _hash_optional(row.get("test")),
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
                unavailable_reason=f"datasets HumanEval unavailable: {type(exc).__name__}: {exc}",
            )


def _hash_optional(value: Any) -> str | None:
    if value is None:
        return None
    import hashlib

    return hashlib.sha256(str(value).encode()).hexdigest()
