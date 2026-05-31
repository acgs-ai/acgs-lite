"""Dataset contracts and helpers for real-LLM experiments."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class DatasetRecord:
    """One prompt-bearing benchmark record."""

    id: str
    prompt: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "prompt": self.prompt, "metadata": self.metadata}


@dataclass(frozen=True)
class DatasetSnapshot:
    """Loaded dataset subset with reproducibility metadata."""

    dataset_id: str
    records: list[DatasetRecord]
    content_hash: str
    available: bool
    unavailable_reason: str | None = None


class DatasetAdapter(Protocol):
    """Minimal dataset adapter protocol."""

    dataset_id: str

    def load(self, *, limit: int | None = None) -> DatasetSnapshot:
        """Load a bounded snapshot."""
        ...


def records_hash(records: list[DatasetRecord]) -> str:
    payload = [record.to_dict() for record in records]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class StaticDataset:
    """In-memory dataset used by unit tests and dry-run CLI mode."""

    dataset_id: str
    records: list[dict[str, Any] | DatasetRecord]
    available: bool = False
    unavailable_reason: str | None = "static simulated dataset"

    def load(self, *, limit: int | None = None) -> DatasetSnapshot:
        normalized = [
            record
            if isinstance(record, DatasetRecord)
            else DatasetRecord(
                id=str(record["id"]),
                prompt=str(record["prompt"]),
                metadata=dict(record.get("metadata", {})),
            )
            for record in self.records
        ]
        if limit is not None:
            normalized = normalized[:limit]
        return DatasetSnapshot(
            dataset_id=self.dataset_id,
            records=normalized,
            content_hash=records_hash(normalized),
            available=self.available,
            unavailable_reason=None if self.available else self.unavailable_reason,
        )
