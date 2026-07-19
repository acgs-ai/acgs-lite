"""EU AI Act Article 12 — Automatic Record-Keeping Compliance.

Article 12 mandates that high-risk AI systems automatically log events
throughout their lifecycle. Logs must be:

- Automatically generated (not manually written)
- Tamper-evident (any modification is detectable)
- Retained for at least 10 years (or the system's lifetime, whichever is longer)
- Sufficient to reconstruct the sequence of events leading to a decision

This module provides a drop-in logging wrapper that supports Article 12
record-keeping requirements with zero infrastructure dependencies.

Constitutional Hash: 608508a9bd224290

Usage::

    from acgs_lite.eu_ai_act import Article12Logger

    logger = Article12Logger(system_id="my-hiring-tool", risk_level="high_risk")

    # Wrap any LLM call — logging is automatic
    response = logger.log_call(
        operation="candidate_screening",
        call=lambda: llm.complete(prompt),
    )

    # Append-only JSONL export (supports Article 12 record-keeping)
    logger.export_jsonl("audit_trail.jsonl")
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

CONSTITUTIONAL_HASH = "608508a9bd224290"

logger = logging.getLogger(__name__)

RETENTION_PERIOD_YEARS = 10  # Article 12 minimum

T = TypeVar("T")


@dataclass(frozen=True)
class Article12Record:
    """A single Article 12 compliant audit record.

    Every field is required under Article 12 to ensure traceability.
    Records are immutable (frozen) to prevent post-hoc modification.
    """

    record_id: str
    system_id: str
    operation: str
    timestamp: str
    outcome: str  # "success" | "failure" | "blocked" | "pending"
    constitutional_hash: str = CONSTITUTIONAL_HASH
    human_oversight_applied: bool = False
    risk_level: str = "high_risk"
    retention_period_years: int = RETENTION_PERIOD_YEARS
    latency_ms: float = 0.0
    input_hash: str = ""  # SHA-256 prefix of input (not the input itself — privacy)
    output_hash: str = ""  # SHA-256 prefix of output
    error: str | None = None
    tenant_id: str | None = None
    rule_version: str = "eu_ai_act_2024"
    metadata: dict[str, Any] = field(default_factory=dict)
    prev_record_hash: str = "genesis"  # Chain link

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSONL export."""
        return asdict(self)

    @property
    def record_hash(self) -> str:
        """Deterministic hash of this record's content."""
        data = {k: v for k, v in asdict(self).items() if k != "prev_record_hash"}
        canonical = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _hash_content(content: str) -> str:
    """Return a short SHA-256 hash of content — for audit without storing raw data."""
    return hashlib.sha256(content.encode()).hexdigest()[:16]


class Article12Logger:
    """Article 12 compliant automatic record-keeping for high-risk AI systems.

    Wraps any callable (LLM call, decision function, agent step) and
    automatically logs each invocation with a tamper-evident chain.

    Features:
    - Automatic timestamps and latency measurement
    - Cryptographic chaining (each record links to the previous)
    - Privacy-preserving: inputs/outputs stored as hashes, not raw text
    - JSONL append-only export (survives process restarts)
    - Chain integrity verification

    Usage::

        logger = Article12Logger(system_id="cv-screener-v1", risk_level="high_risk")

        # Option 1: Wrap a callable
        result = logger.log_call(
            operation="screen_candidate",
            call=lambda: my_llm(prompt),
            input_text=prompt,
        )

        # Option 2: Manual record creation
        with logger.record_operation("screen_candidate", input_text=prompt) as ctx:
            result = my_llm(prompt)
            ctx.set_output(result)

        # Verify integrity
        assert logger.verify_chain()

        # Export (append-only JSONL per Article 12)
        logger.export_jsonl("audit.jsonl")
    """

    def __init__(
        self,
        system_id: str,
        *,
        risk_level: str = "high_risk",
        tenant_id: str | None = None,
        rule_version: str = "eu_ai_act_2024",
        max_records: int = 100_000,
    ) -> None:
        self.system_id = system_id
        self.risk_level = risk_level
        self.tenant_id = tenant_id
        self.rule_version = rule_version
        self.max_records = max_records
        self._records: list[Article12Record] = []
        self._chain_hashes: list[str] = []

    def log_call(
        self,
        operation: str,
        call: Callable[[], T],
        *,
        input_text: str = "",
        human_oversight_applied: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> T:
        """Wrap a callable and automatically log the invocation.

        Args:
            operation: Name of the operation (e.g. "candidate_screening").
            call: Zero-argument callable to invoke.
            input_text: Input string for hashing (not stored raw).
            human_oversight_applied: Whether a human reviewed this decision.
            metadata: Optional extra metadata to record.

        Returns:
            The return value of ``call()``.

        Raises:
            Re-raises any exception from ``call()`` after logging the failure.
        """
        start = time.perf_counter()
        record_id = str(uuid.uuid4())[:8]
        outcome = "success"
        error_msg: str | None = None
        output_text = ""

        try:
            result = call()
            if isinstance(result, str):
                output_text = result
            return result
        except Exception as exc:  # noqa: BLE001 — top-level audit wrapper must catch all to record outcome
            outcome = "failure"
            error_msg = str(exc)[:500]
            raise
        finally:
            latency_ms = (time.perf_counter() - start) * 1000
            self._append(
                Article12Record(
                    record_id=record_id,
                    system_id=self.system_id,
                    operation=operation,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    outcome=outcome,
                    constitutional_hash=CONSTITUTIONAL_HASH,
                    human_oversight_applied=human_oversight_applied,
                    risk_level=self.risk_level,
                    retention_period_years=RETENTION_PERIOD_YEARS,
                    latency_ms=round(latency_ms, 3),
                    input_hash=_hash_content(input_text) if input_text else "",
                    output_hash=_hash_content(output_text) if output_text else "",
                    error=error_msg,
                    tenant_id=self.tenant_id,
                    rule_version=self.rule_version,
                    metadata=metadata or {},
                    prev_record_hash=self._chain_hashes[-1] if self._chain_hashes else "genesis",
                )
            )

    def record_operation(
        self,
        operation: str,
        *,
        input_text: str = "",
        human_oversight_applied: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> _OperationContext:
        """Context manager for manual operation recording.

        Usage::

            with logger.record_operation("classify_risk", input_text=text) as ctx:
                result = model.classify(text)
                ctx.set_output(result)
        """
        return _OperationContext(
            log=self,
            operation=operation,
            input_text=input_text,
            human_oversight_applied=human_oversight_applied,
            metadata=metadata or {},
        )

    def _append(self, record: Article12Record) -> None:
        """Append a record and update the chain hash."""
        chain_input = f"{record.prev_record_hash}|{record.record_hash}"
        chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()[:16]
        self._records.append(record)
        self._chain_hashes.append(chain_hash)

        # Trim old records if over limit (keep most recent)
        if len(self._records) > self.max_records:
            self._records = self._records[-self.max_records :]
            self._chain_hashes = self._chain_hashes[-self.max_records :]

    def verify_chain(self) -> bool:
        """Verify the tamper-evident chain integrity.

        Returns True if no records have been modified since creation.
        """
        if not self._records:
            return True

        for i, record in enumerate(self._records):
            prev_hash = record.prev_record_hash
            chain_input = f"{prev_hash}|{record.record_hash}"
            expected = hashlib.sha256(chain_input.encode()).hexdigest()[:16]
            if expected != self._chain_hashes[i]:
                return False

        return True

    @property
    def records(self) -> list[Article12Record]:
        """All records (read-only copy)."""
        return list(self._records)

    @property
    def record_count(self) -> int:
        """Return the number of records in the audit log."""
        return len(self._records)

    def export_jsonl(self, path: str | Path, *, append: bool = True) -> None:
        """Export records as append-only JSONL (EU AI Act Article 12 format).

        Args:
            path: Destination file path.
            append: If True (default), append to existing file rather than overwrite.
                    Append-only files are harder to tamper with.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with open(path, mode) as f:
            for record in self._records:
                f.write(json.dumps(record.to_dict(), separators=(",", ":"), default=str))
                f.write("\n")

    def export_dict(self) -> dict[str, Any]:
        """Export as a dictionary with chain integrity status."""
        return {
            "system_id": self.system_id,
            "record_count": len(self._records),
            "chain_valid": self.verify_chain(),
            "risk_level": self.risk_level,
            "constitutional_hash": CONSTITUTIONAL_HASH,
            "records": [r.to_dict() for r in self._records],
        }

    def compliance_summary(self) -> dict[str, Any]:
        """Return an Article 12 compliance summary for this logger instance.

        Useful for including in compliance reports.
        """
        if not self._records:
            return {
                "article": "Article 12 — Record-Keeping",
                "compliant": True,
                "record_count": 0,
                "chain_valid": True,
                "system_id": self.system_id,
                "note": "No operations logged yet.",
            }

        total = len(self._records)
        failures = sum(1 for r in self._records if r.outcome == "failure")
        human_reviewed = sum(1 for r in self._records if r.human_oversight_applied)

        return {
            "article": "Article 12 — Record-Keeping",
            "compliant": self.verify_chain(),
            "record_count": total,
            "failure_count": failures,
            "human_oversight_rate": round(human_reviewed / total, 4) if total else 0.0,
            "chain_valid": self.verify_chain(),
            "retention_period_years": RETENTION_PERIOD_YEARS,
            "constitutional_hash": CONSTITUTIONAL_HASH,
            "system_id": self.system_id,
            "risk_level": self.risk_level,
        }

    def __repr__(self) -> str:
        return (
            f"Article12Logger(system_id={self.system_id!r}, "
            f"records={len(self._records)}, "
            f"chain_valid={self.verify_chain()})"
        )


class _OperationContext:
    """Internal context manager for manual operation recording."""

    def __init__(
        self,
        log: Article12Logger,
        operation: str,
        input_text: str,
        human_oversight_applied: bool,
        metadata: dict[str, Any],
    ) -> None:
        self._log = log
        self._operation = operation
        self._input_text = input_text
        self._human_oversight_applied = human_oversight_applied
        self._metadata = metadata
        self._output_text = ""
        self._start = 0.0
        self._record_id = str(uuid.uuid4())[:8]

    def set_output(self, output: Any) -> None:
        """Record the operation output for hashing."""
        if isinstance(output, str):
            self._output_text = output
        else:
            self._output_text = str(output)[:500]

    def __enter__(self) -> _OperationContext:
        self._start = time.perf_counter()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        latency_ms = (time.perf_counter() - self._start) * 1000
        outcome = "failure" if exc_val is not None else "success"
        error_msg = str(exc_val)[:500] if exc_val is not None else None

        self._log._append(
            Article12Record(
                record_id=self._record_id,
                system_id=self._log.system_id,
                operation=self._operation,
                timestamp=datetime.now(timezone.utc).isoformat(),
                outcome=outcome,
                constitutional_hash=CONSTITUTIONAL_HASH,
                human_oversight_applied=self._human_oversight_applied,
                risk_level=self._log.risk_level,
                retention_period_years=RETENTION_PERIOD_YEARS,
                latency_ms=round(latency_ms, 3),
                input_hash=_hash_content(self._input_text) if self._input_text else "",
                output_hash=_hash_content(self._output_text) if self._output_text else "",
                error=error_msg,
                tenant_id=self._log.tenant_id,
                rule_version=self._log.rule_version,
                metadata=self._metadata,
                prev_record_hash=(
                    self._log._chain_hashes[-1] if self._log._chain_hashes else "genesis"
                ),
            )
        )
