"""In-process single-use grant consumption and terminal attempt records."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from acgs_lite.legitimacy.invariants import LegitimacyInvariantError
from acgs_lite.legitimacy.invocation import InvocationBinding, PolicyBinding


class AttemptStatus(str, Enum):
    """Terminal and in-flight execution-attempt states."""

    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"
    CANCELLED = "cancelled"
    PARTIAL = "partial"


@dataclass(slots=True)
class ExecutionAttemptRecord:
    """Pre/post-execution attempt evidence. Only COMPLETED is success evidence."""

    attempt_id: str
    grant_id: str
    decision_receipt_hash: str
    policy_digest: str
    argument_digest: str
    method_id: str
    status: AttemptStatus
    output_sha256: str | None
    error_code: str | None
    started_at: str
    finished_at: str | None


@dataclass(slots=True)
class ConsumeDecision:
    """Result of an atomic consume: execute now, or recover a prior attempt."""

    mode: str  # "proceed" | "recover"
    record: ExecutionAttemptRecord
    result: Any = None


class InProcessGrantLedger:
    """Thread-safe process-local ledger. Not durable across processes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grant_attempt: dict[str, str] = {}
        self._attempts: dict[str, ExecutionAttemptRecord] = {}
        self._results: dict[str, Any] = {}
        self._bindings: dict[str, tuple[str, str, str, str | None, tuple[str, ...]]] = {}

    def consume(
        self,
        *,
        grant_id: str,
        attempt_id: str,
        receipt_hash: str,
        invocation: InvocationBinding,
        policy: PolicyBinding,
    ) -> ConsumeDecision:
        """Atomically reserve or recover one attempt for a single-use grant."""
        binding = (
            invocation.method_id,
            invocation.argument_digest,
            policy.digest,
            invocation.scope,
            invocation.subjects,
        )
        with self._lock:
            existing = self._grant_attempt.get(grant_id)
            if existing is None:
                now = datetime.now(timezone.utc).isoformat()
                record = ExecutionAttemptRecord(
                    attempt_id=attempt_id,
                    grant_id=grant_id,
                    decision_receipt_hash=receipt_hash,
                    policy_digest=policy.digest,
                    argument_digest=invocation.argument_digest,
                    method_id=invocation.method_id,
                    status=AttemptStatus.STARTED,
                    output_sha256=None,
                    error_code=None,
                    started_at=now,
                    finished_at=None,
                )
                self._grant_attempt[grant_id] = attempt_id
                self._attempts[attempt_id] = record
                self._bindings[grant_id] = binding
                return ConsumeDecision(mode="proceed", record=record)

            if existing != attempt_id:
                raise LegitimacyInvariantError("single-use grant already consumed")
            if self._bindings.get(grant_id) != binding:
                raise LegitimacyInvariantError("grant cannot move across invocation bindings")
            record = self._attempts[existing]
            if record.status is AttemptStatus.COMPLETED:
                return ConsumeDecision(
                    mode="recover",
                    record=record,
                    result=self._results.get(existing),
                )
            if record.status is AttemptStatus.STARTED:
                return ConsumeDecision(mode="proceed", record=record)
            return ConsumeDecision(mode="recover", record=record, result=None)

    def finalize(
        self,
        *,
        attempt_id: str,
        status: AttemptStatus,
        result: Any = None,
        error_code: str | None = None,
        output_sha256: str | None = None,
    ) -> ExecutionAttemptRecord:
        """Commit a terminal attempt record. First terminal write wins."""
        if status is AttemptStatus.STARTED:
            raise ValueError("finalize requires a terminal status")
        with self._lock:
            record = self._attempts.get(attempt_id)
            if record is None:
                raise LegitimacyInvariantError("unknown execution attempt")
            if record.status is not AttemptStatus.STARTED:
                return record
            record.status = status
            record.error_code = error_code
            record.output_sha256 = output_sha256
            record.finished_at = datetime.now(timezone.utc).isoformat()
            if status is AttemptStatus.COMPLETED:
                self._results[attempt_id] = result
            return record


def digest_output(value: Any) -> str | None:
    """Best-effort SHA-256 of a stringified result. None if not representable."""
    if value is None:
        return hashlib.sha256(b"null").hexdigest()
    try:
        payload = repr(value).encode("utf-8")
    except Exception:
        return None
    return hashlib.sha256(payload).hexdigest()


__all__ = [
    "AttemptStatus",
    "ConsumeDecision",
    "ExecutionAttemptRecord",
    "InProcessGrantLedger",
    "digest_output",
]
