# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Audit trail — tamper-evident logging for governance actions.

Every validation, every decision, every override gets recorded.
The audit log provides cryptographic proof of governance compliance.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_RETENTION_DAYS = 90


@dataclass(frozen=True, slots=True)
class AuditInvariantContract:
    """Explicit audit-trail invariants for a concrete runtime/backend adapter."""

    runtime: str
    adapter: str
    constitutional_hash: str
    append_only: bool
    hash_chain: bool
    retention_days: int | None
    durable: bool
    default_persistence_mode: Literal["best-effort", "fail-closed"]
    supports_fail_closed_persistence: bool


def describe_audit_backend(
    backend: AuditBackend | None,
    *,
    constitutional_hash: str,
) -> AuditInvariantContract:
    """Describe the audit invariants exposed by *backend*.

    ``record()`` is best-effort for all current backends: it preserves in-memory
    chain integrity and logs backend failures, but only ``record_atomic()``
    provides fail-closed persistence semantics when the backend can roll back a
    durable append.
    """

    if backend is None or isinstance(backend, InMemoryAuditBackend):
        return AuditInvariantContract(
            runtime="python",
            adapter="memory",
            constitutional_hash=constitutional_hash,
            append_only=True,
            hash_chain=True,
            retention_days=None,
            durable=False,
            default_persistence_mode="best-effort",
            supports_fail_closed_persistence=False,
        )

    if isinstance(backend, JSONLAuditBackend):
        return AuditInvariantContract(
            runtime="python",
            adapter="jsonl",
            constitutional_hash=constitutional_hash,
            append_only=True,
            hash_chain=True,
            retention_days=DEFAULT_AUDIT_RETENTION_DAYS,
            durable=True,
            default_persistence_mode="best-effort",
            supports_fail_closed_persistence=True,
        )

    return AuditInvariantContract(
        runtime="python",
        adapter=type(backend).__name__,
        constitutional_hash=constitutional_hash,
        append_only=True,
        hash_chain=True,
        retention_days=DEFAULT_AUDIT_RETENTION_DAYS,
        durable=True,
        default_persistence_mode="best-effort",
        supports_fail_closed_persistence=all(
            hasattr(backend, attribute) for attribute in ("begin_checkpoint", "rollback_to")
        ),
    )


# ---------------------------------------------------------------------------
# Backend Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class AuditBackend(Protocol):
    """Pluggable storage backend for audit entries.

    Implementations must be append-only and support chain hash verification.
    """

    def write(self, entry_dict: dict[str, Any], chain_hash: str) -> None:
        """Persist a single audit entry with its chain hash."""
        ...

    def flush(self) -> None:
        """Ensure all buffered writes are durable."""
        ...

    def read_all(self) -> list[tuple[dict[str, Any], str]]:
        """Read all stored (entry_dict, chain_hash) pairs in order."""
        ...

    def begin_checkpoint(self) -> Any:
        """Return an opaque token representing the current backend state.

        Used by ``record_atomic`` to roll back a durable append if persist fails.
        Backends that cannot rewind must still implement this: the returned
        token will be passed unchanged to ``rollback_to``.
        """
        ...

    def rollback_to(self, token: Any) -> None:
        """Revert backend state to the checkpoint represented by *token*."""
        ...


class InMemoryAuditBackend:
    """In-memory backend (default). No durability guarantees."""

    def __init__(self) -> None:
        self._records: list[tuple[dict[str, Any], str]] = []

    def write(self, entry_dict: dict[str, Any], chain_hash: str) -> None:
        self._records.append((entry_dict, chain_hash))

    def flush(self) -> None:
        pass  # no-op for in-memory

    def read_all(self) -> list[tuple[dict[str, Any], str]]:
        return list(self._records)

    def begin_checkpoint(self) -> int:
        return len(self._records)

    def rollback_to(self, token: int) -> None:
        del self._records[token:]


class JSONLAuditBackend:
    """Append-only JSONL file backend with explicit flush/fsync.

    Each line is a JSON object with ``_chain_hash`` alongside the entry fields.
    Retention is a governance policy concern rather than an inline delete path:
    the backend never rewrites historical rows except an immediate rollback from
    ``record_atomic()`` / ``record_atomic_many()`` after a failed persist step.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fd = open(self._path, "a")  # noqa: SIM115

    def write(self, entry_dict: dict[str, Any], chain_hash: str) -> None:
        record = {**entry_dict, "_chain_hash": chain_hash}
        self._fd.write(json.dumps(record, sort_keys=True) + "\n")

    def flush(self) -> None:
        self._fd.flush()
        os.fsync(self._fd.fileno())

    def begin_checkpoint(self) -> int:
        self._fd.flush()
        return self._fd.tell()

    def rollback_to(self, token: int) -> None:
        self._fd.flush()
        self._fd.truncate(token)
        self._fd.seek(token)
        os.fsync(self._fd.fileno())

    def read_all(self) -> list[tuple[dict[str, Any], str]]:
        results: list[tuple[dict[str, Any], str]] = []
        if not self._path.exists():
            return results
        with open(self._path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                chain_hash = record.pop("_chain_hash", "")
                results.append((record, chain_hash))
        return results

    def close(self) -> None:
        self._fd.close()

    def __del__(self) -> None:
        try:
            self._fd.close()
        except Exception as exc:
            logger.debug("failed to close JSONL audit backend file handle: %s", exc, exc_info=True)


@dataclass
class AuditEntry:
    """A single audit log entry."""

    id: str
    type: str  # validation, override, maci_check, stabilizer, failure_mode
    agent_id: str = ""
    action: str = ""
    valid: bool = True
    violations: list[str] = field(default_factory=list)
    constitutional_hash: str = ""
    pqc_signature: str | None = None
    latency_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "agent_id": self.agent_id,
            "action": self.action,
            "valid": self.valid,
            "violations": self.violations,
            "constitutional_hash": self.constitutional_hash,
            "pqc_signature": self.pqc_signature,
            "latency_ms": self.latency_ms,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }

    def to_adapter_dict(self) -> dict[str, Any]:
        """Serialize with adapter-facing policy hash vocabulary."""
        from acgs_lite.legitimacy.receipt import to_receipt_dict

        return to_receipt_dict(self)

    @property
    def entry_hash(self) -> str:
        """Hash of this entry for chain integrity."""
        entry_dict = self.to_dict()
        entry_dict.pop("pqc_signature", None)
        canonical = json.dumps(entry_dict, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


class AuditLog:
    """Tamper-evident audit log.

    Records all governance decisions with cryptographic chaining.
    Each entry's hash includes the previous entry's hash, creating
    a chain that detects tampering.

    Usage::

        log = AuditLog()
        log.record(AuditEntry(id="1", type="validation", valid=True))
        log.export_json("audit.json")
    """

    def __init__(
        self,
        max_entries: int = 10000,
        backend: AuditBackend | None = None,
        pqc_signer: Any | None = None,
    ) -> None:
        self._entries: list[AuditEntry] = []
        self._chain_hashes: list[str] = []
        self.max_entries = max_entries
        self._backend = backend
        self._pqc_signer = pqc_signer
        # Protects _entries / _chain_hashes against concurrent record() calls
        # from multi-agent or multi-threaded workloads. Chain hash integrity
        # requires read-modify-write atomicity.
        #
        # RLock (not plain Lock) because record_atomic() holds the lock across
        # a user-supplied ``persist`` callback whose implementation may call
        # back into the log (``export_json`` → ``verify_chain`` re-acquires
        # the lock).  With a plain Lock that would deadlock; with RLock the
        # re-entry is safe and the transaction remains serialized against
        # other writers.
        self._lock = threading.RLock()

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def invariant_contract(
        self, constitutional_hash: str = "608508a9bd224290"
    ) -> AuditInvariantContract:
        """Return the explicit audit-trail invariants for this log instance."""
        return describe_audit_backend(
            self._backend,
            constitutional_hash=constitutional_hash,
        )

    def record(
        self,
        entry: AuditEntry,
        *,
        proof_certificate: Any | None = None,
        provenance: Any | None = None,
    ) -> str:
        """Record an audit entry and return its chain hash.

        The chain hash includes the previous entry's hash, providing
        tamper detection. This method is intentionally best-effort for durable
        backends; callers that require fail-closed persistence should use
        ``record_atomic()`` instead.
        """
        self._prepare_entry(entry, proof_certificate, provenance)

        # Chain hash computation + append + backend write must all be serialized.
        # Previously the backend write happened outside the lock as an I/O
        # optimization, but that let a record() from thread B race past a
        # concurrent record_atomic() from thread A: if B's write landed
        # between A's checkpoint and A's persist, A's rollback_to() would
        # truncate the backend past B's committed entry. Correctness
        # requires the backend write to be ordered against the state lock.
        with self._lock:
            chain_hash = self._append_locked(entry)
            if self._backend is not None:
                try:
                    self._backend.write(entry.to_dict(), chain_hash)
                except Exception as exc:
                    logger.warning("audit backend write failed: %s", exc, exc_info=True)

        return chain_hash

    def _prepare_entry(
        self,
        entry: AuditEntry,
        proof_certificate: Any | None,
        provenance: Any | None,
    ) -> None:
        """Inject metadata + signature onto *entry* before append. Lock-free."""
        if proof_certificate is not None:
            entry.metadata["proof_certificate"] = (
                proof_certificate.to_audit_dict()
                if hasattr(proof_certificate, "to_audit_dict")
                else proof_certificate
            )
        if provenance is not None:
            entry.metadata["provenance"] = (
                provenance.to_dict() if hasattr(provenance, "to_dict") else provenance
            )
        if self._pqc_signer is not None:
            entry.pqc_signature = self._pqc_signer.sign(entry.entry_hash.encode())

    def _append_locked(self, entry: AuditEntry) -> str:
        """Compute chain hash, append entry + hash, trim if needed. Caller holds ``_lock``."""
        prev_hash = self._chain_hashes[-1] if self._chain_hashes else "genesis"
        chain_input = f"{prev_hash}|{entry.entry_hash}"
        chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()[:16]

        self._entries.append(entry)
        self._chain_hashes.append(chain_hash)

        if len(self._entries) > self.max_entries:
            self._entries = self._entries[-self.max_entries :]
            self._chain_hashes = self._chain_hashes[-self.max_entries :]
            first_chain_input = f"genesis|{self._entries[0].entry_hash}"
            self._chain_hashes[0] = hashlib.sha256(first_chain_input.encode()).hexdigest()[:16]

        return chain_hash

    def record_atomic(
        self,
        entry: AuditEntry,
        *,
        persist: Callable[[AuditLog], None] | None = None,
        proof_certificate: Any | None = None,
        provenance: Any | None = None,
    ) -> str:
        """Record *entry* and, if *persist* is supplied, invoke it atomically.

        Snapshot + append + persist run under a single held lock so that a
        rollback on persist failure cannot wipe out concurrent writers that
        raced in between snapshotting and persisting.  If ``persist``
        raises, the just-appended entry and its chain hash are rolled
        back so a retry does not produce a duplicate audit history with
        a different ``id``.

        Because the lock is held across the persist callback, this
        operation serializes writers — callers that care about write
        throughput should keep ``persist`` I/O-light.  The lock is an
        RLock, so callbacks may re-enter the log (``export_json``
        calls back into ``verify_chain``, for example) without
        deadlocking.

        Note on trimming: if appending *entry* pushed the log past
        ``max_entries``, the trim is applied *before* persist runs.
        Rollback restores the pre-append snapshot (including the trimmed
        entry) so the log is fully reverted rather than left in a
        silently-smaller state.

        Durability: the backend write is performed *inside* the lock and
        is covered by rollback. If the backend implements
        ``begin_checkpoint`` / ``rollback_to`` (both ``InMemoryAuditBackend``
        and ``JSONLAuditBackend`` do), a persist failure truncates the
        durable log back to its pre-append state so a later
        ``from_backend`` reconstruction will not replay a phantom entry.
        Backends that don't implement checkpointing get a warning logged
        — the in-memory state still rolls back, but durable divergence
        cannot be prevented.
        """
        self._prepare_entry(entry, proof_certificate, provenance)

        with self._lock:
            pre_entries = list(self._entries)
            pre_chain_hashes = list(self._chain_hashes)

            checkpoint: Any = None
            can_checkpoint = self._backend is not None and hasattr(
                self._backend, "begin_checkpoint"
            )
            if can_checkpoint:
                checkpoint = self._backend.begin_checkpoint()  # type: ignore[union-attr]
            elif self._backend is not None:
                logger.warning(
                    "audit backend %s does not implement begin_checkpoint; "
                    "record_atomic rollback cannot cover durable state",
                    type(self._backend).__name__,
                )

            chain_hash = self._append_locked(entry)

            try:
                if self._backend is not None:
                    self._backend.write(entry.to_dict(), chain_hash)
                if persist is not None:
                    persist(self)
            except Exception:
                self._entries = pre_entries
                self._chain_hashes = pre_chain_hashes
                if can_checkpoint:
                    try:
                        self._backend.rollback_to(checkpoint)  # type: ignore[union-attr]
                    except Exception as rb_exc:
                        logger.error("audit backend rollback failed: %s", rb_exc, exc_info=True)
                raise

            return chain_hash

    def record_atomic_many(
        self,
        entries: list[AuditEntry],
        *,
        persist: Callable[[AuditLog], None] | None = None,
        proof_certificate: Any | None = None,
        provenance: Any | None = None,
    ) -> list[str]:
        """Record multiple *entries* atomically, invoking *persist* once after all appends.

        Semantics mirror :meth:`record_atomic` for a batch: snapshot + appends +
        backend writes + persist all run under a single held lock, and if *any*
        step raises, the log is rolled back to its pre-batch state (in-memory +
        durable backend via ``rollback_to`` when supported). Callers therefore
        never observe a partial batch after a failure, and a retry will not
        duplicate audit history with different IDs.

        Each entry is prepared (metadata/signature) lock-free, then the whole
        batch is committed under ``_lock``. Returns the list of chain hashes in
        the same order as *entries*. If *entries* is empty, no lock is acquired
        and an empty list is returned.
        """
        if not entries:
            return []

        for entry in entries:
            self._prepare_entry(entry, proof_certificate, provenance)

        with self._lock:
            pre_entries = list(self._entries)
            pre_chain_hashes = list(self._chain_hashes)

            checkpoint: Any = None
            can_checkpoint = self._backend is not None and hasattr(
                self._backend, "begin_checkpoint"
            )
            if can_checkpoint:
                checkpoint = self._backend.begin_checkpoint()  # type: ignore[union-attr]
            elif self._backend is not None:
                logger.warning(
                    "audit backend %s does not implement begin_checkpoint; "
                    "record_atomic_many rollback cannot cover durable state",
                    type(self._backend).__name__,
                )

            chain_hashes: list[str] = []
            try:
                for entry in entries:
                    chain_hash = self._append_locked(entry)
                    chain_hashes.append(chain_hash)
                    if self._backend is not None:
                        self._backend.write(entry.to_dict(), chain_hash)
                if persist is not None:
                    persist(self)
            except Exception:
                self._entries = pre_entries
                self._chain_hashes = pre_chain_hashes
                if can_checkpoint:
                    try:
                        self._backend.rollback_to(checkpoint)  # type: ignore[union-attr]
                    except Exception as rb_exc:
                        logger.error("audit backend rollback failed: %s", rb_exc, exc_info=True)
                raise

            return chain_hashes

    def flush(self) -> None:
        """Flush pending writes to the backend. No-op if no backend."""
        if self._backend is not None:
            self._backend.flush()

    @classmethod
    def from_backend(cls, backend: AuditBackend, max_entries: int = 10000) -> AuditLog:
        """Reconstruct an AuditLog from a durable backend.

        Reads all persisted entries and rebuilds the in-memory chain.
        """
        log = cls(max_entries=max_entries, backend=backend)
        for entry_dict, chain_hash in backend.read_all():
            entry = AuditEntry(
                id=entry_dict.get("id", ""),
                type=entry_dict.get("type", ""),
                agent_id=entry_dict.get("agent_id", ""),
                action=entry_dict.get("action", ""),
                valid=entry_dict.get("valid", True),
                violations=entry_dict.get("violations", []),
                constitutional_hash=entry_dict.get("constitutional_hash", ""),
                pqc_signature=entry_dict.get("pqc_signature"),
                latency_ms=entry_dict.get("latency_ms", 0.0),
                metadata=entry_dict.get("metadata", {}),
                timestamp=entry_dict.get("timestamp", ""),
            )
            log._entries.append(entry)
            log._chain_hashes.append(chain_hash)
        # Trim to max if needed
        if len(log._entries) > max_entries:
            log._entries = log._entries[-max_entries:]
            log._chain_hashes = log._chain_hashes[-max_entries:]
        return log

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire audit chain.

        Returns True if no entries have been tampered with.
        """
        with self._lock:
            entries = list(self._entries)
            chain_hashes = list(self._chain_hashes)

        if not entries:
            return True

        prev_hash = "genesis"
        for i, entry in enumerate(entries):
            chain_input = f"{prev_hash}|{entry.entry_hash}"
            expected = hashlib.sha256(chain_input.encode()).hexdigest()[:16]

            if expected != chain_hashes[i]:
                return False

            prev_hash = chain_hashes[i]

        return True

    def query(
        self,
        *,
        agent_id: str | None = None,
        entry_type: str | None = None,
        valid: bool | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit entries with filters."""
        results = self._entries

        if agent_id is not None:
            results = [e for e in results if e.agent_id == agent_id]
        if entry_type is not None:
            results = [e for e in results if e.type == entry_type]
        if valid is not None:
            results = [e for e in results if e.valid == valid]

        return results[-limit:]

    def export_json(self, path: str | Path) -> None:
        """Export audit log to JSON file."""
        data = {
            "entries": [e.to_dict() for e in self._entries],
            "chain_valid": self.verify_chain(),
            "entry_count": len(self._entries),
        }
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def export_dicts(self) -> list[dict[str, Any]]:
        """Export audit log as list of dicts."""
        return [e.to_dict() for e in self._entries]

    @property
    def compliance_rate(self) -> float:
        """Percentage of valid entries."""
        if not self._entries:
            return 1.0
        valid_count = sum(1 for e in self._entries if e.valid)
        return valid_count / len(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return (
            f"AuditLog(entries={len(self._entries)}, "
            f"compliance={self.compliance_rate:.1%}, "
            f"chain_valid={self.verify_chain()})"
        )
