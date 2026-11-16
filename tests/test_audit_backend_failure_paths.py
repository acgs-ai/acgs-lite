"""Failure-path tests for AuditLog backends: rollback, poisoning, import validation.

Every failure test asserts the post-failure state (entry count and
``verify_chain()``), not just the exception.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.audit import AuditEntry, AuditLog, InMemoryAuditBackend, JSONLAuditBackend


def _entry(i: int) -> AuditEntry:
    return AuditEntry(id=f"e{i}", type="validation", agent_id="a", action=f"act {i}")


def _raiser(log: AuditLog) -> None:
    raise RuntimeError("persist failed")


@pytest.fixture
def open_backend(tmp_path: Path) -> Iterator[Callable[..., Any]]:
    """Factory for JSONL backends that are always closed on teardown."""
    created: list[JSONLAuditBackend] = []

    def _make(cls: type[JSONLAuditBackend], path: Path) -> Any:
        backend = cls(path)
        created.append(backend)
        return backend

    yield _make
    for backend in created:
        backend.close()


class _FailingWriteBackend(InMemoryAuditBackend):
    def write(self, entry_dict: dict[str, Any], chain_hash: str) -> None:
        raise OSError("disk full")


class _NoRollbackJSONL(JSONLAuditBackend):
    @property
    def rollback_to(self) -> Any:  # type: ignore[override]
        raise AttributeError("rollback_to")


class _RollbackFailsJSONL(JSONLAuditBackend):
    def rollback_to(self, token: int) -> None:
        raise OSError("truncate failed")


class _PlainBackend:
    """Backend with write/flush/read_all only: no checkpoint support."""

    def __init__(self) -> None:
        self.rows: list[tuple[dict[str, Any], str]] = []

    def write(self, entry_dict: dict[str, Any], chain_hash: str) -> None:
        self.rows.append((entry_dict, chain_hash))

    def flush(self) -> None:
        pass

    def read_all(self) -> list[tuple[dict[str, Any], str]]:
        return list(self.rows)


class _RowsBackend:
    def __init__(self, rows: list[tuple[dict[str, Any], str]]) -> None:
        self._rows = rows

    def write(self, entry_dict: dict[str, Any], chain_hash: str) -> None:
        pass

    def flush(self) -> None:
        pass

    def read_all(self) -> list[tuple[dict[str, Any], str]]:
        return [(dict(row), chain_hash) for row, chain_hash in self._rows]


class _ProofCert:
    def to_audit_dict(self) -> dict[str, str]:
        return {"proof": "ok"}


class _Prov:
    def to_dict(self) -> dict[str, str]:
        return {"src": "x"}


# -- best-effort record() ----------------------------------------------------


def test_best_effort_record_logs_backend_write_failure(caplog: pytest.LogCaptureFixture) -> None:
    log = AuditLog(backend=_FailingWriteBackend())
    with caplog.at_level(logging.WARNING):
        chain_hash = log.record(_entry(1))
    assert len(chain_hash) == 64
    assert len(log) == 1
    assert log.verify_chain() is True
    assert "audit backend write failed" in caplog.text


def test_record_injects_proof_and_provenance_metadata() -> None:
    log = AuditLog()
    first = _entry(1)
    log.record(first, proof_certificate=_ProofCert(), provenance=_Prov())
    assert first.metadata == {"proof_certificate": {"proof": "ok"}, "provenance": {"src": "x"}}

    second = _entry(2)
    log.record(second, proof_certificate={"raw": 1}, provenance={"raw": 2})
    assert second.metadata == {"proof_certificate": {"raw": 1}, "provenance": {"raw": 2}}
    assert len(log) == 2
    assert log.verify_chain() is True


def test_inmemory_flush_is_noop_and_repr() -> None:
    log = AuditLog(backend=InMemoryAuditBackend())
    log.record(_entry(1))
    log.flush()
    assert len(log) == 1
    assert repr(log) == "AuditLog(entries=1, compliance=100.0%, chain_valid=True)"


# -- strict durability guards and rollback poisoning -------------------------


def test_validate_durable_state_requires_jsonl_backend() -> None:
    with pytest.raises(RuntimeError, match="requires a durable backend"):
        AuditLog(backend=InMemoryAuditBackend()).validate_durable_state()
    with pytest.raises(RuntimeError, match="requires a durable backend"):
        AuditLog().validate_durable_state()


def test_record_durable_rejects_backend_without_rollback(
    tmp_path: Path, open_backend: Callable[..., Any]
) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(backend=open_backend(_NoRollbackJSONL, path))
    with pytest.raises(RuntimeError, match="lacks checkpoint"):
        log.record_durable(_entry(1))
    assert len(log) == 0
    assert log.verify_chain() is True
    assert path.read_text() == ""


def test_atomic_paths_warn_without_checkpoint_support(caplog: pytest.LogCaptureFixture) -> None:
    log = AuditLog(backend=_PlainBackend())
    with caplog.at_level(logging.WARNING):
        log.record_atomic(_entry(1))
        log.record_atomic_many([_entry(2), _entry(3)])
    assert caplog.text.count("does not implement begin_checkpoint") == 2
    assert len(log) == 3
    assert log.verify_chain() is True

    # Documented limitation, deliberately not asserted because it is not desired
    # behaviour: without checkpoint support the backend keeps the row written
    # before the failed persist step.
    with pytest.raises(RuntimeError, match="persist failed"):
        log.record_atomic(_entry(4), persist=_raiser)
    assert len(log) == 3
    assert log.verify_chain() is True


@pytest.mark.parametrize("many", [False, True])
def test_atomic_rollback_failure_poisons_strict_log(
    many: bool,
    tmp_path: Path,
    open_backend: Callable[..., Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    log = AuditLog(backend=open_backend(_RollbackFailsJSONL, tmp_path / "a.jsonl"))
    log.record_durable(_entry(0))

    with caplog.at_level(logging.ERROR), pytest.raises(RuntimeError, match="persist failed"):
        if many:
            log.record_atomic_many([_entry(1), _entry(2)], persist=_raiser)
        else:
            log.record_atomic(_entry(1), persist=_raiser)
    assert "audit backend rollback failed" in caplog.text
    assert len(log) == 1
    assert log.verify_chain() is True

    with pytest.raises(RuntimeError, match="poisoned"):
        log.validate_durable_state()
    with pytest.raises(RuntimeError, match="poisoned"):
        log.record_durable(_entry(9))
    assert len(log) == 1
    assert log.verify_chain() is True


# -- JSONL backend file states ----------------------------------------------


def test_jsonl_write_rejects_unsupported_hash_length(
    tmp_path: Path, open_backend: Callable[..., Any]
) -> None:
    backend = open_backend(JSONLAuditBackend, tmp_path / "a.jsonl")
    with pytest.raises(ValueError, match="unsupported audit chain hash length"):
        backend.write({"id": "x"}, "abc")
    backend.flush()
    assert backend.read_all() == []


def test_jsonl_read_all_skips_blank_lines_and_handles_missing_file(
    tmp_path: Path, open_backend: Callable[..., Any]
) -> None:
    path = tmp_path / "a.jsonl"
    backend = open_backend(JSONLAuditBackend, path)
    AuditLog(backend=backend).record_durable(_entry(1))
    with open(path, "a") as handle:
        handle.write("\n   \n")
    assert len(backend.read_all()) == 1
    recovered = AuditLog.from_backend(backend)
    assert len(recovered) == 1
    assert recovered.verify_chain() is True

    backend.close()
    path.unlink()
    assert backend.read_all() == []


def test_record_durable_rejects_replaced_parent_directory(
    tmp_path: Path, open_backend: Callable[..., Any]
) -> None:
    directory = tmp_path / "sub"
    path = directory / "a.jsonl"
    log = AuditLog(backend=open_backend(JSONLAuditBackend, path))
    log.record_durable(_entry(1))
    size = path.stat().st_size

    # Same file inode (check_identity passes) but a different directory inode.
    os.rename(directory, tmp_path / "old")
    directory.mkdir()
    os.rename(tmp_path / "old" / "a.jsonl", path)

    with pytest.raises(RuntimeError, match="audit directory identity changed"):
        log.record_durable(_entry(2))
    assert len(log) == 1
    assert log.verify_chain() is True
    assert path.stat().st_size == size


# -- import validation -------------------------------------------------------


def _persisted_rows(tmp_path: Path) -> list[tuple[dict[str, Any], str]]:
    backend = JSONLAuditBackend(tmp_path / "src.jsonl")
    try:
        log = AuditLog(backend=backend)
        for i in (1, 2, 3):
            log.record_durable(_entry(i))
        rows = backend.read_all()
    finally:
        backend.close()
    assert [row["_format_version"] for row, _ in rows] == ["sha256-v1"] * 3
    assert all(len(chain_hash) == 64 for _, chain_hash in rows)
    return rows


def test_from_backend_rejects_inconsistent_formats(tmp_path: Path) -> None:
    rows = _persisted_rows(tmp_path)

    mixed_markers = [({**rows[0][0], "_format_version": "legacy-sha256-16"}, rows[0][1]), *rows[1:]]
    with pytest.raises(ValueError, match="mixed or unknown format versions"):
        AuditLog.from_backend(_RowsBackend(mixed_markers))

    unknown_marker = [({**rows[0][0], "_format_version": "md5"}, rows[0][1])]
    with pytest.raises(ValueError, match="mixed or unknown format versions"):
        AuditLog.from_backend(_RowsBackend(unknown_marker))

    mixed_lengths = [(rows[0][0], rows[0][1][:16]), *rows[1:]]
    with pytest.raises(ValueError, match="mixed or unknown chain hash formats"):
        AuditLog.from_backend(_RowsBackend(mixed_lengths))

    marker_mismatch = [(row, chain_hash[:16]) for row, chain_hash in rows]
    with pytest.raises(ValueError, match="format marker does not match"):
        AuditLog.from_backend(_RowsBackend(marker_mismatch))


def test_from_backend_trims_to_max_entries_and_keeps_chain_verifiable(tmp_path: Path) -> None:
    rows = _persisted_rows(tmp_path)
    log = AuditLog.from_backend(_RowsBackend(rows), max_entries=2)
    assert len(log) == 2
    assert [e.id for e in log.entries] == ["e2", "e3"]
    assert log.retained_predecessor_hash == rows[0][1]
    assert log.verify_chain() is True


def test_from_json_rejects_bad_exports(tmp_path: Path) -> None:
    source = AuditLog()
    source.record(_entry(1))
    source.record(_entry(2))
    export = tmp_path / "export.json"
    source.export_json(export)

    loaded = AuditLog.from_json(export)
    assert len(loaded) == 2
    assert loaded.verify_chain() is True

    payload = json.loads(export.read_text())

    def _write(**changes: Any) -> Path:
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({**payload, **changes}))
        return path

    with pytest.raises(ValueError, match="unknown audit export format"):
        AuditLog.from_json(_write(format_version="md5"))

    with pytest.raises(ValueError, match="malformed audit export"):
        AuditLog.from_json(_write(chain_hashes=payload["chain_hashes"][:1]))
    with pytest.raises(ValueError, match="malformed audit export"):
        AuditLog.from_json(_write(entries="x"))

    tampered = [dict(item) for item in payload["entries"]]
    tampered[0]["action"] = "tampered"
    with pytest.raises(ValueError, match="chain verification failed"):
        AuditLog.from_json(_write(entries=tampered))
