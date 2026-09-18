"""Regression tests for retained audit anchors and durable confirmation."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.audit import AuditEntry, AuditLog, InMemoryAuditBackend, JSONLAuditBackend


def _entry(index: int) -> AuditEntry:
    return AuditEntry(id=str(index), type="validation", action=f"action-{index}")


def test_new_chain_uses_full_sha256_and_retains_anchor_across_repeated_trims() -> None:
    log = AuditLog(max_entries=2)
    hashes = [log.record(_entry(index)) for index in range(4)]

    assert all(len(chain_hash) == 64 for chain_hash in hashes)
    assert [entry.id for entry in log.entries] == ["2", "3"]
    assert log.retained_predecessor_hash == hashes[1]
    assert log.verify_chain()


def test_export_and_load_round_trip_retained_window_metadata(tmp_path: Path) -> None:
    original = AuditLog(max_entries=2)
    for index in range(3):
        original.record(_entry(index))
    export_path = tmp_path / "audit.json"

    original.export_json(export_path)
    payload = json.loads(export_path.read_text())
    restored = AuditLog.from_json(export_path)

    assert payload["format_version"] == "sha256-v1"
    assert payload["retained_predecessor_hash"] == original.retained_predecessor_hash
    assert restored.retained_predecessor_hash == original.retained_predecessor_hash
    assert restored.verify_chain()


def test_legacy_16_hex_backend_rows_verify_without_rewriting() -> None:
    backend = InMemoryAuditBackend()
    entry = _entry(1)
    legacy_hash = hashlib.sha256(f"genesis|{entry.entry_hash[:16]}".encode()).hexdigest()[:16]
    backend.write(entry.to_dict(), legacy_hash)

    restored = AuditLog.from_backend(backend)

    assert restored.hash_format == "legacy-sha256-16"
    assert restored.verify_chain()
    assert backend.read_all()[0][1] == legacy_hash


@pytest.mark.parametrize("marked", [False, True])
def test_legacy_signature_digest_survives_load_export_and_append(
    tmp_path: Path, marked: bool
) -> None:
    class Signer:
        def sign(self, message: bytes) -> str:
            return hmac.new(b"synthetic-test-key", message, hashlib.sha256).hexdigest()

    signer = Signer()
    entry = _entry(1)
    old_digest = entry.entry_hash[:16]
    entry.pqc_signature = signer.sign(old_digest.encode())
    chain = hashlib.sha256(f"genesis|{old_digest}".encode()).hexdigest()[:16]
    row = {**entry.to_dict(), "_chain_hash": chain}
    if marked:
        row["_format_version"] = "legacy-sha256-16"
    path = tmp_path / "legacy.jsonl"
    path.write_text(json.dumps(row) + "\n")
    original_bytes = path.read_bytes()
    backend = JSONLAuditBackend(path)
    restored = AuditLog.from_backend(backend)
    loaded = restored.entries[0]
    assert loaded.signature_digest == old_digest
    assert signer.sign(loaded.signature_digest.encode()) == loaded.pqc_signature
    assert len(loaded.entry_hash) == 64
    assert path.read_bytes() == original_bytes
    exported = tmp_path / "export.json"
    restored.export_json(exported)
    assert AuditLog.from_json(exported).entries[0].signature_digest == old_digest
    restored._pqc_signer = signer
    restored.record_durable(_entry(2))
    reloaded = AuditLog.from_backend(backend)
    assert reloaded.verify_chain()
    assert all(
        signer.sign(e.signature_digest.encode()) == e.pqc_signature for e in reloaded.entries
    )
    assert all(len(e.signature_digest) == 16 for e in reloaded.entries)
    assert path.read_bytes().startswith(original_bytes)
    loaded.action = "changed"
    assert signer.sign(loaded.signature_digest.encode()) != loaded.pqc_signature


def test_new_audit_signature_uses_full_digest() -> None:
    class Signer:
        def sign(self, message: bytes) -> str:
            return message.hex()

    backend = InMemoryAuditBackend()
    log = AuditLog(backend=backend, pqc_signer=Signer())
    log.record(_entry(1))
    entry = AuditLog.from_backend(backend).entries[0]
    assert entry.signature_digest == entry.entry_hash
    assert len(entry.signature_digest) == 64
    assert entry.pqc_signature == entry.signature_digest.encode().hex()


class _FaultBackend(JSONLAuditBackend):
    def __init__(
        self,
        path: Path,
        *,
        fail_flush: bool = False,
        fail_rollback: bool = False,
    ) -> None:
        super().__init__(path)
        self.fail_flush = fail_flush
        self.fail_rollback = fail_rollback
        self.flush_calls = 0

    def flush(self) -> None:
        self.flush_calls += 1
        if self.fail_flush:
            raise OSError("flush failed")

    def rollback_to(self, token: Any) -> None:
        if self.fail_rollback:
            raise OSError("rollback failed")
        super().rollback_to(token)


def test_durable_record_confirms_flush_before_return(tmp_path: Path) -> None:
    backend = _FaultBackend(tmp_path / "audit.jsonl")
    log = AuditLog(backend=backend)

    chain_hash = log.record_durable(_entry(1))

    assert len(chain_hash) == 64
    assert backend.flush_calls == 1
    assert len(log) == 1


def test_durable_record_rolls_back_memory_and_backend_on_flush_failure(tmp_path: Path) -> None:
    backend = _FaultBackend(tmp_path / "audit.jsonl", fail_flush=True)
    log = AuditLog(backend=backend)

    with pytest.raises(OSError, match="flush failed"):
        log.record_durable(_entry(1))

    assert len(log) == 0
    assert backend.read_all() == []


def test_durable_record_rolls_back_memory_when_backend_write_fails(tmp_path: Path) -> None:
    class WriteFailureBackend(JSONLAuditBackend):
        def write(self, entry_dict: dict[str, Any], chain_hash: str) -> None:
            raise OSError("write failed")

    backend = WriteFailureBackend(tmp_path / "audit.jsonl")
    log = AuditLog(backend=backend)

    with pytest.raises(OSError, match="write failed"):
        log.record_durable(_entry(1))

    assert len(log) == 0
    assert backend.read_all() == []


def test_failed_durable_rollback_poisons_future_strict_appends(tmp_path: Path) -> None:
    backend = _FaultBackend(
        tmp_path / "audit.jsonl",
        fail_flush=True,
        fail_rollback=True,
    )
    log = AuditLog(backend=backend)

    with pytest.raises(RuntimeError, match="rollback failed"):
        log.record_durable(_entry(1))
    backend.fail_flush = False
    backend.fail_rollback = False

    with pytest.raises(RuntimeError, match="poisoned"):
        log.record_durable(_entry(2))


def test_plain_memory_backend_is_not_durable() -> None:
    with pytest.raises(RuntimeError, match="durable backend"):
        AuditLog(backend=InMemoryAuditBackend()).record_durable(_entry(1))


class _UnqualifiedBackend:
    def write(self, entry_dict: dict[str, Any], chain_hash: str) -> None:
        pass

    def flush(self) -> None:
        pass

    def read_all(self) -> list[tuple[dict[str, Any], str]]:
        return []

    def begin_checkpoint(self) -> int:
        return 0

    def rollback_to(self, token: int) -> None:
        pass


def test_protocol_shape_alone_does_not_claim_qualified_durability() -> None:
    contract = AuditLog(backend=_UnqualifiedBackend()).invariant_contract()

    assert not contract.durable
    assert not contract.supports_fail_closed_persistence


def test_jsonl_rows_include_explicit_format_version(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    backend = JSONLAuditBackend(path)
    AuditLog(backend=backend).record_durable(_entry(1))

    row = json.loads(path.read_text().strip())

    assert row["_format_version"] == "sha256-v1"


def test_resumed_legacy_jsonl_append_preserves_format_and_reloads(tmp_path: Path) -> None:
    path = tmp_path / "legacy.jsonl"
    first = _entry(1)
    first_hash = hashlib.sha256(f"genesis|{first.entry_hash[:16]}".encode()).hexdigest()[:16]
    path.write_text(json.dumps({**first.to_dict(), "_chain_hash": first_hash}) + "\n")
    backend = JSONLAuditBackend(path)
    restored = AuditLog.from_backend(backend)

    restored.record_durable(_entry(2))
    rows = [json.loads(line) for line in path.read_text().splitlines()]

    assert rows[1]["_format_version"] == "legacy-sha256-16"
    assert len(rows[1]["_chain_hash"]) == 16
    assert AuditLog.from_backend(backend).verify_chain()


def test_actual_fsync_failure_rolls_back_file_without_phantom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"
    backend = JSONLAuditBackend(path)
    log = AuditLog(backend=backend)
    real_fsync = os.fsync
    calls = 0

    def fail_first_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_first_fsync)
    with pytest.raises(OSError, match="fsync failed"):
        log.record_durable(_entry(1))

    assert path.read_bytes() == b""
    assert AuditLog.from_backend(backend).entries == []


def test_recovery_verifies_discarded_prefix_before_trimming() -> None:
    backend = InMemoryAuditBackend()
    source = AuditLog(backend=backend)
    source.record(_entry(1))
    source.record(_entry(2))
    backend._records[0] = (backend._records[0][0], "0" * 64)

    with pytest.raises(ValueError, match="verification failed"):
        AuditLog.from_backend(backend, max_entries=1)


def test_max_entries_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        AuditLog(max_entries=0)


def test_strict_append_requires_recovery_of_existing_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    backend = JSONLAuditBackend(path)
    AuditLog(backend=backend).record_durable(_entry(1))
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="recover"):
        AuditLog(backend=backend).record_durable(_entry(2))
    assert path.read_bytes() == before
    recovered = AuditLog.from_backend(backend, max_entries=1)
    recovered.record_durable(_entry(2))
    assert AuditLog.from_backend(backend).verify_chain()


def test_strict_append_rejects_replaced_path(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    backend = JSONLAuditBackend(path)
    log = AuditLog(backend=backend)
    path.rename(tmp_path / "old.jsonl")
    path.write_bytes(b"")
    with pytest.raises(RuntimeError, match="identity"):
        log.record_durable(_entry(1))
    assert path.read_bytes() == b""
    assert (tmp_path / "old.jsonl").read_bytes() == b""
    assert len(log) == 0


def test_strict_append_syncs_created_directory_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "new" / "nested" / "audit.jsonl"
    backend = JSONLAuditBackend(path)
    synced: list[tuple[int, int]] = []
    real_fsync = os.fsync

    def capture(fd: int) -> None:
        info = os.fstat(fd)
        synced.append((stat.S_IFMT(info.st_mode), info.st_ino))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", capture)
    AuditLog(backend=backend).record_durable(_entry(1))
    assert synced[0][0] == stat.S_IFREG
    assert [inode for kind, inode in synced if kind == stat.S_IFDIR] == [
        path.parent.stat().st_ino,
        path.parent.parent.stat().st_ino,
        tmp_path.stat().st_ino,
    ]


@pytest.mark.parametrize("mutation", ["truncate", "corrupt", "other_writer", "unlink"])
def test_strict_append_rejects_changed_history(tmp_path: Path, mutation: str) -> None:
    path = tmp_path / "audit.jsonl"
    backend = JSONLAuditBackend(path)
    log = AuditLog(backend=backend)
    log.record_durable(_entry(1))
    if mutation == "truncate":
        path.write_bytes(b"")
    elif mutation == "corrupt":
        path.write_text(path.read_text().replace("action-1", "modified"))
    elif mutation == "other_writer":
        AuditLog.from_backend(backend).record_durable(_entry(2))
    else:
        path.unlink()
    with pytest.raises((RuntimeError, ValueError)):
        log.record_durable(_entry(3))
    assert len(log) == 1


def test_directory_sync_failure_rolls_back_and_retries_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "new" / "audit.jsonl"
    backend = JSONLAuditBackend(path)
    log = AuditLog(backend=backend)
    real_fsync = os.fsync
    fail = True
    directories = 0

    def sync(fd: int) -> None:
        nonlocal directories
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directories += 1
            if fail:
                raise OSError("directory failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", sync)
    with pytest.raises(OSError, match="directory failed"):
        log.record_durable(_entry(1))
    assert len(log) == 0 and path.read_bytes() == b""
    fail = False
    log.record_durable(_entry(2))
    assert directories == 3
    assert AuditLog.from_backend(backend).verify_chain()


def test_path_replacement_during_flush_poisons_strict_log(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"

    class ReplacingBackend(JSONLAuditBackend):
        def flush(self) -> None:
            super().flush()
            path.rename(tmp_path / "old.jsonl")
            path.write_bytes(b"")

    log = AuditLog(backend=ReplacingBackend(path))
    with pytest.raises(RuntimeError, match="rollback failed"):
        log.record_durable(_entry(1))
    with pytest.raises(RuntimeError, match="poisoned"):
        log.record_durable(_entry(2))
    assert path.read_bytes() == b""
    assert len(log) == 0
