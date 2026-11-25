"""Regression and edge-case tests for review & optimization improvements."""

from __future__ import annotations

import gc
import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from acgs_lite import (
    AuditEntry,
    AuditLog,
    Constitution,
    GovernanceEngine,
    JSONLAuditBackend,
    Rule,
    Severity,
    ViolationAction,
)
from acgs_lite.engine import audit_runtime as engine_audit_runtime
from acgs_lite.engine import core as engine_core
from acgs_lite.engine import types as engine_types

pytestmark = pytest.mark.unit


# ── 1. normalize_for_matching Unicode parity & fallback ───────────────────────


class TestNormalizeForMatchingOptimization:
    def test_hidden_char_regex_matches_is_hidden_char_for_all_unicode(self) -> None:
        """_HIDDEN_CHAR_RE must match _is_hidden_char on every Unicode scalar value."""
        hidden_re = engine_core._HIDDEN_CHAR_RE
        assert hidden_re is not None
        mismatches = [
            cp
            for cp in range(0x110000)
            if (hidden_re.search(chr(cp)) is not None) != engine_core._is_hidden_char(chr(cp))
        ]
        assert mismatches == []

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("", ""),
            ("plain ascii\t\n\r", "plain ascii\t\n\r"),
            ("del\x00ete\x7f\x1f", "delete"),
            ("analyse des données financières", "analyse des données financières"),
            ("生産データベースの監視", "生産データベースの監視"),
            ("ｄｅｌｅｔｅ production", "delete production"),
            ("exp\u200bort\ufeff\u00ad\u202edata", "exportdata"),
            ("a\u034fb\ufe0fc", "abc"),
        ],
    )
    def test_normalize_examples_match_fallback_path(
        self, raw: str, expected: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert engine_core.normalize_for_matching(raw) == expected
        monkeypatch.setattr(engine_core, "_HIDDEN_CHAR_RE", None)
        assert engine_core.normalize_for_matching(raw) == expected


# ── 2. AuditLog O(1) deque trimming & O(k) rollback ──────────────────────────


class TestAuditLogDequeAndRollback:
    def test_entry_hash_matches_canonical_to_dict_without_pqc_signature(self) -> None:
        entry = AuditEntry(
            id="req-1",
            type="validation",
            agent_id="agent-a",
            action="check status",
            valid=True,
            violations=["R-1"],
            constitutional_hash="abc123",
            pqc_signature="deadbeef",
            latency_ms=1.25,
            metadata={"z": 1, "a": {"nested": True}},
            timestamp="2026-11-25T00:00:00Z",
        )
        d = entry.to_dict()
        d.pop("pqc_signature")
        expected = hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()
        assert entry.entry_hash == expected

        # Mutating an entry field must immediately change entry_hash (tamper detection).
        entry.action = "tampered"
        assert entry.entry_hash != expected

    def test_trim_at_max_entries_preserves_chain_and_anchor(self) -> None:
        log = AuditLog(max_entries=3)
        hashes = [log.record(AuditEntry(id=f"e-{i}", type="validation")) for i in range(7)]
        assert len(log) == 3
        assert [e.id for e in log.entries] == ["e-4", "e-5", "e-6"]
        assert log.retained_predecessor_hash == hashes[3]
        assert log.verify_chain() is True

    def test_record_atomic_rollback_restores_evicted_entry_at_max_entries(self) -> None:
        log = AuditLog(max_entries=3)
        for i in range(3):
            log.record(AuditEntry(id=f"e-{i}", type="validation"))
        before_ids = [e.id for e in log.entries]
        before_hashes = list(log._chain_hashes)
        before_anchor = log.retained_predecessor_hash

        def _boom(_log: AuditLog) -> None:
            raise RuntimeError("persist failed")

        with pytest.raises(RuntimeError, match="persist failed"):
            log.record_atomic(AuditEntry(id="e-3", type="validation"), persist=_boom)

        assert [e.id for e in log.entries] == before_ids
        assert list(log._chain_hashes) == before_hashes
        assert log.retained_predecessor_hash == before_anchor
        assert log.verify_chain() is True

    def test_record_atomic_many_rollback_when_batch_exceeds_max_entries(self) -> None:
        """Batch larger than max_entries trims original AND new items; rollback restores all."""
        log = AuditLog(max_entries=3)
        for i in range(3):
            log.record(AuditEntry(id=f"orig-{i}", type="validation"))
        before_ids = [e.id for e in log.entries]
        before_hashes = list(log._chain_hashes)
        before_anchor = log.retained_predecessor_hash

        batch = [AuditEntry(id=f"new-{i}", type="validation") for i in range(5)]

        def _boom(_log: AuditLog) -> None:
            raise RuntimeError("batch persist failed")

        with pytest.raises(RuntimeError, match="batch persist failed"):
            log.record_atomic_many(batch, persist=_boom)

        assert [e.id for e in log.entries] == before_ids
        assert list(log._chain_hashes) == before_hashes
        assert log.retained_predecessor_hash == before_anchor
        assert log.verify_chain() is True

    def test_record_atomic_many_partial_backend_failure_restores_all(self) -> None:
        class _FailOnThirdBackend:
            def __init__(self) -> None:
                self.records: list[tuple[dict[str, Any], str]] = []
                self.writes = 0

            def write(self, entry_dict: dict[str, Any], chain_hash: str) -> None:
                self.writes += 1
                if self.writes == 5:
                    raise OSError("disk full")
                self.records.append((entry_dict, chain_hash))

            def flush(self) -> None:
                pass

            def read_all(self) -> list[tuple[dict[str, Any], str]]:
                return list(self.records)

            def begin_checkpoint(self) -> int:
                return len(self.records)

            def rollback_to(self, token: int) -> None:
                del self.records[token:]

        backend = _FailOnThirdBackend()
        log = AuditLog(max_entries=2, backend=backend)
        log.record(AuditEntry(id="orig-0", type="validation"))
        log.record(AuditEntry(id="orig-1", type="validation"))
        before_ids = [e.id for e in log.entries]
        before_anchor = log.retained_predecessor_hash

        batch = [AuditEntry(id=f"b-{i}", type="validation") for i in range(4)]
        with pytest.raises(OSError, match="disk full"):
            log.record_atomic_many(batch)

        assert [e.id for e in log.entries] == before_ids
        assert log.retained_predecessor_hash == before_anchor
        assert len(backend.records) == 2
        assert log.verify_chain() is True

    def test_record_durable_rollback_at_max_entries(self, tmp_path: Path) -> None:
        backend = JSONLAuditBackend(tmp_path / "audit.jsonl")
        try:
            log = AuditLog(max_entries=2, backend=backend)
            log.record_durable(AuditEntry(id="d-0", type="validation"))
            log.record_durable(AuditEntry(id="d-1", type="validation"))
            before_ids = [e.id for e in log.entries]
            before_anchor = log.retained_predecessor_hash

            with (
                patch.object(backend, "flush_durable", side_effect=OSError("fsync failed")),
                pytest.raises(OSError, match="fsync failed"),
            ):
                log.record_durable(AuditEntry(id="d-2", type="validation"))

            assert [e.id for e in log.entries] == before_ids
            assert log.retained_predecessor_hash == before_anchor
            assert log.verify_chain() is True
            reloaded = AuditLog.from_backend(backend, max_entries=2)
            assert [e.id for e in reloaded.entries] == before_ids
        finally:
            backend.close()

    def test_query_returns_slice_with_limit(self) -> None:
        log = AuditLog(max_entries=10)
        for i in range(5):
            log.record(AuditEntry(id=f"q-{i}", type="validation", agent_id="a1"))
        queried = log.query(agent_id="a1", limit=2)
        assert [e.id for e in queried] == ["q-3", "q-4"]

    def test_concurrent_record_and_readers_never_raise_mutation_error(self) -> None:
        log = AuditLog(max_entries=20)
        errors: list[Exception] = []
        stop = threading.Event()

        def _writer() -> None:
            i = 0
            while not stop.is_set():
                log.record(AuditEntry(id=f"w-{i}", type="validation", valid=(i % 2 == 0)))
                i += 1

        def _reader() -> None:
            try:
                for _ in range(150):
                    _ = log.compliance_rate
                    _ = log.export_dicts()
                    _ = log.query(limit=5)
                    _ = len(log)
                    assert log.verify_chain() is True
            except Exception as exc:
                errors.append(exc)

        wt = threading.Thread(target=_writer)
        rt = threading.Thread(target=_reader)
        wt.start()
        rt.start()
        rt.join(timeout=10)
        stop.set()
        wt.join(timeout=5)
        assert errors == []


# ── 3. BatchValidationMixin thread-safety ────────────────────────────────────


class TestBatchValidationThreadSafety:
    def test_validate_batch_never_mutates_engine_strict(self) -> None:
        constitution = Constitution(
            name="batch-strict",
            rules=[
                Rule(
                    id="R-CRIT",
                    text="Block dangerous drop",
                    severity=Severity.CRITICAL,
                    keywords=["drop table"],
                ),
            ],
        )
        observed_strict: list[bool] = []
        engine = GovernanceEngine(constitution, strict=True, warmup=False, freeze_gc=False)

        def _spy(_action: str, _ctx: dict[str, Any]) -> list[Any]:
            observed_strict.append(engine.strict)
            return []

        engine.add_validator(_spy)
        results = engine.validate_batch(["safe query", "drop table users"])
        assert engine.strict is True
        assert observed_strict == [True, True]
        assert results[0].valid is True
        assert results[1].valid is False
        assert results[1].violations[0].rule_id == "R-CRIT"

    def test_validate_batch_concurrent_strict_calls_stay_fail_closed(self) -> None:
        constitution = Constitution(
            name="batch-concurrent",
            rules=[
                Rule(
                    id="R-BLOCK",
                    text="Block forbidden keyword",
                    severity=Severity.CRITICAL,
                    keywords=["forbidden"],
                ),
            ],
        )
        engine = GovernanceEngine(constitution, strict=True, warmup=False, freeze_gc=False)
        errors: list[str] = []
        stop = threading.Event()

        def _batch_worker() -> None:
            while not stop.is_set():
                engine.validate_batch(["clean", "forbidden action"])

        t = threading.Thread(target=_batch_worker)
        t.start()
        try:
            for _ in range(200):
                try:
                    engine.validate("forbidden action")
                    errors.append("strict validate unexpectedly succeeded")
                    break
                except Exception:
                    pass
        finally:
            stop.set()
            t.join(timeout=5)
        assert errors == []

    def test_validate_batch_report_handles_multiple_violations_and_halt(self) -> None:
        constitution = Constitution(
            name="batch-report-halt",
            rules=[
                Rule(
                    id="R-1",
                    text="Block alpha",
                    severity=Severity.HIGH,
                    keywords=["alpha"],
                ),
                Rule(
                    id="R-2",
                    text="Block beta",
                    severity=Severity.CRITICAL,
                    keywords=["beta"],
                ),
                Rule(
                    id="R-HALT",
                    text="Halt omega",
                    severity=Severity.CRITICAL,
                    keywords=["omega"],
                    workflow_action=ViolationAction.HALT,
                ),
            ],
        )
        engine = GovernanceEngine(constitution, strict=True, warmup=False, freeze_gc=False)
        report = engine.validate_batch_report(["alpha beta", "omega trigger", "clean"])
        assert report.total == 3
        assert report.allowed == 1
        assert report.denied == 2
        assert set(report.critical_rule_ids) == {"R-1", "R-2", "R-HALT"}


# ── 4. Rule temporal caching & GovernanceEngine GC guard ─────────────────────


class TestRuleTemporalAndGcGuard:
    def test_mutating_temporal_bounds_updates_runtime_filtering(self) -> None:
        rule = Rule(
            id="R-TMP",
            text="Temporary block",
            severity=Severity.HIGH,
            keywords=["secret"],
            valid_from="2020-01-01",
            valid_until="2030-12-31",
        )
        constitution = Constitution(name="temporal", rules=[rule])
        engine = GovernanceEngine(constitution, strict=False, warmup=False, freeze_gc=False)
        assert engine.validate("leak secret").valid is False

        rule.valid_until = "2021-01-01"
        assert engine.validate("leak secret").valid is True

        with pytest.raises(ValueError):
            engine.validate("leak secret", context={"timestamp": "not-an-iso-date"})

    def test_freeze_gc_false_skips_gc_collect_and_freeze(self) -> None:
        constitution = Constitution.default()
        with (
            patch.object(gc, "collect") as mock_collect,
            patch.object(gc, "freeze") as mock_freeze,
        ):
            GovernanceEngine(constitution, warmup=False, freeze_gc=False, disable_gc=False)
            mock_collect.assert_not_called()
            mock_freeze.assert_not_called()


# ── 5. Cold-start lazy imports & module deduplication ────────────────────────


class TestLazyImportsAndDeduplication:
    def test_bare_import_acgs_lite_stays_lean(self) -> None:
        code = (
            "import json, sys\n"
            "import acgs_lite\n"
            "loaded = {\n"
            "    'z3': 'z3' in sys.modules,\n"
            "    'z3_verify': 'acgs_lite.z3_verify' in sys.modules,\n"
            "    'lean_verify': 'acgs_lite.lean_verify' in sys.modules,\n"
            "    'governed': 'acgs_lite.governed' in sys.modules,\n"
            "    'agents': 'acgs_lite.agents' in sys.modules,\n"
            "    'policygen': 'acgs_lite.policygen' in sys.modules,\n"
            "    'trajectory': 'acgs_lite.trajectory' in sys.modules,\n"
            "}\n"
            "print(json.dumps(loaded))\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        loaded = json.loads(completed.stdout)
        assert loaded == {k: False for k in loaded}

    def test_import_server_does_not_eagerly_import_optional_routers(self) -> None:
        code = (
            "import json, sys\n"
            "import acgs_lite.server\n"
            "print(json.dumps({\n"
            "    'federation': 'acgs_lite.federation' in sys.modules,\n"
            "    'telegram_webhook': 'acgs_lite.integrations.telegram_webhook' in sys.modules,\n"
            "}))\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        assert json.loads(completed.stdout) == {"federation": False, "telegram_webhook": False}

    def test_shadowed_maci_file_removed_and_engine_types_deduplicated(self) -> None:
        root = Path(__file__).resolve().parents[1]
        assert not (root / "src" / "acgs_lite" / "maci.py").exists()
        assert engine_types._FastAuditLog is engine_audit_runtime._FastAuditLog
        assert engine_types._NoopRecorder is engine_audit_runtime._NoopRecorder
        assert engine_types._request_counter is engine_audit_runtime._request_counter


# ── 6. Federation constant-time auth ─────────────────────────────────────────


def test_federation_transport_accepts_exact_bearer_and_rejects_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from acgs_lite._meta import CONSTITUTIONAL_HASH
    from acgs_lite.server import create_governance_app

    monkeypatch.setenv("ACGS_FEDERATION_ENABLED", "true")
    monkeypatch.setenv("ACGS_FEDERATION_TOKEN", "top-secret-token")

    client = TestClient(create_governance_app(require_auth=False))
    payload = {
        "entry_id": "e1",
        "agent_id": "a1",
        "action": "share",
        "valid": True,
        "constitutional_hash": CONSTITUTIONAL_HASH,
        "timestamp": "2026-11-25T00:00:00Z",
    }

    assert client.post("/v1/federation/audit/push", json=payload).status_code == 401
    assert (
        client.post(
            "/v1/federation/audit/push",
            json=payload,
            headers={"Authorization": "Bearer top-secret-token"},
        ).status_code
        == 200
    )
