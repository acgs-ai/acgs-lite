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


def test_federation_transport_handles_non_ascii_header_and_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("fastapi")
    import asyncio

    from fastapi import HTTPException

    from acgs_lite.federation.transport import _require_federation_auth
    from acgs_lite.server import create_governance_app

    async def _raw_asgi_get(app: Any, path: str, headers: list[tuple[bytes, bytes]]) -> int:
        status_code = 0
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": headers,
        }

        async def _receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def _send(msg: dict[str, Any]) -> None:
            nonlocal status_code
            if msg["type"] == "http.response.start":
                status_code = int(msg["status"])

        await app(scope, _receive, _send)
        return status_code

    monkeypatch.setenv("ACGS_FEDERATION_ENABLED", "true")

    # Non-ASCII Authorization header against ASCII token must return 401 (never TypeError/500).
    monkeypatch.setenv("ACGS_FEDERATION_TOKEN", "ascii-token")
    app_ascii = create_governance_app(require_auth=False)
    assert (
        asyncio.run(
            _raw_asgi_get(
                app_ascii,
                "/v1/federation/capabilities",
                [(b"authorization", b"Bearer \xe9")],
            )
        )
        == 401
    )
    with pytest.raises(HTTPException) as exc_info:
        _require_federation_auth("Bearer \xe9")
    assert exc_info.value.status_code == 401

    # Non-ASCII ACGS_FEDERATION_TOKEN: exact match -> 200, mismatch -> 401.
    monkeypatch.setenv("ACGS_FEDERATION_TOKEN", "s\xe9cret-token")
    app_non_ascii = create_governance_app(require_auth=False)
    assert (
        asyncio.run(
            _raw_asgi_get(
                app_non_ascii,
                "/v1/federation/capabilities",
                [(b"authorization", b"Bearer s\xe9cret-token")],
            )
        )
        == 200
    )
    assert (
        asyncio.run(
            _raw_asgi_get(
                app_non_ascii,
                "/v1/federation/capabilities",
                [(b"authorization", b"Bearer wrong-token")],
            )
        )
        == 401
    )
    assert (
        asyncio.run(
            _raw_asgi_get(
                app_non_ascii,
                "/v1/federation/capabilities",
                [(b"authorization", b"Bearer s\xe8cret-token")],
            )
        )
        == 401
    )

    # Arbitrary Unicode token tested directly on helper.
    monkeypatch.setenv("ACGS_FEDERATION_TOKEN", "s\u00e9cret-\u2603")
    _require_federation_auth("Bearer s\u00e9cret-\u2603")
    with pytest.raises(HTTPException) as exc_info2:
        _require_federation_auth("Bearer s\u00e9cret-other")
    assert exc_info2.value.status_code == 401

    # Lone surrogates (e.g. non-UTF-8 Linux env vars decoded via surrogateescape)
    # must never raise UnicodeEncodeError / HTTP 500.
    monkeypatch.setenv("ACGS_FEDERATION_TOKEN", "surrogate-\udc80-tok")
    _require_federation_auth("Bearer surrogate-\udc80-tok")
    with pytest.raises(HTTPException) as exc_info3:
        _require_federation_auth("Bearer wrong")
    assert exc_info3.value.status_code == 401
    with pytest.raises(HTTPException) as exc_info4:
        _require_federation_auth("Bearer \ud800")
    assert exc_info4.value.status_code == 401


# ── 7. Hardening regressions (re-entrant rollback, Rust/HALT parity, lazy proxy, streaming) ──


class TestAuditLogReentrantRollbackAndSnapshots:
    def test_record_atomic_reentrant_record_rollback_preserves_chain(self) -> None:
        log = AuditLog(max_entries=2)
        log.record(AuditEntry(id="e0", type="validation"))
        log.record(AuditEntry(id="e1", type="validation"))
        before_ids = [e.id for e in log.entries]
        before_anchor = log.retained_predecessor_hash

        def _reentrant_boom(al: AuditLog) -> None:
            al.record(AuditEntry(id="reentrant", type="validation"))
            raise RuntimeError("persist failed after re-entrant record")

        with pytest.raises(RuntimeError, match="persist failed"):
            log.record_atomic(AuditEntry(id="e2", type="validation"), persist=_reentrant_boom)

        assert [e.id for e in log.entries] == before_ids
        assert log.retained_predecessor_hash == before_anchor
        assert log.verify_chain() is True
        assert log._tx_undo_stack == []

    def test_record_atomic_nested_rollback_then_outer_rollback_preserves_chain(self) -> None:
        log = AuditLog(max_entries=3)
        for i in range(3):
            log.record(AuditEntry(id=f"e{i}", type="validation"))
        before_ids = [e.id for e in log.entries]
        before_anchor = log.retained_predecessor_hash

        def _inner_boom(_al: AuditLog) -> None:
            raise RuntimeError("inner failed")

        def _outer_persist(al: AuditLog) -> None:
            with pytest.raises(RuntimeError, match="inner failed"):
                al.record_atomic(AuditEntry(id="inner", type="validation"), persist=_inner_boom)
            raise RuntimeError("outer failed")

        with pytest.raises(RuntimeError, match="outer failed"):
            log.record_atomic(AuditEntry(id="outer", type="validation"), persist=_outer_persist)

        assert [e.id for e in log.entries] == before_ids
        assert log.retained_predecessor_hash == before_anchor
        assert log.verify_chain() is True
        assert log._tx_undo_stack == []

    def test_repr_and_export_json_consistent_under_concurrent_writes(self, tmp_path: Path) -> None:
        log = AuditLog(max_entries=10)
        for i in range(5):
            log.record(AuditEntry(id=f"seed-{i}", type="validation", valid=(i % 2 == 0)))
        rendered = repr(log)
        assert "entries=5" in rendered
        assert "chain_valid=True" in rendered
        export_path = tmp_path / "export.json"
        log.export_json(export_path)
        reloaded = AuditLog.from_json(export_path)
        assert [e.id for e in reloaded.entries] == [e.id for e in log.entries]
        assert reloaded.verify_chain() is True


class TestEngineHaltRustParityAndFallbacks:
    def test_halt_precedence_and_enforcement_action_with_critical_block_rule(self) -> None:
        from acgs_lite.errors import ConstitutionalViolationError

        constitution = Constitution(
            name="crit-plus-halt",
            rules=[
                Rule(
                    id="R-CRIT",
                    text="Critical block",
                    severity=Severity.CRITICAL,
                    keywords=["alpha"],
                ),
                Rule(
                    id="R-HALT",
                    text="Critical halt",
                    severity=Severity.CRITICAL,
                    keywords=["beta"],
                    workflow_action=ViolationAction.HALT,
                ),
            ],
        )
        engine = GovernanceEngine(constitution, strict=True, warmup=False, freeze_gc=False)
        for strict_arg in (True, False):
            with pytest.raises(ConstitutionalViolationError) as exc_info:
                engine.validate("alpha beta", strict=strict_arg)
            assert exc_info.value.rule_id == "R-HALT"
            assert exc_info.value.enforcement_action is ViolationAction.HALT

    def test_validate_batch_collects_all_violations_when_critical_and_high_both_match(self) -> None:
        constitution = Constitution(
            name="crit-plus-high",
            rules=[
                Rule(
                    id="R-CRIT",
                    text="Critical block",
                    severity=Severity.CRITICAL,
                    keywords=["alpha"],
                ),
                Rule(
                    id="R-HIGH",
                    text="High block",
                    severity=Severity.HIGH,
                    keywords=["beta"],
                ),
            ],
        )
        engine = GovernanceEngine(constitution, strict=True, warmup=False, freeze_gc=False)
        results = engine.validate_batch(["alpha beta", "clean"])
        assert results[0].valid is False
        assert {v.rule_id for v in results[0].violations} == {"R-CRIT", "R-HIGH"}
        assert results[1].valid is True

    def test_lookaround_regex_and_unicode_ignorecase_folding_work_with_or_without_rust(
        self,
    ) -> None:
        c_lookaround = Constitution(
            name="lookaround",
            rules=[
                Rule(
                    id="R-LOOK",
                    text="Negative lookbehind",
                    severity=Severity.HIGH,
                    patterns=[r"(?<!not )allowed"],
                ),
            ],
        )
        engine_la = GovernanceEngine(c_lookaround, strict=False, warmup=False, freeze_gc=False)
        assert engine_la.validate("allowed action").valid is False
        assert engine_la.validate("not allowed action").valid is True

        c_fold = Constitution(
            name="fold",
            rules=[
                Rule(
                    id="R-DISK",
                    text="Block disk",
                    severity=Severity.HIGH,
                    patterns=["disk"],
                ),
            ],
        )
        engine_fold = GovernanceEngine(c_fold, strict=False, warmup=False, freeze_gc=False)
        for obfuscated in ("dısk", "diſk", "disK"):
            assert engine_fold.validate(obfuscated).valid is False

    def test_matcher_rust_paths_respect_per_call_strict_and_halt_precedence(self) -> None:
        from acgs_lite.engine.matcher import (
            _RUST_ALLOW,
            _RUST_DENY,
            GovernanceMatcherMixin,
        )
        from acgs_lite.engine.models import ValidationResult, Violation
        from acgs_lite.errors import ConstitutionalViolationError

        class _FakeRust:
            def __init__(self) -> None:
                self.hot: dict[str, tuple[int, int]] = {}
                self.full: tuple[int, list[tuple[str, str, str, str, str]], bool] = (
                    _RUST_ALLOW,
                    [],
                    False,
                )

            def validate_hot(self, text: str) -> tuple[int, int]:
                return self.hot.get(text, (_RUST_ALLOW, 0))

            def validate_full(
                self, _text: str, _pairs: list[tuple[str, str]]
            ) -> tuple[int, list[tuple[str, str, str, str, str]], bool]:
                return self.full

        class _Host(GovernanceMatcherMixin):
            def __init__(self) -> None:
                self._rule_data = [
                    ("R-BLK", "block", Severity.HIGH, "high", "sec", False, "block"),
                    ("R-HLT", "halt", Severity.CRITICAL, "critical", "sec", False, "halt"),
                ]
                self._rule_excs = [None, None]
                self._rule_id_to_exc_idx = {}
                self._rule_id_to_wa = {
                    "R-BLK": ViolationAction.BLOCK,
                    "R-HLT": ViolationAction.HALT,
                }
                self._rust_validator = _FakeRust()
                self.strict = False

            def _new_fast_allow_result(self) -> ValidationResult:
                return ValidationResult(True, "h")

            def _new_fast_result(
                self, *, valid: bool, violations: list[Violation], action: str
            ) -> ValidationResult:
                return ValidationResult(valid, "h", violations, action=action)

        host = _Host()
        # Per-call strict=True override on strict=False engine must raise in gov_context.
        host._rust_validator.hot["bad"] = (_RUST_DENY, 0b01)
        recs: list[Any] = []
        with pytest.raises(ConstitutionalViolationError, match="R-BLK"):
            host._validate_rust_gov_context(
                "ok", _RUST_ALLOW, 0, {"action_detail": "bad"}, host._rule_excs, recs, strict=True
            )
        assert recs == []

        # When BOTH BLOCK and HALT match, all Rust decoders defer to _post_dispatch_result.
        res_no_ctx = host._validate_rust_no_context(
            "both", _RUST_DENY, 0b11, host._rule_excs, [], strict=True
        )
        assert res_no_ctx is not None and res_no_ctx.valid is False
        assert {v.rule_id for v in res_no_ctx.violations} == {"R-BLK", "R-HLT"}

        host._rust_validator.hot["both"] = (_RUST_DENY, 0b11)
        res_gov = host._validate_rust_gov_context(
            "ok", _RUST_ALLOW, 0, {"action_detail": "both"}, host._rule_excs, [], strict=True
        )
        assert res_gov is not None and res_gov.valid is False

        res_meta = host._validate_rust_metadata_context(
            "both", _RUST_DENY, 0b11, host._rule_excs, [], True
        )
        assert res_meta is not None and res_meta.valid is False

        host._rust_validator.full = (
            _RUST_DENY,
            [
                ("R-BLK", "block", "high", "", "sec"),
                ("R-HLT", "halt", "critical", "", "sec"),
            ],
            True,
        )
        full_recs: list[Any] = []
        res_full = host._validate_rust_full("both", True, [], host._rule_excs, full_recs)
        assert res_full is not None and res_full.valid is False
        assert full_recs == [None]

    def test_validate_rust_gov_context_critical_respects_effective_strict(self) -> None:
        from acgs_lite.engine.matcher import (
            _RUST_ALLOW,
            _RUST_DENY,
            _RUST_DENY_CRITICAL,
            GovernanceMatcherMixin,
        )
        from acgs_lite.engine.models import ValidationResult, Violation
        from acgs_lite.errors import ConstitutionalViolationError

        class _FakeRust:
            def __init__(self) -> None:
                self.hot: dict[str, tuple[int, int]] = {}

            def validate_hot(self, text: str) -> tuple[int, int]:
                return self.hot.get(text, (_RUST_ALLOW, 0))

        class _Host(GovernanceMatcherMixin):
            def __init__(self) -> None:
                self._rule_data = [
                    ("R-CRIT-0", "crit0", Severity.CRITICAL, "critical", "sec", True, "crit0"),
                    ("R-HIGH-1", "high1", Severity.HIGH, "high", "sec", False, "high1"),
                    ("R-CRIT-2", "crit2", Severity.CRITICAL, "critical", "sec", True, "crit2"),
                ]
                self._rule_excs = [
                    ConstitutionalViolationError("crit0", rule_id="R-CRIT-0", severity="critical"),
                    None,
                    ConstitutionalViolationError("crit2", rule_id="R-CRIT-2", severity="critical"),
                ]
                self._rule_id_to_exc_idx = {"R-CRIT-0": 0, "R-CRIT-2": 2}
                self._rule_id_to_wa = {
                    "R-CRIT-0": ViolationAction.BLOCK,
                    "R-HIGH-1": ViolationAction.BLOCK,
                    "R-CRIT-2": ViolationAction.BLOCK,
                }
                self._rust_validator = _FakeRust()
                self.strict = True

            def _new_fast_allow_result(self) -> ValidationResult:
                return ValidationResult(True, "h")

            def _new_fast_result(
                self, *, valid: bool, violations: list[Violation], action: str
            ) -> ValidationResult:
                return ValidationResult(valid, "h", violations, action=action)

        host = _Host()
        # Critical from action + high from detail + second critical from description, strict=False.
        host._rust_validator.hot["detail-high"] = (_RUST_DENY, 0b010)
        host._rust_validator.hot["desc-crit2"] = (_RUST_DENY_CRITICAL, 2)
        recs: list[Any] = []
        res = host._validate_rust_gov_context(
            "act-crit0",
            _RUST_DENY_CRITICAL,
            0,
            {"action_detail": "detail-high", "action_description": "desc-crit2"},
            host._rule_excs,
            recs,
            strict=False,
        )
        assert res is not None and res.valid is False
        assert {v.rule_id for v in res.violations} == {"R-CRIT-0", "R-HIGH-1", "R-CRIT-2"}
        assert recs == [None]

        # Out-of-range critical index with strict=False returns non-raising UNKNOWN violation.
        recs_oor: list[Any] = []
        res_oor = host._validate_rust_gov_context(
            "act",
            _RUST_DENY_CRITICAL,
            99,
            {"action_detail": "ok"},
            host._rule_excs,
            recs_oor,
            strict=False,
        )
        assert res_oor is not None and res_oor.valid is False
        assert [v.rule_id for v in res_oor.violations] == ["UNKNOWN"]
        assert recs_oor == [None]

        # Out-of-range critical match must NOT drop concurrent in-range violations.
        host._rust_validator.hot["detail-oor"] = (_RUST_DENY_CRITICAL, 99)
        res_high_plus_oor = host._validate_rust_gov_context(
            "act",
            _RUST_DENY,
            0b010,
            {"action_detail": "detail-oor"},
            host._rule_excs,
            [],
            strict=False,
        )
        assert res_high_plus_oor is not None and res_high_plus_oor.valid is False
        assert {v.rule_id for v in res_high_plus_oor.violations} == {"R-HIGH-1", "UNKNOWN"}

        res_crit_plus_oor = host._validate_rust_gov_context(
            "act",
            _RUST_DENY_CRITICAL,
            0,
            {"action_detail": "detail-oor"},
            host._rule_excs,
            [],
            strict=False,
        )
        assert res_crit_plus_oor is not None and res_crit_plus_oor.valid is False
        assert {v.rule_id for v in res_crit_plus_oor.violations} == {"R-CRIT-0", "UNKNOWN"}

        # Critical index valid in rule_excs but past _rule_data falls back to UNKNOWN without IndexError.
        longer_excs = [
            *host._rule_excs,
            ConstitutionalViolationError("extra", rule_id="R-EXTRA", severity="critical"),
        ]
        res_mismatch_len = host._validate_rust_gov_context(
            "act",
            _RUST_DENY_CRITICAL,
            3,
            {"action_detail": "ok"},
            longer_excs,
            [],
            strict=False,
        )
        assert res_mismatch_len is not None and res_mismatch_len.valid is False
        assert [v.rule_id for v in res_mismatch_len.violations] == ["UNKNOWN"]

        # Same critical paths with strict=True still raise ConstitutionalViolationError.
        with pytest.raises(ConstitutionalViolationError, match="crit0"):
            host._validate_rust_gov_context(
                "act-crit0",
                _RUST_DENY_CRITICAL,
                0,
                {"action_detail": "ok"},
                host._rule_excs,
                [],
                strict=True,
            )
        with pytest.raises(ConstitutionalViolationError, match="index out of range"):
            host._validate_rust_gov_context(
                "act",
                _RUST_DENY_CRITICAL,
                99,
                {"action_detail": "ok"},
                host._rule_excs,
                [],
                strict=True,
            )

    def test_validate_rust_full_respects_warn_override_on_high_severity_rule(self) -> None:
        from acgs_lite.engine.matcher import _RUST_DENY, GovernanceMatcherMixin
        from acgs_lite.engine.models import ValidationResult, Violation

        class _FakeRust:
            def validate_full(
                self, _text: str, _pairs: list[tuple[str, str]]
            ) -> tuple[int, list[tuple[str, str, str, str, str]], bool]:
                # Rust flags _blocking=True from severity=high alone (unaware of WARN).
                return (_RUST_DENY, [("R-WARN-HIGH", "warn only", "high", "", "sec")], True)

        class _Host(GovernanceMatcherMixin):
            def __init__(self) -> None:
                self._rule_data = [
                    ("R-WARN-HIGH", "warn only", Severity.HIGH, "high", "sec", False, "warn")
                ]
                self._rule_excs = [None]
                self._rule_id_to_exc_idx = {}
                self._rule_id_to_wa = {"R-WARN-HIGH": ViolationAction.WARN}
                self._rust_validator = _FakeRust()
                self.strict = True

            def _new_fast_allow_result(self) -> ValidationResult:
                return ValidationResult(True, "h")

            def _new_fast_result(
                self, *, valid: bool, violations: list[Violation], action: str
            ) -> ValidationResult:
                return ValidationResult(valid, "h", violations, action=action)

        host = _Host()
        recs: list[Any] = []
        res = host._validate_rust_full("trigger", True, [("action_detail", "x")], [None], recs)
        assert res is not None and res.valid is True
        assert [v.rule_id for v in res.violations] == ["R-WARN-HIGH"]
        assert recs == [None]

    def test_constitutions_over_63_rules_enforce_all_rules_without_rust_i64_overflow(
        self,
    ) -> None:
        """Constitutions with >63 active rules must never suffer Rust i64 bitmask overflow."""
        for count in (63, 64, 65):
            rules = [
                Rule(
                    id=f"R-{i:03d}",
                    text=f"Block rule {i}",
                    severity=Severity.HIGH,
                    keywords=[f"kw{i:03d}"],
                )
                for i in range(count)
            ]
            constitution = Constitution(name=f"rules-{count}", rules=rules)
            engine = GovernanceEngine(constitution, strict=False, warmup=False, freeze_gc=False)
            if count > 63:
                assert engine._rust_validator is None
            for idx in (0, 62, count - 1):
                res = engine.validate(f"trigger kw{idx:03d}")
                assert res.valid is False, f"count={count} idx={idx} failed open"
                assert [v.rule_id for v in res.violations] == [f"R-{idx:03d}"]
            assert engine.validate("completely clean action").valid is True

    def test_runtime_rule_filtering_receipt_reflects_post_init_rule_mutations(self) -> None:
        base_rule = Rule(
            id="R-BASE",
            text="Base conditional rule",
            severity=Severity.HIGH,
            keywords=["alpha"],
            condition={"env": "prod"},
        )
        constitution = Constitution(name="dynamic-runtime", rules=[base_rule])
        engine = GovernanceEngine(
            constitution,
            strict=False,
            audit_mode="full",
            warmup=False,
            freeze_gc=False,
        )

        # Mutate constitution.rules post-init: add a new rule and update existing rule severity.
        dynamic_rule = Rule(
            id="R-DYNAMIC",
            text="Added after engine init",
            severity=Severity.CRITICAL,
            keywords=["beta"],
        )
        constitution.rules.append(dynamic_rule)
        base_rule.severity = Severity.MEDIUM

        result = engine.validate("trigger beta", context={"env": "staging"})
        assert result.valid is False
        assert [v.rule_id for v in result.violations] == ["R-DYNAMIC"]

        evals = {
            item["rule_id"]: item
            for item in engine.audit_log.entries[-1].metadata["rule_evaluations"]
        }
        assert set(evals) == {"R-BASE", "R-DYNAMIC"}
        assert evals["R-BASE"]["severity"] == "medium"
        assert evals["R-BASE"]["evaluated"] is False
        assert evals["R-BASE"]["reason"] == "inactive"
        assert evals["R-DYNAMIC"]["severity"] == "critical"
        assert evals["R-DYNAMIC"]["evaluated"] is True
        assert evals["R-DYNAMIC"]["matched"] is True
        assert evals["R-DYNAMIC"]["reason"] == "violation"


class TestLazySubmoduleAndStreamingHardening:
    def test_lazy_submodule_resolution_on_acgs_lite_constitution_and_formal(self) -> None:
        code = (
            "import sys, types\n"
            "from unittest.mock import patch\n"
            "import acgs_lite\n"
            "import acgs_lite.constitution as c\n"
            "expected_top = {\n"
            "    'agents', 'circuit_breaker', 'constrained_output', 'events', 'formal',\n"
            "    'governed', 'lean_verify', 'legitimacy', 'licensing', 'policygen',\n"
            "    'production', 'provenance', 'provider_capabilities', 'scoring',\n"
            "    'serialization', 'trajectory', 'z3_verify',\n"
            "}\n"
            "expected_const = {\n"
            "    'abac', 'activation', 'autonomy_ratio', 'boundaries', 'bundle',\n"
            "    'claim_lifecycle', 'comparison', 'conflict_resolution', 'coverage_analysis',\n"
            "    'deduplication', 'dependency_analysis', 'diffing', 'editor', 'evidence',\n"
            "    'experience_library', 'filtering', 'governance_memory', 'intent_alignment',\n"
            "    'interpolation', 'lifecycle', 'memoization', 'merging', 'metrics',\n"
            "    'obligation_engine', 'permission_ceiling', 'provenance', 'refusal_reasoning',\n"
            "    'regulatory', 'rendering', 'reporting', 'routing', 'semantic_search',\n"
            "    'serialization', 'similarity', 'snapshot', 'spot_check', 'templates',\n"
            "    'trust_score', 'validator_selection', 'versioning', 'weighted_policy',\n"
            "    'workflow_analytics',\n"
            "}\n"
            "# Cold start must remain lazy: none of the lazy submodules are preloaded.\n"
            "assert [m for m in expected_top if f'acgs_lite.{m}' in sys.modules] == []\n"
            "assert [m for m in expected_const if f'acgs_lite.constitution.{m}' in sys.modules] == []\n"
            "assert expected_top.issubset(set(dir(acgs_lite)))\n"
            "assert expected_const.issubset(set(dir(c)))\n"
            "# unittest.mock.patch against lazy submodule targets works on fresh import.\n"
            "with patch('acgs_lite.governed.GovernedAgent') as mg:\n"
            "    assert acgs_lite.governed.GovernedAgent is mg\n"
            "with patch('acgs_lite.constitution.diffing.AmendmentReviewReport') as md:\n"
            "    assert c.diffing.AmendmentReviewReport is md\n"
            "# All lazy submodules resolve to real ModuleType and cache into globals().\n"
            "for name in sorted(expected_top):\n"
            "    mod = getattr(acgs_lite, name)\n"
            "    assert isinstance(mod, types.ModuleType), name\n"
            "    assert vars(acgs_lite)[name] is mod\n"
            "    assert sys.modules[f'acgs_lite.{name}'] is mod\n"
            "assert isinstance(acgs_lite.formal.exemption, types.ModuleType)\n"
            "assert isinstance(acgs_lite.formal.policy_ast, types.ModuleType)\n"
            "for name in sorted(expected_const):\n"
            "    mod = getattr(c, name)\n"
            "    assert isinstance(mod, types.ModuleType), name\n"
            "    assert vars(c)[name] is mod\n"
            "    assert sys.modules[f'acgs_lite.constitution.{name}'] is mod\n"
        )
        subprocess.run([sys.executable, "-c", code], check=True, timeout=30)

    def test_lazy_submodule_getattr_and_dir_in_process(self) -> None:
        import types

        import acgs_lite
        import acgs_lite.constitution as c
        import acgs_lite.formal as formal_pkg

        assert isinstance(acgs_lite.__getattr__("provenance"), types.ModuleType)
        assert "provenance" in dir(acgs_lite)
        with pytest.raises(AttributeError):
            acgs_lite.__getattr__("nonexistent_submodule_xyz")

        assert isinstance(c.__getattr__("abac"), types.ModuleType)
        assert "abac" in dir(c)
        with pytest.raises(AttributeError):
            c.__getattr__("nonexistent_constitution_submodule_xyz")

        assert isinstance(formal_pkg.__getattr__("exemption"), types.ModuleType)
        assert isinstance(formal_pkg.__getattr__("policy_ast"), types.ModuleType)
        assert {"exemption", "policy_ast"}.issubset(set(dir(formal_pkg)))
        with pytest.raises(AttributeError):
            formal_pkg.__getattr__("nonexistent_formal_submodule_xyz")

    def test_lazy_submodule_supports_mock_patch_and_binds_real_module(self) -> None:
        code = (
            "import types\n"
            "from unittest.mock import patch\n"
            "import acgs_lite.constitution.constitution as cm\n"
            "assert not isinstance(cm.diffing, types.ModuleType)\n"
            "with patch('acgs_lite.constitution.constitution.diffing.AmendmentReviewReport') as m:\n"
            "    assert cm.diffing.AmendmentReviewReport is m\n"
            "assert isinstance(cm.diffing, types.ModuleType)\n"
        )
        subprocess.run([sys.executable, "-c", code], check=True, timeout=30)

    def test_streaming_validator_uses_per_call_strict_false_without_mutating_engine(self) -> None:
        from acgs_lite.engine.streaming import StreamingValidator

        constitution = Constitution(
            name="stream-strict",
            rules=[
                Rule(
                    id="R-CRIT",
                    text="Block forbidden",
                    severity=Severity.CRITICAL,
                    keywords=["forbidden"],
                ),
            ],
        )
        observed_strict: list[bool] = []
        engine = GovernanceEngine(constitution, strict=True, warmup=False, freeze_gc=False)

        def _spy(_action: str, _ctx: dict[str, Any]) -> list[Any]:
            observed_strict.append(engine.strict)
            return []

        engine.add_validator(_spy)
        sv = StreamingValidator(
            engine,
            flush_interval_chars=5,
            blocking_severities={"critical"},
        )
        chunk_res = sv.feed("forbidden payload")
        assert engine.strict is True
        assert observed_strict == [True]
        assert chunk_res.passed is False
        assert chunk_res.should_halt is True

    def test_streaming_validator_does_not_misinterpret_inner_typeerror_with_strict_text(
        self,
    ) -> None:
        from contextlib import contextmanager

        from acgs_lite.engine.streaming import StreamingValidator

        class _StrictCapableFailingEngine:
            def __init__(self) -> None:
                self.strict = True
                self.validate_calls = 0
                self.non_strict_entries = 0

            @contextmanager
            def non_strict(self) -> Any:
                self.non_strict_entries += 1
                old = self.strict
                self.strict = False
                try:
                    yield
                finally:
                    self.strict = old

            def validate(self, text: str, *, strict: bool | None = None) -> Any:
                del text, strict
                self.validate_calls += 1
                raise TypeError("downstream parser failed in strict mode")

        eng = _StrictCapableFailingEngine()
        sv = StreamingValidator(eng, flush_interval_chars=5, blocking_severities={"critical"})
        res = sv.feed("hello world")
        assert res.passed is False
        assert res.should_halt is True
        assert eng.validate_calls == 1
        assert eng.non_strict_entries == 0
        assert eng.strict is True

    def test_server_lazy_router_attributes_support_import_and_mock_patch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("fastapi")
        from fastapi import APIRouter

        import acgs_lite.server as srv

        # Subprocess verifies bare import stays lazy while dir() and patch() work.
        code = (
            "import sys\n"
            "from unittest.mock import patch\n"
            "from fastapi import APIRouter\n"
            "import acgs_lite.server as srv\n"
            "assert 'acgs_lite.federation' not in sys.modules\n"
            "assert 'acgs_lite.integrations.telegram_webhook' not in sys.modules\n"
            "assert 'federation_router' in dir(srv)\n"
            "assert 'create_telegram_webhook_router' in dir(srv)\n"
            "fake = APIRouter()\n"
            "@fake.get('/ping')\n"
            "def _ping(): return {'ok': True}\n"
            "with patch('acgs_lite.server.federation_router', fake):\n"
            "    assert srv.federation_router is fake\n"
        )
        subprocess.run([sys.executable, "-c", code], check=True, timeout=30)

        # In-process: patching acgs_lite.server.federation_router is honored by create_governance_app.
        from fastapi.testclient import TestClient

        fake_router = APIRouter()

        @fake_router.get("/patched-probe")
        def _patched_probe() -> dict[str, bool]:
            return {"patched": True}

        monkeypatch.setenv("ACGS_FEDERATION_ENABLED", "true")
        with patch("acgs_lite.server.federation_router", fake_router):
            app = srv.create_governance_app(require_auth=False)
            resp = TestClient(app).get("/v1/federation/patched-probe")
            assert resp.status_code == 200
            assert resp.json() == {"patched": True}

        # Unknown attribute still raises AttributeError.
        with pytest.raises(AttributeError):
            srv.__getattr__("nonexistent_server_router_xyz")


# ── 8. Constant-time auth, input validation, and batch/rule edge cases ───────


class TestConstantTimeAuthAndInputHardening:
    def test_constant_time_compare_handles_ascii_unicode_empty_and_surrogates(self) -> None:
        from acgs_lite._compat import constant_time_compare

        assert constant_time_compare("", "") is True
        assert constant_time_compare("secret-key", "secret-key") is True
        assert constant_time_compare("secret-key", "secret-key-2") is False
        assert constant_time_compare("clé-secrète", "clé-secrète") is True
        assert constant_time_compare("clé-secrète", "ascii-key") is False
        assert constant_time_compare("\ud800bad", "\ud800bad") is True
        assert constant_time_compare("\ud800bad", "ascii") is False

    @staticmethod
    def _raw_asgi_post(
        app: Any,
        path: str,
        payload: dict[str, Any],
        headers: list[tuple[bytes, bytes]],
    ) -> tuple[int, dict[str, Any]]:
        import asyncio

        body = json.dumps(payload).encode("utf-8")
        req_headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            *headers,
        ]
        status_code = 0
        chunks: list[bytes] = []

        async def _run() -> tuple[int, dict[str, Any]]:
            nonlocal status_code
            sent = False
            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": path,
                "raw_path": path.encode("ascii"),
                "query_string": b"",
                "headers": req_headers,
            }

            async def _receive() -> dict[str, Any]:
                nonlocal sent
                if not sent:
                    sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return {"type": "http.disconnect"}

            async def _send(message: dict[str, Any]) -> None:
                nonlocal status_code
                if message["type"] == "http.response.start":
                    status_code = int(message["status"])
                elif message["type"] == "http.response.body":
                    chunks.append(message.get("body", b""))

            await app(scope, _receive, _send)
            raw = b"".join(chunks)
            return status_code, json.loads(raw.decode("utf-8")) if raw else {}

        return asyncio.run(_run())

    def test_server_rejects_non_ascii_api_key_with_401_and_non_string_action_with_422(
        self,
    ) -> None:
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from acgs_lite.server import create_governance_app

        app = create_governance_app(api_key="test-key", require_auth=True)

        # Raw Latin-1 non-ASCII X-API-Key header must fail closed with 401 (never TypeError -> 500).
        status_auth, _ = self._raw_asgi_post(
            app,
            "/validate",
            {"action": "check status"},
            [(b"x-api-key", b"cl\xe9-invalide")],
        )
        assert status_auth == 401

        client = TestClient(app)
        # Non-string 'action' values must return 422 (never AttributeError -> 500).
        for bad_action in (None, 123, ["rm -rf"], {"cmd": "ls"}, True):
            resp = client.post(
                "/validate",
                json={"action": bad_action},
                headers={"X-API-Key": "test-key"},
            )
            assert resp.status_code == 422, f"expected 422 for action={bad_action!r}"

    def test_lifecycle_router_rejects_non_ascii_api_key_with_401(self) -> None:
        pytest.importorskip("fastapi")
        from fastapi import FastAPI

        from acgs_lite.constitution.lifecycle_router import create_lifecycle_router

        app = FastAPI()
        app.include_router(create_lifecycle_router(api_key="lifecycle-secret"))

        status_code, body = self._raw_asgi_post(
            app,
            "/constitution/lifecycle/draft",
            {"tenant_id": "acme", "name": "draft-1"},
            [(b"x-api-key", b"cl\xe9-non-ascii"), (b"x-actor-id", b"alice")],
        )
        assert status_code == 401
        assert body["detail"]["code"] == "AUTH_REQUIRED"

    def test_telegram_webhook_rejects_non_ascii_token_and_boolean_chat_id(self) -> None:
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from acgs_lite.integrations.telegram_webhook import create_telegram_webhook_router

        engine = GovernanceEngine(
            Constitution.default(), strict=False, warmup=False, freeze_gc=False
        )
        app = FastAPI()
        app.include_router(
            create_telegram_webhook_router(
                engine_getter=lambda: engine,
                webhook_path_secret="hook-secret",
                secret_token="tg-secret",
            )
        )

        # Raw Latin-1 non-ASCII secret header must return 401 rather than crashing with TypeError.
        status_bad_tok, _ = self._raw_asgi_post(
            app,
            "/telegram/webhook/hook-secret",
            {"message": {"chat": {"id": 42}, "text": "hello"}},
            [(b"x-telegram-bot-api-secret-token", b"jeton-invalide-\xe9")],
        )
        assert status_bad_tok == 401

        client = TestClient(app)
        # Boolean chat.id (True is an int subclass in Python) must be ignored safely.
        resp_bool_chat = client.post(
            "/telegram/webhook/hook-secret",
            json={"message": {"chat": {"id": True}, "text": "hello"}},
            headers={"X-Telegram-Bot-Api-Secret-Token": "tg-secret"},
        )
        assert resp_bool_chat.status_code == 200
        assert resp_bool_chat.json() == {"ok": True}

    def test_github_and_autonoma_signature_checks_reject_non_ascii_safely(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from acgs_lite.integrations.github import GitHubWebhookHandler

        handler = GitHubWebhookHandler(webhook_secret="gh-secret", bot=None)  # type: ignore[arg-type]
        assert handler.verify_signature(b'{"action":"opened"}', "sha256=invalide-é") is False

        pytest.importorskip("fastapi")
        pytest.importorskip("jwt")
        from fastapi import HTTPException

        from acgs_lite.autonoma import _verify_hmac

        monkeypatch.setenv("AUTONOMA_SIGNING_SECRET", "autonoma-secret")
        with pytest.raises(HTTPException) as exc_info:
            _verify_hmac(b"{}", "signature-non-ascii-é")
        assert exc_info.value.status_code == 401

    def test_rule_model_validate_does_not_mutate_caller_dict(self) -> None:
        raw: dict[str, Any] = {
            "id": "R-NOMUT",
            "text": "Warn only rule",
            "severity": "medium",
            "keywords": ["warnme"],
        }
        rule = Rule.model_validate(raw)
        assert rule.workflow_action is ViolationAction.WARN
        assert "workflow_action" not in raw

    def test_validate_batch_report_fast_path_and_empty_batch(self) -> None:
        rules = [
            Rule(
                id="B-HIGH",
                text="Block danger",
                severity=Severity.HIGH,
                keywords=["danger"],
            ),
            Rule(
                id="B-MED",
                text="Warn caution",
                severity=Severity.MEDIUM,
                keywords=["caution"],
            ),
            Rule(
                id="B-HALT",
                text="Halt catastrophic",
                severity=Severity.CRITICAL,
                keywords=["catastrophic"],
                workflow_action=ViolationAction.HALT,
            ),
        ]
        engine = GovernanceEngine(
            Constitution(name="batch-test", rules=rules),
            strict=True,
            warmup=False,
            freeze_gc=False,
        )

        empty = engine.validate_batch_report([])
        assert empty.total == 0
        assert empty.compliance_rate == 1.0

        report = engine.validate_batch_report(
            [
                "safe action",
                "trigger danger now",
                ("note caution here", {"source": "test"}),
                "trigger catastrophic halt",
            ]
        )
        assert report.total == 4
        assert report.allowed == 1
        assert report.denied == 2
        assert report.escalated == 1
        assert set(report.critical_rule_ids) == {"B-HIGH", "B-HALT"}

    def test_rust_fast_path_falls_through_when_audit_metadata_present_with_context(self) -> None:
        """Passing audit_metadata with context must bypass the Rust fast path cleanly."""
        calls: list[str] = []

        class _SpyRust:
            def validate_hot(self, text: str) -> tuple[int, int]:
                calls.append(f"hot:{text}")
                return (0, 0)

            def validate_full(self, text: str, pairs: Any) -> tuple[int, list[Any], bool]:
                calls.append(f"full:{text}")
                return (0, [], False)

        const = Constitution(
            name="meta-test",
            rules=[Rule(id="M-1", text="Block bad", severity=Severity.HIGH, keywords=["bad"])],
        )
        engine = GovernanceEngine(const, strict=False, warmup=False, freeze_gc=False)
        engine._rust_validator = _SpyRust()
        hot = list(engine._hot)
        hot[10] = engine._rust_validator
        engine._hot = tuple(hot)

        res = engine.validate(
            "bad action",
            context={"source": "probe"},
            audit_metadata={"trace_id": "t-123"},
            strict=False,
        )
        assert res.valid is False
        assert calls == []

        with pytest.raises(engine_core.ConstitutionalViolationError):
            engine.validate(
                "bad action",
                context={"source": "probe"},
                audit_metadata={"trace_id": "t-123"},
                strict=True,
            )
        assert calls == []

    def test_unified_python_ac_matcher_handles_positive_verb_and_anchors(self) -> None:
        """Unified _validate_python_ac matches keywords, anchors, and no-anchor patterns identically."""
        from acgs_lite.engine.matcher import _HAS_AHO

        const = Constitution(
            name="ac-parity",
            rules=[
                Rule(
                    id="AC-KW",
                    text="Audit keyword",
                    severity=Severity.HIGH,
                    keywords=["audit"],
                ),
                Rule(
                    id="AC-NEG",
                    text="Bypass keyword",
                    severity=Severity.CRITICAL,
                    keywords=["bypass"],
                ),
                Rule(
                    id="AC-PAT-ANCHOR",
                    text="Anchored secret",
                    severity=Severity.HIGH,
                    patterns=[r"AKIA[0-9A-Z]{16}"],
                ),
                Rule(
                    id="AC-PAT-NOANCHOR",
                    text="Unanchored ssn",
                    severity=Severity.HIGH,
                    patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
                ),
            ],
        )
        engine = GovernanceEngine(const, strict=False, warmup=False, freeze_gc=False)
        # Positive verb exempts non-negative keyword, still catches negative keyword and patterns.
        assert engine.validate("run audit report").valid is True
        assert {v.rule_id for v in engine.validate("run audit without review").violations} == {
            "AC-KW"
        }
        assert {v.rule_id for v in engine.validate("run bypass check").violations} == {"AC-NEG"}
        assert {
            v.rule_id for v in engine.validate("run check AKIAABCDEFGHIJKLMNOP").violations
        } == {"AC-PAT-ANCHOR"}
        assert {v.rule_id for v in engine.validate("run check 123-45-6789").violations} == {
            "AC-PAT-NOANCHOR"
        }
        if _HAS_AHO:
            assert engine._ac_iter is not None
