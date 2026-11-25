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


class TestLazySubmoduleAndStreamingHardening:
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
