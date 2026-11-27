"""Tests for O(1) deque eviction in non-core modules and PEP 639 SPDX license metadata."""

from __future__ import annotations

import sys
import threading
from collections import deque
from pathlib import Path

from acgs_lite.constitution import Severity
from acgs_lite.constitution.metrics import AuditLedger, GovernanceForecaster, GovernanceSession
from acgs_lite.constitution.versioning import GovernanceChangelog
from acgs_lite.engine.types import Violation
from acgs_lite.eu_ai_act.article12 import Article12Logger
from acgs_lite.integrations.dashboard import ViolationTimeline

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib


class TestDequeEvictionEdgeCases:
    def test_governance_session_deque_eviction_and_consecutive_denials(self) -> None:
        session = GovernanceSession("agent-1", max_history=10, deny_threshold=0.9)
        assert isinstance(session._decisions, deque)
        assert session._decisions.maxlen == 10

        # Record 15 events: first 10 allows, last 5 denies -> retains last 10 (5 allows + 5 denies).
        for i in range(10):
            session.record("allow", action=f"allow-{i}")
        for i in range(5):
            session.record("deny", action=f"deny-{i}", rule_ids=[f"R-{i}"])

        report = session.analyze()
        assert report["total_decisions"] == 10
        assert report["by_decision"]["allow"] == 5
        assert report["by_decision"]["deny"] == 5
        assert any("5 consecutive denials" in a for a in report["anomalies"])
        assert [d["action"] for d in report["recent_denials"]] == [f"deny-{i}" for i in range(5)]

        # Zero-capacity session stays empty without crashing.
        zero = GovernanceSession("agent-0", max_history=0)
        zero.record("deny", action="x")
        assert zero.analyze()["total_decisions"] == 0

    def test_audit_ledger_deque_eviction_and_summary(self) -> None:
        ledger = AuditLedger(max_entries=3)
        assert isinstance(ledger._entries, deque)
        for i in range(6):
            ledger.record(
                f"act-{i}",
                "deny" if i % 2 else "allow",
                agent_id=f"a-{i}",
                timestamp=f"2026-01-01T00:00:0{i}Z",
            )
        assert len(ledger) == 3
        summary = ledger.summary()
        assert summary["total"] == 3
        assert summary["time_range"] == {
            "earliest": "2026-01-01T00:00:03Z",
            "latest": "2026-01-01T00:00:05Z",
        }
        assert [e.action for e in ledger.query()] == ["act-3", "act-4", "act-5"]

    def test_governance_forecaster_deque_eviction_and_dynamic_max_windows(self) -> None:
        fc = GovernanceForecaster(max_windows=3)
        assert isinstance(fc._windows, deque)
        for i in range(5):
            fc.record_window(f"w-{i}", allow=10 - i, deny=i)
        assert [w["label"] for w in fc.history()] == ["w-2", "w-3", "w-4"]

        # Mutating public max_windows post-init resizes the underlying deque.
        fc.max_windows = 2
        fc.record_window("w-5", allow=5, deny=5)
        assert [w["label"] for w in fc.history()] == ["w-4", "w-5"]

    def test_governance_changelog_deque_eviction_and_summary(self) -> None:
        cl = GovernanceChangelog(max_entries=2)
        assert isinstance(cl._entries, deque)
        for i in range(4):
            cl.record(
                "rule_added",
                rule_id=f"R-{i}",
                actor=f"u-{i}",
                timestamp=f"2026-01-01T00:00:0{i}Z",
            )
        assert len(cl) == 2
        assert [e.rule_id for e in cl.query()] == ["R-2", "R-3"]
        summary = cl.summary()
        assert summary["time_range"] == {
            "earliest": "2026-01-01T00:00:02Z",
            "latest": "2026-01-01T00:00:03Z",
        }

    def test_article12_logger_deque_eviction_preserves_chain_and_detects_tamper(self) -> None:
        logger = Article12Logger(system_id="sys-1", max_records=3)
        assert isinstance(logger._records, deque)
        assert isinstance(logger._chain_hashes, deque)

        for i in range(6):
            logger.log_call(f"op-{i}", call=lambda v=i: f"res-{v}", input_text=f"in-{i}")

        assert logger.record_count == 3
        assert [r.operation for r in logger.records] == ["op-3", "op-4", "op-5"]
        assert logger.verify_chain() is True

        # Dynamic max_records shrink takes effect cleanly on next append.
        logger.max_records = 2
        logger.log_call("op-6", call=lambda: "res-6")
        assert logger.record_count == 2
        assert [r.operation for r in logger.records] == ["op-5", "op-6"]
        assert logger.verify_chain() is True

        # Tampering with stored chain hash is still detected.
        logger._chain_hashes[-1] = "0" * 16
        assert logger.verify_chain() is False

        # Clearing _records while _chain_hashes remains non-empty must also fail closed.
        logger._records.clear()
        assert logger.verify_chain() is False

    def test_negative_capacity_clamps_to_zero_without_crashing(self) -> None:
        session = GovernanceSession("agent-neg", max_history=-5)
        assert session._max_history == 0
        assert session._decisions.maxlen == 0
        session.record("deny", action="x")
        assert session.analyze()["total_decisions"] == 0

        ledger = AuditLedger(max_entries=-3)
        assert ledger._max_entries == 0
        assert ledger._entries.maxlen == 0
        ledger.record("act", "deny")
        assert len(ledger) == 0

        fc = GovernanceForecaster(max_windows=-2)
        assert fc._windows.maxlen == 0
        fc.record_window("w-0", allow=1, deny=0)
        assert fc.history() == []

        cl = GovernanceChangelog(max_entries=-1)
        assert cl._max_entries == 0
        assert cl._entries.maxlen == 0
        cl.record("rule_added", rule_id="R-1")
        assert len(cl) == 0

        logger = Article12Logger(system_id="sys-neg", max_records=-4)
        assert logger._records.maxlen == 0
        assert logger._chain_hashes.maxlen == 0
        logger.log_call("op-neg", call=lambda: "ok")
        assert logger.record_count == 0
        assert logger.verify_chain() is True

        tl = ViolationTimeline(max_entries=-2)
        assert tl._max_entries == 0
        assert tl._entries.maxlen == 0
        tl.record(Violation("R-0", "Rule 0", Severity.HIGH, "act", "sec"), "agent-1")
        assert tl.get_timeline() == []

    def test_violation_timeline_deque_eviction_and_last_n_edges(self) -> None:
        tl = ViolationTimeline(max_entries=4)
        assert isinstance(tl._entries, deque)
        for i in range(7):
            tl.record(
                Violation(f"R-{i}", f"Rule {i}", Severity.HIGH, "act", "sec"),
                "agent-1",
                timestamp=f"2026-01-01T0{i}:00:00Z",
            )

        assert [e["rule_id"] for e in tl.get_timeline()] == ["R-3", "R-4", "R-5", "R-6"]
        assert [e["rule_id"] for e in tl.get_timeline(last_n=2)] == ["R-5", "R-6"]
        assert [e["rule_id"] for e in tl.get_timeline(last_n=10)] == ["R-3", "R-4", "R-5", "R-6"]
        assert tl.get_timeline(last_n=0) == []
        assert tl.get_timeline(last_n=-3) == []


def test_pyproject_uses_pep639_spdx_license() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    data = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    assert "setuptools>=77.0.3" in data["build-system"]["requires"]
    project = data["project"]
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE", "NOTICE"]
    assert not any(c.startswith("License ::") for c in project.get("classifiers", []))
    assert "twine>=6.1" in project["optional-dependencies"]["dev"]
    assert (repo_root / "LICENSE").is_file()
    assert (repo_root / "NOTICE").is_file()


class TestConcurrentDequeSafety:
    def test_violation_timeline_concurrent_record_and_reads(self) -> None:
        tl = ViolationTimeline(max_entries=16)
        barrier = threading.Barrier(3)
        done = threading.Event()
        errors: list[BaseException] = []

        def writer() -> None:
            try:
                barrier.wait()
                for i in range(300):
                    tl.record(
                        Violation(f"R-{i}", f"Rule {i}", Severity.HIGH, "act", "sec"),
                        "agent-1" if i % 2 == 0 else "agent-2",
                        timestamp=f"2026-01-01T{i % 24:02d}:00:00Z",
                    )
                    if i % 20 == 0:
                        threading.Event().wait(0.0001)
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)
            finally:
                done.set()

        def reader() -> None:
            try:
                barrier.wait()
                passes = 0
                while not done.is_set() or passes < 10:
                    s = tl.summary()
                    assert s["total"] <= 16
                    assert len(tl.get_by_severity("high")) <= 16
                    assert len(tl.get_by_agent("agent-1")) <= 16
                    assert len(tl.get_timeline()) <= 16
                    assert len(tl.get_timeline(last_n=5)) <= 5
                    passes += 1
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
            assert not t.is_alive()

        assert errors == []
        assert tl.summary()["total"] == 16

    def test_governance_session_concurrent_record_and_analyze(self) -> None:
        session = GovernanceSession("agent-concurrent", max_history=20, deny_threshold=0.5)
        barrier = threading.Barrier(3)
        done = threading.Event()
        errors: list[BaseException] = []

        def writer() -> None:
            try:
                barrier.wait()
                for i in range(300):
                    decision = ("allow", "deny", "escalate")[i % 3]
                    session.record(
                        decision,
                        action=f"act-{i}",
                        rule_ids=[f"R-{i % 4}"] if decision != "allow" else (),
                    )
                    if i % 20 == 0:
                        threading.Event().wait(0.0001)
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)
            finally:
                done.set()

        def reader() -> None:
            try:
                barrier.wait()
                passes = 0
                while not done.is_set() or passes < 10:
                    report = session.analyze()
                    assert report["total_decisions"] <= 20
                    passes += 1
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
            assert not t.is_alive()

        assert errors == []
        assert session.analyze()["total_decisions"] == 20

    def test_audit_ledger_concurrent_record_and_reads(self) -> None:
        ledger = AuditLedger(max_entries=20)
        barrier = threading.Barrier(3)
        done = threading.Event()
        errors: list[BaseException] = []

        def writer() -> None:
            try:
                barrier.wait()
                for i in range(300):
                    ledger.record(
                        f"act-{i}",
                        "deny" if i % 2 else "allow",
                        rule_ids=[f"R-{i % 5}"],
                        agent_id=f"a-{i % 3}",
                        timestamp=f"2026-01-01T00:{i % 60:02d}:00Z",
                    )
                    if i % 20 == 0:
                        threading.Event().wait(0.0001)
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)
            finally:
                done.set()

        def reader() -> None:
            try:
                barrier.wait()
                passes = 0
                while not done.is_set() or passes < 10:
                    assert len(ledger.query(decision="deny")) <= 20
                    assert ledger.summary()["total"] <= 20
                    assert len(ledger.export()) <= 20
                    assert len(ledger) <= 20
                    passes += 1
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
            assert not t.is_alive()

        assert errors == []
        assert len(ledger) == 20

    def test_governance_forecaster_concurrent_record_and_forecast(self) -> None:
        fc = GovernanceForecaster(max_windows=15)
        barrier = threading.Barrier(3)
        done = threading.Event()
        errors: list[BaseException] = []

        def writer() -> None:
            try:
                barrier.wait()
                for i in range(200):
                    fc.record_window(f"w-{i}", allow=80, deny=i % 20, escalate=i % 5)
                    if i % 20 == 0:
                        threading.Event().wait(0.0001)
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)
            finally:
                done.set()

        def reader() -> None:
            try:
                barrier.wait()
                passes = 0
                while not done.is_set() or passes < 10:
                    pred = fc.forecast(steps=3)
                    assert pred["history_windows"] <= 15
                    assert fc.summary()["windows_recorded"] <= 15
                    assert len(fc.history()) <= 15
                    assert "GovernanceForecaster(" in repr(fc)
                    passes += 1
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
            assert not t.is_alive()

        assert errors == []
        assert fc.summary()["windows_recorded"] == 15

    def test_governance_changelog_concurrent_record_and_reads(self) -> None:
        cl = GovernanceChangelog(max_entries=20)
        barrier = threading.Barrier(3)
        done = threading.Event()
        errors: list[BaseException] = []

        def writer() -> None:
            try:
                barrier.wait()
                for i in range(300):
                    cl.record(
                        "rule_added",
                        rule_id=f"R-{i}",
                        actor=f"u-{i % 4}",
                        timestamp=f"2026-01-01T00:{i % 60:02d}:00Z",
                    )
                    if i % 20 == 0:
                        threading.Event().wait(0.0001)
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)
            finally:
                done.set()

        def reader() -> None:
            try:
                barrier.wait()
                passes = 0
                while not done.is_set() or passes < 10:
                    assert len(cl.query(change_type="rule_added")) <= 20
                    assert cl.summary()["total"] <= 20
                    assert len(cl.export()) <= 20
                    assert len(cl) <= 20
                    passes += 1
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
            assert not t.is_alive()

        assert errors == []
        assert len(cl) == 20

    def test_article12_logger_concurrent_writers_and_verify_chain(self) -> None:
        logger = Article12Logger(system_id="sys-concurrent", max_records=25)
        barrier = threading.Barrier(4)
        writers_done = threading.Event()
        lock = threading.Lock()
        remaining_writers = 2
        errors: list[BaseException] = []

        def call_writer() -> None:
            nonlocal remaining_writers
            try:
                barrier.wait()
                for i in range(150):
                    logger.log_call(f"call-{i}", call=lambda v=i: f"out-{v}", input_text=f"in-{i}")
                    if i % 15 == 0:
                        threading.Event().wait(0.0001)
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)
            finally:
                with lock:
                    remaining_writers -= 1
                    if remaining_writers == 0:
                        writers_done.set()

        def ctx_writer() -> None:
            nonlocal remaining_writers
            try:
                barrier.wait()
                for i in range(150):
                    with logger.record_operation(f"ctx-{i}", input_text=f"in-{i}") as ctx:
                        ctx.set_output(f"res-{i}")
                    if i % 15 == 0:
                        threading.Event().wait(0.0001)
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)
            finally:
                with lock:
                    remaining_writers -= 1
                    if remaining_writers == 0:
                        writers_done.set()

        def reader() -> None:
            try:
                barrier.wait()
                passes = 0
                while not writers_done.is_set() or passes < 10:
                    assert logger.verify_chain() is True
                    exported = logger.export_dict()
                    assert exported["chain_valid"] is True
                    assert exported["record_count"] <= 25
                    summary = logger.compliance_summary()
                    assert summary["chain_valid"] is True
                    assert len(logger.records) <= 25
                    assert "Article12Logger(" in repr(logger)
                    passes += 1
            except BaseException as exc:  # pragma: no cover - test failure guard
                errors.append(exc)

        threads = [
            threading.Thread(target=call_writer),
            threading.Thread(target=ctx_writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
            assert not t.is_alive()

        assert errors == []
        assert logger.record_count == 25
        assert logger.verify_chain() is True
