"""Phase 5: incident single mutation lock (state file, fail closed)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from acgs_lite.control_plane import DEFAULT_IMMUTABLE_CORE, Principal, PrincipalKind
from acgs_lite.control_plane.incident import IncidentLockError, IncidentMutationLock

pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parents[2]
COMMANDER = Principal("carol", PrincipalKind.HUMAN)
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
OTHER = Principal("agent-2", PrincipalKind.AGENT, system_id="sys-a")
BOB = Principal("bob", PrincipalKind.HUMAN)


@pytest.fixture()
def lock(tmp_path: Path) -> IncidentMutationLock:
    return IncidentMutationLock(registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)))


def test_no_incident_allows_writes(lock: IncidentMutationLock) -> None:
    assert lock.state() is None
    assert lock.write_denial(AGENT) is None


def test_single_holder(lock: IncidentMutationLock) -> None:
    lock.declare_incident(COMMANDER, "inc-1")
    assert "held by nobody" in str(lock.write_denial(COMMANDER))
    token = lock.acquire(AGENT, "inc-1", commander=COMMANDER)
    assert token.holder_id == "agent-1"
    assert lock.write_denial(AGENT) is None
    assert "held by agent-1" in str(lock.write_denial(OTHER))
    assert "held by agent-1" in str(lock.write_denial(BOB))
    # Same id, different kind is a different principal.
    assert lock.write_denial(Principal("agent-1", PrincipalKind.HUMAN)) is not None
    with pytest.raises(IncidentLockError, match="held by"):
        lock.acquire(OTHER, "inc-1", commander=COMMANDER)


def test_commander_only_operations(lock: IncidentMutationLock) -> None:
    with pytest.raises(IncidentLockError, match="HUMAN"):
        lock.declare_incident(AGENT, "inc-1")
    with pytest.raises(IncidentLockError, match="no incident"):
        lock.release(COMMANDER)
    lock.declare_incident(COMMANDER, "inc-1")
    with pytest.raises(IncidentLockError, match="already declared"):
        lock.declare_incident(BOB, "inc-2")
    with pytest.raises(IncidentLockError, match="HUMAN"):
        lock.acquire(AGENT, "inc-1", commander=AGENT)
    with pytest.raises(IncidentLockError, match="declaring"):
        lock.acquire(AGENT, "inc-1", commander=BOB)
    with pytest.raises(IncidentLockError, match="mismatch"):
        lock.acquire(AGENT, "inc-9", commander=COMMANDER)
    lock.acquire(AGENT, "inc-1", commander=COMMANDER)
    with pytest.raises(IncidentLockError):
        lock.transfer(AGENT, OTHER)
    with pytest.raises(IncidentLockError):
        lock.release(BOB)
    lock.transfer(COMMANDER, BOB)
    assert lock.write_denial(BOB) is None and lock.write_denial(AGENT) is not None
    lock.release(COMMANDER)
    assert "nobody" in str(lock.write_denial(BOB))
    with pytest.raises(IncidentLockError):
        lock.resolve(BOB)
    lock.resolve(COMMANDER)
    assert lock.write_denial(AGENT) is None
    with pytest.raises(IncidentLockError):
        lock.resolve(COMMANDER)


def test_validation(tmp_path: Path, lock: IncidentMutationLock) -> None:
    with pytest.raises(IncidentLockError, match="incident_id"):
        lock.declare_incident(COMMANDER, "bad id")
    lock.declare_incident(COMMANDER, "inc-1")
    with pytest.raises(IncidentLockError, match="Principal"):
        lock.acquire("agent-1", "inc-1", commander=COMMANDER)  # type: ignore[arg-type]
    with pytest.raises(IncidentLockError, match="Principal"):
        lock.transfer(COMMANDER, "x")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="immutable core"):
        IncidentMutationLock(
            tmp_path / "workspace" / "lock.json",
            registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)),
        )


@pytest.mark.parametrize(
    "content",
    ["{not json", json.dumps({"version": 2}), json.dumps([1]), ""],
)
def test_corrupted_state_denies_writes(lock: IncidentMutationLock, content: str) -> None:
    lock.state_path.write_text(content, encoding="utf-8")
    assert "unreadable" in str(lock.write_denial(AGENT))
    assert "unreadable" in str(lock.write_denial(COMMANDER))
    with pytest.raises(IncidentLockError, match="unreadable"):
        lock.declare_incident(COMMANDER, "inc-1")
    with pytest.raises(IncidentLockError, match="unreadable"):
        lock.release(COMMANDER)


@pytest.mark.parametrize(
    "mutate",
    [
        {"incident_id": "bad id"},
        {"commander": {"id": "carol", "kind": "agent"}},
        {"commander": {"id": 1, "kind": "human"}},
        {"holder": {"id": "x", "kind": "robot"}},
        {"declared_at": "now"},
    ],
)
def test_malformed_fields_deny(lock: IncidentMutationLock, mutate: dict[str, object]) -> None:
    lock.declare_incident(COMMANDER, "inc-1")
    data = json.loads(lock.state_path.read_text())
    data.update(mutate)
    lock.state_path.write_text(json.dumps(data))
    assert lock.write_denial(AGENT) is not None


def test_missing_directory_denies(lock: IncidentMutationLock) -> None:
    lock.state_path.parent.rmdir()
    assert "unreadable" in str(lock.write_denial(AGENT))


def test_cross_process_visibility(tmp_path: Path, lock: IncidentMutationLock) -> None:
    code = (
        "import sys\n"
        "from acgs_lite.control_plane import DEFAULT_IMMUTABLE_CORE, Principal, PrincipalKind\n"
        "from acgs_lite.control_plane.incident import IncidentMutationLock\n"
        "lock = IncidentMutationLock(registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(sys.argv[1]))\n"
        "c = Principal('carol', PrincipalKind.HUMAN)\n"
        "lock.declare_incident(c, 'inc-x')\n"
        "lock.acquire(Principal('agent-2', PrincipalKind.AGENT, system_id='sys-a'), 'inc-x', "
        "commander=c)\n"
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    subprocess.run([sys.executable, "-c", code, str(tmp_path)], check=True, env=env, timeout=120)
    assert "held by agent-2" in str(lock.write_denial(AGENT))
    assert lock.write_denial(OTHER) is None


# -- through the dispatcher ----------------------------------------------------

from typing import Any  # noqa: E402

from acgs_lite.control_plane import ToolDenied  # noqa: E402


class TestDispatcherIncident:
    def test_writes_denied_reads_allowed(self, p5: Any, runbook_data: Any, sre: Any) -> None:
        digest = p5.approve_runbook(runbook_data())
        write = {"path": f"{p5.worktree}/a.md"}
        kw: dict[str, Any] = {
            "change_id": "c1",
            "runbook_id": "rb-restart-cache",
            "runbook_hash": digest,
        }
        p5.dispatcher.dispatch(AGENT, "write_file", write, **kw)
        p5.incident.declare_incident(COMMANDER, "inc-1")
        with pytest.raises(ToolDenied, match="held by nobody"):
            p5.dispatcher.dispatch(AGENT, "write_file", write, **kw)
        assert p5.dispatcher.dispatch(AGENT, "read_file", {"path": "workspace/a"}).value
        p5.incident.acquire(BOB, "inc-1", commander=COMMANDER)
        with pytest.raises(ToolDenied, match="held by bob"):
            p5.dispatcher.dispatch(AGENT, "write_file", write, **kw)
        with pytest.raises(ToolDenied, match="held by bob"):
            p5.dispatcher.dispatch(COMMANDER, "write_file", {"path": "workspace/x"})
        p5.incident.transfer(COMMANDER, AGENT)
        p5.dispatcher.dispatch(AGENT, "write_file", write, **kw)
        p5.incident.state_path.write_text("garbage")
        with pytest.raises(ToolDenied, match="unreadable"):
            p5.dispatcher.dispatch(AGENT, "write_file", write, **kw)
        assert p5.dispatcher.dispatch(AGENT, "read_file", {"path": "workspace/a"}).value


class TestIncidentHardening:
    """M5: deletion fails closed; promotion/core writes/invoke honour the lock."""

    def test_deleted_state_after_declare_denies(self, lock: IncidentMutationLock) -> None:
        lock.declare_incident(COMMANDER, "inc-1")
        lock.state_path.unlink()
        assert "unreadable" in str(lock.write_denial(AGENT))

    def test_resolve_writes_tombstone(self, tmp_path: Path, lock: IncidentMutationLock) -> None:
        lock.declare_incident(COMMANDER, "inc-1")
        lock.resolve(COMMANDER)
        assert lock.state_path.exists() and lock.write_denial(AGENT) is None
        assert [e["event"] for e in lock.history()] == ["declare", "resolve"]
        # A fresh process sees the history: deleting the tombstone fails closed.
        lock.state_path.unlink()
        fresh = IncidentMutationLock(registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)))
        assert "unreadable" in str(fresh.write_denial(AGENT))
        with pytest.raises(IncidentLockError, match="unreadable"):
            lock.declare_incident(COMMANDER, "inc-2")

    def test_never_declared_has_no_history(self, lock: IncidentMutationLock) -> None:
        assert lock.history() == ()
        assert lock.write_denial(AGENT) is None

    def test_commander_capability_and_break_glass(
        self, tmp_path: Path, ledger_pdp: Any, approver_factory: Any
    ) -> None:
        """R3: staleness counts from the last commander/holder activity, and a
        takeover needs a signed approval from a second incident_admin."""
        from acgs_lite.control_plane.roles import RoleAssignments

        admin = Principal("root-admin", PrincipalKind.HUMAN)
        roles = RoleAssignments(admin, pdp=ledger_pdp)
        now = [1000.0]
        lock = IncidentMutationLock(
            registry=ledger_pdp.registry,
            roles=roles,
            clock=lambda: now[0],
            stale_after_s=60,
            pdp=ledger_pdp,
        )
        with pytest.raises(IncidentLockError, match="incident_commander"):
            lock.declare_incident(COMMANDER, "inc-1")
        roles.grant_capability(admin, "incident_commander", COMMANDER)
        lock.declare_incident(COMMANDER, "inc-1")
        lock.acquire(AGENT, "inc-1", commander=COMMANDER)
        with pytest.raises(IncidentLockError, match="incident_admin"):
            lock.take_over(BOB, "commander unreachable")
        roles.grant_capability(admin, "incident_admin", BOB)
        dave_sign = approver_factory("dave")
        dave = Principal("dave", PrincipalKind.HUMAN)
        roles.grant_capability(admin, "incident_admin", dave)
        with pytest.raises(IncidentLockError, match="reason"):
            lock.take_over(BOB, " ")
        # Active commander: heartbeats keep the incident fresh past its age.
        for _ in range(3):
            now[0] += 50
            lock.heartbeat(COMMANDER)
        with pytest.raises(IncidentLockError, match="not stale"):
            lock.take_over(BOB, "hijack")
        with pytest.raises(IncidentLockError, match="commander or the holder"):
            lock.heartbeat(BOB)
        now[0] += 120  # now really stale
        with pytest.raises(IncidentLockError, match="second incident_admin"):
            lock.take_over(BOB, "commander unreachable")
        bob_sign = approver_factory("bob")
        own = lock.takeover_request(BOB, "commander unreachable")
        from acgs_lite.control_plane import action_hash

        with pytest.raises(IncidentLockError, match="second incident_admin"):
            lock.take_over(BOB, "commander unreachable", approvals=[bob_sign(action_hash(own))])
        approval = dave_sign(action_hash(own))
        state = lock.take_over(BOB, "commander unreachable", approvals=[approval])
        assert state.commander_id == "bob"
        assert "held by nobody" in str(lock.write_denial(AGENT))
        takeover = lock.history()[-1]
        assert takeover["event"] == "takeover" and takeover["approved_by"] == "dave"
        actions = [r.receipt.action for r in ledger_pdp.receipt_ledger.receipts()]
        assert actions.count("incident.take_over") == 1 and "incident.declare" in actions
        with pytest.raises(IncidentLockError, match="role assignments and a PDP"):
            IncidentMutationLock(
                tmp_path / "control-plane" / "incident" / "x.json",
                registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)),
            ).take_over(BOB, "r")
        with pytest.raises(TypeError):
            IncidentMutationLock(
                registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)),
                roles="r",  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError, match="ledger"):
            IncidentMutationLock(
                registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)),
                pdp="p",  # type: ignore[arg-type]
            )

    def test_restart_after_rmtree_denies_writes(self, ledger_pdp: Any) -> None:
        """R4: the ledger remembers an unresolved incident across a restart
        even when the whole state directory is deleted."""
        import shutil

        lock = IncidentMutationLock(registry=ledger_pdp.registry, pdp=ledger_pdp)
        lock.declare_incident(COMMANDER, "inc-2")
        shutil.rmtree(lock.state_path.parent)
        restarted = IncidentMutationLock(registry=ledger_pdp.registry, pdp=ledger_pdp)
        assert not restarted.state_path.parent.exists()  # not recreated empty
        assert "unreadable" in str(restarted.write_denial(AGENT))

    def test_resolved_in_ledger_allows_fresh_start(self, ledger_pdp: Any) -> None:
        import shutil

        lock = IncidentMutationLock(registry=ledger_pdp.registry, pdp=ledger_pdp)
        lock.declare_incident(COMMANDER, "inc-3")
        lock.resolve(COMMANDER)
        shutil.rmtree(lock.state_path.parent)
        restarted = IncidentMutationLock(registry=ledger_pdp.registry, pdp=ledger_pdp)
        assert restarted.write_denial(AGENT) is None
        assert [r.receipt.action for r in ledger_pdp.receipt_ledger.receipts()][-1] == (
            "incident.resolve"
        )

    def test_invoke_time_recheck(self, p5: Any, runbook_data: Any) -> None:
        digest = p5.approve_runbook(runbook_data())

        def declare_mid_flight(decision: Any) -> None:
            if p5.incident.state() is None:
                p5.incident.declare_incident(COMMANDER, "inc-late")

        p5.pdp._listeners = (declare_mid_flight,)
        with pytest.raises(ToolDenied, match="held by nobody"):
            p5.dispatcher.dispatch(
                AGENT,
                "write_file",
                {"path": f"{p5.worktree}/a"},
                change_id="c1",
                runbook_id="rb-restart-cache",
                runbook_hash=digest,
            )
        assert p5.calls == []

    def test_core_writer_honours_lock(
        self, tmp_path: Path, constitution: Any, permit_all: Any, approval_gate: Any
    ) -> None:
        from acgs_lite.control_plane import CoreChangeWriter, CoreWriteRejected, PolicyDecisionPoint

        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        lock = IncidentMutationLock(registry=registry)
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, approval_gate=approval_gate, registry=registry
        ) as pdp:
            writer = CoreChangeWriter(pdp, incident_lock=lock)
            lock.declare_incident(COMMANDER, "inc-1")
            with pytest.raises(CoreWriteRejected, match="incident"):
                writer.write_core(BOB, "policy/x.yaml", b"x", approvals=[])
            with pytest.raises(TypeError):
                CoreChangeWriter(pdp, incident_lock="lock")  # type: ignore[arg-type]
