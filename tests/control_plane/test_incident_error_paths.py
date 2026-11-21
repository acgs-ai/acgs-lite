"""Incident mutation lock: fail-closed error paths (unreadable state, unavailable
sidecar locks, failed state writes, PDP denials of lifecycle steps)."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    action_hash,
)
from acgs_lite.control_plane.approvals import ApprovalGate
from acgs_lite.control_plane.incident import IncidentLockError, IncidentMutationLock

pytest.importorskip("cryptography")
from acgs_lite.control_plane import InMemoryReceiptStore, ReceiptLedger  # noqa: E402
from acgs_lite.control_plane.roles import RoleAssignments  # noqa: E402
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = [pytest.mark.unit]

ADMIN = Principal("root-admin", PrincipalKind.HUMAN)
COMMANDER = Principal("carol", PrincipalKind.HUMAN)
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
BOB = Principal("bob", PrincipalKind.HUMAN)
DAVE = Principal("dave", PrincipalKind.HUMAN)


@pytest.fixture()
def lock(tmp_path: Path) -> IncidentMutationLock:
    return IncidentMutationLock(registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)))


@pytest.fixture()
def forbid_pdp(
    tmp_path: Path, approval_gate: ApprovalGate
) -> Iterator[Callable[[str], PolicyDecisionPoint]]:
    """``forbid_pdp(action)`` -> a ledger-backed, gated PDP that permits
    everything except *action*, forbidden by statement ``no-<action>``."""
    opened: list[PolicyDecisionPoint] = []

    def make(action: str) -> PolicyDecisionPoint:
        ledger = ReceiptLedger(
            Ed25519ReceiptSigner.from_seed(b"ledger-seed".ljust(32, b"0"), key_id="test-ledger"),
            store=InMemoryReceiptStore(),
        )
        policy = PolicySet.from_mapping(
            {
                "version": 1,
                "statements": [
                    {"id": "permit-all", "effect": "permit", "actions": ["*"], "resources": ["**"]},
                    {
                        "id": f"no-{action}",
                        "effect": "forbid",
                        "actions": [action],
                        "resources": ["**"],
                    },
                ],
            }
        )
        pdp = PolicyDecisionPoint.for_constitution(
            Constitution.default(),
            policy,
            approval_gate=approval_gate,
            receipt_ledger=ledger,
            registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)),
        )
        opened.append(pdp)
        return pdp

    yield make
    for pdp in opened:
        pdp.close()


def _rewrite_state(lock: IncidentMutationLock, **changes: Any) -> None:
    data = json.loads(lock.state_path.read_text(encoding="utf-8"))
    data.update(changes)
    lock.state_path.write_text(json.dumps(data), encoding="utf-8")


def test_unknown_status_is_unreadable_and_denies_writes(lock: IncidentMutationLock) -> None:
    lock.declare_incident(COMMANDER, "inc-1")
    _rewrite_state(lock, status="paused")

    assert lock.write_denial(AGENT) == (
        "incident lock state unreadable (ValueError); writes denied"
    )
    with pytest.raises(ValueError, match="malformed incident status"):
        lock.state()


def test_execution_lease_sidecar_unavailable_fails_closed(lock: IncidentMutationLock) -> None:
    sidecar = lock.state_path.with_name(lock.state_path.name + ".execution.flock")
    sidecar.mkdir()

    with pytest.raises(IncidentLockError, match="incident execution lease unavailable"):
        lock.declare_incident(COMMANDER, "inc-1")
    body: list[str] = []
    with (
        pytest.raises(IncidentLockError, match="incident execution lease unavailable"),
        lock.execution(AGENT),
    ):
        body.append("ran")
    assert body == []
    assert lock.state() is None


def test_lifecycle_lock_sidecar_unavailable_fails_closed(lock: IncidentMutationLock) -> None:
    sidecar = lock.state_path.with_name(lock.state_path.name + ".flock")
    sidecar.mkdir()

    with pytest.raises(IncidentLockError, match="incident lock unavailable: IsADirectoryError"):
        lock.heartbeat(COMMANDER)
    with pytest.raises(IncidentLockError, match="incident lock unavailable: IsADirectoryError"):
        lock.declare_incident(COMMANDER, "inc-1")
    assert lock.state() is None


def test_failed_state_write_cleans_temp_and_denies_writes(
    lock: IncidentMutationLock, monkeypatch: pytest.MonkeyPatch
) -> None:
    def disk_full(src: Any, dst: Any) -> None:
        raise OSError("disk full")

    with monkeypatch.context() as m:
        m.setattr(os, "replace", disk_full)
        with pytest.raises(OSError, match="disk full"):
            lock.declare_incident(COMMANDER, "inc-1")

    assert list(lock.state_path.parent.glob(".lock-*.tmp")) == []
    assert not lock.state_path.exists()
    # The declare was attempted: a missing state file must keep denying writes.
    assert "unreadable" in str(lock.write_denial(AGENT))


def test_heartbeat_without_incident_is_refused(lock: IncidentMutationLock) -> None:
    with pytest.raises(IncidentLockError, match="no incident is declared"):
        lock.heartbeat(COMMANDER)
    assert lock.history() == ()


def test_heartbeat_on_corrupt_state_is_refused(lock: IncidentMutationLock) -> None:
    lock.state_path.write_text("{not json", encoding="utf-8")

    with pytest.raises(IncidentLockError, match="incident state unreadable: JSONDecodeError"):
        lock.heartbeat(COMMANDER)
    assert lock.history() == ()


def test_takeover_request_without_incident_is_refused(lock: IncidentMutationLock) -> None:
    with pytest.raises(IncidentLockError, match="no incident is declared"):
        lock.takeover_request(BOB, "r")


def test_pdp_denied_declare_is_receipted_and_changes_nothing(
    forbid_pdp: Callable[[str], PolicyDecisionPoint],
) -> None:
    pdp = forbid_pdp("incident.declare")
    lock = IncidentMutationLock(registry=pdp.registry, pdp=pdp)

    with pytest.raises(
        IncidentLockError, match="PDP denied incident.declare: forbidden by no-incident.declare"
    ):
        lock.declare_incident(COMMANDER, "inc-1")

    assert lock.state() is None
    assert lock.history() == ()
    assert pdp.receipt_ledger is not None
    receipts = [(r.receipt.action, r.receipt.allowed) for r in pdp.receipt_ledger.receipts()]
    assert receipts == [("incident.declare", False)]


def test_takeover_refusals_and_pdp_denial_keep_command(
    forbid_pdp: Callable[[str], PolicyDecisionPoint],
    approver_factory: Callable[..., Callable[..., Any]],
) -> None:
    pdp = forbid_pdp("incident.take_over")
    roles = RoleAssignments(ADMIN, pdp=pdp)
    now = [1000.0]
    lock = IncidentMutationLock(
        registry=pdp.registry, roles=roles, clock=lambda: now[0], stale_after_s=60, pdp=pdp
    )
    for holder in (BOB, COMMANDER, DAVE):
        roles.grant_capability(ADMIN, "incident_admin", holder)
    roles.grant_capability(ADMIN, "incident_commander", COMMANDER)
    dave_sign = approver_factory("dave")

    with pytest.raises(IncidentLockError, match="no incident is declared"):
        lock.take_over(BOB, "r")

    lock.declare_incident(COMMANDER, "inc-1")
    with pytest.raises(IncidentLockError, match="the current commander cannot take over"):
        lock.take_over(COMMANDER, "r")

    now[0] += 120  # stale: the commander has been silent past stale_after_s
    approval = dave_sign(action_hash(lock.takeover_request(BOB, "commander unreachable")))
    with pytest.raises(
        IncidentLockError, match="PDP denied takeover: forbidden by no-incident.take_over"
    ):
        lock.take_over(BOB, "commander unreachable", approvals=[approval])
    state = lock.state()
    assert state is not None and state.commander_id == "carol"
    assert [event["event"] for event in lock.history()] == ["declare"]

    lock.state_path.write_text("{bad", encoding="utf-8")
    with pytest.raises(
        IncidentLockError, match=re.escape("incident state unreadable: JSONDecodeError")
    ):
        lock.take_over(BOB, "r")
