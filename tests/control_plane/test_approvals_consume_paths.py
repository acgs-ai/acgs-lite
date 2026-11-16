"""Refusal paths of ApprovalGate.consume, evaluate and telemetry bookkeeping.

A refused consumption must leave every approval unspent, and telemetry
failures are best-effort: counted, never raised, never an authorization input.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from acgs_lite.control_plane import Principal, PrincipalKind
from acgs_lite.control_plane.action_hash import action_hash
from acgs_lite.control_plane.approvals import (
    ApprovalAuthority,
    ApprovalGate,
    ApprovalRegistrationRejected,
    QuorumResult,
    SignedApproval,
)
from acgs_lite.control_plane.pdp import DecisionRequest
from acgs_lite.control_plane.telemetry import InMemoryTelemetryStore, TelemetryRecorder
from acgs_lite.control_plane.tiers import ActionTier

pytest.importorskip("cryptography")

pytestmark = pytest.mark.unit

AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
ADMIN = Principal("root-admin", PrincipalKind.HUMAN)
REQUEST = DecisionRequest(AGENT, "file.write", "workspace/a", ActionTier.T2)


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now
        self.fail = False

    def __call__(self) -> float:
        if self.fail:
            raise RuntimeError("clock broken")
        return self.now


@pytest.fixture()
def clock() -> _Clock:
    return _Clock(time.time())


@pytest.fixture()
def gate(approval_authority: ApprovalAuthority, clock: _Clock) -> ApprovalGate:
    return ApprovalGate(approval_authority, clock=clock)


@pytest.fixture()
def sign(approver_factory: Callable[..., Callable[..., SignedApproval]]) -> Callable[..., Any]:
    return approver_factory("bob")


@pytest.fixture()
def approval(sign: Callable[..., Any], clock: _Clock) -> SignedApproval:
    return sign(action_hash(REQUEST), now=clock.now)  # type: ignore[no-any-return]


def test_unsatisfied_result_is_not_spendable(gate: ApprovalGate) -> None:
    assert gate.consume(QuorumResult(False, "x", 1)) is False


def test_non_finite_clock_refuses_consumption(
    gate: ApprovalGate, clock: _Clock, approval: SignedApproval
) -> None:
    result = gate.evaluate(REQUEST, [approval])
    assert result.satisfied
    clock.now = math.nan

    assert gate.consume(result) is False
    assert gate.is_consumed(approval) is False


def test_raising_clock_refuses_consumption_without_burning_approvals(
    gate: ApprovalGate, clock: _Clock, approval: SignedApproval
) -> None:
    result = gate.evaluate(REQUEST, [approval])
    assert result.satisfied
    clock.now = time.time()
    clock.fail = True

    assert gate.consume(result) is False
    assert not gate.is_consumed(approval)

    clock.fail = False
    assert gate.consume(result) is True
    assert gate.is_consumed(approval)


def test_human_cannot_be_a_system_member(approval_authority: ApprovalAuthority) -> None:
    with pytest.raises(ApprovalRegistrationRejected, match="system members are agents or services"):
        approval_authority.register_system_member(
            ADMIN, Principal("hum", PrincipalKind.HUMAN, system_id="s")
        )

    assert approval_authority.is_system_member("s", "hum") is False


@pytest.mark.parametrize("bad", ["", " bob", "bo\x00b"])
def test_malformed_approver_id_is_rejected_not_counted(
    gate: ApprovalGate, approval: SignedApproval, bad: str
) -> None:
    result = gate.evaluate(REQUEST, [replace(approval, approver_id=bad)])

    assert not result.satisfied
    assert result.rejected[0][1] == "malformed approver_id"
    assert result.counted_approvals == ()
    assert gate.is_consumed(approval) is False


class TestTelemetryBookkeeping:
    @pytest.fixture()
    def tclock(self) -> _Clock:
        return _Clock(time.time())

    @pytest.fixture()
    def tgate(self, approval_authority: ApprovalAuthority, tclock: _Clock) -> ApprovalGate:
        recorder = TelemetryRecorder(
            InMemoryTelemetryStore(), Principal("ci-bot", PrincipalKind.SERVICE), clock=tclock
        )
        return ApprovalGate(approval_authority, clock=_Clock(time.time()), telemetry=recorder)

    def test_clock_failure_while_noting_a_request_is_counted_not_raised(
        self, tgate: ApprovalGate, tclock: _Clock
    ) -> None:
        tclock.fail = True

        assert tgate.note_approval_requested("sha256:" + "c" * 64) is None
        assert tgate.telemetry_failures == 1

    def test_telemetry_failure_at_grant_time_does_not_block_a_valid_quorum(
        self, tgate: ApprovalGate, tclock: _Clock, sign: Callable[..., Any]
    ) -> None:
        granted = sign(action_hash(REQUEST), now=time.time())
        result = tgate.evaluate(REQUEST, [granted])
        assert result.satisfied
        before = tgate.telemetry_failures
        tclock.fail = True

        assert tgate.consume(result) is True
        assert tgate.is_consumed(granted)
        assert tgate.telemetry_failures == before + 1
        # Single use still holds: the spent quorum cannot be spent again.
        assert tgate.consume(result) is False

    def test_pending_tracking_evicts_oldest_first_and_never_gates_authorization(
        self, tgate: ApprovalGate, sign: Callable[..., Any]
    ) -> None:
        first = action_hash(REQUEST)
        cycle = tgate.note_approval_requested(first)
        assert cycle is not None
        assert tgate.note_approval_requested(first) == cycle  # still tracked, same cycle

        middle = newest = None
        for i in range(1, 4098):
            digest = "sha256:" + f"{i:064x}"
            recorded = tgate.note_approval_requested(digest)
            if i == 101:
                middle = (digest, recorded)
            if i == 4097:
                newest = (digest, recorded)

        assert middle is not None and newest is not None
        # Oldest-first eviction, not a wipe: newer entries keep their cycle.
        assert tgate.note_approval_requested(middle[0]) == middle[1]
        assert tgate.note_approval_requested(newest[0]) == newest[1]
        assert tgate.note_approval_requested(first) != cycle  # evicted, new cycle

        # Telemetry bookkeeping never affects authorization: a valid approval
        # for the evicted request still satisfies and consumes.
        granted = sign(first, now=time.time())
        result = tgate.evaluate(REQUEST, [granted])
        assert result.satisfied
        assert tgate.consume(result) is True
