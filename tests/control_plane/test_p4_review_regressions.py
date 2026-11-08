"""Regression tests for the PR #240 (phase 4) review threads."""

from __future__ import annotations

from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.autonomy import AutonomyController, ErrorBudget
from acgs_lite.control_plane.breaker import (
    BreakerPolicy,
    TriggerCircuitBreaker,
    TriggerRegistry,
)
from acgs_lite.control_plane.budgets import BudgetLedger
from acgs_lite.control_plane.telemetry import (
    DecisionObserved,
    InMemoryTelemetryStore,
    OversightMetrics,
    TelemetryRecorder,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

CI = Principal("ci-bot", PrincipalKind.SERVICE)
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
ALICE = Principal("alice", PrincipalKind.HUMAN)


class Clock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _breaker(
    policy: BreakerPolicy, autonomy: AutonomyController | None = None
) -> tuple[TriggerCircuitBreaker, TelemetryRecorder, Clock, InMemoryTelemetryStore]:
    clock = Clock()
    store = InMemoryTelemetryStore()
    registry = TriggerRegistry()
    registry.bind(ALICE, "loop-a", principals=[AGENT])
    breaker = TriggerCircuitBreaker(policy, store, autonomy, registry=registry, clock=clock)
    return breaker, TelemetryRecorder(store, CI, clock=clock), clock, store


def _dispatcher(
    pdp: PolicyDecisionPoint, breaker: TriggerCircuitBreaker, calls: list[str], **kw: Any
) -> GovernedToolDispatcher:
    d = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE, [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))]
        ),
        tool_tiers={"write": ActionTier.T1},
        breaker=breaker,
        **kw,
    )
    d.register("write", lambda path: calls.append(path), path_params={"path"})
    return d


class TestAutonomyControllerMustMatch:
    """240.1 / 240.6: dispatcher and breaker must share one controller."""

    def test_mismatched_controller_rejected(self, pdp: PolicyDecisionPoint) -> None:
        budgets = BudgetLedger()
        breaker, _, _, _ = _breaker(BreakerPolicy(), AutonomyController(ErrorBudget(), budgets))
        with pytest.raises(ValueError, match="breaker's AutonomyController"):
            _dispatcher(
                pdp,
                breaker,
                [],
                budgets=budgets,
                autonomy=AutonomyController(ErrorBudget(), budgets),
            )

    def test_same_controller_accepted(self, pdp: PolicyDecisionPoint) -> None:
        budgets = BudgetLedger()
        autonomy = AutonomyController(ErrorBudget(), budgets)
        breaker, _, _, _ = _breaker(BreakerPolicy(), autonomy)
        _dispatcher(pdp, breaker, [], budgets=budgets, autonomy=autonomy)


class TestCohortBindingPinsIdentity:
    """240.2 / 240.5 / 240.13: cohort-only bindings pin the first system."""

    def test_cohort_admitted_agent_cannot_switch_system(self) -> None:
        registry = TriggerRegistry()
        registry.bind(ALICE, "t-a", system_ids=["sys-a"])
        registry.bind(ALICE, "t-b", system_ids=["sys-b"])
        as_a = Principal("agent-7", PrincipalKind.AGENT, system_id="sys-a")
        as_b = Principal("agent-7", PrincipalKind.AGENT, system_id="sys-b")
        assert registry.is_bound("t-a", as_a)
        assert not registry.is_bound("t-b", as_b)
        assert registry.cohorts_of(as_b) == ("sys-a",)

    def test_first_admission_decides(self) -> None:
        registry = TriggerRegistry()
        registry.bind(ALICE, "t-b", system_ids=["sys-b"])
        as_b = Principal("agent-8", PrincipalKind.AGENT, system_id="sys-b")
        assert registry.is_bound("t-b", as_b)
        assert registry.is_bound("t-b", as_b)  # repeat admission is fine


class TestHalfOpenProbe:
    """240.4 / 240.9: a denied call must not spend the only probe."""

    def test_denied_call_keeps_the_probe(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        breaker, rec, clock, _ = _breaker(
            BreakerPolicy(max_rollbacks=1, cooldown_s=100, cohort_suspension=False)
        )
        d = _dispatcher(pdp, breaker, calls)
        rec.record_rollback("loop-a", "c1", agent=AGENT)
        clock.now += 100
        # Denied by the PDP after the harness's half-open availability check.
        # A pre-check denial would not exercise probe preservation here.
        with pytest.raises(ToolDenied, match="INV-"):
            d.dispatch(AGENT, "write", {"path": "workspace/.env"}, trigger_id="loop-a")
        assert breaker.status("loop-a").probes == 0
        d.dispatch(AGENT, "write", {"path": "workspace/a"}, trigger_id="loop-a")
        assert calls == ["workspace/a"]
        assert breaker.status("loop-a").probes == 1


class TestAdmissionRecheckedBeforeInvoke:
    """240.7: a trip during PDP evaluation stops the already-authorised call."""

    def test_trip_during_evaluation_blocks_invocation(
        self, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        calls: list[str] = []
        breaker, rec, _, store = _breaker(BreakerPolicy(max_rollbacks=1, cohort_suspension=False))
        tripped: list[bool] = []

        def trip_on_allow(decision: Any) -> None:
            if decision.allowed and not tripped:
                tripped.append(True)
                rec.record_rollback("loop-a", "c1", agent=AGENT)

        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, listeners=[trip_on_allow], telemetry=rec
        ) as pdp:
            d = _dispatcher(pdp, breaker, calls)
            with pytest.raises(ToolDenied, match="autonomous mode suspended") as denied:
                d.dispatch(AGENT, "write", {"path": "workspace/a"}, trigger_id="loop-a")
        assert tripped and calls == []
        rec.record_override(denied.value.decision.decision_id, ALICE, "human_overrode_deny")
        metric = OversightMetrics(store).override_rate("agent")
        assert metric.denominator == 1
        assert metric.numerator == 1


class TestPreDenialTelemetryKind:
    """240.3 / 240.8: dispatcher pre-denials keep the validated kind."""

    def test_pre_denial_segmented_as_agent(
        self, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        store = InMemoryTelemetryStore()
        recorder = TelemetryRecorder(store, CI)
        breaker, _, _, _ = _breaker(BreakerPolicy())
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, telemetry=recorder
        ) as pdp:
            d = _dispatcher(pdp, breaker, [])
            with pytest.raises(ToolDenied, match="trigger_id"):
                d.dispatch(AGENT, "write", {"path": "workspace/a"})  # no trigger_id
        events = [e for e in store.read_all() if isinstance(e, DecisionObserved)]
        assert events and events[-1].principal_kind is PrincipalKind.AGENT
        assert events[-1].allowed is False


class TestQuorumCompletionLatency:
    """240.11: latency runs to the grant that completes the quorum."""

    def test_t3_latency_is_last_grant(self) -> None:
        store = InMemoryTelemetryStore()
        rec = TelemetryRecorder(store, CI, clock=Clock())
        digest = "sha256:" + "b" * 64
        rec.record_approval_requested(digest, at=1000)
        rec.record_approval_granted(digest, "bob", at=1010)
        rec.record_approval_granted(digest, "carol", at=1090)
        latency = OversightMetrics(store).approval_latency()
        assert latency.max_s == 90
        assert latency.pre_approved == 0
