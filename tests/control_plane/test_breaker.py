"""Phase 4: per-trigger circuit breaker suspends autonomous mode.

The breaker is a design inference (see :mod:`acgs_lite.control_plane.breaker`);
these tests pin its configured behaviour: trips at, not before, the
thresholds; windows expire; OPEN denies non-human dispatch for that trigger
(and its cohort) through the dispatcher only; triggers must be bound by a
human; reset is human-only; a trip demotes through the AutonomyController
(tested with no error-budget bridge attached, so the demotion can only come
from the breaker). Security-review regressions are tagged H1/M1/M4/L1/L2.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.audit import AuditEntry, AuditLog, JSONLAuditBackend
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    CredentialIssuer,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.autonomy import AutonomyController, AutonomyLevel, ErrorBudget
from acgs_lite.control_plane.breaker import (
    BreakerPolicy,
    BreakerResetRejected,
    BreakerState,
    TriggerBindingRejected,
    TriggerCircuitBreaker,
    TriggerRegistry,
)
from acgs_lite.control_plane.credentials import CredentialIssuanceRefused
from acgs_lite.control_plane.telemetry import (
    InMemoryTelemetryStore,
    TelemetryAutonomyBridge,
    TelemetryRecorder,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

CI = Principal("ci-bot", PrincipalKind.SERVICE)
SVC = Principal("loop-runner", PrincipalKind.SERVICE, system_id="sys-a")
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
SIBLING = Principal("agent-2", PrincipalKind.AGENT, system_id="sys-a")
OTHER = Principal("agent-9", PrincipalKind.AGENT, system_id="sys-b")
ALICE = Principal("alice", PrincipalKind.HUMAN)


class Clock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _registry() -> TriggerRegistry:
    registry = TriggerRegistry()
    registry.bind(ALICE, "loop-a", principals=[AGENT, SVC])
    registry.bind(ALICE, "loop-b", principals=[AGENT])
    registry.bind(ALICE, "loop-x", principals=[OTHER])
    return registry


def _setup(
    policy: BreakerPolicy | None = None,
    autonomy: AutonomyController | None = None,
    audit_log: AuditLog | None = None,
    registry: TriggerRegistry | None = None,
) -> tuple[TriggerCircuitBreaker, TelemetryRecorder, Clock]:
    clock = Clock(1000.0)
    store = InMemoryTelemetryStore()
    breaker = TriggerCircuitBreaker(
        policy,
        store,
        autonomy,
        registry=registry if registry is not None else _registry(),
        audit_log=audit_log,
        clock=clock,
    )
    return breaker, TelemetryRecorder(store, CI, clock=clock), clock


class TestPolicy:
    def test_defaults_are_the_documented_design_inference(self) -> None:
        policy = BreakerPolicy()
        assert (policy.max_failed_verifications, policy.max_rollbacks) == (3, 2)
        assert (policy.window_s, policy.cooldown_s) == (86400.0, None)
        assert (policy.max_skew_s, policy.cohort_suspension) == (300.0, True)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_failed_verifications": 0},
            {"max_rollbacks": True},
            {"window_s": 0},
            {"window_s": float("inf")},
            {"cooldown_s": -1},
            {"max_skew_s": 0},
            {"cohort_suspension": "yes"},
        ],
    )
    def test_invalid(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            BreakerPolicy(**kwargs)

    def test_constructor_type_checks(self) -> None:
        with pytest.raises(TypeError):
            TriggerCircuitBreaker("strict")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            TriggerCircuitBreaker(None, "store")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            TriggerCircuitBreaker(None, None, "autonomy")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            TriggerCircuitBreaker(registry=object())  # type: ignore[arg-type]


class TestRegistry:
    def test_only_a_human_binds(self) -> None:
        registry = TriggerRegistry()
        for who in (AGENT, SVC, "alice"):
            with pytest.raises(TriggerBindingRejected):
                registry.bind(who, "loop-a", principals=[AGENT])  # type: ignore[arg-type]
            with pytest.raises(TriggerBindingRejected):
                registry.unbind(who, "loop-a")  # type: ignore[arg-type]

    def test_binding_validation(self) -> None:
        registry = TriggerRegistry()
        with pytest.raises(TriggerBindingRejected):
            registry.bind(ALICE, "<script>", principals=[AGENT])
        with pytest.raises(TriggerBindingRejected):
            registry.bind(ALICE, "loop-a")
        with pytest.raises(TriggerBindingRejected):
            registry.bind(ALICE, "loop-a", principals=["agent-1"])  # type: ignore[list-item]
        with pytest.raises(ValueError):
            registry.bind(ALICE, "loop-a", system_ids=["bad id"])

    def test_lookup(self) -> None:
        registry = TriggerRegistry()
        registry.bind(ALICE, "loop-a", principals=[AGENT])
        registry.bind(ALICE, "loop-c", system_ids=["SYS-A"])
        assert registry.is_bound("loop-a", AGENT)
        assert registry.is_bound("loop-c", SIBLING)  # cohort binding, casefolded
        assert not registry.is_bound("loop-a", SIBLING)
        assert registry.triggers_for_cohort("sys-a") == ("loop-a", "loop-c")
        assert registry.system_ids_for("loop-c") == ("sys-a",)
        registry.unbind(ALICE, "loop-a")
        assert not registry.is_bound("loop-a", AGENT)


class TestTrips:
    def test_failed_verifications_trip_at_threshold_not_before(self) -> None:
        breaker, rec, _ = _setup()
        rec.record_verification_failed("loop-a", "s1")
        rec.record_verification_failed("loop-a", "s2")
        assert breaker.state("loop-a") is BreakerState.CLOSED
        rec.record_verification_failed("loop-a", "s3")
        assert breaker.state("loop-a") is BreakerState.OPEN
        status = breaker.status("loop-a")
        assert (status.failed_verifications, status.rollbacks) == (3, 0)
        assert status.tripped_at == 1000.0
        assert "failed verifications" in status.reason

    def test_rollbacks_trip_at_threshold_not_before(self) -> None:
        breaker, rec, _ = _setup()
        rec.record_rollback("loop-a", "c1")
        assert breaker.state("loop-a") is BreakerState.CLOSED
        rec.record_rollback("loop-a", "c2")
        assert breaker.state("loop-a") is BreakerState.OPEN
        assert "rollbacks" in breaker.status("loop-a").reason

    def test_thresholds_are_configurable(self) -> None:
        breaker, rec, _ = _setup(BreakerPolicy(max_failed_verifications=1, max_rollbacks=5))
        rec.record_rollback("loop-a", "c1")
        assert breaker.state("loop-a") is BreakerState.CLOSED
        rec.record_verification_failed("loop-a", "s1")
        assert breaker.state("loop-a") is BreakerState.OPEN

    def test_window_expiry_by_ingestion_time(self) -> None:
        breaker, rec, clock = _setup(BreakerPolicy(window_s=100))
        rec.record_verification_failed("loop-a", "s1")
        rec.record_verification_failed("loop-a", "s2")
        clock.now += 101
        rec.record_verification_failed("loop-a", "s3")
        assert breaker.state("loop-a") is BreakerState.CLOSED
        assert breaker.status("loop-a").failed_verifications == 1

    def test_triggers_are_independent_and_other_events_ignored(self) -> None:
        breaker, rec, _ = _setup()
        for subject in ("s1", "s2", "s3"):
            rec.record_verification_failed("loop-x", subject)
        rec.record_merge("c1", author_kind="agent", author_id="agent-1")
        assert breaker.state("loop-x") is BreakerState.OPEN
        assert breaker.state("loop-a") is BreakerState.CLOSED
        assert [s.trigger_id for s in breaker.statuses()] == ["loop-x"]
        assert breaker.status("never-seen").state is BreakerState.CLOSED

    def test_invalid_trigger_id_fails_closed(self) -> None:
        breaker, _, _ = _setup()
        assert breaker.state("<script>") is BreakerState.OPEN
        assert breaker.allow_autonomous("<script>") is False
        assert breaker.status("<script>").state is BreakerState.OPEN


class TestClocks:
    def test_m4_skewed_recorder_clock_still_trips(self) -> None:
        """M4: a recorder on another clock (monotonic vs wall) cannot hide
        failures -- events count at ingestion by the breaker's clock."""
        breaker, _, clock = _setup(BreakerPolicy(max_rollbacks=2))
        store = InMemoryTelemetryStore()
        breaker2 = TriggerCircuitBreaker(
            BreakerPolicy(max_rollbacks=2), store, registry=_registry(), clock=clock
        )
        monotonic_rec = TelemetryRecorder(store, CI, clock=lambda: 12.5)
        monotonic_rec.record_rollback("loop-a", "c1")
        monotonic_rec.record_rollback("loop-a", "c2")
        assert breaker2.state("loop-a") is BreakerState.OPEN
        assert breaker2.skewed_events == 2
        assert breaker.skewed_events == 0

    def test_l2_future_event_is_pruned_by_ingestion_time(self) -> None:
        """L2: an event dated far in the future does not stay in the window."""
        breaker, rec, clock = _setup(BreakerPolicy(max_rollbacks=2, window_s=100))
        rec.record_rollback("loop-a", "c1", at=1e12)
        clock.now += 10_000
        rec.record_rollback("loop-a", "c2")
        assert breaker.state("loop-a") is BreakerState.CLOSED
        assert breaker.status("loop-a").rollbacks == 1
        assert breaker.skewed_events == 1

    @pytest.mark.parametrize("bad", [math.nan, math.inf])
    def test_m4_non_finite_clock_reads_open(self, bad: float) -> None:
        breaker, rec, clock = _setup()
        clock.now = bad
        assert breaker.state("loop-a") is BreakerState.OPEN
        assert breaker.allow_autonomous("loop-a") is False
        rec.record_rollback("loop-a", "c1", at=0)  # ingested while the clock is bad
        clock.now = 1000.0
        status = breaker.status("loop-a")
        assert status.state is BreakerState.OPEN
        assert status.reason == "breaker clock unavailable"

    def test_m4_raising_clock_reads_open(self) -> None:
        def broken() -> float:
            raise OSError("no clock")

        breaker = TriggerCircuitBreaker(registry=_registry(), clock=broken)
        assert breaker.state("loop-a") is BreakerState.OPEN
        assert breaker.allow_autonomous("loop-a") is False
        assert breaker.status("loop-a").state is BreakerState.OPEN


class TestHalfOpen:
    def test_no_cooldown_means_no_probe(self) -> None:
        breaker, rec, clock = _setup(BreakerPolicy(max_rollbacks=1))
        rec.record_rollback("loop-a", "c1")
        clock.now += 10**9
        assert breaker.state("loop-a") is BreakerState.OPEN
        assert breaker.allow_autonomous("loop-a") is False

    def test_l1_one_probe_per_trip_then_locked_half_open(self) -> None:
        breaker, rec, clock = _setup(BreakerPolicy(max_rollbacks=1, cooldown_s=100))
        rec.record_rollback("loop-a", "c1")
        assert breaker.allow_autonomous("loop-a") is False
        clock.now += 100
        assert breaker.state("loop-a") is BreakerState.HALF_OPEN
        assert breaker.allow_autonomous("loop-a", consume=False) is True  # dry run
        assert breaker.allow_autonomous("loop-a") is True  # the one probe
        for _ in range(5):  # successful probe: HALF_OPEN, but no more probes
            clock.now += 100
            assert breaker.state("loop-a") is BreakerState.HALF_OPEN
            assert breaker.allow_autonomous("loop-a") is False
        assert breaker.status("loop-a").probes == 1
        breaker.reset(ALICE, "loop-a")
        assert breaker.state("loop-a") is BreakerState.CLOSED

    def test_failure_after_probe_locks_until_human_reset(self) -> None:
        breaker, rec, clock = _setup(BreakerPolicy(max_rollbacks=1, cooldown_s=100))
        rec.record_rollback("loop-a", "c1")
        clock.now += 100
        assert breaker.allow_autonomous("loop-a") is True
        rec.record_verification_failed("loop-a", "s1")
        clock.now += 10**6
        status = breaker.status("loop-a")
        assert status.state is BreakerState.OPEN
        assert status.reason == "failure after half-open probe"
        assert breaker.allow_autonomous("loop-a") is False
        breaker.reset(ALICE, "loop-a")
        assert breaker.state("loop-a") is BreakerState.CLOSED

    def test_failure_while_open_restarts_cooldown(self) -> None:
        breaker, rec, clock = _setup(BreakerPolicy(max_rollbacks=1, cooldown_s=100))
        rec.record_rollback("loop-a", "c1")
        clock.now += 90
        rec.record_rollback("loop-a", "c2")
        clock.now += 20
        assert breaker.state("loop-a") is BreakerState.OPEN
        clock.now += 80
        assert breaker.state("loop-a") is BreakerState.HALF_OPEN


class TestResetAndAudit:
    def test_reset_is_human_only(self, tmp_path: Path) -> None:
        log = AuditLog(backend=JSONLAuditBackend(tmp_path / "audit.jsonl"))
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1), audit_log=log)
        rec.record_rollback("loop-a", "c1")
        for who in (AGENT, CI, "alice"):
            with pytest.raises(BreakerResetRejected):
                breaker.reset(who, "loop-a")  # type: ignore[arg-type]
        assert breaker.state("loop-a") is BreakerState.OPEN
        with pytest.raises(ValueError):
            breaker.reset(ALICE, "<script>")
        breaker.reset(ALICE, "loop-a")
        assert breaker.state("loop-a") is BreakerState.CLOSED
        assert breaker.status("loop-a").rollbacks == 0
        types = [entry.type for entry in log.entries]
        assert types == ["trigger_breaker_trip", "trigger_breaker_reset"]
        assert breaker.audit_failures == 0

    def test_audit_failure_is_counted_and_trip_still_applies(self) -> None:
        class BrokenLog(AuditLog):
            def record_durable(self, entry: AuditEntry) -> str:
                raise OSError("disk full")

        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1), audit_log=BrokenLog())
        rec.record_rollback("loop-a", "c1")
        assert breaker.state("loop-a") is BreakerState.OPEN
        assert breaker.audit_failures == 1

    def test_best_effort_audit_mode(self) -> None:
        log = AuditLog()
        store = InMemoryTelemetryStore()
        breaker = TriggerCircuitBreaker(
            BreakerPolicy(max_rollbacks=1), store, audit_log=log, durable_audit=False
        )
        TelemetryRecorder(store, CI).record_rollback("loop-a", "c1")
        assert breaker.policy.max_rollbacks == 1
        assert [entry.type for entry in log.entries] == ["trigger_breaker_trip"]


class TestTripDemotes:
    def test_trip_demotes_attributed_agents_via_autonomy(self) -> None:
        # Large error budget and no bridge: only the breaker can demote.
        autonomy = AutonomyController(ErrorBudget(max_failures=100, max_rollbacks=100))
        breaker, rec, _ = _setup(autonomy=autonomy, registry=TriggerRegistry())
        rec.record_verification_failed("loop-a", "s1", agent=AGENT)
        rec.record_verification_failed("loop-a", "s2", agent=AGENT)
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED
        rec.record_verification_failed("loop-a", "s3")
        assert breaker.state("loop-a") is BreakerState.OPEN
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY
        assert autonomy.level(OTHER) is AutonomyLevel.T1_PREAUTHORIZED

    def test_h1_unattributed_trip_demotes_bound_principals_and_cohorts(self) -> None:
        autonomy = AutonomyController(
            ErrorBudget(max_failures=100, max_rollbacks=100), demote_system=False
        )
        registry = TriggerRegistry()
        registry.bind(ALICE, "loop-a", principals=[OTHER, ALICE], system_ids=["sys-a"])
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1), autonomy, registry=registry)
        rec.record_rollback("loop-a", "c1")  # no agent= attribution
        assert breaker.state("loop-a") is BreakerState.OPEN
        assert autonomy.level(OTHER) is AutonomyLevel.P0_ONLY  # bound principal
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY  # bound cohort
        assert autonomy.level(SIBLING) is AutonomyLevel.P0_ONLY
        autonomy.restore(ALICE, SIBLING)  # restoring a member lifts the cohort
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED


def _dispatcher(
    pdp: PolicyDecisionPoint,
    breaker: TriggerCircuitBreaker,
    calls: list[str],
    **kwargs: Any,
) -> GovernedToolDispatcher:
    d = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE,
            [
                WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",)),
                WriteGrant("agent-2", PrincipalKind.AGENT, ("workspace/**",)),
                WriteGrant("agent-9", PrincipalKind.AGENT, ("workspace/**",)),
                WriteGrant("loop-runner", PrincipalKind.SERVICE, ("workspace/**",)),
                WriteGrant("alice", PrincipalKind.HUMAN, ("workspace/**",)),
            ],
        ),
        tool_tiers={"read": ActionTier.T0, "write": ActionTier.T1},
        read_only_tools=frozenset({"read"}),
        breaker=breaker,
        **kwargs,
    )

    def read(path: str) -> str:
        calls.append("read:" + path)
        return "data"

    def write(path: str) -> str:
        calls.append("write:" + path)
        return "ok"

    d.register("read", read, path_params={"path"})
    d.register("write", write, path_params={"path"})
    return d


class TestDispatcherIntegration:
    def test_open_breaker_denies_agent_for_that_trigger(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1, cohort_suspension=False))
        d = _dispatcher(pdp, breaker, calls)
        d.dispatch(AGENT, "write", {"path": "workspace/a"}, trigger_id="loop-a")
        rec.record_rollback("loop-a", "c1", agent=AGENT)
        for tool in ("write", "read"):  # T0 reads too: the trigger is suspended
            with pytest.raises(ToolDenied, match="autonomous mode suspended"):
                d.dispatch(AGENT, tool, {"path": "workspace/b"}, trigger_id="loop-a")
        d.dispatch(OTHER, "write", {"path": "workspace/c"}, trigger_id="loop-x")
        d.dispatch(ALICE, "write", {"path": "workspace/d"}, trigger_id="loop-a")
        d.dispatch(ALICE, "write", {"path": "workspace/e"})
        assert calls == [
            "write:workspace/a",
            "write:workspace/c",
            "write:workspace/d",
            "write:workspace/e",
        ]
        breaker.reset(ALICE, "loop-a")
        d.dispatch(AGENT, "write", {"path": "workspace/f"}, trigger_id="loop-a")
        assert calls[-1] == "write:workspace/f"

    def test_h1_agent_cannot_switch_to_an_unbound_trigger(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1))
        d = _dispatcher(pdp, breaker, calls)
        rec.record_rollback("loop-a", "c1")  # unattributed
        for fresh in ("fresh-1", "loop-x"):
            with pytest.raises(ToolDenied, match="not bound to principal"):
                d.dispatch(AGENT, "write", {"path": "workspace/x"}, trigger_id=fresh)
        assert calls == []

    def test_h1_cohort_suspension_covers_all_bound_triggers(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1))
        d = _dispatcher(pdp, breaker, calls)
        rec.record_rollback("loop-a", "c1")
        with pytest.raises(ToolDenied, match="cohort sys-a suspended"):
            d.dispatch(AGENT, "write", {"path": "workspace/x"}, trigger_id="loop-b")
        d.dispatch(OTHER, "write", {"path": "workspace/y"}, trigger_id="loop-x")  # sys-b
        assert calls == ["write:workspace/y"]

    def test_h1_registry_required(self, pdp: PolicyDecisionPoint) -> None:
        with pytest.raises(ValueError, match="TriggerRegistry"):
            _dispatcher(pdp, TriggerCircuitBreaker(), [])

    def test_h1_trigger_bound_from_credential(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        issuer = CredentialIssuer()
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1, cohort_suspension=False))
        d = _dispatcher(pdp, breaker, calls, credential_issuer=issuer, require_credential=True)
        token = issuer.issue(AGENT, scopes=["tool:write"], trigger_id="loop-a").token
        d.dispatch(AGENT, "write", {"path": "workspace/a"}, credential=token)  # uses loop-a
        with pytest.raises(ToolDenied, match="does not match the credential session"):
            d.dispatch(
                AGENT, "write", {"path": "workspace/b"}, credential=token, trigger_id="loop-b"
            )
        rec.record_rollback("loop-a", "c1")
        with pytest.raises(ToolDenied, match="autonomous mode suspended"):
            d.dispatch(AGENT, "write", {"path": "workspace/c"}, credential=token)
        assert calls == ["write:workspace/a"]
        with pytest.raises(CredentialIssuanceRefused):
            issuer.issue(AGENT, scopes=["tool:write"], requester=AGENT, trigger_id="loop-b")
        with pytest.raises(CredentialIssuanceRefused):
            issuer.issue(AGENT, scopes=["tool:write"], trigger_id="<script>")
        plain = issuer.issue(AGENT, scopes=["tool:write"])
        assert issuer.verify(plain.token, required_scope="tool:write").trigger_id is None

    def test_m1_service_principals_are_governed(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1, cohort_suspension=False))
        d = _dispatcher(pdp, breaker, calls)
        d.dispatch(SVC, "read", {"path": "workspace/x"}, trigger_id="loop-a")
        with pytest.raises(ToolDenied, match="must name its trigger_id"):
            d.dispatch(SVC, "read", {"path": "workspace/x"})
        rec.record_rollback("loop-a", "c1")
        with pytest.raises(ToolDenied, match="autonomous mode suspended"):
            d.dispatch(SVC, "read", {"path": "workspace/x"}, trigger_id="loop-a")
        assert calls == ["read:workspace/x"]

    def test_agent_must_name_a_valid_trigger(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        breaker, _, _ = _setup()
        d = _dispatcher(pdp, breaker, calls)
        with pytest.raises(ToolDenied, match="must name its trigger_id"):
            d.dispatch(AGENT, "read", {"path": "workspace/a"})
        with pytest.raises(ToolDenied, match="invalid trigger_id"):
            d.dispatch(AGENT, "read", {"path": "workspace/a"}, trigger_id="<script>")
        with pytest.raises(ToolDenied, match="must name its trigger_id"):
            d.authorize_without_consuming(AGENT, "read", {"path": "workspace/a"})
        assert calls == []

    def test_l1_dry_run_does_not_burn_the_probe(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        breaker, rec, clock = _setup(
            BreakerPolicy(max_rollbacks=1, cooldown_s=10, cohort_suspension=False)
        )
        d = _dispatcher(pdp, breaker, calls)
        rec.record_rollback("loop-a", "c1")
        clock.now += 11
        for _ in range(3):
            d.authorize_without_consuming(
                AGENT, "read", {"path": "workspace/x"}, trigger_id="loop-a"
            )
        assert breaker.state("loop-a") is BreakerState.HALF_OPEN
        d.dispatch(AGENT, "write", {"path": "workspace/p0"}, trigger_id="loop-a")  # the probe
        for i in range(3):  # no failure, still no second probe (L1)
            clock.now += 11
            with pytest.raises(ToolDenied):
                d.dispatch(AGENT, "write", {"path": f"workspace/p1{i}"}, trigger_id="loop-a")
        rec.record_rollback("loop-a", "c2")  # probe failed -> locked
        for _ in range(3):
            clock.now += 11
            with pytest.raises(ToolDenied):
                d.dispatch(AGENT, "write", {"path": "workspace/p2"}, trigger_id="loop-a")
        assert calls == ["write:workspace/p0"]
        assert breaker.status("loop-a").probes == 1

    def test_l2_probing_trigger_exempt_from_its_own_cohort_check(
        self, pdp: PolicyDecisionPoint
    ) -> None:
        calls: list[str] = []
        breaker, rec, clock = _setup(BreakerPolicy(max_rollbacks=1, cooldown_s=10))
        d = _dispatcher(pdp, breaker, calls)
        rec.record_rollback("loop-a", "c1")
        clock.now += 11
        with pytest.raises(ToolDenied, match="cohort sys-a suspended"):  # other trigger
            d.dispatch(AGENT, "write", {"path": "workspace/b"}, trigger_id="loop-b")
        d.dispatch(AGENT, "write", {"path": "workspace/a"}, trigger_id="loop-a")  # the probe
        with pytest.raises(ToolDenied, match="cohort sys-a suspended"):
            d.dispatch(AGENT, "write", {"path": "workspace/b"}, trigger_id="loop-b")
        assert calls == ["write:workspace/a"]

    @pytest.mark.parametrize("presented", [None, "sys-zzz"])
    def test_m1_changing_system_id_does_not_escape_cohort(
        self, pdp: PolicyDecisionPoint, presented: str | None
    ) -> None:
        calls: list[str] = []
        registry = TriggerRegistry()
        registry.bind(ALICE, "loop-a", principals=[AGENT])
        registry.bind(ALICE, "loop-b", principals=[AGENT])
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1), registry=registry)
        d = _dispatcher(pdp, breaker, calls)
        rec.record_rollback("loop-a", "c1")
        alias = Principal("agent-1", PrincipalKind.AGENT, system_id=presented)
        with pytest.raises(ToolDenied, match="not bound to principal"):
            d.dispatch(alias, "write", {"path": "workspace/x"}, trigger_id="loop-b")
        with pytest.raises(ToolDenied, match="cohort sys-a suspended"):
            d.dispatch(AGENT, "write", {"path": "workspace/x"}, trigger_id="loop-b")
        assert calls == []

    def test_m1_conflicting_pin_refused(self) -> None:
        registry = TriggerRegistry()
        registry.bind(ALICE, "loop-a", principals=[AGENT])
        with pytest.raises(TriggerBindingRejected, match="already bound"):
            registry.bind(ALICE, "loop-b", principals=[Principal("agent-1", PrincipalKind.AGENT)])
        assert registry.cohorts_of(Principal("agent-1", PrincipalKind.AGENT)) == ("sys-a",)
        nosys = Principal("agent-7", PrincipalKind.AGENT)
        registry.bind(ALICE, "loop-n", principals=[nosys])
        assert registry.is_bound("loop-n", nosys)
        assert not registry.is_bound(
            "loop-n", Principal("agent-7", PrincipalKind.AGENT, system_id="sys-a")
        )
        assert registry.cohorts_of(nosys) == ()

    def test_m1_dropping_system_id_does_not_escape_demotion(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        autonomy = AutonomyController(ErrorBudget(max_failures=99, max_rollbacks=99))
        registry = TriggerRegistry()
        registry.bind(ALICE, "loop-a", system_ids=["sys-a"])
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1), autonomy, registry=registry)
        d = GovernedToolDispatcher(
            pdp,
            permissions=RepositoryPermissions(
                DEFAULT_IMMUTABLE_CORE,
                [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))],
            ),
            tool_tiers={"write": ActionTier.T1},
            autonomy=autonomy,
        )

        def write(path: str) -> str:
            calls.append(path)
            return "ok"

        d.register("write", write, path_params={"path"})
        d.dispatch(AGENT, "write", {"path": "workspace/a"})  # identity sys-a recorded
        rec.record_rollback("loop-a", "c1")  # unattributed -> cohort sys-a demoted
        for alias in (
            Principal("agent-1", PrincipalKind.AGENT),
            Principal("agent-1", PrincipalKind.AGENT, system_id="sys-zzz"),
        ):
            assert autonomy.level(alias) is AutonomyLevel.P0_ONLY
            with pytest.raises(ToolDenied, match="P0_ONLY"):
                d.dispatch(alias, "write", {"path": "workspace/b"})
        assert calls == ["workspace/a"]

    def test_m1_dispatcher_enforces_the_breakers_demotions(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        autonomy = AutonomyController(ErrorBudget(max_failures=99, max_rollbacks=99))
        registry = TriggerRegistry()
        registry.bind(ALICE, "loop-a", system_ids=["sys-a"])
        nosys = Principal("agent-1", PrincipalKind.AGENT)
        registry.bind(ALICE, "loop-b", principals=[nosys])
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1), autonomy, registry=registry)
        d = _dispatcher(pdp, breaker, calls)  # no autonomy= of its own
        # agent-1 is pinned to system None here, so as sys-a it is unbound...
        with pytest.raises(ToolDenied, match="not bound to principal"):
            d.dispatch(AGENT, "write", {"path": "workspace/a"}, trigger_id="loop-a")
        # ...but the controller has seen it as sys-a (e.g. under another harness).
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED
        d.dispatch(nosys, "write", {"path": "workspace/a"}, trigger_id="loop-b")
        rec.record_rollback("loop-a", "c1")  # unattributed -> cohort sys-a demoted
        with pytest.raises(ToolDenied, match="P0_ONLY"):
            d.dispatch(nosys, "write", {"path": "workspace/b"}, trigger_id="loop-b")
        assert calls == ["write:workspace/a"]

    def test_m1_credential_signs_system_id(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        issuer = CredentialIssuer()
        breaker, _, _ = _setup(BreakerPolicy(cohort_suspension=False))
        d = _dispatcher(pdp, breaker, calls, credential_issuer=issuer, require_credential=True)
        credential = issuer.issue(AGENT, scopes=["tool:write"], trigger_id="loop-a")
        assert credential.system_id == "sys-a"
        for presented in (None, "sys-zzz"):
            alias = Principal("agent-1", PrincipalKind.AGENT, system_id=presented)
            with pytest.raises(ToolDenied, match="another system_id"):
                d.dispatch(alias, "write", {"path": "workspace/x"}, credential=credential.token)
        d.dispatch(AGENT, "write", {"path": "workspace/x"}, credential=credential.token)
        assert calls == ["write:workspace/x"]
        unscoped = Principal("agent-7", PrincipalKind.AGENT)
        token = issuer.issue(unscoped, scopes=["tool:write"]).token
        assert (
            issuer.verify(token, required_scope="tool:write", principal=unscoped).system_id is None
        )

    async def test_async_dispatch_honours_breaker(self, pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        breaker, rec, _ = _setup(BreakerPolicy(max_rollbacks=1))
        d = _dispatcher(pdp, breaker, calls)
        await d.adispatch(AGENT, "read", {"path": "workspace/a"}, trigger_id="loop-a")
        rec.record_rollback("loop-a", "c1")
        with pytest.raises(ToolDenied):
            await d.adispatch(AGENT, "read", {"path": "workspace/a"}, trigger_id="loop-a")
        assert calls == ["read:workspace/a"]

    def test_breaker_type_checked(self, pdp: PolicyDecisionPoint) -> None:
        with pytest.raises(TypeError):
            GovernedToolDispatcher(
                pdp,
                permissions=RepositoryPermissions(DEFAULT_IMMUTABLE_CORE, []),
                tool_tiers={},
                breaker=object(),  # type: ignore[arg-type]
            )


class TestEndToEnd:
    def test_bridge_and_breaker_together(self, pdp: PolicyDecisionPoint) -> None:
        """Error budget (bridge) and breaker both watch one store."""
        clock = Clock(1000.0)
        store = InMemoryTelemetryStore()
        autonomy = AutonomyController(ErrorBudget(max_failures=3), clock=clock)
        TelemetryAutonomyBridge(autonomy).attach(store)
        breaker = TriggerCircuitBreaker(
            BreakerPolicy(), store, autonomy, registry=_registry(), clock=clock
        )
        rec = TelemetryRecorder(store, CI, clock=clock)
        calls: list[str] = []
        d = _dispatcher(pdp, breaker, calls)
        for subject in ("s1", "s2", "s3"):
            rec.record_verification_failed("loop-a", subject, agent=AGENT)
        assert breaker.state("loop-a") is BreakerState.OPEN
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY
        with pytest.raises(ToolDenied):
            d.dispatch(AGENT, "read", {"path": "workspace/a"}, trigger_id="loop-a")
        assert calls == []


def test_unscoped_principal_cannot_switch_to_sibling_trigger(pdp: PolicyDecisionPoint) -> None:
    agent = Principal("agent-1", PrincipalKind.AGENT)
    unrelated = Principal("agent-9", PrincipalKind.AGENT)
    registry = TriggerRegistry()
    registry.bind(ALICE, "loop-a", principals=[agent])
    registry.bind(ALICE, "loop-b", principals=[agent])
    registry.bind(ALICE, "loop-x", principals=[unrelated])
    breaker, rec, clock = _setup(BreakerPolicy(max_rollbacks=1, cooldown_s=10), registry=registry)
    calls: list[str] = []
    dispatcher = _dispatcher(pdp, breaker, calls)
    rec.record_rollback("loop-a", "trip")
    with pytest.raises(ToolDenied, match="principal.*suspended"):
        dispatcher.dispatch(agent, "write", {"path": "workspace/blocked"}, trigger_id="loop-b")
    dispatcher.dispatch(unrelated, "write", {"path": "workspace/unrelated"}, trigger_id="loop-x")
    clock.now += 11
    dispatcher.dispatch(agent, "write", {"path": "workspace/probe"}, trigger_id="loop-a")
    assert breaker.status("loop-a").probes == 1
    with pytest.raises(ToolDenied, match="principal.*suspended"):
        dispatcher.dispatch(agent, "write", {"path": "workspace/blocked"}, trigger_id="loop-b")
    breaker.reset(ALICE, "loop-a")
    dispatcher.dispatch(agent, "write", {"path": "workspace/resumed"}, trigger_id="loop-b")
    assert calls == [
        "write:workspace/unrelated",
        "write:workspace/probe",
        "write:workspace/resumed",
    ]


def test_unscoped_cohort_suspension_can_be_disabled(pdp: PolicyDecisionPoint) -> None:
    agent = Principal("agent-1", PrincipalKind.AGENT)
    registry = TriggerRegistry()
    for trigger in ("loop-a", "loop-b"):
        registry.bind(ALICE, trigger, principals=[agent])
    breaker, rec, _ = _setup(
        BreakerPolicy(max_rollbacks=1, cohort_suspension=False), registry=registry
    )
    calls: list[str] = []
    dispatcher = _dispatcher(pdp, breaker, calls)
    rec.record_rollback("loop-a", "trip")
    dispatcher.dispatch(agent, "write", {"path": "workspace/allowed"}, trigger_id="loop-b")
    assert calls == ["write:workspace/allowed"]
