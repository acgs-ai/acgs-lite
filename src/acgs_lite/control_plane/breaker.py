"""Per-trigger circuit breaker that suspends a trigger's autonomous mode.

A *trigger* is an autonomous loop, runbook or schedule that initiates agent
actions. A HUMAN admin binds each trigger to the principals and/or system
cohorts allowed to act under it (:class:`TriggerRegistry`, harness-owned;
agents cannot bind). The breaker watches the telemetry store for
VERIFICATION_FAILED and ROLLBACK events of each trigger. When either count
inside the sliding window reaches its threshold the breaker trips: the
trigger goes OPEN, the attributed agent -- and, through the registry, every
principal and cohort bound to the trigger -- is demoted through the
:class:`~.autonomy.AutonomyController`, and an audit entry is written.

:class:`~.dispatcher.GovernedToolDispatcher` with a breaker denies every
non-HUMAN dispatch that does not name a trigger bound to that principal,
whose trigger is OPEN, or (``cohort_suspension=True``) whose system cohort
has *any* bound trigger that is not CLOSED -- so switching to another
trigger does not evade a trip.

DESIGN INFERENCE: the whole breaker is a design inference, not a measured
control. STOP showed a prompt warning did not stop agents disabling their
sandbox, and in the Replit incident an agent deleted a production database
during a natural-language freeze -- so the response to repeated failure is
enforced by the harness, not requested of the model. The thresholds, window,
skew bound, cohort suspension and half-open rule have no primary evidence
behind them and are configurable (:class:`BreakerPolicy`).

Only a HUMAN :meth:`TriggerCircuitBreaker.reset` ever closes a breaker. With
``cooldown_s`` set, an OPEN breaker reads HALF_OPEN after the cooldown and
admits one probe per cooldown; it stays HALF_OPEN/OPEN until a human
reset, and a failure after a probe locks it OPEN (no more probes).

Clocks: events are counted at *ingestion* time by this breaker's own clock,
not by their ``at`` (a recorder on another clock cannot hide failures). An
event whose ``at`` deviates from now by more than ``max_skew_s`` is logged
and counted in :attr:`TriggerCircuitBreaker.skewed_events` but still counted
(dropping it would let a skewed clock disable the breaker). A clock that
raises or returns a non-finite value reads every trigger OPEN.
"""

from __future__ import annotations

import collections
import contextlib
import logging
import math
import re
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from acgs_lite._compat import StrEnum
from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.control_plane.autonomy import AutonomyController
from acgs_lite.control_plane.principal import Principal, PrincipalKind

if TYPE_CHECKING:
    from acgs_lite.control_plane.identity import AdminAttestor
from acgs_lite.control_plane.telemetry import (
    OversightEvent,
    Rollback,
    TelemetryStore,
    VerificationFailed,
)

__all__ = [
    "BreakerPolicy",
    "BreakerResetRejected",
    "BreakerState",
    "BreakerStatus",
    "TriggerBindingRejected",
    "TriggerCircuitBreaker",
    "TriggerRegistry",
    "valid_trigger_id",
]

logger = logging.getLogger(__name__)

_TRIGGER_ID = re.compile(r"[A-Za-z0-9._:/@+-]{1,256}")


def valid_trigger_id(value: object) -> bool:
    return isinstance(value, str) and _TRIGGER_ID.fullmatch(value) is not None


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class BreakerResetRejected(PermissionError):
    """Only a HUMAN may reset a breaker."""


class TriggerBindingRejected(PermissionError):
    """Only a HUMAN admin may bind triggers (or the binding is malformed)."""


def _require_human(admin: object) -> None:
    if not isinstance(admin, Principal) or admin.kind is not PrincipalKind.HUMAN:
        raise TriggerBindingRejected("only a HUMAN admin may bind triggers")


class TriggerRegistry:
    """Harness-side map trigger_id -> principals / system cohorts allowed to
    act under it. The agent process must never hold a reference to it."""

    # TODO(control-plane-gap): the bindings (and system_id pins, which
    # outlive unbind) live in memory. Phase 6a: with *admin_attestor* every
    # bind/unbind must carry a verified HUMAN admin ``admin_credential=``.

    def __init__(self, *, admin_attestor: AdminAttestor | None = None) -> None:
        from acgs_lite.control_plane.identity import checked_attestor

        self._attestor = checked_attestor(admin_attestor)
        self._lock = threading.Lock()
        self._principals: dict[str, dict[str, Principal]] = {}
        self._systems: dict[str, set[str]] = {}
        # canonical id -> the system_id it was first bound with (None
        # included). A principal presenting any other system_id is unbound
        # everywhere, so it cannot shed its cohort.
        self._pins: dict[str, str | None] = {}

    def bind(
        self,
        admin: Principal,
        trigger_id: str,
        *,
        principals: Iterable[Principal] = (),
        system_ids: Iterable[str] = (),
        admin_credential: str | None = None,
    ) -> None:
        _require_human(admin)
        self._attest(admin, admin_credential)
        if not valid_trigger_id(trigger_id):
            raise TriggerBindingRejected("invalid trigger_id")
        members = tuple(principals)
        if not all(isinstance(p, Principal) for p in members):
            raise TriggerBindingRejected("principals must be Principal objects")
        systems = []
        for system_id in system_ids:
            # Same canonical charset/casefolding as Principal.system_id.
            probe = Principal("cohort-probe", PrincipalKind.AGENT, system_id=system_id)
            if probe.system_id is None:  # pragma: no cover - system_id given
                raise TriggerBindingRejected("invalid system_id")
            systems.append(probe.system_id)
        if not members and not systems:
            raise TriggerBindingRejected("bind at least one principal or system_id")
        with self._lock:
            for member in members:
                pinned = self._pins.get(member.canonical_id, member.system_id)
                if pinned != member.system_id:
                    raise TriggerBindingRejected(
                        f"principal {member.id} is already bound with system_id {pinned!r}"
                    )
            bound = self._principals.setdefault(trigger_id, {})
            for member in members:
                self._pins.setdefault(member.canonical_id, member.system_id)
                bound[member.canonical_id] = member
            self._systems.setdefault(trigger_id, set()).update(systems)

    def _attest(self, admin: Principal, credential: str | None) -> None:
        if self._attestor is not None:
            self._attestor.require(admin, credential, error=TriggerBindingRejected)

    def unbind(
        self, admin: Principal, trigger_id: str, *, admin_credential: str | None = None
    ) -> None:
        _require_human(admin)
        self._attest(admin, admin_credential)
        with self._lock:
            self._principals.pop(trigger_id, None)
            self._systems.pop(trigger_id, None)

    def is_bound(self, trigger_id: str, principal: Principal) -> bool:
        """True if *principal* -- with exactly its pinned system_id -- is
        bound to *trigger_id* directly or through its cohort."""
        with self._lock:
            cid = principal.canonical_id
            if cid in self._pins and self._pins[cid] != principal.system_id:
                return False
            if cid in self._principals.get(trigger_id, {}):
                return True
            return principal.system_id is not None and principal.system_id in self._systems.get(
                trigger_id, set()
            )

    def cohorts_of(self, principal: Principal) -> tuple[str, ...]:
        """The bound (pinned) system cohort of *principal*, else its own."""
        with self._lock:
            system_id = self._pins.get(principal.canonical_id, principal.system_id)
        return () if system_id is None else (system_id,)

    def principals_for(self, trigger_id: str) -> tuple[Principal, ...]:
        with self._lock:
            return tuple(self._principals.get(trigger_id, {}).values())

    def system_ids_for(self, trigger_id: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._systems.get(trigger_id, set())))

    def triggers_for_cohort(self, system_id: str) -> tuple[str, ...]:
        """Triggers bound to *system_id* directly or via a member principal."""
        with self._lock:
            ids = {t for t, systems in self._systems.items() if system_id in systems}
            ids.update(
                t
                for t, members in self._principals.items()
                if any(m.system_id == system_id for m in members.values())
            )
        return tuple(sorted(ids))


def _positive_int(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be an int >= 1")


def _positive_number(value: object, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{label} must be a positive finite number")


@dataclass(frozen=True)
class BreakerPolicy:
    """Trip thresholds per trigger.

    TODO(control-plane-gap): thresholds are design inference; no primary
    evidence for N (3 failed verifications / 2 rollbacks per 24 h), the
    300 s skew bound, cohort-wide suspension or the default of no half-open
    cooldown. Configure per deployment.
    """

    max_failed_verifications: int = 3
    max_rollbacks: int = 2
    window_s: float = 86400.0
    cooldown_s: float | None = None
    max_skew_s: float = 300.0
    cohort_suspension: bool = True

    def __post_init__(self) -> None:
        _positive_int(self.max_failed_verifications, "max_failed_verifications")
        _positive_int(self.max_rollbacks, "max_rollbacks")
        _positive_number(self.window_s, "window_s")
        _positive_number(self.max_skew_s, "max_skew_s")
        if self.cooldown_s is not None:
            _positive_number(self.cooldown_s, "cooldown_s")
        if not isinstance(self.cohort_suspension, bool):
            raise ValueError("cohort_suspension must be a bool")


@dataclass(frozen=True)
class BreakerStatus:
    trigger_id: str
    state: BreakerState
    failed_verifications: int
    rollbacks: int
    tripped_at: float | None
    reason: str
    probes: int = 0


class _Trigger:
    def __init__(self) -> None:
        self.failures: collections.deque[float] = collections.deque()
        self.rollbacks: collections.deque[float] = collections.deque()
        self.agents: dict[str, Principal] = {}
        self.open = False
        self.tripped_at: float | None = None
        self.last_probe_at: float | None = None
        self.probes = 0
        self.locked = False
        self.reason = ""


class _ClockUnavailable(Exception):
    pass


class TriggerCircuitBreaker:
    """Suspend a trigger's autonomous mode after repeated failures.

    TODO(control-plane-gap): breaker state lives in memory and is not
    rebuilt from the telemetry store on restart (like
    :class:`~.autonomy.AutonomyController` demotions).
    """

    def __init__(
        self,
        policy: BreakerPolicy | None = None,
        telemetry_store: TelemetryStore | None = None,
        autonomy: AutonomyController | None = None,
        *,
        registry: TriggerRegistry | None = None,
        audit_log: AuditLog | None = None,
        durable_audit: bool = True,
        clock: Callable[[], float] = time.time,
        admin_attestor: AdminAttestor | None = None,
    ) -> None:
        from acgs_lite.control_plane.identity import checked_attestor

        self._attestor = checked_attestor(admin_attestor)
        policy = BreakerPolicy() if policy is None else policy
        if not isinstance(policy, BreakerPolicy):
            raise TypeError("policy must be a BreakerPolicy")
        if autonomy is not None and not isinstance(autonomy, AutonomyController):
            raise TypeError("autonomy must be an AutonomyController")
        if registry is not None and type(registry) is not TriggerRegistry:
            raise TypeError("registry must be a TriggerRegistry")
        self._policy = policy
        self._autonomy = autonomy
        self._registry = registry
        self._audit_log = audit_log
        self._durable_audit = durable_audit
        self._clock = clock
        self._lock = threading.Lock()
        self._triggers: dict[str, _Trigger] = {}
        self.audit_failures = 0
        self.skewed_events = 0
        if telemetry_store is not None:
            if not isinstance(telemetry_store, TelemetryStore):
                raise TypeError("telemetry_store must implement TelemetryStore")
            telemetry_store.subscribe(self.observe)

    @property
    def policy(self) -> BreakerPolicy:
        return self._policy

    @property
    def registry(self) -> TriggerRegistry | None:
        return self._registry

    @property
    def autonomy(self) -> AutonomyController | None:
        return self._autonomy

    def _now(self) -> float:
        try:
            now = float(self._clock())
        except Exception as exc:
            raise _ClockUnavailable(type(exc).__name__) from exc
        if not math.isfinite(now):
            raise _ClockUnavailable("non-finite clock")
        return now

    def _prune(self, trigger: _Trigger, now: float) -> None:
        # Full scan: a wall clock may step backwards, so deques need not be sorted.
        horizon = now - self._policy.window_s
        trigger.failures = collections.deque(t for t in trigger.failures if t > horizon)
        trigger.rollbacks = collections.deque(t for t in trigger.rollbacks if t > horizon)

    def observe(self, event: OversightEvent) -> None:
        """Store listener: count trigger failures at ingestion and trip."""
        if not isinstance(event, (VerificationFailed, Rollback)):
            return
        try:
            now = self._now()
            clock_ok = True
        except _ClockUnavailable:
            now, clock_ok = math.nan, False
        skewed = clock_ok and abs(event.at - now) > self._policy.max_skew_s
        if skewed:
            logger.warning(
                "breaker event %s at %.3f deviates from now by more than %ss; counted at ingestion",
                event.event_id,
                event.at,
                self._policy.max_skew_s,
            )
        tripped = False
        with self._lock:
            if skewed:
                self.skewed_events += 1
            trigger = self._triggers.setdefault(event.trigger_id, _Trigger())
            agent = event.agent()
            if agent is not None:
                trigger.agents[agent.canonical_id] = agent
            reason = ""
            if not clock_ok:
                reason = "breaker clock unavailable"
            else:
                target = trigger.rollbacks if isinstance(event, Rollback) else trigger.failures
                target.append(now)
                self._prune(trigger, now)
                if len(trigger.failures) >= self._policy.max_failed_verifications:
                    reason = f"{len(trigger.failures)} failed verifications within window"
                elif len(trigger.rollbacks) >= self._policy.max_rollbacks:
                    reason = f"{len(trigger.rollbacks)} rollbacks within window"
            if trigger.open:
                if trigger.probes > 0 and not trigger.locked:
                    # A failure after a probe: no more probes until a human reset.
                    trigger.locked = True
                    trigger.reason = "failure after half-open probe"
                    tripped = True
                if clock_ok:
                    # Any failure while open restarts the cooldown.
                    trigger.tripped_at = now
                    trigger.last_probe_at = None
            elif reason:
                trigger.open = True
                trigger.tripped_at = now if clock_ok else None
                trigger.reason = reason
                tripped = True
            agents = tuple(trigger.agents.values())
            final_reason = trigger.reason
        if tripped:
            self._on_trip(event.trigger_id, final_reason, agents)

    def _probe_available(self, trigger: _Trigger, now: float) -> bool:
        cooldown = self._policy.cooldown_s
        if cooldown is None or trigger.locked or trigger.tripped_at is None:
            return False
        if trigger.probes >= 1:
            return False  # one probe per trip; then only a human reset
        last = trigger.last_probe_at if trigger.last_probe_at is not None else trigger.tripped_at
        return now - last >= cooldown

    def _on_trip(self, trigger_id: str, reason: str, agents: tuple[Principal, ...]) -> None:
        autonomy = self._autonomy
        if autonomy is not None:
            note = f"trigger {trigger_id} circuit breaker: {reason}"
            targets = {agent.canonical_id: agent for agent in agents}
            systems: tuple[str, ...] = ()
            registry = self._registry
            if registry is not None:
                for member in registry.principals_for(trigger_id):
                    if member.kind is not PrincipalKind.HUMAN:
                        targets.setdefault(member.canonical_id, member)
                systems = registry.system_ids_for(trigger_id)
            for agent in targets.values():
                try:
                    autonomy.demote(agent, note)
                except Exception as exc:  # pragma: no cover - demote is defensive
                    logger.error("breaker demotion failed: %s", type(exc).__name__)
            for system_id in systems:
                try:
                    autonomy.demote_cohort(system_id, note)
                except Exception as exc:  # pragma: no cover - demote is defensive
                    logger.error("breaker cohort demotion failed: %s", type(exc).__name__)
        self._audit("trigger_breaker_trip", trigger_id, reason, valid=False)

    def state(self, trigger_id: str) -> BreakerState:
        """Current state; an invalid id or unavailable clock reads OPEN."""
        if not valid_trigger_id(trigger_id):
            return BreakerState.OPEN
        try:
            now = self._now()
        except _ClockUnavailable:
            return BreakerState.OPEN
        with self._lock:
            trigger = self._triggers.get(trigger_id)
            if trigger is None or not trigger.open:
                return BreakerState.CLOSED
            if self._probe_available(trigger, now) or (trigger.probes > 0 and not trigger.locked):
                # After its one probe the breaker stays HALF_OPEN (no further
                # probes) until a human reset; a failure locks it OPEN.
                return BreakerState.HALF_OPEN
            return BreakerState.OPEN

    def allow_autonomous(self, trigger_id: str, *, consume: bool = True) -> bool:
        """True if a non-human may act under *trigger_id* now. A tripped
        breaker admits one probe per trip once the cooldown has elapsed;
        ``consume=False`` (dry runs) answers without spending it."""
        if not valid_trigger_id(trigger_id):
            return False
        try:
            now = self._now()
        except _ClockUnavailable:
            return False
        with self._lock:
            trigger = self._triggers.get(trigger_id)
            if trigger is None or not trigger.open:
                return True
            if not self._probe_available(trigger, now):
                return False
            if consume:
                trigger.last_probe_at = now
                trigger.probes += 1
            return True

    def cohort_suspended(self, system_id: str | None, *, probing: str | None = None) -> bool:
        """True if ``cohort_suspension`` is on and any trigger bound to
        *system_id* is not CLOSED. The HALF_OPEN state of *probing* (the
        trigger being probed) is ignored; every other trigger still counts."""
        registry = self._registry
        if not self._policy.cohort_suspension or system_id is None or registry is None:
            return False
        for trigger_id in registry.triggers_for_cohort(system_id):
            state = self.state(trigger_id)
            if state is BreakerState.CLOSED:
                continue
            if trigger_id == probing and state is BreakerState.HALF_OPEN:
                continue
            return True
        return False

    def reset(
        self, admin: Principal, trigger_id: str, *, admin_credential: str | None = None
    ) -> None:
        """Close the breaker and clear its windows. HUMAN only.

        It does not restore demoted agents; use
        :meth:`AutonomyController.restore`.
        """
        if not isinstance(admin, Principal) or admin.kind is not PrincipalKind.HUMAN:
            raise BreakerResetRejected("only a HUMAN may reset a trigger circuit breaker")
        if self._attestor is not None:
            self._attestor.require(admin, admin_credential, error=BreakerResetRejected)
        if not valid_trigger_id(trigger_id):
            raise ValueError("invalid trigger_id")
        with self._lock:
            self._triggers.pop(trigger_id, None)
        self._audit("trigger_breaker_reset", trigger_id, f"reset by {admin.id}", valid=True)

    def status(self, trigger_id: str) -> BreakerStatus:
        state = self.state(trigger_id)
        with self._lock:
            trigger = self._triggers.get(trigger_id) if valid_trigger_id(trigger_id) else None
            if trigger is None:
                return BreakerStatus(trigger_id, state, 0, 0, None, "")
            with contextlib.suppress(_ClockUnavailable):
                self._prune(trigger, self._now())
            return BreakerStatus(
                trigger_id,
                state,
                len(trigger.failures),
                len(trigger.rollbacks),
                trigger.tripped_at,
                trigger.reason,
                trigger.probes,
            )

    def statuses(self) -> tuple[BreakerStatus, ...]:
        with self._lock:
            ids = sorted(self._triggers)
        return tuple(self.status(trigger_id) for trigger_id in ids)

    def _audit(self, event: str, trigger_id: str, reason: str, *, valid: bool) -> None:
        log = self._audit_log
        if log is None:
            return
        entry = AuditEntry(
            id=f"{event}-{uuid.uuid4().hex}",
            type=event,
            agent_id=trigger_id,
            action=f"breaker.{event.rsplit('_', 1)[-1]}",
            valid=valid,
            violations=[],
            metadata={"trigger_id": trigger_id, "reason": reason},
        )
        try:
            if self._durable_audit:
                log.record_durable(entry)
            else:
                log.record(entry)
        except Exception as exc:
            # The trip itself already applies (fail closed).
            logger.error("breaker audit failed: %s", type(exc).__name__)
            with self._lock:
                self.audit_failures += 1
