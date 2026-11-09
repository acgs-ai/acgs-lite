"""Autonomy levels with automatic, sticky demotion.

An agent starts at :attr:`AutonomyLevel.T1_PREAUTHORIZED` (it may run T0 and
T1 tools on its own; T2/T3 still need a signed-approval quorum). The
:class:`AutonomyController` demotes it to :attr:`AutonomyLevel.P0_ONLY`
(read-only T0 tools only) as soon as its error budget (failed verifications,
policy denials, rollbacks inside a sliding window) or any resource budget is
exhausted, and to :attr:`AutonomyLevel.SUSPENDED` while the kill switch is
engaged. Demotion is sticky: only a HUMAN :meth:`AutonomyController.restore`
lifts it. Every demotion is written to the audit log (``record_durable`` by
default) (and, if a PDP is supplied, receipted as a deny).

Evidence: STOP -- a prompt warning did not stop agents disabling their
sandbox, so the response to misbehaviour is enforced by the harness, not
requested of the model; DGM -- the agent faked its own success logs, so the
failure signal comes from the harness (verifications, PDP denials), not from
the agent's self-report.
"""

from __future__ import annotations

import collections
import logging
import math
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from acgs_lite._compat import StrEnum
from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.control_plane.budgets import BudgetLedger
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.tiers import ActionTier

if TYPE_CHECKING:
    from acgs_lite.control_plane.killswitch import KillSwitch
    from acgs_lite.control_plane.pdp import PolicyDecisionPoint

__all__ = [
    "AutonomyController",
    "AutonomyLevel",
    "AutonomyRestoreRejected",
    "ErrorBudget",
    "FailureKind",
    "max_tier_for",
]

logger = logging.getLogger(__name__)


class AutonomyLevel(StrEnum):
    T1_PREAUTHORIZED = "t1_preauthorized"
    P0_ONLY = "p0_only"
    SUSPENDED = "suspended"


class FailureKind(StrEnum):
    VERIFICATION_FAILED = "verification_failed"
    POLICY_DENIAL = "policy_denial"
    ROLLBACK = "rollback"


class AutonomyRestoreRejected(PermissionError):
    """Only a HUMAN may restore autonomy."""


def max_tier_for(level: AutonomyLevel) -> ActionTier | None:
    """Highest tier a principal at *level* may request (``None``: nothing)."""
    if level is AutonomyLevel.T1_PREAUTHORIZED:
        return ActionTier.T3
    if level is AutonomyLevel.P0_ONLY:
        return ActionTier.T0
    return None


@dataclass(frozen=True)
class ErrorBudget:
    """Sliding-window failure budget.

    TODO(control-plane-gap): window, thresholds and which failure kinds count
    are design inference; configure per deployment.
    """

    window_s: float = 3600.0
    max_failures: int = 5
    max_rollbacks: int = 2
    counted_kinds: frozenset[FailureKind] = frozenset(
        {FailureKind.VERIFICATION_FAILED, FailureKind.POLICY_DENIAL}
    )

    def __post_init__(self) -> None:
        if (
            isinstance(self.window_s, bool)
            or not isinstance(self.window_s, (int, float))
            or not math.isfinite(self.window_s)
            or self.window_s <= 0
        ):
            raise ValueError("window_s must be a positive finite number")
        for name in ("max_failures", "max_rollbacks"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be an int >= 1")
        object.__setattr__(
            self, "counted_kinds", frozenset(FailureKind(k) for k in self.counted_kinds)
        )


class AutonomyController:
    """Track failures per principal and compute its :class:`AutonomyLevel`.

    Only non-human principals are governed by autonomy levels; humans always
    read as ``T1_PREAUTHORIZED`` (their actions are gated by the PDP and the
    approval quorum instead).
    """

    def __init__(
        self,
        error_budget: ErrorBudget,
        budgets: BudgetLedger | None = None,
        *,
        kill_switch: KillSwitch | None = None,
        audit_log: AuditLog | None = None,
        durable_audit: bool = True,
        pdp: PolicyDecisionPoint | None = None,
        clock: Callable[[], float] = time.monotonic,
        demote_system: bool = True,
        demote_unscoped_agents: bool = False,
    ) -> None:
        if not isinstance(error_budget, ErrorBudget):
            raise TypeError("error_budget must be an ErrorBudget")
        if budgets is not None and not isinstance(budgets, BudgetLedger):
            raise TypeError("budgets must be a BudgetLedger")
        self._error_budget = error_budget
        self._budgets = budgets
        self._kill_switch = kill_switch
        self._audit_log = audit_log
        self._durable_audit = durable_audit
        self._pdp = pdp
        self._clock = clock
        self._lock = threading.Lock()
        self._failures: dict[str, collections.deque[float]] = {}
        self._rollbacks: dict[str, collections.deque[float]] = {}
        self._demoted: dict[str, str] = {}
        # Demoting one agent demotes its whole system_id cohort, so a fresh
        # principal id for the same system inherits the demotion.
        # TODO(control-plane-gap): demotions live in memory; persistence
        # across a harness restart is not implemented.
        self._demote_system = bool(demote_system)
        self._demoted_systems: dict[str, str] = {}
        # An agent with system_id None is its own cohort (keyed by its
        # canonical id). With demote_unscoped_agents=True every unscoped
        # agent shares one cohort, so a renamed unscoped agent stays demoted.
        # TODO(control-plane-gap): the right cohort for unscoped agents is
        # design inference; off by default to avoid mass demotion.
        self._demote_unscoped = bool(demote_unscoped_agents)
        self.audit_failures = 0

    _UNSCOPED_COHORT = "\x00unscoped"

    def _cohort(self, principal: Principal) -> str | None:
        if not self._demote_system:
            return None
        if principal.system_id is not None:
            return principal.system_id
        return self._UNSCOPED_COHORT if self._demote_unscoped else None

    @property
    def budgets(self) -> BudgetLedger | None:
        return self._budgets

    def _window(
        self, store: dict[str, collections.deque[float]], key: str
    ) -> collections.deque[float]:
        horizon = float(self._clock()) - self._error_budget.window_s
        events = store.setdefault(key, collections.deque())
        while events and events[0] < horizon:
            events.popleft()
        return events

    def record_failure(self, principal: Principal, kind: FailureKind | str) -> AutonomyLevel:
        failure = FailureKind(kind)
        if failure is FailureKind.ROLLBACK:
            return self.record_rollback(principal)
        if not self._governed(principal):
            return self.level(principal)
        trip = False
        with self._lock:
            if failure in self._error_budget.counted_kinds:
                events = self._window(self._failures, principal.canonical_id)
                events.append(float(self._clock()))
                trip = len(events) >= self._error_budget.max_failures
        if trip:
            self.demote(principal, f"error budget exhausted ({failure.value})")
        return self.level(principal)

    def record_rollback(self, principal: Principal) -> AutonomyLevel:
        if not self._governed(principal):
            return self.level(principal)
        with self._lock:
            events = self._window(self._rollbacks, principal.canonical_id)
            events.append(float(self._clock()))
            trip = len(events) >= self._error_budget.max_rollbacks
        if trip:
            self.demote(principal, "rollback budget exhausted")
        return self.level(principal)

    def demote(self, principal: Principal, reason: str) -> None:
        """Sticky demotion to P0_ONLY; audited durably (best effort receipt)."""
        if not self._governed(principal):
            return
        system = self._cohort(principal)
        with self._lock:
            if principal.canonical_id in self._demoted:
                return
            self._demoted[principal.canonical_id] = reason
            if system is not None:
                self._demoted_systems.setdefault(system, reason)
        self._record(principal, "autonomy_demotion", reason)

    def is_demoted(self, principal: Principal) -> bool:
        with self._lock:
            if principal.canonical_id in self._demoted:
                return True
            cohort = self._cohort(principal)
            return cohort is not None and cohort in self._demoted_systems

    def level(self, principal: Principal) -> AutonomyLevel:
        """Current level; any error computing it counts as SUSPENDED."""
        try:
            return self._level(principal)
        except Exception as exc:
            logger.error("autonomy level unavailable: %s", type(exc).__name__)
            return AutonomyLevel.SUSPENDED

    def admitted_level(self, principal: Principal) -> AutonomyLevel:
        """Recheck restrictions for a call whose resource admission already passed.

        Do not re-evaluate budget exhaustion: admission may have charged the
        final permitted iteration. Sticky error/cohort demotion and the kill
        switch still apply, and any unavailable state suspends execution.
        """
        try:
            return self._level(principal, check_budgets=False)
        except Exception as exc:
            logger.error("autonomy level unavailable: %s", type(exc).__name__)
            return AutonomyLevel.SUSPENDED

    def _level(self, principal: Principal, *, check_budgets: bool = True) -> AutonomyLevel:
        if self._kill_switch is not None and self._kill_switch.is_engaged():
            return AutonomyLevel.SUSPENDED
        if not self._governed(principal):
            return AutonomyLevel.T1_PREAUTHORIZED
        if self.is_demoted(principal):
            return AutonomyLevel.P0_ONLY
        budgets = self._budgets
        if check_budgets and budgets is not None and budgets.has_run(principal):
            state = budgets.state(principal)
            if state.is_exhausted:
                self.demote(principal, "resource budget exhausted: " + ", ".join(state.exhausted))
                return AutonomyLevel.P0_ONLY
        return AutonomyLevel.T1_PREAUTHORIZED

    def restore(self, admin: Principal, principal: Principal) -> None:
        """Lift a demotion and clear the failure windows. HUMAN admin only.

        Exhausted resource budgets keep demoting until the harness starts a
        new run.
        """
        if not isinstance(admin, Principal) or admin.kind is not PrincipalKind.HUMAN:
            raise AutonomyRestoreRejected("only a HUMAN may restore autonomy")
        with self._lock:
            self._demoted.pop(principal.canonical_id, None)
            cohort = self._cohort(principal)
            if cohort is not None:
                self._demoted_systems.pop(cohort, None)
            self._failures.pop(principal.canonical_id, None)
            self._rollbacks.pop(principal.canonical_id, None)
        self._record(principal, "autonomy_restore", f"restored by {admin.id}")

    @staticmethod
    def _governed(principal: object) -> bool:
        return isinstance(principal, Principal) and principal.kind is not PrincipalKind.HUMAN

    def _record(self, principal: Principal, event: str, reason: str) -> None:
        if self._audit_log is not None:
            entry = AuditEntry(
                id=f"{event}-{uuid.uuid4().hex}",
                type=event,
                agent_id=principal.id,
                action=f"autonomy.{event.rsplit('_', 1)[-1]}",
                valid=event != "autonomy_demotion",
                violations=[],
                metadata={"reason": reason, "system_id": principal.system_id},
            )
            try:
                if self._durable_audit:
                    self._audit_log.record_durable(entry)
                else:
                    self._audit_log.record(entry)
            except Exception as exc:
                # The demotion itself already applies (fail closed).
                logger.error("autonomy audit failed: %s", type(exc).__name__)
                with self._lock:
                    self.audit_failures += 1
        if self._pdp is not None and event == "autonomy_demotion":
            try:
                self._pdp.record_denial(
                    f"autonomy demoted to p0_only: {reason}",
                    principal_id=principal.id,
                    action="autonomy.demote",
                    resource=principal.id,
                    error="autonomy_demoted",
                )
            except Exception as exc:  # pragma: no cover - record_denial never raises
                logger.error("autonomy receipt failed: %s", type(exc).__name__)

    def principals_demoted(self) -> Iterable[str]:
        with self._lock:
            return tuple(self._demoted)
