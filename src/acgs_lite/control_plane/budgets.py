"""Harness-enforced resource budgets (spend, tokens, iterations, wall clock).

Evidence: in the Darwin Goedel Machine runs the agent fabricated "tests
passed" logs, so nothing the model reports about itself is authoritative.
Usage is charged only by the harness (the dispatcher charges one iteration
per dispatch) or by a SERVICE/HUMAN reporter such as an LLM proxy counting
tokens; a charge reported by an AGENT is refused. Wall-clock time comes from
a harness-owned monotonic clock started at :meth:`BudgetLedger.start_run`.

A budget is exhausted when usage *reaches* its limit (``used >= limit``),
checked before the next dispatch.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from acgs_lite.control_plane.principal import Principal, PrincipalKind

__all__ = [
    "BudgetChargeRefused",
    "BudgetExhausted",
    "BudgetLedger",
    "BudgetLimits",
    "BudgetState",
]


class BudgetExhausted(Exception):
    """Raised by :meth:`BudgetLedger.check` when any budget is used up."""

    def __init__(self, principal_id: str, exhausted: tuple[str, ...]) -> None:
        super().__init__(f"budget exhausted for {principal_id}: {', '.join(exhausted)}")
        self.principal_id = principal_id
        self.exhausted = exhausted


class BudgetChargeRefused(PermissionError):
    """A charge came from a reporter that may not report usage."""


def _limit(value: object, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number or None")
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be finite and >= 0")
    return float(value)


@dataclass(frozen=True)
class BudgetLimits:
    """Per-run limits; ``None`` means unlimited for that resource.

    TODO(control-plane-gap): there are no default limits; values are design
    inference and must be configured per deployment.
    """

    spend_usd: float | None = None
    tokens: int | None = None
    iterations: int | None = None
    wall_clock_s: float | None = None

    def __post_init__(self) -> None:
        for name in ("spend_usd", "tokens", "iterations", "wall_clock_s"):
            object.__setattr__(self, name, _limit(getattr(self, name), name))


@dataclass(frozen=True)
class BudgetState:
    principal_id: str
    spend_usd: float
    tokens: int
    iterations: int
    elapsed_s: float
    exhausted: tuple[str, ...]

    @property
    def is_exhausted(self) -> bool:
        return bool(self.exhausted)


@dataclass
class _Run:
    limits: BudgetLimits
    started: float
    spend_usd: float = 0.0
    tokens: int = 0
    iterations: int = 0


def _amount(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be finite and >= 0")
    return float(value)


class BudgetLedger:
    """Thread-safe usage ledger keyed by canonical principal id."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._runs: dict[str, _Run] = {}

    def start_run(self, principal: Principal, limits: BudgetLimits) -> None:
        """Start (or restart) a run; harness-only API."""
        if not isinstance(principal, Principal):
            raise TypeError("principal must be a Principal")
        if not isinstance(limits, BudgetLimits):
            raise TypeError("limits must be BudgetLimits")
        with self._lock:
            self._runs[principal.canonical_id] = _Run(limits, float(self._clock()))

    def has_run(self, principal: Principal) -> bool:
        with self._lock:
            return principal.canonical_id in self._runs

    def charge(
        self,
        principal: Principal,
        *,
        spend_usd: float = 0,
        tokens: int = 0,
        iterations: int = 0,
        reporter: Principal | None = None,
    ) -> BudgetState:
        """Record usage. ``reporter=None`` is the harness itself.

        Raises :class:`BudgetChargeRefused` for an AGENT reporter and
        ``KeyError`` when no run was started for *principal*.
        """
        if reporter is not None and (
            not isinstance(reporter, Principal) or reporter.kind is PrincipalKind.AGENT
        ):
            raise BudgetChargeRefused("agents may not report their own (or any) usage")
        spend = _amount(spend_usd, "spend_usd")
        token_count = _amount(tokens, "tokens")
        iteration_count = _amount(iterations, "iterations")
        with self._lock:
            run = self._runs[principal.canonical_id]
            run.spend_usd += spend
            run.tokens += int(token_count)
            run.iterations += int(iteration_count)
            return self._state(principal.canonical_id, run)

    def try_charge(
        self,
        principal: Principal,
        *,
        spend_usd: float = 0,
        tokens: int = 0,
        iterations: int = 1,
        reporter: Principal | None = None,
    ) -> BudgetState | None:
        """Atomically: if no budget is exhausted, charge and return the new
        state; otherwise charge nothing and return ``None``.

        Check and charge happen under one lock, so concurrent callers cannot
        both pass the check for the last unit of budget.
        """
        if reporter is not None and (
            not isinstance(reporter, Principal) or reporter.kind is PrincipalKind.AGENT
        ):
            raise BudgetChargeRefused("agents may not report their own (or any) usage")
        spend = _amount(spend_usd, "spend_usd")
        token_count = _amount(tokens, "tokens")
        iteration_count = _amount(iterations, "iterations")
        with self._lock:
            run = self._runs[principal.canonical_id]
            if self._state(principal.canonical_id, run).is_exhausted:
                return None
            run.spend_usd += spend
            run.tokens += int(token_count)
            run.iterations += int(iteration_count)
            return self._state(principal.canonical_id, run)

    def state(self, principal: Principal) -> BudgetState:
        with self._lock:
            return self._state(principal.canonical_id, self._runs[principal.canonical_id])

    def used_fraction(self, principal: Principal) -> float | None:
        """Largest used/limit ratio over the run's limited resources (Phase 5
        runbook ``budget_fraction`` stop condition); ``None`` without a run
        or without any limit."""
        with self._lock:
            run = self._runs.get(principal.canonical_id)
            if run is None:
                return None
            elapsed = max(0.0, float(self._clock()) - run.started)
            limits = run.limits
            ratios = [
                used / limit if limit > 0 else 1.0
                for used, limit in (
                    (run.spend_usd, limits.spend_usd),
                    (float(run.tokens), limits.tokens),
                    (float(run.iterations), limits.iterations),
                    (elapsed, limits.wall_clock_s),
                )
                if limit is not None
            ]
        return max(ratios) if ratios else None

    def check(self, principal: Principal) -> BudgetState:
        """Return the state or raise :class:`BudgetExhausted` (or ``KeyError``)."""
        state = self.state(principal)
        if state.is_exhausted:
            raise BudgetExhausted(state.principal_id, state.exhausted)
        return state

    def _state(self, principal_id: str, run: _Run) -> BudgetState:
        elapsed = max(0.0, float(self._clock()) - run.started)
        limits = run.limits
        exhausted = tuple(
            name
            for name, used, limit in (
                ("spend_usd", run.spend_usd, limits.spend_usd),
                ("tokens", float(run.tokens), limits.tokens),
                ("iterations", float(run.iterations), limits.iterations),
                ("wall_clock_s", elapsed, limits.wall_clock_s),
            )
            if limit is not None and used >= limit
        )
        return BudgetState(
            principal_id=principal_id,
            spend_usd=run.spend_usd,
            tokens=run.tokens,
            iterations=run.iterations,
            elapsed_s=elapsed,
            exhausted=exhausted,
        )
