"""Tier assignment by irreversibility and blast radius -- never by confidence.

:func:`classify_tier` is pure and deterministic and takes no confidence
input (a test asserts the signature): a confident agent deleting a live
database is still T3.

* T0 -- read-only: autonomous, logged.
* T1 -- reversible, narrow (``blast_radius <= min(runbook.max_blast_radius,
  narrow_max_blast_radius)``), not novel and covered by an approved T1
  runbook: pre-authorised, with post-hoc human review
  (:class:`ReviewQueue`).
* T2 -- reversible but wide, novel or without a runbook: human approval per
  action (Phase-3 signed quorum).
* T3 -- irreversible or data-destroying: a HUMAN executes (Phase-3 two-person
  approval still applies via INV-T3-TWO-PERSON), or two-person signed
  approval *and* a verified backup (:func:`t3_execution_problem`).

Evidence: Replit -- an agent deleted a live production database during a
code freeze; irreversible / data-destroying actions are therefore T3, and an
agent may only run one with two human approvals and a backup proven by an
external run (an agent-written log is not proof, DGM).

The dispatcher computes the tier from a host-registered
:class:`ActionProfile` factory and ignores (or refuses, when lower) any tier a
caller supplies.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from acgs_lite._compat import StrEnum
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.tiers import ActionTier

if TYPE_CHECKING:
    from acgs_lite.control_plane.identity import AdminAttestor
    from acgs_lite.control_plane.runbook import Runbook

__all__ = [
    "DEFAULT_NARROW_MAX_BLAST_RADIUS",
    "DEFAULT_REVIEW_SLA_S",
    "ActionProfile",
    "PostHocReviewItem",
    "ProfileFactory",
    "ReviewOutcome",
    "ReviewQueue",
    "classify_tier",
    "static_profile",
    "t3_execution_problem",
]

# TODO(control-plane-gap): "narrow" = at most 10 resources is a design
# inference (no primary source fixes the number); it is an absolute cap on
# top of each runbook's own max_blast_radius and configurable per call.
DEFAULT_NARROW_MAX_BLAST_RADIUS = 10
# TODO(control-plane-gap): a 24 h post-hoc review SLA is a design inference;
# configure per ReviewQueue.
DEFAULT_REVIEW_SLA_S = 24 * 3600.0


@dataclass(frozen=True)
class ActionProfile:
    """What an action does to the world (host-computed from the call's args).

    ``blast_radius`` counts the resources the action touches.
    ``has_verified_backup`` is only a claim; the dispatcher additionally
    requires a backup run validated by its run verifier for agent T3.
    ``read_only`` is honoured only for tools *registered* read-only.
    """

    reversible: bool
    data_destroying: bool
    blast_radius: int
    novel: bool
    has_verified_backup: bool = False
    read_only: bool = False

    def __post_init__(self) -> None:
        for name in ("reversible", "data_destroying", "novel", "has_verified_backup", "read_only"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"ActionProfile.{name} must be a bool")
        if (
            isinstance(self.blast_radius, bool)
            or not isinstance(self.blast_radius, int)
            or self.blast_radius < 0
        ):
            raise ValueError("ActionProfile.blast_radius must be an int >= 0")
        if self.read_only and (self.data_destroying or not self.reversible):
            raise ValueError("a read-only action cannot be irreversible or data-destroying")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "reversible": self.reversible,
            "data_destroying": self.data_destroying,
            "blast_radius": self.blast_radius,
            "novel": self.novel,
            "has_verified_backup": self.has_verified_backup,
            "read_only": self.read_only,
        }


ProfileFactory = Callable[[Mapping[str, Any]], ActionProfile]
"""Host code mapping a tool call's (snapshotted) arguments to its profile."""


def static_profile(profile: ActionProfile) -> ProfileFactory:
    """A factory that ignores the arguments (fixed-effect tools)."""
    if not isinstance(profile, ActionProfile):
        raise TypeError("profile must be an ActionProfile")

    def factory(arguments: Mapping[str, Any]) -> ActionProfile:
        return profile

    return factory


def classify_tier(
    profile: ActionProfile,
    *,
    runbook: Runbook | None = None,
    narrow_max_blast_radius: int = DEFAULT_NARROW_MAX_BLAST_RADIUS,
) -> ActionTier:
    """Pure tier assignment. *runbook* must already be approved and matched
    (the dispatcher validates it through ``RunbookRegistry`` first)."""
    if not isinstance(profile, ActionProfile):
        raise TypeError("profile must be an ActionProfile")
    if (
        isinstance(narrow_max_blast_radius, bool)
        or not isinstance(narrow_max_blast_radius, int)
        or narrow_max_blast_radius < 1
    ):
        raise ValueError("narrow_max_blast_radius must be an int >= 1")
    if profile.data_destroying or not profile.reversible:
        return ActionTier.T3
    if profile.read_only:
        return ActionTier.T0
    if (
        runbook is not None
        and runbook.action_tier is ActionTier.T1
        and not profile.novel
        and 1 <= profile.blast_radius <= min(runbook.max_blast_radius, narrow_max_blast_radius)
    ):
        return ActionTier.T1
    return ActionTier.T2


def t3_execution_problem(
    executor: Principal, *, backup_verified: bool, profile: ActionProfile | None = None
) -> str | None:
    """Why *executor* may not run a T3 action, or ``None``.

    A HUMAN executes ("human executes"; INV-T3-TWO-PERSON still demands two
    other human approvers). Anyone else additionally needs a backup proven by
    an independently validated external run.
    """
    if executor.kind is PrincipalKind.HUMAN:
        return None
    if profile is not None and not profile.has_verified_backup:
        return "T3 by a non-human needs an action profile with has_verified_backup"
    if not backup_verified:
        return "T3 by a non-human needs a backup proven by a validated external run"
    return None


class ReviewOutcome(StrEnum):
    ACCEPTED = "accepted"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True)
class PostHocReviewItem:
    """One pre-authorised T1 execution awaiting human review."""

    item_id: str
    decision_id: str
    """The ``tool.call`` decision id (its receipt carries the same id)."""
    runbook_id: str
    runbook_hash: str
    principal_id: str
    tool_name: str
    created_at: float
    outcome: ReviewOutcome | None = None
    reviewed_by: str | None = None


@dataclass
class ReviewQueue:
    """Harness-owned queue of T1 executions; only a HUMAN resolves items."""

    sla_s: float = DEFAULT_REVIEW_SLA_S
    clock: Callable[[], float] = time.time
    admin_attestor: AdminAttestor | None = None
    """Phase 6a: when set, :meth:`resolve` needs the reviewer's verified
    single-use HUMAN ``admin_credential=`` (any directory human)."""
    _items: dict[str, PostHocReviewItem] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def record(
        self,
        *,
        decision_id: str,
        runbook_id: str,
        runbook_hash: str,
        principal_id: str,
        tool_name: str,
    ) -> PostHocReviewItem:
        item = PostHocReviewItem(
            item_id=uuid.uuid4().hex,
            decision_id=decision_id,
            runbook_id=runbook_id,
            runbook_hash=runbook_hash,
            principal_id=principal_id,
            tool_name=tool_name,
            created_at=float(self.clock()),
        )
        with self._lock:
            self._items[item.item_id] = item
        return item

    def __post_init__(self) -> None:
        from acgs_lite.control_plane.identity import checked_attestor

        checked_attestor(self.admin_attestor)

    def resolve(
        self,
        reviewer: Principal,
        item_id: str,
        outcome: ReviewOutcome | str,
        *,
        admin_credential: str | None = None,
    ) -> PostHocReviewItem:
        if not isinstance(reviewer, Principal) or reviewer.kind is not PrincipalKind.HUMAN:
            raise PermissionError("only a HUMAN reviewer may resolve post-hoc review items")
        if self.admin_attestor is not None:
            self.admin_attestor.require(
                reviewer, admin_credential, admin_only=False, error=PermissionError
            )
        verdict = ReviewOutcome(outcome)
        with self._lock:
            item = self._items.get(item_id)
            if item is None:
                raise KeyError(item_id)
            if item.outcome is not None:
                raise ValueError("review item already resolved")
            if reviewer.canonical_id == item.principal_id.casefold():
                raise PermissionError("the executing principal cannot review its own action")
            resolved = PostHocReviewItem(
                **{**item.__dict__, "outcome": verdict, "reviewed_by": reviewer.id}
            )
            self._items[item_id] = resolved
            return resolved

    def items(self) -> tuple[PostHocReviewItem, ...]:
        with self._lock:
            return tuple(self._items.values())

    def unresolved(self) -> tuple[PostHocReviewItem, ...]:
        return tuple(item for item in self.items() if item.outcome is None)

    def overdue(self) -> tuple[PostHocReviewItem, ...]:
        now = float(self.clock())
        return tuple(item for item in self.unresolved() if now - item.created_at > self.sla_s)

    def snapshot(self) -> dict[str, int]:
        return {
            "total": len(self.items()),
            "unresolved": len(self.unresolved()),
            "overdue": len(self.overdue()),
        }
