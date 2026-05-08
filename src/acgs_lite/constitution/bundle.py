"""Constitution bundle lifecycle models and state machine.

Week 1 of the constitution lifecycle spec adds a bundle artifact that wraps a
``Constitution`` with deployment metadata, approval lineage, and transition
history. This module only models the lifecycle surface, it does not run rollout
or deployment side effects.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from acgs_lite.constitution.constitution import Constitution
from acgs_lite.constitution.editor import ConstitutionDiff
from acgs_lite.errors import MACIViolationError
from acgs_lite.maci import MACIRole


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BundleStatus(str, Enum):
    """Lifecycle state of a constitution bundle."""

    DRAFT = "draft"
    REVIEW = "review"
    EVAL = "eval"
    APPROVE = "approve"
    STAGED = "staged"
    ACTIVE = "active"
    ROLLED_BACK = "rolled_back"
    SUPERSEDED = "superseded"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


VALID_TRANSITIONS: dict[BundleStatus, set[BundleStatus]] = {
    BundleStatus.DRAFT: {BundleStatus.REVIEW, BundleStatus.WITHDRAWN},
    BundleStatus.REVIEW: {BundleStatus.EVAL, BundleStatus.REJECTED, BundleStatus.WITHDRAWN},
    BundleStatus.EVAL: {BundleStatus.APPROVE, BundleStatus.REJECTED, BundleStatus.WITHDRAWN},
    BundleStatus.APPROVE: {BundleStatus.STAGED, BundleStatus.REJECTED, BundleStatus.WITHDRAWN},
    BundleStatus.STAGED: {BundleStatus.ACTIVE, BundleStatus.ROLLED_BACK, BundleStatus.WITHDRAWN},
    BundleStatus.ACTIVE: {BundleStatus.ROLLED_BACK, BundleStatus.SUPERSEDED},
    # TODO: ROLLED_BACK → DRAFT was removed to prevent version conflicts on re-entry;
    # operators must create a new draft instead of recycling a rolled-back bundle.
    BundleStatus.ROLLED_BACK: {BundleStatus.SUPERSEDED},
    BundleStatus.SUPERSEDED: set(),
    BundleStatus.REJECTED: set(),
    BundleStatus.WITHDRAWN: set(),
}

_SYSTEM_ACTOR_ROLE = "system"


class StatusTransition(BaseModel):
    """Single state change in a bundle's lifecycle."""

    model_config = ConfigDict(use_enum_values=False)

    from_status: BundleStatus
    to_status: BundleStatus
    actor_id: str
    actor_role: str
    reason: str = ""
    timestamp: datetime = Field(default_factory=_utcnow)
    evidence_ref: str | None = None

    @field_validator("actor_role")
    @classmethod
    def _validate_actor_role(cls, value: str) -> str:
        normalized = value.lower().strip()
        allowed = {role.value for role in MACIRole} | {_SYSTEM_ACTOR_ROLE}
        if normalized not in allowed:
            raise ValueError(f"Unsupported actor_role: {value!r}")
        return normalized


class ConstitutionBundle(BaseModel):
    """Immutable, versioned, signable constitution deployment artifact."""

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    bundle_id: str = Field(default_factory=lambda: str(uuid4()))
    version: int = 1
    tenant_id: str

    constitution: Constitution
    constitutional_hash: str = ""
    parent_bundle_id: str | None = None
    parent_hash: str | None = None

    diff: ConstitutionDiff | None = None
    rules_added: int = 0
    rules_removed: int = 0
    rules_modified: int = 0

    status: BundleStatus = BundleStatus.DRAFT
    status_history: list[StatusTransition] = Field(default_factory=list)

    proposed_by: str
    reviewed_by: str | None = None
    approved_by: str | None = None
    staged_by: str | None = None
    activated_by: str | None = None

    eval_run_ids: list[str] = Field(default_factory=list)
    eval_summary: dict[str, Any] = Field(default_factory=dict)
    eval_attempt_count: int = 0

    evidence_bundle_id: str | None = None
    approval_signature: str | None = None

    created_at: datetime = Field(default_factory=_utcnow)
    submitted_at: datetime | None = None
    approved_at: datetime | None = None
    staged_at: datetime | None = None
    activated_at: datetime | None = None
    rolled_back_at: datetime | None = None

    canary_agent_ids: list[str] = Field(default_factory=list)
    rollout_flip_threshold: float = 0.05

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: int) -> int:
        if value < 1:
            raise ValueError("version must be >= 1")
        return value

    @field_validator("rollout_flip_threshold")
    @classmethod
    def _validate_flip_threshold(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("rollout_flip_threshold must be between 0.0 and 1.0")
        return value

    @model_validator(mode="after")
    def _populate_derived_fields(self) -> ConstitutionBundle:
        object.__setattr__(self, "constitutional_hash", self.constitution.hash)
        if self.diff is not None:
            object.__setattr__(self, "rules_added", len(self.diff.added))
            object.__setattr__(self, "rules_removed", len(self.diff.removed))
            object.__setattr__(self, "rules_modified", len(self.diff.modified))
        return self

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            BundleStatus.SUPERSEDED,
            BundleStatus.REJECTED,
            BundleStatus.WITHDRAWN,
        }

    def can_transition_to(self, target: BundleStatus) -> bool:
        return target in VALID_TRANSITIONS.get(self.status, set())

    def assert_can_transition_to(self, target: BundleStatus) -> None:
        if not self.can_transition_to(target):
            raise ValueError(
                f"Cannot transition bundle {self.bundle_id!r} from "
                f"{self.status.value!r} to {target.value!r}"
            )

    def to_adapter_dict(self) -> dict[str, Any]:
        """Serialize with adapter-facing policy hash vocabulary."""
        from acgs_lite.legitimacy.receipt import to_receipt_dict

        return to_receipt_dict(self)

    def transition_to(
        self,
        target: BundleStatus,
        *,
        actor_id: str,
        actor_role: MACIRole | str,
        reason: str = "",
        evidence_ref: str | None = None,
    ) -> StatusTransition:
        """Validate and apply a lifecycle state transition."""

        self.assert_can_transition_to(target)
        actor_role_value = actor_role.value if isinstance(actor_role, MACIRole) else actor_role
        actor_role_value = actor_role_value.lower().strip()
        self._enforce_role_gate(target, actor_id=actor_id, actor_role=actor_role_value)

        transition = StatusTransition(
            from_status=self.status,
            to_status=target,
            actor_id=actor_id,
            actor_role=actor_role_value,
            reason=reason,
            evidence_ref=evidence_ref,
        )
        self.status = target
        self.status_history.append(transition)
        self._apply_transition_side_effects(target, actor_id=actor_id)
        return transition

    def _apply_transition_side_effects(self, target: BundleStatus, *, actor_id: str) -> None:
        now = _utcnow()
        if target == BundleStatus.REVIEW:
            self.submitted_at = now
        elif target == BundleStatus.EVAL:
            self.reviewed_by = actor_id
        elif target == BundleStatus.APPROVE:
            self.approved_by = actor_id
            self.approved_at = now
        elif target == BundleStatus.STAGED:
            self.staged_by = actor_id
            self.staged_at = now
        elif target == BundleStatus.ACTIVE:
            self.activated_by = actor_id
            self.activated_at = now
        elif target == BundleStatus.ROLLED_BACK:
            self.rolled_back_at = now

    def _enforce_role_gate(self, target: BundleStatus, *, actor_id: str, actor_role: str) -> None:
        if target == BundleStatus.REVIEW:
            self._require_role(actor_role, MACIRole.PROPOSER)
            if actor_id != self.proposed_by:
                self._raise_maci_violation(
                    "Only the original proposer may submit a draft for review",
                    actor_role=actor_role,
                    attempted_action=target.value,
                )
            return

        if target == BundleStatus.EVAL:
            self._require_role(actor_role, MACIRole.VALIDATOR)
            self._require_distinct(
                actor_id,
                actor_role,
                target.value,
                self.proposed_by,
                "validator",
                "proposer",
            )
            return

        if target == BundleStatus.APPROVE:
            self._require_role(actor_role, MACIRole.VALIDATOR)
            self._require_distinct(
                actor_id,
                actor_role,
                target.value,
                self.proposed_by,
                "approver",
                "proposer",
            )
            return

        if target == BundleStatus.STAGED:
            self._require_role(actor_role, MACIRole.EXECUTOR)
            self._require_distinct(
                actor_id,
                actor_role,
                target.value,
                self.proposed_by,
                "executor",
                "proposer",
            )
            self._require_distinct(
                actor_id,
                actor_role,
                target.value,
                self.reviewed_by,
                "executor",
                "reviewer",
            )
            self._require_distinct(
                actor_id,
                actor_role,
                target.value,
                self.approved_by,
                "executor",
                "approver",
            )
            if self.approval_signature is None:
                raise ValueError("Cannot stage a bundle without an approval_signature")
            return

        if target == BundleStatus.ACTIVE:
            self._require_role(actor_role, MACIRole.EXECUTOR)
            if self.staged_by is None:
                raise ValueError("Cannot activate a bundle that has not been staged")
            if actor_id != self.staged_by:
                self._raise_maci_violation(
                    "Only the executor who staged the bundle may activate it",
                    actor_role=actor_role,
                    attempted_action=target.value,
                )
            return

        if target == BundleStatus.ROLLED_BACK:
            self._require_role(actor_role, MACIRole.EXECUTOR)
            return

        if target == BundleStatus.WITHDRAWN:
            self._require_role(actor_role, MACIRole.PROPOSER)
            if actor_id != self.proposed_by:
                self._raise_maci_violation(
                    "Only the original proposer may withdraw a bundle",
                    actor_role=actor_role,
                    attempted_action=target.value,
                )
            return

        if target == BundleStatus.SUPERSEDED:
            if actor_role != _SYSTEM_ACTOR_ROLE:
                self._raise_maci_violation(
                    "SUPERSEDED transitions are reserved for the system actor",
                    actor_role=actor_role,
                    attempted_action=target.value,
                )
            return

        if target == BundleStatus.REJECTED:
            self._require_role(actor_role, MACIRole.VALIDATOR)
            return

    @staticmethod
    def _require_role(actual: str, expected: MACIRole) -> None:
        if actual != expected.value:
            raise MACIViolationError(
                f"Transition requires role {expected.value!r}, got {actual!r}",
                actor_role=actual,
                attempted_action=expected.value,
            )

    @staticmethod
    def _require_distinct(
        actor_id: str,
        actor_role: str,
        attempted_action: str,
        other_actor_id: str | None,
        actor_label: str,
        other_label: str,
    ) -> None:
        if other_actor_id is not None and actor_id == other_actor_id:
            raise MACIViolationError(
                f"MACI separation violated: {actor_label} must differ from {other_label}",
                actor_role=actor_role,
                attempted_action=attempted_action,
            )

    @staticmethod
    def _raise_maci_violation(message: str, *, actor_role: str, attempted_action: str) -> None:
        raise MACIViolationError(
            message,
            actor_role=actor_role,
            attempted_action=attempted_action,
        )


__all__ = [
    "BundleStatus",
    "ConstitutionBundle",
    "StatusTransition",
    "VALID_TRANSITIONS",
]
