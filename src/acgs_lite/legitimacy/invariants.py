"""Runtime legitimacy invariants for governed execution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.legitimacy.decide import CANONICAL_DECISION_STATES, canonicalize_decision_state
from acgs_lite.legitimacy.receipt import DecisionReceipt, ExecutionBoundary


class LegitimacyInvariantError(ConstitutionalViolationError):
    """Raised when a governed call lacks valid legitimacy proof."""

    def __init__(self, message: str, *, action: str = "") -> None:
        super().__init__(
            message,
            rule_id="LEGITIMACY-INVARIANT",
            severity="critical",
            action=action,
        )


@dataclass(slots=True, frozen=True)
class ActualCall:
    """Normalized actual executor call used for boundary matching."""

    method: str
    scope: str | None
    subjects: tuple[str, ...]


def normalize_actual_call(
    *,
    fallback_method: str,
    kwargs: dict[str, Any],
) -> ActualCall:
    """Normalize call metadata before invariant comparison."""
    method = str(
        kwargs.get("governance_method")
        or kwargs.get("method")
        or kwargs.get("action")
        or fallback_method
    )
    scope_value = kwargs.get("governance_scope", kwargs.get("scope"))
    scope = str(scope_value) if scope_value is not None else None
    raw_subjects = kwargs.get("governance_subjects", kwargs.get("subjects", ()))
    if raw_subjects is None:
        subjects: tuple[str, ...] = ()
    elif isinstance(raw_subjects, str):
        subjects = (raw_subjects,)
    else:
        subjects = tuple(str(subject) for subject in raw_subjects)
    return ActualCall(method=method, scope=scope, subjects=subjects)


def call_matches(boundary: ExecutionBoundary, actual_call: ActualCall) -> bool:
    """Return whether the normalized actual call stays inside the receipt boundary."""
    if boundary.allowed_method is not None and boundary.allowed_method != actual_call.method:
        return False
    if boundary.allowed_scope is not None and boundary.allowed_scope != actual_call.scope:
        return False
    allowed_subjects = set(boundary.allowed_subjects)
    if allowed_subjects and not set(actual_call.subjects).issubset(allowed_subjects):
        return False
    if boundary.expires_at is not None:
        try:
            expires_at = datetime.fromisoformat(boundary.expires_at)
        except ValueError:
            return False
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            return False
    return True


def validate_receipt_for_execution(
    receipt: DecisionReceipt | None,
    *,
    actual_call: ActualCall | None = None,
    human_approval: dict[str, Any] | None = None,
) -> None:
    """Fail closed unless receipt integrity and runtime invariants hold."""
    if receipt is None:
        raise LegitimacyInvariantError("No legitimacy receipt, no execution")
    if not isinstance(receipt, DecisionReceipt):
        raise LegitimacyInvariantError("Invalid legitimacy receipt type")
    if not receipt.verify_hash():
        raise LegitimacyInvariantError("Decision receipt integrity check failed")
    try:
        decision_type = canonicalize_decision_state(receipt.decision_type)
    except ValueError as exc:
        raise LegitimacyInvariantError("Unknown decision type is not allow") from exc
    if decision_type not in CANONICAL_DECISION_STATES:
        raise LegitimacyInvariantError("Unknown decision type is not allow")
    if decision_type not in {"ALLOW", "ALLOW_WITH_CONTROLS"}:
        raise LegitimacyInvariantError(f"Decision {decision_type} does not permit execution")
    if not receipt.policy_version:
        raise LegitimacyInvariantError("No policy version, no execution")
    if not receipt.authority_basis:
        raise LegitimacyInvariantError("No authority basis, no execution")
    if receipt.execution_boundary is None:
        raise LegitimacyInvariantError("No execution boundary, no execution")
    if receipt.matched_constraints is None:
        raise LegitimacyInvariantError("No constraint proof, no execution")
    if not receipt.matched_constraints:
        raise LegitimacyInvariantError("Empty constraint proof is not executable")
    if _requires_human_approval(receipt) and not _has_structured_human_approval(human_approval):
        raise LegitimacyInvariantError("Human approval requires structured approval fields")
    if actual_call is not None and not call_matches(receipt.execution_boundary, actual_call):
        raise LegitimacyInvariantError("Execution boundary mismatch blocks completion")


def route_ambiguous_decision(confidence: float | None, *, threshold: float = 0.8) -> str:
    """Low or missing confidence must route to review, never ALLOW."""
    if confidence is None or confidence < threshold:
        return "STRUCTURED_REVIEW_REQUIRED"
    return "ALLOW"


def _requires_human_approval(receipt: DecisionReceipt) -> bool:
    controls = {control.upper() for control in receipt.required_controls}
    return "HUMAN_APPROVAL" in controls or "STRUCTURED_HUMAN_APPROVAL" in controls


def _has_structured_human_approval(value: dict[str, Any] | None) -> bool:
    if not isinstance(value, dict):
        return False
    required = ("approved_by", "approved_at", "approval_id")
    return all(isinstance(value.get(field), str) and value[field] for field in required)


__all__ = [
    "ActualCall",
    "LegitimacyInvariantError",
    "call_matches",
    "normalize_actual_call",
    "route_ambiguous_decision",
    "validate_receipt_for_execution",
]
