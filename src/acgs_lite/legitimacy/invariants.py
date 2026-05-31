"""Runtime legitimacy invariants for governed execution."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.legitimacy.decide import canonicalize_decision_state
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


_SUBJECT_ARGUMENT_NAMES = frozenset(
    (
        "subject",
        "subject_id",
        "subjects",
        "resource",
        "resource_id",
        "object_id",
        "account_id",
        "customer_id",
        "user_id",
    )
)
_SCOPE_ARGUMENT_NAMES = frozenset(
    (
        "scope",
        "governance_scope",
        "tenant",
        "tenant_id",
        "workspace_id",
        "organization_id",
        "org_id",
        "project_id",
    )
)


def normalize_actual_call(
    *,
    fallback_method: str,
    kwargs: dict[str, Any],
    args: tuple[Any, ...] = (),
    func: Callable[..., Any] | None = None,
) -> ActualCall:
    """Normalize call metadata before invariant comparison."""
    bound_arguments = _bind_call_arguments(func, args, kwargs)
    method = str(
        kwargs.get("governance_method")
        or kwargs.get("method")
        or kwargs.get("action")
        or fallback_method
    )
    scope_value = kwargs.get("governance_scope", kwargs.get("scope"))
    if scope_value is None:
        scope_value = _first_bound_value(bound_arguments, _SCOPE_ARGUMENT_NAMES)
    scope = str(scope_value) if scope_value is not None else None
    raw_subjects = kwargs.get("governance_subjects", kwargs.get("subjects", ()))
    if raw_subjects in (None, ()):
        raw_subjects = _subjects_from_bound_arguments(bound_arguments)
    subjects = _coerce_subjects(raw_subjects)
    return ActualCall(method=method, scope=scope, subjects=subjects)


def call_matches(boundary: ExecutionBoundary, actual_call: ActualCall) -> bool:
    """Return whether the normalized actual call stays inside the receipt boundary."""
    if boundary.allowed_method is not None and boundary.allowed_method != actual_call.method:
        return False
    if boundary.allowed_scope is not None and boundary.allowed_scope != actual_call.scope:
        return False
    allowed_subjects = set(boundary.allowed_subjects)
    if allowed_subjects:
        if not actual_call.subjects:
            return False
        if not set(actual_call.subjects).issubset(allowed_subjects):
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
    audit_log: Any | None = None,
) -> None:
    """Fail closed unless receipt integrity and runtime invariants hold."""
    if receipt is None:
        raise LegitimacyInvariantError("No legitimacy receipt, no execution")
    if not isinstance(receipt, DecisionReceipt):
        raise LegitimacyInvariantError("Invalid legitimacy receipt type")
    try:
        decision_type = canonicalize_decision_state(receipt.decision_type)
    except ValueError as exc:
        raise LegitimacyInvariantError("Unknown decision type is not allow") from exc
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
    if audit_log is not None and not _audit_evidence_verifiable(audit_log):
        raise LegitimacyInvariantError("Audit evidence is not verifiable, no execution")
    try:
        receipt_hash_valid = receipt.verify_hash()
    except Exception as exc:
        raise LegitimacyInvariantError("Decision receipt integrity check failed") from exc
    if not receipt_hash_valid:
        raise LegitimacyInvariantError("Decision receipt integrity check failed")
    if decision_type not in {"ALLOW", "ALLOW_WITH_CONTROLS"}:
        raise LegitimacyInvariantError(f"Decision {decision_type} does not permit execution")
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


def _bind_call_arguments(
    func: Callable[..., Any] | None,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    if func is None:
        return {}
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return {}

    parameters = signature.parameters
    accepts_var_kwargs = any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
    )
    bindable_kwargs = {
        key: value for key, value in kwargs.items() if accepts_var_kwargs or key in parameters
    }
    try:
        bound = signature.bind_partial(*args, **bindable_kwargs)
    except TypeError:
        return {}
    return dict(bound.arguments)


def _first_bound_value(bound_arguments: Mapping[str, Any], names: frozenset[str]) -> Any | None:
    for name in names:
        if name in bound_arguments:
            return bound_arguments[name]
    return None


def _subjects_from_bound_arguments(bound_arguments: Mapping[str, Any]) -> Any:
    if "subjects" in bound_arguments:
        return bound_arguments["subjects"]
    return tuple(
        value for name, value in bound_arguments.items() if name in _SUBJECT_ARGUMENT_NAMES
    )


def _coerce_subjects(raw_subjects: Any) -> tuple[str, ...]:
    if raw_subjects is None:
        return ()
    if isinstance(raw_subjects, str):
        return (raw_subjects,)
    if isinstance(raw_subjects, Mapping):
        return tuple(str(value) for value in raw_subjects.values())
    try:
        return tuple(str(subject) for subject in raw_subjects)
    except TypeError:
        return (str(raw_subjects),)


def _audit_evidence_verifiable(audit_log: Any) -> bool:
    verifier = getattr(audit_log, "verify_chain", None)
    if not callable(verifier):
        return False
    try:
        return verifier() is True
    except Exception:
        return False


__all__ = [
    "ActualCall",
    "LegitimacyInvariantError",
    "call_matches",
    "normalize_actual_call",
    "route_ambiguous_decision",
    "validate_receipt_for_execution",
]
