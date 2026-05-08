"""Replayable legitimacy receipts and canonical receipt serialization."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from acgs_lite.legitimacy.decide import (
    CANONICAL_DECISION_STATES,
    DecisionState,
    canonicalize_decision_state,
)

BASELINE_CONSTRAINT_MARKER = "NO_SPECIFIC_CONSTRAINT_MATCHED_UNDER_POLICY_VERSION"


@dataclass(slots=True, frozen=True)
class ExecutionBoundary:
    """Executor boundary that a governed call must match before side effects."""

    allowed_method: str | None
    allowed_scope: str | None
    allowed_subjects: tuple[str, ...]
    expires_at: str | None
    single_use: bool


@dataclass(slots=True, frozen=True)
class DecisionReceipt:
    """Replayable decision receipt emitted before execution."""

    request_id: str
    goal: str
    proposed_method: str
    decision_type: DecisionState
    authority_basis: str
    matched_constraints: tuple[str, ...]
    policy_version: str
    required_controls: tuple[str, ...]
    transformation_applied: str | None
    denial_or_review_rationale: str | None
    execution_boundary: ExecutionBoundary
    issued_at: str
    receipt_hash: str

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        goal: str,
        proposed_method: str,
        decision_type: Any,
        authority_basis: str,
        matched_constraints: tuple[str, ...],
        policy_version: str,
        required_controls: tuple[str, ...] = (),
        transformation_applied: str | None = None,
        denial_or_review_rationale: str | None = None,
        execution_boundary: ExecutionBoundary,
        issued_at: str | None = None,
    ) -> DecisionReceipt:
        """Validate fields, issue a timestamp, compute the hash, and freeze."""
        receipt_issued_at = issued_at or datetime.now(timezone.utc).isoformat()
        canonical_decision_type = canonicalize_decision_state(decision_type)
        canonical_constraints = tuple(matched_constraints)
        canonical_controls = tuple(required_controls)
        data = {
            "request_id": request_id,
            "goal": goal,
            "proposed_method": proposed_method,
            "decision_type": canonical_decision_type,
            "authority_basis": authority_basis,
            "matched_constraints": canonical_constraints,
            "policy_version": policy_version,
            "required_controls": canonical_controls,
            "transformation_applied": transformation_applied,
            "denial_or_review_rationale": denial_or_review_rationale,
            "execution_boundary": execution_boundary,
            "issued_at": receipt_issued_at,
        }
        _validate_receipt_payload(data)
        receipt_hash = _hash_receipt_payload(data)
        return cls(
            request_id=request_id,
            goal=goal,
            proposed_method=proposed_method,
            decision_type=canonical_decision_type,
            authority_basis=authority_basis,
            matched_constraints=canonical_constraints,
            policy_version=policy_version,
            required_controls=canonical_controls,
            transformation_applied=transformation_applied,
            denial_or_review_rationale=denial_or_review_rationale,
            execution_boundary=execution_boundary,
            issued_at=receipt_issued_at,
            receipt_hash=receipt_hash,
        )

    def __post_init__(self) -> None:
        data = self.to_receipt_dict(include_hash=False)
        _validate_receipt_payload(data)
        expected_hash = _hash_receipt_payload(data)
        if self.receipt_hash != expected_hash:
            raise ValueError("receipt_hash does not match canonical receipt payload")

    def to_receipt_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        """Project this receipt to canonical JSON-compatible receipt fields."""
        payload = asdict(self)
        if not include_hash:
            payload.pop("receipt_hash", None)
        return payload

    def verify_hash(self) -> bool:
        """Verify receipt integrity against the canonical hash payload."""
        return self.receipt_hash == _hash_receipt_payload(self.to_receipt_dict(include_hash=False))


def _validate_receipt_payload(payload: Mapping[str, Any]) -> None:
    required_string_fields = (
        "request_id",
        "goal",
        "proposed_method",
        "decision_type",
        "authority_basis",
        "policy_version",
        "issued_at",
    )
    for field in required_string_fields:
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"DecisionReceipt requires non-empty {field}")
    decision_type = payload["decision_type"]
    if decision_type not in CANONICAL_DECISION_STATES:
        raise ValueError(f"Unknown decision_type: {decision_type!r}")
    if payload.get("execution_boundary") is None:
        raise ValueError("DecisionReceipt requires execution_boundary")
    constraints = payload.get("matched_constraints")
    if constraints is None:
        raise ValueError("DecisionReceipt requires matched_constraints proof")
    if not tuple(constraints):
        raise ValueError("DecisionReceipt requires at least one matched constraint")


def _hash_receipt_payload(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        _json_ready(payload),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _json_ready(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return _json_ready(asdict(value))
    return value


def to_receipt_dict(source: Any) -> dict[str, Any]:
    """Shared compatibility projection for receipt-like adapter payloads.

    Existing adapter serializers used ``constitutional_hash`` internally and
    ``policy_hash`` externally. This helper preserves ``None`` values and avoids
    stringifying missing fields while centralizing that projection.
    """
    if isinstance(source, DecisionReceipt):
        return source.to_receipt_dict()
    if isinstance(source, Mapping):
        payload = dict(source)
    elif hasattr(source, "model_dump"):
        payload = source.model_dump(mode="json")
    elif hasattr(source, "to_dict"):
        payload = source.to_dict()
    else:
        raise TypeError(f"Cannot project {type(source).__name__} to receipt dict")

    if "constitutional_hash" in payload and "policy_hash" not in payload:
        payload["policy_hash"] = payload.pop("constitutional_hash")
    return payload


__all__ = [
    "BASELINE_CONSTRAINT_MARKER",
    "DecisionReceipt",
    "ExecutionBoundary",
    "to_receipt_dict",
]
