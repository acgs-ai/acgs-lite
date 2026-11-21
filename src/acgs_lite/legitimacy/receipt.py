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

RECEIPT_SCHEMA_V1 = 1
RECEIPT_SCHEMA_V2 = 2
# v2 hashes are domain-separated; v1 keeps the bare SHA-256 so stored hashes still verify.
RECEIPT_HASH_DOMAIN_V2 = b"acgs-receipt-v2\x00"

_V1_KEYS = (
    "request_id",
    "goal",
    "proposed_method",
    "decision_type",
    "authority_basis",
    "matched_constraints",
    "policy_version",
    "required_controls",
    "transformation_applied",
    "denial_or_review_rationale",
    "execution_boundary",
    "issued_at",
)
_V2_REQUIRED_KEYS = ("grant_id", "policy_digest", "method_id", "argument_digest")
_V2_OPTIONAL_KEYS = ("context_digest",)
V2_EXTENSION_KEYS = ("schema_version", *_V2_REQUIRED_KEYS, *_V2_OPTIONAL_KEYS)


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
    # v2 extension. ``None`` and ``1`` both mean v1; v2 is never inferred.
    schema_version: int | None = None
    grant_id: str | None = None
    policy_digest: str | None = None
    method_id: str | None = None
    argument_digest: str | None = None
    context_digest: str | None = None

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
        schema_version: int | None = None,
        grant_id: str | None = None,
        policy_digest: str | None = None,
        method_id: str | None = None,
        argument_digest: str | None = None,
        context_digest: str | None = None,
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
            "schema_version": schema_version,
            "grant_id": grant_id,
            "policy_digest": policy_digest,
            "method_id": method_id,
            "argument_digest": argument_digest,
            "context_digest": context_digest,
        }
        _validate_receipt_payload(data)
        receipt_hash = _hash_receipt_payload(_project_payload(data))
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
            schema_version=schema_version,
            grant_id=grant_id,
            policy_digest=policy_digest,
            method_id=method_id,
            argument_digest=argument_digest,
            context_digest=context_digest,
        )

    def __post_init__(self) -> None:
        full = asdict(self)
        full.pop("receipt_hash", None)
        # Validate the full field set first so v2 fields cannot hide in a v1 receipt.
        _validate_receipt_payload(full)
        if self.receipt_hash != _hash_receipt_payload(_project_payload(full)):
            raise ValueError("receipt_hash does not match canonical receipt payload")

    def to_receipt_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        """Project this receipt to its canonical wire fields for its schema version.

        v1: exactly the original keys (plus ``schema_version`` only when set to 1).
        v2: the v1 keys (nulls kept), ``schema_version: 2`` and every non-None v2
        extension key.
        """
        payload = _project_payload(asdict(self))
        if self.schema_version is not None and "schema_version" not in payload:
            payload["schema_version"] = self.schema_version
        if include_hash:
            payload["receipt_hash"] = self.receipt_hash
        return payload

    def verify_hash(self) -> bool:
        """Verify receipt integrity against the canonical hash payload."""
        full = asdict(self)
        full.pop("receipt_hash", None)
        try:
            _validate_receipt_payload(full)
        except ValueError:
            return False
        return self.receipt_hash == _hash_receipt_payload(_project_payload(full))


def _schema_version(payload: Mapping[str, Any]) -> int:
    version = payload.get("schema_version")
    if version is None:
        return RECEIPT_SCHEMA_V1
    # bool is an int subclass; True must not read as v1.
    if type(version) is not int or version not in (RECEIPT_SCHEMA_V1, RECEIPT_SCHEMA_V2):
        raise ValueError(f"Unsupported receipt schema_version: {version!r}")
    return version


def _project_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Hash/wire payload: v1 keys only for v1; v1 keys plus non-None v2 keys for v2."""
    projected = {key: payload[key] for key in _V1_KEYS if key in payload}
    if _schema_version(payload) == RECEIPT_SCHEMA_V2:
        for key in V2_EXTENSION_KEYS:
            if payload.get(key) is not None:
                projected[key] = payload[key]
    return projected


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
    if _schema_version(payload) == RECEIPT_SCHEMA_V1:
        smuggled = [key for key in V2_EXTENSION_KEYS[1:] if payload.get(key) is not None]
        if smuggled:
            raise ValueError(f"v1 receipt cannot carry v2 fields: {', '.join(smuggled)}")
        return
    for key in _V2_REQUIRED_KEYS:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"v2 DecisionReceipt requires non-empty {key}")
    for key in _V2_OPTIONAL_KEYS:
        value = payload.get(key)
        if value is not None and (not isinstance(value, str) or not value):
            raise ValueError(f"v2 DecisionReceipt {key} must be None or a non-empty string")


def _hash_receipt_payload(payload: Mapping[str, Any]) -> str:
    """SHA-256 over canonical JSON; v2 payloads are prefixed with the v2 domain."""
    canonical = json.dumps(
        _json_ready(payload),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if _schema_version(payload) == RECEIPT_SCHEMA_V2:
        return hashlib.sha256(RECEIPT_HASH_DOMAIN_V2 + canonical).hexdigest()
    return hashlib.sha256(canonical).hexdigest()


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
    "RECEIPT_HASH_DOMAIN_V2",
    "RECEIPT_SCHEMA_V1",
    "RECEIPT_SCHEMA_V2",
    "V2_EXTENSION_KEYS",
    "DecisionReceipt",
    "ExecutionBoundary",
    "to_receipt_dict",
]
