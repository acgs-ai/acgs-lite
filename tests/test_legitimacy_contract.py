"""Fail-closed legitimacy receipt and boundary contract tests."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine import GovernanceEngine
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import (
    CANONICAL_DECISION_STATES,
    DecisionReceipt,
    DecisionState,
    ExecutionBoundary,
    LegitimacyInvariantError,
    call_matches,
    canonicalize_decision_state,
    is_allow_state,
    normalize_actual_call,
    route_ambiguous_decision,
    to_receipt_dict,
    validate_receipt_for_execution,
)


def _boundary(
    method: str = "process",
    subjects: tuple[str, ...] = ("subject-1",),
    *,
    expires_at: str | None = None,
) -> ExecutionBoundary:
    return ExecutionBoundary(
        allowed_method=method,
        allowed_scope="tenant-a",
        allowed_subjects=subjects,
        expires_at=expires_at,
        single_use=True,
    )


def _receipt(
    *,
    method: str = "process",
    decision_type: str = "ALLOW",
    authority_basis: str = "role:operator",
    policy_version: str = "policy-v1",
    required_controls: tuple[str, ...] = (),
    execution_boundary: ExecutionBoundary | None = None,
) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-1",
        goal="Process an authorized account request",
        proposed_method=method,
        decision_type=decision_type,
        authority_basis=authority_basis,
        matched_constraints=("baseline-policy-rule",),
        policy_version=policy_version,
        required_controls=required_controls,
        transformation_applied=None,
        denial_or_review_rationale=None,
        execution_boundary=execution_boundary or _boundary(method),
    )


def _tampered_receipt(field: str, value: Any) -> DecisionReceipt:
    receipt = _receipt()
    object.__setattr__(receipt, field, value)
    return receipt


def test_legitimacy_public_api_stable_exports() -> None:
    import acgs_lite.legitimacy as legitimacy

    expected_exports = {
        "BASELINE_CONSTRAINT_MARKER",
        "CANONICAL_DECISION_STATES",
        "ActualCall",
        "DecisionReceipt",
        "DecisionState",
        "ExecutionBoundary",
        "LegitimacyInvariantError",
        "call_matches",
        "canonicalize_decision_state",
        "is_allow_state",
        "normalize_actual_call",
        "route_ambiguous_decision",
        "to_receipt_dict",
        "validate_receipt_for_execution",
    }

    assert expected_exports.issubset(set(legitimacy.__all__))
    for name in expected_exports:
        assert getattr(legitimacy, name) is not None

    assert legitimacy.DecisionReceipt is DecisionReceipt
    assert legitimacy.ExecutionBoundary is ExecutionBoundary
    assert legitimacy.DecisionState is DecisionState
    assert legitimacy.CANONICAL_DECISION_STATES is CANONICAL_DECISION_STATES
    assert legitimacy.call_matches is call_matches
    assert legitimacy.canonicalize_decision_state is canonicalize_decision_state
    assert legitimacy.is_allow_state is is_allow_state
    assert legitimacy.to_receipt_dict is to_receipt_dict
    assert set(CANONICAL_DECISION_STATES) == {
        "ALLOW",
        "ALLOW_WITH_CONTROLS",
        "TRANSFORM_REQUIRED",
        "REPLAN_REQUIRED",
        "STRUCTURED_REVIEW_REQUIRED",
        "DENY_OPERATION_WITH_ALTERNATIVE",
        "DENY_GOAL",
        "HARD_DENY",
    }
    assert tuple(field.name for field in dataclasses.fields(DecisionReceipt)) == (
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
        "receipt_hash",
    )
    assert tuple(field.name for field in dataclasses.fields(ExecutionBoundary)) == (
        "allowed_method",
        "allowed_scope",
        "allowed_subjects",
        "expires_at",
        "single_use",
    )


def test_missing_receipt_blocks_execution() -> None:
    calls: list[str] = []

    @GovernedCallable()
    def process(input: str) -> str:
        calls.append(input)
        return input

    with pytest.raises(LegitimacyInvariantError, match="No legitimacy receipt"):
        process("safe data")

    assert calls == []


def test_invalid_receipt_type_blocks_execution() -> None:
    with pytest.raises(LegitimacyInvariantError, match="Invalid legitimacy receipt type"):
        validate_receipt_for_execution("not-a-receipt")  # type: ignore[arg-type]


def test_missing_authority_basis_fails_closed() -> None:
    calls: list[str] = []
    receipt = _tampered_receipt("authority_basis", "")

    @GovernedCallable()
    def process(input: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        calls.append(input)
        return input

    with pytest.raises(LegitimacyInvariantError, match="authority basis"):
        process(
            "safe data",
            scope="tenant-a",
            subjects=("subject-1",),
            decision_receipt=receipt,
        )

    assert calls == []


def test_missing_policy_version_fails_closed() -> None:
    with pytest.raises(ValueError, match="policy_version"):
        _receipt(policy_version="")


def test_prohibited_method_with_legitimate_goal() -> None:
    receipt = _receipt(method="read_profile")
    actual_call = normalize_actual_call(
        fallback_method="delete_profile",
        kwargs={"scope": "tenant-a", "subjects": ("subject-1",)},
    )

    with pytest.raises(LegitimacyInvariantError, match="boundary mismatch"):
        validate_receipt_for_execution(receipt, actual_call=actual_call)


def test_prohibited_goal_hard_denies() -> None:
    receipt = _receipt(method="process", decision_type="HARD_DENY")
    actual_call = normalize_actual_call(
        fallback_method="process",
        kwargs={"scope": "tenant-a", "subjects": ("subject-1",)},
    )

    with pytest.raises(LegitimacyInvariantError, match="HARD_DENY"):
        validate_receipt_for_execution(receipt, actual_call=actual_call)


def test_execution_boundary_mismatch_blocks() -> None:
    calls: list[dict[str, Any]] = []
    receipt = _receipt(method="allowed_method")

    @GovernedCallable()
    def blocked_call(**kwargs: Any) -> str:
        calls.append(kwargs)
        return "executed"

    with pytest.raises(LegitimacyInvariantError, match="boundary mismatch"):
        blocked_call(
            governance_method="other_method",
            scope="tenant-a",
            subjects=("subject-1",),
            decision_receipt=receipt,
        )

    assert calls == []


def test_stale_expired_receipt_blocks_side_effect() -> None:
    calls: list[str] = []
    expired_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    receipt = _receipt(execution_boundary=_boundary("process", expires_at=expired_at))

    @GovernedCallable()
    def process(input: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        calls.append(input)
        return "executed"

    with pytest.raises(LegitimacyInvariantError, match="boundary mismatch"):
        process(
            "safe data",
            scope="tenant-a",
            subjects=("subject-1",),
            decision_receipt=receipt,
        )

    assert calls == []


def test_tampered_receipt_hash_blocks_side_effect() -> None:
    calls: list[str] = []
    receipt = _tampered_receipt("receipt_hash", "0" * 64)

    @GovernedCallable()
    def process(input: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        calls.append(input)
        return "executed"

    with pytest.raises(LegitimacyInvariantError, match="integrity"):
        process(
            "safe data",
            scope="tenant-a",
            subjects=("subject-1",),
            decision_receipt=receipt,
        )

    assert calls == []


def test_execution_boundary_mismatch_on_positional_subject_blocks_side_effect() -> None:
    calls: list[str] = []
    receipt = DecisionReceipt.create(
        request_id="req-positional-subject",
        goal="Email one authorized customer",
        proposed_method="send_email",
        decision_type="ALLOW",
        authority_basis="role:operator",
        matched_constraints=("customer-contact-policy",),
        policy_version="policy-v1",
        execution_boundary=_boundary("send_email", subjects=("customer-123",)),
    )

    @GovernedCallable()
    def send_email(customer_id: str, *, scope: str) -> str:
        calls.append(customer_id)
        return "sent"

    with pytest.raises(LegitimacyInvariantError, match="boundary mismatch"):
        send_email("customer-999", scope="tenant-a", decision_receipt=receipt)

    assert calls == []


def test_argument_substitution_outside_receipt_subjects_blocks() -> None:
    receipt = DecisionReceipt.create(
        request_id="req-subject",
        goal="Email an authorized customer",
        proposed_method="send_email",
        decision_type="ALLOW",
        authority_basis="role:operator",
        matched_constraints=("customer-contact-policy",),
        policy_version="policy-v1",
        execution_boundary=_boundary("send_email", subjects=("customer-123",)),
    )
    substituted_call = normalize_actual_call(
        fallback_method="send_email",
        kwargs={"scope": "tenant-a", "subjects": ("customer-999",)},
    )

    with pytest.raises(LegitimacyInvariantError, match="boundary mismatch"):
        validate_receipt_for_execution(receipt, actual_call=substituted_call)


def test_human_approval_without_structure_invalid() -> None:
    receipt = _receipt(required_controls=("HUMAN_APPROVAL",))
    actual_call = normalize_actual_call(
        fallback_method="process",
        kwargs={"scope": "tenant-a", "subjects": ("subject-1",)},
    )

    with pytest.raises(LegitimacyInvariantError, match="Human approval"):
        validate_receipt_for_execution(receipt, actual_call=actual_call)


def test_missing_constitution_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Constitution file not found"):
        Constitution.from_yaml(tmp_path / "missing-constitution.yaml")


def test_malformed_constitution_fails_closed() -> None:
    with pytest.raises(ValueError, match="rules"):
        Constitution.from_yaml_str("name: malformed\nrules: not-a-list\n")


def test_denied_action_produces_audit_evidence() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="no-wire-transfer",
                text="Block wire transfers without approval",
                severity=Severity.CRITICAL,
                keywords=["wire transfer"],
            )
        ],
        name="side-effect-policy",
    )
    audit_log = AuditLog()
    engine = GovernanceEngine(
        constitution,
        audit_log=audit_log,
        strict=False,
        audit_mode="full",
    )

    result = engine.validate("wire transfer $1000", agent_id="runtime")

    assert result.valid is False
    denied_entries = audit_log.query(agent_id="runtime", entry_type="validation", valid=False)
    assert len(denied_entries) == 1
    assert denied_entries[0].violations == ["no-wire-transfer"]
    assert audit_log.verify_chain() is True


def test_replay_rejects_tampered_audit_evidence() -> None:
    audit_log = AuditLog()
    audit_log.record(AuditEntry(id="ev-1", type="validation", action="allowed", valid=True))
    audit_log.record(AuditEntry(id="ev-2", type="validation", action="denied", valid=False))

    audit_log._entries[0].action = "tampered"  # deliberate integrity probe

    assert audit_log.verify_chain() is False


def test_unknown_decision_type_fails_closed() -> None:
    calls: list[str] = []
    receipt = _tampered_receipt("decision_type", "MAYBE_ALLOW")

    @GovernedCallable()
    def process(input: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        calls.append(input)
        return "executed"

    with pytest.raises(LegitimacyInvariantError, match="Unknown decision"):
        process(
            "safe data",
            scope="tenant-a",
            subjects=("subject-1",),
            decision_receipt=receipt,
        )

    assert calls == []


def test_unverifiable_audit_evidence_blocks_side_effect() -> None:
    calls: list[str] = []
    guard = GovernedCallable()

    @guard
    def process(input: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        calls.append(input)
        return "executed"

    guard.audit_log.record(AuditEntry(id="ev-1", type="validation", action="allowed", valid=True))
    guard.audit_log.record(AuditEntry(id="ev-2", type="validation", action="allowed", valid=True))
    guard.audit_log._entries[0].action = "tampered"  # deliberate integrity probe

    assert guard.audit_log.verify_chain() is False

    with pytest.raises(LegitimacyInvariantError, match="Audit evidence"):
        process(
            "safe data",
            scope="tenant-a",
            subjects=("subject-1",),
            decision_receipt=_receipt(),
        )

    assert calls == []


def test_ambiguous_low_confidence_routes_to_review() -> None:
    assert route_ambiguous_decision(None) == "STRUCTURED_REVIEW_REQUIRED"
    assert route_ambiguous_decision(0.3) == "STRUCTURED_REVIEW_REQUIRED"
    assert route_ambiguous_decision(0.95) == "ALLOW"
