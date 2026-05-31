"""Fail-closed legitimacy receipt and boundary contract tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine import GovernanceEngine
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import (
    DecisionReceipt,
    ExecutionBoundary,
    LegitimacyInvariantError,
    normalize_actual_call,
    route_ambiguous_decision,
    validate_receipt_for_execution,
)


def _boundary(
    method: str = "process", subjects: tuple[str, ...] = ("subject-1",)
) -> ExecutionBoundary:
    return ExecutionBoundary(
        allowed_method=method,
        allowed_scope="tenant-a",
        allowed_subjects=subjects,
        expires_at=None,
        single_use=True,
    )


def _receipt(
    *,
    method: str = "process",
    decision_type: str = "ALLOW",
    authority_basis: str = "role:operator",
    policy_version: str = "policy-v1",
    required_controls: tuple[str, ...] = (),
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
        execution_boundary=_boundary(method),
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
    with pytest.raises(ValueError, match="authority_basis"):
        _receipt(authority_basis="")


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
    with pytest.raises(ValueError, match="Unknown decision"):
        _receipt(decision_type="MAYBE_ALLOW")


def test_ambiguous_low_confidence_routes_to_review() -> None:
    assert route_ambiguous_decision(None) == "STRUCTURED_REVIEW_REQUIRED"
    assert route_ambiguous_decision(0.3) == "STRUCTURED_REVIEW_REQUIRED"
    assert route_ambiguous_decision(0.95) == "ALLOW"
