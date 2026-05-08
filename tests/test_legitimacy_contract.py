"""Fail-closed legitimacy receipt and boundary contract tests."""

from __future__ import annotations

from typing import Any

import pytest

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


def test_human_approval_without_structure_invalid() -> None:
    receipt = _receipt(required_controls=("HUMAN_APPROVAL",))
    actual_call = normalize_actual_call(
        fallback_method="process",
        kwargs={"scope": "tenant-a", "subjects": ("subject-1",)},
    )

    with pytest.raises(LegitimacyInvariantError, match="Human approval"):
        validate_receipt_for_execution(receipt, actual_call=actual_call)


@pytest.mark.xfail(reason="Full replay verifier is explicitly deferred from the MVP")
def test_replay_failure_marks_goal_incomplete() -> None:
    raise NotImplementedError("Replay verifier follow-up")


def test_unknown_decision_type_fails_closed() -> None:
    with pytest.raises(ValueError, match="Unknown decision"):
        _receipt(decision_type="MAYBE_ALLOW")


def test_ambiguous_low_confidence_routes_to_review() -> None:
    assert route_ambiguous_decision(None) == "STRUCTURED_REVIEW_REQUIRED"
    assert route_ambiguous_decision(0.3) == "STRUCTURED_REVIEW_REQUIRED"
    assert route_ambiguous_decision(0.95) == "ALLOW"
