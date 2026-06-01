"""Pinned governance-regression invariants for PR safety gates."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import acgs_lite
from acgs_lite._meta import CONSTITUTIONAL_HASH
from acgs_lite.constitution import Constitution
from acgs_lite.legitimacy import (
    ActualCall,
    DecisionReceipt,
    ExecutionBoundary,
    LegitimacyInvariantError,
    validate_receipt_for_execution,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "governance_regression"
    / "expected_invariants.json"
)


def _expected_invariants() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _boundary(
    *,
    method: str = "execute_transfer",
    scope: str = "tenant-a",
    subjects: tuple[str, ...] = ("account-123",),
    expires_at: str | None = None,
) -> ExecutionBoundary:
    return ExecutionBoundary(
        allowed_method=method,
        allowed_scope=scope,
        allowed_subjects=subjects,
        expires_at=expires_at,
        single_use=True,
    )


def _receipt(
    *,
    method: str = "execute_transfer",
    scope: str = "tenant-a",
    subjects: tuple[str, ...] = ("account-123",),
    expires_at: str | None = None,
) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-governance-regression",
        goal="Execute approved governance-regression side effect",
        proposed_method=method,
        decision_type="ALLOW",
        authority_basis="role:executor",
        matched_constraints=("governance-regression-policy",),
        policy_version=f"constitution:{CONSTITUTIONAL_HASH}",
        execution_boundary=_boundary(
            method=method,
            scope=scope,
            subjects=subjects,
            expires_at=expires_at,
        ),
        issued_at="2026-01-01T00:00:00+00:00",
    )


def _actual_call(
    *,
    method: str = "execute_transfer",
    scope: str = "tenant-a",
    subjects: tuple[str, ...] = ("account-123",),
) -> ActualCall:
    return ActualCall(method=method, scope=scope, subjects=subjects)


def _receipt_rejection_cases() -> dict[str, Callable[[], None]]:
    def missing_receipt() -> None:
        validate_receipt_for_execution(None, actual_call=_actual_call())

    def tampered_receipt() -> None:
        receipt = _receipt()
        object.__setattr__(receipt, "receipt_hash", "0" * 64)
        validate_receipt_for_execution(receipt, actual_call=_actual_call())

    def stale_receipt() -> None:
        expired_at = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
        receipt = _receipt(expires_at=expired_at)
        validate_receipt_for_execution(receipt, actual_call=_actual_call())

    def boundary_mismatched_receipt() -> None:
        validate_receipt_for_execution(
            _receipt(),
            actual_call=_actual_call(method="wire_funds", subjects=("account-999",)),
        )

    return {
        "missing_receipt": missing_receipt,
        "tampered_receipt": tampered_receipt,
        "stale_receipt": stale_receipt,
        "boundary_mismatched_receipt": boundary_mismatched_receipt,
    }


def test_constitutional_hash_matches_versioned_invariant_fixture() -> None:
    expected = _expected_invariants()

    assert acgs_lite.__constitutional_hash__ == CONSTITUTIONAL_HASH
    assert Constitution.default().hash == CONSTITUTIONAL_HASH
    assert expected["constitutional_hash"] == CONSTITUTIONAL_HASH


def test_valid_receipt_binding_still_allows_matching_execution_boundary() -> None:
    expected = _expected_invariants()["receipt_binding"]
    receipt = _receipt()

    validate_receipt_for_execution(receipt, actual_call=_actual_call())

    assert receipt.decision_type == expected["valid_decision_type"]


@pytest.mark.parametrize("case_name", sorted(_receipt_rejection_cases()))
def test_receipt_binding_rejections_match_versioned_invariant_fixture(case_name: str) -> None:
    expected = _expected_invariants()["receipt_binding"]["rejected_cases"]
    rejection_case = _receipt_rejection_cases()[case_name]

    with pytest.raises(LegitimacyInvariantError) as exc_info:
        rejection_case()

    assert case_name in expected
    assert expected[case_name]["error_contains"] in str(exc_info.value)
