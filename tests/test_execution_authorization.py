"""Production execution-grant contract: forged auth must invoke the callable 0 times."""

from __future__ import annotations

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import (
    AuthorizationProfile,
    DecisionReceipt,
    ExecutionBoundary,
    ExecutionGrant,
    LegitimacyInvariantError,
)


def _receipt(*, method: str = "transfer") -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-forged",
        goal="Move funds",
        proposed_method=method,
        decision_type="ALLOW",
        authority_basis="role:forger",
        matched_constraints=("forged-constraint",),
        policy_version="policy-v1",
        execution_boundary=ExecutionBoundary(
            allowed_method=method,
            allowed_scope=None,
            allowed_subjects=(),
            expires_at=None,
            single_use=False,
        ),
    )


def test_raw_receipt_rejected_in_production_profile() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    with pytest.raises(LegitimacyInvariantError, match="unsigned"):
        transfer("acct-1", 10, decision_receipt=_receipt())
    assert calls == []


def test_compatibility_profile_still_accepts_raw_receipt() -> None:
    calls: list[str] = []

    @GovernedCallable(Constitution.default())
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    result = transfer("acct-1", 10, decision_receipt=_receipt())
    assert result == "sent"
    assert calls == ["acct-1:10"]


def test_issue_grant_then_execute_in_production() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)
    assert isinstance(grant, ExecutionGrant)
    assert transfer("acct-1", 10, execution_grant=grant) == "sent"
    assert calls == ["acct-1:10"]


def test_argument_substitution_inside_allowed_subject_blocked() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)
    with pytest.raises(LegitimacyInvariantError, match="invocation"):
        transfer("acct-1", 1_000_000, execution_grant=grant)
    assert calls == []


def test_method_spoof_via_governance_method_kwarg_blocked() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)
    with pytest.raises(LegitimacyInvariantError):
        transfer(
            "acct-1",
            10,
            execution_grant=grant,
            governance_method="allowed_method",
        )
    assert calls == []


def test_foreign_guard_grant_blocked() -> None:
    calls: list[str] = []
    left = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )
    right = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @left
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    @right
    def other(account_id: str, amount: int) -> str:
        return "other"

    grant = other.issue_grant("acct-1", 10)
    with pytest.raises(LegitimacyInvariantError, match="grant"):
        transfer("acct-1", 10, execution_grant=grant)
    assert calls == []


def test_both_authorization_kwargs_blocked() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)
    with pytest.raises(LegitimacyInvariantError, match="one authorization"):
        transfer("acct-1", 10, execution_grant=grant, decision_receipt=_receipt())
    assert calls == []


def test_issue_grant_does_not_invoke_target() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    transfer.issue_grant("acct-1", 10)
    assert calls == []


def test_issue_grant_rejects_caller_created_receipt() -> None:
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        return "sent"

    with pytest.raises(TypeError, match="caller-created"):
        transfer.issue_grant("acct-1", 10, receipt=_receipt())  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_async_wrapper_rejects_raw_receipt_in_production() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    async def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    with pytest.raises(LegitimacyInvariantError, match="unsigned"):
        await transfer("acct-1", 10, decision_receipt=_receipt())
    assert calls == []


@pytest.mark.asyncio
async def test_async_wrapper_argument_substitution_blocked() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    async def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)
    with pytest.raises(LegitimacyInvariantError, match="invocation"):
        await transfer("acct-1", 99, execution_grant=grant)
    assert calls == []


def test_hand_constructed_grant_blocked() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    real = transfer.issue_grant("acct-1", 10)
    forged = ExecutionGrant(
        grant_id=real.grant_id,
        issuer_id=real.issuer_id,
        receipt=real.receipt,
        method_id=real.method_id,
        argument_digest="0" * 64,
        policy_digest=real.policy_digest,
        scope=real.scope,
        subjects=real.subjects,
        issued_at=real.issued_at,
        expires_at=real.expires_at,
        binding_mac=real.binding_mac,
    )
    with pytest.raises(LegitimacyInvariantError, match="grant"):
        transfer("acct-1", 10, execution_grant=forged)
    assert calls == []


def test_grant_id_rejected_until_ledger() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    with pytest.raises(LegitimacyInvariantError, match="ledger"):
        transfer("acct-1", 10, grant_id="grant-1")
    assert calls == []


def test_legacy_signed_receipt_rejected_in_production() -> None:
    pytest.importorskip("cryptography")
    from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner, sign_receipt

    calls: list[str] = []
    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        trusted_issuer_keys={signer.key_id: signer.public_key_hex()},
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    signed = sign_receipt(_receipt(), signer)
    with pytest.raises(LegitimacyInvariantError, match="unsigned"):
        transfer("acct-1", 10, signed_receipt=signed)
    assert calls == []
