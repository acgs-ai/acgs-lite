"""Arguments mutated between authorization and the call are refused.

``GovernedCallable`` digests the bound arguments at the gate, then runs the Z3
gate and payload validation, then calls the function. A list/dict argument
mutated inside that window (here by a validation hook; equally another thread)
would reach the callable unchecked, so the wrapper re-digests just before the
call and denies on mismatch. Every test goes through the decorated function.
"""

from __future__ import annotations

from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import AuthorizationProfile, LegitimacyInvariantError
from acgs_lite.legitimacy.ledger import AttemptStatus
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner


def _compat() -> GovernedCallable:
    return GovernedCallable(Constitution.default())


def _production() -> GovernedCallable:
    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    return GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        receipt_signer=signer,
        trusted_execution_keys={signer.key_id: signer.public_key_hex()},
    )


def _mutate_during_validation(
    monkeypatch: pytest.MonkeyPatch, guard: GovernedCallable, mutate: Any
) -> None:
    """Run ``mutate`` once, from inside the first execute-time validation."""
    real = guard.engine.validate
    pending = [mutate]

    def validate(*args: Any, **kwargs: Any) -> Any:
        if pending:
            pending.pop()()
        return real(*args, **kwargs)

    monkeypatch.setattr(guard.engine, "validate", validate)


@pytest.mark.parametrize("make_guard", [_compat, _production])
def test_list_mutated_during_validation_is_denied(
    monkeypatch: pytest.MonkeyPatch, make_guard: Any
) -> None:
    calls: list[list[str]] = []
    guard = make_guard()

    @guard
    def send(recipients: list[str]) -> str:
        calls.append(list(recipients))
        return "sent"

    recipients = ["alice"]
    grant = send.issue_grant(recipients)
    _mutate_during_validation(monkeypatch, guard, lambda: recipients.append("mallory"))
    with pytest.raises(LegitimacyInvariantError, match="arguments changed after authorization"):
        send(recipients, execution_grant=grant, execution_attempt_id="att-1")
    assert calls == []
    if guard.authorization_profile is AuthorizationProfile.PRODUCTION:
        assert guard._ledger.attempt_status_for_grant(grant.grant_id) is AttemptStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize("make_guard", [_compat, _production])
async def test_async_dict_mutated_during_validation_is_denied(
    monkeypatch: pytest.MonkeyPatch, make_guard: Any
) -> None:
    calls: list[dict[str, int]] = []
    guard = make_guard()

    @guard
    async def transfer(order: dict[str, int]) -> str:
        calls.append(dict(order))
        return "sent"

    order = {"amount": 10}
    grant = transfer.issue_grant(order)
    _mutate_during_validation(monkeypatch, guard, lambda: order.update(amount=10_000))
    with pytest.raises(LegitimacyInvariantError, match="arguments changed after authorization"):
        await transfer(order, execution_grant=grant, execution_attempt_id="att-1")
    assert calls == []
    if guard.authorization_profile is AuthorizationProfile.PRODUCTION:
        assert guard._ledger.attempt_status_for_grant(grant.grant_id) is AttemptStatus.FAILED


def test_mutation_into_undigestible_value_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    guard = _compat()

    @guard
    def send(items: list[Any]) -> str:
        calls.append(len(items))
        return "sent"

    items: list[Any] = ["a"]
    grant = send.issue_grant(items)
    _mutate_during_validation(monkeypatch, guard, lambda: items.append(items))
    with pytest.raises(LegitimacyInvariantError):
        send(items, execution_grant=grant)
    assert calls == []


@pytest.mark.parametrize("make_guard", [_compat, _production])
def test_unmutated_call_runs(make_guard: Any) -> None:
    calls: list[list[str]] = []
    guard = make_guard()

    @guard
    def send(recipients: list[str], note: str = "hi") -> str:
        calls.append(list(recipients))
        return "sent"

    grant = send.issue_grant(["alice"])
    assert send(["alice"], execution_grant=grant, execution_attempt_id="att-1") == "sent"
    assert calls == [["alice"]]


@pytest.mark.asyncio
@pytest.mark.parametrize("make_guard", [_compat, _production])
async def test_async_unmutated_call_runs(make_guard: Any) -> None:
    calls: list[dict[str, int]] = []
    guard = make_guard()

    @guard
    async def transfer(order: dict[str, int]) -> str:
        calls.append(dict(order))
        return "sent"

    grant = transfer.issue_grant({"amount": 10})
    assert await transfer({"amount": 10}, execution_grant=grant) == "sent"
    assert calls == [{"amount": 10}]
