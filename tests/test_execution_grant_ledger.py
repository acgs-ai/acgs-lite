"""Single-use grant ledger: one winner, retry recovers, second attempt blocked."""

from __future__ import annotations

import threading

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import AuthorizationProfile, ExecutionGrant, LegitimacyInvariantError


def test_second_attempt_on_single_use_grant_blocked() -> None:
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
    assert grant.single_use is True
    assert transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1") == "sent"
    with pytest.raises(LegitimacyInvariantError, match="already consumed"):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-2")
    assert calls == ["acct-1:10"]


def test_retry_same_attempt_recovers_without_reexecution() -> None:
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
    first = transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    second = transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert first == second == "sent"
    assert calls == ["acct-1:10"]


def test_implicit_attempt_id_is_single_use() -> None:
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
    assert transfer("acct-1", 10, execution_grant=grant) == "sent"
    with pytest.raises(LegitimacyInvariantError, match="already consumed"):
        transfer("acct-1", 10, execution_grant=grant)
    assert calls == ["acct-1:10"]


def test_concurrent_single_use_has_one_winner() -> None:
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
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def worker(attempt_id: str) -> None:
        barrier.wait()
        try:
            outcomes.append(
                transfer(
                    "acct-1",
                    10,
                    execution_grant=grant,
                    execution_attempt_id=attempt_id,
                )
            )
        except Exception as exc:
            outcomes.append(exc)

    threads = [
        threading.Thread(target=worker, args=("att-a",)),
        threading.Thread(target=worker, args=("att-b",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    wins = [item for item in outcomes if item == "sent"]
    losses = [item for item in outcomes if isinstance(item, LegitimacyInvariantError)]
    assert wins == ["sent"]
    assert len(losses) == 1
    assert calls == ["acct-1:10"]


@pytest.mark.asyncio
async def test_async_retry_recovers_one_terminal_record() -> None:
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
    assert isinstance(grant, ExecutionGrant)
    first = await transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    second = await transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert first == second == "sent"
    assert calls == ["acct-1:10"]
