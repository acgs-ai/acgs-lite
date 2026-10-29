"""Single-use grant ledger: one winner, retry recovers, second attempt blocked."""

from __future__ import annotations

import asyncio
import threading

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import AuthorizationProfile, ExecutionGrant, LegitimacyInvariantError
from acgs_lite.legitimacy.ledger import AttemptStatus
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner


def _production_signing() -> dict[str, object]:
    """Pinned, non-ephemeral Ed25519 execution signer the production profile requires."""
    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    return {
        "receipt_signer": signer,
        "trusted_execution_keys": {signer.key_id: signer.public_key_hex()},
    }


def test_second_attempt_on_single_use_grant_blocked() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        **_production_signing(),
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
        **_production_signing(),
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
        **_production_signing(),
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


def test_in_flight_same_attempt_does_not_reexecute() -> None:
    calls: list[str] = []
    started = threading.Event()
    release = threading.Event()
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        **_production_signing(),
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        started.set()
        assert release.wait(timeout=2)
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)
    result: list[object] = []

    def first() -> None:
        result.append(transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1"))

    thread = threading.Thread(target=first)
    thread.start()
    assert started.wait(timeout=2)
    with pytest.raises(LegitimacyInvariantError, match="already in flight"):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    release.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert result == ["sent"]
    assert calls == ["acct-1:10"]


def test_raised_attempt_is_partial_and_retry_does_not_reexecute() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        **_production_signing(),
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        raise RuntimeError("downstream failed")

    grant = transfer.issue_grant("acct-1", 10)
    with pytest.raises(RuntimeError, match="downstream failed"):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    # Once user code starts, a raised exception cannot prove that no external
    # side effect occurred. Recovery therefore exposes PARTIAL, never retries.
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert calls == ["acct-1:10"]


def test_concurrent_single_use_has_one_winner() -> None:
    calls: list[str] = []
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        **_production_signing(),
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
        **_production_signing(),
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


def _production_guard() -> GovernedCallable:
    return GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        **_production_signing(),
    )


def test_keyboard_interrupt_settles_attempt_partial() -> None:
    calls: list[str] = []
    guard = _production_guard()

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        raise KeyboardInterrupt

    grant = transfer.issue_grant("acct-1", 10)
    with pytest.raises(KeyboardInterrupt):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert guard._ledger.attempt_status_for_grant(grant.grant_id) is AttemptStatus.PARTIAL
    # Recovery reports the settled status, never "already in flight", and never re-runs.
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert calls == ["acct-1:10"]


def test_system_exit_before_call_settles_attempt_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    guard = _production_guard()

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)

    def interrupt(*_args: object, **_kwargs: object) -> object:
        raise SystemExit(1)

    monkeypatch.setattr(guard.engine, "validate", interrupt)
    with pytest.raises(SystemExit):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert guard._ledger.attempt_status_for_grant(grant.grant_id) is AttemptStatus.FAILED
    with pytest.raises(LegitimacyInvariantError, match="already failed"):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert calls == []


@pytest.mark.asyncio
async def test_closed_coroutine_settles_attempt_partial() -> None:
    calls: list[str] = []
    guard = _production_guard()

    @guard
    async def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        await asyncio.sleep(0)
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)
    coro = transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    coro.send(None)  # gate, ledger consume, then suspend inside the callable
    assert guard._ledger.attempt_status_for_grant(grant.grant_id) is AttemptStatus.STARTED
    coro.close()  # GeneratorExit at the await; must settle, then propagate cleanly
    assert guard._ledger.attempt_status_for_grant(grant.grant_id) is AttemptStatus.PARTIAL
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        await transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert calls == ["acct-1:10"]


def test_keyboard_interrupt_propagates_in_compat_profile() -> None:
    calls: list[str] = []
    guard = GovernedCallable(Constitution.default())

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        raise KeyboardInterrupt

    grant = transfer.issue_grant("acct-1", 10)
    with pytest.raises(KeyboardInterrupt):
        transfer("acct-1", 10, execution_grant=grant)
    assert calls == ["acct-1:10"]


@pytest.mark.asyncio
async def test_closed_coroutine_propagates_in_compat_profile() -> None:
    calls: list[str] = []
    guard = GovernedCallable(Constitution.default())

    @guard
    async def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        await asyncio.sleep(0)
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)
    coro = transfer("acct-1", 10, execution_grant=grant)
    coro.send(None)
    coro.close()
    assert calls == ["acct-1:10"]
