"""Single-use grant ledger: one winner, retry recovers, second attempt blocked."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest

from acgs_lite.audit import AuditEntry, AuditLog, JSONLAuditBackend
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


# --- interrupts while committing the completed result -------------------------


def _interrupt_ledger_completion(
    guard: GovernedCallable, monkeypatch: pytest.MonkeyPatch, *, after_write: bool
) -> None:
    """Raise KeyboardInterrupt from the COMPLETED ledger write only.

    Other statuses pass through, so the interrupt handler's own PARTIAL write is
    not intercepted by the same patch.
    """
    original = guard._ledger.finalize

    def finalize(**kwargs: object) -> object:
        if kwargs.get("status") is not AttemptStatus.COMPLETED:
            return original(**kwargs)  # type: ignore[arg-type]
        if after_write:
            original(**kwargs)  # type: ignore[arg-type]
        raise KeyboardInterrupt

    monkeypatch.setattr(guard._ledger, "finalize", finalize)


def _attempt(guard: GovernedCallable, attempt_id: str = "att-1") -> object:
    return guard._ledger._attempts[attempt_id]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_interrupt_before_completed_write_settles_partial(
    monkeypatch: pytest.MonkeyPatch, asynchronous: bool
) -> None:
    calls: list[str] = []
    guard = _production_guard()

    def body(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    if asynchronous:

        async def transfer(account_id: str, amount: int) -> str:
            return body(account_id, amount)

    else:

        def transfer(account_id: str, amount: int) -> str:  # type: ignore[misc]
            return body(account_id, amount)

    governed = guard(transfer)
    grant = governed.issue_grant("acct-1", 10)
    _interrupt_ledger_completion(guard, monkeypatch, after_write=False)

    def call() -> object:
        result = governed("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
        return asyncio.run(result) if asynchronous else result  # type: ignore[arg-type]

    with pytest.raises(KeyboardInterrupt):
        call()
    record = _attempt(guard)
    assert record.status is AttemptStatus.PARTIAL  # type: ignore[attr-defined]
    assert record.error_code == "interrupted"  # type: ignore[attr-defined]
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        call()
    assert calls == ["acct-1:10"]


def test_interrupt_after_ledger_commit_without_durable_audit_keeps_completed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Without durable audit the ledger write is the commit: it is not downgraded.
    calls: list[str] = []
    guard = _production_guard()

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)
    _interrupt_ledger_completion(guard, monkeypatch, after_write=True)
    with pytest.raises(KeyboardInterrupt):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert _attempt(guard).status is AttemptStatus.COMPLETED  # type: ignore[attr-defined]
    assert transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1") == "sent"
    assert calls == ["acct-1:10"]


def test_interrupt_before_durable_completion_audit_downgrades_to_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    audit = AuditLog(backend=JSONLAuditBackend(tmp_path / "audit.jsonl"))
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        audit_log=audit,
        require_durable_audit=True,
        **_production_signing(),
    )

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)
    original = audit.record_durable

    def record_durable(entry: AuditEntry) -> object:
        if entry.type == "execution_completed":
            raise SystemExit(1)
        return original(entry)

    monkeypatch.setattr(audit, "record_durable", record_durable)
    with pytest.raises(SystemExit):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    record = _attempt(guard)
    assert record.status is AttemptStatus.PARTIAL  # type: ignore[attr-defined]
    assert record.error_code == "interrupted"  # type: ignore[attr-defined]
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert calls == ["acct-1:10"]


def test_interrupt_acquiring_completion_lock_settles_partial() -> None:
    calls: list[str] = []
    guard = _production_guard()

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    real_lock = guard._completion_lock

    class _InterruptingLock:
        """The real lock, except that acquiring it after the side effect ran interrupts."""

        def __enter__(self) -> object:
            if calls:
                raise KeyboardInterrupt
            return real_lock.__enter__()

        def __exit__(self, *exc: object) -> None:
            real_lock.__exit__(*exc)  # type: ignore[arg-type]

    grant = transfer.issue_grant("acct-1", 10)
    guard._completion_lock = _InterruptingLock()  # type: ignore[assignment]
    with pytest.raises(KeyboardInterrupt):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    record = _attempt(guard)
    assert record.status is AttemptStatus.PARTIAL  # type: ignore[attr-defined]
    assert record.error_code == "interrupted"  # type: ignore[attr-defined]
    assert calls == ["acct-1:10"]


def test_interrupt_with_unsettleable_attempt_disables_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    guard = _production_guard()

    @guard
    def transfer(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    grant = transfer.issue_grant("acct-1", 10)

    def finalize(**kwargs: object) -> object:
        if kwargs.get("status") is AttemptStatus.COMPLETED:
            raise KeyboardInterrupt
        raise OSError("ledger unavailable")

    monkeypatch.setattr(guard._ledger, "finalize", finalize)
    with pytest.raises(KeyboardInterrupt):
        transfer("acct-1", 10, execution_grant=grant, execution_attempt_id="att-1")
    assert guard._execution_disabled is True
    assert calls == ["acct-1:10"]


# --- interrupts between the consume and the governed call --------------------


def _governed_transfer(guard: GovernedCallable, calls: list[str], *, asynchronous: bool) -> object:
    def body(account_id: str, amount: int) -> str:
        calls.append(f"{account_id}:{amount}")
        return "sent"

    if asynchronous:

        async def transfer(account_id: str, amount: int) -> str:
            return body(account_id, amount)

    else:

        def transfer(account_id: str, amount: int) -> str:  # type: ignore[misc]
            return body(account_id, amount)

    return guard(transfer)


def _call(governed: object, grant: object, *, asynchronous: bool) -> object:
    result = governed(  # type: ignore[operator]
        "acct-1", 10, execution_grant=grant, execution_attempt_id="att-1"
    )
    return asyncio.run(result) if asynchronous else result


def _assert_failed_interrupted(guard: GovernedCallable) -> None:
    record = _attempt(guard)
    assert record.status is AttemptStatus.FAILED  # type: ignore[attr-defined]
    assert record.error_code == "interrupted"  # type: ignore[attr-defined]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_interrupt_in_durable_authorization_audit_settles_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
) -> None:
    calls: list[str] = []
    audit = AuditLog(backend=JSONLAuditBackend(tmp_path / "audit.jsonl"))
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        audit_log=audit,
        require_durable_audit=True,
        **_production_signing(),
    )
    governed = _governed_transfer(guard, calls, asynchronous=asynchronous)
    grant = governed.issue_grant("acct-1", 10)  # type: ignore[attr-defined]
    original = audit.record_durable

    def record_durable(entry: AuditEntry) -> object:
        if entry.type == "execution_authorized":
            raise KeyboardInterrupt
        return original(entry)

    monkeypatch.setattr(audit, "record_durable", record_durable)
    with pytest.raises(KeyboardInterrupt):
        _call(governed, grant, asynchronous=asynchronous)
    _assert_failed_interrupted(guard)
    with pytest.raises(LegitimacyInvariantError, match="already failed"):
        _call(governed, grant, asynchronous=asynchronous)
    assert calls == []


def test_interrupt_in_durable_authorization_audit_unsettleable_disables_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    audit = AuditLog(backend=JSONLAuditBackend(tmp_path / "audit.jsonl"))
    guard = GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        audit_log=audit,
        require_durable_audit=True,
        **_production_signing(),
    )
    governed = _governed_transfer(guard, calls, asynchronous=False)
    grant = governed.issue_grant("acct-1", 10)  # type: ignore[attr-defined]

    def record_durable(entry: AuditEntry) -> object:
        raise KeyboardInterrupt

    def finalize(**kwargs: object) -> object:
        raise OSError("ledger unavailable")

    monkeypatch.setattr(audit, "record_durable", record_durable)
    monkeypatch.setattr(guard._ledger, "finalize", finalize)
    with pytest.raises(KeyboardInterrupt):
        _call(governed, grant, asynchronous=False)
    assert guard._execution_disabled is True
    assert calls == []


@pytest.mark.parametrize("raised", [KeyboardInterrupt, RuntimeError])
def test_failure_releasing_grant_reservation_settles_failed(
    monkeypatch: pytest.MonkeyPatch, raised: type[BaseException]
) -> None:
    calls: list[str] = []
    guard = _production_guard()
    governed = _governed_transfer(guard, calls, asynchronous=False)
    grant = governed.issue_grant("acct-1", 10)  # type: ignore[attr-defined]
    original = guard._release_signed_grant
    fired: list[bool] = []

    def release(grant_id: str) -> None:
        original(grant_id)
        if not fired:
            fired.append(True)
            raise raised

    monkeypatch.setattr(guard, "_release_signed_grant", release)
    with pytest.raises(raised):
        _call(governed, grant, asynchronous=False)
    record = _attempt(guard)
    assert record.status is AttemptStatus.FAILED  # type: ignore[attr-defined]
    expected = "interrupted" if raised is KeyboardInterrupt else "exception"
    assert record.error_code == expected  # type: ignore[attr-defined]
    with pytest.raises(LegitimacyInvariantError, match="already failed"):
        _call(governed, grant, asynchronous=False)
    assert calls == []


@pytest.mark.parametrize("asynchronous", [False, True])
def test_interrupt_entering_execution_settles_failed(
    monkeypatch: pytest.MonkeyPatch, asynchronous: bool
) -> None:
    calls: list[str] = []
    guard = _production_guard()
    governed = _governed_transfer(guard, calls, asynchronous=asynchronous)
    grant = governed.issue_grant("acct-1", 10)  # type: ignore[attr-defined]
    original = guard._recovered_result
    fired: list[bool] = []

    def recovered_result(outcome: object) -> object:
        if not fired:
            fired.append(True)
            raise KeyboardInterrupt
        return original(outcome)  # type: ignore[arg-type]

    monkeypatch.setattr(guard, "_recovered_result", recovered_result)
    with pytest.raises(KeyboardInterrupt):
        _call(governed, grant, asynchronous=asynchronous)
    _assert_failed_interrupted(guard)
    with pytest.raises(LegitimacyInvariantError, match="already failed"):
        _call(governed, grant, asynchronous=asynchronous)
    assert calls == []


def test_recovery_failure_does_not_resettle_the_recorded_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A recover outcome belongs to an earlier call; a failure while recovering it
    # must not write a new terminal status over the recorded one.
    calls: list[str] = []
    guard = _production_guard()
    governed = _governed_transfer(guard, calls, asynchronous=False)
    grant = governed.issue_grant("acct-1", 10)  # type: ignore[attr-defined]
    assert _call(governed, grant, asynchronous=False) == "sent"
    writes: list[object] = []
    original = guard._ledger.finalize

    def finalize(**kwargs: object) -> object:
        writes.append(kwargs.get("status"))
        return original(**kwargs)  # type: ignore[arg-type]

    def recovered_result(outcome: object) -> object:
        raise RuntimeError("recovery failed")

    monkeypatch.setattr(guard._ledger, "finalize", finalize)
    monkeypatch.setattr(guard, "_recovered_result", recovered_result)
    with pytest.raises(RuntimeError, match="recovery failed"):
        _call(governed, grant, asynchronous=False)
    assert writes == []
    assert _attempt(guard).status is AttemptStatus.COMPLETED  # type: ignore[attr-defined]
    assert calls == ["acct-1:10"]
