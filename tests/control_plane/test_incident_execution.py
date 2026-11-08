"""Incident ownership cannot change while an authorized write is executing."""

from __future__ import annotations

import asyncio
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.incident import IncidentLockError, IncidentMutationLock

pytestmark = [pytest.mark.unit, pytest.mark.red_team]
ADMIN = Principal("commander", PrincipalKind.HUMAN)
A = Principal("writer-a", PrincipalKind.AGENT)
B = Principal("writer-b", PrincipalKind.AGENT)


def _setup(
    tmp_path: Path, pdp: PolicyDecisionPoint, fn: Any, *, active: bool = True, **options: Any
) -> tuple[GovernedToolDispatcher, IncidentMutationLock, IncidentMutationLock]:
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    lock = IncidentMutationLock(registry=registry)
    other = IncidentMutationLock(registry=registry)
    if active:
        lock.declare_incident(ADMIN, "inc-1")
        lock.acquire(A, "inc-1", commander=ADMIN)
    dispatcher = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            pdp.registry,
            [WriteGrant(p.id, p.kind, ("workspace/**",)) for p in (A, B)],
        ),
        tool_tiers={"write": ActionTier.T1},
        incident_lock=lock,
        **options,
    )
    dispatcher.register("write", fn, path_params={"path"}, merge_capable=False)
    return dispatcher, lock, other


def test_execution_lease_denial_retains_credential_id(
    tmp_path: Path, pdp: PolicyDecisionPoint
) -> None:
    from acgs_lite.control_plane.credentials import CredentialIssuer

    issuer = CredentialIssuer()
    credential = issuer.issue(A, scopes={"tool:write"})
    calls: list[str] = []

    def write(path: str) -> None:
        calls.append(path)

    d, _, other = _setup(
        tmp_path, pdp, write, active=False, credential_issuer=issuer, require_credential=True
    )

    def declare(decisions: Any) -> None:
        other.declare_incident(ADMIN, "during-callback")

    with pytest.raises(ToolDenied, match="incident") as denied:
        d.dispatch(
            A,
            "write",
            {"path": "workspace/a.txt"},
            credential=credential.token,
            on_authorized=declare,
        )
    assert calls == []
    assert denied.value.decision.credential_id == credential.credential_id


@pytest.mark.parametrize("active", [False, True])
def test_lifecycle_cannot_reassign_during_sync_write(
    tmp_path: Path, pdp: PolicyDecisionPoint, active: bool
) -> None:
    started, finish = threading.Event(), threading.Event()
    calls: list[str] = []

    def write(path: str) -> None:
        started.set()
        assert finish.wait(5)
        calls.append(path)

    d, lock, other = _setup(tmp_path, pdp, write, active=active)
    with ThreadPoolExecutor() as pool:
        future = pool.submit(d.dispatch, A, "write", {"path": "workspace/a.txt"})
        try:
            assert started.wait(5)
            with pytest.raises(IncidentLockError, match="execution"):
                if active:
                    other.transfer(ADMIN, B)
                else:
                    other.declare_incident(ADMIN, "new-incident")
            if active:
                probe = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "import sys\n"
                        "from acgs_lite.control_plane.incident import IncidentMutationLock, IncidentLockError\n"
                        "from acgs_lite.control_plane import Principal, PrincipalKind\n"
                        "lock = IncidentMutationLock(sys.argv[1])\n"
                        "try:\n"
                        " lock.transfer(Principal('commander', PrincipalKind.HUMAN), "
                        "Principal('writer-b', PrincipalKind.AGENT))\n"
                        "except IncidentLockError as exc:\n"
                        " sys.exit(0 if 'execution' in str(exc) else 3)\n"
                        "sys.exit(2)\n",
                        str(lock.state_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                assert probe.returncode == 0, probe.stderr
                with pytest.raises(ToolDenied, match="held by writer-a"):
                    d.dispatch(B, "write", {"path": "workspace/b.txt"})
        finally:
            finish.set()
        future.result(timeout=5)
    assert calls == ["workspace/a.txt"]
    if active:
        other.transfer(ADMIN, B)
    else:
        other.declare_incident(ADMIN, "new-incident")
        other.acquire(B, "new-incident", commander=ADMIN)
    assert lock.write_denial(B) is None


@pytest.mark.parametrize("sync_wrapper", [False, True])
async def test_async_body_cannot_transfer_and_cancel_releases_lease(
    tmp_path: Path, pdp: PolicyDecisionPoint, sync_wrapper: bool
) -> None:
    entered = asyncio.Event()
    wait = asyncio.Event()
    other: IncidentMutationLock

    async def write(path: str) -> None:
        # Nonblocking refusal also prevents a lifecycle call on this event
        # loop from deadlocking behind its own execution lease.
        with pytest.raises(IncidentLockError, match="execution"):
            other.transfer(ADMIN, B)
        entered.set()
        await wait.wait()

    def wrapped(path: str) -> Any:
        return write(path)

    d, _, other = _setup(tmp_path, pdp, wrapped if sync_wrapper else write)
    task = asyncio.create_task(d.adispatch(A, "write", {"path": "workspace/a.txt"}))
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        with pytest.raises(ToolDenied, match="held by writer-a"):
            await d.adispatch(B, "write", {"path": "workspace/b.txt"})
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    other.transfer(ADMIN, B)


async def test_cancelled_sync_worker_keeps_lease_until_it_finishes(
    tmp_path: Path, pdp: PolicyDecisionPoint
) -> None:
    started, finish, completed = threading.Event(), threading.Event(), threading.Event()

    def write(path: str) -> None:
        started.set()
        try:
            assert finish.wait(5)
        finally:
            completed.set()

    d, _, other = _setup(tmp_path, pdp, write)
    task = asyncio.create_task(d.adispatch(A, "write", {"path": "workspace/a.txt"}))
    try:
        assert await asyncio.to_thread(started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(IncidentLockError, match="execution"):
            other.transfer(ADMIN, B)
    finally:
        finish.set()
        assert await asyncio.to_thread(completed.wait, 5)
    # Completion bookkeeping may still be finishing when the tool signals.
    for _ in range(100):
        try:
            other.transfer(ADMIN, B)
            break
        except IncidentLockError:
            await asyncio.sleep(0.01)
    else:
        pytest.fail("execution lease leaked after the cancelled worker completed")
