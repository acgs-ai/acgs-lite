"""Change ownership remains pinned until each authorized write finishes."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from acgs_lite.control_plane import (
    ActionTier,
    GovernedToolDispatcher,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.change_ownership import ChangeOwnershipRegistry, OwnershipDenied

pytestmark = [pytest.mark.unit, pytest.mark.red_team]
ADMIN = Principal("admin", PrincipalKind.HUMAN)
A = Principal("writer-a", PrincipalKind.AGENT)
B = Principal("writer-b", PrincipalKind.AGENT)
ROOT = "workspace/owned"


def setup(pdp, fn, **options):
    owners = ChangeOwnershipRegistry(pdp.registry, admin=ADMIN)
    owners.assign(ADMIN, "c1", A, ROOT)
    d = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            pdp.registry, [WriteGrant(p.id, p.kind, ("workspace/**",)) for p in (A, B)]
        ),
        tool_tiers={"write": ActionTier.T1},
        ownership=owners,
        **options,
    )
    d.register("write", fn, path_params={"path"}, merge_capable=False)
    return d, owners


def test_reassignment_cannot_start_second_writer_during_sync_write(pdp):
    started, finish = threading.Event(), threading.Event()
    mutations = []

    def write(path):
        if path.endswith("a.txt"):
            started.set()
            assert finish.wait(5)
        mutations.append(path)

    d, owners = setup(pdp, write)
    with ThreadPoolExecutor() as pool:
        future = pool.submit(d.dispatch, A, "write", {"path": ROOT + "/a.txt"}, change_id="c1")
        try:
            assert started.wait(5)
            try:
                owners.release(ADMIN, "c1")
            except OwnershipDenied:
                pass
            else:
                owners.assign(ADMIN, "c1", B, ROOT)
                d.dispatch(B, "write", {"path": ROOT + "/b.txt"}, change_id="c1")
            assert mutations == [], "second writer mutated while the original writer was active"
            with pytest.raises(ToolDenied):
                d.dispatch(B, "write", {"path": ROOT + "/b.txt"}, change_id="c1")
        finally:
            finish.set()
        future.result(timeout=5)
    assert owners.release(ADMIN, "c1")
    owners.assign(ADMIN, "c1", B, ROOT)
    d.dispatch(B, "write", {"path": ROOT + "/b.txt"}, change_id="c1")
    assert mutations == [ROOT + "/a.txt", ROOT + "/b.txt"]


@pytest.mark.parametrize("sync_wrapper", [False, True])
async def test_async_write_lease_survives_await_and_releases_on_cancel(pdp, sync_wrapper):
    entered, finish = asyncio.Event(), asyncio.Event()

    async def write(path):
        entered.set()
        await finish.wait()

    def wrapper(path):
        return write(path)

    d, owners = setup(pdp, wrapper if sync_wrapper else write)
    task = asyncio.create_task(d.adispatch(A, "write", {"path": ROOT + "/a.txt"}, change_id="c1"))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        with pytest.raises(OwnershipDenied, match="execution"):
            owners.release(ADMIN, "c1")
        with pytest.raises(ToolDenied):
            await d.adispatch(B, "write", {"path": ROOT + "/b.txt"}, change_id="c1")
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert owners.release(ADMIN, "c1")
    owners.assign(ADMIN, "c1", B, ROOT)


async def test_cancelled_client_cannot_release_active_sync_worker(pdp):
    started, finish, completed = threading.Event(), threading.Event(), threading.Event()

    def write(path):
        started.set()
        try:
            assert finish.wait(5)
        finally:
            completed.set()

    d, owners = setup(pdp, write)
    task = asyncio.create_task(d.adispatch(A, "write", {"path": ROOT + "/a.txt"}, change_id="c1"))
    try:
        assert await asyncio.to_thread(started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(OwnershipDenied, match="execution"):
            owners.release(ADMIN, "c1")
    finally:
        finish.set()
        assert await asyncio.to_thread(completed.wait, 5)
    for _ in range(100):
        try:
            assert owners.release(ADMIN, "c1")
            break
        except OwnershipDenied:
            await asyncio.sleep(0.01)
    else:
        pytest.fail("ownership execution lease leaked")


def test_reassignment_before_invocation_rechecks_new_worktree(pdp, monkeypatch):
    calls = []

    def write(path):
        calls.append(path)

    d, owners = setup(pdp, write)
    authorize = d._authorize

    def changed(*args, **kwargs):
        result = authorize(*args, **kwargs)
        owners.release(ADMIN, "c1")
        owners.assign(ADMIN, "c1", A, "workspace/new")
        return result

    monkeypatch.setattr(d, "_authorize", changed)
    with pytest.raises(ToolDenied, match="outside worktree"):
        d.dispatch(A, "write", {"path": ROOT + "/a.txt"}, change_id="c1")
    assert calls == []
    assert owners.release(ADMIN, "c1")


@pytest.mark.parametrize("sync_wrapper", [False, True])
async def test_reassignment_before_await_rechecks_and_closes_coroutine(
    pdp, monkeypatch, sync_wrapper
):
    import inspect

    calls = []

    async def write(path):
        calls.append(path)

    def wrapper(path):
        return write(path)

    d, owners = setup(pdp, wrapper if sync_wrapper else write)
    original = asyncio.to_thread
    pending = []

    async def replaced(func, *args, **kwargs):
        result = await original(func, *args, **kwargs)
        pending.append(result[1])
        owners.release(ADMIN, "c1")
        owners.assign(ADMIN, "c1", A, "workspace/new")
        return result

    monkeypatch.setattr(asyncio, "to_thread", replaced)
    with pytest.raises(ToolDenied, match="outside worktree"):
        await d.adispatch(A, "write", {"path": ROOT + "/a.txt"}, change_id="c1")
    assert calls == []
    assert inspect.getcoroutinestate(pending[0]) == inspect.CORO_CLOSED
    assert owners.release(ADMIN, "c1")


def test_multiple_same_owner_leases_pin_until_last_exit(pdp):
    _, owners = setup(pdp, lambda path: None)
    with owners.execution(A, "c1"):
        with owners.execution(A, "c1"), pytest.raises(OwnershipDenied, match="execution"):
            owners.release(ADMIN, "c1")
        with pytest.raises(OwnershipDenied, match="execution"):
            owners.release(ADMIN, "c1")
        # Independent assignments remain mutable while this change executes.
        owners.assign(ADMIN, "c2", B, "workspace/independent")
        assert owners.release(ADMIN, "c2")
    assert owners.release(ADMIN, "c1")


def test_tool_failure_releases_ownership_lease(pdp):
    def broken(path):
        raise RuntimeError("tool failed")

    d, owners = setup(pdp, broken)
    with pytest.raises(RuntimeError, match="tool failed"):
        d.dispatch(A, "write", {"path": ROOT + "/a.txt"}, change_id="c1")
    assert owners.release(ADMIN, "c1")


def test_callback_reassignment_denial_preserves_credential(pdp):
    from acgs_lite.control_plane.credentials import CredentialIssuer

    issuer = CredentialIssuer()
    credential = issuer.issue(A, scopes={"tool:write"})
    calls = []

    def write(path):
        calls.append(path)

    d, owners = setup(
        pdp,
        write,
        credential_issuer=issuer,
        require_credential=True,
    )

    def reassign(decisions):
        assert owners.release(ADMIN, "c1")
        owners.assign(ADMIN, "c1", B, ROOT)

    with pytest.raises(ToolDenied, match="change ownership") as denied:
        d.dispatch(
            A,
            "write",
            {"path": ROOT + "/a.txt"},
            change_id="c1",
            credential=credential.token,
            on_authorized=reassign,
        )
    assert calls == []
    assert denied.value.decision.credential_id == credential.credential_id
    assert owners.get("c1").writer == B
