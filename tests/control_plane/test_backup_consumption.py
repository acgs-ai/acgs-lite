"""Backup single-use is a durable claim shared by independent dispatchers."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.control_plane import (
    ActionTier,
    EvidenceSource,
    ExternalRunRef,
    GovernedToolDispatcher,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    TrustedRunRegistry,
    WriteGrant,
    evidence,
)
from acgs_lite.control_plane.dispatcher import backup_subject_digest

pytest.importorskip("cryptography")
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.red_team]
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
SERVICE = Principal("backups", PrincipalKind.SERVICE)
ARGS = {"path": "workspace/data.txt"}


@pytest.fixture()
def harness(tmp_path: Path, ledger_pdp: Any, approver_factory: Any):
    signer = Ed25519ReceiptSigner.from_seed(b"durable-backup-test".ljust(32, b"0"))
    path = tmp_path / "audit" / "backup-runs.jsonl"
    core = ledger_pdp.registry
    ref = ExternalRunRef(
        "backups",
        "run-1",
        EvidenceSource.CI_SYSTEM,
        artifact_digest=backup_subject_digest("delete", ARGS),
    )
    calls = []
    signers = [approver_factory("bob"), approver_factory("carol")]

    def registry():
        return TrustedRunRegistry(path=path, registry=core, signer=signer)

    registry().register_run(SERVICE, ref, conclusion="success")

    def dispatcher(runs=None, verifier=None):
        runs = registry() if runs is None else runs
        d = GovernedToolDispatcher(
            ledger_pdp,
            permissions=RepositoryPermissions(
                core, [WriteGrant(AGENT.id, AGENT.kind, ("workspace/**",))]
            ),
            tool_tiers={"delete": ActionTier.T3},
            run_verifier=runs if verifier is None else verifier,
            backup_consumption_registry=runs,
            backup_workflows={"backups"},
        )
        d.register(
            "delete", lambda path: calls.append(path), path_params={"path"}, merge_capable=False
        )
        return d

    def kwargs(d):
        kw = {"backup_run": ref, "requested_by": "olivia"}
        digest = d.action_hash_for(AGENT, "delete", ARGS, **kw)
        return {**kw, "approvals": [sign(digest) for sign in signers]}

    return registry, dispatcher, kwargs, calls, path, ref, signer, core


def test_dispatcher_replacement_and_registry_restart_reject_backup(harness):
    registry, dispatcher, kwargs, calls, _, ref, _, _ = harness
    first, already_open = dispatcher(), dispatcher()
    first_kw, second_kw = kwargs(first), kwargs(already_open)
    first.dispatch(AGENT, "delete", ARGS, **first_kw)
    with pytest.raises(ToolDenied, match="already consumed"):
        already_open.dispatch(AGENT, "delete", ARGS, **second_kw)
    restarted = dispatcher()
    with pytest.raises(ToolDenied, match="already consumed"):
        restarted.dispatch(AGENT, "delete", ARGS, **second_kw)
    assert registry().backup_consumed(ref)
    assert calls == [ARGS["path"]]


def test_concurrent_dispatchers_atomically_claim_once(harness, monkeypatch):
    _, dispatcher, kwargs, calls, _, _, _, _ = harness
    left, right = dispatcher(), dispatcher()
    inputs = [(left, kwargs(left)), (right, kwargs(right))]
    barrier = threading.Barrier(2)
    for d in (left, right):
        consume = d._consume_backup

        def synchronized(ref, consume=consume):
            barrier.wait(timeout=5)
            return consume(ref)

        monkeypatch.setattr(d, "_consume_backup", synchronized)

    def run(item):
        d, kw = item
        try:
            d.dispatch(AGENT, "delete", ARGS, **kw)
        except ToolDenied:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(run, inputs)) == [False, True]
    assert calls == [ARGS["path"]]


def test_fsync_failure_rolls_back_claim_and_never_executes(harness, monkeypatch):
    registry, dispatcher, kwargs, calls, path, ref, _, _ = harness
    d = dispatcher()
    before = path.read_bytes()
    kw = kwargs(d)
    with monkeypatch.context() as patch:

        def fail(fd):
            raise OSError("fsync unavailable")

        patch.setattr(evidence.os, "fsync", fail)
        with pytest.raises(ToolDenied):
            d.dispatch(AGENT, "delete", ARGS, **kw)
    assert calls == []
    assert path.read_bytes() == before
    assert not registry().backup_consumed(ref)
    d.dispatch(AGENT, "delete", ARGS, **kwargs(d))
    assert calls == [ARGS["path"]]


def test_corrupt_registry_tail_blocks_before_execution(harness):
    _, dispatcher, kwargs, calls, path, _, _, _ = harness
    d = dispatcher()
    kw = kwargs(d)
    with path.open("ab") as f:
        f.write(b'{"unsigned": true}')
    with pytest.raises(ToolDenied):
        d.dispatch(AGENT, "delete", ARGS, **kw)
    assert calls == []


def test_memory_and_readonly_claim_stores_fail_closed(harness):
    registry, dispatcher, _, calls, path, ref, signer, core = harness
    memory = TrustedRunRegistry()
    memory.register_run(SERVICE, ref, conclusion="success")
    readonly = TrustedRunRegistry(
        path=path, registry=core, trusted_public_keys={signer.key_id: signer.public_key_hex()}
    )
    for store in (memory, readonly):
        assert not store.consume_backup(ref)
        with pytest.raises(ToolDenied, match="persistent signing registry"):
            dispatcher(store).dispatch(AGENT, "delete", ARGS, backup_run=ref, requested_by="olivia")
    assert calls == []


def test_custom_verifier_uses_separate_durable_claim_store(harness):
    registry, dispatcher, kwargs, calls, _, _, _, _ = harness

    class Verifier:
        verifier_id = "test-workflow-verifier"
        attests_artifact_digest = True

        def validate(self, ref):
            return registry().validate(ref)

    d = dispatcher(verifier=Verifier())
    d.dispatch(AGENT, "delete", ARGS, **kwargs(d))
    assert calls == [ARGS["path"]]


def test_tampered_consumption_record_cannot_load(harness):
    registry, _, _, _, path, ref, _, _ = harness
    assert registry().consume_backup(ref)
    lines = path.read_text().splitlines()
    claim = json.loads(lines[-1])
    claim["record"]["ref"]["run_id"] = "forged"
    lines[-1] = json.dumps(claim)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="signature"):
        registry()


def _claim_in_process(path, core, ref, barrier, results):
    signer = Ed25519ReceiptSigner.from_seed(b"durable-backup-test".ljust(32, b"0"))
    registry = TrustedRunRegistry(path=path, registry=core, signer=signer)
    barrier.wait(timeout=10)
    results.put(registry.consume_backup(ref))


def test_separate_processes_share_atomic_durable_claim(harness):
    import multiprocessing

    registry, _, _, _, path, ref, _, core = harness
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(2)
    results = context.Queue()
    processes = [
        context.Process(target=_claim_in_process, args=(path, core, ref, barrier, results))
        for _ in range(2)
    ]
    try:
        for process in processes:
            process.start()
        assert sorted(results.get(timeout=15) for _ in processes) == [False, True]
        for process in processes:
            process.join(timeout=10)
            assert process.exitcode == 0
        assert registry().backup_consumed(ref)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        results.close()
