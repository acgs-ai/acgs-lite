"""Unwind and guard-rail tests for ConstitutionLifecycle.

Failures are injected through constructor arguments (an armable evidence sink,
a provenance graph whose edge write fails) rather than by reassigning
coordinator internals. Every failure test asserts the restored stored state.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from acgs_lite.constitution.bundle import BundleStatus
from acgs_lite.constitution.bundle_store import InMemoryBundleStore
from acgs_lite.constitution.evidence import (
    InMemoryLifecycleAuditSink,
    LifecycleAuditSinkError,
)
from acgs_lite.constitution.lifecycle_service import (
    ConstitutionLifecycle,
    LifecycleError,
    LifecycleEvidenceError,
)
from acgs_lite.constitution.provenance import RuleProvenanceGraph
from acgs_lite.errors import MACIViolationError
from acgs_lite.evals.schema import EvalScenario

TENANT = "tenant-a"

PASS = EvalScenario(id="s1", input_action="check current status of the system", expected_valid=True)
FAIL = EvalScenario(
    id="s1", input_action="check current status of the system", expected_valid=False
)


class _ArmableSink(InMemoryLifecycleAuditSink):
    """In-memory sink whose appends fail while ``armed`` is True."""

    def __init__(self) -> None:
        super().__init__()
        self.armed = False

    def append(self, record: Any, expected_prev_hash: str | None) -> Any:
        if self.armed:
            raise LifecycleAuditSinkError("simulated")
        return super().append(record, expected_prev_hash)


class _EdgeFailsGraph(RuleProvenanceGraph):
    __slots__ = ()

    def add_relation(self, *args: Any, **kwargs: Any) -> Any:
        raise ValueError("edge store down")


def _build(
    provenance: RuleProvenanceGraph | None = None,
) -> tuple[ConstitutionLifecycle, InMemoryBundleStore, _ArmableSink]:
    store = InMemoryBundleStore()
    sink = _ArmableSink()
    lc = ConstitutionLifecycle(
        store=store,
        sink=sink,
        provenance=provenance if provenance is not None else RuleProvenanceGraph(),
    )
    return lc, store, sink


async def _drive_to_eval(lc: ConstitutionLifecycle) -> str:
    active = await lc.get_active_bundle(TENANT)
    base_id = active.bundle_id if active is not None else None
    draft = await lc.create_draft(TENANT, "proposer-1", base_bundle_id=base_id)
    await lc.submit_for_review(draft.bundle_id, "proposer-1")
    await lc.approve_review(draft.bundle_id, "reviewer-1")
    return draft.bundle_id


async def _drive_to_staged(lc: ConstitutionLifecycle) -> str:
    bundle_id = await _drive_to_eval(lc)
    await lc.run_evaluation(bundle_id, scenarios=[PASS])
    await lc.approve(bundle_id, "approver-1", signature="sig")
    await lc.stage(bundle_id, "executor-1")
    return bundle_id


async def _drive_to_active(lc: ConstitutionLifecycle) -> str:
    bundle_id = await _drive_to_staged(lc)
    await lc.activate(bundle_id, "executor-1")
    return bundle_id


def _stored(store: InMemoryBundleStore, bundle_id: str) -> Any:
    bundle = store.get_bundle(bundle_id)
    assert bundle is not None
    return bundle


# -- approve_review / run_evaluation / approve guards ------------------------


@pytest.mark.asyncio
async def test_approve_review_unwinds_to_review_on_evidence_failure() -> None:
    lc, store, sink = _build()
    draft = await lc.create_draft(TENANT, "proposer-1")
    await lc.submit_for_review(draft.bundle_id, "proposer-1")
    before = _stored(store, draft.bundle_id)
    history_len = len(before.status_history)
    evidence_count = len(sink)
    version = store.get_tenant_version(TENANT)

    sink.armed = True
    with pytest.raises(LifecycleEvidenceError, match="approve_review"):
        await lc.approve_review(draft.bundle_id, "reviewer-1")

    after = _stored(store, draft.bundle_id)
    assert after.status == BundleStatus.REVIEW
    assert after.reviewed_by is None
    assert len(after.status_history) == history_len
    assert len(sink) == evidence_count
    assert store.get_tenant_version(TENANT) == version


@pytest.mark.asyncio
async def test_sixth_evaluation_attempt_is_refused() -> None:
    lc, store, sink = _build()
    bundle_id = await _drive_to_eval(lc)
    for _ in range(5):
        await lc.run_evaluation(bundle_id, scenarios=[PASS])
    evidence_count = len(sink)

    with pytest.raises(LifecycleError, match="maximum of 5 evaluation attempts"):
        await lc.run_evaluation(bundle_id, scenarios=[PASS])

    stored = _stored(store, bundle_id)
    assert stored.eval_attempt_count == 5
    assert len(stored.eval_run_ids) == 5
    assert len(sink) == evidence_count


@pytest.mark.asyncio
async def test_approve_requires_passing_evaluation() -> None:
    lc, store, sink = _build()
    bundle_id = await _drive_to_eval(lc)
    evidence_count = len(sink)

    with pytest.raises(LifecycleError, match="requires a passing evaluation"):
        await lc.approve(bundle_id, "approver-1", signature="sig")
    assert len(sink) == evidence_count

    await lc.run_evaluation(bundle_id, scenarios=[FAIL])
    evidence_count = len(sink)
    assert _stored(store, bundle_id).eval_summary["status"] == "failed"
    with pytest.raises(LifecycleError, match="requires a passing evaluation"):
        await lc.approve(bundle_id, "approver-1", signature="sig")

    stored = _stored(store, bundle_id)
    assert stored.status == BundleStatus.EVAL
    assert stored.approval_signature is None
    assert len(sink) == evidence_count


# -- activate guard rails and provenance tolerance ---------------------------


@pytest.mark.asyncio
async def test_activate_by_other_executor_restores_superseded_bundle() -> None:
    lc, store, sink = _build()
    v1 = await _drive_to_active(lc)
    v2 = await _drive_to_staged(lc)
    v1_history = len(_stored(store, v1).status_history)
    evidence_count = len(sink)

    with pytest.raises(MACIViolationError):
        await lc.activate(v2, "executor-2")

    assert _stored(store, v1).status == BundleStatus.ACTIVE
    assert len(_stored(store, v1).status_history) == v1_history
    assert _stored(store, v2).status == BundleStatus.STAGED
    activation = store.get_activation(TENANT)
    assert activation is not None
    assert activation.bundle_id == v1
    active = store.get_active_bundle(TENANT)
    assert active is not None
    assert active.bundle_id == v1
    assert len(sink) == evidence_count


@pytest.mark.asyncio
async def test_activate_logs_and_continues_when_provenance_edge_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    graph = _EdgeFailsGraph()
    lc, store, _ = _build(provenance=graph)
    v1 = await _drive_to_active(lc)
    v2 = await _drive_to_staged(lc)

    with caplog.at_level(logging.WARNING):
        record = await lc.activate(v2, "executor-1")

    assert record.bundle_id == v2
    assert record.rollback_to_bundle_id == v1
    assert "Provenance edge write failed" in caplog.text
    assert graph.successors(v1) == []
    assert _stored(store, v1).status == BundleStatus.SUPERSEDED
    assert _stored(store, v2).status == BundleStatus.ACTIVE


@pytest.mark.asyncio
async def test_rollback_logs_and_continues_when_provenance_edge_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    graph = _EdgeFailsGraph()
    lc, store, _ = _build(provenance=graph)
    v1 = await _drive_to_active(lc)
    v2 = await _drive_to_active(lc)

    with caplog.at_level(logging.WARNING):
        record = await lc.rollback(v2, "executor-2", "regression")

    assert record.bundle_id == v1
    assert "Provenance edge write failed on rollback" in caplog.text
    assert _stored(store, v2).status == BundleStatus.ROLLED_BACK
    assert _stored(store, v1).status == BundleStatus.ACTIVE


@pytest.mark.asyncio
async def test_rollback_adds_missing_provenance_nodes() -> None:
    lc_a, store, sink = _build()
    v1 = await _drive_to_active(lc_a)
    v2 = await _drive_to_active(lc_a)

    fresh = RuleProvenanceGraph()
    lc_b = ConstitutionLifecycle(store=store, sink=sink, provenance=fresh)
    record = await lc_b.rollback(v2, "executor-2", "regression")

    assert record.bundle_id == v1
    assert fresh.get_node(v1) is not None
    assert fresh.get_node(v2) is not None
    assert [edge.target_rule_id for edge in fresh.successors(v2)] == [v1]


@pytest.mark.asyncio
async def test_rolled_back_bundle_without_activation_record_is_refused() -> None:
    lc, store_a, sink = _build()
    v1 = await _drive_to_active(lc)
    await lc.rollback(v1, "executor-2", "bad")
    rolled_back = _stored(store_a, v1)
    assert rolled_back.status == BundleStatus.ROLLED_BACK

    store_b = InMemoryBundleStore()
    store_b.save_bundle(rolled_back)
    assert store_b.get_activation(TENANT) is None
    lc_b = ConstitutionLifecycle(store=store_b, sink=sink)

    with pytest.raises(LifecycleError, match="no activation record"):
        await lc_b.rollback(v1, "executor-2", "again")
    assert _stored(store_b, v1).status == BundleStatus.ROLLED_BACK


# -- rollback / activate evidence-failure unwind -----------------------------


@pytest.mark.asyncio
async def test_rollback_unwinds_when_evidence_append_fails_with_parent() -> None:
    lc, store, sink = _build()
    v1 = await _drive_to_active(lc)
    v2 = await _drive_to_active(lc)
    v2_history = len(_stored(store, v2).status_history)
    activation_before = store.get_activation(TENANT)
    assert activation_before is not None
    assert activation_before.bundle_id == v2
    assert activation_before.rollback_to_bundle_id == v1
    evidence_count = len(sink)
    version = store.get_tenant_version(TENANT)

    sink.armed = True
    with pytest.raises(LifecycleEvidenceError, match="rollback"):
        await lc.rollback(v2, "executor-2", "regression")

    restored = _stored(store, v2)
    assert restored.status == BundleStatus.ACTIVE
    assert restored.rolled_back_at is None
    assert len(restored.status_history) == v2_history
    assert _stored(store, v1).status == BundleStatus.SUPERSEDED
    assert store.get_activation(TENANT) == activation_before
    active = store.get_active_bundle(TENANT)
    assert active is not None
    assert active.bundle_id == v2
    assert len(sink) == evidence_count
    assert store.get_tenant_version(TENANT) == version


@pytest.mark.asyncio
async def test_rollback_unwinds_when_evidence_append_fails_without_parent() -> None:
    lc, store, sink = _build()
    v1 = await _drive_to_active(lc)
    activation_before = store.get_activation(TENANT)
    assert activation_before is not None
    evidence_count = len(sink)

    sink.armed = True
    with pytest.raises(LifecycleEvidenceError, match="rollback"):
        await lc.rollback(v1, "executor-2", "regression")

    assert _stored(store, v1).status == BundleStatus.ACTIVE
    assert _stored(store, v1).rolled_back_at is None
    assert store.get_activation(TENANT) == activation_before
    assert len(sink) == evidence_count


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "rollback evidence-failure unwind clears the parent bundle's activated_by "
        "instead of restoring it (lifecycle_service.py:826-832)"
    ),
)
@pytest.mark.asyncio
async def test_rollback_unwind_restores_parent_activated_by() -> None:
    lc, store, sink = _build()
    v1 = await _drive_to_active(lc)
    v2 = await _drive_to_active(lc)
    parent = store.get_bundle(v1)
    if parent is None or parent.activated_by != "executor-1":
        pytest.fail("precondition: parent bundle must exist and be activated by executor-1")
    before = parent.activated_by

    sink.armed = True
    with pytest.raises(LifecycleEvidenceError, match="rollback"):
        await lc.rollback(v2, "executor-2", "regression")

    restored_parent = store.get_bundle(v1)
    if restored_parent is None:
        pytest.fail("parent bundle disappeared from the store")
    assert restored_parent.activated_by == before


@pytest.mark.asyncio
async def test_activate_unwind_without_prior_activation_restores_staged_and_no_active() -> None:
    lc, store, sink = _build()
    v1 = await _drive_to_staged(lc)
    assert store.get_activation(TENANT) is None

    sink.armed = True
    with pytest.raises(LifecycleEvidenceError, match="activate"):
        await lc.activate(v1, "executor-1")

    assert _stored(store, v1).status == BundleStatus.STAGED
    assert store.get_active_bundle(TENANT) is None


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "activate unwind keeps the new ActivationRecord when there was no prior "
        "activation (lifecycle_service.py:701-702 only restores a non-None record)"
    ),
)
@pytest.mark.asyncio
async def test_activate_unwind_without_prior_activation_leaves_no_activation() -> None:
    lc, store, sink = _build()
    v1 = await _drive_to_staged(lc)
    if store.get_activation(TENANT) is not None:
        pytest.fail("precondition: tenant must have no prior activation")

    sink.armed = True
    with pytest.raises(LifecycleEvidenceError, match="activate"):
        await lc.activate(v1, "executor-1")

    bundle = store.get_bundle(v1)
    if bundle is None or bundle.status != BundleStatus.STAGED:
        pytest.fail("bundle did not return to STAGED after the failed activation")
    if store.get_active_bundle(TENANT) is not None:
        pytest.fail("a bundle is active after the failed activation")
    assert store.get_activation(TENANT) is None
