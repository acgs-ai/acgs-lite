"""Integration tests for AFFiNE-inspired architecture patterns.

Test IDs: AS-01..05 (AgentScope), GS-01..03 (GovernanceStream), PS-01..03 (PolicyStorage).
GW-01 lives in src/core/services/api_gateway/tests/unit/test_redis_backend.py.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from acgs_lite.events import EventBus, GovernanceEvent, GovernanceStream
from acgs_lite.integrations.policy_storage import (
    InMemoryPolicyStorage,
    Policy,
    PolicyNotFoundError,
    PolicyStorage,
)
from core.shared.di_container import AgentScope, DIContainer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _DummyService:
    """Minimal test service — no real behaviour needed."""

    def __init__(self, label: str = "") -> None:
        self.label = label


# ---------------------------------------------------------------------------
# AS-01  child_scope() returns an AgentScope
# ---------------------------------------------------------------------------


def test_as01_child_scope_returns_agent_scope() -> None:
    DIContainer.reset()
    scope = DIContainer.child_scope("agent-as01")
    assert isinstance(scope, AgentScope)
    assert scope.scope_id == "agent-as01"


# ---------------------------------------------------------------------------
# AS-02  register + resolve within scope
# ---------------------------------------------------------------------------


def test_as02_scope_register_and_resolve() -> None:
    DIContainer.reset()
    scope = DIContainer.child_scope("agent-as02")
    svc = _DummyService("scoped")
    scope.register(_DummyService, svc)

    resolved = scope.get(_DummyService)
    assert resolved is svc


# ---------------------------------------------------------------------------
# AS-03  cleanup removes scoped services
# ---------------------------------------------------------------------------


def test_as03_cleanup_removes_scoped_services() -> None:
    DIContainer.reset()
    scope = DIContainer.child_scope("agent-as03")
    scope.register(_DummyService, _DummyService("temp"))
    assert scope.get(_DummyService) is not None

    scope.reset()

    with pytest.raises(KeyError):
        scope.get(_DummyService)


# ---------------------------------------------------------------------------
# AS-04  CRITICAL: scope A cannot resolve scope B's services
# ---------------------------------------------------------------------------


def test_as04_cross_scope_isolation() -> None:
    DIContainer.reset()
    scope_a = DIContainer.child_scope("agent-a")
    scope_b = DIContainer.child_scope("agent-b")

    svc_a = _DummyService("owned-by-a")
    svc_b = _DummyService("owned-by-b")

    scope_a.register(_DummyService, svc_a)
    scope_b.register(_DummyService, svc_b)

    # Each scope sees its own service
    assert scope_a.get(_DummyService) is svc_a
    assert scope_b.get(_DummyService) is svc_b

    # A's service is NOT the same as B's service
    assert scope_a.get(_DummyService) is not scope_b.get(_DummyService)


# ---------------------------------------------------------------------------
# AS-05  context manager cleans up on exception (fail-closed)
# ---------------------------------------------------------------------------


def test_as05_context_manager_cleans_up_on_exception() -> None:
    DIContainer.reset()
    scope = DIContainer.child_scope("agent-as05")
    scope.register(_DummyService, _DummyService("will-be-cleaned"))

    with pytest.raises(RuntimeError), scope:
        raise RuntimeError("simulated session crash")

    # After __exit__, scoped services are gone
    with pytest.raises(KeyError):
        scope.get(_DummyService)


# ---------------------------------------------------------------------------
# GS-01  existing EventBus subscribers still receive events after GovernanceStream
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gs01_eventbus_backward_compat() -> None:
    """GovernanceStream must not break existing plain subscribe() callers."""
    bus = EventBus()
    received: list[GovernanceEvent] = []

    async def legacy_consumer() -> None:
        async for event in bus.subscribe(maxsize=10):
            received.append(event)

    task = asyncio.create_task(legacy_consumer())
    await asyncio.sleep(0)  # let coroutine start

    event = GovernanceEvent(event_type="audit", system_id="sys", payload={"ok": True})
    bus.publish(event)
    await asyncio.sleep(0)

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    assert len(received) == 1
    assert received[0].event_type == "audit"


# ---------------------------------------------------------------------------
# GS-02  GovernanceStream.subscribe() delivers transformed values
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gs02_governance_stream_transforms_events() -> None:
    bus = EventBus()
    stream: GovernanceStream[str] = GovernanceStream(
        bus=bus,
        transform=lambda e: e.event_type,
    )

    results: list[str] = []

    async def consumer() -> None:
        async for value in stream.subscribe():
            results.append(value)

    task = asyncio.create_task(consumer())
    await asyncio.sleep(0)

    bus.publish(GovernanceEvent(event_type="violation", system_id="s", payload={}))
    await asyncio.sleep(0)

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    assert results == ["violation"]


# ---------------------------------------------------------------------------
# GS-03  scope_id filter blocks cross-scope events
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gs03_scope_id_filter() -> None:
    bus = EventBus()
    events_for_a: list[GovernanceEvent] = []

    async def scoped_consumer() -> None:
        async for event in bus.subscribe(scope_id="scope-a"):
            events_for_a.append(event)

    task = asyncio.create_task(scoped_consumer())
    await asyncio.sleep(0)

    # This event targets scope-b — should NOT reach the scope-a subscriber
    bus.publish(GovernanceEvent(event_type="audit", system_id="s", payload={}, scope_id="scope-b"))
    # This event targets scope-a — SHOULD reach the subscriber
    bus.publish(
        GovernanceEvent(event_type="policy_applied", system_id="s", payload={}, scope_id="scope-a")
    )
    # Default scope_id events also pass through
    bus.publish(GovernanceEvent(event_type="heartbeat", system_id="s", payload={}))
    await asyncio.sleep(0)

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    event_types = {e.event_type for e in events_for_a}
    assert "scope-b" not in {e.scope_id for e in events_for_a}
    assert "policy_applied" in event_types
    assert "heartbeat" in event_types


# ---------------------------------------------------------------------------
# PS-01  PolicyStorage Protocol is satisfied by InMemoryPolicyStorage
# ---------------------------------------------------------------------------


def test_ps01_in_memory_satisfies_protocol() -> None:
    storage = InMemoryPolicyStorage()
    assert isinstance(storage, PolicyStorage)


# ---------------------------------------------------------------------------
# PS-02  PolicyStorage.load() raises PolicyNotFoundError (never returns None)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ps02_load_raises_on_missing_policy() -> None:
    storage = InMemoryPolicyStorage()

    with pytest.raises(PolicyNotFoundError) as exc_info:
        await storage.load("nonexistent-policy")

    assert "nonexistent-policy" in str(exc_info.value)


# ---------------------------------------------------------------------------
# PS-03  InMemoryPolicyStorage scope isolation (two instances don't share state)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ps03_scope_isolation_between_instances() -> None:
    storage_a = InMemoryPolicyStorage(scope_id="a")
    storage_b = InMemoryPolicyStorage(scope_id="b")

    policy_a = Policy(policy_id="p1", content={"owner": "a"}, version="v1")
    await storage_a.store(policy_a)

    # storage_b knows nothing about p1
    with pytest.raises(PolicyNotFoundError):
        await storage_b.load("p1", version="v1")

    # storage_a can load it just fine
    loaded = await storage_a.load("p1", version="v1")
    assert loaded.content["owner"] == "a"
