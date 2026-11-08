"""Admission generations preserve probes across async scheduling boundaries."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.breaker import BreakerPolicy, TriggerCircuitBreaker, TriggerRegistry
from acgs_lite.control_plane.credentials import CredentialIssuer
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.telemetry import InMemoryTelemetryStore, TelemetryRecorder

pytestmark = [pytest.mark.unit, pytest.mark.red_team]


def test_admission_generation_invalidates_same_clock_reset_and_retrip() -> None:
    now = [1000.0]
    store = InMemoryTelemetryStore()
    breaker = TriggerCircuitBreaker(
        BreakerPolicy(max_rollbacks=1, cooldown_s=1), store, clock=lambda: now[0]
    )
    recorder = TelemetryRecorder(
        store, Principal("ci", PrincipalKind.SERVICE), clock=lambda: now[0]
    )
    recorder.record_rollback("loop", "first")
    now[0] = 1001.0
    admission = breaker._reserve_admission("loop")
    assert admission is not None and breaker._admission_valid(admission)
    breaker.reset(Principal("admin", PrincipalKind.HUMAN), "loop")
    now[0] = 1000.0
    recorder.record_rollback("loop", "second")
    now[0] = 1001.0
    assert not breaker._admission_valid(admission)
    fresh = breaker._reserve_admission("loop")
    assert fresh is not None and breaker._admission_valid(fresh)


def test_admission_rechecks_do_not_consume_another_probe() -> None:
    now = [1000.0]
    store = InMemoryTelemetryStore()
    breaker = TriggerCircuitBreaker(
        BreakerPolicy(max_rollbacks=1, cooldown_s=1), store, clock=lambda: now[0]
    )
    recorder = TelemetryRecorder(
        store, Principal("ci", PrincipalKind.SERVICE), clock=lambda: now[0]
    )
    recorder.record_rollback("loop", "first")
    now[0] = 1001.0
    admission = breaker._reserve_admission("loop")
    assert admission is not None
    for _ in range(3):
        assert breaker._admission_valid(admission)
    assert breaker.status("loop").probes == 1
    assert breaker._reserve_admission("loop") is None
    recorder.record_rollback("loop", "after-probe")
    assert not breaker._admission_valid(admission)


def test_healthy_admission_is_invalidated_by_trip() -> None:
    now = [1000.0]
    store = InMemoryTelemetryStore()
    breaker = TriggerCircuitBreaker(
        BreakerPolicy(max_rollbacks=1, cooldown_s=1), store, clock=lambda: now[0]
    )
    recorder = TelemetryRecorder(
        store, Principal("ci", PrincipalKind.SERVICE), clock=lambda: now[0]
    )
    admission = breaker._reserve_admission("loop")
    assert admission is not None and breaker._admission_valid(admission)
    recorder.record_rollback("loop", "trip")
    assert not breaker._admission_valid(admission)


@pytest.mark.parametrize("sync_wrapper", [False, True])
@pytest.mark.parametrize("interruption", ["none", "failure", "reset_retrip", "unbind", "expire"])
async def test_async_body_uses_its_original_admission(
    pdp: PolicyDecisionPoint,
    monkeypatch: pytest.MonkeyPatch,
    sync_wrapper: bool,
    interruption: str,
) -> None:
    now = [1000.0]
    admin = Principal("admin", PrincipalKind.HUMAN)
    agent = Principal("agent", PrincipalKind.AGENT)
    registry = TriggerRegistry()
    registry.bind(admin, "loop", principals=[agent])
    store = InMemoryTelemetryStore()
    breaker = TriggerCircuitBreaker(
        BreakerPolicy(max_rollbacks=1, cooldown_s=1),
        store,
        registry=registry,
        clock=lambda: now[0],
    )
    recorder = TelemetryRecorder(
        store, Principal("ci", PrincipalKind.SERVICE), clock=lambda: now[0]
    )
    credentials = CredentialIssuer(clock=lambda: now[0])
    credential = credentials.issue(agent, scopes={"tool:write"}, ttl_s=10).token
    dispatcher = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE, [WriteGrant("agent", PrincipalKind.AGENT, ("workspace/**",))]
        ),
        tool_tiers={"write": ActionTier.T1},
        breaker=breaker,
        credential_issuer=credentials,
        require_credential=True,
    )
    calls: list[str] = []

    async def write(path: str) -> str:
        calls.append(path)
        return "done"

    fn = (lambda path: write(path)) if sync_wrapper else write
    dispatcher.register("write", fn, path_params={"path"}, merge_capable=False)
    recorder.record_rollback("loop", "first")
    now[0] = 1001.0
    original = asyncio.to_thread

    async def interrupt_after_worker(fn: Any, *args: Any, **kwargs: Any) -> Any:
        result = await original(fn, *args, **kwargs)
        if interruption == "failure":
            recorder.record_rollback("loop", "after-probe")
        elif interruption == "reset_retrip":
            breaker.reset(admin, "loop")
            now[0] = 1000.0
            recorder.record_rollback("loop", "replacement")
            now[0] = 1001.0
        elif interruption == "unbind":
            registry.unbind(admin, "loop")
        elif interruption == "expire":
            now[0] = 1011.0
        return result

    monkeypatch.setattr(asyncio, "to_thread", interrupt_after_worker)
    if interruption == "none":
        result = await dispatcher.adispatch(
            agent, "write", {"path": "workspace/file"}, trigger_id="loop", credential=credential
        )
        assert result.value == "done"
        assert calls == ["workspace/file"]
        assert breaker.status("loop").probes == 1
    else:
        with pytest.raises(ToolDenied):
            await dispatcher.adispatch(
                agent, "write", {"path": "workspace/file"}, trigger_id="loop", credential=credential
            )
        assert calls == []
