"""Admission generations preserve probes across async scheduling boundaries."""

from __future__ import annotations

import pytest

from acgs_lite.control_plane.breaker import BreakerPolicy, TriggerCircuitBreaker
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
