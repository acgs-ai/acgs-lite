"""The service intent hook cannot leave stale execution admission behind."""

from pathlib import Path
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
)
from acgs_lite.control_plane.breaker import BreakerPolicy, TriggerCircuitBreaker, TriggerRegistry
from acgs_lite.control_plane.credentials import CredentialIssuer
from acgs_lite.control_plane.killswitch import KillSwitch
from acgs_lite.control_plane.telemetry import (
    InMemoryTelemetryStore,
    OversightMetrics,
    TelemetryRecorder,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]


@pytest.mark.parametrize("mode", ["sync", "async_sync", "async_coroutine"])
@pytest.mark.parametrize("interruption", ["breaker", "halt", "expiry"])
async def test_hook_invalidates_sync_execution_and_keeps_one_decision_group(
    constitution: Constitution,
    permit_all: PolicySet,
    tmp_path: Path,
    mode: str,
    interruption: str,
) -> None:
    now = [1000.0]
    halted = [False]
    admin = Principal("admin", PrincipalKind.HUMAN)
    agent = Principal("agent", PrincipalKind.AGENT)
    store = InMemoryTelemetryStore()
    recorder = TelemetryRecorder(
        store, Principal("ci", PrincipalKind.SERVICE), clock=lambda: now[0]
    )
    registry = TriggerRegistry()
    registry.bind(admin, "loop", principals=[agent])
    breaker = TriggerCircuitBreaker(
        BreakerPolicy(max_rollbacks=1), store, registry=registry, clock=lambda: now[0]
    )
    issuer = CredentialIssuer(clock=lambda: now[0])
    credential = issuer.issue(agent, scopes={"tool:read"}, ttl_s=1)
    switch = KillSwitch("sys-a", signal_dir=tmp_path / "halt", probe=lambda _: halted[0])
    calls: list[str] = []
    with PolicyDecisionPoint.for_constitution(constitution, permit_all, telemetry=recorder) as pdp:
        dispatcher = GovernedToolDispatcher(
            pdp,
            permissions=RepositoryPermissions(DEFAULT_IMMUTABLE_CORE, []),
            tool_tiers={"read": ActionTier.T0},
            read_only_tools={"read"},
            breaker=breaker,
            kill_switch=switch,
            credential_issuer=issuer,
            require_credential=True,
        )

        async def read() -> None:
            calls.append("ran")

        fn = read if mode == "async_coroutine" else lambda: calls.append("ran")
        dispatcher.register("read", fn, merge_capable=False)

        def hook(_decisions: Any) -> None:
            if interruption == "breaker":
                recorder.record_rollback("loop", "failure")
            elif interruption == "halt":
                halted[0] = True
            else:
                now[0] += 2

        kwargs = dict(credential=credential.token, trigger_id="loop", on_authorized=hook)
        with pytest.raises(ToolDenied) as denied:
            if mode != "sync":
                await dispatcher.adispatch(agent, "read", {}, **kwargs)
            else:
                dispatcher.dispatch(agent, "read", {}, **kwargs)
        assert denied.value.decision.credential_id == credential.credential_id
        assert calls == []
    recorder.record_override(denied.value.decision.decision_id, admin, "human_overrode_deny")
    metric = OversightMetrics(store).override_rate("agent")
    assert metric.denominator == metric.numerator == 1
