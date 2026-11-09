"""Admission must remain valid after listeners and async scheduling."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from acgs_lite.control_plane import (
    ActionTier,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.autonomy import AutonomyController, ErrorBudget, FailureKind
from acgs_lite.control_plane.budgets import BudgetLedger, BudgetLimits

pytestmark = [pytest.mark.unit, pytest.mark.red_team]
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
SIBLING = Principal("agent-2", PrincipalKind.AGENT, system_id="sys-a")


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async_sync", "async_coroutine"])
@pytest.mark.parametrize("demote", [AGENT, SIBLING, None])
@pytest.mark.parametrize("stage", ["listener", "post_auth"])
async def test_final_admission_rechecks_autonomy_without_recharging(
    pdp: PolicyDecisionPoint,
    mode: str,
    demote: Principal | None,
    stage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    budgets = BudgetLedger()
    budgets.start_run(AGENT, BudgetLimits(iterations=1))
    autonomy = AutonomyController(ErrorBudget(max_failures=1), budgets=budgets)
    calls = []

    def write(path):
        calls.append(path)

    async def awrite(path):
        calls.append(path)

    dispatcher = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            pdp.registry, [WriteGrant(AGENT.id, AGENT.kind, ("workspace/**",))]
        ),
        tool_tiers={"write": ActionTier.T1},
        budgets=budgets,
        autonomy=autonomy,
    )
    dispatcher.register(
        "write", awrite if mode == "async_coroutine" else write, path_params={"path"}
    )
    original = dispatcher._authorize

    def authorize(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        if demote is not None and stage == "post_auth":
            autonomy.record_failure(demote, FailureKind.VERIFICATION_FAILED)
        return result

    def listener(decision: Any) -> None:
        if decision.allowed and demote is not None and stage == "listener":
            autonomy.record_failure(demote, FailureKind.VERIFICATION_FAILED)

    monkeypatch.setattr(pdp, "_listeners", (listener,))
    monkeypatch.setattr(dispatcher, "_authorize", authorize)

    async def invoke():
        if mode == "sync":
            return dispatcher.dispatch(AGENT, "write", {"path": "workspace/a"})
        return await dispatcher.adispatch(AGENT, "write", {"path": "workspace/a"})

    if demote is not None:
        with pytest.raises(ToolDenied, match="autonomy"):
            await invoke()
        assert calls == []
    else:
        await invoke()
        assert calls == ["workspace/a"]
    assert budgets.state(AGENT).iterations == 1


@pytest.mark.asyncio
async def test_coroutine_body_rechecks_demotion_after_worker(
    pdp: PolicyDecisionPoint,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    autonomy = AutonomyController(ErrorBudget(max_failures=1))
    calls = []

    async def write(path):
        calls.append(path)

    dispatcher = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            pdp.registry, [WriteGrant(AGENT.id, AGENT.kind, ("workspace/**",))]
        ),
        tool_tiers={"write": ActionTier.T1},
        autonomy=autonomy,
    )
    dispatcher.register("write", write, path_params={"path"})
    original = asyncio.to_thread

    async def demote_after_worker(fn: Any, *args: Any, **kwargs: Any) -> Any:
        result = await original(fn, *args, **kwargs)
        autonomy.record_failure(AGENT, FailureKind.VERIFICATION_FAILED)
        return result

    monkeypatch.setattr(asyncio, "to_thread", demote_after_worker)
    with pytest.raises(ToolDenied, match="autonomy"):
        await dispatcher.adispatch(AGENT, "write", {"path": "workspace/a"})
    assert calls == []


def test_admitted_level_fails_closed_if_state_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from acgs_lite.control_plane.autonomy import AutonomyLevel

    autonomy = AutonomyController(ErrorBudget())

    def unavailable(principal):
        raise OSError("unavailable")

    monkeypatch.setattr(autonomy, "is_demoted", unavailable)
    assert autonomy.admitted_level(AGENT) is AutonomyLevel.SUSPENDED
