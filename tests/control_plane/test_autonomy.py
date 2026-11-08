"""Phase 3: error-budget exhaustion automatically demotes autonomy."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from acgs_lite.audit import AuditLog, JSONLAuditBackend
from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    Decision,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.autonomy import (
    AutonomyController,
    AutonomyLevel,
    ErrorBudget,
    FailureKind,
    max_tier_for,
)
from acgs_lite.control_plane.budgets import BudgetLedger, BudgetLimits
from acgs_lite.control_plane.killswitch import KillSwitch

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
ALICE = Principal("alice", PrincipalKind.HUMAN)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _dispatcher(
    pdp: PolicyDecisionPoint, autonomy: AutonomyController, calls: list[str]
) -> GovernedToolDispatcher:
    d = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE, [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))]
        ),
        tool_tiers={"read": ActionTier.T0, "write": ActionTier.T1},
        read_only_tools=frozenset({"read"}),
        autonomy=autonomy,
    )

    def read(path: str) -> str:
        calls.append("read:" + path)
        return "data"

    def write(path: str) -> str:
        calls.append("write:" + path)
        return "ok"

    d.register("read", read, path_params={"path"})
    d.register("write", write, path_params={"path"})
    return d


class TestErrorBudget:
    def test_failures_in_window_demote_and_are_audited(self, tmp_path: Path) -> None:
        clock = Clock()
        log = AuditLog(backend=JSONLAuditBackend(tmp_path / "audit.jsonl"))
        autonomy = AutonomyController(
            ErrorBudget(window_s=60, max_failures=3), audit_log=log, clock=clock
        )
        for _ in range(2):
            autonomy.record_failure(AGENT, FailureKind.VERIFICATION_FAILED)
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED
        level = autonomy.record_failure(AGENT, "verification_failed")
        assert level is AutonomyLevel.P0_ONLY
        demotions = [e for e in log.entries if e.type == "autonomy_demotion"]
        assert len(demotions) == 1
        assert demotions[0].agent_id == "agent-1" and not demotions[0].valid
        assert "error budget" in demotions[0].metadata["reason"]
        assert "autonomy_demotion" in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        autonomy.record_failure(AGENT, FailureKind.VERIFICATION_FAILED)
        assert len([e for e in log.entries if e.type == "autonomy_demotion"]) == 1  # sticky
        assert tuple(autonomy.principals_demoted()) == ("agent-1",)
        autonomy.restore(ALICE, AGENT)
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED
        assert [e.type for e in log.entries][-1] == "autonomy_restore"

    def test_failures_outside_window_do_not_count(self) -> None:
        clock = Clock()
        autonomy = AutonomyController(ErrorBudget(window_s=60, max_failures=3), clock=clock)
        for _ in range(2):
            autonomy.record_failure(AGENT, FailureKind.VERIFICATION_FAILED)
        clock.now += 61
        autonomy.record_failure(AGENT, FailureKind.VERIFICATION_FAILED)
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED
        clock.now += 1
        autonomy.record_failure(AGENT, FailureKind.VERIFICATION_FAILED)
        autonomy.record_failure(AGENT, FailureKind.VERIFICATION_FAILED)
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY

    def test_rollbacks_and_uncounted_kinds(self) -> None:
        autonomy = AutonomyController(
            ErrorBudget(
                max_failures=1,
                max_rollbacks=2,
                counted_kinds=frozenset({FailureKind.VERIFICATION_FAILED}),
            ),
            durable_audit=False,
            audit_log=AuditLog(),
        )
        autonomy.record_failure(AGENT, FailureKind.POLICY_DENIAL)  # not counted
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED
        autonomy.record_failure(AGENT, FailureKind.ROLLBACK)
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED
        assert autonomy.record_rollback(AGENT) is AutonomyLevel.P0_ONLY

    def test_policy_denials_through_dispatcher_demote(self, pdp: PolicyDecisionPoint) -> None:
        autonomy = AutonomyController(ErrorBudget(max_failures=2))
        calls: list[str] = []
        d = _dispatcher(pdp, autonomy, calls)
        for target in ("evaluator/score.py", "policies/main.yaml"):
            with pytest.raises(ToolDenied):
                d.dispatch(AGENT, "write", {"path": target})
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY
        with pytest.raises(ToolDenied, match="P0_ONLY"):
            d.dispatch(AGENT, "write", {"path": "workspace/a.txt"})
        d.dispatch(AGENT, "read", {"path": "workspace/a.txt"})
        assert calls == ["read:workspace/a.txt"]

    def test_humans_are_not_demoted(self) -> None:
        autonomy = AutonomyController(ErrorBudget(max_failures=1, max_rollbacks=1))
        autonomy.record_failure(ALICE, FailureKind.VERIFICATION_FAILED)
        autonomy.record_rollback(ALICE)
        autonomy.demote(ALICE, "x")
        assert autonomy.level(ALICE) is AutonomyLevel.T1_PREAUTHORIZED
        assert not autonomy.is_demoted(ALICE)


class TestLevels:
    def test_kill_switch_suspends(self, tmp_path: Path, pdp: PolicyDecisionPoint) -> None:
        switch = KillSwitch("sys-a", signal_dir=tmp_path / "halt")
        autonomy = AutonomyController(ErrorBudget(), kill_switch=switch)
        calls: list[str] = []
        d = _dispatcher(pdp, autonomy, calls)
        switch.engage(ALICE, "freeze")
        assert autonomy.level(AGENT) is AutonomyLevel.SUSPENDED
        with pytest.raises(ToolDenied, match="suspended"):
            d.dispatch(AGENT, "read", {"path": "workspace/a.txt"})
        assert calls == []

    def test_level_errors_suspend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        budgets = BudgetLedger()
        budgets.start_run(AGENT, BudgetLimits())
        autonomy = AutonomyController(ErrorBudget(), budgets)

        def boom(principal: Principal) -> Any:
            raise RuntimeError("x")

        monkeypatch.setattr(budgets, "state", boom)
        assert autonomy.level(AGENT) is AutonomyLevel.SUSPENDED

    def test_max_tier_for(self) -> None:
        assert max_tier_for(AutonomyLevel.T1_PREAUTHORIZED) is ActionTier.T3
        assert max_tier_for(AutonomyLevel.P0_ONLY) is ActionTier.T0
        assert max_tier_for(AutonomyLevel.SUSPENDED) is None

    def test_demotion_is_receipted_as_a_deny_and_audit_failures_counted(
        self, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        seen: list[Decision] = []
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, listeners=[seen.append]
        ) as pdp:
            # AuditLog() has no durable backend: record_durable raises, the
            # demotion still applies and the failure is counted.
            autonomy = AutonomyController(
                ErrorBudget(max_failures=1), audit_log=AuditLog(), pdp=pdp
            )
            autonomy.record_failure(AGENT, FailureKind.VERIFICATION_FAILED)
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY
        assert autonomy.audit_failures == 1
        assert [d.error for d in seen] == ["autonomy_demoted"]
        assert not seen[0].allowed and seen[0].action == "autonomy.demote"

    def test_validation(self) -> None:
        for bad in ({"window_s": 0}, {"max_failures": 0}, {"max_rollbacks": True}):
            with pytest.raises(ValueError):
                ErrorBudget(**bad)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            AutonomyController("budget")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            AutonomyController(ErrorBudget(), budgets="x")  # type: ignore[arg-type]

    def test_dispatcher_rejects_bad_components(self, pdp: PolicyDecisionPoint) -> None:
        permissions = RepositoryPermissions(DEFAULT_IMMUTABLE_CORE)
        for kwargs in ({"budgets": object()}, {"autonomy": object()}):
            with pytest.raises(TypeError):
                GovernedToolDispatcher(pdp, permissions=permissions, tool_tiers={}, **kwargs)  # type: ignore[arg-type]
