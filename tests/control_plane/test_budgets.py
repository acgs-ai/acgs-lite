"""Phase 3: budgets are enforced outside the model and trigger demotion."""

from __future__ import annotations

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
from acgs_lite.control_plane.autonomy import (
    AutonomyController,
    AutonomyLevel,
    AutonomyRestoreRejected,
    ErrorBudget,
)
from acgs_lite.control_plane.budgets import (
    BudgetChargeRefused,
    BudgetExhausted,
    BudgetLedger,
    BudgetLimits,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
ALICE = Principal("alice", PrincipalKind.HUMAN)
PROXY = Principal("llm-proxy", PrincipalKind.SERVICE)


class Clock:
    def __init__(self) -> None:
        self.now = 50.0

    def __call__(self) -> float:
        return self.now


def _dispatcher(
    pdp: PolicyDecisionPoint,
    budgets: BudgetLedger,
    calls: list[str],
    autonomy: AutonomyController | None = None,
) -> GovernedToolDispatcher:
    d = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE, [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))]
        ),
        tool_tiers={"read": ActionTier.T0, "write": ActionTier.T1},
        read_only_tools=frozenset({"read"}),
        budgets=budgets,
        autonomy=autonomy,
    )

    def read(path: str) -> str:
        calls.append("read:" + path)
        return "data"

    def write(path: str) -> str:
        calls.append("write:" + path)
        return "ok"

    d.register("read", read, path_params={"path"}, merge_capable=False)
    d.register("write", write, path_params={"path"}, merge_capable=False)
    return d


ARGS = {"path": "workspace/a"}


class TestEnforcement:
    def test_iterations_exhausted_denies_before_invocation(self, pdp: PolicyDecisionPoint) -> None:
        budgets = BudgetLedger(clock=Clock())
        budgets.start_run(AGENT, BudgetLimits(iterations=2))
        calls: list[str] = []
        d = _dispatcher(pdp, budgets, calls)
        d.dispatch(AGENT, "write", ARGS)
        d.dispatch(AGENT, "write", ARGS)
        with pytest.raises(ToolDenied, match="iterations"):
            d.dispatch(AGENT, "write", ARGS)
        with pytest.raises(ToolDenied):
            d.dispatch(AGENT, "read", ARGS)  # no autonomy controller: everything stops
        assert calls == ["write:workspace/a", "write:workspace/a"]
        assert budgets.state(AGENT).iterations == 2

    @pytest.mark.parametrize(
        ("limits", "charge"),
        [
            (BudgetLimits(spend_usd=1.0), {"spend_usd": 1.25}),
            (BudgetLimits(tokens=1000), {"tokens": 1000}),
        ],
    )
    def test_service_reported_usage_exhausts(
        self, pdp: PolicyDecisionPoint, limits: BudgetLimits, charge: dict[str, float]
    ) -> None:
        budgets = BudgetLedger(clock=Clock())
        budgets.start_run(AGENT, limits)
        calls: list[str] = []
        d = _dispatcher(pdp, budgets, calls)
        d.dispatch(AGENT, "write", ARGS)
        budgets.charge(AGENT, reporter=PROXY, **charge)
        with pytest.raises(ToolDenied, match="budget exhausted"):
            d.dispatch(AGENT, "write", ARGS)
        assert calls == ["write:workspace/a"]

    def test_wall_clock_from_harness_clock(self, pdp: PolicyDecisionPoint) -> None:
        clock = Clock()
        budgets = BudgetLedger(clock=clock)
        budgets.start_run(AGENT, BudgetLimits(wall_clock_s=30))
        calls: list[str] = []
        d = _dispatcher(pdp, budgets, calls)
        d.dispatch(AGENT, "write", ARGS)
        clock.now += 30
        with pytest.raises(ToolDenied, match="wall_clock_s"):
            d.dispatch(AGENT, "write", ARGS)
        assert calls == ["write:workspace/a"]
        with pytest.raises(BudgetExhausted) as excinfo:
            budgets.check(AGENT)
        assert excinfo.value.exhausted == ("wall_clock_s",)

    def test_agent_cannot_report_usage(self) -> None:
        budgets = BudgetLedger()
        budgets.start_run(AGENT, BudgetLimits(tokens=10))
        for reporter in (AGENT, Principal("agent-9", PrincipalKind.AGENT), "llm-proxy"):
            with pytest.raises(BudgetChargeRefused):
                budgets.charge(AGENT, tokens=0, reporter=reporter)  # type: ignore[arg-type]
        budgets.charge(AGENT, tokens=3, reporter=ALICE)
        assert budgets.check(AGENT).tokens == 3

    def test_no_run_means_deny_for_agents_but_not_humans(
        self, gated_pdp: PolicyDecisionPoint
    ) -> None:
        calls: list[str] = []
        d = _dispatcher(gated_pdp, BudgetLedger(), calls)
        with pytest.raises(ToolDenied, match="no budget run"):
            d.dispatch(AGENT, "write", ARGS)
        d.dispatch(ALICE, "read", ARGS)
        assert calls == ["read:workspace/a"]

    def test_validation(self) -> None:
        for bad in ({"spend_usd": -1}, {"tokens": "5"}, {"iterations": float("inf")}):
            with pytest.raises(ValueError):
                BudgetLimits(**bad)  # type: ignore[arg-type]
        budgets = BudgetLedger()
        with pytest.raises(TypeError):
            budgets.start_run("agent", BudgetLimits())  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            budgets.start_run(AGENT, {"tokens": 1})  # type: ignore[arg-type]
        budgets.start_run(AGENT, BudgetLimits())
        for bad_amount in (-1, float("nan"), True):
            with pytest.raises(ValueError):
                budgets.charge(AGENT, tokens=bad_amount)
        with pytest.raises(KeyError):
            budgets.charge(ALICE, tokens=1)
        assert not budgets.check(AGENT).is_exhausted


class TestDemotion:
    def test_exhaustion_demotes_to_p0_only(self, pdp: PolicyDecisionPoint) -> None:
        budgets = BudgetLedger(clock=Clock())
        budgets.start_run(AGENT, BudgetLimits(iterations=1))
        autonomy = AutonomyController(ErrorBudget(), budgets)
        calls: list[str] = []
        d = _dispatcher(pdp, budgets, calls, autonomy)
        d.dispatch(AGENT, "write", ARGS)
        with pytest.raises(ToolDenied):
            d.dispatch(AGENT, "write", ARGS)
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY
        d.dispatch(AGENT, "read", ARGS)  # T0 read still allowed
        with pytest.raises(ToolDenied, match="budget exhausted"):
            d.dispatch(AGENT, "write", ARGS)
        assert calls == ["write:workspace/a", "read:workspace/a"]

        with pytest.raises(AutonomyRestoreRejected):
            autonomy.restore(AGENT, AGENT)
        autonomy.restore(ALICE, AGENT)
        # The budget itself is still spent: the next level check demotes again.
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY
        autonomy.restore(ALICE, AGENT)
        budgets.start_run(AGENT, BudgetLimits(iterations=5))
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED
        d.dispatch(AGENT, "write", ARGS)
        assert calls[-1] == "write:workspace/a"

    def test_level_check_alone_demotes_on_reported_spend(self, pdp: PolicyDecisionPoint) -> None:
        budgets = BudgetLedger(clock=Clock())
        budgets.start_run(AGENT, BudgetLimits(spend_usd=2))
        autonomy = AutonomyController(ErrorBudget(), budgets)
        calls: list[str] = []
        d = _dispatcher(pdp, budgets, calls, autonomy)
        budgets.charge(AGENT, spend_usd=2, reporter=PROXY)
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY
        assert autonomy.is_demoted(AGENT)
        with pytest.raises(ToolDenied):
            d.dispatch(AGENT, "write", ARGS)
        d.dispatch(AGENT, "read", ARGS)
        assert calls == ["read:workspace/a"]
