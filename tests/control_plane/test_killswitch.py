"""Phase 3: an independent kill switch the agent cannot operate."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    DecisionRequest,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.killswitch import (
    DEFAULT_HALT_DIR,
    KillSwitch,
    KillSwitchOperationRejected,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

ROOT = Path(__file__).resolve().parents[2]
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
ALICE = Principal("alice", PrincipalKind.HUMAN)
OPS = Principal("ops-bot", PrincipalKind.SERVICE)
HALT_FILE = (DEFAULT_HALT_DIR / "acgs-halt-sys-a").as_posix()


@pytest.fixture()
def switch(tmp_path: Path) -> KillSwitch:
    return KillSwitch("sys-a", signal_dir=tmp_path / "halt")


@pytest.fixture()
def wired(
    constitution: Constitution, permit_all: PolicySet, switch: KillSwitch
) -> Iterator[tuple[GovernedToolDispatcher, PolicyDecisionPoint, list[str]]]:
    calls: list[str] = []
    with PolicyDecisionPoint.for_constitution(constitution, permit_all, kill_switch=switch) as pdp:
        d = GovernedToolDispatcher(
            pdp,
            permissions=RepositoryPermissions(
                DEFAULT_IMMUTABLE_CORE,
                [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))],
            ),
            tool_tiers={"read": ActionTier.T0, "rm": ActionTier.T1},
            read_only_tools=frozenset({"read"}),
        )

        def read(path: str) -> str:
            calls.append("read:" + path)
            return "data"

        def rm(path: str) -> str:
            calls.append("rm:" + path)
            if os.path.exists(path):
                os.unlink(path)
            return "ok"

        d.register("read", read, path_params={"path"})
        d.register("rm", rm, path_params={"path"})
        yield d, pdp, calls


class TestKillSwitch:
    def test_engaged_by_human_denies_everything_including_t0(
        self,
        wired: tuple[GovernedToolDispatcher, PolicyDecisionPoint, list[str]],
        switch: KillSwitch,
    ) -> None:
        d, pdp, calls = wired
        d.dispatch(AGENT, "read", {"path": "workspace/a"})
        switch.engage(ALICE, "incident 42")
        assert switch.signal_path.exists()
        assert "incident 42" in switch.reason
        for tool in ("read", "rm"):
            with pytest.raises(ToolDenied, match="kill switch"):
                d.dispatch(AGENT, tool, {"path": "workspace/a"})
            with pytest.raises(ToolDenied, match="kill switch"):
                d.dispatch(ALICE, tool, {"path": "workspace/a"})
        decision = pdp.decide(DecisionRequest(ALICE, "file.read", "workspace/a", ActionTier.T0))
        assert not decision.allowed and decision.error == "kill_switch"
        assert calls == ["read:workspace/a"]
        switch.release(ALICE)
        assert not switch.is_engaged()
        d.dispatch(AGENT, "read", {"path": "workspace/a"})
        assert len(calls) == 2

    def test_engaged_by_another_process(
        self,
        wired: tuple[GovernedToolDispatcher, PolicyDecisionPoint, list[str]],
        switch: KillSwitch,
    ) -> None:
        d, _, calls = wired
        code = (
            "import sys; from pathlib import Path\n"
            "from acgs_lite.circuit_breaker import GovernanceCircuitBreaker\n"
            "GovernanceCircuitBreaker('sys-a', signal_dir=Path(sys.argv[1])).trip('remote')\n"
        )
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        subprocess.run(
            [sys.executable, "-c", code, str(switch.signal_path.parent)],
            check=True,
            env=env,
            timeout=60,
        )
        assert switch.is_engaged()
        assert switch.reason == "remote"
        with pytest.raises(ToolDenied, match="kill switch"):
            d.dispatch(AGENT, "read", {"path": "workspace/a"})
        assert calls == []

    def test_unreadable_state_counts_as_engaged(self, tmp_path: Path) -> None:
        def broken(path: Path) -> bool:
            raise PermissionError("EACCES")

        switch = KillSwitch("sys-a", signal_dir=tmp_path / "h", probe=broken)
        assert switch.is_engaged()
        gone = KillSwitch("sys-b", signal_dir=tmp_path / "gone")
        (tmp_path / "gone").rmdir()
        assert gone.is_engaged()

        def weird(path: Path) -> bool:
            raise RuntimeError("?")

        assert KillSwitch("sys-c", signal_dir=tmp_path / "w", probe=weird).is_engaged()

    def test_pdp_and_dispatcher_fail_closed_on_probe_errors(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        switch = KillSwitch("sys-a", signal_dir=tmp_path / "h")

        def explode() -> bool:
            raise RuntimeError("boom")

        monkeypatch.setattr(switch, "is_engaged", explode)
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, kill_switch=switch
        ) as pdp:
            request = DecisionRequest(ALICE, "file.read", "workspace/a", ActionTier.T0)
            assert pdp.decide(request).error == "kill_switch"
            d = GovernedToolDispatcher(
                pdp, permissions=RepositoryPermissions(DEFAULT_IMMUTABLE_CORE), tool_tiers={}
            )
            assert d._kill_switch_engaged()

    def test_agent_cannot_operate_switch(self, switch: KillSwitch) -> None:
        with pytest.raises(KillSwitchOperationRejected):
            switch.engage(AGENT, "x")
        with pytest.raises(KillSwitchOperationRejected):
            switch.engage("alice", "x")  # type: ignore[arg-type]
        switch.engage(OPS, "")
        assert switch.is_engaged()
        for bad in (AGENT, OPS):
            with pytest.raises(KillSwitchOperationRejected):
                switch.release(bad)
        assert switch.is_engaged()
        switch.release(ALICE)
        assert not switch.is_engaged()
        assert switch.reason.startswith("halted")

    def test_agent_cannot_delete_halt_file_through_dispatcher(
        self, wired: tuple[GovernedToolDispatcher, PolicyDecisionPoint, list[str]]
    ) -> None:
        d, _, calls = wired
        assert DEFAULT_IMMUTABLE_CORE.is_core(HALT_FILE)
        for target in (HALT_FILE, DEFAULT_HALT_DIR.as_posix(), "control-plane/halt/"):
            with pytest.raises(ToolDenied):
                d.dispatch(AGENT, "rm", {"path": target})
        assert calls == []

    def test_release_keeps_switch_engaged_if_file_survives(self, tmp_path: Path) -> None:
        switch = KillSwitch("sys-a", signal_dir=tmp_path / "h", probe=lambda path: True)
        switch.engage(ALICE, "stop")
        with pytest.raises(KillSwitchOperationRejected, match="stays engaged"):
            switch.release(ALICE)
        assert switch.is_engaged()

        def failing(path: Path) -> bool:
            raise OSError("io")

        sticky = KillSwitch("sys-b", signal_dir=tmp_path / "s", probe=failing)
        sticky.engage(ALICE, "stop")  # file check fails -> still engaged in-process
        with pytest.raises(KillSwitchOperationRejected):
            sticky.release(ALICE)
        assert sticky.is_engaged()

    def test_engage_without_signal_file_still_halts_in_process(self, tmp_path: Path) -> None:
        switch = KillSwitch("sys-a", signal_dir=tmp_path / "h", probe=lambda path: False)
        switch.engage(ALICE, "stop")
        assert switch.is_engaged()
        assert switch.system_id == "sys-a"

    def test_validation(self, constitution: Constitution, permit_all: PolicySet) -> None:
        with pytest.raises(ValueError):
            KillSwitch("")
        with pytest.raises(ValueError):
            PolicyDecisionPoint.for_constitution(constitution, permit_all, kill_switch=object())  # type: ignore[arg-type]
        with (
            PolicyDecisionPoint.for_constitution(constitution, permit_all) as pdp,
            pytest.raises(TypeError),
        ):
            GovernedToolDispatcher(
                pdp,
                permissions=RepositoryPermissions(DEFAULT_IMMUTABLE_CORE),
                tool_tiers={},
                kill_switch=object(),  # type: ignore[arg-type]
            )
