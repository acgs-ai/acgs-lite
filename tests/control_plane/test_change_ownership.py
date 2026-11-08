"""Phase 5: single writer per change (own worktree / branch only)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from acgs_lite.control_plane import DEFAULT_IMMUTABLE_CORE, Principal, PrincipalKind
from acgs_lite.control_plane.change_ownership import (
    ChangeOwnershipRegistry,
    OwnershipDenied,
    branch_for,
)

pytestmark = [pytest.mark.unit]

ADMIN = Principal("root-admin", PrincipalKind.HUMAN)
AGENT = Principal("Agent-1", PrincipalKind.AGENT, system_id="sys-a")
OTHER = Principal("agent-2", PrincipalKind.AGENT, system_id="sys-a")
WT = "workspace/wt/agent-1/c1"


@pytest.fixture()
def owners(tmp_path: Path) -> ChangeOwnershipRegistry:
    (tmp_path / WT).mkdir(parents=True)
    registry = ChangeOwnershipRegistry(
        DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)), admin=ADMIN
    )
    registry.assign(ADMIN, "c1", AGENT, WT)
    return registry


def test_branch_name() -> None:
    assert branch_for(AGENT, "c1") == "agent/agent-1/c1"


@pytest.mark.parametrize(
    "principal_id,change_id",
    [
        ("agent:1", "c1"),
        ("agent-1", "change.lock"),
        (".agent", "c1"),
        ("agent..1", "c1"),
        ("agent-1", "change."),
    ],
)
def test_invalid_git_branch_rejected_before_assignment(principal_id: str, change_id: str) -> None:
    principal = Principal(principal_id, PrincipalKind.AGENT)
    raw = f"agent/{principal.canonical_id}/{change_id}"
    assert (
        subprocess.run(["git", "check-ref-format", "--branch", raw], capture_output=True).returncode
        != 0
    )
    registry = ChangeOwnershipRegistry(DEFAULT_IMMUTABLE_CORE, admin=ADMIN)
    with pytest.raises(OwnershipDenied, match="Git branch"):
        registry.assign(ADMIN, change_id, principal, "workspace/wt")
    assert registry.get(change_id) is None


@pytest.mark.parametrize(
    "principal_id,change_id", [("agent-1", "c1"), ("agent@host", "change.v2"), ("_agent", "c_1")]
)
def test_valid_branch_names_pass_git(principal_id: str, change_id: str) -> None:
    branch = branch_for(Principal(principal_id, PrincipalKind.AGENT), change_id)
    assert (
        subprocess.run(
            ["git", "check-ref-format", "--branch", branch], capture_output=True
        ).returncode
        == 0
    )


def test_worktree_containment_preserves_case_without_repo_root() -> None:
    owners = ChangeOwnershipRegistry(DEFAULT_IMMUTABLE_CORE, admin=ADMIN)
    owners.assign(ADMIN, "c1", AGENT, "workspace/A")
    owners.assert_writer(AGENT, "c1", "workspace/A/payload.md")
    with pytest.raises(OwnershipDenied, match="outside"):
        owners.assert_writer(AGENT, "c1", "workspace/a/payload.md")


def test_owner_inside_worktree(owners: ChangeOwnershipRegistry) -> None:
    ownership = owners.assert_writer(AGENT, "c1", f"{WT}/prompts/a.md", branch="agent/agent-1/c1")
    assert ownership.worktree_root == WT
    owners.assert_writer(AGENT, "c1", WT)
    assert owners.get("c1") is ownership


@pytest.mark.parametrize(
    "path",
    [
        "workspace/wt/agent-1/c2/x.md",
        f"{WT}/../c2/x.md",
        f"{WT}/../../../evaluator/x.py",
        "../outside.md",
        "/etc/passwd",
        "workspace/wt/agent-1/c1x/a.md",
    ],
)
def test_outside_worktree_denied(owners: ChangeOwnershipRegistry, path: str) -> None:
    with pytest.raises(OwnershipDenied, match="outside"):
        owners.assert_writer(AGENT, "c1", path)


def test_second_writer_and_wrong_branch_denied(owners: ChangeOwnershipRegistry) -> None:
    with pytest.raises(OwnershipDenied, match="not the writer"):
        owners.assert_writer(OTHER, "c1", f"{WT}/a.md")
    with pytest.raises(OwnershipDenied, match="not the writer"):
        owners.assert_writer(Principal("agent-1", PrincipalKind.HUMAN), "c1", f"{WT}/a.md")
    with pytest.raises(OwnershipDenied, match="branch"):
        owners.assert_writer(AGENT, "c1", f"{WT}/a.md", branch="main")
    with pytest.raises(OwnershipDenied, match="already has writer"):
        owners.assign(ADMIN, "c1", OTHER, "workspace/wt/agent-2/c1")
    with pytest.raises(OwnershipDenied, match="no assigned writer"):
        owners.assert_writer(AGENT, "c9", f"{WT}/a.md")
    with pytest.raises(OwnershipDenied, match="change_id is required"):
        owners.assert_writer(AGENT, None, f"{WT}/a.md")


def test_symlink_escape_denied(tmp_path: Path, owners: ChangeOwnershipRegistry) -> None:
    (tmp_path / "evaluator").mkdir()
    os.symlink(tmp_path / "evaluator", tmp_path / WT / "link")
    with pytest.raises(OwnershipDenied, match="symlink"):
        owners.assert_writer(AGENT, "c1", f"{WT}/link/score.py")


def test_symlinked_root_denied(tmp_path: Path) -> None:
    (tmp_path / "workspace" / "real").mkdir(parents=True)
    os.symlink(tmp_path / "workspace" / "real", tmp_path / "workspace" / "wtlink")
    registry = ChangeOwnershipRegistry(
        DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)), admin=ADMIN
    )
    registry.assign(ADMIN, "c1", AGENT, "workspace/wtlink")
    with pytest.raises(OwnershipDenied, match="symlink"):
        registry.assert_writer(AGENT, "c1", "workspace/wtlink/a.md")


def test_assignment_rules(owners: ChangeOwnershipRegistry) -> None:
    with pytest.raises(OwnershipDenied, match="HUMAN"):
        owners.assign(AGENT, "c2", AGENT, "workspace/wt/c2")
    with pytest.raises(OwnershipDenied, match="Principal"):
        owners.assign(ADMIN, "c2", "agent", "workspace/wt/c2")  # type: ignore[arg-type]
    with pytest.raises(OwnershipDenied, match="change_id"):
        owners.assign(ADMIN, "bad id", AGENT, "workspace/wt/c2")
    for root in (".", "../x", "src", "evaluator/sub", "control-plane/x"):
        with pytest.raises(OwnershipDenied):
            owners.assign(ADMIN, "c2", AGENT, root)
    with pytest.raises(OwnershipDenied, match="overlaps"):
        owners.assign(ADMIN, "c2", OTHER, f"{WT}/nested")
    with pytest.raises(OwnershipDenied, match="HUMAN"):
        owners.release(AGENT, "c1")
    assert owners.release(ADMIN, "c1") is True
    assert owners.release(ADMIN, "c1") is False
    with pytest.raises(TypeError):
        ChangeOwnershipRegistry("core", admin=ADMIN)  # type: ignore[arg-type]
    assert owners.registry.repo_root is not None


def test_without_repo_root_still_checks_prefix() -> None:
    registry = ChangeOwnershipRegistry(DEFAULT_IMMUTABLE_CORE, admin=ADMIN)
    registry.assign(ADMIN, "c1", AGENT, WT)
    registry.assert_writer(AGENT, "c1", f"{WT}/a.md")
    with pytest.raises(OwnershipDenied):
        registry.assert_writer(AGENT, "c1", "workspace/other.md")


# -- through the dispatcher and the PDP -------------------------------------

from typing import Any  # noqa: E402

from acgs_lite.control_plane import ActionTier, DecisionRequest, ToolDenied  # noqa: E402
from acgs_lite.control_plane.runbook import RunbookRejected  # noqa: E402

A1 = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
A2 = Principal("agent-2", PrincipalKind.AGENT, system_id="sys-a")
SVC = Principal("ci-bot", PrincipalKind.SERVICE)
ALICE = Principal("alice", PrincipalKind.HUMAN)


class TestDispatcherOwnership:
    def _approvals(
        self, p5: Any, factory: Any, principal: Principal, tool: str, args: Any, **kw: Any
    ) -> list[Any]:
        digest = p5.dispatcher.action_hash_for(principal, tool, args, **kw)
        return [factory("bob")(digest)]

    def test_owner_writes_inside_worktree(self, p5: Any, approver_factory: Any) -> None:
        pytest.importorskip("cryptography")
        args = {"path": f"{p5.worktree}/prompt.md", "content": "x"}
        kw: dict[str, Any] = {"change_id": "c1", "requested_by": "olivia"}
        approvals = self._approvals(p5, approver_factory, A1, "write_file", args, **kw)
        p5.dispatcher.dispatch(A1, "write_file", args, approvals=approvals, **kw)
        assert p5.calls == [("write_file", args["path"])]

    @pytest.mark.parametrize(
        ("principal", "path", "change_id", "match"),
        [
            (A1, "{wt}/a.md", None, "change_id"),
            (A2, "{wt}/a.md", "c1", "not the writer"),
            (A1, "workspace/elsewhere.md", "c1", "outside"),
            (A1, "{wt}/../c2/a.md", "c1", "INV-TOOL-ARG-CORE"),
            (A1, "{wt}/link/x.md", "c1", "symlink"),
            (A1, "{wt}/a.md", "c9", "no assigned writer"),
        ],
    )
    def test_writes_denied(
        self, p5: Any, principal: Principal, path: str, change_id: str | None, match: str
    ) -> None:
        (p5.root / "workspace" / "target").mkdir()
        os.symlink(p5.root / "workspace" / "target", p5.root / p5.worktree / "link")
        with pytest.raises(ToolDenied, match=match):
            p5.dispatcher.dispatch(
                principal,
                "write_file",
                {"path": path.format(wt=p5.worktree)},
                change_id=change_id,
                requested_by="olivia",
            )
        assert p5.calls == []

    def test_branch_must_be_owners(self, p5: Any) -> None:
        with pytest.raises(ToolDenied, match="branch"):
            p5.dispatcher.dispatch(
                A1,
                "git_commit",
                {"path": f"{p5.worktree}/a", "branch": "main"},
                change_id="c1",
                requested_by="olivia",
            )
        with pytest.raises(ValueError, match="branch_param"):
            p5.dispatcher.register(
                "x",
                lambda path, b: None,
                path_params={"path"},
                opaque_params={"b"},
                branch_param="branch",
                merge_capable=False,
            )

    def test_human_without_change_id_allowed_by_ownership(
        self, p5: Any, approver_factory: Any
    ) -> None:
        pytest.importorskip("cryptography")
        args = {"path": "workspace/notes.md"}
        approvals = self._approvals(p5, approver_factory, ALICE, "write_file", args)
        p5.dispatcher.dispatch(ALICE, "write_file", args, approvals=approvals)

    @pytest.mark.parametrize("principal", [A1, SVC])
    def test_agent_cannot_merge_even_with_approval(
        self, p5: Any, approver_factory: Any, principal: Principal
    ) -> None:
        pytest.importorskip("cryptography")
        kw: dict[str, Any] = {"change_id": "c1"}
        if principal is A1:
            kw["requested_by"] = "olivia"
        approvals = self._approvals(p5, approver_factory, principal, "pr.merge", {"pr": "7"}, **kw)
        with pytest.raises(ToolDenied) as excinfo:
            p5.dispatcher.dispatch(principal, "pr.merge", {"pr": "7"}, approvals=approvals, **kw)
        if principal is A1:  # the change owner gets past ownership; the PDP forbids
            assert "INV-AGENT-NO-MERGE" in excinfo.value.decision.determining_policies
        else:
            assert "not the writer" in excinfo.value.decision.reason
        assert p5.calls == []

    def test_human_may_merge_with_approval(self, p5: Any, approver_factory: Any) -> None:
        pytest.importorskip("cryptography")
        approvals = self._approvals(p5, approver_factory, ALICE, "pr.merge", {"pr": "7"})
        p5.dispatcher.dispatch(ALICE, "pr.merge", {"pr": "7"}, approvals=approvals)
        assert p5.calls == [("pr.merge", "7")]

    @pytest.mark.parametrize(
        "action", ["git.merge", "pr.merge", "pr.approve", "change.approve", "PR.Merge"]
    )
    def test_pdp_forbids_agent_merge_actions(self, pdp: Any, action: str) -> None:
        for principal in (A1, SVC):
            decision = pdp.decide(DecisionRequest(principal, action, "repo#7", ActionTier.T2))
            assert "INV-AGENT-NO-MERGE" in decision.determining_policies
        via_tool = DecisionRequest(
            A1, "file.write", "workspace/a", ActionTier.T1, attributes={"via_tool": "pr.merge"}
        )
        assert "INV-AGENT-NO-MERGE" in pdp.decide(via_tool).determining_policies
        human = pdp.decide(DecisionRequest(ALICE, action, "repo#7", ActionTier.T1))
        assert "INV-AGENT-NO-MERGE" not in human.determining_policies


class TestBranchAndMergeHardening:
    """H1: a branch default or ``None`` must not bypass branch ownership."""

    def _register_push(self, p5: Any) -> list[str]:
        from acgs_lite.control_plane.tier_policy import ActionProfile

        pushed: list[str] = []

        def git_push(branch: str | None = "main") -> str:
            pushed.append(str(branch))
            return "pushed"

        p5.dispatcher.register(
            "git.push",
            git_push,
            opaque_params={"branch"},
            branch_param="branch",
            profile=lambda a: ActionProfile(True, False, 1, False),
            merge_capable=False,
            merge_capable_override_reason="test: pushes the owned change branch",
        )
        return pushed

    def _push_runbook(self, p5: Any, runbook_data: Any, **selector: Any) -> str:
        data = runbook_data()
        data["scope_selector"] = {**data["scope_selector"], "tools": ["git.push"], **selector}
        return p5.approve_runbook(data)

    @pytest.mark.parametrize("args", [{}, {"branch": None}, {"branch": "main"}])
    def test_default_none_or_foreign_branch_denied(
        self, p5: Any, runbook_data: Any, args: dict[str, Any]
    ) -> None:
        pushed = self._register_push(p5)
        digest = self._push_runbook(p5, runbook_data, allow_pathless=True)
        with pytest.raises(ToolDenied, match="branch"):
            p5.dispatcher.dispatch(
                A1,
                "git.push",
                args,
                change_id="c1",
                runbook_id="rb-restart-cache",
                runbook_hash=digest,
            )
        assert pushed == []

    def test_owned_branch_allowed_only_with_allow_pathless(
        self, p5: Any, runbook_data: Any
    ) -> None:
        pushed = self._register_push(p5)
        args = {"branch": "agent/agent-1/c1"}
        digest = self._push_runbook(p5, runbook_data)
        with pytest.raises(ToolDenied, match="allow_pathless"):
            p5.dispatcher.dispatch(
                A1,
                "git.push",
                args,
                change_id="c1",
                runbook_id="rb-restart-cache",
                runbook_hash=digest,
            )
        digest = self._push_runbook(p5, runbook_data, allow_pathless=True)
        p5.dispatcher.dispatch(
            A1, "git.push", args, change_id="c1", runbook_id="rb-restart-cache", runbook_hash=digest
        )
        assert pushed == ["agent/agent-1/c1"]

    def test_branch_tool_without_ownership_denied_for_agents(self, gated_pdp: Any) -> None:
        from acgs_lite.control_plane import (
            GovernedToolDispatcher,
            RepositoryPermissions,
        )

        d = GovernedToolDispatcher(
            gated_pdp,
            permissions=RepositoryPermissions(gated_pdp.registry),
            tool_tiers={"push": ActionTier.T2},
        )
        d.register(
            "push",
            lambda branch="main": branch,
            opaque_params={"branch"},
            branch_param="branch",
            merge_capable=False,
            merge_capable_override_reason="test: branch-push tool",
        )
        with pytest.raises(ToolDenied, match="change ownership"):
            d.dispatch(A1, "push", {}, requested_by="olivia")

    def test_merge_capable_flag_forbids_agents_and_runbooks(
        self, p5: Any, runbook_data: Any, approver_factory: Any
    ) -> None:
        pytest.importorskip("cryptography")
        from acgs_lite.control_plane.tier_policy import ActionProfile

        p5.dispatcher.register(
            "ship_it",
            lambda pr: "shipped",
            opaque_params={"pr"},
            merge_capable=True,
            profile=lambda a: ActionProfile(True, False, 1, False),
        )
        with pytest.raises(TypeError):
            p5.dispatcher.register("bad", lambda pr: pr, opaque_params={"pr"}, merge_capable="yes")  # type: ignore[arg-type]
        glob = runbook_data()
        glob["scope_selector"] = {**glob["scope_selector"], "tools": ["*"], "allow_pathless": True}
        with pytest.raises(RunbookRejected, match="exact tool names"):
            p5.approve_runbook(glob)
        data = runbook_data()
        data["scope_selector"] = {
            **data["scope_selector"],
            "tools": ["ship_it"],
            "allow_pathless": True,
        }
        digest = p5.approve_runbook(data)
        with pytest.raises(ToolDenied, match="never covered by a runbook"):
            p5.dispatcher.dispatch(
                A1,
                "ship_it",
                {"pr": "7"},
                change_id="c1",
                runbook_id="rb-restart-cache",
                runbook_hash=digest,
            )
        kw: dict[str, Any] = {"change_id": "c1", "requested_by": "olivia"}
        approvals = self._approvals(p5, approver_factory, A1, "ship_it", {"pr": "7"}, **kw)
        with pytest.raises(ToolDenied) as excinfo:
            p5.dispatcher.dispatch(A1, "ship_it", {"pr": "7"}, approvals=approvals, **kw)
        assert "INV-AGENT-NO-MERGE" in excinfo.value.decision.determining_policies

    def _approvals(
        self, p5: Any, factory: Any, principal: Principal, tool: str, args: Any, **kw: Any
    ) -> list[Any]:
        digest = p5.dispatcher.action_hash_for(principal, tool, args, **kw)
        return [factory("bob")(digest)]

    def test_rate_limit_keyed_per_principal(self, p5: Any, runbook_data: Any) -> None:
        data = runbook_data(rate_limit={"max_executions": 1, "per_seconds": 3600})
        data["scope_selector"] = {
            **data["scope_selector"],
            "principals": [],
            "system_ids": ["sys-a"],
        }
        digest = p5.approve_runbook(data)
        p5.runbooks.check_execution(
            "rb-restart-cache",
            digest,
            tool_name="write_file",
            paths=["workspace/a"],
            principal=A1,
            blast_radius=1,
            signals=None,
        )
        # A sibling has its own window; the first principal's is spent.
        p5.runbooks.check_execution(
            "rb-restart-cache",
            digest,
            tool_name="write_file",
            paths=["workspace/a"],
            principal=A2,
            blast_radius=1,
        )
        from acgs_lite.control_plane.runbook import RunbookDenied

        with pytest.raises(RunbookDenied, match="rate limit"):
            p5.runbooks.check_execution(
                "rb-restart-cache",
                digest,
                tool_name="write_file",
                paths=["workspace/a"],
                principal=A1,
                blast_radius=1,
            )
