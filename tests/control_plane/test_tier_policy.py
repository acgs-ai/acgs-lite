"""Phase 5: tier classification by irreversibility and blast radius."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

import pytest

from acgs_lite.control_plane import ActionTier, Principal, PrincipalKind
from acgs_lite.control_plane.runbook import parse_runbook
from acgs_lite.control_plane.tier_policy import (
    ActionProfile,
    ReviewOutcome,
    ReviewQueue,
    classify_tier,
    static_profile,
    t3_execution_problem,
)

pytestmark = [pytest.mark.unit]

AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")


def profile(**kw: Any) -> ActionProfile:
    base: dict[str, Any] = {
        "reversible": True,
        "data_destroying": False,
        "blast_radius": 1,
        "novel": False,
    }
    base.update(kw)
    return ActionProfile(**base)


class TestClassify:
    def test_signature_takes_no_confidence(self) -> None:
        params = inspect.signature(classify_tier).parameters
        assert list(params) == ["profile", "runbook", "narrow_max_blast_radius"]
        assert not any("confid" in name for name in params)
        assert not any("confid" in name for name in ActionProfile.__dataclass_fields__)

    @pytest.mark.parametrize(
        ("kw", "with_runbook", "expected"),
        [
            ({"read_only": True, "blast_radius": 0}, False, ActionTier.T0),
            ({"read_only": True, "blast_radius": 0}, True, ActionTier.T0),
            ({}, True, ActionTier.T1),
            ({"blast_radius": 3}, True, ActionTier.T1),
            ({"blast_radius": 4}, True, ActionTier.T2),  # wider than the runbook
            ({"blast_radius": 0}, True, ActionTier.T2),
            ({"novel": True}, True, ActionTier.T2),
            ({}, False, ActionTier.T2),  # no runbook
            ({"reversible": False}, True, ActionTier.T3),
            ({"data_destroying": True}, True, ActionTier.T3),
            ({"data_destroying": True, "has_verified_backup": True}, False, ActionTier.T3),
        ],
    )
    def test_table(
        self,
        runbook_data: Callable[..., dict[str, Any]],
        kw: dict[str, Any],
        with_runbook: bool,
        expected: ActionTier,
    ) -> None:
        runbook = parse_runbook(runbook_data()) if with_runbook else None
        assert classify_tier(profile(**kw), runbook=runbook) is expected

    def test_narrow_cap_applies_on_top_of_runbook(
        self, runbook_data: Callable[..., dict[str, Any]]
    ) -> None:
        runbook = parse_runbook(runbook_data(max_blast_radius=50))
        assert classify_tier(profile(blast_radius=11), runbook=runbook) is ActionTier.T2
        assert (
            classify_tier(profile(blast_radius=11), runbook=runbook, narrow_max_blast_radius=20)
            is ActionTier.T1
        )

    def test_non_t1_runbook_gives_t2(self, runbook_data: Callable[..., dict[str, Any]]) -> None:
        assert (
            classify_tier(profile(), runbook=parse_runbook(runbook_data(action_tier=2)))
            is ActionTier.T2
        )

    def test_validation(self) -> None:
        with pytest.raises(TypeError):
            classify_tier("T0")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            classify_tier(profile(), narrow_max_blast_radius=0)
        with pytest.raises(TypeError):
            profile(reversible=1)
        with pytest.raises(ValueError):
            profile(blast_radius=-1)
        with pytest.raises(ValueError):
            profile(blast_radius=True)
        with pytest.raises(ValueError):
            profile(read_only=True, data_destroying=True)

    def test_static_profile(self) -> None:
        fixed = profile(blast_radius=2)
        assert static_profile(fixed)({"anything": 1}) is fixed
        with pytest.raises(TypeError):
            static_profile("x")  # type: ignore[arg-type]
        assert fixed.to_canonical()["blast_radius"] == 2


class TestT3Rule:
    def test_human_executes(self, human: Principal) -> None:
        assert t3_execution_problem(human, backup_verified=False) is None

    def test_agent_needs_verified_backup(self) -> None:
        assert t3_execution_problem(AGENT, backup_verified=False) is not None
        assert t3_execution_problem(AGENT, backup_verified=True) is None
        claimed = profile(data_destroying=True, has_verified_backup=False)
        assert "has_verified_backup" in str(
            t3_execution_problem(AGENT, backup_verified=True, profile=claimed)
        )


class TestReviewQueue:
    def test_record_resolve_and_counts(self, human: Principal) -> None:
        now = [100.0]
        queue = ReviewQueue(sla_s=10, clock=lambda: now[0])
        item = queue.record(
            decision_id="d1",
            runbook_id="rb",
            runbook_hash="sha256:" + "a" * 64,
            principal_id="agent-1",
            tool_name="write_file",
        )
        assert queue.snapshot() == {"total": 1, "unresolved": 1, "overdue": 0}
        now[0] = 200.0
        assert queue.overdue() == (item,)
        with pytest.raises(PermissionError):
            queue.resolve(AGENT, item.item_id, "accepted")
        with pytest.raises(PermissionError, match="own action"):
            queue.resolve(Principal("agent-1", PrincipalKind.HUMAN), item.item_id, "accepted")
        with pytest.raises(KeyError):
            queue.resolve(human, "missing", ReviewOutcome.ACCEPTED)
        done = queue.resolve(human, item.item_id, ReviewOutcome.ROLLED_BACK)
        assert done.reviewed_by == "alice" and done.outcome is ReviewOutcome.ROLLED_BACK
        with pytest.raises(ValueError, match="already"):
            queue.resolve(human, item.item_id, "accepted")
        assert queue.snapshot() == {"total": 1, "unresolved": 0, "overdue": 0}


# -- through the dispatcher and the PDP --------------------------------------

from acgs_lite.control_plane import (  # noqa: E402
    DecisionRequest,
    EvidenceSource,
    ExternalRunRef,
    ToolDenied,
)

SVC = Principal("ci-bot", PrincipalKind.SERVICE)


def _approve(
    p5: Any, approver_factory: Any, principal: Principal, tool: str, args: Any, **kw: Any
) -> list[Any]:
    digest = p5.dispatcher.action_hash_for(principal, tool, args, **kw)
    return [approver_factory("bob")(digest), approver_factory("carol")(digest)]


class TestDispatcherTiers:
    def test_tier_is_computed_from_profile(self, p5: Any) -> None:
        d = p5.dispatcher
        assert d.tier_of_call(AGENT, "read_file", {"path": "workspace/a.txt"}) is ActionTier.T0
        assert d.tier_of_call(AGENT, "write_file", {"path": f"{p5.worktree}/a"}) is ActionTier.T2
        with pytest.raises(ValueError, match="T3 by a non-human"):
            d.tier_of_call(AGENT, "delete_file", {"path": f"{p5.worktree}/a"})
        human = Principal("alice", PrincipalKind.HUMAN)
        assert d.tier_of_call(human, "delete_file", {"path": "workspace/a.txt"}) is ActionTier.T3

    def test_caller_tier_lower_than_computed_denied(self, p5: Any) -> None:
        with pytest.raises(ToolDenied, match="lower than the computed tier"):
            p5.dispatcher.dispatch(
                AGENT,
                "write_file",
                {"path": f"{p5.worktree}/a"},
                change_id="c1",
                tier=ActionTier.T0,
            )
        with pytest.raises(ToolDenied, match="not an ActionTier"):
            p5.dispatcher.dispatch(AGENT, "read_file", {"path": "workspace/a.txt"}, tier=True)  # type: ignore[arg-type]
        assert p5.calls == []

    def test_caller_tier_higher_is_ignored(self, p5: Any) -> None:
        result = p5.dispatcher.dispatch(
            AGENT, "read_file", {"path": "workspace/a.txt"}, tier=ActionTier.T3
        )
        assert result.decisions[0].tier is ActionTier.T0

    def test_t2_profile_needs_human_approval(self, p5: Any) -> None:
        with pytest.raises(ToolDenied):
            p5.dispatcher.dispatch(
                AGENT,
                "write_file",
                {"path": f"{p5.worktree}/a"},
                change_id="c1",
                requested_by="olivia",
            )
        assert p5.calls == []

    def test_t3_human_executes_with_two_person(self, p5: Any, approver_factory: Any) -> None:
        pytest.importorskip("cryptography")
        human = Principal("alice", PrincipalKind.HUMAN)
        args = {"path": "workspace/db.sqlite"}
        with pytest.raises(ToolDenied):
            p5.dispatcher.dispatch(human, "delete_file", args)
        approvals = _approve(p5, approver_factory, human, "delete_file", args)
        p5.dispatcher.dispatch(human, "delete_file", args, approvals=approvals)
        assert p5.calls == [("delete_file", "workspace/db.sqlite")]

    def test_t3_agent_needs_verified_backup(self, p5: Any, approver_factory: Any) -> None:
        pytest.importorskip("cryptography")
        args = {"path": f"{p5.worktree}/db.sqlite"}
        kw: dict[str, Any] = {"change_id": "c1", "requested_by": "olivia"}
        log = ExternalRunRef("agent", "bk-1", EvidenceSource.AGENT_LOG)
        for backup in (None, log, ExternalRunRef("backups", "unregistered", "ci_system")):
            with pytest.raises(ToolDenied, match="backup"):
                p5.dispatcher.dispatch(AGENT, "delete_file", args, backup_run=backup, **kw)
        with pytest.raises(ToolDenied, match="ExternalRunRef"):
            p5.dispatcher.dispatch(AGENT, "delete_file", args, backup_run="x", **kw)  # type: ignore[arg-type]
        from acgs_lite.control_plane.dispatcher import backup_subject_digest

        subject = backup_subject_digest("delete_file", args)
        backup = ExternalRunRef(
            "backups", "bk-7", EvidenceSource.CI_SYSTEM, artifact_digest=subject
        )
        p5.runs.register_run(SVC, backup, conclusion="success")
        # Any successful run is not a backup: wrong workflow, unbound digest.
        other = ExternalRunRef("ci", "bk-8", EvidenceSource.CI_SYSTEM, artifact_digest=subject)
        p5.runs.register_run(SVC, other, conclusion="success")
        with pytest.raises(ToolDenied, match="allow-listed workflow"):
            p5.dispatcher.dispatch(AGENT, "delete_file", args, backup_run=other, **kw)
        approvals = _approve(
            p5, approver_factory, AGENT, "delete_file", args, backup_run=backup, **kw
        )
        result = p5.dispatcher.dispatch(
            AGENT, "delete_file", args, backup_run=backup, approvals=approvals, **kw
        )
        assert result.decisions[0].tier is ActionTier.T3
        assert p5.calls == [("delete_file", args["path"])]
        # Single use: the same backup cannot authorise a second destructive call.
        with pytest.raises(ValueError, match="already consumed"):
            p5.dispatcher.tier_of_call(AGENT, "delete_file", args, backup_run=backup)
        # Action-bound: a backup of one target does not cover another.
        other_args = {"path": f"{p5.worktree}/users.sqlite"}
        with pytest.raises(ValueError, match="not bound to this action"):
            p5.dispatcher.tier_of_call(AGENT, "delete_file", other_args, backup_run=backup)

    def test_profile_factory_faults_deny(self, p5: Any, approval_gate: Any) -> None:
        d = p5.dispatcher

        def broken(arguments: Any) -> ActionProfile:
            raise RuntimeError("x")

        def wrong_type(arguments: Any) -> Any:
            return "T0"

        def lies(arguments: Any) -> ActionProfile:
            return ActionProfile(True, False, 0, False, read_only=True)

        for name, factory in (("b1", broken), ("b2", wrong_type), ("b3", lies)):
            d.register(
                name, lambda path: None, path_params={"path"}, profile=factory, merge_capable=False
            )
            with pytest.raises(ToolDenied):
                d.dispatch(AGENT, name, {"path": f"{p5.worktree}/a"}, change_id="c1")
        with pytest.raises(TypeError):
            d.register(
                "b4", lambda path: None, path_params={"path"}, profile="x", merge_capable=False
            )  # type: ignore[arg-type]

    def test_profile_tool_needs_gate(self, pdp: Any) -> None:
        from acgs_lite.control_plane import (
            GovernedToolDispatcher,
            RepositoryPermissions,
        )

        d = GovernedToolDispatcher(
            pdp, permissions=RepositoryPermissions(pdp.registry), tool_tiers={}
        )
        with pytest.raises(ValueError, match="ApprovalGate"):
            d.register(
                "w",
                lambda path: None,
                path_params={"path"},
                profile=static_profile(profile()),
                merge_capable=False,
            )


class TestPdpTierFloor:
    def _req(self, attributes: dict[str, Any], tier: ActionTier) -> DecisionRequest:
        return DecisionRequest(AGENT, "tool.call", "delete_file", tier, attributes=attributes)

    def test_lower_tier_than_profile_floor_denied(self, pdp: Any) -> None:
        destroying = profile(data_destroying=True).to_canonical()
        decision = pdp.decide(self._req({"action_profile": destroying}, ActionTier.T0))
        assert not decision.allowed and "INV-TIER-FLOOR" in decision.determining_policies
        nested = DecisionRequest(
            AGENT,
            "file.write",
            "workspace/a.txt",
            ActionTier.T1,
            attributes={"via_tool": "x", "tool_call": {"action_profile": destroying}},
        )
        assert "INV-TIER-FLOOR" in pdp.decide(nested).determining_policies
        reversible = profile().to_canonical()
        assert pdp.decide(self._req({"action_profile": reversible}, ActionTier.T1)).allowed
        assert not pdp.decide(self._req({"action_profile": reversible}, ActionTier.T0)).allowed
        read = profile(read_only=True, blast_radius=0).to_canonical()
        assert pdp.decide(self._req({"action_profile": read}, ActionTier.T0)).allowed

    @pytest.mark.parametrize(
        "raw", [{"reversible": True}, "T3", {**profile().to_canonical(), "novel": "no"}]
    )
    def test_malformed_profile_denied(self, pdp: Any, raw: Any) -> None:
        decision = pdp.decide(self._req({"action_profile": raw}, ActionTier.T3))
        assert not decision.allowed and decision.error == "evaluation_error"


class TestRegistrationMergeGuard:
    """R2: merge_capable is a required keyword; merge-like names need a reason."""

    def test_merge_capable_is_required(self, p5: Any) -> None:
        with pytest.raises(TypeError):
            p5.dispatcher.register("w2", lambda path: path, path_params={"path"})  # type: ignore[call-arg]

    @pytest.mark.parametrize("name", ["gh.pr_merge", "Approve-PR", "squash", "land_it", "push"])
    def test_merge_like_names_need_flag_or_reason(self, p5: Any, name: str) -> None:
        with pytest.raises(ValueError, match="looks merge-capable"):
            p5.dispatcher.register(name, lambda pr: pr, opaque_params={"pr"}, merge_capable=False)
        with pytest.raises(ValueError, match="looks merge-capable"):
            p5.dispatcher.register(
                name,
                lambda pr: pr,
                opaque_params={"pr"},
                merge_capable=False,
                merge_capable_override_reason="  ",
            )
        p5.dispatcher.register(
            name,
            lambda pr: pr,
            opaque_params={"pr"},
            merge_capable=True,
            profile=lambda a: ActionProfile(True, False, 1, False),
        )
        with pytest.raises(ToolDenied):
            p5.dispatcher.dispatch(AGENT, name, {"pr": "1"}, change_id="c1", requested_by="olivia")
