"""Phase 3: constitution/allowlist/evaluator/memory-write-policy edits are a
distinct, human-only change class with a second-human approval."""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    CoreCategory,
    CoreChangeWriter,
    CoreWriteRejected,
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
from acgs_lite.control_plane.action_hash import action_hash
from acgs_lite.control_plane.approvals import ApprovalGate, SignedApproval
from acgs_lite.control_plane.change_class import (
    CORE_HUMAN_ONLY_CATEGORIES,
    ChangeClass,
    classify_change,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

ROOT = Path(__file__).resolve().parents[2]
ALICE = Principal("alice", PrincipalKind.HUMAN)
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
SERVICE = Principal("ci-bot", PrincipalKind.SERVICE)
Factory = Callable[..., Callable[..., SignedApproval]]

CORE_EDITS = [
    ("constitution.update", "main"),
    ("policy.update", "p-1"),
    ("allowlist.add", "tools"),
    ("evaluator.update", "grader"),
    ("memory_policy.update", "long-term"),
    ("memory_write_policy.set", "long-term"),
    ("file.write", "policies/main.yaml"),
    ("file.write", "config/constitution.yaml"),
    ("file.write", "config/tool_allowlist.json"),
    ("file.write", "evaluator/score.py"),
    ("file.write", "eval_suites/a.py"),
    ("file.write", "memory-policy/rules.yaml"),
    ("file.write", "agents/memory_write_policy.json"),
    ("file.write", "promotion/rules.yaml"),
    ("file.delete", "sandbox/config.toml"),
]


class TestClassification:
    @pytest.mark.parametrize(("action", "resource"), CORE_EDITS)
    def test_core_edits_are_human_only(self, action: str, resource: str) -> None:
        request = DecisionRequest(ALICE, action, resource, ActionTier.T2)
        assert classify_change(request, DEFAULT_IMMUTABLE_CORE) is ChangeClass.CORE_HUMAN_ONLY

    @pytest.mark.parametrize(
        ("action", "resource"),
        [
            ("file.read", "policies/main.yaml"),
            ("file.write", "workspace/x.py"),
            ("file.write", "secrets/rotation.txt"),
            ("promotion.promote", "candidate-1"),
            ("tool.call", "edit"),
        ],
    )
    def test_routine(self, action: str, resource: str) -> None:
        request = DecisionRequest(ALICE, action, resource, ActionTier.T2)
        assert classify_change(request, DEFAULT_IMMUTABLE_CORE) is ChangeClass.ROUTINE

    def test_memory_write_policy_is_core_and_code_owned(self) -> None:
        assert CoreCategory.MEMORY_WRITE_POLICY in CORE_HUMAN_ONLY_CATEGORIES
        assert (
            DEFAULT_IMMUTABLE_CORE.classify("memory-policy/x.yaml")
            is CoreCategory.MEMORY_WRITE_POLICY
        )
        codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        assert "/memory-policy/** " in codeowners
        manifest = (ROOT / "control-plane" / "immutable-core.yaml").read_text(encoding="utf-8")
        assert "memory_write_policy:" in manifest


def _dispatcher(pdp: PolicyDecisionPoint, calls: list[str]) -> GovernedToolDispatcher:
    permissions = RepositoryPermissions(
        pdp.registry,
        [
            WriteGrant("alice", PrincipalKind.HUMAN, ("**",)),
            WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",)),
        ],
    )
    d = GovernedToolDispatcher(
        pdp,
        permissions=permissions,
        tool_tiers={"edit": ActionTier.T2, "quick_edit": ActionTier.T1, "drop": ActionTier.T3},
        trust_host_identity=True,
    )

    def tool(path: str) -> str:
        calls.append(path)
        return "ok"

    for name in ("edit", "quick_edit", "drop"):
        d.register(name, tool, path_params={"path"}, merge_capable=False)
    return d


@pytest.fixture()
def calls() -> list[str]:
    return []


@pytest.fixture()
def dispatcher(gated_pdp: PolicyDecisionPoint, calls: list[str]) -> GovernedToolDispatcher:
    return _dispatcher(gated_pdp, calls)


TARGETS = [
    "policies/main.yaml",
    "config/tool_allowlist.json",
    "evaluator/score.py",
    "memory-policy/rules.yaml",
]


class TestThroughDispatcher:
    @pytest.mark.parametrize("target", TARGETS)
    def test_human_without_second_human_denied(
        self, dispatcher: GovernedToolDispatcher, calls: list[str], target: str
    ) -> None:
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(ALICE, "edit", {"path": target})
        policies = {p for d in excinfo.value.decisions for p in d.determining_policies}
        assert "INV-HUMAN-ONLY-CHANGE-CLASS" in policies
        assert calls == []

    @pytest.mark.parametrize("target", TARGETS)
    def test_human_with_second_human_approval_allowed(
        self,
        writer: CoreChangeWriter,
        repo: Path,
        dispatcher: GovernedToolDispatcher,
        calls: list[str],
        approver_factory: Factory,
        target: str,
    ) -> None:
        """The approved human path is the harness CoreChangeWriter; agent
        *tools* never receive core paths (INV-TOOL-ARG-CORE holds for humans)."""
        pytest.importorskip("cryptography")
        bob = approver_factory("bob")
        approval = bob(writer.action_hash_for(ALICE, target, b"v1"))
        assert writer.write_core(ALICE, target, b"v1", approvals=[approval]).allowed
        assert (repo / target).read_bytes() == b"v1"
        tool_approval = bob(dispatcher.action_hash_for(ALICE, "edit", {"path": target}))
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(ALICE, "edit", {"path": target}, approvals=[tool_approval])
        assert "INV-TOOL-ARG-CORE" in excinfo.value.decision.determining_policies
        assert calls == []

    def test_self_approval_is_not_a_second_human(
        self, dispatcher: GovernedToolDispatcher, calls: list[str], approver_factory: Factory
    ) -> None:
        pytest.importorskip("cryptography")
        args = {"path": "policies/main.yaml"}
        approval = approver_factory("alice")(dispatcher.action_hash_for(ALICE, "edit", args))
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(ALICE, "edit", args, approvals=[approval])
        assert calls == []

    def test_low_tier_core_edit_denied_even_with_approval(
        self, dispatcher: GovernedToolDispatcher, calls: list[str], approver_factory: Factory
    ) -> None:
        pytest.importorskip("cryptography")
        args = {"path": "policies/main.yaml"}
        approval = approver_factory("bob")(dispatcher.action_hash_for(ALICE, "quick_edit", args))
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(ALICE, "quick_edit", args, approvals=[approval])
        policies = {p for d in excinfo.value.decisions for p in d.determining_policies}
        assert {"INV-CORE-HUMAN-ONLY-CHANGE", "INV-HUMAN-ONLY-CHANGE-CLASS"} <= policies
        assert calls == []

    @pytest.mark.parametrize("principal", [AGENT, SERVICE])
    @pytest.mark.parametrize("tool", ["edit", "drop"])
    def test_non_humans_always_denied_even_with_approvals(
        self,
        dispatcher: GovernedToolDispatcher,
        calls: list[str],
        approver_factory: Factory,
        principal: Principal,
        tool: str,
    ) -> None:
        pytest.importorskip("cryptography")
        bob, carol = approver_factory("bob"), approver_factory("carol")
        for target in TARGETS:
            if tool == "drop":
                # Phase 5: a non-human T3 call without a verified backup is
                # refused before an approval can even be bound to it.
                with pytest.raises(ValueError, match="T3 by a non-human"):
                    dispatcher.action_hash_for(principal, tool, {"path": target})
                digest = "sha256:" + "0" * 64
            else:
                digest = dispatcher.action_hash_for(principal, tool, {"path": target})
            with pytest.raises(ToolDenied):
                dispatcher.dispatch(
                    principal, tool, {"path": target}, approvals=[bob(digest), carol(digest)]
                )
        assert calls == []

    def test_direct_pdp_core_edits_are_always_denied(
        self, gated_pdp: PolicyDecisionPoint, approver_factory: Factory
    ) -> None:
        """Namespace edits and file writes with a caller-claimed digest never
        pass a direct decide(), even with a valid second-human approval."""
        pytest.importorskip("cryptography")
        bob = approver_factory("bob")
        for request in (
            _direct("constitution.update", "main"),
            _direct("file.write", "policies/main.yaml"),
            _direct("file.write", "policies/main.yaml", source="harness"),
        ):
            approved = replace(request, approvals=(bob(action_hash(request)),))
            decision = gated_pdp.decide(approved)
            assert not decision.allowed
            assert decision.determining_policies == ("INV-HUMAN-ONLY-CHANGE-CLASS",)


def _direct(action: str, resource: str, *, source: str | None = None) -> DecisionRequest:
    attrs = {"content_digest": "sha256:" + "c" * 64}
    if source is not None:
        attrs["content_digest_source"] = source
    return DecisionRequest(ALICE, action, resource, ActionTier.T2, attributes=attrs)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture()
def rooted_pdp(
    constitution: Constitution, permit_all: PolicySet, approval_gate: ApprovalGate, repo: Path
) -> Iterator[PolicyDecisionPoint]:
    with PolicyDecisionPoint.for_constitution(
        constitution,
        permit_all,
        approval_gate=approval_gate,
        registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(repo)),
    ) as point:
        yield point


@pytest.fixture()
def writer(rooted_pdp: PolicyDecisionPoint) -> CoreChangeWriter:
    return CoreChangeWriter(rooted_pdp)


TARGET = "policies/main.yaml"


class TestCoreChangeWriter:
    """Security review H1 / (b): approvals are single-use and bind the real bytes."""

    def test_same_approval_writes_once(
        self,
        writer: CoreChangeWriter,
        repo: Path,
        approval_gate: ApprovalGate,
        approver_factory: Factory,
    ) -> None:
        pytest.importorskip("cryptography")
        approval = approver_factory("bob")(writer.action_hash_for(ALICE, TARGET, b"v1"))
        writer.write_core(ALICE, TARGET, b"v1", approvals=[approval])
        assert approval_gate.is_consumed(approval)
        (repo / TARGET).write_bytes(b"tampered")
        with pytest.raises(CoreWriteRejected) as excinfo:
            writer.write_core(ALICE, TARGET, b"v1", approvals=[approval])
        assert excinfo.value.decision is not None
        assert "INV-APPROVAL-QUORUM" in excinfo.value.decision.determining_policies
        assert (repo / TARGET).read_bytes() == b"tampered"

    def test_lost_consume_race_is_a_replay_deny(
        self,
        writer: CoreChangeWriter,
        repo: Path,
        approval_gate: ApprovalGate,
        approver_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("cryptography")
        approval = approver_factory("bob")(writer.action_hash_for(ALICE, TARGET, b"v1"))
        monkeypatch.setattr(approval_gate, "consume", lambda result: False)
        with pytest.raises(CoreWriteRejected) as excinfo:
            writer.write_core(ALICE, TARGET, b"v1", approvals=[approval])
        assert excinfo.value.decision is not None
        assert excinfo.value.decision.error == "approval_replay"
        assert not (repo / TARGET).exists()

    def test_approval_for_x_cannot_write_y(
        self, writer: CoreChangeWriter, repo: Path, approver_factory: Factory
    ) -> None:
        pytest.importorskip("cryptography")
        approval = approver_factory("bob")(writer.action_hash_for(ALICE, TARGET, b"approved"))
        with pytest.raises(CoreWriteRejected):
            writer.write_core(ALICE, TARGET, b"evil", approvals=[approval])
        assert not (repo / TARGET).exists()
        writer.write_core(ALICE, TARGET, b"approved", approvals=[approval])
        assert (repo / TARGET).read_bytes() == b"approved"

    def test_agent_and_self_approval_denied(
        self, writer: CoreChangeWriter, repo: Path, approver_factory: Factory
    ) -> None:
        pytest.importorskip("cryptography")
        own = approver_factory("alice")(writer.action_hash_for(ALICE, TARGET, b"x"))
        with pytest.raises(CoreWriteRejected):
            writer.write_core(ALICE, TARGET, b"x", approvals=[own])
        digest = writer.action_hash_for(AGENT, TARGET, b"x", requested_by="carol")
        with pytest.raises(CoreWriteRejected):
            writer.write_core(
                AGENT,
                TARGET,
                b"x",
                requested_by="carol",
                approvals=[approver_factory("bob")(digest), approver_factory("erin")(digest)],
            )
        assert not (repo / TARGET).exists()

    def test_paths_and_configuration(
        self,
        writer: CoreChangeWriter,
        rooted_pdp: PolicyDecisionPoint,
        repo: Path,
        tmp_path_factory: pytest.TempPathFactory,
        gated_pdp: PolicyDecisionPoint,
        constitution: Constitution,
        permit_all: PolicySet,
    ) -> None:
        for bad in ("../escape.yaml", "/etc/passwd", ".", ""):
            with pytest.raises(CoreWriteRejected):
                writer.write_core(ALICE, bad, b"x", approvals=[])
        with pytest.raises(CoreWriteRejected):
            writer.write_core(ALICE, TARGET, "text", approvals=[])  # type: ignore[arg-type]
        outside = tmp_path_factory.mktemp("outside")
        (repo / "policies").symlink_to(outside, target_is_directory=True)
        with pytest.raises(CoreWriteRejected, match="escapes"):
            writer.write_core(ALICE, "policies/x.yaml", b"x", approvals=[])
        (repo / "audit").mkdir()
        (repo / "audit" / "log").symlink_to(outside / "f")
        with pytest.raises(CoreWriteRejected, match="symlink"):
            writer.write_core(ALICE, "audit/log", b"x", approvals=[])
        with pytest.raises(ValueError, match="already bound"):
            CoreChangeWriter(rooted_pdp)
        with (
            PolicyDecisionPoint.for_constitution(
                constitution, permit_all, approval_gate=gated_pdp.approval_gate
            ) as unbound_pdp,
            pytest.raises(ValueError, match="repo_root"),
        ):
            CoreChangeWriter(unbound_pdp)
        with pytest.raises(TypeError):
            CoreChangeWriter("pdp")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            rooted_pdp._bind_core_writer(object())
        with pytest.raises(TypeError):
            copy.deepcopy(writer)
        assert "CoreChangeWriter" in repr(writer)
