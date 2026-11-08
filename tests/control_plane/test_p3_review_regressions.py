"""Regression tests for the PR #239 (phase 3) review threads."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

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
from acgs_lite.control_plane.action_hash import action_hash, approval_subject, arguments_digest
from acgs_lite.control_plane.approvals import (
    ApprovalAuthority,
    ApprovalGate,
    QuorumPolicy,
    SignedApproval,
)
from acgs_lite.control_plane.core_write import CoreChangeWriter, CoreWriteRejected
from acgs_lite.control_plane.killswitch import KillSwitch

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

ADMIN = Principal("admin", PrincipalKind.HUMAN)
ALICE = Principal("alice", PrincipalKind.HUMAN)
TARGET = "policies/main.yaml"
Factory = Callable[..., Callable[..., SignedApproval]]


def _switch(tmp_path: Path, state: dict[str, bool], name: str = "halt") -> KillSwitch:
    return KillSwitch("sys-a", signal_dir=tmp_path / name, probe=lambda _p: state["on"])


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


@pytest.fixture()
def state() -> dict[str, bool]:
    return {"on": False}


@pytest.fixture()
def rooted(
    constitution: Constitution,
    permit_all: PolicySet,
    approval_gate: ApprovalGate,
    repo: Path,
    tmp_path: Path,
    state: dict[str, bool],
) -> Iterator[PolicyDecisionPoint]:
    with PolicyDecisionPoint.for_constitution(
        constitution,
        permit_all,
        approval_gate=approval_gate,
        registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(repo)),
        kill_switch=_switch(tmp_path, state),
    ) as point:
        yield point


@pytest.fixture()
def writer(rooted: PolicyDecisionPoint) -> CoreChangeWriter:
    return CoreChangeWriter(rooted)


def _approve(writer: CoreChangeWriter, factory: Factory, path: str, content: bytes) -> Any:
    pytest.importorskip("cryptography")
    return factory("bob")(writer.action_hash_for(ALICE, path, content))


def _after_decide(writer: CoreChangeWriter, hook: Callable[[], None]) -> None:
    original = writer._decide

    def decide(request: DecisionRequest) -> Any:
        decision = original(request)
        hook()
        return decision

    writer._decide = decide  # type: ignore[method-assign]


class TestCoreWriteKillSwitch:
    """239.1 / 239.9: a halt engaged after the PDP allow stops the write."""

    def test_switch_engaged_after_allow_blocks_write(
        self,
        writer: CoreChangeWriter,
        repo: Path,
        state: dict[str, bool],
        approver_factory: Factory,
    ) -> None:
        approval = _approve(writer, approver_factory, TARGET, b"v1")
        _after_decide(writer, lambda: state.update(on=True))
        with pytest.raises(CoreWriteRejected, match="kill switch"):
            writer.write_core(ALICE, TARGET, b"v1", approvals=[approval])
        assert not (repo / TARGET).exists()


class TestCoreWriteTargets:
    """239.7 / 239.2 / 239.8: core-only targets, modes, descriptor-relative writes."""

    def test_non_core_target_rejected(self, writer: CoreChangeWriter, repo: Path) -> None:
        with pytest.raises(CoreWriteRejected, match="not immutable core"):
            writer.write_core(ALICE, "workspace/x.py", b"x", approvals=[])
        assert not (repo / "workspace").exists()

    def test_existing_mode_preserved(
        self, writer: CoreChangeWriter, repo: Path, approver_factory: Factory
    ) -> None:
        target = repo / "evaluator" / "run.sh"
        target.parent.mkdir()
        target.write_bytes(b"old")
        os.chmod(target, 0o755)
        approval = _approve(writer, approver_factory, "evaluator/run.sh", b"new")
        writer.write_core(ALICE, "evaluator/run.sh", b"new", approvals=[approval])
        assert target.read_bytes() == b"new"
        assert stat.S_IMODE(target.stat().st_mode) == 0o755

    def test_new_file_modes(
        self, writer: CoreChangeWriter, repo: Path, approver_factory: Factory
    ) -> None:
        writer.write_core(
            ALICE, TARGET, b"p", approvals=[_approve(writer, approver_factory, TARGET, b"p")]
        )
        assert stat.S_IMODE((repo / TARGET).stat().st_mode) == 0o644

    def test_parent_swapped_for_symlink_during_decision(
        self, writer: CoreChangeWriter, repo: Path, tmp_path: Path, approver_factory: Factory
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (repo / "policies").mkdir()
        approval = _approve(writer, approver_factory, TARGET, b"v1")

        def swap() -> None:
            (repo / "policies").rmdir()
            (repo / "policies").symlink_to(outside, target_is_directory=True)

        _after_decide(writer, swap)
        with pytest.raises(CoreWriteRejected, match="not a plain directory"):
            writer.write_core(ALICE, TARGET, b"v1", approvals=[approval])
        assert list(outside.iterdir()) == []


class TestDispatcherChecksBothSwitches:
    """239.10: the final recheck must also watch the PDP's own switch."""

    def test_pdp_switch_engaged_after_evaluation(
        self, constitution: Constitution, permit_all: PolicySet, tmp_path: Path
    ) -> None:
        pdp_state = {"on": False}
        calls: list[str] = []
        pdp_switch = _switch(tmp_path, pdp_state, "pdp-halt")
        dispatcher_switch = _switch(tmp_path, {"on": False}, "dispatcher-halt")

        def engage_on_allow(decision: Any) -> None:
            if decision.allowed:
                pdp_state["on"] = True

        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, kill_switch=pdp_switch, listeners=[engage_on_allow]
        ) as pdp:
            permissions = RepositoryPermissions(
                DEFAULT_IMMUTABLE_CORE,
                [WriteGrant("alice", PrincipalKind.HUMAN, ("**",))],
            )
            d = GovernedToolDispatcher(
                pdp,
                permissions=permissions,
                tool_tiers={"write": ActionTier.T1},
                kill_switch=dispatcher_switch,
            )
            d.register("write", lambda path: calls.append(path), path_params={"path"})
            with pytest.raises(ToolDenied, match="kill switch"):
                d.dispatch(ALICE, "write", {"path": "workspace/a.py"})
        assert calls == []


class TestApprovalSubject:
    """239.4 / 239.6: sub-request subjects and their exclusions."""

    def _parent(self, read_only: bool, **extra: Any) -> DecisionRequest:
        return DecisionRequest(
            ALICE,
            "tool.call",
            "tool",
            ActionTier.T2,
            attributes={
                "paths": ["workspace/a"],
                "tool_read_only": read_only,
                "arguments_digest": arguments_digest({"path": "workspace/a"}),
                **extra,
            },
        )

    def _child(self, parent: DecisionRequest, action: str) -> DecisionRequest:
        return DecisionRequest(
            ALICE,
            action,
            "workspace/a",
            ActionTier.T2,
            attributes={"via_tool": "tool", "tool_call": dict(parent.attributes)},
        )

    def test_read_only_approval_does_not_cover_a_write(self) -> None:
        parent = self._parent(read_only=True)
        write_child = self._child(parent, "file.write")
        assert approval_subject(write_child) is write_child
        assert action_hash(write_child) != action_hash(parent)
        read_child = self._child(parent, "file.read")
        assert action_hash(read_child) == action_hash(parent)

    def test_sub_request_author_excluded(
        self, approval_gate: ApprovalGate, approver_factory: Factory
    ) -> None:
        pytest.importorskip("cryptography")
        parent = self._parent(read_only=False, authored_by="dave")
        child = self._child(parent, "file.write")
        approval = approver_factory("dave")(action_hash(child))
        result = approval_gate.evaluate(child, [approval])
        assert result.counted_approver_ids == ()
        assert "authoring principal" in result.rejected[0][1]


class TestQuorumPolicyRequired:
    """239.5: a gated tier without a configured policy is not a 0-of-0 quorum."""

    def test_missing_t2_policy_unsatisfied(self) -> None:
        gate = ApprovalGate(ApprovalAuthority(), policies={ActionTier.T3: QuorumPolicy(2)})
        request = DecisionRequest(ALICE, "tool.call", "edit", ActionTier.T2)
        result = gate.evaluate(request, [])
        assert not result.satisfied
        assert "no quorum policy" in result.rejected[0][1]

    def test_ungated_tier_without_policy_still_trivially_satisfied(self) -> None:
        gate = ApprovalGate(ApprovalAuthority(), policies={ActionTier.T3: QuorumPolicy(2)})
        request = DecisionRequest(ALICE, "tool.call", "edit", ActionTier.T1)
        assert gate.evaluate(request, []).satisfied


class TestApproverIdCharset:
    """239.3 / 239.11: approver ids follow the Principal id rules."""

    def test_email_style_approver_counts(
        self, approval_authority: ApprovalAuthority, approval_gate: ApprovalGate
    ) -> None:
        pytest.importorskip("cryptography")
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        bob = Principal("bob@example.com", PrincipalKind.HUMAN)
        signer = Ed25519ReceiptSigner.from_seed(
            hashlib.sha256(b"bob@example.com").digest(), key_id="key-bob-example"
        )
        approval_authority.register_approver(
            ADMIN, bob, signer.public_key_hex(), key_id="key-bob-example"
        )
        request = DecisionRequest(ALICE, "tool.call", "edit", ActionTier.T2)
        approval = SignedApproval.create(signer, approver=bob, action_hash=action_hash(request))
        result = approval_gate.evaluate(request, [approval])
        assert result.satisfied, result.rejected
        assert result.counted_approver_ids == ("bob@example.com",)
