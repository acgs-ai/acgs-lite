"""Phase 3: an agent cannot satisfy its own approval gate.

Every property about the tool path is exercised through
GovernedToolDispatcher; gate internals are tested directly.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    DecisionRequest,
    GovernedToolDispatcher,
    InMemoryReceiptStore,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    ReceiptLedger,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.action_hash import (
    action_hash,
    approval_subject,
    arguments_digest,
)
from acgs_lite.control_plane.approvals import (
    ApprovalAuthority,
    ApprovalGate,
    ApprovalRegistrationRejected,
    QuorumPolicy,
    QuorumResult,
    SignedApproval,
)

pytest.importorskip("cryptography")

from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

Sign = Callable[..., SignedApproval]
Factory = Callable[..., Sign]

ADMIN = Principal("root-admin", PrincipalKind.HUMAN)  # same admin as conftest
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
SIBLING = Principal("agent-2", PrincipalKind.AGENT, system_id="sys-a")
ALICE = Principal("alice", PrincipalKind.HUMAN)
REQ = "requester-1"  # original requester for agent T2+ calls (INV-AGENT-REQUESTED-BY)
TIERS = {"deploy": ActionTier.T3, "edit": ActionTier.T2, "write": ActionTier.T1}


class Calls:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def tool(self, path: str, content: str = "") -> str:
        self.paths.append(path)
        return "ok"


def _dispatcher(pdp: PolicyDecisionPoint) -> tuple[GovernedToolDispatcher, Calls]:
    calls = Calls()
    permissions = RepositoryPermissions(
        pdp.registry,
        [
            WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",)),
            WriteGrant("alice", PrincipalKind.HUMAN, ("**",)),
        ],
    )
    dispatcher = GovernedToolDispatcher(pdp, permissions=permissions, tool_tiers=TIERS)
    for name in TIERS:
        dispatcher.register(
            name, calls.tool, path_params={"path"}, opaque_params={"content"}, merge_capable=False
        )
    return dispatcher, calls


@pytest.fixture()
def setup(gated_pdp: PolicyDecisionPoint) -> tuple[GovernedToolDispatcher, Calls]:
    return _dispatcher(gated_pdp)


def _hash(d: GovernedToolDispatcher, who: Principal, tool: str, path: str, **kw: Any) -> str:
    return d.action_hash_for(who, tool, {"path": path}, **kw)


class TestRegistration:
    def test_agents_and_services_can_never_be_approvers(
        self, approval_authority: ApprovalAuthority
    ) -> None:
        key = Ed25519ReceiptSigner.generate().public_key_hex()
        for bad in (AGENT, Principal("svc", PrincipalKind.SERVICE)):
            with pytest.raises(ApprovalRegistrationRejected):
                approval_authority.register_approver(ADMIN, bad, key)
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_approver(AGENT, ALICE, key)  # non-human admin
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_approver(ALICE, ALICE, key)  # self-registration
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_approver(ADMIN, ALICE, "not-hex")
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_approver(ADMIN, ALICE, key, key_id="bad id")
        kid = approval_authority.register_approver(ADMIN, ALICE, key)
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_approver(ADMIN, ALICE, key, key_id=kid)
        assert approval_authority.lookup(kid) == (ALICE, key)
        assert approval_authority.lookup(42) is None

    def test_system_members_and_approvers_are_disjoint(
        self, approval_authority: ApprovalAuthority
    ) -> None:
        key = Ed25519ReceiptSigner.generate().public_key_hex()
        approval_authority.register_system_member(ADMIN, SIBLING)
        assert approval_authority.is_system_member("sys-a", "AGENT-2")
        assert not approval_authority.is_system_member(None, "agent-2")
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_approver(
                ADMIN, Principal("agent-2", PrincipalKind.HUMAN), key
            )
        approval_authority.register_approver(ADMIN, ALICE, key)
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_system_member(
                ADMIN, Principal("alice", PrincipalKind.AGENT, system_id="sys-b")
            )
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_system_member(ADMIN, Principal("x", PrincipalKind.AGENT))
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_system_member(ADMIN, ALICE)
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_system_member(AGENT, SIBLING)

    def test_revoked_key_no_longer_counts(
        self,
        setup: tuple[GovernedToolDispatcher, Calls],
        approval_authority: ApprovalAuthority,
        approver_factory: Factory,
    ) -> None:
        d, calls = setup
        bob = approver_factory("bob")
        digest = _hash(d, AGENT, "edit", "workspace/a", requested_by=REQ)
        # Control: before revocation the identical call is allowed, so the
        # denial below can only come from the revoked key.
        d.dispatch(
            AGENT, "edit", {"path": "workspace/a"}, requested_by=REQ, approvals=[bob(digest)]
        )
        assert calls.paths == ["workspace/a"]
        assert approval_authority.revoke_approver(ADMIN, "key-bob")
        assert not approval_authority.revoke_approver(ADMIN, "key-bob")
        with pytest.raises(ToolDenied) as excinfo:
            d.dispatch(
                AGENT, "edit", {"path": "workspace/a"}, requested_by=REQ, approvals=[bob(digest)]
            )
        assert "INV-APPROVAL-QUORUM" in excinfo.value.decision.determining_policies
        assert calls.paths == ["workspace/a"]


class TestAgentCannotSatisfyItsOwnGate:
    def test_self_signed_with_unregistered_key_rejected(
        self, setup: tuple[GovernedToolDispatcher, Calls], approval_gate: ApprovalGate
    ) -> None:
        d, calls = setup
        own = Ed25519ReceiptSigner.generate(key_id="key-agent-1")
        digest = _hash(d, AGENT, "edit", "workspace/a", requested_by=REQ)
        forged = SignedApproval.create(
            own, approver=Principal("agent-1", PrincipalKind.HUMAN), action_hash=digest
        )
        with pytest.raises(ToolDenied) as excinfo:
            d.dispatch(AGENT, "edit", {"path": "workspace/a"}, requested_by=REQ, approvals=[forged])
        assert "INV-APPROVAL-QUORUM" in excinfo.value.decision.determining_policies
        assert calls.paths == []
        result = approval_gate.evaluate(_tool_request(d, AGENT, "edit", "workspace/a"), [forged])
        assert result.rejected == ((forged.approval_id, "unknown approver key"),)

    def test_registered_key_id_with_forged_signature_rejected(
        self,
        setup: tuple[GovernedToolDispatcher, Calls],
        approval_gate: ApprovalGate,
        approver_factory: Factory,
    ) -> None:
        d, _ = setup
        approver_factory("bob")
        attacker = Ed25519ReceiptSigner.generate(key_id="key-bob")
        digest = _hash(d, AGENT, "edit", "workspace/a", requested_by=REQ)
        forged = SignedApproval.create(
            attacker, approver=Principal("bob", PrincipalKind.HUMAN), action_hash=digest
        )
        result = approval_gate.evaluate(_tool_request(d, AGENT, "edit", "workspace/a"), [forged])
        assert result.rejected[0][1] == "invalid signature"
        with pytest.raises(ToolDenied):
            d.dispatch(AGENT, "edit", {"path": "workspace/a"}, requested_by=REQ, approvals=[forged])

    def test_approval_by_requester_does_not_count(
        self, setup: tuple[GovernedToolDispatcher, Calls], approver_factory: Factory
    ) -> None:
        d, calls = setup
        digest = _hash(d, ALICE, "deploy", "workspace/db")
        approvals = [approver_factory("alice")(digest), approver_factory("bob")(digest)]
        with pytest.raises(ToolDenied):
            d.dispatch(ALICE, "deploy", {"path": "workspace/db"}, approvals=approvals)
        assert calls.paths == []

    def test_approval_by_authoring_principal_does_not_count(
        self, setup: tuple[GovernedToolDispatcher, Calls], approver_factory: Factory
    ) -> None:
        d, calls = setup
        digest = _hash(d, AGENT, "edit", "workspace/a", authored_by="dave", requested_by=REQ)
        call = {"authored_by": "dave", "requested_by": REQ}
        erin = approver_factory("erin")
        with pytest.raises(ToolDenied) as excinfo:
            d.dispatch(
                AGENT,
                "edit",
                {"path": "workspace/a"},
                **call,
                approvals=[approver_factory("dave")(digest)],
            )
        assert "INV-APPROVAL-QUORUM" in excinfo.value.decision.determining_policies
        assert calls.paths == []
        # The same approval cannot be laundered by dropping authored_by: the
        # author is part of the hash.
        with pytest.raises(ToolDenied) as excinfo:
            d.dispatch(
                AGENT,
                "edit",
                {"path": "workspace/a"},
                requested_by=REQ,
                approvals=[erin(digest)],
            )
        assert "INV-APPROVAL-QUORUM" in excinfo.value.decision.determining_policies
        assert calls.paths == []
        # Control: a non-author approving the exact call is accepted.
        d.dispatch(AGENT, "edit", {"path": "workspace/a"}, **call, approvals=[erin(digest)])
        assert calls.paths == ["workspace/a"]

    def test_sibling_of_agent_system_does_not_count(
        self,
        setup: tuple[GovernedToolDispatcher, Calls],
        approver_factory: Factory,
        approval_gate: ApprovalGate,
    ) -> None:
        d, calls = setup
        digest = _hash(d, AGENT, "edit", "workspace/a", requested_by=REQ)
        sibling = approver_factory("sam", system_id="sys-a")(digest)
        with pytest.raises(ToolDenied):
            d.dispatch(
                AGENT, "edit", {"path": "workspace/a"}, requested_by=REQ, approvals=[sibling]
            )
        result = approval_gate.evaluate(_tool_request(d, AGENT, "edit", "workspace/a"), [sibling])
        assert "sibling" in result.rejected[0][1]
        assert calls.paths == []

    def test_registered_member_of_agent_system_does_not_count(
        self,
        approval_gate: ApprovalGate,
        approver_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sign = approver_factory("mia")
        authority = approval_gate.authority
        monkeypatch.setattr(authority, "is_system_member", lambda system, pid: pid == "mia")
        request = DecisionRequest(AGENT, "file.write", "workspace/a", ActionTier.T2)
        result = approval_gate.evaluate(request, [sign(action_hash(request))])
        assert "registered member" in result.rejected[0][1]

    def test_approval_for_different_arguments_is_not_replayable(
        self, setup: tuple[GovernedToolDispatcher, Calls], approver_factory: Factory
    ) -> None:
        d, calls = setup
        bob = approver_factory("bob")
        approval = bob(
            d.action_hash_for(
                AGENT, "edit", {"path": "workspace/a", "content": "v1"}, requested_by=REQ
            )
        )
        for args in (
            {"path": "workspace/b", "content": "v1"},
            {"path": "workspace/a", "content": "v2"},
        ):
            with pytest.raises(ToolDenied):
                d.dispatch(AGENT, "edit", args, requested_by=REQ, approvals=[approval])
        assert calls.paths == []
        d.dispatch(
            AGENT,
            "edit",
            {"path": "workspace/a", "content": "v1"},
            requested_by=REQ,
            approvals=[approval],
        )
        assert calls.paths == ["workspace/a"]

    def test_consumed_nonce_cannot_be_replayed(
        self,
        setup: tuple[GovernedToolDispatcher, Calls],
        approver_factory: Factory,
        approval_gate: ApprovalGate,
    ) -> None:
        d, calls = setup
        digest = _hash(d, ALICE, "deploy", "workspace/db")
        approvals = [approver_factory("bob")(digest), approver_factory("carol")(digest)]
        d.dispatch(ALICE, "deploy", {"path": "workspace/db"}, approvals=approvals)
        assert all(approval_gate.is_consumed(a) for a in approvals)
        with pytest.raises(ToolDenied):
            d.dispatch(ALICE, "deploy", {"path": "workspace/db"}, approvals=approvals)
        assert calls.paths == ["workspace/db"]

    def test_authorize_does_not_consume(
        self,
        setup: tuple[GovernedToolDispatcher, Calls],
        approver_factory: Factory,
        approval_gate: ApprovalGate,
    ) -> None:
        d, _ = setup
        approval = approver_factory("bob")(_hash(d, AGENT, "edit", "workspace/a", requested_by=REQ))
        d.authorize_without_consuming(
            AGENT, "edit", {"path": "workspace/a"}, requested_by=REQ, approvals=[approval]
        )
        assert not approval_gate.is_consumed(approval)

    def test_concurrent_consume_loses(
        self,
        setup: tuple[GovernedToolDispatcher, Calls],
        approver_factory: Factory,
        approval_gate: ApprovalGate,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        d, calls = setup
        approval = approver_factory("bob")(_hash(d, AGENT, "edit", "workspace/a", requested_by=REQ))
        monkeypatch.setattr(approval_gate, "consume", lambda result: False)
        with pytest.raises(ToolDenied) as excinfo:
            d.dispatch(
                AGENT, "edit", {"path": "workspace/a"}, requested_by=REQ, approvals=[approval]
            )
        assert "replay" in excinfo.value.decision.reason
        assert calls.paths == []

    @pytest.mark.parametrize(
        ("kwargs", "reason"),
        [
            ({"now": time.time() - 2000}, "approval expired"),
            ({"ttl_s": 10_000}, "approval lifetime exceeds the policy TTL"),
            ({"now": time.time() + 3600}, "approval issued in the future"),
            ({"ttl_s": 0}, "empty validity window"),
        ],
    )
    def test_validity_window(
        self,
        setup: tuple[GovernedToolDispatcher, Calls],
        approver_factory: Factory,
        approval_gate: ApprovalGate,
        kwargs: dict[str, Any],
        reason: str,
    ) -> None:
        d, calls = setup
        approval = approver_factory("bob")(
            _hash(d, AGENT, "edit", "workspace/a", requested_by=REQ), **kwargs
        )
        result = approval_gate.evaluate(_tool_request(d, AGENT, "edit", "workspace/a"), [approval])
        assert result.rejected[0][1] == reason
        with pytest.raises(ToolDenied):
            d.dispatch(
                AGENT, "edit", {"path": "workspace/a"}, requested_by=REQ, approvals=[approval]
            )
        assert calls.paths == []

    def test_duplicate_approvals_from_one_human_count_once(
        self,
        setup: tuple[GovernedToolDispatcher, Calls],
        approver_factory: Factory,
        approval_gate: ApprovalGate,
    ) -> None:
        d, calls = setup
        bob = approver_factory("bob")
        digest = _hash(d, ALICE, "deploy", "workspace/db")
        approvals = [bob(digest), bob(digest)]
        result = approval_gate.evaluate(
            _tool_request(d, ALICE, "deploy", "workspace/db"), approvals
        )
        assert result.counted_approver_ids == ("bob",)
        assert result.rejected[0][1] == "duplicate approver (counted once)"
        with pytest.raises(ToolDenied) as excinfo:
            d.dispatch(ALICE, "deploy", {"path": "workspace/db"}, approvals=approvals)
        assert "INV-T3-TWO-PERSON" in excinfo.value.decision.determining_policies
        assert calls.paths == []

    def test_two_distinct_humans_allow_t3(
        self, setup: tuple[GovernedToolDispatcher, Calls], approver_factory: Factory
    ) -> None:
        d, calls = setup
        digest = _hash(d, ALICE, "deploy", "workspace/db")
        approvals = [approver_factory("bob")(digest), approver_factory("carol")(digest)]
        result = d.dispatch(ALICE, "deploy", {"path": "workspace/db"}, approvals=approvals)
        assert calls.paths == ["workspace/db"]
        assert all(decision.allowed for decision in result.decisions)

    async def test_adispatch_consumes(
        self,
        setup: tuple[GovernedToolDispatcher, Calls],
        approver_factory: Factory,
        approval_gate: ApprovalGate,
    ) -> None:
        d, calls = setup
        approval = approver_factory("bob")(_hash(d, AGENT, "edit", "workspace/a", requested_by=REQ))
        await d.adispatch(
            AGENT, "edit", {"path": "workspace/a"}, requested_by=REQ, approvals=[approval]
        )
        assert approval_gate.is_consumed(approval)
        with pytest.raises(ToolDenied):
            await d.adispatch(
                AGENT, "edit", {"path": "workspace/a"}, requested_by=REQ, approvals=[approval]
            )
        assert calls.paths == ["workspace/a"]

    def test_host_asserted_approvers_ignored_when_gated(
        self, setup: tuple[GovernedToolDispatcher, Calls], gated_pdp: PolicyDecisionPoint
    ) -> None:
        d, calls = setup
        fake = (Principal("bob", PrincipalKind.HUMAN), Principal("carol", PrincipalKind.HUMAN))
        with pytest.raises(ToolDenied):
            d.dispatch(ALICE, "deploy", {"path": "workspace/db"}, approvers=fake)
        decision = gated_pdp.decide(
            DecisionRequest(ALICE, "db.drop", "prod", ActionTier.T3, approvers=fake)
        )
        assert not decision.allowed
        assert {"INV-T3-TWO-PERSON", "INV-APPROVAL-QUORUM"} <= set(decision.determining_policies)
        assert calls.paths == []

    def test_bad_authored_by_denied(self, setup: tuple[GovernedToolDispatcher, Calls]) -> None:
        d, calls = setup
        with pytest.raises(ToolDenied):
            d.dispatch(AGENT, "write", {"path": "workspace/a"}, authored_by=3)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            d.action_hash_for(AGENT, "nope", {})
        assert calls.paths == []


def _tool_request(
    d: GovernedToolDispatcher, who: Principal, tool: str, path: str
) -> DecisionRequest:
    # The dispatcher authorises the effective arguments, defaults included
    # (Calls.tool has content=""), so the digest must cover them too.
    args = {"path": path, "content": ""}
    return DecisionRequest(
        who,
        "tool.call",
        tool,
        d.tier_for(tool),
        attributes={
            "paths": [path],
            "tool_read_only": False,
            "arguments_digest": arguments_digest(args),
            **({"requested_by": REQ} if who.kind is PrincipalKind.AGENT else {}),
        },
    )


class TestGateInternals:
    def test_required_roles(
        self, approval_authority: ApprovalAuthority, approver_factory: Factory
    ) -> None:
        gate = ApprovalGate(
            approval_authority, policies={ActionTier.T2: QuorumPolicy(1, frozenset({"dba"}))}
        )
        request = DecisionRequest(ALICE, "db.migrate", "prod", ActionTier.T2)
        digest = action_hash(request)
        plain = gate.evaluate(request, [approver_factory("bob")(digest)])
        assert not plain.satisfied
        assert plain.missing_roles == frozenset({"dba"})
        dba = gate.evaluate(request, [approver_factory("dora", roles=frozenset({"dba"}))(digest)])
        assert dba.satisfied
        assert gate.policy_for(ActionTier.T3) is None

    def test_t0_t1_need_no_quorum(self, approval_gate: ApprovalGate) -> None:
        request = DecisionRequest(AGENT, "file.write", "workspace/a", ActionTier.T1)
        result = approval_gate.evaluate(request, [])
        assert result.satisfied and result.required == 0

    @pytest.mark.parametrize(
        ("field", "value", "reason"),
        [
            ("approval_id", "bad id", "malformed approval_id"),
            ("signature", "", "missing signature"),
            ("action_hash", "sha256:xyz", "malformed action_hash"),
            ("issued_at", float("nan"), "malformed validity window"),
            ("approver_kind", "agent", "approver is not human"),
            ("approver_id", "mallory", "approver id does not match the registered key"),
        ],
    )
    def test_malformed_fields_rejected(
        self,
        approval_gate: ApprovalGate,
        approver_factory: Factory,
        field: str,
        value: Any,
        reason: str,
    ) -> None:
        request = DecisionRequest(AGENT, "file.write", "workspace/a", ActionTier.T2)
        approval = approver_factory("bob")(action_hash(request))
        object.__setattr__(approval, field, value)
        result = approval_gate.evaluate(request, [approval, "not-an-approval"])
        assert result.rejected == ((approval.approval_id, reason), ("?", "not a SignedApproval"))

    def test_signature_unverifiable_without_crypto(
        self,
        approval_gate: ApprovalGate,
        approver_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from acgs_lite.control_plane import approvals as module
        from acgs_lite.legitimacy.signing import ReceiptSigningUnavailable

        def unavailable(*args: Any) -> bool:
            raise ReceiptSigningUnavailable("no crypto")

        request = DecisionRequest(AGENT, "file.write", "workspace/a", ActionTier.T2)
        approval = approver_factory("bob")(action_hash(request))
        monkeypatch.setattr(module, "verify_signature", unavailable)
        result = approval_gate.evaluate(request, [approval])
        assert not result.satisfied
        assert "signature unverifiable" in result.rejected[0][1]

    def test_non_json_attributes_fail_closed(
        self, approval_gate: ApprovalGate, approver_factory: Factory
    ) -> None:
        sign = approver_factory("bob")
        request = DecisionRequest(
            AGENT, "file.write", "w/a", ActionTier.T2, attributes={"x": object()}
        )
        approval = sign("sha256:" + "0" * 64)
        result = approval_gate.evaluate(request, [approval])
        assert not result.satisfied and result.action_hash == ""
        assert approval_gate.evaluate(request, []).rejected[0][1] == "action hash unavailable"

    def test_evaluate_never_raises(self, approval_gate: ApprovalGate) -> None:
        result = approval_gate.evaluate("not a request", [])  # type: ignore[arg-type]
        assert not result.satisfied
        assert "approval evaluation failed" in result.rejected[0][1]

    def test_consume_is_single_use(
        self, approval_gate: ApprovalGate, approver_factory: Factory
    ) -> None:
        request = DecisionRequest(AGENT, "file.write", "workspace/a", ActionTier.T2)
        result = approval_gate.evaluate(request, [approver_factory("bob")(action_hash(request))])
        assert approval_gate.consume(result)
        assert not approval_gate.consume(result)
        assert approval_gate.consume(QuorumResult(True, "", 0))

    def test_constructor_validation(self, approval_authority: ApprovalAuthority) -> None:
        with pytest.raises(TypeError):
            ApprovalGate("authority")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            ApprovalGate(approval_authority, policies={ActionTier.T2: 1})  # type: ignore[dict-item]
        with pytest.raises(ValueError):
            ApprovalGate(approval_authority, max_clock_skew_s=-1)
        for bad in ({"min_approvals": 0}, {"min_approvals": True}):
            with pytest.raises(ValueError):
                QuorumPolicy(**bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            QuorumPolicy(1, frozenset({""}))
        with pytest.raises(ValueError):
            QuorumPolicy(1, ttl_s=0)


class TestPdpIntegration:
    def test_pdp_rejects_wrong_gate_type(
        self, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        with pytest.raises(ValueError):
            PolicyDecisionPoint.for_constitution(constitution, permit_all, approval_gate=object())  # type: ignore[arg-type]

    def test_attestation_error_denies(
        self,
        gated_pdp: PolicyDecisionPoint,
        approval_gate: ApprovalGate,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def boom(request: Any, approvals: Any) -> QuorumResult:
            raise RuntimeError("boom")

        monkeypatch.setattr(approval_gate, "evaluate", boom)
        decision = gated_pdp.decide(
            DecisionRequest(ALICE, "file.write", "workspace/a", ActionTier.T1)
        )
        assert not decision.allowed and decision.error == "approval_error"

    def test_invalid_request_still_denied_with_gate(self, gated_pdp: PolicyDecisionPoint) -> None:
        bad = DecisionRequest(ALICE, "", "workspace/a", ActionTier.T1)
        assert gated_pdp.decide(bad).error == "invalid_request"
        bad2 = DecisionRequest(ALICE, "file.write", "workspace/a", ActionTier.T1)
        object.__setattr__(bad2, "approvals", ["x"])
        assert gated_pdp.decide(bad2).error == "invalid_request"

    def test_receipt_cites_approval_id_and_action_hash(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        approval_gate: ApprovalGate,
        approver_factory: Factory,
        tmp_path: Path,
    ) -> None:
        ledger = ReceiptLedger(
            Ed25519ReceiptSigner.from_seed(b"\x02" * 32, key_id="h"), store=InMemoryReceiptStore()
        )
        with PolicyDecisionPoint.for_constitution(
            constitution,
            permit_all,
            approval_gate=approval_gate,
            receipt_ledger=ledger,
            registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)),
        ) as pdp:
            d, calls = _dispatcher(pdp)
            digest = _hash(d, ALICE, "deploy", "workspace/db")
            approvals = [approver_factory("bob")(digest), approver_factory("carol")(digest)]
            d.dispatch(ALICE, "deploy", {"path": "workspace/db"}, approvals=approvals)
        assert calls.paths == ["workspace/db"]
        tool_receipt = ledger.receipts()[0].receipt
        refs = {(a.principal_id, a.approval_id, a.action_hash) for a in tool_receipt.approvers}
        assert refs == {(a.approver_id, a.approval_id, digest) for a in approvals}
        # Path sub-decisions resolve to the same approved tool call.
        assert {a.action_hash for a in ledger.receipts()[1].receipt.approvers} == {digest}


class TestActionHash:
    def test_sub_request_resolves_to_parent_tool_call(self) -> None:
        tool_call = {"paths": ["workspace/a"], "tool_read_only": False, "arguments_digest": "d"}
        parent = DecisionRequest(AGENT, "tool.call", "edit", ActionTier.T2, attributes=tool_call)
        child = DecisionRequest(
            AGENT,
            "file.write",
            "workspace/a",
            ActionTier.T2,
            attributes={"via_tool": "edit", "tool_call": tool_call},
        )
        assert action_hash(child) == action_hash(parent)
        stray = DecisionRequest(
            AGENT,
            "file.write",
            "workspace/zzz",
            ActionTier.T2,
            attributes={"via_tool": "edit", "tool_call": tool_call},
        )
        assert approval_subject(stray) is stray
        assert action_hash(stray) != action_hash(parent)

    def test_hash_excludes_approvers_but_binds_principal_and_tier(self) -> None:
        base = DecisionRequest(AGENT, "file.write", "workspace/a", ActionTier.T2)
        with_approvers = DecisionRequest(
            AGENT, "file.write", "workspace/a", ActionTier.T2, approvers=(ALICE,)
        )
        assert action_hash(base) == action_hash(with_approvers)
        assert action_hash(base) != action_hash(
            DecisionRequest(SIBLING, "file.write", "workspace/a", ActionTier.T2)
        )
        assert action_hash(base) != action_hash(
            DecisionRequest(AGENT, "file.write", "workspace/a", ActionTier.T3)
        )

    def test_arguments_digest_is_canonical(self) -> None:
        a = arguments_digest({"x": {"b": 1, "a": [1, 2]}, "s": {3, 1}, "raw": b"\x00"})
        b = arguments_digest({"raw": b"\x00", "s": {1, 3}, "x": {"a": (1, 2), "b": 1}})
        assert a == b
        assert a != arguments_digest({"raw": b"\x01", "s": {1, 3}, "x": {"a": [1, 2], "b": 1}})
        assert arguments_digest({"f": 1.5}) != arguments_digest({"f": 2.5})
        for bad in ({"f": float("nan")}, {"o": object()}):
            with pytest.raises((TypeError, ValueError)):
                arguments_digest(bad)
        deep: Any = "x"
        for _ in range(40):
            deep = [deep]
        with pytest.raises(ValueError):
            arguments_digest({"d": deep})


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("change", ["expiry", "revoke"])
async def test_consume_rechecks_after_pdp_evaluation(
    setup, approver_factory, approval_gate, approval_authority, monkeypatch, change, asynchronous
):
    dispatcher, calls = setup
    approval = approver_factory("bob")(_hash(dispatcher, ALICE, "edit", "workspace/a"))
    original = approval_gate.consume

    def consume(result):
        if change == "expiry":
            monkeypatch.setattr(approval_gate, "_clock", lambda: approval.expires_at)
        else:
            approval_authority.revoke_approver(ADMIN, approval.key_id)
        return original(result)

    monkeypatch.setattr(approval_gate, "consume", consume)
    with pytest.raises(ToolDenied):
        if asynchronous:
            await dispatcher.adispatch(ALICE, "edit", {"path": "workspace/a"}, approvals=[approval])
        else:
            dispatcher.dispatch(ALICE, "edit", {"path": "workspace/a"}, approvals=[approval])
    assert calls.paths == []
    assert not approval_gate.is_consumed(approval)
