"""Regression tests for the Phase 3 security review (reviewer repros f1..f7).

Each test reproduces one finding through the public path; before the fix
every one of them showed the bypass.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    CoreCategory,
    DecisionRequest,
    EvidenceSource,
    ExternalRunRef,
    GovernedToolDispatcher,
    InMemoryReceiptStore,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    PromotionGate,
    PromotionRejected,
    ReceiptLedger,
    RepositoryPermissions,
    ToolDenied,
    TrustedRunRegistry,
    WriteGrant,
)
from acgs_lite.control_plane.action_hash import action_hash
from acgs_lite.control_plane.approvals import (
    ApprovalAuthority,
    ApprovalGate,
    ApprovalRegistrationRejected,
    SignedApproval,
)
from acgs_lite.control_plane.autonomy import (
    AutonomyController,
    AutonomyLevel,
    ErrorBudget,
    FailureKind,
)
from acgs_lite.control_plane.budgets import BudgetLedger, BudgetLimits
from acgs_lite.control_plane.credentials import CredentialInvalid, CredentialIssuer
from acgs_lite.control_plane.killswitch import KillSwitch

pytest.importorskip("cryptography")

from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

ADMIN = Principal("root-admin", PrincipalKind.HUMAN)
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
ALICE = Principal("alice", PrincipalKind.HUMAN)
BOB = Principal("bob", PrincipalKind.HUMAN)
CAROL = Principal("carol", PrincipalKind.HUMAN)
Factory = Callable[..., Callable[..., SignedApproval]]


def _permissions() -> RepositoryPermissions:
    return RepositoryPermissions(
        DEFAULT_IMMUTABLE_CORE, [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))]
    )


class TestM2OneKeyOneApprover:
    def test_key_cannot_back_two_approvers(self, approval_authority: ApprovalAuthority) -> None:
        mallory = Ed25519ReceiptSigner.from_seed(b"\x09" * 32)
        approval_authority.register_approver(ADMIN, BOB, mallory.public_key_hex(), key_id="k-bob")
        with pytest.raises(ApprovalRegistrationRejected, match="different approver"):
            approval_authority.register_approver(
                ADMIN, CAROL, mallory.public_key_hex(), key_id="k-carol"
            )
        # Same approver, second key id: allowed, and still counts once.
        approval_authority.register_approver(ADMIN, BOB, mallory.public_key_hex(), key_id="k-b2")
        with pytest.raises(ApprovalRegistrationRejected, match="already registered"):
            approval_authority.register_approver(
                ADMIN, BOB, Ed25519ReceiptSigner.generate().public_key_hex(), key_id="k-bob"
            )
        # Revoking every key id frees the key for someone else.
        approval_authority.revoke_approver(ADMIN, "k-bob")
        approval_authority.revoke_approver(ADMIN, "k-b2")
        approval_authority.register_approver(ADMIN, CAROL, mallory.public_key_hex(), key_id="k-c")

    def test_one_key_holder_cannot_fill_t3_quorum(
        self, gated_pdp: PolicyDecisionPoint, approval_authority: ApprovalAuthority
    ) -> None:
        seed = b"\x0a" * 32
        key = Ed25519ReceiptSigner.from_seed(seed).public_key_hex()
        approval_authority.register_approver(ADMIN, BOB, key, key_id="k-bob")
        with pytest.raises(ApprovalRegistrationRejected):
            approval_authority.register_approver(ADMIN, CAROL, key, key_id="k-carol")
        request = DecisionRequest(AGENT, "deploy.run", "prod", ActionTier.T3)
        approvals = tuple(
            SignedApproval.create(
                Ed25519ReceiptSigner.from_seed(seed, key_id=kid),
                approver=who,
                action_hash=action_hash(request),
            )
            for kid, who in (("k-bob", BOB), ("k-carol", CAROL))
        )
        decision = gated_pdp.decide(
            DecisionRequest(AGENT, "deploy.run", "prod", ActionTier.T3, approvals=approvals)
        )
        assert not decision.allowed


class TestM3AtomicBudget:
    def test_concurrent_dispatches_cannot_overshoot(
        self, pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ledger = BudgetLedger()
        ledger.start_run(AGENT, BudgetLimits(iterations=1))
        original = ledger.state

        def slow_state(principal: Principal) -> Any:
            state = original(principal)
            time.sleep(0.05)  # widen any check-then-charge window
            return state

        monkeypatch.setattr(ledger, "state", slow_state)
        d = GovernedToolDispatcher(
            pdp, permissions=_permissions(), tool_tiers={"w": ActionTier.T1}, budgets=ledger
        )
        calls: list[str] = []
        lock = threading.Lock()

        def w(path: str) -> None:
            with lock:
                calls.append(path)

        d.register("w", w, path_params={"path"})

        def run(i: int) -> None:
            with contextlib.suppress(ToolDenied):
                d.dispatch(AGENT, "w", {"path": f"workspace/f{i}.txt"})

        threads = [threading.Thread(target=run, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(calls) == 1
        assert original(AGENT).iterations == 1

    def test_try_charge(self) -> None:
        ledger = BudgetLedger()
        ledger.start_run(AGENT, BudgetLimits(tokens=10))
        state = ledger.try_charge(AGENT, tokens=10, iterations=0)
        assert state is not None and state.is_exhausted
        assert ledger.try_charge(AGENT, tokens=1) is None
        assert ledger.state(AGENT).tokens == 10
        with pytest.raises(PermissionError):
            ledger.try_charge(AGENT, reporter=AGENT)


class TestM4PromotionApprovals:
    @pytest.fixture()
    def wired(
        self, constitution: Constitution, permit_all: PolicySet, approval_gate: ApprovalGate
    ) -> Iterator[tuple[PromotionGate, ReceiptLedger]]:
        digest = "sha256:" + "d" * 64
        runs = TrustedRunRegistry()
        runs.register_run(
            Principal("ci-bot", PrincipalKind.SERVICE),
            ExternalRunRef("ci", "7", EvidenceSource.CI_SYSTEM, artifact_digest=digest),
            conclusion="success",
        )
        ledger = ReceiptLedger(
            Ed25519ReceiptSigner.from_seed(b"\x07" * 32, key_id="gate"),
            store=InMemoryReceiptStore(),
        )
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger, approval_gate=approval_gate
        ) as pdp:
            yield PromotionGate(ledger, runs, pdp=pdp), ledger

    def test_signed_approvals_only(
        self, wired: tuple[PromotionGate, ReceiptLedger], approver_factory: Factory
    ) -> None:
        gate, ledger = wired
        digest = "sha256:" + "d" * 64
        run = ExternalRunRef("ci", "7", EvidenceSource.CI_SYSTEM, artifact_digest=digest)
        with pytest.raises(PromotionRejected, match="host-asserted"):
            gate.promote(ALICE, "c1", candidate_digest=digest, evidence=[run], approvers=[BOB])
        with pytest.raises(PromotionRejected, match="PDP denied"):
            gate.promote(ALICE, "c1", candidate_digest=digest, evidence=[run])
        request = DecisionRequest(
            ALICE,
            "promotion.promote",
            "c1",
            ActionTier.T2,
            attributes={"candidate_digest": digest, "external_runs": [run.to_dict()]},
        )
        approval = approver_factory("bob")(action_hash(request))
        signed = gate.promote(
            ALICE, "c1", candidate_digest=digest, evidence=[run], approvals=[approval]
        )
        refs = signed.receipt.approvers
        assert [(a.principal_id, a.approval_id) for a in refs] == [("bob", approval.approval_id)]
        with pytest.raises(PromotionRejected):  # single use
            gate.promote(ALICE, "c1", candidate_digest=digest, evidence=[run], approvals=[approval])


class TestM5OriginalRequester:
    def test_requested_by_cannot_approve(
        self, gated_pdp: PolicyDecisionPoint, approver_factory: Factory
    ) -> None:
        d = GovernedToolDispatcher(
            gated_pdp, permissions=_permissions(), tool_tiers={"edit": ActionTier.T2}
        )
        calls: list[str] = []

        def edit(path: str) -> None:
            calls.append(path)

        d.register("edit", edit, path_params={"path"})
        args = {"path": "workspace/a"}
        digest = d.action_hash_for(AGENT, "edit", args, requested_by="carol")
        with pytest.raises(ToolDenied):
            d.dispatch(
                AGENT,
                "edit",
                args,
                requested_by="carol",
                approvals=[approver_factory("carol")(digest)],
            )
        # requested_by is hashed: dropping it does not launder carol's approval.
        with pytest.raises(ToolDenied):
            d.dispatch(AGENT, "edit", args, approvals=[approver_factory("dave")(digest)])
        d.dispatch(
            AGENT, "edit", args, requested_by="carol", approvals=[approver_factory("erin")(digest)]
        )
        assert calls == ["workspace/a"]
        with pytest.raises(ToolDenied):
            d.dispatch(AGENT, "edit", args, requested_by="")


class TestL7StrictTokens:
    def test_malleated_tokens_rejected(self) -> None:
        issuer = CredentialIssuer(b"k" * 32)
        token = issuer.issue(AGENT, scopes={"tool:w"}).token
        body, mac = token.split(".")
        for bad in (
            body[:5] + "!!" + body[5:] + "." + mac,
            body + "=." + mac,
            body.replace("-", "+").replace("_", "/") + "x." + mac,
            body[:-1] + "+" + "." + mac,
        ):
            with pytest.raises(CredentialInvalid):
                issuer.verify(bad, required_scope="tool:w")
        issuer.verify(token, required_scope="tool:w")


class TestL8SystemCohort:
    def test_new_principal_in_demoted_system_inherits(self) -> None:
        autonomy = AutonomyController(ErrorBudget(max_failures=1))
        autonomy.record_failure(AGENT, FailureKind.POLICY_DENIAL)
        retry = Principal("agent-1-retry", PrincipalKind.AGENT, system_id="sys-a")
        other = Principal("agent-9", PrincipalKind.AGENT, system_id="sys-b")
        assert autonomy.level(retry) is AutonomyLevel.P0_ONLY
        assert autonomy.level(other) is AutonomyLevel.T1_PREAUTHORIZED
        autonomy.restore(ALICE, AGENT)
        assert autonomy.level(retry) is AutonomyLevel.T1_PREAUTHORIZED

    def test_cohort_flag_can_be_disabled(self) -> None:
        autonomy = AutonomyController(ErrorBudget(max_failures=1), demote_system=False)
        autonomy.record_failure(AGENT, FailureKind.POLICY_DENIAL)
        retry = Principal("agent-1-retry", PrincipalKind.AGENT, system_id="sys-a")
        assert autonomy.level(retry) is AutonomyLevel.T1_PREAUTHORIZED


class TestL9SharedLedger:
    def test_autonomy_must_watch_the_charged_ledger(self, pdp: PolicyDecisionPoint) -> None:
        ledger = BudgetLedger()
        with pytest.raises(ValueError, match="same BudgetLedger"):
            GovernedToolDispatcher(
                pdp,
                permissions=_permissions(),
                tool_tiers={},
                autonomy=AutonomyController(ErrorBudget(), ledger),
            )
        with pytest.raises(ValueError, match="same BudgetLedger"):
            GovernedToolDispatcher(
                pdp,
                permissions=_permissions(),
                tool_tiers={},
                budgets=ledger,
                autonomy=AutonomyController(ErrorBudget(), BudgetLedger()),
            )
        GovernedToolDispatcher(
            pdp,
            permissions=_permissions(),
            tool_tiers={},
            budgets=ledger,
            autonomy=AutonomyController(ErrorBudget(), ledger),
        )


class TestL10DryRunIsNamedAsSuch:
    def test_authorize_renamed(self) -> None:
        assert not hasattr(GovernedToolDispatcher, "authorize")
        assert "not* consumed" in (GovernedToolDispatcher.authorize_without_consuming.__doc__ or "")


class TestKillSwitchToctouAndPaths:
    async def test_async_body_rechecks_halt_after_worker_returns(
        self, pdp: PolicyDecisionPoint, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        switch = KillSwitch("sys-a", signal_dir=tmp_path / "h")
        dispatcher = GovernedToolDispatcher(
            pdp, permissions=_permissions(), tool_tiers={"w": ActionTier.T1}, kill_switch=switch
        )
        calls: list[str] = []

        async def write(path: str) -> None:
            calls.append(path)

        dispatcher.register("w", write, path_params={"path"})
        original = asyncio.to_thread

        async def halt_after_worker(fn: Any, *args: Any, **kwargs: Any) -> Any:
            result = await original(fn, *args, **kwargs)
            switch.engage(ALICE, "after worker")
            return result

        monkeypatch.setattr(asyncio, "to_thread", halt_after_worker)
        with pytest.raises(ToolDenied, match="kill switch"):
            await dispatcher.adispatch(AGENT, "w", {"path": "workspace/a"})
        assert calls == []

    def _dispatcher(
        self, pdp: PolicyDecisionPoint, switch: KillSwitch, engage_during_auth: bool
    ) -> tuple[GovernedToolDispatcher, list[str]]:
        d = GovernedToolDispatcher(
            pdp, permissions=_permissions(), tool_tiers={"w": ActionTier.T1}, kill_switch=switch
        )
        calls: list[str] = []

        def w(path: str) -> None:
            calls.append(path)

        d.register("w", w, path_params={"path"})
        if engage_during_auth:
            original = d._authorize

            def authorize_then_engage(*args: Any, **kwargs: Any) -> Any:
                result = original(*args, **kwargs)
                switch.engage(ALICE, "mid-flight")
                return result

            d._authorize = authorize_then_engage  # type: ignore[method-assign]
        return d, calls

    def test_engaged_between_authorize_and_invoke_sync(
        self, pdp: PolicyDecisionPoint, tmp_path: Path
    ) -> None:
        switch = KillSwitch("sys-a", signal_dir=tmp_path / "h")
        d, calls = self._dispatcher(pdp, switch, True)
        with pytest.raises(ToolDenied, match="kill switch"):
            d.dispatch(AGENT, "w", {"path": "workspace/a"})
        assert calls == []

    async def test_engaged_between_authorize_and_invoke_async(
        self, pdp: PolicyDecisionPoint, tmp_path: Path
    ) -> None:
        switch = KillSwitch("sys-a", signal_dir=tmp_path / "h")
        d, calls = self._dispatcher(pdp, switch, True)
        with pytest.raises(ToolDenied, match="kill switch"):
            await d.adispatch(AGENT, "w", {"path": "workspace/a"})
        assert calls == []

    def test_halt_dir_resolves_against_repo_root(self, tmp_path: Path) -> None:
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        switch = KillSwitch("sys-a", registry=registry)
        assert switch.signal_path == tmp_path / "control-plane" / "halt" / "acgs-halt-sys-a"
        assert registry.is_core(str(switch.signal_path))

    @pytest.mark.parametrize("path", ["config/constitution.json", "x/constitution-v2.toml"])
    def test_constitution_json_toml_are_policy(self, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify(path) is CoreCategory.POLICY


def _edit_dispatcher(
    pdp: PolicyDecisionPoint, permissions: RepositoryPermissions | None = None, **kw: Any
) -> tuple[GovernedToolDispatcher, list[str]]:
    d = GovernedToolDispatcher(
        pdp,
        permissions=permissions or _permissions(),
        tool_tiers={"edit": ActionTier.T2, "w": ActionTier.T1},
        **kw,
    )
    calls: list[str] = []

    def edit(path: str) -> None:
        calls.append(path)

    d.register("edit", edit, path_params={"path"})
    d.register("w", edit, path_params={"path"})
    return d, calls


class TestReReviewD_RequestedByRequired:
    ARGS = {"path": "workspace/a.txt"}

    def test_agent_t2_without_requested_by_denied(
        self, gated_pdp: PolicyDecisionPoint, approver_factory: Factory
    ) -> None:
        d, calls = _edit_dispatcher(gated_pdp)
        alice = approver_factory("alice")
        approval = alice(d.action_hash_for(AGENT, "edit", self.ARGS))
        with pytest.raises(ToolDenied, match="requested_by required"):
            d.dispatch(AGENT, "edit", self.ARGS, approvals=[approval])
        for bad in ("agent-1", "AGENT-1", "bad id"):
            with pytest.raises(ToolDenied, match="requested_by"):
                d.dispatch(AGENT, "edit", self.ARGS, requested_by=bad)
        # The true requester cannot self-approve once named.
        digest = d.action_hash_for(AGENT, "edit", self.ARGS, requested_by="alice")
        with pytest.raises(ToolDenied):
            d.dispatch(AGENT, "edit", self.ARGS, requested_by="alice", approvals=[alice(digest)])
        d.dispatch(AGENT, "w", self.ARGS)  # T1 needs no requester
        assert calls == ["workspace/a.txt"]

    def test_pdp_invariant_enforces_it_directly(self, gated_pdp: PolicyDecisionPoint) -> None:
        for attrs in ({}, {"requested_by": "agent-1"}):
            decision = gated_pdp.decide(
                DecisionRequest(AGENT, "deploy.run", "prod", ActionTier.T2, attributes=attrs)
            )
            assert "INV-AGENT-REQUESTED-BY" in decision.determining_policies

    def test_requested_by_bound_from_credential_session(
        self, gated_pdp: PolicyDecisionPoint, approver_factory: Factory
    ) -> None:
        issuer = CredentialIssuer()
        d, calls = _edit_dispatcher(gated_pdp, credential_issuer=issuer, require_credential=True)
        token = issuer.issue(AGENT, scopes={"tool:edit"}, on_behalf_of="Carol").token
        digest = d.action_hash_for(AGENT, "edit", self.ARGS, requested_by="carol")
        with pytest.raises(ToolDenied, match="credential session"):
            d.dispatch(AGENT, "edit", self.ARGS, credential=token, requested_by="dave")
        with pytest.raises(ToolDenied):  # carol is bound from the session; cannot approve
            d.dispatch(
                AGENT,
                "edit",
                self.ARGS,
                credential=token,
                approvals=[approver_factory("carol")(digest)],
            )
        d.dispatch(
            AGENT,
            "edit",
            self.ARGS,
            credential=token,
            approvals=[approver_factory("erin")(digest)],
        )
        assert calls == ["workspace/a.txt"]

    def test_on_behalf_of_issuance_rules(self) -> None:
        issuer = CredentialIssuer()
        cred = issuer.issue(AGENT, scopes={"tool:edit"}, on_behalf_of="carol")
        assert issuer.verify(cred.token, required_scope="tool:edit").on_behalf_of == "carol"
        assert issuer.issue(AGENT, scopes={"tool:edit"}).on_behalf_of is None
        from acgs_lite.control_plane.credentials import CredentialIssuanceRefused

        for kwargs in (
            {"on_behalf_of": "agent-1"},
            {"on_behalf_of": "bad id"},
            {"on_behalf_of": "carol", "requester": AGENT},
        ):
            with pytest.raises(CredentialIssuanceRefused):
                issuer.issue(AGENT, scopes={"tool:edit"}, **kwargs)  # type: ignore[arg-type]


class TestReReviewA_IamBeforeConsumption:
    def test_iam_deny_does_not_burn_approval(
        self,
        gated_pdp: PolicyDecisionPoint,
        approval_gate: ApprovalGate,
        approver_factory: Factory,
    ) -> None:
        d, calls = _edit_dispatcher(
            gated_pdp, permissions=RepositoryPermissions(DEFAULT_IMMUTABLE_CORE, [])
        )
        args = {"path": "workspace/a.txt"}
        approval = approver_factory("bob")(
            d.action_hash_for(AGENT, "edit", args, requested_by="carol")
        )
        with pytest.raises(ToolDenied, match="repository permissions"):
            d.dispatch(AGENT, "edit", args, requested_by="carol", approvals=[approval])
        assert not approval_gate.is_consumed(approval)
        assert calls == []


class TestReReviewE_SystemIdCohorts:
    def test_system_id_is_casefolded_and_canonical(self) -> None:
        assert Principal("a", PrincipalKind.AGENT, system_id="SYS-A").system_id == "sys-a"
        for bad in ("sys a", " sys", "sýs", ""):
            with pytest.raises(ValueError):
                Principal("a", PrincipalKind.AGENT, system_id=bad)

    def test_case_variants_share_a_cohort(self) -> None:
        autonomy = AutonomyController(ErrorBudget(max_failures=1))
        autonomy.record_failure(AGENT, FailureKind.POLICY_DENIAL)
        variant = Principal("agent-9", PrincipalKind.AGENT, system_id="SYS-A")
        assert autonomy.level(variant) is AutonomyLevel.P0_ONLY

    def test_unscoped_agents(self) -> None:
        lone = Principal("lone-1", PrincipalKind.AGENT)
        renamed = Principal("lone-2", PrincipalKind.AGENT)
        default = AutonomyController(ErrorBudget(max_failures=1))
        default.record_failure(lone, FailureKind.POLICY_DENIAL)
        assert default.level(lone) is AutonomyLevel.P0_ONLY  # own cohort
        assert default.level(renamed) is AutonomyLevel.T1_PREAUTHORIZED
        shared = AutonomyController(ErrorBudget(max_failures=1), demote_unscoped_agents=True)
        shared.record_failure(lone, FailureKind.POLICY_DENIAL)
        assert shared.level(renamed) is AutonomyLevel.P0_ONLY
        shared.restore(ALICE, renamed)
        assert shared.level(Principal("lone-3", PrincipalKind.AGENT)) is (
            AutonomyLevel.T1_PREAUTHORIZED
        )
