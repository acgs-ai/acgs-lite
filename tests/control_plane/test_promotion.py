"""PromotionGate: bound external evidence first, PDP permit, PROMOTION receipt."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    ActionTier,
    EvidencePolicy,
    EvidenceSource,
    ExternalRunRef,
    InMemoryReceiptStore,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    PromotionGate,
    PromotionRejected,
    ReceiptCapabilityError,
    ReceiptKind,
    ReceiptLedger,
    SignedControlPlaneReceipt,
    TrustedRunRegistry,
    verify_chain,
    verify_receipt,
)

pytest.importorskip("cryptography")

from acgs_lite.control_plane.killswitch import KillSwitch  # noqa: E402
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.constitutional]

CANDIDATE = "sha256:" + "d" * 64
OTHER_CANDIDATE = "sha256:" + "e" * 64
CI_RUN = ExternalRunRef("ci", "7", EvidenceSource.CI_SYSTEM, artifact_digest=CANDIDATE)
EVAL_RUN = ExternalRunRef(
    "evaluator", "e-1", EvidenceSource.EVALUATOR_SERVICE, artifact_digest=CANDIDATE
)
AGENT_LOG = ExternalRunRef("agent", "log", EvidenceSource.AGENT_LOG)
ALICE = Principal("alice", PrincipalKind.HUMAN)
BOB = Principal("bob", PrincipalKind.HUMAN)


@pytest.fixture()
def signer() -> Ed25519ReceiptSigner:
    return Ed25519ReceiptSigner.from_seed(b"\x07" * 32, key_id="gate")


@pytest.fixture()
def runs() -> TrustedRunRegistry:
    registry = TrustedRunRegistry()
    service = Principal("ci-bot", PrincipalKind.SERVICE)
    registry.register_run(service, CI_RUN, conclusion="success")
    registry.register_run(service, EVAL_RUN, conclusion="success")
    return registry


@pytest.fixture()
def ledger(signer: Ed25519ReceiptSigner) -> ReceiptLedger:
    return ReceiptLedger(signer, store=InMemoryReceiptStore())


@pytest.fixture()
def pdp(
    constitution: Constitution, permit_all: PolicySet, ledger: ReceiptLedger
) -> Iterator[PolicyDecisionPoint]:
    with PolicyDecisionPoint.for_constitution(
        constitution, permit_all, receipt_ledger=ledger
    ) as point:
        yield point


@pytest.fixture()
def gate(
    pdp: PolicyDecisionPoint, ledger: ReceiptLedger, runs: TrustedRunRegistry
) -> PromotionGate:
    return PromotionGate(ledger, runs, pdp=pdp)


def _kw(signer: Ed25519ReceiptSigner, runs: TrustedRunRegistry) -> dict[str, Any]:
    return {"trusted_public_keys": {signer.key_id: signer.public_key_hex()}, "run_verifier": runs}


class TestPromotionGate:
    @pytest.mark.parametrize("unreadable", [False, True])
    def test_halt_during_decision_blocks_promotion_append(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        ledger: ReceiptLedger,
        runs: TrustedRunRegistry,
        tmp_path: Path,
        unreadable: bool,
    ) -> None:
        state = {"on": False}

        def probe(_path: Path) -> bool:
            if state["on"] and unreadable:
                raise OSError("state unavailable")
            return state["on"]

        def halt(decision: Any) -> None:
            if decision.allowed:
                state["on"] = True

        switch = KillSwitch("sys-a", signal_dir=tmp_path / "halt", probe=probe)
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger, kill_switch=switch, listeners=[halt]
        ) as point:
            gate = PromotionGate(ledger, runs, pdp=point)
            with pytest.raises(PromotionRejected, match="kill switch"):
                gate.promote(
                    ALICE,
                    "candidate",
                    candidate_digest=CANDIDATE,
                    evidence=[CI_RUN],
                    approvers=[BOB],
                )
        assert all(item.receipt.kind is not ReceiptKind.PROMOTION for item in ledger.receipts())

    def test_verified_ci_evidence_emits_verifiable_receipt(
        self,
        gate: PromotionGate,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
    ) -> None:
        signed = gate.promote(
            ALICE,
            "cand-1",
            candidate_digest=CANDIDATE,
            evidence=[CI_RUN, AGENT_LOG],
            approvers=[BOB],
        )
        receipt = signed.receipt
        assert receipt.kind is ReceiptKind.PROMOTION
        assert receipt.allowed and receipt.claims_success
        assert receipt.candidate_digest == CANDIDATE
        assert receipt.action == "promotion.promote" and receipt.resource == "cand-1"
        assert receipt.tier == int(ActionTier.T2)
        assert receipt.external_runs == (CI_RUN, AGENT_LOG)
        assert [a.principal_id for a in receipt.approvers] == ["bob"]
        assert verify_receipt(signed, **_kw(signer, runs)).valid
        chain = ledger.receipts()
        assert [s.receipt.kind for s in chain] == [
            ReceiptKind.POLICY_DECISION,
            ReceiptKind.PROMOTION,
        ]
        assert chain[0].receipt.decision_id == receipt.decision_id
        assert verify_chain(chain, **_kw(signer, runs)).valid
        wire = SignedControlPlaneReceipt.from_dict(signed.to_dict())
        assert verify_receipt(wire, **_kw(signer, runs)).valid

    def test_h1_run_cannot_certify_a_second_candidate(
        self, gate: PromotionGate, ledger: ReceiptLedger
    ) -> None:
        gate.promote(ALICE, "cand-1", candidate_digest=CANDIDATE, evidence=[CI_RUN])
        before = len(ledger)
        with pytest.raises(PromotionRejected, match="does not match the candidate"):
            gate.promote(ALICE, "cand-2", candidate_digest=OTHER_CANDIDATE, evidence=[CI_RUN])
        unbound = ExternalRunRef("ci", "7", EvidenceSource.CI_SYSTEM)
        with pytest.raises(PromotionRejected, match="not bound|does not match"):
            gate.promote(ALICE, "cand-2", candidate_digest=OTHER_CANDIDATE, evidence=[unbound])
        assert len(ledger) == before

    @pytest.mark.parametrize(
        ("evidence", "needle"),
        [
            ([AGENT_LOG], "only agent-written logs"),
            ([], "no external run evidence"),
            (
                [ExternalRunRef("ci", "404", EvidenceSource.CI_SYSTEM, artifact_digest=CANDIDATE)],
                "not registered",
            ),
            (
                [
                    CI_RUN,
                    ExternalRunRef(
                        "ci", "404", EvidenceSource.CI_SYSTEM, artifact_digest=CANDIDATE
                    ),
                ],
                "ci/404",
            ),
        ],
    )
    def test_bad_evidence_rejected_without_receipt(
        self,
        gate: PromotionGate,
        ledger: ReceiptLedger,
        evidence: list[ExternalRunRef],
        needle: str,
    ) -> None:
        with pytest.raises(PromotionRejected, match=needle):
            gate.promote(ALICE, "cand-1", candidate_digest=CANDIDATE, evidence=evidence)
        assert len(ledger) == 0

    def test_m4_duplicate_evidence_counts_once(
        self, pdp: PolicyDecisionPoint, ledger: ReceiptLedger, runs: TrustedRunRegistry
    ) -> None:
        gate = PromotionGate(
            ledger, runs, pdp=pdp, evidence_policy=EvidencePolicy(min_external_runs=2)
        )
        with pytest.raises(PromotionRejected, match="required 2"):
            gate.promote(ALICE, "cand-1", candidate_digest=CANDIDATE, evidence=[CI_RUN, CI_RUN])
        assert gate.promote(
            ALICE, "cand-1", candidate_digest=CANDIDATE, evidence=[CI_RUN, EVAL_RUN]
        ).receipt.allowed

    def test_self_approval_rejected(self, gate: PromotionGate, ledger: ReceiptLedger) -> None:
        with pytest.raises(PromotionRejected, match="own promotion"):
            gate.promote(
                ALICE,
                "cand-1",
                candidate_digest=CANDIDATE,
                evidence=[CI_RUN],
                approvers=[Principal("ALICE", PrincipalKind.HUMAN)],
            )
        assert len(ledger) == 0

    def test_duplicate_approvers_rejected_by_ledger(
        self, gate: PromotionGate, ledger: ReceiptLedger
    ) -> None:
        with pytest.raises(PromotionRejected, match="could not be emitted"):
            gate.promote(
                ALICE,
                "cand-1",
                candidate_digest=CANDIDATE,
                evidence=[CI_RUN],
                approvers=[BOB, Principal("BOB", PrincipalKind.HUMAN)],
            )
        assert all(s.receipt.kind is ReceiptKind.POLICY_DECISION for s in ledger.receipts())

    def test_h3_agent_cannot_promote(
        self, gate: PromotionGate, ledger: ReceiptLedger, agent: Principal
    ) -> None:
        with pytest.raises(PromotionRejected) as excinfo:
            gate.promote(agent, "cand-1", candidate_digest=CANDIDATE, evidence=[CI_RUN])
        decision = excinfo.value.decision
        assert decision is not None and "INV-CORE-WRITE" in decision.determining_policies
        (only,) = ledger.receipts()
        assert only.receipt.kind is ReceiptKind.POLICY_DECISION and not only.receipt.allowed

    def test_h2_append_promotion_only_through_gate(
        self, gate: PromotionGate, ledger: ReceiptLedger, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        from acgs_lite.control_plane import DecisionRequest

        request = DecisionRequest(agent, "promotion.promote", "candidate-EVIL", ActionTier.T2)
        real = pdp.decide(DecisionRequest(ALICE, "file.write", "workspace/x", ActionTier.T1))
        with pytest.raises(ReceiptCapabilityError):
            ledger.append_promotion(real, request, capability=object())
        with pytest.raises(ReceiptCapabilityError, match="already bound"):
            PromotionGate(ledger, TrustedRunRegistry(), pdp=pdp)
        assert all(s.receipt.kind is ReceiptKind.POLICY_DECISION for s in ledger.receipts())

    @pytest.mark.parametrize(
        ("principal", "candidate", "digest", "evidence", "approvers"),
        [
            ("alice", "c", CANDIDATE, [CI_RUN], []),
            (ALICE, "  ", CANDIDATE, [CI_RUN], []),
            (ALICE, "c", "sha256:short", [CI_RUN], []),
            (ALICE, "c", CANDIDATE, [CI_RUN.to_dict()], []),
            (ALICE, "c", CANDIDATE, [CI_RUN], ["bob"]),
        ],
    )
    def test_input_validation(
        self,
        gate: PromotionGate,
        principal: Any,
        candidate: Any,
        digest: Any,
        evidence: Any,
        approvers: Any,
    ) -> None:
        with pytest.raises(PromotionRejected):
            gate.promote(
                principal,
                candidate,
                candidate_digest=digest,
                evidence=evidence,
                approvers=approvers,
            )

    def test_receipt_failure_rejects(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
    ) -> None:
        class Broken(InMemoryReceiptStore):
            def append(self, signed: SignedControlPlaneReceipt) -> None:
                raise OSError("full")

        ledger = ReceiptLedger(signer, store=Broken())
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger
        ) as pdp:
            gate = PromotionGate(ledger, runs, pdp=pdp)
            with pytest.raises(PromotionRejected, match="PDP denied"):
                gate.promote(ALICE, "c", candidate_digest=CANDIDATE, evidence=[CI_RUN])

    def test_construction(
        self,
        ledger: ReceiptLedger,
        runs: TrustedRunRegistry,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
    ) -> None:
        with PolicyDecisionPoint.for_constitution(constitution, permit_all) as unbound:
            with pytest.raises(TypeError):
                PromotionGate("x", runs, pdp=unbound)  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                PromotionGate(ledger, object(), pdp=unbound)  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                PromotionGate(ledger, runs, pdp="x")  # type: ignore[arg-type]
            # A permissive PDP that is not bound to this ledger cannot be paired with it.
            with pytest.raises(ValueError, match="same receipt ledger"):
                PromotionGate(ledger, runs, pdp=unbound)


def _gh_verifier(artifact_fetch: Any = None) -> Any:
    from acgs_lite.control_plane import GitHubActionsRunVerifier

    payload = {
        "id": 555,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "e" * 40,
        "path": ".github/workflows/ci.yml",
        "head_branch": "main",
        "event": "push",
        "repository": {"full_name": "org/repo"},
        "head_repository": {"full_name": "org/repo"},
    }
    return GitHubActionsRunVerifier(
        lambda path: payload,
        repository="org/repo",
        allowed_workflows=[".github/workflows/ci.yml"],
        allowed_branches=["main"],
        allowed_events=["push"],
        artifact_fetch=artifact_fetch,
    )


GH_RUN = ExternalRunRef(
    "github-actions", "555", EvidenceSource.CI_SYSTEM, artifact_digest=CANDIDATE, head_sha="e" * 40
)


class TestR1PromotionBinding:
    def test_github_run_cannot_vouch_for_self_asserted_digest(
        self, pdp: PolicyDecisionPoint, ledger: ReceiptLedger
    ) -> None:
        gate = PromotionGate(ledger, _gh_verifier(), pdp=pdp)
        with pytest.raises(PromotionRejected, match="verifier cannot attest artifact digest"):
            gate.promote(ALICE, "prod-model-v9", candidate_digest=CANDIDATE, evidence=[GH_RUN])
        assert len(ledger) == 0

    def test_github_with_artifact_attestation_promotes(
        self, pdp: PolicyDecisionPoint, ledger: ReceiptLedger, signer: Ed25519ReceiptSigner
    ) -> None:
        verifier = _gh_verifier(lambda path: [CANDIDATE])
        gate = PromotionGate(ledger, verifier, pdp=pdp)
        signed = gate.promote(ALICE, "prod-model-v9", candidate_digest=CANDIDATE, evidence=[GH_RUN])
        assert verify_receipt(signed, **_kw(signer, verifier)).valid

    def test_same_run_and_digest_cannot_certify_two_candidates(
        self,
        gate: PromotionGate,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
    ) -> None:
        gate.promote(ALICE, "prod-model-v9", candidate_digest=CANDIDATE, evidence=[CI_RUN])
        # Re-promoting the same candidate id is allowed ...
        gate.promote(ALICE, "prod-model-v9", candidate_digest=CANDIDATE, evidence=[CI_RUN])
        before = len(ledger)
        # ... but the same (run, digest) cannot certify another name.
        with pytest.raises(PromotionRejected, match="already certified candidate 'prod-model-v9'"):
            gate.promote(ALICE, "prod-model-v10", candidate_digest=CANDIDATE, evidence=[CI_RUN])
        assert len(ledger) == before
        assert verify_chain(ledger.receipts(), **_kw(signer, runs)).valid

    def test_verify_chain_flags_cross_candidate_reuse(
        self, signer: Ed25519ReceiptSigner, runs: TrustedRunRegistry
    ) -> None:
        from acgs_lite.control_plane import GENESIS_RECEIPT_HASH, ApproverRef, ControlPlaneReceipt
        from acgs_lite.control_plane.receipts import sign_control_plane_receipt

        chain: list[SignedControlPlaneReceipt] = []
        prev = GENESIS_RECEIPT_HASH
        for sequence, name in enumerate(("prod-model-v9", "prod-model-v10")):
            receipt = ControlPlaneReceipt.create(
                ledger_id="l",
                origin="promotion_gate",
                kind=ReceiptKind.PROMOTION,
                sequence=sequence,
                prev_receipt_hash=prev,
                principal_id="alice",
                principal_kind="human",
                system_id=None,
                action="promotion.promote",
                resource=name,
                tier=2,
                constitution_hash="c",
                policy_digest="p",
                policy_set_digest="s",
                inputs_digest="i",
                decision_id=f"d{sequence}",
                allowed=True,
                determining_policies=(),
                reason="ok",
                error=None,
                claims_success=True,
                candidate_digest=CANDIDATE,
                approvers=(ApproverRef("bob", "human"),),
                external_runs=(CI_RUN,),
            )
            chain.append(sign_control_plane_receipt(receipt, signer))
            prev = receipt.receipt_hash
        result = verify_chain(chain, **_kw(signer, runs))
        assert not result.valid
        assert any("already certified 'prod-model-v9'" in r for r in result.reasons)


class TestR3R6GateHygiene:
    def test_gate_cannot_be_copied_and_hides_token(self, gate: PromotionGate) -> None:
        import copy

        for clone in (copy.copy, copy.deepcopy):
            with pytest.raises(TypeError):
                clone(gate)
        assert "object at" not in repr(gate)
        assert not any(type(v) is object for v in vars(gate).values())

    def test_shared_registry_and_ledger_key_warns(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        tmp_path: Any,
    ) -> None:
        from acgs_lite.control_plane import DEFAULT_IMMUTABLE_CORE

        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        shared = TrustedRunRegistry(
            path=tmp_path / "audit" / "runs.jsonl", registry=core, signer=signer
        )
        ledger = ReceiptLedger(signer, store=InMemoryReceiptStore())
        with (
            PolicyDecisionPoint.for_constitution(
                constitution, permit_all, receipt_ledger=ledger
            ) as pdp,
            pytest.warns(UserWarning, match="share a signing key"),
        ):
            PromotionGate(ledger, shared, pdp=pdp)
        other = Ed25519ReceiptSigner.from_seed(b"\x08" * 32, key_id="runs")
        separate = TrustedRunRegistry(
            path=tmp_path / "audit" / "r2.jsonl", registry=core, signer=other
        )
        ledger2 = ReceiptLedger(signer, store=InMemoryReceiptStore())
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger2
        ) as pdp2:
            import warnings

            with warnings.catch_warnings():
                warnings.simplefilter("error")
                PromotionGate(ledger2, separate, pdp=pdp2)
