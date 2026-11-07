"""Phase 2: signed hash-chained receipts for every decision; independent verification."""

from __future__ import annotations

import ast
import dataclasses
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    GENESIS_RECEIPT_HASH,
    ActionTier,
    ApproverRef,
    ControlPlaneReceipt,
    Decision,
    DecisionRequest,
    EvidenceSource,
    ExternalRunRef,
    GovernedToolDispatcher,
    InMemoryReceiptStore,
    JSONLReceiptStore,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    ReceiptCapabilityError,
    ReceiptConflict,
    ReceiptEmissionError,
    ReceiptKind,
    ReceiptLedger,
    ReceiptStoreCorrupted,
    RepositoryPermissions,
    SignedControlPlaneReceipt,
    ToolDenied,
    TrustedRunRegistry,
    WriteGrant,
    verify_chain,
    verify_receipt,
)
from acgs_lite.control_plane.receipts import sign_control_plane_receipt
from acgs_lite.legitimacy.signing import ReceiptSigningUnavailable

pytest.importorskip("cryptography")

from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.constitutional]

DIGEST = "sha256:" + "a" * 64
CI_SERVICE = Principal("ci-bot", PrincipalKind.SERVICE)
CI_RUN = ExternalRunRef("ci", "101", EvidenceSource.CI_SYSTEM, artifact_digest=DIGEST)
AGENT_LOG = ExternalRunRef("agent", "log-1", EvidenceSource.AGENT_LOG)
ALICE = Principal("alice", PrincipalKind.HUMAN)
DENY_ALL: dict[str, Any] = {"version": 1, "statements": []}


@pytest.fixture()
def signer() -> Ed25519ReceiptSigner:
    return Ed25519ReceiptSigner.from_seed(b"\x01" * 32, key_id="harness-1")


@pytest.fixture()
def runs() -> TrustedRunRegistry:
    registry = TrustedRunRegistry()
    registry.register_run(CI_SERVICE, CI_RUN, conclusion="success", artifact_digest=DIGEST)
    registry.register_run(
        CI_SERVICE,
        ExternalRunRef("ci", "102", EvidenceSource.CI_SYSTEM, artifact_digest=DIGEST),
        conclusion="failure",
    )
    return registry


@pytest.fixture()
def ledger(signer: Ed25519ReceiptSigner) -> ReceiptLedger:
    return ReceiptLedger(signer, store=InMemoryReceiptStore())


@pytest.fixture()
def wired_pdp(
    constitution: Constitution, permit_all: PolicySet, ledger: ReceiptLedger
) -> Iterator[PolicyDecisionPoint]:
    with PolicyDecisionPoint.for_constitution(
        constitution, permit_all, receipt_ledger=ledger
    ) as pdp:
        yield pdp


def _keys(signer: Ed25519ReceiptSigner) -> dict[str, str]:
    return {signer.key_id: signer.public_key_hex()}


def _req(
    principal: Principal, action: str = "file.write", resource: str = "workspace/x.py", **kw: Any
) -> DecisionRequest:
    return DecisionRequest(principal, action, resource, kw.pop("tier", ActionTier.T1), **kw)


def _forged(allowed: bool, action: str, resource: str) -> Decision:
    return Decision(
        allowed=allowed,
        reason="forged",
        determining_policies=(),
        constitution_hash="c",
        policy_digest="p",
        inputs_digest="i",
        decided_at="t",
        principal_id="agent-1",
        action=action,
        resource=resource,
        tier=ActionTier.T2,
    )


def _resign(
    signed: SignedControlPlaneReceipt, signer: Ed25519ReceiptSigner, **changes: Any
) -> SignedControlPlaneReceipt:
    """Tamper with a field and recompute only the signature (hash left stale)."""
    receipt = dataclasses.replace(signed.receipt, **changes)
    resigned = dataclasses.replace(signed, receipt=receipt)
    return dataclasses.replace(resigned, signature=signer.sign(resigned.signing_message()))


def _allowed_receipt(
    pdp: PolicyDecisionPoint,
    ledger: ReceiptLedger,
    action: str,
    evidence: tuple[ExternalRunRef, ...],
    principal: Principal = ALICE,
) -> SignedControlPlaneReceipt:
    attributes = {"external_runs": [ref.to_dict() for ref in evidence]}
    decision = pdp.decide(_req(principal, action, "cand-1", attributes=attributes))
    assert decision.allowed, decision.reason
    return ledger.receipts()[-1]


class TestEveryDecisionEmitsReceipt:
    def test_allow_and_deny(
        self,
        wired_pdp: PolicyDecisionPoint,
        ledger: ReceiptLedger,
        agent: Principal,
        human: Principal,
    ) -> None:
        decisions = [
            wired_pdp.decide(_req(agent)),
            wired_pdp.decide(_req(agent, resource="evaluator/x.py")),
            wired_pdp.decide(_req(agent, tier=ActionTier.T3)),
            wired_pdp.decide(_req(agent, approvers=(human,))),
            wired_pdp.decide("not a request"),
            wired_pdp.decide(_req(agent, expected_constitution_hash="stale")),
            wired_pdp.decide(_req(agent, attributes={"x": object()})),
        ]
        assert [d.allowed for d in decisions] == [True, False, False, True, False, False, False]
        receipts = ledger.receipts()
        assert len(receipts) == len(decisions)
        for decision, signed in zip(decisions, receipts, strict=True):
            r = signed.receipt
            assert r.kind is ReceiptKind.POLICY_DECISION
            assert r.ledger_id == ledger.ledger_id
            assert r.decision_id == decision.decision_id
            assert r.allowed == decision.allowed
            assert r.constitution_hash == decision.constitution_hash
            assert r.policy_digest == decision.policy_digest
            assert r.inputs_digest == decision.inputs_digest
            assert r.determining_policies == decision.determining_policies
        first = receipts[0].receipt
        assert (first.principal_id, first.principal_kind, first.system_id) == (
            "agent-1",
            "agent",
            "sys-a",
        )
        assert first.constitution_hash and first.policy_digest and first.inputs_digest
        assert receipts[3].receipt.approvers[0].principal_id == "alice"
        assert receipts[4].receipt.principal_kind is None
        assert "INV-CORE-WRITE" in receipts[1].receipt.determining_policies

    def test_fail_closed_backstop_is_receipted(
        self,
        wired_pdp: PolicyDecisionPoint,
        ledger: ReceiptLedger,
        agent: Principal,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def explode(*_: object) -> None:
            raise RuntimeError("bug")

        monkeypatch.setattr("acgs_lite.control_plane.pdp.core_category_for", explode)
        decision = wired_pdp.decide(_req(agent))
        assert not decision.allowed and decision.error == "fail_closed"
        (signed,) = ledger.receipts()
        assert signed.receipt.decision_id == decision.decision_id
        assert signed.receipt.error == "fail_closed"

    def test_dispatcher_pre_denial_is_receipted(
        self, wired_pdp: PolicyDecisionPoint, ledger: ReceiptLedger, agent: Principal
    ) -> None:
        dispatcher = GovernedToolDispatcher(
            wired_pdp,
            permissions=RepositoryPermissions(DEFAULT_IMMUTABLE_CORE, ()),
            tool_tiers={},
        )
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(agent, "missing", {})
        assert ledger.receipts()[-1].receipt.error == "dispatch_denied"
        assert not ledger.receipts()[-1].receipt.allowed

    def test_external_runs_from_attributes(
        self, wired_pdp: PolicyDecisionPoint, ledger: ReceiptLedger, agent: Principal
    ) -> None:
        allow = wired_pdp.decide(
            _req(agent, action="eval.report", attributes={"external_runs": [CI_RUN.to_dict()]})
        )
        assert allow.allowed
        receipt = ledger.receipts()[-1].receipt
        assert receipt.external_runs == (CI_RUN,)
        assert receipt.claims_success
        bad = wired_pdp.decide(_req(agent, attributes={"external_runs": "nope"}))
        assert not bad.allowed and bad.error == "receipt_failed"
        denied = wired_pdp.decide(
            _req(agent, resource="evaluator/x", attributes={"external_runs": [{"bad": 1}]})
        )
        assert not denied.allowed
        assert ledger.receipts()[-1].receipt.decision_id == denied.decision_id
        assert ledger.receipts()[-1].receipt.external_runs == ()
        claimed = wired_pdp.decide(_req(agent, attributes={"claims_success": True}))
        assert claimed.allowed and ledger.receipts()[-1].receipt.claims_success


class TestH2NoSigningOracle:
    def test_publish_is_not_public(
        self, constitution: Constitution, ledger: ReceiptLedger, signer: Ed25519ReceiptSigner
    ) -> None:
        with PolicyDecisionPoint.for_constitution(
            constitution, PolicySet.from_mapping(DENY_ALL), receipt_ledger=ledger
        ) as pdp:
            assert not hasattr(pdp, "publish")
            denied = pdp.record_denial("pre-check", principal_id="agent-1", action="file.write")
        assert not denied.allowed
        assert all(not s.receipt.allowed for s in ledger.receipts())

    def test_direct_append_requires_capability(self, wired_pdp: PolicyDecisionPoint) -> None:
        ledger = wired_pdp.receipt_ledger
        assert ledger is not None
        fake = _forged(True, "file.write", "evaluator/core.py")
        for capability in (None, object()):
            with pytest.raises(ReceiptCapabilityError):
                ledger.append_decision(fake, capability=capability)
            with pytest.raises(ReceiptCapabilityError):
                ledger.append_promotion(
                    fake, _req(ALICE, "promotion.promote", "c"), capability=capability
                )
        assert len(ledger) == 0

    def test_binding_is_single_and_exact(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        wired_pdp: PolicyDecisionPoint,
        signer: Ed25519ReceiptSigner,
    ) -> None:
        ledger = wired_pdp.receipt_ledger
        assert ledger is not None
        with pytest.raises(ReceiptCapabilityError, match="already bound"):
            PolicyDecisionPoint.for_constitution(constitution, permit_all, receipt_ledger=ledger)
        with pytest.raises(ReceiptCapabilityError):
            ledger.bind_decision_source(object())
        with pytest.raises(ReceiptCapabilityError):
            ledger.bind_promotion_gate(object())

        class Sniffer(ReceiptLedger):
            pass

        with pytest.raises(ValueError):
            PolicyDecisionPoint.for_constitution(
                constitution,
                permit_all,
                receipt_ledger=Sniffer(signer, store=InMemoryReceiptStore()),
            )

    def test_decision_must_match_request(
        self, wired_pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        """Even the bound capability will not sign a decision for another request."""
        ledger = wired_pdp.receipt_ledger
        assert ledger is not None
        append = wired_pdp._append_receipt  # in-process limitation, documented
        assert append is not None
        real = wired_pdp.decide(_req(agent))
        with pytest.raises(ReceiptEmissionError, match="inputs_digest"):
            append(real, _req(agent, resource="workspace/y"), "pdp")


class _FailingStore(InMemoryReceiptStore):
    def __init__(self, fail_times: int) -> None:
        super().__init__()
        self.fail_times = fail_times

    def append(self, signed: SignedControlPlaneReceipt) -> None:
        if self.fail_times > 0:
            self.fail_times -= 1
            raise OSError("disk full")
        super().append(signed)


class _UnavailableSigner:
    algorithm = "ed25519"
    key_id = "none"

    def public_key_hex(self) -> str:
        return "00"

    def sign(self, message: bytes) -> str:
        raise ReceiptSigningUnavailable("no crypto")


class TestFailClosedEmission:
    def test_emission_failure_on_allow_becomes_deny(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        agent: Principal,
    ) -> None:
        ledger = ReceiptLedger(signer, store=_FailingStore(fail_times=1))
        seen: list[Decision] = []
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger, listeners=[seen.append]
        ) as pdp:
            decision = pdp.decide(_req(agent))
            assert pdp.receipt_failures == 1
        assert not decision.allowed
        assert decision.error == "receipt_failed"
        assert seen == [decision]
        (signed,) = ledger.receipts()
        assert not signed.receipt.allowed and signed.receipt.sequence == 0
        assert signed.receipt.decision_id == decision.decision_id

    def test_l1_deny_with_failing_store_is_counted_and_audited(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        agent: Principal,
    ) -> None:
        ledger = ReceiptLedger(signer, store=_FailingStore(fail_times=5))
        audit = AuditLog()
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger, audit_log=audit
        ) as pdp:
            deny = pdp.decide(_req(agent, resource="evaluator/x.py"))
            assert pdp.receipt_failures == 1
            allow = pdp.decide(_req(agent))
            assert pdp.receipt_failures == 3  # allow failed, then its withdrawal failed
        assert not deny.allowed and deny.error is None
        assert not allow.allowed and allow.error == "receipt_failed"
        assert len(ledger) == 0
        failures = [e for e in audit.entries if e.type == "pdp_receipt_failure"]
        assert len(failures) == 3
        assert failures[0].metadata["decision_id"] == deny.decision_id

    def test_receipt_failure_audit_is_best_effort(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        agent: Principal,
    ) -> None:
        class Flaky(AuditLog):
            def record(self, entry: Any, *args: Any, **kwargs: Any) -> str:
                if entry.type == "pdp_receipt_failure":
                    raise OSError("audit down")
                return super().record(entry, *args, **kwargs)

        ledger = ReceiptLedger(signer, store=_FailingStore(fail_times=5))
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger, audit_log=Flaky()
        ) as pdp:
            assert not pdp.decide(_req(agent, resource="evaluator/x.py")).allowed
            assert pdp.receipt_failures == 1

    def test_signing_unavailable_denies(
        self, constitution: Constitution, permit_all: PolicySet, agent: Principal
    ) -> None:
        ledger = ReceiptLedger(_UnavailableSigner(), store=InMemoryReceiptStore())
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger
        ) as pdp:
            decision = pdp.decide(_req(agent))
        assert not decision.allowed and decision.error == "receipt_failed"
        assert len(ledger) == 0

    def test_ledger_construction(self, signer: Ed25519ReceiptSigner) -> None:
        with pytest.raises(TypeError):
            ReceiptLedger("x", store=InMemoryReceiptStore())  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            ReceiptLedger(signer, store="x")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            PolicyDecisionPoint(
                None,
                constitution_hash="h",
                policy_digest="d",
                receipt_ledger="x",  # type: ignore[arg-type]
            )

    def test_ledger_has_no_unguarded_mutation_api(self) -> None:
        public = {name for name in dir(ReceiptLedger) if not name.startswith("_")}
        assert public == {
            "append_decision",
            "append_promotion",
            "bind_decision_source",
            "bind_promotion_gate",
            "head_hash",
            "key_id",
            "ledger_id",
            "public_key_hex",
            "receipts",
        }


def _jsonl_ledger(
    tmp_path: Path, signer: Ed25519ReceiptSigner, name: str = "receipts.jsonl"
) -> ReceiptLedger:
    core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    return ReceiptLedger(signer, store=JSONLReceiptStore(f"audit/{name}", registry=core))


class TestChain:
    def _build(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        ledger: ReceiptLedger,
        agent: Principal,
        n: int = 4,
    ) -> tuple[SignedControlPlaneReceipt, ...]:
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger
        ) as pdp:
            for i in range(n):
                pdp.decide(_req(agent, resource=f"evaluator/{i}.py"))
        return ledger.receipts()

    def test_linkage_and_verify(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
        agent: Principal,
    ) -> None:
        chain = self._build(constitution, permit_all, ledger, agent)
        assert [s.receipt.sequence for s in chain] == [0, 1, 2, 3]
        assert chain[0].receipt.prev_receipt_hash == GENESIS_RECEIPT_HASH
        for prev, cur in zip(chain, chain[1:], strict=False):
            assert cur.receipt.prev_receipt_hash == prev.receipt.receipt_hash
        assert ledger.head_hash == chain[-1].receipt.receipt_hash
        kw: dict[str, Any] = {"trusted_public_keys": _keys(signer), "run_verifier": runs}
        assert verify_chain(chain, **kw).valid
        assert verify_chain(
            chain, expected_head_hash=ledger.head_hash, expected_ledger_id=ledger.ledger_id, **kw
        ).valid
        assert verify_chain((), **kw).valid
        assert not verify_chain(chain[:-1], expected_head_hash=ledger.head_hash, **kw).valid
        assert not verify_chain(list(chain) + ["junk"], **kw).valid  # type: ignore[list-item]

    def test_tamper_reorder_drop(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
        agent: Principal,
    ) -> None:
        chain = list(self._build(constitution, permit_all, ledger, agent))
        kw: dict[str, Any] = {"trusted_public_keys": _keys(signer), "run_verifier": runs}
        for name, value in [
            ("allowed", True),
            ("reason", "x"),
            ("policy_digest", "p"),
            ("principal_kind", "human"),
            ("issued_at", "t"),
            ("ledger_id", "other"),
        ]:
            tampered = list(chain)
            tampered[1] = _resign(chain[1], signer, **{name: value})
            result = verify_chain(tampered, **kw)
            assert not result.valid and any("receipt_hash mismatch" in r for r in result.reasons)
        assert not verify_chain([chain[1], chain[0], *chain[2:]], **kw).valid
        assert not verify_chain([chain[0], *chain[2:]], **kw).valid

    def test_l3_chain_must_have_one_ledger_id(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
        agent: Principal,
    ) -> None:
        first = ReceiptLedger(signer, store=InMemoryReceiptStore(), ledger_id="ledger-a")
        second = ReceiptLedger(signer, store=InMemoryReceiptStore(), ledger_id="ledger-b")
        a = self._build(constitution, permit_all, first, agent, 2)
        b = self._build(constitution, permit_all, second, agent, 2)
        kw: dict[str, Any] = {"trusted_public_keys": _keys(signer), "run_verifier": runs}
        assert verify_chain(a, expected_ledger_id="ledger-a", **kw).valid
        assert not verify_chain(a, expected_ledger_id="ledger-b", **kw).valid
        # Splice b[1] onto a, correctly relinked and re-hashed by the same key:
        # contiguity and signatures hold, but the chain mixes ledger ids.
        fields = {f.name: getattr(b[1].receipt, f.name) for f in dataclasses.fields(b[1].receipt)}
        fields.pop("receipt_hash")
        fields["prev_receipt_hash"] = a[0].receipt.receipt_hash
        spliced = sign_control_plane_receipt(ControlPlaneReceipt.create(**fields), signer)
        result = verify_chain([a[0], spliced], **kw)
        assert not result.valid and any("mixes ledger ids" in r for r in result.reasons)

    def test_jsonl_round_trip_and_reopen(
        self,
        tmp_path: Path,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
        agent: Principal,
    ) -> None:
        first = _jsonl_ledger(tmp_path, signer)
        self._build(constitution, permit_all, first, agent, 2)
        reopened = _jsonl_ledger(tmp_path, signer)
        assert reopened.receipts() == first.receipts()
        assert reopened.ledger_id == first.ledger_id
        self._build(constitution, permit_all, reopened, agent, 1)
        chain = _jsonl_ledger(tmp_path, signer).receipts()
        assert [s.receipt.sequence for s in chain] == [0, 1, 2]
        assert verify_chain(chain, trusted_public_keys=_keys(signer), run_verifier=runs).valid
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        with pytest.raises(ReceiptStoreCorrupted, match="ledger_id"):
            ReceiptLedger(
                signer,
                store=JSONLReceiptStore("audit/receipts.jsonl", registry=core),
                ledger_id="someone-else",
            )

    def test_m5_two_writers_on_one_file_fail_closed(
        self,
        tmp_path: Path,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
        agent: Principal,
    ) -> None:
        ledger_a = _jsonl_ledger(tmp_path, signer)
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger_a
        ) as pdp_a:
            assert not pdp_a.decide(_req(agent, resource="evaluator/x")).allowed
            ledger_b = _jsonl_ledger(tmp_path, signer)
            with PolicyDecisionPoint.for_constitution(
                constitution, permit_all, receipt_ledger=ledger_b
            ) as pdp_b:
                assert pdp_a.decide(_req(agent)).allowed
                forked = pdp_b.decide(_req(agent))  # b's head is stale -> conflict
                assert not forked.allowed and forked.error == "receipt_failed"
                assert pdp_b.receipt_failures == 2
        chain = _jsonl_ledger(tmp_path, signer).receipts()
        assert [s.receipt.sequence for s in chain] == [0, 1]
        assert verify_chain(chain, trusted_public_keys=_keys(signer), run_verifier=runs).valid

    def test_in_memory_store_refuses_fork(self, signer: Ed25519ReceiptSigner) -> None:
        store = InMemoryReceiptStore()
        receipt = ControlPlaneReceipt.create(
            ledger_id="x",
            origin="pdp",
            kind=ReceiptKind.POLICY_DECISION,
            sequence=0,
            prev_receipt_hash="sha256:" + "1" * 64,
            principal_id="a",
            principal_kind=None,
            system_id=None,
            action="a",
            resource="r",
            tier=None,
            constitution_hash="",
            policy_digest="",
            policy_set_digest="",
            inputs_digest="",
            decision_id="d",
            allowed=False,
            determining_policies=(),
            reason="r",
            error=None,
            claims_success=False,
            candidate_digest=None,
            approvers=(),
            external_runs=(),
        )
        with pytest.raises(ReceiptConflict):
            store.append(sign_control_plane_receipt(receipt, signer))

    def test_m6_reopen_rejects_forged_or_foreign_tail(
        self,
        tmp_path: Path,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        agent: Principal,
    ) -> None:
        ledger = _jsonl_ledger(tmp_path, signer)
        self._build(constitution, permit_all, ledger, agent, 1)
        path = tmp_path / "audit" / "receipts.jsonl"
        good = path.read_text()
        head = ledger.receipts()[-1].receipt
        fake = dataclasses.replace(
            head, sequence=1, prev_receipt_hash=head.receipt_hash, allowed=True, reason="forged"
        )
        fake = ControlPlaneReceipt.create(
            **{f.name: getattr(fake, f.name) for f in dataclasses.fields(fake)}
            | {"receipt_id": "z"}
        )
        garbage = SignedControlPlaneReceipt(
            fake, "ed25519", signer.key_id, signer.public_key_hex(), "00" * 64
        )
        attacker = Ed25519ReceiptSigner.from_seed(b"\x09" * 32, key_id=signer.key_id)
        foreign_key = sign_control_plane_receipt(fake, attacker)
        relabeled = dataclasses.replace(foreign_key, public_key_hex=signer.public_key_hex())
        for forged, needle in [
            (garbage, "bad signature"),
            (foreign_key, "not signed by this ledger"),
            (relabeled, "bad signature"),
        ]:
            path.write_text(good + json.dumps(forged.to_dict()) + "\n")
            with pytest.raises(ReceiptStoreCorrupted, match=needle):
                _jsonl_ledger(tmp_path, signer)

    def test_jsonl_corruption_fails_closed(
        self,
        tmp_path: Path,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        agent: Principal,
    ) -> None:
        ledger = _jsonl_ledger(tmp_path, signer)
        self._build(constitution, permit_all, ledger, agent, 2)
        path = tmp_path / "audit" / "receipts.jsonl"
        lines = path.read_text().splitlines()
        path.write_text(lines[1] + "\n" + lines[0] + "\n")
        with pytest.raises(ReceiptStoreCorrupted):
            _jsonl_ledger(tmp_path, signer)
        record = json.loads(lines[0])
        record["receipt"]["reason"] = "rewritten"
        path.write_text(json.dumps(record) + "\n")
        with pytest.raises(ReceiptStoreCorrupted, match="hash"):
            _jsonl_ledger(tmp_path, signer)
        path.write_text("{not json\n")
        with pytest.raises(ReceiptStoreCorrupted):
            _jsonl_ledger(tmp_path, signer)

    def test_reopen_with_unverifiable_signature_fails_closed(
        self,
        tmp_path: Path,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        agent: Principal,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._build(constitution, permit_all, _jsonl_ledger(tmp_path, signer), agent, 1)

        def unavailable(*_: object) -> bool:
            raise ReceiptSigningUnavailable("missing")

        monkeypatch.setattr("acgs_lite.control_plane.receipt_ledger.verify_signature", unavailable)
        with pytest.raises(ReceiptStoreCorrupted, match="cannot verify"):
            _jsonl_ledger(tmp_path, signer)

    def test_l2_store_has_no_core_path_escape_hatch(self, tmp_path: Path) -> None:
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        for bad in (
            tmp_path / "workspace" / "r.jsonl",
            tmp_path / "evaluator" / "r.jsonl",
            "/elsewhere/r.jsonl",
        ):
            with pytest.raises(PermissionError):
                JSONLReceiptStore(bad, registry=core)
        with pytest.raises(PermissionError):
            JSONLReceiptStore(tmp_path / "audit" / "r.jsonl")  # DEFAULT core has no repo_root
        with pytest.raises(TypeError):
            JSONLReceiptStore(  # type: ignore[call-arg]
                tmp_path / "workspace" / "r.jsonl", require_core_path=False
            )

    def test_jsonl_partial_write_rolled_back(
        self,
        tmp_path: Path,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        agent: Principal,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ledger = _jsonl_ledger(tmp_path, signer)
        path = tmp_path / "audit" / "receipts.jsonl"
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger
        ) as pdp:
            pdp.decide(_req(agent, resource="evaluator/x"))
            size = path.stat().st_size

            def bad_fsync(fd: int) -> None:
                raise OSError("fsync failed")

            monkeypatch.setattr("acgs_lite.control_plane.receipt_ledger.os.fsync", bad_fsync)
            assert not pdp.decide(_req(agent)).allowed
        assert path.stat().st_size == size
        assert len(ledger) == 1

    def test_agent_tool_cannot_write_receipt_store(
        self, wired_pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        permissions = RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE, (WriteGrant(agent.id, agent.kind, ("workspace/**",)),)
        )
        dispatcher = GovernedToolDispatcher(
            wired_pdp, permissions=permissions, tool_tiers={"write": ActionTier.T1}
        )
        calls: list[str] = []

        def write(path: str, content: str) -> None:
            calls.append(path)

        dispatcher.register("write", write, path_params={"path"}, opaque_params={"content"})
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(agent, "write", {"path": "audit/receipts.jsonl", "content": "{}"})
        assert calls == []
        policies = {p for d in excinfo.value.decisions for p in d.determining_policies}
        assert "INV-CORE-WRITE" in policies


class TestIndependentVerification:
    def test_good_receipt_round_trips_and_verifies(
        self,
        wired_pdp: PolicyDecisionPoint,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
    ) -> None:
        signed = _allowed_receipt(wired_pdp, ledger, "eval.report", (CI_RUN, AGENT_LOG))
        wire = json.loads(json.dumps(signed.to_dict()))
        restored = SignedControlPlaneReceipt.from_dict(wire)
        assert restored == signed
        # The verifier holds only the public key and the run registry.
        result = verify_receipt(
            restored, trusted_public_keys={"harness-1": signer.public_key_hex()}, run_verifier=runs
        )
        assert result.valid, result.reasons

    @pytest.mark.parametrize(
        ("evidence", "needle"),
        [
            ((AGENT_LOG,), "only agent-written logs"),
            ((), "no external run evidence"),
            ((ExternalRunRef("ci", "999", "ci_system", artifact_digest=DIGEST),), "not registered"),
            (
                (ExternalRunRef("ci", "102", "ci_system", artifact_digest=DIGEST),),
                "conclusion is failure",
            ),
            (
                (ExternalRunRef("ci", "101", "ci_system", artifact_digest="sha256:" + "f" * 64),),
                "digest",
            ),
            ((ExternalRunRef("ci", "101", "ci_system"),), "not bound to an artifact"),
            ((CI_RUN, ExternalRunRef("ci", "999", "ci_system", artifact_digest=DIGEST)), "ci/999"),
        ],
    )
    def test_evidence_rejections(
        self,
        wired_pdp: PolicyDecisionPoint,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
        evidence: tuple[ExternalRunRef, ...],
        needle: str,
    ) -> None:
        signed = _allowed_receipt(wired_pdp, ledger, "eval.pass", evidence)
        result = verify_receipt(signed, trusted_public_keys=_keys(signer), run_verifier=runs)
        assert not result.valid
        assert any(needle in reason for reason in result.reasons), result.reasons

    def test_ordinary_allow_needs_no_evidence_but_cited_runs_must_validate(
        self,
        wired_pdp: PolicyDecisionPoint,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
    ) -> None:
        kw: dict[str, Any] = {"trusted_public_keys": _keys(signer), "run_verifier": runs}
        assert verify_receipt(_allowed_receipt(wired_pdp, ledger, "file.write", ()), **kw).valid
        bad = _allowed_receipt(
            wired_pdp, ledger, "file.write", (ExternalRunRef("ci", "999", "ci_system"),)
        )
        assert not verify_receipt(bad, **kw).valid
        plain = _allowed_receipt(wired_pdp, ledger, "file.write", ())
        assert not verify_receipt(plain, require_external_evidence=True, **kw).valid
        claim = _allowed_receipt(wired_pdp, ledger, "eval.report", (AGENT_LOG,))
        assert verify_receipt(claim, require_external_evidence=False, **kw).valid
        wired_pdp.decide(
            _req(
                ALICE,
                "eval.x",
                "evaluator/x",
                attributes={"external_runs": [AGENT_LOG.to_dict()]},
            )
        )
        deny = ledger.receipts()[-1]
        assert not deny.receipt.allowed
        assert verify_receipt(deny, **kw).valid

    def test_key_and_signature_rejections(
        self,
        wired_pdp: PolicyDecisionPoint,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
    ) -> None:
        signed = _allowed_receipt(wired_pdp, ledger, "eval.report", (CI_RUN,))
        other = Ed25519ReceiptSigner.from_seed(b"\x02" * 32, key_id="harness-1")
        cases = {
            "unknown signing key": {"trusted_public_keys": {"other": signer.public_key_hex()}},
            "does not match": {"trusted_public_keys": {"harness-1": other.public_key_hex()}},
        }
        for needle, kw in cases.items():
            result = verify_receipt(signed, run_verifier=runs, **kw)
            assert not result.valid and any(needle in r for r in result.reasons)
        flipped_sig = signed.signature[:-1] + ("0" if signed.signature[-1] != "0" else "1")
        bit_flip = dataclasses.replace(signed, signature=flipped_sig)
        result = verify_receipt(bit_flip, trusted_public_keys=_keys(signer), run_verifier=runs)
        assert "bad signature" in result.reasons
        forged = sign_control_plane_receipt(signed.receipt, other)
        assert not verify_receipt(
            forged, trusted_public_keys=_keys(signer), run_verifier=runs
        ).valid
        bad_alg = dataclasses.replace(signed, algorithm="rsa")
        assert any(
            "algorithm" in r
            for r in verify_receipt(
                bad_alg, trusted_public_keys=_keys(signer), run_verifier=runs
            ).reasons
        )
        assert not verify_receipt(
            {"x": 1}, trusted_public_keys=_keys(signer), run_verifier=runs
        ).valid

    def test_signature_verification_unavailable(
        self,
        wired_pdp: PolicyDecisionPoint,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        signed = _allowed_receipt(wired_pdp, ledger, "file.write", ())

        def unavailable(*_: object) -> bool:
            raise ReceiptSigningUnavailable("missing")

        monkeypatch.setattr("acgs_lite.control_plane.receipt_verify.verify_signature", unavailable)
        result = verify_receipt(signed, trusted_public_keys=_keys(signer), run_verifier=runs)
        assert not result.valid and any("unavailable" in r for r in result.reasons)


def _issuer_signed_promotion(signer: Ed25519ReceiptSigner, **overrides: Any) -> Any:
    """A PROMOTION receipt signed by a compromised/buggy issuer (bypasses the gate)."""
    fields: dict[str, Any] = {
        "ledger_id": "ledger-a",
        "origin": "promotion_gate",
        "kind": ReceiptKind.PROMOTION,
        "sequence": 0,
        "prev_receipt_hash": GENESIS_RECEIPT_HASH,
        "principal_id": "alice",
        "principal_kind": "human",
        "system_id": None,
        "action": "promotion.promote",
        "resource": "cand-1",
        "tier": 2,
        "constitution_hash": "c",
        "policy_digest": "p",
        "policy_set_digest": "s",
        "inputs_digest": "i",
        "decision_id": "d",
        "allowed": True,
        "determining_policies": ("permit-all",),
        "reason": "permitted",
        "error": None,
        "claims_success": True,
        "candidate_digest": DIGEST,
        "approvers": (ApproverRef("bob", "human"),),
        "external_runs": (CI_RUN,),
    }
    fields.update(overrides)
    return sign_control_plane_receipt(ControlPlaneReceipt.create(**fields), signer)


class TestH3VerifierReassertsPromotionInvariants:
    def test_well_formed_issuer_receipt_verifies(
        self, signer: Ed25519ReceiptSigner, runs: TrustedRunRegistry
    ) -> None:
        signed = _issuer_signed_promotion(signer)
        assert verify_receipt(signed, trusted_public_keys=_keys(signer), run_verifier=runs).valid

    @pytest.mark.parametrize(
        ("overrides", "needle"),
        [
            ({"principal_kind": "agent", "principal_id": "agent-1"}, "human principal"),
            ({"principal_kind": None}, "human principal"),
            ({"allowed": False}, "allowed decision"),
            ({"approvers": (ApproverRef("ALICE", "human"),)}, "own approvers"),
            (
                {"approvers": (ApproverRef("bob", "human"), ApproverRef("Bob", "human"))},
                "not distinct",
            ),
            ({"candidate_digest": None}, "no candidate_digest"),
            ({"candidate_digest": "sha256:" + "e" * 64}, "does not match the candidate"),
            ({"external_runs": (AGENT_LOG,)}, "only agent-written logs"),
        ],
    )
    def test_rejections(
        self,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
        overrides: dict[str, Any],
        needle: str,
    ) -> None:
        signed = _issuer_signed_promotion(signer, **overrides)
        result = verify_receipt(signed, trusted_public_keys=_keys(signer), run_verifier=runs)
        assert not result.valid
        assert any(needle in r for r in result.reasons), result.reasons


class TestReceiptModel:
    def test_strict_from_dict(
        self,
        wired_pdp: PolicyDecisionPoint,
        ledger: ReceiptLedger,
    ) -> None:
        signed = _allowed_receipt(wired_pdp, ledger, "eval.report", (CI_RUN,))
        data = signed.to_dict()
        for mutate in (
            lambda d: d.update(extra=1),
            lambda d: d.pop("signature"),
            lambda d: d["receipt"].update(extra=1),
            lambda d: d["receipt"].pop("sequence"),
            lambda d: d["receipt"].update(approvers="x"),
            lambda d: d["receipt"].update(approvers=[{"principal_id": "a"}]),
            lambda d: d["receipt"].update(external_runs=[{"bogus": 1}]),
            lambda d: d["receipt"].update(sequence=-1),
            lambda d: d["receipt"].update(sequence=True),
            lambda d: d["receipt"].update(tier="1"),
            lambda d: d["receipt"].update(allowed="yes"),
            lambda d: d["receipt"].update(prev_receipt_hash="abc"),
            lambda d: d["receipt"].update(kind="other"),
            lambda d: d["receipt"].update(reason=3),
            lambda d: d["receipt"].update(error=3),
            lambda d: d["receipt"].update(receipt_id=""),
            lambda d: d["receipt"].update(ledger_id="bad id!"),
            lambda d: d["receipt"].update(candidate_digest="sha256:x"),
            lambda d: d["receipt"].update(determining_policies=[1]),
            lambda d: d.update(signature="ZZ"),
            lambda d: d.update(key_id=""),
        ):
            copy = json.loads(json.dumps(data))
            mutate(copy)
            with pytest.raises(ValueError):
                SignedControlPlaneReceipt.from_dict(copy)
        with pytest.raises(ValueError):
            ControlPlaneReceipt.from_dict("x")
        with pytest.raises(ValueError):
            SignedControlPlaneReceipt("x", "ed25519", "k", "00", "00")  # type: ignore[arg-type]

    def test_refuses_to_sign_stale_hash(
        self,
        wired_pdp: PolicyDecisionPoint,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
    ) -> None:
        signed = _allowed_receipt(wired_pdp, ledger, "file.write", ())
        receipt = dataclasses.replace(signed.receipt, reason="y")
        with pytest.raises(ValueError):
            sign_control_plane_receipt(receipt, signer)

    def test_model_validation(self) -> None:
        with pytest.raises(ValueError):
            ApproverRef("", "human")
        with pytest.raises(ValueError):
            ApproverRef("a", "")


class TestVerifierIndependence:
    """The verifier must work without the PDP: no PDP-side import anywhere
    in its control-plane import closure (checked by AST, like the IAM test)."""

    FORBIDDEN = (
        "pdp",
        "policy",
        "invariants",
        "dispatcher",
        "receipt_ledger",
        "promotion",
        "context",
    )

    def test_verify_closure_does_not_import_pdp(self) -> None:
        root = Path(__file__).resolve().parents[2] / "src" / "acgs_lite" / "control_plane"
        pending = ["receipt_verify"]
        seen: set[str] = set()
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            tree = ast.parse((root / f"{name}.py").read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.startswith("acgs_lite.control_plane."):
                        pending.append(node.module.rsplit(".", 1)[-1])
                    elif node.module == "acgs_lite.control_plane":
                        pytest.fail(f"{name} imports the control_plane package (pulls in the PDP)")
                elif isinstance(node, ast.Import):
                    assert not any(a.name.startswith("acgs_lite.control_plane") for a in node.names)
        assert "receipts" in seen and "evidence" in seen
        assert not (seen & set(self.FORBIDDEN)), seen


class TestR2BoundedCost:
    def test_append_cost_does_not_grow_with_the_file(
        self, tmp_path: Path, constitution: Constitution, signer: Ed25519ReceiptSigner
    ) -> None:
        import time

        ledger = _jsonl_ledger(tmp_path, signer)
        with PolicyDecisionPoint.for_constitution(
            constitution,
            PolicySet.from_mapping(DENY_ALL),
            receipt_ledger=ledger,
            pre_denial_receipt_limit=None,
        ) as pdp:
            costs: list[float] = []
            for _ in range(2000):
                start = time.perf_counter()
                pdp.record_denial("x" * 900, principal_id="alice", action="tool.call", resource="t")
                costs.append(time.perf_counter() - start)
        assert len(ledger) == 2000
        first, last = sum(costs[:100]) / 100, sum(costs[-100:]) / 100
        assert last < 5 * first, (first, last)

    def test_length_caps(
        self, wired_pdp: PolicyDecisionPoint, ledger: ReceiptLedger, agent: Principal
    ) -> None:
        from acgs_lite.control_plane.receipts import MAX_REASON_CHARS, TRUNCATION_MARKER

        denied = wired_pdp.record_denial("r" * 10_000, principal_id="alice", action="tool.call")
        assert not denied.allowed
        reason = ledger.receipts()[-1].receipt.reason
        assert len(reason) == MAX_REASON_CHARS and reason.endswith(TRUNCATION_MARKER)
        before = len(ledger)
        oversized = wired_pdp.record_denial("x", principal_id="a" * 600, action="tool.call")
        assert not oversized.allowed
        assert len(ledger) == before and wired_pdp.receipt_failures == 1
        long_resource = wired_pdp.decide(_req(agent, resource="workspace/" + "y" * 600))
        assert not long_resource.allowed and long_resource.error == "receipt_failed"

    def test_pre_denial_rate_limit(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        ledger: ReceiptLedger,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        clock = [1000.0]
        monkeypatch.setattr("acgs_lite.control_plane.pdp.time.monotonic", lambda: clock[0])
        with PolicyDecisionPoint.for_constitution(
            constitution,
            permit_all,
            receipt_ledger=ledger,
            pre_denial_receipt_limit=3,
            pre_denial_window_s=10,
        ) as pdp:
            results = [pdp.record_denial("spam", principal_id="mallory") for _ in range(5)]
            assert all(not d.allowed for d in results)
            assert len(ledger) == 3 and pdp.suppressed_denial_receipts == 2
            pdp.record_denial("other", principal_id="bob")  # separate budget
            assert len(ledger) == 4
            clock[0] += 11
            pdp.record_denial("later", principal_id="mallory")
            assert len(ledger) == 5 and pdp.suppressed_denial_receipts == 2
        for bad in (0, True, "3"):
            with pytest.raises(ValueError):
                PolicyDecisionPoint(
                    None,
                    constitution_hash="h",
                    policy_digest="d",
                    pre_denial_receipt_limit=bad,  # type: ignore[arg-type]
                )
        with pytest.raises(ValueError):
            PolicyDecisionPoint(
                None, constitution_hash="h", policy_digest="d", pre_denial_window_s=0
            )

    def test_tracked_principals_are_pruned(
        self, wired_pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = [0.0]
        monkeypatch.setattr("acgs_lite.control_plane.pdp.time.monotonic", lambda: clock[0])
        monkeypatch.setattr("acgs_lite.control_plane.pdp._MAX_TRACKED_PRE_DENIAL_KEYS", 5)
        for i in range(6):
            wired_pdp.record_denial("x", principal_id=f"p{i}")
        clock[0] += 1000
        wired_pdp.record_denial("x", principal_id="fresh")
        assert set(wired_pdp._pre_denials) == {"fresh"}

    def test_store_shrink_and_foreign_append(
        self,
        tmp_path: Path,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        agent: Principal,
    ) -> None:
        ledger = _jsonl_ledger(tmp_path, signer)
        path = tmp_path / "audit" / "receipts.jsonl"
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger
        ) as pdp:
            pdp.decide(_req(agent, resource="evaluator/a"))
            pdp.decide(_req(agent, resource="evaluator/b"))
            path.write_text(path.read_text().splitlines()[0] + "\n")  # truncate the tail
            assert not pdp.decide(_req(agent)).allowed
            path.write_bytes(path.read_bytes() + b'{"broken"\n')
            assert not pdp.decide(_req(agent)).allowed
            path.write_bytes(path.read_bytes() + b"\xff\xfe\n")
            assert not pdp.decide(_req(agent)).allowed


class TestR3TokenHygiene:
    def test_allow_without_request_is_rejected(self, wired_pdp: PolicyDecisionPoint) -> None:
        append = wired_pdp._append_receipt  # in-process limitation, documented
        assert append is not None
        with pytest.raises(ReceiptEmissionError, match="needs its request"):
            append(_forged(True, "file.write", "evaluator/core.py"), None, "pdp")
        with pytest.raises(ReceiptEmissionError, match="needs its request"):
            append(_forged(True, "file.write", "x"), _req(ALICE), "dispatcher_pre_denial")
        with pytest.raises(ReceiptEmissionError, match="origin"):
            append(_forged(False, "file.write", "x"), None, "promotion_gate")
        with pytest.raises(ReceiptEmissionError):
            append("x", None, "pdp")  # type: ignore[arg-type]
        assert len(wired_pdp.receipt_ledger or ()) == 0

    def test_no_token_attribute_copy_or_repr_leak(self, wired_pdp: PolicyDecisionPoint) -> None:
        import copy

        ledger = wired_pdp.receipt_ledger
        assert ledger is not None
        for owner in (wired_pdp, ledger):
            assert not any(type(v) is object for v in vars(owner).values())
            assert "object at" not in repr(owner)
            for clone in (copy.copy, copy.deepcopy):
                with pytest.raises(TypeError):
                    clone(owner)
        assert not hasattr(wired_pdp, "_receipt_token")


class TestR4OriginAndAttribution:
    def test_origins_and_attribution(
        self,
        wired_pdp: PolicyDecisionPoint,
        ledger: ReceiptLedger,
        signer: Ed25519ReceiptSigner,
        runs: TrustedRunRegistry,
        agent: Principal,
    ) -> None:
        kw: dict[str, Any] = {"trusted_public_keys": _keys(signer), "run_verifier": runs}
        dispatcher = GovernedToolDispatcher(
            wired_pdp,
            permissions=RepositoryPermissions(DEFAULT_IMMUTABLE_CORE, ()),
            tool_tiers={},
        )
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(agent, "missing", {})
        pre = ledger.receipts()[-1]
        assert pre.receipt.origin == "dispatcher_pre_denial"
        assert pre.receipt.principal_id == "agent-1" and pre.receipt.principal_kind is None
        pre_result = verify_receipt(pre, **kw)
        assert pre_result.valid and not pre_result.attributed
        wired_pdp.decide(_req(agent))
        decided = ledger.receipts()[-1]
        assert decided.receipt.origin == "pdp"
        decided_result = verify_receipt(decided, **kw)
        assert decided_result.valid and decided_result.attributed
        wired_pdp.decide("garbage")
        unparsed = verify_receipt(ledger.receipts()[-1], **kw)
        assert unparsed.valid and not unparsed.attributed
        tampered = _resign(decided, signer, origin="dispatcher_pre_denial")
        assert not verify_receipt(tampered, **kw).attributed
        with pytest.raises(ValueError):
            dataclasses.replace(decided.receipt, origin="agent")
