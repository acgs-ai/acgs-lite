"""Regression tests for the PR #238 (phase 2) review threads."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    GENESIS_RECEIPT_HASH,
    ActionTier,
    ApproverRef,
    ControlPlaneReceipt,
    DecisionRequest,
    EvidenceSource,
    ExternalRunRef,
    InMemoryReceiptStore,
    JSONLReceiptStore,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    ReceiptConflict,
    ReceiptKind,
    ReceiptLedger,
    ReceiptStoreCorrupted,
    RunRegistrationRejected,
    TrustedRunRegistry,
    verify_receipt,
)
from acgs_lite.control_plane import evidence as evidence_module
from acgs_lite.control_plane import pdp as pdp_module
from acgs_lite.control_plane.receipts import (
    MAX_APPROVERS,
    MAX_EXTERNAL_RUNS,
    sign_control_plane_receipt,
)

pytest.importorskip("cryptography")

from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

DIGEST = "sha256:" + "a" * 64
CI = Principal("ci-bot", PrincipalKind.SERVICE)
AGENT = Principal("agent-1", PrincipalKind.AGENT)
ALICE = Principal("alice", PrincipalKind.HUMAN)


def test_verifier_import_does_not_load_issuer_modules() -> None:
    code = """
import importlib.abc
import sys
blocked = {
    'acgs_lite.control_plane.pdp',
    'acgs_lite.control_plane.dispatcher',
    'acgs_lite.control_plane.invariants',
    'acgs_lite.control_plane.receipt_ledger',
}
class BlockIssuer(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in blocked:
            raise ImportError('issuer module imported: ' + fullname)
sys.meta_path.insert(0, BlockIssuer())
from acgs_lite.control_plane.receipt_verify import verify_receipt
from acgs_lite.control_plane import verify_chain
assert callable(verify_receipt) and callable(verify_chain)
assert not blocked.intersection(sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


@pytest.fixture()
def signer() -> Ed25519ReceiptSigner:
    return Ed25519ReceiptSigner.from_seed(b"\x02" * 32, key_id="harness-2")


def _ci(run_id: str = "101") -> ExternalRunRef:
    return ExternalRunRef("ci", run_id, EvidenceSource.CI_SYSTEM, artifact_digest=DIGEST)


def _receipt(signer: Ed25519ReceiptSigner, **overrides: Any) -> Any:
    fields: dict[str, Any] = {
        "ledger_id": "ledger-a",
        "origin": "pdp",
        "kind": ReceiptKind.POLICY_DECISION,
        "sequence": 0,
        "prev_receipt_hash": GENESIS_RECEIPT_HASH,
        "principal_id": "alice",
        "principal_kind": "human",
        "system_id": None,
        "action": "db.drop",
        "resource": "prod",
        "tier": 3,
        "constitution_hash": "c",
        "policy_digest": "p",
        "policy_set_digest": "s",
        "inputs_digest": "i",
        "decision_id": "d",
        "allowed": True,
        "determining_policies": ("permit-all",),
        "reason": "permitted",
        "error": None,
        "claims_success": False,
        "candidate_digest": None,
        "approvers": (ApproverRef("bob", "human"), ApproverRef("carol", "human")),
        "external_runs": (),
    }
    fields.update(overrides)
    return sign_control_plane_receipt(ControlPlaneReceipt.create(**fields), signer)


def _verify(signed: Any, signer: Ed25519ReceiptSigner) -> Any:
    return verify_receipt(
        signed,
        trusted_public_keys={signer.key_id: signer.public_key_hex()},
        run_verifier=TrustedRunRegistry(),
    )


class TestT3TwoPersonInVerifier:
    """238.1 / 238.7: allowed T3 receipts must carry two distinct humans."""

    def test_two_distinct_humans_verify(self, signer: Ed25519ReceiptSigner) -> None:
        assert _verify(_receipt(signer), signer).valid

    @pytest.mark.parametrize(
        ("approvers", "needle"),
        [
            ((), "fewer than 2"),
            ((ApproverRef("bob", "human"),), "fewer than 2"),
            ((ApproverRef("bot-1", "agent"), ApproverRef("bot-2", "agent")), "human"),
            ((ApproverRef("bob", "human"), ApproverRef("Bob", "human")), "distinct"),
            ((ApproverRef("alice", "human"), ApproverRef("bob", "human")), "requester"),
        ],
    )
    def test_bad_quorum_rejected(
        self, signer: Ed25519ReceiptSigner, approvers: tuple[ApproverRef, ...], needle: str
    ) -> None:
        result = _verify(_receipt(signer, approvers=approvers), signer)
        assert not result.valid
        assert any(needle in reason for reason in result.reasons), result.reasons

    def test_t3_deny_needs_no_quorum(self, signer: Ed25519ReceiptSigner) -> None:
        result = _verify(_receipt(signer, allowed=False, approvers=()), signer)
        assert not any("T3" in reason for reason in result.reasons)


class TestRunRegistryAcrossInstances:
    """238.2 / 238.3 / 238.10 / 238.11: the persisted run registry."""

    def _pair(self, tmp_path: Path, signer: Ed25519ReceiptSigner) -> Any:
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        path = tmp_path / "audit" / "runs.jsonl"
        a = TrustedRunRegistry(path=path, registry=core, signer=signer)
        b = TrustedRunRegistry(path=path, registry=core, signer=signer)
        return core, path, a, b

    def test_second_instance_cannot_double_register(
        self, tmp_path: Path, signer: Ed25519ReceiptSigner
    ) -> None:
        core, path, a, b = self._pair(tmp_path, signer)
        a.register_run(CI, _ci(), conclusion="success", artifact_digest=DIGEST)
        with pytest.raises(RunRegistrationRejected, match="already registered"):
            b.register_run(CI, _ci(), conclusion="failure", artifact_digest=DIGEST)
        # b reconciled a's line, and the file still reopens.
        assert b.validate(_ci()).valid
        reopened = TrustedRunRegistry(path=path, registry=core, signer=signer)
        assert len(reopened) == 1 and reopened.validate(_ci()).valid

    def test_interleaved_registrations_both_persist(
        self, tmp_path: Path, signer: Ed25519ReceiptSigner
    ) -> None:
        core, path, a, b = self._pair(tmp_path, signer)
        a.register_run(CI, _ci("1"), conclusion="success", artifact_digest=DIGEST)
        b.register_run(CI, _ci("2"), conclusion="success", artifact_digest=DIGEST)
        a.register_run(CI, _ci("3"), conclusion="success", artifact_digest=DIGEST)
        assert len(TrustedRunRegistry(path=path, registry=core, signer=signer)) == 3

    def test_unreloadable_registered_by_is_rejected(
        self, tmp_path: Path, signer: Ed25519ReceiptSigner
    ) -> None:
        core, path, a, _ = self._pair(tmp_path, signer)
        long_service = Principal("s" * 300, PrincipalKind.SERVICE)
        with pytest.raises(RunRegistrationRejected, match="would not reload"):
            a.register_run(long_service, _ci(), conclusion="success", artifact_digest=DIGEST)
        assert not path.exists() or path.read_bytes() == b""
        TrustedRunRegistry(path=path, registry=core, signer=signer)

    def test_fsync_failure_rolls_back_the_line(
        self, tmp_path: Path, signer: Ed25519ReceiptSigner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        core, path, a, _ = self._pair(tmp_path, signer)
        a.register_run(CI, _ci("1"), conclusion="success", artifact_digest=DIGEST)
        size = path.stat().st_size

        def boom(fd: int) -> None:
            raise OSError("fsync failed")

        monkeypatch.setattr(evidence_module.os, "fsync", boom)
        with pytest.raises(OSError):
            a.register_run(CI, _ci("2"), conclusion="success", artifact_digest=DIGEST)
        monkeypatch.undo()
        assert path.stat().st_size == size
        a.register_run(CI, _ci("2"), conclusion="success", artifact_digest=DIGEST)
        assert len(TrustedRunRegistry(path=path, registry=core, signer=signer)) == 2

    def test_unterminated_registry_tail_refused(
        self, tmp_path: Path, signer: Ed25519ReceiptSigner
    ) -> None:
        core, path, a, _ = self._pair(tmp_path, signer)
        a.register_run(CI, _ci("1"), conclusion="success", artifact_digest=DIGEST)
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
        with pytest.raises(ValueError, match="newline"):
            TrustedRunRegistry(path=path, registry=core, signer=signer)


class TestPreDenialKeyBound:
    """238.4: unvalidated pre-denial labels must not grow without bound."""

    def test_new_labels_beyond_capacity_get_no_receipt(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        signer: Ed25519ReceiptSigner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(pdp_module, "_MAX_TRACKED_PRE_DENIAL_KEYS", 3)
        ledger = ReceiptLedger(signer, store=InMemoryReceiptStore())
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger
        ) as pdp:
            for index in range(10):
                decision = pdp.record_denial("nope", principal_id=f"label-{index}")
                assert not decision.allowed
            assert len(pdp._pre_denials) <= 3
            assert pdp.suppressed_denial_receipts == 7
            assert len(ledger.receipts()) == 3


class TestReceiptStoreTail:
    """238.5 / 238.6: unterminated tails and unexpected growth."""

    def _store(self, tmp_path: Path) -> JSONLReceiptStore:
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        return JSONLReceiptStore(tmp_path / "audit" / "receipts.jsonl", registry=core)

    def test_unterminated_tail_refused_on_open(
        self, tmp_path: Path, signer: Ed25519ReceiptSigner
    ) -> None:
        store = self._store(tmp_path)
        store.append(_receipt(signer, tier=1, approvers=()))
        store.path.write_bytes(store.path.read_bytes().rstrip(b"\n"))
        with pytest.raises(ReceiptStoreCorrupted, match="newline"):
            self._store(tmp_path)

    def test_duplicated_head_line_is_not_trusted(
        self, tmp_path: Path, signer: Ed25519ReceiptSigner
    ) -> None:
        store = self._store(tmp_path)
        first = _receipt(signer, tier=1, approvers=())
        store.append(first)
        store.path.write_bytes(store.path.read_bytes() * 2)  # copy of the head
        second = _receipt(
            signer,
            tier=1,
            approvers=(),
            sequence=1,
            prev_receipt_hash=first.receipt.receipt_hash,
            decision_id="d2",
        )
        with pytest.raises(ReceiptConflict, match="grew"):
            store.append(second)


class TestReceiptSizeLimits:
    """238.8: collection and string limits; oversized denies still recorded."""

    def test_model_limits(self, signer: Ed25519ReceiptSigner) -> None:
        with pytest.raises(ValueError, match="external_runs"):
            _receipt(signer, external_runs=tuple(_ci(str(i)) for i in range(MAX_EXTERNAL_RUNS + 1)))
        with pytest.raises(ValueError, match="approvers"):
            _receipt(
                signer,
                approvers=tuple(ApproverRef(f"h{i}", "human") for i in range(MAX_APPROVERS + 1)),
            )
        with pytest.raises(ValueError, match="system_id"):
            _receipt(signer, system_id="x" * 600)
        with pytest.raises(ValueError, match="approver fields"):
            ApproverRef("h" * 600, "human")

    @pytest.fixture()
    def wired(
        self, constitution: Constitution, permit_all: PolicySet, signer: Ed25519ReceiptSigner
    ) -> Iterator[tuple[PolicyDecisionPoint, ReceiptLedger]]:
        ledger = ReceiptLedger(signer, store=InMemoryReceiptStore())
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger
        ) as pdp:
            yield pdp, ledger

    def _many_runs(self) -> list[dict[str, Any]]:
        return [_ci(str(i)).to_dict() for i in range(MAX_EXTERNAL_RUNS + 10)]

    def test_oversized_deny_is_recorded_without_evidence(
        self, wired: tuple[PolicyDecisionPoint, ReceiptLedger]
    ) -> None:
        pdp, ledger = wired
        request = DecisionRequest(
            AGENT,
            "file.write",
            "evaluator/x.py",
            ActionTier.T1,
            attributes={"external_runs": self._many_runs()},
        )
        decision = pdp.decide(request)
        assert not decision.allowed
        assert ledger.receipts()[-1].receipt.external_runs == ()
        assert ledger.receipts()[-1].receipt.decision_id == decision.decision_id

    def test_oversized_allow_is_withdrawn(
        self, wired: tuple[PolicyDecisionPoint, ReceiptLedger]
    ) -> None:
        pdp, _ = wired
        request = DecisionRequest(
            ALICE,
            "file.write",
            "workspace/x.py",
            ActionTier.T1,
            attributes={"external_runs": self._many_runs()},
        )
        decision = pdp.decide(request)
        assert not decision.allowed
        assert decision.error == "receipt_failed"
