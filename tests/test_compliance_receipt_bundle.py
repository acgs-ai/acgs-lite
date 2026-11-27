"""Tests for deterministic compliance receipt bundle export and offline verification."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from acgs_lite.compliance.receipt_bundle import (
    BUNDLE_SCHEMA_VERSION,
    PROFILE_CA_ADMT_2027,
    PROFILE_EU_AI_ACT_ART12_26,
    SELF_ASSESSMENT_NOTICE,
    BundleExportError,
    export_receipt_bundle,
    verify_receipt_bundle,
)
from acgs_lite.legitimacy import (
    ContractedEffectStore,
    DecisionReceipt,
    Ed25519ReceiptSigner,
    EffectOutcome,
    EffectRequest,
    EffectStore,
    ExecutionBoundary,
    OutcomeReceipt,
    ProviderContract,
    ProviderContractClass,
    ProviderContractRegistry,
    ProviderResult,
    SignedReceipt,
    receipt_identity,
    sign_outcome,
    sign_receipt,
)
from acgs_lite.legitimacy.decide import DecisionState


class _StubProvider:
    contract = ProviderContract(
        provider_id="stub-payments",
        contract_class=ProviderContractClass.FENCEABLE,
        version="1.0",
        dedup_by_key=True,
        atomic_query_fence=True,
    )

    @property
    def provider_id(self) -> str:
        return self.contract.provider_id

    def send(self, request: EffectRequest) -> ProviderResult:
        return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE, fenced=True)

    def query_and_fence(self, request: EffectRequest) -> ProviderResult:
        return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE, fenced=False)


def _sample_action(x: str, *, scope: str, subject: str) -> str:
    return x


def _make_receipt(
    signer: Ed25519ReceiptSigner,
    *,
    request_id: str,
    decision_type: DecisionState,
    rationale: str | None = None,
) -> SignedReceipt:
    boundary = ExecutionBoundary(
        allowed_method="charge",
        allowed_scope="prod",
        allowed_subjects=("acct_1",),
        expires_at="2026-12-31T00:00:00Z",
        single_use=True,
    )
    receipt = DecisionReceipt.create(
        request_id=request_id,
        goal=f"goal-{request_id}",
        proposed_method="charge",
        decision_type=decision_type,
        authority_basis="constitution:default",
        matched_constraints=("RULE-1",),
        policy_version="1.0.0",
        denial_or_review_rationale=rationale,
        execution_boundary=boundary,
        issued_at="2026-11-27T10:00:00+00:00",
    )
    return sign_receipt(receipt, signer, signed_at="2026-11-27T10:00:00+00:00")


def test_export_and_verify_ca_admt_and_eu_bundles_round_trip(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    signer = Ed25519ReceiptSigner.from_seed(b"\x21" * 32, key_id="org-signer-1")
    trusted = {signer.key_id: signer.public_key_hex()}

    r_allow = _make_receipt(signer, request_id="req-allow", decision_type="ALLOW")
    r_deny = _make_receipt(
        signer,
        request_id="req-deny",
        decision_type="DENY_GOAL",
        rationale="Blocked high-risk transfer without review",
    )
    r_review = _make_receipt(
        signer,
        request_id="req-review",
        decision_type="STRUCTURED_REVIEW_REQUIRED",
        rationale="Requires second-person approval",
    )

    # Create a real chained SignedOutcomeReceipt linked to SignedReceipt via signed_envelope_identity
    registry = ProviderContractRegistry()
    provider = _StubProvider()
    contract = registry.register(provider.contract)
    store = EffectStore(tmp_path / "bundle.sqlite")
    store.create_budget("b1", 100)
    rec = store.reserve(
        provider_id=provider.provider_id,
        grant_identity="grant-1",
        action={"op": "charge"},
        budget_id="b1",
        amount=1,
    )
    contracted = ContractedEffectStore(store, registry)
    rec = contracted.send(rec.key, provider)
    outcome = sign_outcome(
        OutcomeReceipt(
            effect_key=rec.key,
            provider_id=provider.provider_id,
            provider_contract_digest=contract.digest,
            decision_receipt_identity=receipt_identity(r_allow.receipt),
            grant_identity="grant-1",
            outcome=EffectOutcome.DONE,
            recorded_at=datetime.now(timezone.utc).isoformat(),
            provider_reference="ch_123",
        ),
        signer,
    )

    escalations = [
        {
            "escalation_id": "esc-1",
            "request_id": "req-review",
            "decision": "approve",
            "proposer_id": "agent-1",
            "approver_id": "human-auditor-1",
            "decided_at": "2026-11-27T10:05:00Z",
            "rationale": "Reviewed invoice",
        }
    ]
    halts = [{"event_id": "halt-1", "reason": "manual drill", "at": "2026-11-27T09:00:00Z"}]

    ca_bundle = export_receipt_bundle(
        [r_allow, r_deny, r_review],
        profile=PROFILE_CA_ADMT_2027,
        trusted_public_keys=trusted,
        system_id="billing-agent",
        outcome_receipts=[outcome],
        retention_days=90,
        escalations=escalations,
        halt_events=halts,
        generated_at="2026-11-27T10:10:00Z",
    )
    assert ca_bundle.schema_version == BUNDLE_SCHEMA_VERSION
    assert ca_bundle.self_assessment_notice == SELF_ASSESSMENT_NOTICE
    assert len(ca_bundle.adverse_decisions) == 2
    assert ca_bundle.oversight["effective_date"] == "2027-01-01"
    assert ca_bundle.oversight["retention_meets_art26_6_floor"] is False
    assert ca_bundle.oversight["every_escalation_has_distinct_human_overseer"] is True
    assert '"bundle_digest"' in ca_bundle.to_json(indent=None)

    ver_ca = verify_receipt_bundle(ca_bundle.to_dict(), trusted_public_keys=trusted)
    assert ver_ca.valid is True
    assert ver_ca.verified_decision_count == 3
    assert ver_ca.verified_outcome_count == 1
    assert ver_ca.reasons == ()

    eu_bundle = export_receipt_bundle(
        [r_allow, r_deny, r_review],
        profile=PROFILE_EU_AI_ACT_ART12_26,
        trusted_public_keys=trusted,
        system_id="billing-agent",
        outcome_receipts=[outcome],
        retention_days=365,
        escalations=escalations,
        halt_events=halts,
    )
    assert eu_bundle.oversight["effective_date"] == "2027-12-02"
    assert eu_bundle.oversight["retention_floor_days"] == 180
    assert eu_bundle.oversight["retention_meets_art26_6_floor"] is True
    ver_eu = verify_receipt_bundle(eu_bundle.to_dict(), trusted_public_keys=trusted)
    assert ver_eu.valid is True


def test_export_fails_closed_on_invalid_inputs_or_unlinked_outcome(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    signer = Ed25519ReceiptSigner.from_seed(b"\x22" * 32, key_id="k1")
    other = Ed25519ReceiptSigner.from_seed(b"\x23" * 32, key_id="k2")
    trusted = {signer.key_id: signer.public_key_hex()}
    r_allow = _make_receipt(signer, request_id="r1", decision_type="ALLOW")
    r_other = _make_receipt(other, request_id="r2", decision_type="ALLOW")

    with pytest.raises(BundleExportError, match="Unsupported compliance bundle profile"):
        export_receipt_bundle([], profile="unknown", trusted_public_keys=trusted, system_id="sys")
    with pytest.raises(BundleExportError, match="system_id"):
        export_receipt_bundle(
            [], profile=PROFILE_CA_ADMT_2027, trusted_public_keys=trusted, system_id="  "
        )
    with pytest.raises(BundleExportError, match="retention_days"):
        export_receipt_bundle(
            [],
            profile=PROFILE_CA_ADMT_2027,
            trusted_public_keys=trusted,
            system_id="sys",
            retention_days=0,
        )
    with pytest.raises(BundleExportError, match="trusted_public_keys"):
        export_receipt_bundle(
            [], profile=PROFILE_CA_ADMT_2027, trusted_public_keys={}, system_id="sys"
        )
    with pytest.raises(BundleExportError, match="Untrusted signing key_id"):
        export_receipt_bundle(
            [r_other], profile=PROFILE_CA_ADMT_2027, trusted_public_keys=trusted, system_id="sys"
        )

    # Wrong pinned public key for k1 fails signature verification
    with pytest.raises(BundleExportError, match="Signature or hash"):
        export_receipt_bundle(
            [r_allow],
            profile=PROFILE_CA_ADMT_2027,
            trusted_public_keys={"k1": other.public_key_hex()},
            system_id="sys",
        )

    # Unlinked outcome receipt is rejected
    unlinked_outcome = sign_outcome(
        OutcomeReceipt(
            effect_key="acgs:effect:v1:" + "0" * 64,
            provider_id="stub",
            provider_contract_digest="a" * 64,
            decision_receipt_identity=receipt_identity(r_other.receipt),
            grant_identity="g1",
            outcome=EffectOutcome.DONE,
            recorded_at="2026-11-27T10:00:00Z",
        ),
        signer,
    )
    with pytest.raises(BundleExportError, match="unbundled decision_receipt_identity"):
        export_receipt_bundle(
            [r_allow],
            profile=PROFILE_CA_ADMT_2027,
            trusted_public_keys=trusted,
            system_id="sys",
            outcome_receipts=[unlinked_outcome],
        )


def test_verify_receipt_bundle_detects_tampering_never_raises() -> None:
    pytest.importorskip("cryptography")
    signer = Ed25519ReceiptSigner.from_seed(b"\x24" * 32, key_id="k1")
    trusted = {signer.key_id: signer.public_key_hex()}
    r_deny = _make_receipt(
        signer, request_id="req-tamp", decision_type="DENY_GOAL", rationale="deny"
    )
    bundle = export_receipt_bundle(
        [r_deny],
        profile=PROFILE_EU_AI_ACT_ART12_26,
        trusted_public_keys=trusted,
        system_id="sys-tamper",
        retention_days=180,
        escalations=[{"escalation_id": "e1", "proposer_id": "a1", "approver_id": "a1"}],
    )
    assert bundle.oversight["every_escalation_has_distinct_human_overseer"] is False

    # Non-mapping or empty key failures return valid=False without raising
    assert verify_receipt_bundle("not-a-dict", trusted_public_keys=trusted).valid is False  # type: ignore[arg-type]
    raw = bundle.to_dict()
    assert verify_receipt_bundle(raw, trusted_public_keys={}).valid is False

    # Tamper payload field -> digest mismatch + invalid signed_receipt (hash mismatch)
    tampered = bundle.to_dict()
    tampered["decisions"][0]["signed_receipt"]["receipt"]["goal"] = "tampered-goal"
    ver = verify_receipt_bundle(tampered, trusted_public_keys=trusted)
    assert ver.valid is False
    assert any("bundle_digest mismatch" in r for r in ver.reasons)
    assert any("invalid signed_receipt" in r for r in ver.reasons)

    # Tamper signature hex -> digest mismatch + signature verification failure
    tampered_sig = bundle.to_dict()
    tampered_sig["decisions"][0]["signed_receipt"]["signature"] = "00" * 64
    ver_sig = verify_receipt_bundle(tampered_sig, trusted_public_keys=trusted)
    assert ver_sig.valid is False
    assert any("bundle_digest mismatch" in r for r in ver_sig.reasons)
    assert any("signature or hash verification failed" in r for r in ver_sig.reasons)

    # Dropping an adverse decision while keeping signed decisions triggers adverse mismatch
    missing_adverse = bundle.to_dict()
    missing_adverse["adverse_decisions"] = []
    ver_adverse = verify_receipt_bundle(missing_adverse, trusted_public_keys=trusted)
    assert ver_adverse.valid is False
    assert any("adverse_decisions does not match" in r for r in ver_adverse.reasons)

    # Corrupt structural metadata / section digests / lists cleanly without raising
    corrupt = bundle.to_dict()
    corrupt["schema_version"] = "bad"
    corrupt["profile"] = "bad-profile"
    corrupt["self_assessment_notice"] = "altered"
    corrupt["bundle_digest"] = "not-sha256"
    corrupt["section_digests"] = "not-a-mapping"
    corrupt["decisions"] = ["bad-entry"]
    corrupt["outcomes"] = [{"not": "an-outcome"}]
    ver_corrupt = verify_receipt_bundle(corrupt, trusted_public_keys=trusted)
    assert ver_corrupt.valid is False
    assert any("unexpected schema_version" in r for r in ver_corrupt.reasons)
    assert any("section_digests must be a mapping" in r for r in ver_corrupt.reasons)
    assert any("decisions[0] missing signed_receipt" in r for r in ver_corrupt.reasons)
    assert any("outcomes[0] invalid signed outcome" in r for r in ver_corrupt.reasons)

    # Non-ASCII digest string (e.g. "sha256:é") must return valid=False cleanly without TypeError
    non_ascii = bundle.to_dict()
    non_ascii["bundle_digest"] = "sha256:\u00e9"
    non_ascii["section_digests"]["decisions"] = "sha256:\u00e9"
    ver_non_ascii = verify_receipt_bundle(non_ascii, trusted_public_keys=trusted)
    assert ver_non_ascii.valid is False
    assert any("bundle_digest missing or malformed" in r for r in ver_non_ascii.reasons)
    assert any(
        "section_digests['decisions'] missing or malformed" in r for r in ver_non_ascii.reasons
    )

    # Summary-rehash attack: rewriting wrapper/adverse/oversight fields + recomputing digests still fails
    import hashlib
    import json

    forged = bundle.to_dict()
    forged["decisions"][0]["decision_type"] = "ALLOW"
    forged["decisions"][0]["denial_or_review_rationale"] = None
    forged["adverse_decisions"][0]["decision_type"] = "ALLOW"
    forged["adverse_decisions"][0]["human_review"] = {
        "decision": "approve",
        "approver_id": "mallory",
    }
    forged["oversight"]["every_escalation_has_distinct_human_overseer"] = True
    forged["oversight"]["adverse_decision_count"] = 0
    for name, sec in (
        ("decisions", forged["decisions"]),
        ("adverse_decisions", forged["adverse_decisions"]),
        ("outcomes", forged["outcomes"]),
        ("oversight", forged["oversight"]),
    ):
        forged["section_digests"][name] = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(sec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                    "utf-8"
                )
            ).hexdigest()
        )
    unsigned_forged = {k: v for k, v in forged.items() if k != "bundle_digest"}
    forged["bundle_digest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                unsigned_forged, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
    )
    ver_forged = verify_receipt_bundle(forged, trusted_public_keys=trusted)
    assert ver_forged.valid is False
    assert any("does not match verified signed_receipt" in r for r in ver_forged.reasons)
    assert any(
        "oversight.every_escalation_has_distinct_human_overseer" in r for r in ver_forged.reasons
    )
    assert any("human_review does not match" in r for r in ver_forged.reasons)

    # Non-hashable key_id in signed_receipt must return valid=False cleanly without TypeError
    bad_key_id = bundle.to_dict()
    bad_key_id["decisions"][0]["signed_receipt"]["key_id"] = []
    ver_bad_key = verify_receipt_bundle(bad_key_id, trusted_public_keys=trusted)
    assert ver_bad_key.valid is False
    assert any("malformed envelope metadata" in r for r in ver_bad_key.reasons)

    # Repeated adverse receipts round-trip cleanly with preserved multiplicity
    dup_bundle = export_receipt_bundle(
        [r_deny, r_deny],
        profile=PROFILE_CA_ADMT_2027,
        trusted_public_keys=trusted,
        system_id="sys-dup",
    )
    assert dup_bundle.oversight["adverse_decision_count"] == 2
    assert len(dup_bundle.adverse_decisions) == 2
    ver_dup = verify_receipt_bundle(dup_bundle.to_dict(), trusted_public_keys=trusted)
    assert ver_dup.valid is True
    assert ver_dup.verified_decision_count == 2

    # Casefold equivalence for proposer/approver must NOT report distinct human overseer
    casefold_bundle = export_receipt_bundle(
        [r_deny],
        profile=PROFILE_EU_AI_ACT_ART12_26,
        trusted_public_keys=trusted,
        system_id="sys-case",
        retention_days=180,
        escalations=[
            {
                "escalation_id": "e-case",
                "proposer_id": "Alice@example.com",
                "approver_id": "alice@example.com",
            }
        ],
    )
    assert casefold_bundle.oversight["every_escalation_has_distinct_human_overseer"] is False
    assert (
        verify_receipt_bundle(casefold_bundle.to_dict(), trusted_public_keys=trusted).valid is True
    )
