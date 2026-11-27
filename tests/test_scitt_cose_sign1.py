"""Tests for RFC 9052 SCITT COSE_Sign1 EdDSA exporter, canonical CBOR codec, and verifier."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.compliance import (
    COSE_ALG_EDDSA,
    MEDIA_TYPE_COMPLIANCE_BUNDLE,
    MEDIA_TYPE_DECISION_RECEIPT,
    MEDIA_TYPE_JSON,
    MEDIA_TYPE_OUTCOME_RECEIPT,
    PROFILE_CA_ADMT_2027,
    SCITT_COSE_SIGN1_TAG,
    SCITTExportError,
    export_receipt_bundle,
    export_scitt_cose_sign1,
    verify_scitt_cose_sign1,
)
from acgs_lite.compliance.scitt import (
    COSE_HEADER_ALG,
    COSE_HEADER_CONTENT_TYPE,
    COSE_HEADER_CRIT,
    COSE_HEADER_CWT_CLAIMS,
    COSE_HEADER_KID,
    CWT_CLAIM_IAT,
    CWT_CLAIM_ISS,
    CWT_CLAIM_SUB,
    _cbor_decode,
    _cbor_encode,
    _CborTag,
)
from acgs_lite.legitimacy import (
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
    SignedOutcomeReceipt,
    SignedReceipt,
    receipt_identity,
    sign_outcome,
    sign_receipt,
)


class _StubProvider:
    contract = ProviderContract(
        provider_id="scitt-payments",
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


def _make_signed_receipt(signer: Ed25519ReceiptSigner) -> SignedReceipt:
    boundary = ExecutionBoundary(
        allowed_method="charge",
        allowed_scope="prod",
        allowed_subjects=("acct_scitt",),
        expires_at="2026-12-31T00:00:00Z",
        single_use=True,
    )
    receipt = DecisionReceipt.create(
        request_id="req-scitt-1",
        goal="issue charge",
        proposed_method="charge",
        decision_type="ALLOW",
        authority_basis="constitution:default",
        matched_constraints=("RULE-1",),
        policy_version="1.0.0",
        denial_or_review_rationale=None,
        execution_boundary=boundary,
        issued_at="2026-11-27T12:00:00+00:00",
    )
    return sign_receipt(receipt, signer, signed_at="2026-11-27T12:00:00+00:00")


def _make_signed_outcome(
    tmp_path: Path,
    signer: Ed25519ReceiptSigner,
    signed_decision: SignedReceipt,
) -> SignedOutcomeReceipt:
    registry = ProviderContractRegistry()
    provider = _StubProvider()
    contract = registry.register(provider.contract)
    store = EffectStore(tmp_path / "scitt_effects.sqlite")
    store.create_budget("b1", 100)
    store.reserve(
        provider_id=provider.provider_id,
        grant_identity="grant-scitt-1",
        action={"op": "charge"},
        budget_id="b1",
        amount=1,
    )
    outcome = OutcomeReceipt(
        effect_key="acgs:effect:v1:" + "a" * 64,
        provider_id=provider.provider_id,
        provider_contract_digest=contract.digest,
        decision_receipt_identity=receipt_identity(signed_decision.receipt),
        grant_identity="grant-scitt-1",
        outcome=EffectOutcome.DONE,
        recorded_at="2026-11-27T12:01:00+00:00",
        provider_reference="ch_scitt_1",
    )
    return sign_outcome(outcome, signer)


def test_deterministic_cbor_roundtrip_and_canonical_key_order() -> None:
    payload = _CborTag(
        SCITT_COSE_SIGN1_TAG,
        [
            b"\x01\x02",
            {15: {6: 1700000000, 1: "https://iss.example"}, 1: -8, "z": True, "a": None},
            b"{}",
            b"\xaa" * 64,
        ],
    )
    encoded = _cbor_encode(payload)
    decoded = _cbor_decode(encoded)
    assert decoded == payload

    # Verify RFC 8949 §4.2.1 bytewise lexicographical ordering: 1 (0x01) < 15 (0x0f) < "a" (0x6161) < "z" (0x617a)
    map_encoded = _cbor_encode({"z": 1, "a": 2, 15: 3, 1: 4})
    assert map_encoded.startswith(b"\xa4\x01\x04\x0f\x03")

    # Python bool keys are rejected cleanly as CBOR map keys
    bool_map: dict[Any, Any] = {True: "bool", "ok": 1}
    with pytest.raises(TypeError, match="unsupported CBOR map key type"):
        _cbor_encode(bool_map)


def test_cbor_decoder_rejects_malformed_and_non_canonical_inputs() -> None:
    # Non-minimal 1-byte uint for value 5 (0x18 0x05 instead of 0x05)
    with pytest.raises(ValueError, match="non-canonical"):
        _cbor_decode(b"\x18\x05")
    # Non-minimal 2-byte uint for value 200
    with pytest.raises(ValueError, match="non-canonical"):
        _cbor_decode(b"\x19\x00\xc8")
    # Indefinite length array (0x9f ... 0xff)
    with pytest.raises(ValueError, match="unsupported CBOR additional info"):
        _cbor_decode(b"\x9f\xff")
    # Oversized bstr length exceeding remaining input
    with pytest.raises(ValueError, match="exceeds remaining"):
        _cbor_decode(b"\x5a\x00\x10\x00\x00\xaa")
    # Duplicate map keys
    with pytest.raises(ValueError, match="duplicate CBOR map key"):
        _cbor_decode(b"\xa2\x01\x01\x01\x02")
    # Trailing garbage
    with pytest.raises(ValueError, match="trailing bytes"):
        _cbor_decode(b"\x01\x02")
    # Deeply nested array
    with pytest.raises(ValueError, match="nesting depth"):
        _cbor_decode(b"\x81" * 40 + b"\x01")


def test_export_and_verify_signed_receipt_outcome_bundle_and_mapping(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    signer = Ed25519ReceiptSigner.from_seed(b"\x33" * 32, key_id="scitt-key-1")
    trusted = {signer.key_id: signer.public_key_hex()}
    signed_decision = _make_signed_receipt(signer)
    signed_outcome = _make_signed_outcome(tmp_path, signer, signed_decision)

    bundle = export_receipt_bundle(
        [signed_decision],
        outcome_receipts=[signed_outcome],
        profile=PROFILE_CA_ADMT_2027,
        system_id="scitt-demo",
        trusted_public_keys=trusted,
        generated_at="2026-11-27T12:02:00+00:00",
    )

    for item, expected_cty in (
        (signed_decision, MEDIA_TYPE_DECISION_RECEIPT),
        (signed_outcome, MEDIA_TYPE_OUTCOME_RECEIPT),
        (bundle, MEDIA_TYPE_COMPLIANCE_BUNDLE),
        ({"event": "policy-activated", "version": 4}, MEDIA_TYPE_JSON),
    ):
        env = export_scitt_cose_sign1(
            item,
            signer,
            issuer="did:web:acgs.example",
            subject="agent:billing",
            issued_at=1764244920,
            external_aad=b"registry-seq-42",
        )
        assert env.content_type == expected_cty
        meta = env.to_metadata_dict()
        assert meta["cose_tag"] == SCITT_COSE_SIGN1_TAG
        assert meta["cose_alg"] == COSE_ALG_EDDSA
        assert base64.b64decode(env.to_base64()) == env.cose_bytes
        assert bytes.fromhex(env.to_hex()) == env.cose_bytes

        # Decode structural check of protected headers
        tag_obj = _cbor_decode(env.cose_bytes)
        assert isinstance(tag_obj, _CborTag)
        protected = _cbor_decode(tag_obj.value[0])
        assert protected[COSE_HEADER_ALG] == COSE_ALG_EDDSA
        assert protected[COSE_HEADER_CONTENT_TYPE] == expected_cty
        assert protected[COSE_HEADER_KID] == b"scitt-key-1"
        assert protected[COSE_HEADER_CWT_CLAIMS] == {
            CWT_CLAIM_ISS: "did:web:acgs.example",
            CWT_CLAIM_SUB: "agent:billing",
            CWT_CLAIM_IAT: 1764244920,
        }

        res = verify_scitt_cose_sign1(
            env.cose_bytes,
            trusted,
            expected_content_type=expected_cty,
            expected_issuer="did:web:acgs.example",
            external_aad=b"registry-seq-42",
        )
        assert res.valid is True, res.errors
        assert res.errors == ()
        assert res.key_id == "scitt-key-1"
        assert res.issuer == "did:web:acgs.example"
        assert res.subject == "agent:billing"
        assert res.issued_at == 1764244920
        assert res.payload_sha256 == env.payload_sha256
        assert isinstance(res.payload, dict)


def test_verify_scitt_fails_closed_on_tampering_aad_and_untrusted_keys() -> None:
    pytest.importorskip("cryptography")
    signer = Ed25519ReceiptSigner.from_seed(b"\x44" * 32, key_id="k1")
    other = Ed25519ReceiptSigner.from_seed(b"\x55" * 32, key_id="k1")
    signed = _make_signed_receipt(signer)
    env = export_scitt_cose_sign1(
        signed,
        signer,
        issuer="did:web:acgs.example",
        external_aad=b"ctx-1",
    )

    # Wrong key
    res_wrong_key = verify_scitt_cose_sign1(
        env.cose_bytes,
        {"k1": other.public_key_hex()},
        external_aad=b"ctx-1",
    )
    assert res_wrong_key.valid is False
    assert any("signature verification failed" in err for err in res_wrong_key.errors)

    # Unknown kid
    res_unknown_kid = verify_scitt_cose_sign1(
        env.cose_bytes,
        {"different-key": signer.public_key_hex()},
        external_aad=b"ctx-1",
    )
    assert res_unknown_kid.valid is False
    assert any("untrusted" in err for err in res_unknown_kid.errors)

    # Wrong external_aad
    res_wrong_aad = verify_scitt_cose_sign1(
        env.cose_bytes,
        {"k1": signer.public_key_hex()},
        external_aad=b"ctx-2",
    )
    assert res_wrong_aad.valid is False

    # Expected content_type / issuer mismatch
    res_cty = verify_scitt_cose_sign1(
        env.cose_bytes,
        {"k1": signer.public_key_hex()},
        expected_content_type=MEDIA_TYPE_JSON,
        expected_issuer="https://wrong.example",
        external_aad=b"ctx-1",
    )
    assert res_cty.valid is False
    assert len(res_cty.errors) >= 2

    # Tampered payload byte re-encoded into CBOR fails signature
    tag_obj = _cbor_decode(env.cose_bytes)
    prot_bstr, unprot, payload_bstr, sig_bstr = tag_obj.value
    tampered_payload = payload_bstr.replace(b"req-scitt-1", b"req-scitt-9")
    tampered_cose = _cbor_encode(_CborTag(18, [prot_bstr, unprot, tampered_payload, sig_bstr]))
    res_tampered = verify_scitt_cose_sign1(
        tampered_cose,
        {"k1": signer.public_key_hex()},
        external_aad=b"ctx-1",
    )
    assert res_tampered.valid is False

    # Registrar signs a tampered inner receipt -> embedded check catches it even when COSE sig matches
    fake_dict: dict[str, Any] = signed.to_dict()
    fake_dict["receipt"]["goal"] = "tampered-goal"
    forged_outer = export_scitt_cose_sign1(
        fake_dict,
        signer,
        content_type=MEDIA_TYPE_DECISION_RECEIPT,
    )
    res_inner_tamper = verify_scitt_cose_sign1(
        forged_outer.cose_bytes,
        {"k1": signer.public_key_hex()},
    )
    assert res_inner_tamper.valid is False
    assert any("SignedReceipt" in err for err in res_inner_tamper.errors)

    # Malformed bytes and non-ASCII bundle digests never raise
    res_garbage = verify_scitt_cose_sign1(b"\xff\x00not-cbor", {"k1": signer.public_key_hex()})
    assert res_garbage.valid is False
    res_empty_keys = verify_scitt_cose_sign1(env.cose_bytes, {})
    assert res_empty_keys.valid is False

    non_ascii_bundle = export_scitt_cose_sign1(
        {"bundle_digest": "sha256:" + "\u00e9" * 64},
        signer,
        content_type=MEDIA_TYPE_COMPLIANCE_BUNDLE,
    )
    res_non_ascii_bundle = verify_scitt_cose_sign1(
        non_ascii_bundle.cose_bytes,
        {"k1": signer.public_key_hex()},
    )
    assert res_non_ascii_bundle.valid is False
    assert any("bundle_digest" in err for err in res_non_ascii_bundle.errors)

    # Embedded decision receipt with non-string public_key=null fails closed without TypeError
    null_pk_dict: dict[str, Any] = signed.to_dict()
    null_pk_dict["public_key"] = None
    null_pk_env = export_scitt_cose_sign1(
        null_pk_dict,
        signer,
        content_type=MEDIA_TYPE_DECISION_RECEIPT,
    )
    res_null_pk = verify_scitt_cose_sign1(null_pk_env.cose_bytes, {"k1": signer.public_key_hex()})
    assert res_null_pk.valid is False
    assert any("SignedReceipt" in err for err in res_null_pk.errors)

    # Huge integer payload exceeding Python's JSON int-str limit fails closed without ValueError
    huge_int_payload = b'{"big":' + b"9" * 5000 + b"}"
    huge_sig_structure = _cbor_encode(["Signature1", prot_bstr, b"", huge_int_payload])
    huge_sig = bytes.fromhex(signer.sign(huge_sig_structure))
    huge_cose = _cbor_encode(_CborTag(18, [prot_bstr, {}, huge_int_payload, huge_sig]))
    res_huge_int = verify_scitt_cose_sign1(huge_cose, {"k1": signer.public_key_hex()})
    assert res_huge_int.valid is False
    assert any("JSON" in err for err in res_huge_int.errors)

    # Unsupported critical COSE header parameter (RFC 9052 §3.1) is rejected even with valid sig
    crit_protected = _cbor_encode(
        {
            COSE_HEADER_ALG: COSE_ALG_EDDSA,
            COSE_HEADER_CRIT: [999],
            COSE_HEADER_CONTENT_TYPE: MEDIA_TYPE_JSON,
            COSE_HEADER_KID: b"k1",
            999: "required-unknown-ext",
        }
    )
    crit_payload = b'{"ok":true}'
    crit_sig = bytes.fromhex(
        signer.sign(_cbor_encode(["Signature1", crit_protected, b"", crit_payload]))
    )
    crit_cose = _cbor_encode(_CborTag(18, [crit_protected, {}, crit_payload, crit_sig]))
    res_crit = verify_scitt_cose_sign1(crit_cose, {"k1": signer.public_key_hex()})
    assert res_crit.valid is False
    assert any("critical COSE header" in err for err in res_crit.errors)

    # Deeply nested JSON triggering RecursionError on 3.10/3.11 (or accepted cleanly on 3.12+)
    json_prot = _cbor_encode(
        {
            COSE_HEADER_ALG: COSE_ALG_EDDSA,
            COSE_HEADER_CONTENT_TYPE: MEDIA_TYPE_JSON,
            COSE_HEADER_KID: b"k1",
        }
    )
    nested_payload = b'{"deep":' + (b"[" * 2500) + b"1" + (b"]" * 2500) + b"}"
    nested_sig = bytes.fromhex(
        signer.sign(_cbor_encode(["Signature1", json_prot, b"", nested_payload]))
    )
    nested_cose = _cbor_encode(_CborTag(18, [json_prot, {}, nested_payload, nested_sig]))
    res_nested = verify_scitt_cose_sign1(nested_cose, {"k1": signer.public_key_hex()})
    assert isinstance(res_nested.valid, bool)
    if not res_nested.valid:
        assert any("JSON" in err for err in res_nested.errors)

    # Outer SCITT signature over a bundle with recomputed bundle_digest still rejects forged inner receipts
    bundle_forged_unsigned: dict[str, Any] = {
        "schema_version": "acgs-compliance-bundle-v1",
        "profile": PROFILE_CA_ADMT_2027,
        "system_id": "forged-bundle",
        "generated_at": "2026-11-27T12:00:00Z",
        "self_assessment_notice": (
            "Cryptographically verifiable runtime decision/outcome record bundle; "
            "not legal advice or third-party regulatory certification."
        ),
        "decisions": [{"signed_receipt": null_pk_dict}],
        "adverse_decisions": [],
        "outcomes": [],
        "oversight": {},
        "section_digests": {},
    }
    forged_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(bundle_forged_unsigned, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
    )
    bundle_forged = {**bundle_forged_unsigned, "bundle_digest": forged_digest}
    forged_bundle_env = export_scitt_cose_sign1(
        bundle_forged,
        signer,
        content_type=MEDIA_TYPE_COMPLIANCE_BUNDLE,
    )
    res_forged_bundle = verify_scitt_cose_sign1(
        forged_bundle_env.cose_bytes,
        {"k1": signer.public_key_hex()},
    )
    assert res_forged_bundle.valid is False
    assert any("ComplianceReceiptBundle" in err for err in res_forged_bundle.errors)


def test_export_scitt_fail_closed_validation(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    signer = Ed25519ReceiptSigner.from_seed(b"\x66" * 32, key_id="k1")
    signed = _make_signed_receipt(signer)
    tampered_dict = signed.to_dict()
    tampered_dict["signature"] = "00" * 64
    tampered_signed = SignedReceipt.from_dict(tampered_dict)

    with pytest.raises(SCITTExportError, match="unverifiable SignedReceipt"):
        export_scitt_cose_sign1(tampered_signed, signer)

    outcome = _make_signed_outcome(tmp_path, signer, signed)
    bad_outcome_dict = outcome.to_dict()
    bad_outcome_dict["signature"] = "11" * 64
    bad_outcome = SignedOutcomeReceipt.from_dict(bad_outcome_dict)
    with pytest.raises(SCITTExportError, match="unverifiable SignedOutcomeReceipt"):
        export_scitt_cose_sign1(bad_outcome, signer)

    with pytest.raises(SCITTExportError, match="issued_at"):
        export_scitt_cose_sign1({"ok": 1}, signer, issued_at=True)  # type: ignore[arg-type]

    with pytest.raises(SCITTExportError, match="issuer"):
        export_scitt_cose_sign1({"ok": 1}, signer, issuer="   ")

    with pytest.raises(SCITTExportError, match="strict JSON"):
        export_scitt_cose_sign1({"bad": float("nan")}, signer)

    class _BadSigner:
        algorithm = "rsa"
        key_id = "bad"

        def public_key_hex(self) -> str:
            return "00" * 32

        def sign(self, message: bytes) -> str:  # noqa: ARG002
            return "00" * 64

    with pytest.raises(SCITTExportError, match="ed25519"):
        export_scitt_cose_sign1(json.loads(json.dumps({"ok": True})), _BadSigner())
