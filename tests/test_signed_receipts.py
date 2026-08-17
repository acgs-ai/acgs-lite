"""Asymmetric (Ed25519) signed decision-receipt contract tests.

These prove the differentiator the governance field does not match: a per-decision
receipt whose authenticity an *independent* party can verify with only the signer's
public key -- not a shared secret and not a hash chain alone.
"""

from __future__ import annotations

import json

import pytest

# Ed25519 signing needs the optional `crypto` extra; skip cleanly without it.
pytest.importorskip("cryptography")

from acgs_lite.legitimacy import (  # noqa: E402
    DecisionReceipt,
    Ed25519ReceiptSigner,
    ExecutionBoundary,
    SignedReceipt,
    sign_receipt,
)

# Fixed 32-byte seeds give deterministic Ed25519 keypairs (RFC 8032), so the
# whole signing path is reproducible without sacrificing real asymmetric crypto.
_SEED_A = bytes(range(32))
_SEED_B = bytes(range(32, 64))


def _boundary(method: str = "process") -> ExecutionBoundary:
    return ExecutionBoundary(
        allowed_method=method,
        allowed_scope="tenant-a",
        allowed_subjects=("subject-1",),
        expires_at=None,
        single_use=True,
    )


def _receipt(*, decision_type: str = "ALLOW", method: str = "process") -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-1",
        goal="Process an authorized account request",
        proposed_method=method,
        decision_type=decision_type,
        authority_basis="role:operator",
        matched_constraints=("baseline-policy-rule",),
        policy_version="policy-v1",
        execution_boundary=_boundary(method),
    )


def test_sign_and_verify_roundtrip() -> None:
    signer = Ed25519ReceiptSigner.from_seed(_SEED_A)
    signed = sign_receipt(_receipt(), signer)

    assert isinstance(signed, SignedReceipt)
    assert signed.algorithm == "ed25519"
    assert signed.public_key == signer.public_key_hex()
    assert signed.key_id == signer.key_id
    assert signed.verify_integrity() is True
    assert signed.verify(signer.public_key_hex()) is True


def test_deterministic_seed_is_reproducible() -> None:
    receipt = _receipt()
    a1 = sign_receipt(receipt, Ed25519ReceiptSigner.from_seed(_SEED_A))
    a2 = sign_receipt(receipt, Ed25519ReceiptSigner.from_seed(_SEED_A))

    assert a1.public_key == a2.public_key
    assert a1.signature == a2.signature


def test_from_dict_rejects_non_string_authorization_json() -> None:
    signer = Ed25519ReceiptSigner.from_seed(_SEED_A)
    signed = sign_receipt(_receipt(), signer)
    payload = signed.to_dict()
    payload["authorization_json"] = {"not": "a string"}
    with pytest.raises(ValueError, match="malformed"):
        SignedReceipt.from_dict(payload)


def test_tampered_receipt_payload_fails_verification() -> None:
    signed = sign_receipt(_receipt(), Ed25519ReceiptSigner.from_seed(_SEED_A))
    # Forge the decision after signing -- escalate a controlled allow to a bare allow.
    object.__setattr__(signed.receipt, "decision_type", "TRANSFORM_REQUIRED")

    assert signed.verify(signed.public_key) is False
    assert signed.verify_integrity() is False


def test_tampered_signature_fails_verification() -> None:
    signed = sign_receipt(_receipt(), Ed25519ReceiptSigner.from_seed(_SEED_A))
    flipped = ("0" if signed.signature[0] != "0" else "1") + signed.signature[1:]
    forged = SignedReceipt(
        receipt=signed.receipt,
        algorithm=signed.algorithm,
        key_id=signed.key_id,
        public_key=signed.public_key,
        signature=flipped,
        signed_at=signed.signed_at,
    )

    assert forged.verify(forged.public_key) is False


def test_verification_pinned_to_expected_public_key() -> None:
    signed = sign_receipt(_receipt(), Ed25519ReceiptSigner.from_seed(_SEED_A))
    other_pub = Ed25519ReceiptSigner.from_seed(_SEED_B).public_key_hex()

    assert signed.verify(signed.public_key) is True
    assert signed.verify(other_pub) is False


def test_signature_does_not_verify_under_a_different_key() -> None:
    receipt = _receipt()
    signed_a = sign_receipt(receipt, Ed25519ReceiptSigner.from_seed(_SEED_A))
    forged = SignedReceipt(
        receipt=signed_a.receipt,
        algorithm=signed_a.algorithm,
        key_id="attacker",
        public_key=Ed25519ReceiptSigner.from_seed(_SEED_B).public_key_hex(),
        signature=signed_a.signature,
        signed_at=signed_a.signed_at,
    )

    assert forged.verify(forged.public_key) is False


def test_json_roundtrip_preserves_independent_verification() -> None:
    signed = sign_receipt(_receipt(), Ed25519ReceiptSigner.from_seed(_SEED_A))

    # An independent party receives only JSON + the published public key.
    wire = json.dumps(signed.to_dict())
    restored = SignedReceipt.from_dict(json.loads(wire))

    assert restored == signed
    assert restored.verify(signed.public_key) is True


def test_deny_receipt_with_controls_roundtrips_and_verifies() -> None:
    # Exercise non-empty tuple fields and non-None rationale through the JSON wire,
    # since json.dumps turns tuples into lists and the hash must still revalidate.
    receipt = DecisionReceipt.create(
        request_id="req-9",
        goal="Wire funds to an unverified counterparty",
        proposed_method="wire_transfer",
        decision_type="DENY_GOAL",
        authority_basis="role:operator",
        matched_constraints=("aml-rule-1", "sanctions-rule-2"),
        policy_version="policy-v3",
        required_controls=("dual-approval", "kyc-refresh"),
        denial_or_review_rationale="counterparty failed sanctions screening",
        execution_boundary=ExecutionBoundary(
            allowed_method="wire_transfer",
            allowed_scope="tenant-a",
            allowed_subjects=("subject-1", "subject-2"),
            expires_at=None,
            single_use=True,
        ),
    )
    signed = sign_receipt(receipt, Ed25519ReceiptSigner.from_seed(_SEED_A))

    restored = SignedReceipt.from_dict(json.loads(json.dumps(signed.to_dict())))

    assert restored == signed
    assert restored.receipt.matched_constraints == ("aml-rule-1", "sanctions-rule-2")
    assert restored.receipt.required_controls == ("dual-approval", "kyc-refresh")
    assert restored.verify(signed.public_key) is True


def test_unpinned_self_signed_forgery_is_not_authentic() -> None:
    # An attacker can mint an internally consistent receipt with their OWN key...
    attacker = Ed25519ReceiptSigner.from_seed(_SEED_B)
    forged = sign_receipt(_receipt(decision_type="ALLOW"), attacker)
    membrane_pub = Ed25519ReceiptSigner.from_seed(_SEED_A).public_key_hex()

    # ...verify_integrity (self-consistency) passes -- that is NOT authenticity...
    assert forged.verify_integrity() is True
    # ...but it is not authentic against the membrane's trusted key.
    assert forged.verify(membrane_pub) is False


def test_key_id_confusion_does_not_grant_authenticity() -> None:
    # Attacker forges a receipt but stamps a victim's key_id on it.
    attacker = Ed25519ReceiptSigner.from_seed(_SEED_B, key_id="trusted-membrane")
    forged = sign_receipt(_receipt(), attacker)
    membrane_pub = Ed25519ReceiptSigner.from_seed(_SEED_A).public_key_hex()

    assert forged.key_id == "trusted-membrane"
    # Pinning on the trusted PUBLIC KEY (not key_id) defeats the confusion.
    assert forged.verify(membrane_pub) is False


def test_from_dict_rejects_malformed_payload() -> None:
    with pytest.raises(ValueError):
        SignedReceipt.from_dict({"algorithm": "ed25519"})


def test_refuse_to_sign_hash_mismatched_receipt() -> None:
    receipt = _receipt()
    # Corrupt the receipt so its hash no longer matches its payload.
    object.__setattr__(receipt, "goal", "Exfiltrate the account ledger")

    with pytest.raises(ValueError):
        sign_receipt(receipt, Ed25519ReceiptSigner.from_seed(_SEED_A))
