"""Evidence identities are distinct from authority and display labels."""

import hashlib
import json
from dataclasses import replace

import pytest

from acgs_lite.legitimacy import (
    DecisionReceipt,
    Ed25519ReceiptSigner,
    ExecutionAuthority,
    ExecutionBoundary,
    InvocationBinding,
    PolicyBinding,
    SignedReceipt,
    sign_execution_authorization,
    sign_receipt,
)
from acgs_lite.legitimacy.identity import (
    local_grant_identity,
    policy_identity,
    receipt_identity,
    signed_envelope_identity,
)


@pytest.fixture
def receipt():
    return DecisionReceipt.create(
        request_id="req-1", goal="Read", proposed_method="read", decision_type="ALLOW",
        authority_basis="role:reader", matched_constraints=("rule-1",), policy_version="v1",
        execution_boundary=ExecutionBoundary("read", None, (), None, True),
    )


@pytest.fixture
def signed(receipt):
    pytest.importorskip("cryptography")
    return sign_receipt(receipt, Ed25519ReceiptSigner.from_seed(bytes(range(32))), signed_at="now")


def test_policy_identity_uses_full_digest_not_label():
    binding = PolicyBinding("v1", "sha256", "a" * 64)
    assert policy_identity(binding) == "acgs:policy:v1:sha256:" + "a" * 64
    assert policy_identity(binding) == policy_identity(replace(binding, version="v2"))
    assert policy_identity(binding) != policy_identity(replace(binding, digest="b" * 64))


def test_real_policy_projection_with_same_label_has_distinct_identity():
    from acgs_lite.legitimacy import bind_policy

    class Policy:
        hash = "same-label"

        def __init__(self, rule):
            self.rule = rule

        def to_dict(self):
            return {"rule": self.rule}

    left, right = bind_policy(Policy("allow")), bind_policy(Policy("deny"))
    assert left.version == right.version
    assert policy_identity(left) != policy_identity(right)


def test_namespaces_and_existing_hash_are_preserved(receipt, signed):
    before = receipt.to_receipt_dict()
    rid = receipt_identity(receipt)
    assert rid == "acgs:receipt:v1:sha256:" + receipt.receipt_hash
    assert rid != policy_identity(PolicyBinding("v1", "sha256", receipt.receipt_hash))
    assert signed_envelope_identity(signed).startswith("acgs:signed-envelope:v1:sha256:")
    assert receipt.to_receipt_dict() == before
    assert receipt.verify_hash()


def test_signers_and_unsigned_metadata_distinguish_envelopes(receipt, signed):
    other = sign_receipt(receipt, Ed25519ReceiptSigner.from_seed(bytes(range(32, 64))), signed_at="now")
    assert signed_envelope_identity(other) != signed_envelope_identity(signed)
    for changed in (replace(signed, key_id="other"), replace(signed, signed_at="later")):
        assert changed.verify(signed.public_key)
        assert signed_envelope_identity(changed) != signed_envelope_identity(signed)


def test_legacy_omitted_fields_roundtrip_is_stable(signed):
    before = signed.to_dict()
    assert "signature_scope" not in before and "authorization_json" not in before
    assert signed_envelope_identity(signed) == signed_envelope_identity(SignedReceipt.from_dict(before))
    assert signed.to_dict() == before and signed.verify(signed.public_key)
    expected = hashlib.sha256(
        b"acgs-signed-envelope-identity-v1\x00"
        + json.dumps(before, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("utf-8")
    ).hexdigest()
    assert signed_envelope_identity(signed) == "acgs:signed-envelope:v1:sha256:" + expected


def test_raw_authorization_json_is_not_normalized(receipt):
    pytest.importorskip("cryptography")
    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    left = sign_execution_authorization(receipt, signer, authorization_json='{"a":1}', signed_at="now")
    right = sign_execution_authorization(receipt, signer, authorization_json='{ "a": 1 }', signed_at="now")
    before = right.to_dict()
    assert signed_envelope_identity(left) != signed_envelope_identity(right)
    assert signed_envelope_identity(right) == signed_envelope_identity(SignedReceipt.from_dict(before))
    assert right.to_dict() == before and right.verify(signer.public_key_hex())


def test_local_grant_is_issuer_qualified_evidence(receipt):
    grant = ExecutionAuthority().issue(receipt=receipt,
        invocation=InvocationBinding("read", "a" * 64, None, ()),
        policy=PolicyBinding("v1", "sha256", "b" * 64))
    before = grant.to_evidence_dict()
    identity = local_grant_identity(grant)
    assert identity == f"acgs:local-grant:v1:{grant.issuer_id}:{grant.grant_id}"
    assert identity != local_grant_identity(replace(grant, issuer_id="other"))
    assert identity == local_grant_identity(replace(grant, binding_mac="secret"))
    assert grant.binding_mac not in identity and grant.to_evidence_dict() == before
    for field in ("issuer_id", "grant_id"):
        for value in ("", " ", "bad:id", "bad/id", None):
            with pytest.raises(ValueError):
                local_grant_identity(replace(grant, **{field: value}))


@pytest.mark.parametrize("algorithm,digest", [("md5", "a"*64), ("sha256", "a"*16),
    ("sha256", "g"*64), ("sha256", "A"*64), ("sha256", None)])
def test_invalid_policy_binding_rejected(algorithm, digest):
    with pytest.raises(ValueError):
        policy_identity(PolicyBinding("v1", algorithm, digest))


@pytest.mark.parametrize("fields", [{"algorithm": "rsa"}, {"signature_scope": "unknown"},
    {"signature_scope": "execution", "authorization_json": None}, {"public_key": "bad"},
    {"signature": "bad"}, {"key_id": ""}])
def test_invalid_envelope_rejected(signed, fields):
    with pytest.raises(ValueError):
        signed_envelope_identity(replace(signed, **fields))


def test_invalid_receipt_hash_rejected(receipt):
    object.__setattr__(receipt, "receipt_hash", "short")
    with pytest.raises(ValueError):
        receipt_identity(receipt)


def test_mutated_receipt_payload_rejected(receipt):
    object.__setattr__(receipt, "goal", "forged")
    with pytest.raises(ValueError, match="does not match"):
        receipt_identity(receipt)


@pytest.mark.parametrize("adapter", [
    policy_identity, receipt_identity, signed_envelope_identity, local_grant_identity,
])
def test_wrong_object_type_rejected(adapter):
    with pytest.raises(TypeError):
        adapter(object())
