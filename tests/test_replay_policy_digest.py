"""Replay fails closed when the committed policy digest is absent or differs.

``Constitution.hash`` omits rule patterns, so two constitutions can share a
label while enforcing different rules. Replay must compare ``PolicyBinding.digest``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from acgs_lite.constitution import Constitution  # noqa: E402
from acgs_lite.constitution.rule import Rule  # noqa: E402
from acgs_lite.governed import GovernedCallable  # noqa: E402
from acgs_lite.legitimacy import (  # noqa: E402
    AuthorizationProfile,
    Ed25519ReceiptSigner,
    ReplayInputs,
    replay_and_verify,
    sign_receipt,
)
from acgs_lite.legitimacy.authorization import authorization_envelope_json  # noqa: E402
from acgs_lite.legitimacy.invocation import bind_invocation, bind_policy  # noqa: E402
from acgs_lite.legitimacy.signing import sign_execution_authorization  # noqa: E402

_SIGNER = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
_PUB = _SIGNER.public_key_hex()

C1 = Constitution.from_rules([Rule(id="P", text="pattern rule", patterns=[r"abc\d"])])
C2 = Constitution.from_rules([Rule(id="P", text="pattern rule", patterns=[r"xyz\d"])])


def _target(text: str) -> str:
    return text


def _signed_execution(constitution: Constitution):
    guard = GovernedCallable(constitution, authorization_profile=AuthorizationProfile.PRODUCTION)
    wrapped = guard(_target)
    grant = wrapped.issue_grant("hello")
    invocation = bind_invocation(_target, ("hello",), {}, include_receiver=True)
    envelope = authorization_envelope_json(invocation, bind_policy(constitution))
    return grant.receipt, sign_execution_authorization(
        grant.receipt, _SIGNER, authorization_json=envelope
    )


def _same_decision(inputs: ReplayInputs) -> str:
    return "ALLOW"


def test_same_label_constitutions_have_distinct_policy_digests() -> None:
    assert C1.hash == C2.hash
    assert bind_policy(C1).digest != bind_policy(C2).digest


def test_replay_accepts_matching_policy_digest_and_passes_it_to_evaluator() -> None:
    _receipt, signed = _signed_execution(C1)
    seen: list[ReplayInputs] = []

    def evaluator(inputs: ReplayInputs) -> str:
        seen.append(inputs)
        return "ALLOW"

    result = replay_and_verify(
        signed,
        evaluator,
        expected_public_key=_PUB,
        expected_policy_digest=bind_policy(C1).digest,
    )
    assert result.ok is True
    assert result.policy_digest_valid is True
    assert seen[0].policy_digest == bind_policy(C1).digest
    assert seen[0].required_controls == ()


def test_replay_rejects_same_label_different_constitution() -> None:
    _receipt, signed = _signed_execution(C1)
    result = replay_and_verify(
        signed,
        _same_decision,
        expected_public_key=_PUB,
        expected_policy_digest=bind_policy(C2).digest,
    )
    assert result.ok is False
    assert result.policy_digest_valid is False
    assert any(m.startswith("policy_digest_mismatch") for m in result.mismatches)
    assert result.rederived_decision is None


def test_replay_rejects_receipt_scope_signature_when_digest_expected() -> None:
    receipt, _signed = _signed_execution(C1)
    signed = sign_receipt(receipt, _SIGNER)
    result = replay_and_verify(
        signed,
        _same_decision,
        expected_public_key=_PUB,
        expected_policy_digest=bind_policy(C1).digest,
    )
    assert result.ok is False
    assert "policy_digest_absent" in result.mismatches


def test_replay_rejects_digest_expectation_on_inauthentic_receipt() -> None:
    _receipt, signed = _signed_execution(C1)
    other = Ed25519ReceiptSigner.from_seed(bytes(range(1, 33))).public_key_hex()
    result = replay_and_verify(
        signed,
        _same_decision,
        expected_public_key=other,
        expected_policy_digest=bind_policy(C1).digest,
    )
    assert result.ok is False
    assert result.policy_digest_valid is False


def test_replay_without_digest_expectation_is_unchanged() -> None:
    _receipt, signed = _signed_execution(C1)
    result = replay_and_verify(signed, _same_decision, expected_public_key=_PUB)
    assert result.ok is True
    assert result.policy_digest_valid is True
