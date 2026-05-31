"""Independent replay verification of signed decision receipts.

This is the capability Microsoft's agent-governance-toolkit audit spec explicitly
disclaims ("not designed as a deterministic replay system for re-deriving
governance decisions"): given a signed receipt and the deterministic policy
evaluator, re-derive the verdict from the receipt's recorded inputs and confirm it
reproduces -- on top of verifying the receipt's hash and asymmetric signature.
"""

from __future__ import annotations

import json

from acgs_lite.legitimacy import (
    DecisionReceipt,
    Ed25519ReceiptSigner,
    ExecutionBoundary,
    ReplayInputs,
    ReplayVerification,
    SignedReceipt,
    replay_and_verify,
    sign_receipt,
)

_SEED = bytes(range(32))
_PUB = Ed25519ReceiptSigner.from_seed(_SEED).public_key_hex()


def _signed(*, decision_type: str = "ALLOW") -> SignedReceipt:
    receipt = DecisionReceipt.create(
        request_id="req-1",
        goal="Process an authorized account request",
        proposed_method="process",
        decision_type=decision_type,
        authority_basis="role:operator",
        matched_constraints=("baseline-policy-rule",),
        policy_version="policy-v1",
        execution_boundary=ExecutionBoundary(
            allowed_method="process",
            allowed_scope="tenant-a",
            allowed_subjects=("subject-1",),
            expires_at=None,
            single_use=True,
        ),
    )
    return sign_receipt(receipt, Ed25519ReceiptSigner.from_seed(_SEED))


def _faithful_evaluator(decision: str):
    """A policy that re-derives the same verdict the receipt recorded."""

    def evaluate(inputs: ReplayInputs) -> str:
        assert inputs.policy_version == "policy-v1"
        assert "baseline-policy-rule" in inputs.matched_constraints
        return decision

    return evaluate


def test_faithful_replay_reproduces_verdict() -> None:
    signed = _signed(decision_type="ALLOW")

    result = replay_and_verify(signed, _faithful_evaluator("ALLOW"), expected_public_key=_PUB)

    assert isinstance(result, ReplayVerification)
    assert result.ok is True
    assert result.hash_valid is True
    assert result.signature_valid is True
    assert result.verdict_reproduced is True
    assert result.recorded_decision == "ALLOW"
    assert result.rederived_decision == "ALLOW"
    assert result.mismatches == ()


def test_replay_accepts_legacy_decision_aliases() -> None:
    signed = _signed(decision_type="DENY_GOAL")

    # Evaluator returns a legacy alias that canonicalizes to the recorded state.
    result = replay_and_verify(signed, lambda _inputs: "deny", expected_public_key=_PUB)

    assert result.verdict_reproduced is True
    assert result.rederived_decision == "DENY_GOAL"


def test_replay_detects_decision_divergence() -> None:
    signed = _signed(decision_type="ALLOW")

    # A drifted policy would now block what the receipt recorded as allowed.
    result = replay_and_verify(signed, _faithful_evaluator("HARD_DENY"), expected_public_key=_PUB)

    assert result.ok is False
    assert result.verdict_reproduced is False
    assert result.rederived_decision == "HARD_DENY"
    assert any("decision_mismatch" in m for m in result.mismatches)


def test_replay_fails_on_invalid_signature() -> None:
    signed = _signed()
    forged = SignedReceipt(
        receipt=signed.receipt,
        algorithm=signed.algorithm,
        key_id=signed.key_id,
        public_key=signed.public_key,
        signature="00" * 64,
        signed_at=signed.signed_at,
    )

    result = replay_and_verify(forged, _faithful_evaluator("ALLOW"), expected_public_key=_PUB)

    assert result.ok is False
    assert result.signature_valid is False
    # A receipt that fails authenticity is not re-derived at all.
    assert result.verdict_reproduced is False
    assert "signature_invalid" in result.mismatches


def test_replay_fails_on_tampered_hash() -> None:
    signed = _signed(decision_type="ALLOW")
    object.__setattr__(signed.receipt, "decision_type", "TRANSFORM_REQUIRED")

    result = replay_and_verify(
        signed, _faithful_evaluator("TRANSFORM_REQUIRED"), expected_public_key=_PUB
    )

    assert result.ok is False
    assert result.hash_valid is False
    assert "receipt_hash_invalid" in result.mismatches


def test_replay_surfaces_evaluator_errors() -> None:
    signed = _signed()

    def broken(_inputs: ReplayInputs) -> str:
        raise RuntimeError("policy bundle unavailable")

    result = replay_and_verify(signed, broken, expected_public_key=_PUB)

    assert result.ok is False
    assert result.verdict_reproduced is False
    assert any("evaluator_error" in m for m in result.mismatches)


def test_replay_treats_unknown_evaluator_state_as_failure() -> None:
    signed = _signed(decision_type="ALLOW")

    # An evaluator returning a state outside the canonical taxonomy must fail the
    # replay (via canonicalize raising) rather than crash or silently pass.
    result = replay_and_verify(signed, lambda _inputs: "MAYBE_ALLOW", expected_public_key=_PUB)

    assert result.ok is False
    assert result.rederived_decision is None
    assert any("evaluator_error" in m for m in result.mismatches)


def test_replay_through_json_wire_reproduces_verdict() -> None:
    signed = _signed(decision_type="DENY_GOAL")

    # The real verifier deserializes from the wire before replaying.
    restored = SignedReceipt.from_dict(json.loads(json.dumps(signed.to_dict())))
    result = replay_and_verify(restored, lambda _inputs: "DENY_GOAL", expected_public_key=_PUB)

    assert result.ok is True
    assert result.verdict_reproduced is True


def test_replay_pins_expected_public_key() -> None:
    signed = _signed()
    wrong_pub = Ed25519ReceiptSigner.from_seed(bytes(range(32, 64))).public_key_hex()

    result = replay_and_verify(signed, _faithful_evaluator("ALLOW"), expected_public_key=wrong_pub)

    assert result.ok is False
    assert result.signature_valid is False
