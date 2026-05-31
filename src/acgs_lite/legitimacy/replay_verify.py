"""Deterministic replay verification for signed decision receipts.

Constitutional Hash: 608508a9bd224290

Tamper-evident audit answers "was this record altered?". Replay verification
answers the harder question "would this decision reproduce?" -- it re-derives the
verdict from the receipt's recorded inputs using a deterministic policy evaluator
and confirms it matches what the receipt claims, after first verifying the
receipt's hash and asymmetric signature.

This is the differentiator the surrounding governance field does not provide:
hash-chained audit logs prove integrity but, by their own specifications, are
"not designed as a deterministic replay system for re-deriving governance
decisions". Here, an independent party holding the signer's public key and the
cited policy version can prove a recorded ALLOW/DENY/TRANSFORM verdict was
actually correct -- not merely unaltered.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from acgs_lite.legitimacy.decide import DecisionState, canonicalize_decision_state
from acgs_lite.legitimacy.signing import SignedReceipt


@dataclass(slots=True, frozen=True)
class ReplayInputs:
    """The recorded decision inputs handed to an evaluator during replay.

    These are exactly the fields the receipt commits to, so an evaluator can only
    re-derive from what was actually attested -- it cannot reach for fresh state.
    """

    request_id: str
    goal: str
    proposed_method: str
    policy_version: str
    authority_basis: str
    matched_constraints: tuple[str, ...]


# An evaluator re-derives a decision state from the receipt's recorded inputs.
# It returns any value ``canonicalize_decision_state`` accepts (canonical or legacy).
DecisionEvaluator = Callable[[ReplayInputs], object]


@dataclass(slots=True, frozen=True)
class ReplayVerification:
    """Structured outcome of replaying and verifying one signed receipt."""

    hash_valid: bool
    signature_valid: bool
    verdict_reproduced: bool
    recorded_decision: DecisionState
    rederived_decision: DecisionState | None
    mismatches: tuple[str, ...]

    @property
    def ok(self) -> bool:
        """True only when authenticity, integrity, and verdict all hold."""
        return self.hash_valid and self.signature_valid and self.verdict_reproduced


def replay_and_verify(
    signed: SignedReceipt,
    evaluator: DecisionEvaluator,
    *,
    expected_public_key: str,
) -> ReplayVerification:
    """Verify a signed receipt's authenticity, then re-derive and confirm its verdict.

    ``expected_public_key`` is required and must be the membrane's trusted public
    key: authenticity cannot be established against the receipt's own embedded key
    alone. The verdict is only re-derived once the receipt is proven authentic and
    intact; an inauthentic receipt is not trusted enough to feed an evaluator.
    """
    receipt = signed.receipt
    hash_valid = receipt.verify_hash()
    signature_valid = signed.verify(expected_public_key)

    mismatches: list[str] = []
    rederived: DecisionState | None = None
    verdict_reproduced = False

    if hash_valid and signature_valid:
        inputs = ReplayInputs(
            request_id=receipt.request_id,
            goal=receipt.goal,
            proposed_method=receipt.proposed_method,
            policy_version=receipt.policy_version,
            authority_basis=receipt.authority_basis,
            matched_constraints=receipt.matched_constraints,
        )
        try:
            rederived = canonicalize_decision_state(evaluator(inputs))
        except Exception as exc:  # noqa: BLE001 - any evaluator failure is a replay failure
            mismatches.append(f"evaluator_error: {type(exc).__name__}: {exc}")
        else:
            verdict_reproduced = rederived == receipt.decision_type
            if not verdict_reproduced:
                mismatches.append(
                    f"decision_mismatch: recorded={receipt.decision_type} rederived={rederived}"
                )
    else:
        if not hash_valid:
            mismatches.append("receipt_hash_invalid")
        if not signature_valid:
            mismatches.append("signature_invalid")

    return ReplayVerification(
        hash_valid=hash_valid,
        signature_valid=signature_valid,
        verdict_reproduced=verdict_reproduced,
        recorded_decision=receipt.decision_type,
        rederived_decision=rederived,
        mismatches=tuple(mismatches),
    )


__all__ = [
    "DecisionEvaluator",
    "ReplayInputs",
    "ReplayVerification",
    "replay_and_verify",
]
