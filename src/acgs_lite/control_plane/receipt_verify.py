"""Independent verification of control-plane receipts.

A verifier needs only the issuer's public key(s) and an
:class:`~acgs_lite.control_plane.evidence.ExternalRunVerifier`; it never needs
(and this module never imports) the PDP, the ledger or the dispatcher.

Rejection rules (Darwin Goedel Machine: fabricated "tests passed" logs were
caught only by the lineage archive, so agent-written logs never count):

* unknown key id, key mismatch, bad signature, receipt_hash mismatch or a
  malformed receipt;
* for allowed and PROMOTION receipts, any cited non-agent run that the run
  verifier cannot independently validate (one bad ref rejects the receipt);
* for PROMOTION receipts and allowed success claims (``claims_success`` or
  an action matching ``EvidencePolicy.success_claim_prefixes``), fewer than
  ``min_external_runs`` validated external runs; a receipt whose only
  evidence is AGENT_LOG refs is rejected with "only agent-written logs".

* PROMOTION receipts are re-checked independently of the issuer: decision
  allowed, requester ``principal_kind == "human"``, approvers distinct by
  canonical id and excluding the requester, a ``candidate_digest`` that every
  external evidence ref carries as its ``artifact_digest`` (no run reuse
  across candidates);
* success-claim refs must be bound to an artifact (digest or head sha);
* a chain must carry exactly one ``ledger_id``.

A deny grants nothing, so runs cited on a deny are context and are not
re-validated (unless ``require_external_evidence=True``).
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from acgs_lite.control_plane.evidence import (
    DEFAULT_EVIDENCE_POLICY,
    EvidencePolicy,
    ExternalRunVerifier,
    evaluate_evidence,
)
from acgs_lite.control_plane.principal import canonical_principal_id
from acgs_lite.control_plane.receipts import (
    GENESIS_RECEIPT_HASH,
    ORIGIN_PDP,
    ORIGIN_PROMOTION_GATE,
    ControlPlaneReceipt,
    ReceiptKind,
    SignedControlPlaneReceipt,
    promotion_evidence_keys,
)
from acgs_lite.legitimacy.signing import ReceiptSigningUnavailable, verify_signature

__all__ = ["ReceiptVerification", "verify_chain", "verify_receipt"]


@dataclass(frozen=True)
class ReceiptVerification:
    """``attributed`` is True only for a valid receipt whose origin is the PDP
    or promotion gate *and* that names a validated principal kind; the
    ``principal_id`` of any other receipt (e.g. a dispatcher pre-denial) is an
    unverified label, not an attribution."""

    valid: bool
    reasons: tuple[str, ...]
    attributed: bool = False


def verify_receipt(
    signed: object,
    *,
    trusted_public_keys: Mapping[str, str],
    run_verifier: ExternalRunVerifier,
    require_external_evidence: bool | None = None,
    evidence_policy: EvidencePolicy = DEFAULT_EVIDENCE_POLICY,
) -> ReceiptVerification:
    """Verify one signed receipt. Never raises; any doubt is a rejection."""
    if not isinstance(signed, SignedControlPlaneReceipt):
        return ReceiptVerification(False, ("malformed receipt: not a SignedControlPlaneReceipt",))
    reasons: list[str] = []
    receipt = signed.receipt
    trusted = trusted_public_keys.get(signed.key_id)
    if not isinstance(trusted, str):
        reasons.append(f"unknown signing key id {signed.key_id!r}")
    elif not hmac.compare_digest(trusted.lower(), signed.public_key_hex):
        reasons.append("receipt public key does not match the trusted key")
    else:
        try:
            if not verify_signature(
                signed.algorithm, trusted, signed.signing_message(), signed.signature
            ):
                reasons.append("bad signature")
        except ReceiptSigningUnavailable:
            reasons.append("signature verification unavailable (crypto extra missing)")
        except ValueError as exc:
            reasons.append(f"signature algorithm rejected: {exc}")
    if not receipt.verify_hash():
        reasons.append("receipt_hash mismatch")

    promotion = receipt.kind is ReceiptKind.PROMOTION
    if promotion:
        reasons.extend(_promotion_problems(receipt))
    if receipt.allowed or promotion or require_external_evidence is True:
        if require_external_evidence is None:
            required = (
                promotion
                or receipt.claims_success
                or evidence_policy.is_success_claim(receipt.action)
            )
        else:
            required = require_external_evidence
        reasons.extend(
            evaluate_evidence(
                receipt.external_runs,
                run_verifier,
                evidence_policy,
                required=required,
                bind_digest=receipt.candidate_digest if promotion else None,
            )
        )
    attributed = (
        not reasons
        and receipt.principal_kind is not None
        and receipt.origin in (ORIGIN_PDP, ORIGIN_PROMOTION_GATE)
    )
    return ReceiptVerification(not reasons, tuple(reasons), attributed)


def _promotion_problems(receipt: ControlPlaneReceipt) -> list[str]:
    problems: list[str] = []
    if receipt.allowed is not True:
        problems.append("promotion receipt must record an allowed decision")
    if receipt.principal_kind != "human":
        problems.append("promotion requester must be a human principal")
    if receipt.candidate_digest is None:
        problems.append("promotion receipt has no candidate_digest")
    requester = canonical_principal_id(receipt.principal_id)
    ids = [canonical_principal_id(a.principal_id) for a in receipt.approvers]
    if len(set(ids)) != len(ids):
        problems.append("promotion approvers are not distinct")
    if requester in ids:
        problems.append("promotion requester is among its own approvers")
    return problems


def verify_chain(
    receipts: Sequence[SignedControlPlaneReceipt],
    *,
    trusted_public_keys: Mapping[str, str],
    run_verifier: ExternalRunVerifier,
    expected_head_hash: str | None = None,
    expected_ledger_id: str | None = None,
    require_external_evidence: bool | None = None,
    evidence_policy: EvidencePolicy = DEFAULT_EVIDENCE_POLICY,
) -> ReceiptVerification:
    """Verify sequence contiguity from genesis, prev-hash linkage and each receipt.

    Truncation of the tail is only detectable with ``expected_head_hash``
    (obtain it out of band, e.g. from a published checkpoint).
    """
    # TODO(control-plane-gap): tail truncation needs an externally anchored
    # head (checkpoint publication); this phase only offers expected_head_hash.
    reasons: list[str] = []
    prev = GENESIS_RECEIPT_HASH
    ledger_ids: set[str] = set()
    certified: dict[tuple[str, str, str], str] = {}
    for index, signed in enumerate(receipts):
        if not isinstance(signed, SignedControlPlaneReceipt):
            reasons.append(f"receipt[{index}]: malformed")
            continue
        receipt = signed.receipt
        ledger_ids.add(receipt.ledger_id)
        for key in promotion_evidence_keys(receipt):
            prior = certified.setdefault(key, receipt.resource)
            if prior != receipt.resource:
                reasons.append(
                    f"receipt[{index}]: run {key[0]}/{key[1]} already certified {prior!r}"
                )
        if receipt.sequence != index:
            reasons.append(f"receipt[{index}]: sequence {receipt.sequence} != {index}")
        if receipt.prev_receipt_hash != prev:
            reasons.append(f"receipt[{index}]: prev_receipt_hash does not link")
        result = verify_receipt(
            signed,
            trusted_public_keys=trusted_public_keys,
            run_verifier=run_verifier,
            require_external_evidence=require_external_evidence,
            evidence_policy=evidence_policy,
        )
        reasons.extend(f"receipt[{index}]: {reason}" for reason in result.reasons)
        prev = receipt.receipt_hash
    if len(ledger_ids) > 1:
        reasons.append(f"chain mixes ledger ids {sorted(ledger_ids)}")
    if expected_ledger_id is not None and ledger_ids - {expected_ledger_id}:
        reasons.append("chain ledger_id does not match expected_ledger_id")
    if expected_head_hash is not None and prev != expected_head_hash:
        reasons.append("chain head does not match expected_head_hash")
    return ReceiptVerification(not reasons, tuple(reasons))
