"""Versioned evidence references, never execution authority or proof of authenticity.

These adapters leave all existing hashes, signature payloads and serializers intact.
Envelope identities include key_id and signed_at, which existing signatures do not
authenticate. Local grant references are meaningful only within their issuer's
process-local lifetime; they neither carry nor replace the capability MAC.
"""

from __future__ import annotations

import hashlib
import json
import re

from acgs_lite.legitimacy.authorization import ExecutionGrant
from acgs_lite.legitimacy.invocation import PolicyBinding
from acgs_lite.legitimacy.receipt import DecisionReceipt
from acgs_lite.legitimacy.signing import (
    SIGNATURE_ALGORITHM,
    SIGNATURE_SCOPE_EXECUTION,
    SIGNATURE_SCOPE_RECEIPT,
    SignedReceipt,
)

_ENVELOPE_DOMAIN = b"acgs-signed-envelope-identity-v1\x00"


def _hex(value: str, length: int, name: str) -> None:
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
        raise ValueError(f"{name} must be {length} lowercase hexadecimal characters")


def policy_identity(binding: PolicyBinding) -> str:
    """Identify the full policy digest, independent of its receipt display label."""
    if not isinstance(binding, PolicyBinding):
        raise TypeError("binding must be a PolicyBinding")
    if binding.algorithm != "sha256":
        raise ValueError("unsupported policy digest algorithm")
    _hex(binding.digest, 64, "policy digest")
    return f"acgs:policy:v1:sha256:{binding.digest}"


def receipt_identity(receipt: DecisionReceipt) -> str:
    """Reference an existing receipt commitment without authenticating its issuer."""
    if not isinstance(receipt, DecisionReceipt):
        raise TypeError("receipt must be a DecisionReceipt")
    _hex(receipt.receipt_hash, 64, "receipt hash")
    if not receipt.verify_hash():
        raise ValueError("receipt hash does not match its payload")
    return f"acgs:receipt:v1:sha256:{receipt.receipt_hash}"


def signed_envelope_identity(envelope: SignedReceipt) -> str:
    """Identify serialized evidence, including unauthenticated envelope metadata.

    Canonical JSON sorts object keys using compact separators and ASCII escapes.
    authorization_json remains an opaque string: its signed bytes are never parsed
    or normalized. Legacy omitted fields follow SignedReceipt.to_dict() exactly.
    This performs shape validation, not signature or trusted-key verification.
    """
    if not isinstance(envelope, SignedReceipt):
        raise TypeError("envelope must be a SignedReceipt")
    receipt_identity(envelope.receipt)
    if envelope.algorithm != SIGNATURE_ALGORITHM:
        raise ValueError("unsupported signature algorithm")
    if envelope.signature_scope not in (SIGNATURE_SCOPE_RECEIPT, SIGNATURE_SCOPE_EXECUTION):
        raise ValueError("unsupported signature scope")
    if envelope.authorization_json is not None and not isinstance(envelope.authorization_json, str):
        raise ValueError("authorization_json must be a string")
    if envelope.signature_scope == SIGNATURE_SCOPE_EXECUTION and not envelope.authorization_json:
        raise ValueError("execution scope requires authorization_json")
    _hex(envelope.public_key, 64, "public key")
    _hex(envelope.signature, 128, "signature")
    for name in ("key_id", "signed_at"):
        value = getattr(envelope, name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
    canonical = json.dumps(
        envelope.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    digest = hashlib.sha256(_ENVELOPE_DOMAIN + canonical.encode("utf-8")).hexdigest()
    return f"acgs:signed-envelope:v1:sha256:{digest}"


def local_grant_identity(grant: ExecutionGrant) -> str:
    """Return an issuer-qualified process-local reference, never a capability."""
    if not isinstance(grant, ExecutionGrant):
        raise TypeError("grant must be an ExecutionGrant")
    for name in ("issuer_id", "grant_id"):
        value = getattr(grant, name)
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
            raise ValueError(f"{name} must be a non-empty ASCII identifier")
    return f"acgs:local-grant:v1:{grant.issuer_id}:{grant.grant_id}"


__all__ = [
    "local_grant_identity",
    "policy_identity",
    "receipt_identity",
    "signed_envelope_identity",
]
