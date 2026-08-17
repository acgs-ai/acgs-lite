"""Asymmetric, independently verifiable signatures over decision receipts.

Constitutional Hash: 608508a9bd224290

A :class:`~acgs_lite.legitimacy.receipt.DecisionReceipt` already commits to its
full pre-execution payload through a SHA-256 ``receipt_hash``. A hash proves the
payload was not altered, but anyone who can recompute the hash can also forge a
fresh one -- so a hash alone (or a hash chain) does not prove *who* issued the
decision. This module binds the receipt's commitment to an Ed25519 signature so
an independent party -- holding only the signer's public key -- can verify the
receipt was issued by the governing membrane and was not tampered with, without
trusting the operator and without sharing a secret.

Signing is optional and backed by the ``crypto`` extra (``cryptography``). The
dependency is imported lazily inside the call paths that need it, never at module
import time, so importing this module stays cheap and side-effect free. When the
extra is unavailable, signing and verification raise
:class:`ReceiptSigningUnavailable` rather than silently degrading to a symmetric
scheme that could not honestly back a non-repudiation claim (fail closed).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from acgs_lite.legitimacy.receipt import DecisionReceipt, ExecutionBoundary

# Domain-separation prefix: prevents a receipt signature from ever being replayed
# as a signature over some other acgs-lite message that happens to share bytes.
RECEIPT_SIGNING_DOMAIN = b"acgs-receipt-v1\x00"
EXECUTION_SIGNING_DOMAIN = b"acgs-execution-v1\x00"
SIGNATURE_SCOPE_RECEIPT = "receipt"
SIGNATURE_SCOPE_EXECUTION = "execution"

SIGNATURE_ALGORITHM = "ed25519"


class ReceiptSigningUnavailable(RuntimeError):
    """Raised when Ed25519 signing/verification is requested without ``cryptography``."""


def _require_ed25519() -> Any:
    """Lazily import the Ed25519 primitives or fail closed with a clear message."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ReceiptSigningUnavailable(
            "Ed25519 receipt signing requires the 'crypto' extra: pip install acgs-lite[crypto]"
        ) from exc
    return ed25519


def _signing_message(receipt: DecisionReceipt) -> bytes:
    """The exact bytes signed for a receipt.

    The receipt hash is a collision-resistant commitment to the full canonical
    payload, so signing ``domain || receipt_hash`` binds the signature to every
    field a verifier later re-checks with ``receipt.verify_hash()``.
    """
    return RECEIPT_SIGNING_DOMAIN + receipt.receipt_hash.encode("utf-8")


def _execution_signing_message(receipt: DecisionReceipt, authorization_json: str) -> bytes:
    """v2 message: receipt commitment plus the authorization envelope."""
    return (
        EXECUTION_SIGNING_DOMAIN
        + receipt.receipt_hash.encode("utf-8")
        + b"\x00"
        + authorization_json.encode("utf-8")
    )


@runtime_checkable
class ReceiptSigner(Protocol):
    """Anything that can sign a receipt message and publish its public key."""

    algorithm: str
    key_id: str

    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> str: ...


class Ed25519ReceiptSigner:
    """Ed25519 signer for decision receipts.

    Construct with :meth:`generate` for a fresh ephemeral key, :meth:`from_seed`
    for a deterministic key (tests, reproducible fixtures), or :meth:`from_private_bytes`
    to load an existing 32-byte private key.
    """

    algorithm = SIGNATURE_ALGORITHM

    def __init__(self, private_key: Any, *, key_id: str | None = None) -> None:
        ed25519 = _require_ed25519()
        from cryptography.hazmat.primitives import serialization

        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        self._private_key = private_key
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._public_key_hex = public_bytes.hex()
        # Default key id is a stable fingerprint of the public key.
        self.key_id = key_id or hashlib.sha256(public_bytes).hexdigest()[:16]

    @classmethod
    def generate(cls, *, key_id: str | None = None) -> Ed25519ReceiptSigner:
        ed25519 = _require_ed25519()
        return cls(ed25519.Ed25519PrivateKey.generate(), key_id=key_id)

    @classmethod
    def from_seed(cls, seed: bytes, *, key_id: str | None = None) -> Ed25519ReceiptSigner:
        """Deterministic keypair from exactly 32 seed bytes (RFC 8032)."""
        ed25519 = _require_ed25519()
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes")
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(seed), key_id=key_id)

    @classmethod
    def from_private_bytes(cls, raw: bytes, *, key_id: str | None = None) -> Ed25519ReceiptSigner:
        ed25519 = _require_ed25519()
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(raw), key_id=key_id)

    def public_key_hex(self) -> str:
        return self._public_key_hex

    def sign(self, message: bytes) -> str:
        return self._private_key.sign(message).hex()

    def sign_receipt(self, receipt: DecisionReceipt) -> SignedReceipt:
        return sign_receipt(receipt, self)


def verify_signature(
    algorithm: str,
    public_key_hex: str,
    message: bytes,
    signature_hex: str,
) -> bool:
    """Verify a detached signature over ``message`` under a public key.

    Returns ``False`` for any verification failure (bad signature, malformed key
    or signature hex). Raises :class:`ReceiptSigningUnavailable` only when the
    algorithm is supported in principle but ``cryptography`` is not installed, and
    :class:`ValueError` for an unknown algorithm.
    """
    if algorithm != SIGNATURE_ALGORITHM:
        raise ValueError(f"Unsupported receipt signature algorithm: {algorithm!r}")
    ed25519 = _require_ed25519()
    from cryptography.exceptions import InvalidSignature

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), message)
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(slots=True, frozen=True)
class SignedReceipt:
    """A decision receipt bound to an asymmetric signature over its commitment."""

    receipt: DecisionReceipt
    algorithm: str
    key_id: str
    public_key: str
    signature: str
    signed_at: str
    signature_scope: str = SIGNATURE_SCOPE_RECEIPT
    authorization_json: str | None = None

    def verify(self, expected_public_key: str) -> bool:
        """Verify authenticity against a public key the caller already trusts.

        Authenticity REQUIRES a trust anchor: a valid signature alone only proves
        *someone* signed the receipt, not that the governing membrane did. Pass the
        membrane's known public key (from a key store or out-of-band distribution).
        Verification fails closed unless that key matches the receipt's signing key
        AND the hash and signature both check out. For the unpinned self-consistency
        check use :meth:`verify_integrity` -- but never treat it as authenticity.
        """
        if not hmac.compare_digest(expected_public_key, self.public_key):
            return False
        return self.verify_integrity()

    def verify_integrity(self) -> bool:
        """True iff the payload, hash, and signature are internally consistent.

        This proves the receipt is well-formed and was signed by whoever holds
        ``self.public_key`` -- it does NOT prove that key belongs to the membrane.
        It is necessary but not sufficient for authenticity; pair it with a
        trusted-key comparison (see :meth:`verify`) before trusting a decision.
        """
        if not self.receipt.verify_hash():
            return False
        try:
            return verify_signature(
                self.algorithm,
                self.public_key,
                self._signed_message(),
                self.signature,
            )
        except (ReceiptSigningUnavailable, ValueError):
            return False

    def _signed_message(self) -> bytes:
        if self.signature_scope == SIGNATURE_SCOPE_EXECUTION:
            if not self.authorization_json:
                raise ValueError("execution-scope signature requires authorization_json")
            return _execution_signing_message(self.receipt, self.authorization_json)
        return _signing_message(self.receipt)

    def to_dict(self) -> dict[str, Any]:
        """Project to a JSON-compatible dict for transport to an independent verifier."""
        payload: dict[str, Any] = {
            "receipt": self.receipt.to_receipt_dict(),
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "signature": self.signature,
            "signed_at": self.signed_at,
        }
        if self.signature_scope != SIGNATURE_SCOPE_RECEIPT or self.authorization_json:
            payload["signature_scope"] = self.signature_scope
            payload["authorization_json"] = self.authorization_json
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SignedReceipt:
        # from_dict is the untrusted-wire entry point; a malformed payload must fail
        # closed with a domain error, not leak a bare KeyError to the caller.
        try:
            return cls(
                receipt=_receipt_from_dict(data["receipt"]),
                algorithm=data["algorithm"],
                key_id=data["key_id"],
                public_key=data["public_key"],
                signature=data["signature"],
                signed_at=data["signed_at"],
                signature_scope=str(data.get("signature_scope") or SIGNATURE_SCOPE_RECEIPT),
                authorization_json=data.get("authorization_json"),
            )
        except (KeyError, TypeError) as exc:
            raise ValueError(f"malformed signed-receipt payload: {exc}") from exc


def sign_receipt(
    receipt: DecisionReceipt,
    signer: ReceiptSigner,
    *,
    signed_at: str | None = None,
) -> SignedReceipt:
    """Sign a receipt, refusing to attest to one whose hash already disagrees with its payload."""
    if not receipt.verify_hash():
        raise ValueError("refusing to sign a receipt whose hash does not match its payload")
    return SignedReceipt(
        receipt=receipt,
        algorithm=signer.algorithm,
        key_id=signer.key_id,
        public_key=signer.public_key_hex(),
        signature=signer.sign(_signing_message(receipt)),
        signed_at=signed_at or datetime.now(timezone.utc).isoformat(),
        signature_scope=SIGNATURE_SCOPE_RECEIPT,
        authorization_json=None,
    )


def sign_execution_authorization(
    receipt: DecisionReceipt,
    signer: ReceiptSigner,
    *,
    authorization_json: str,
    signed_at: str | None = None,
) -> SignedReceipt:
    """Sign receipt hash plus the canonical authorization envelope (v2 execution scope)."""
    if not receipt.verify_hash():
        raise ValueError("refusing to sign a receipt whose hash does not match its payload")
    if not authorization_json:
        raise ValueError("execution authorization JSON is required")
    return SignedReceipt(
        receipt=receipt,
        algorithm=signer.algorithm,
        key_id=signer.key_id,
        public_key=signer.public_key_hex(),
        signature=signer.sign(_execution_signing_message(receipt, authorization_json)),
        signed_at=signed_at or datetime.now(timezone.utc).isoformat(),
        signature_scope=SIGNATURE_SCOPE_EXECUTION,
        authorization_json=authorization_json,
    )


def _receipt_from_dict(data: Mapping[str, Any]) -> DecisionReceipt:
    """Reconstruct a frozen DecisionReceipt from its canonical dict projection.

    The receipt's ``__post_init__`` re-validates the hash against the payload, so a
    round-tripped receipt that fails reconstruction is itself evidence of tampering.
    """
    boundary_data = data["execution_boundary"]
    boundary = ExecutionBoundary(
        allowed_method=boundary_data["allowed_method"],
        allowed_scope=boundary_data["allowed_scope"],
        allowed_subjects=tuple(boundary_data["allowed_subjects"]),
        expires_at=boundary_data["expires_at"],
        single_use=boundary_data["single_use"],
    )
    return DecisionReceipt(
        request_id=data["request_id"],
        goal=data["goal"],
        proposed_method=data["proposed_method"],
        decision_type=data["decision_type"],
        authority_basis=data["authority_basis"],
        matched_constraints=tuple(data["matched_constraints"]),
        policy_version=data["policy_version"],
        required_controls=tuple(data["required_controls"]),
        transformation_applied=data["transformation_applied"],
        denial_or_review_rationale=data["denial_or_review_rationale"],
        execution_boundary=boundary,
        issued_at=data["issued_at"],
        receipt_hash=data["receipt_hash"],
    )


__all__ = [
    "Ed25519ReceiptSigner",
    "EXECUTION_SIGNING_DOMAIN",
    "RECEIPT_SIGNING_DOMAIN",
    "ReceiptSigner",
    "ReceiptSigningUnavailable",
    "SIGNATURE_ALGORITHM",
    "SIGNATURE_SCOPE_EXECUTION",
    "SIGNATURE_SCOPE_RECEIPT",
    "SignedReceipt",
    "sign_execution_authorization",
    "sign_receipt",
    "verify_signature",
]
