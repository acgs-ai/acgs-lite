"""Signed outcome receipts for settled external effects; evidence, not authority.

An outcome receipt records that an effect key reached a terminal provider
outcome (DONE or NOT_DONE) under a pinned provider contract, and links it to the
decision receipt that preceded the effect. UNKNOWN never yields a receipt.
Signing reuses the Ed25519 helpers in :mod:`acgs_lite.legitimacy.signing`, which
import ``cryptography`` lazily; verification needs only the public key.

Out of scope for this slice: ``resolution``, timing evidence and
``settled_amount`` from PRODUCT-SLICE-2026-10-26 §3.2.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from acgs_lite.legitimacy.effects import EffectOutcome, EffectRecord, EffectState
from acgs_lite.legitimacy.provider_contract import ProviderContract
from acgs_lite.legitimacy.signing import (
    ReceiptSigner,
    ReceiptSigningUnavailable,
    verify_signature,
)

OUTCOME_RECEIPT_SCHEMA = "acgs-outcome-receipt-v1"
_OUTCOME_DOMAIN = b"acgs-outcome-receipt-v1\x00"
_DECISION_PREFIXES = ("acgs:receipt:", "acgs:signed-envelope:")
_TERMINAL = (EffectOutcome.DONE, EffectOutcome.NOT_DONE)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "effect_key",
        "provider_id",
        "provider_contract_digest",
        "decision_receipt_identity",
        "outcome",
        "provider_reference",
        "recorded_at",
    }
)
_SIGNED_FIELDS = frozenset({"receipt", "algorithm", "key_id", "public_key", "signature"})


def _nonempty(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


def _utc_timestamp(value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("recorded_at must be a nonempty string")
    # Python 3.10 fromisoformat rejects a trailing "Z"; normalize before parsing.
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("recorded_at must be an ISO 8601 timestamp") from exc
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("recorded_at must be a UTC timestamp")


@dataclass(frozen=True)
class OutcomeReceipt:
    """Immutable terminal outcome of one external effect."""

    effect_key: str
    provider_id: str
    provider_contract_digest: str
    decision_receipt_identity: str
    outcome: EffectOutcome
    recorded_at: str
    provider_reference: str | None = None
    schema_version: str = OUTCOME_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != OUTCOME_RECEIPT_SCHEMA:
            raise ValueError("unsupported outcome receipt schema_version")
        if (
            not isinstance(self.effect_key, str)
            or re.fullmatch(r"acgs:effect:v1:[0-9a-f]{64}", self.effect_key) is None
        ):
            raise ValueError("effect_key must be an acgs:effect:v1 key")
        _nonempty(self.provider_id, "provider_id")
        if (
            not isinstance(self.provider_contract_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.provider_contract_digest) is None
        ):
            raise ValueError("provider_contract_digest must be 64 lowercase hexadecimal characters")
        identity = self.decision_receipt_identity
        if not isinstance(identity, str) or not any(
            identity.startswith(prefix) and len(identity) > len(prefix)
            for prefix in _DECISION_PREFIXES
        ):
            raise ValueError("decision_receipt_identity must reference a decision receipt")
        if not isinstance(self.outcome, EffectOutcome) or self.outcome not in _TERMINAL:
            raise ValueError("an outcome receipt requires a terminal DONE or NOT_DONE outcome")
        if self.provider_reference is not None:
            _nonempty(self.provider_reference, "provider_reference")
        _utc_timestamp(self.recorded_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "effect_key": self.effect_key,
            "provider_id": self.provider_id,
            "provider_contract_digest": self.provider_contract_digest,
            "decision_receipt_identity": self.decision_receipt_identity,
            "outcome": self.outcome.value,
            "provider_reference": self.provider_reference,
            "recorded_at": self.recorded_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> OutcomeReceipt:
        if not isinstance(data, Mapping) or set(data) != _RECEIPT_FIELDS:
            raise ValueError("outcome receipt payload must have exactly the v1 fields")
        try:
            outcome = EffectOutcome(data["outcome"])
        except ValueError as exc:
            raise ValueError("unknown outcome value") from exc
        return cls(
            effect_key=data["effect_key"],
            provider_id=data["provider_id"],
            provider_contract_digest=data["provider_contract_digest"],
            decision_receipt_identity=data["decision_receipt_identity"],
            outcome=outcome,
            recorded_at=data["recorded_at"],
            provider_reference=data["provider_reference"],
            schema_version=data["schema_version"],
        )

    def canonical_bytes(self) -> bytes:
        """Domain prefix plus sorted, compact, UTF-8 (``ensure_ascii=False``) JSON."""
        canonical = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return _OUTCOME_DOMAIN + canonical.encode("utf-8")

    @property
    def outcome_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @property
    def identity(self) -> str:
        return f"acgs:outcome:v1:sha256:{self.outcome_hash}"


@dataclass(frozen=True)
class SignedOutcomeReceipt:
    """An outcome receipt with a detached signature over its canonical bytes."""

    receipt: OutcomeReceipt
    algorithm: str
    key_id: str
    public_key: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, OutcomeReceipt):
            raise TypeError("receipt must be an OutcomeReceipt")
        for name in ("algorithm", "key_id", "public_key", "signature"):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"{name} must be a string")

    def verify(self, expected_public_key: str) -> bool:
        """True only if the pinned key matches and the signature verifies offline.

        Returns False, never raises, for a wrong key, tampered field, malformed
        signature, unsupported algorithm or missing ``cryptography`` extra.
        """
        try:
            if not hmac.compare_digest(expected_public_key, self.public_key):
                return False
            return verify_signature(
                self.algorithm,
                self.public_key,
                self.receipt.canonical_bytes(),
                self.signature,
            )
        except (ReceiptSigningUnavailable, TypeError, ValueError):
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt": self.receipt.to_dict(),
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SignedOutcomeReceipt:
        if not isinstance(data, Mapping) or set(data) != _SIGNED_FIELDS:
            raise ValueError("signed outcome payload must have exactly the v1 fields")
        try:
            return cls(
                receipt=OutcomeReceipt.from_dict(data["receipt"]),
                algorithm=data["algorithm"],
                key_id=data["key_id"],
                public_key=data["public_key"],
                signature=data["signature"],
            )
        except TypeError as exc:
            raise ValueError(f"malformed signed outcome payload: {exc}") from exc


def sign_outcome(receipt: OutcomeReceipt, signer: ReceiptSigner) -> SignedOutcomeReceipt:
    if not isinstance(receipt, OutcomeReceipt):
        raise TypeError("receipt must be an OutcomeReceipt")
    return SignedOutcomeReceipt(
        receipt=receipt,
        algorithm=signer.algorithm,
        key_id=signer.key_id,
        public_key=signer.public_key_hex(),
        signature=signer.sign(receipt.canonical_bytes()),
    )


def outcome_from_record(
    record: EffectRecord,
    *,
    contract: ProviderContract,
    decision_receipt_identity: str,
    provider_reference: str | None = None,
    recorded_at: str | None = None,
) -> OutcomeReceipt:
    """Build an outcome receipt only for a terminal record bound to ``contract``."""
    if not isinstance(record, EffectRecord):
        raise TypeError("record must be an EffectRecord")
    if not isinstance(contract, ProviderContract):
        raise TypeError("contract must be a ProviderContract")
    if record.state not in (EffectState.DONE, EffectState.NOT_DONE):
        raise ValueError("effect is not terminal; no outcome receipt for UNKNOWN or pending")
    if record.request.provider_id != contract.provider_id:
        raise ValueError("effect record is bound to a different provider")
    return OutcomeReceipt(
        effect_key=record.key,
        provider_id=record.request.provider_id,
        provider_contract_digest=contract.digest,
        decision_receipt_identity=decision_receipt_identity,
        outcome=EffectOutcome(record.state.value),
        recorded_at=recorded_at or datetime.now(timezone.utc).isoformat(),
        provider_reference=provider_reference,
    )


__all__ = [
    "OUTCOME_RECEIPT_SCHEMA",
    "OutcomeReceipt",
    "SignedOutcomeReceipt",
    "outcome_from_record",
    "sign_outcome",
]
