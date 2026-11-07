"""Signed, hash-chained control-plane receipts.

One receipt is emitted for every PDP decision (allow and deny) and for every
promotion. Each receipt commits to the agent identity, the action, the
constitution version hash, the policy digest, the inputs digest, the decision,
any approvers and the external run ids that back a success claim, and links to
its predecessor by ``prev_receipt_hash``.

Evidence: in the Darwin Goedel Machine runs the agent fabricated "tests
passed" logs; only the lineage archive caught it. A hash-chained, signed
lineage that cites *external* run ids lets a third party holding only the
public key and a run verifier re-check every claim without trusting the agent
or the PDP (see :mod:`.receipt_verify`).

This module must not import the PDP: verification depends on it.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from acgs_lite._compat import StrEnum
from acgs_lite.control_plane.evidence import EvidenceSource, ExternalRunRef
from acgs_lite.legitimacy.signing import ReceiptSigner

__all__ = [
    "GENESIS_RECEIPT_HASH",
    "MAX_FIELD_CHARS",
    "MAX_REASON_CHARS",
    "ORIGIN_DISPATCHER_PRE_DENIAL",
    "ORIGIN_PDP",
    "ORIGIN_PROMOTION_GATE",
    "RECEIPT_ORIGINS",
    "RECEIPT_HASH_DOMAIN",
    "RECEIPT_SIGNATURE_DOMAIN",
    "ApproverRef",
    "ControlPlaneReceipt",
    "ReceiptKind",
    "SignedControlPlaneReceipt",
    "promotion_evidence_keys",
    "sign_control_plane_receipt",
    "truncate_reason",
]

RECEIPT_HASH_DOMAIN = b"acgs-control-plane-receipt-v1\x00"
RECEIPT_SIGNATURE_DOMAIN = b"acgs-control-plane-receipt-sig-v1\x00"
GENESIS_RECEIPT_HASH = "sha256:" + "0" * 64

_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_HEX = re.compile(r"[0-9a-f]+")
_LEDGER_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")

ORIGIN_PDP = "pdp"
ORIGIN_DISPATCHER_PRE_DENIAL = "dispatcher_pre_denial"
ORIGIN_PROMOTION_GATE = "promotion_gate"
RECEIPT_ORIGINS = frozenset({ORIGIN_PDP, ORIGIN_DISPATCHER_PRE_DENIAL, ORIGIN_PROMOTION_GATE})
# Bound per-receipt size so a flood of (pre-)denials cannot balloon the store.
MAX_FIELD_CHARS = 512
MAX_REASON_CHARS = 1024
TRUNCATION_MARKER = "...[truncated]"
# TODO(control-plane-gap): issued_at is the issuer's wall clock and is not
# validated or anchored (no trusted timestamping); treat it as informational.


class ReceiptKind(StrEnum):
    POLICY_DECISION = "policy_decision"
    PROMOTION = "promotion"


_APPROVER_KEYS = frozenset({"principal_id", "kind"})
_APPROVAL_KEYS = frozenset({"approval_id", "action_hash"})


@dataclass(frozen=True)
class ApproverRef:
    """An approver cited by a receipt.

    Phase 3: when the approver was attested by a signed approval, the receipt
    also names that ``approval_id`` and the ``action_hash`` it was bound to.
    Both are omitted from the payload when absent, so Phase 2 receipts keep
    their hashes.
    """

    principal_id: str
    kind: str
    approval_id: str | None = None
    action_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, str) or not self.principal_id:
            raise ValueError("approver principal_id must be a non-empty string")
        if not isinstance(self.kind, str) or not self.kind:
            raise ValueError("approver kind must be a non-empty string")
        if (self.approval_id is None) != (self.action_hash is None):
            raise ValueError("approval_id and action_hash must be given together")
        if self.approval_id is not None and (
            not isinstance(self.approval_id, str) or not self.approval_id
        ):
            raise ValueError("approver approval_id must be a non-empty string")
        if self.action_hash is not None and (
            not isinstance(self.action_hash, str) or not _HASH.fullmatch(self.action_hash)
        ):
            raise ValueError("approver action_hash must be 'sha256:<64 hex>'")

    def to_dict(self) -> dict[str, str]:
        out = {"principal_id": self.principal_id, "kind": self.kind}
        if self.approval_id is not None and self.action_hash is not None:
            out["approval_id"] = self.approval_id
            out["action_hash"] = self.action_hash
        return out

    @classmethod
    def from_dict(cls, data: object) -> ApproverRef:
        if not isinstance(data, Mapping) or set(data) not in (
            _APPROVER_KEYS,
            _APPROVER_KEYS | _APPROVAL_KEYS,
        ):
            raise ValueError("malformed approver")
        return cls(
            data["principal_id"],
            data["kind"],
            data.get("approval_id"),
            data.get("action_hash"),
        )


_FIELDS = (
    "ledger_id",
    "origin",
    "receipt_id",
    "kind",
    "sequence",
    "prev_receipt_hash",
    "issued_at",
    "principal_id",
    "principal_kind",
    "system_id",
    "action",
    "resource",
    "tier",
    "constitution_hash",
    "policy_digest",
    "policy_set_digest",
    "inputs_digest",
    "decision_id",
    "allowed",
    "determining_policies",
    "reason",
    "error",
    "claims_success",
    "candidate_digest",
    "approvers",
    "external_runs",
    "receipt_hash",
)


def _str(value: object, label: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")


def _opt_str(value: object, label: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{label} must be a string or None")


@dataclass(frozen=True)
class ControlPlaneReceipt:
    """One link of the receipt chain. Build with :meth:`create`.

    ``ledger_id`` names the chain (a verifier rejects mixed chains);
    ``candidate_digest`` is the artifact a PROMOTION receipt promotes and
    every promotion evidence ref must carry it as ``artifact_digest``.
    ``origin`` says which code path asserted the content (see
    :data:`RECEIPT_ORIGINS`); only ``pdp``/``promotion_gate`` receipts with a
    ``principal_kind`` attribute the decision to a principal.
    """

    ledger_id: str
    origin: str
    receipt_id: str
    kind: ReceiptKind
    sequence: int
    prev_receipt_hash: str
    issued_at: str
    principal_id: str
    principal_kind: str | None
    system_id: str | None
    action: str
    resource: str
    tier: int | None
    constitution_hash: str
    policy_digest: str
    policy_set_digest: str
    inputs_digest: str
    decision_id: str
    allowed: bool
    determining_policies: tuple[str, ...]
    reason: str
    error: str | None
    claims_success: bool
    candidate_digest: str | None
    approvers: tuple[ApproverRef, ...]
    external_runs: tuple[ExternalRunRef, ...]
    receipt_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ReceiptKind(self.kind))
        for name in (
            "ledger_id",
            "receipt_id",
            "issued_at",
            "principal_id",
            "action",
            "resource",
            "constitution_hash",
            "policy_digest",
            "policy_set_digest",
            "inputs_digest",
            "decision_id",
            "reason",
        ):
            _str(getattr(self, name), name)
        for name in ("principal_kind", "system_id", "error"):
            _opt_str(getattr(self, name), name)
        if self.origin not in RECEIPT_ORIGINS:
            raise ValueError(f"origin must be one of {sorted(RECEIPT_ORIGINS)}")
        for name in ("principal_id", "action", "resource"):
            if len(getattr(self, name)) > MAX_FIELD_CHARS:
                raise ValueError(f"{name} exceeds {MAX_FIELD_CHARS} characters")
        if len(self.reason) > MAX_REASON_CHARS:
            raise ValueError(f"reason exceeds {MAX_REASON_CHARS} characters")
        if not self.receipt_id or not self.decision_id or not _LEDGER_ID.fullmatch(self.ledger_id):
            raise ValueError("ledger_id, receipt_id and decision_id must be non-empty ids")
        if self.candidate_digest is not None and (
            not isinstance(self.candidate_digest, str) or not _HASH.fullmatch(self.candidate_digest)
        ):
            raise ValueError("candidate_digest must be 'sha256:<64 hex>' or None")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise ValueError("sequence must be an int")
        if self.sequence < 0:
            raise ValueError("sequence must be >= 0")
        if self.tier is not None and (
            isinstance(self.tier, bool) or not isinstance(self.tier, int)
        ):
            raise ValueError("tier must be an int or None")
        if not isinstance(self.allowed, bool) or not isinstance(self.claims_success, bool):
            raise ValueError("allowed and claims_success must be bools")
        for name in ("prev_receipt_hash", "receipt_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _HASH.fullmatch(value):
                raise ValueError(f"{name} must be 'sha256:<64 hex>'")
        policies = tuple(self.determining_policies)
        if not all(isinstance(p, str) for p in policies):
            raise ValueError("determining_policies must be strings")
        object.__setattr__(self, "determining_policies", policies)
        approvers = tuple(self.approvers)
        if not all(isinstance(a, ApproverRef) for a in approvers):
            raise ValueError("approvers must be ApproverRef")
        object.__setattr__(self, "approvers", approvers)
        runs = tuple(self.external_runs)
        if not all(isinstance(r, ExternalRunRef) for r in runs):
            raise ValueError("external_runs must be ExternalRunRef")
        object.__setattr__(self, "external_runs", runs)

    @classmethod
    def create(cls, **fields: Any) -> ControlPlaneReceipt:
        """Build a receipt, defaulting ``receipt_id``/``issued_at`` and computing the hash."""
        fields.setdefault("receipt_id", uuid.uuid4().hex)
        fields.setdefault("issued_at", datetime.now(timezone.utc).isoformat())
        draft = cls(**{**fields, "receipt_hash": GENESIS_RECEIPT_HASH})
        return cls(**{**fields, "receipt_hash": draft.compute_hash()})

    def _payload(self) -> dict[str, Any]:
        return {
            "ledger_id": self.ledger_id,
            "origin": self.origin,
            "receipt_id": self.receipt_id,
            "kind": self.kind.value,
            "sequence": self.sequence,
            "prev_receipt_hash": self.prev_receipt_hash,
            "issued_at": self.issued_at,
            "principal_id": self.principal_id,
            "principal_kind": self.principal_kind,
            "system_id": self.system_id,
            "action": self.action,
            "resource": self.resource,
            "tier": self.tier,
            "constitution_hash": self.constitution_hash,
            "policy_digest": self.policy_digest,
            "policy_set_digest": self.policy_set_digest,
            "inputs_digest": self.inputs_digest,
            "decision_id": self.decision_id,
            "allowed": self.allowed,
            "determining_policies": list(self.determining_policies),
            "reason": self.reason,
            "error": self.error,
            "claims_success": self.claims_success,
            "candidate_digest": self.candidate_digest,
            "approvers": [a.to_dict() for a in self.approvers],
            "external_runs": [r.to_dict() for r in self.external_runs],
        }

    def compute_hash(self) -> str:
        canonical = json.dumps(
            self._payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        digest = hashlib.sha256(RECEIPT_HASH_DOMAIN + canonical.encode("utf-8")).hexdigest()
        return "sha256:" + digest

    def verify_hash(self) -> bool:
        return self.compute_hash() == self.receipt_hash

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "receipt_hash": self.receipt_hash}

    @classmethod
    def from_dict(cls, data: object) -> ControlPlaneReceipt:
        """Strict: the key set must match exactly. Does not check the hash."""
        if not isinstance(data, Mapping):
            raise ValueError("receipt must be a mapping")
        if set(data) != set(_FIELDS):
            extra = sorted(map(str, set(data) - set(_FIELDS)))
            missing = sorted(set(_FIELDS) - set(data))
            raise ValueError(f"receipt keys mismatch: unknown={extra} missing={missing}")
        for name in ("determining_policies", "approvers", "external_runs"):
            if not isinstance(data[name], list):
                raise ValueError(f"{name} must be a list")
        values = dict(data)
        values["determining_policies"] = tuple(data["determining_policies"])
        values["approvers"] = tuple(ApproverRef.from_dict(a) for a in data["approvers"])
        values["external_runs"] = tuple(ExternalRunRef.from_dict(r) for r in data["external_runs"])
        return cls(**values)


_SIGNED_KEYS = frozenset({"receipt", "algorithm", "key_id", "public_key_hex", "signature"})


@dataclass(frozen=True)
class SignedControlPlaneReceipt:
    """A receipt plus a detached signature over its ``receipt_hash``."""

    receipt: ControlPlaneReceipt
    algorithm: str
    key_id: str
    public_key_hex: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, ControlPlaneReceipt):
            raise ValueError("receipt must be a ControlPlaneReceipt")
        for name in ("algorithm", "key_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("public_key_hex", "signature"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _HEX.fullmatch(value):
                raise ValueError(f"{name} must be lowercase hex")

    def signing_message(self) -> bytes:
        return RECEIPT_SIGNATURE_DOMAIN + self.receipt.receipt_hash.encode("ascii")

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt": self.receipt.to_dict(),
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "public_key_hex": self.public_key_hex,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: object) -> SignedControlPlaneReceipt:
        if not isinstance(data, Mapping) or set(data) != _SIGNED_KEYS:
            raise ValueError("malformed signed receipt: key set mismatch")
        return cls(
            receipt=ControlPlaneReceipt.from_dict(data["receipt"]),
            algorithm=data["algorithm"],
            key_id=data["key_id"],
            public_key_hex=data["public_key_hex"],
            signature=data["signature"],
        )


def promotion_evidence_keys(receipt: ControlPlaneReceipt) -> tuple[tuple[str, str, str], ...]:
    """``(provider, run_id, artifact_digest)`` of the external runs a PROMOTION cites."""
    if receipt.kind is not ReceiptKind.PROMOTION:
        return ()
    return tuple(
        (ref.provider, ref.run_id, ref.artifact_digest or "")
        for ref in receipt.external_runs
        if ref.source is not EvidenceSource.AGENT_LOG
    )


def truncate_reason(reason: str) -> str:
    """Clip *reason* to :data:`MAX_REASON_CHARS`, marking the cut."""
    if len(reason) <= MAX_REASON_CHARS:
        return reason
    return reason[: MAX_REASON_CHARS - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def sign_control_plane_receipt(
    receipt: ControlPlaneReceipt, signer: ReceiptSigner
) -> SignedControlPlaneReceipt:
    """Sign *receipt*; raises (e.g. ``ReceiptSigningUnavailable``) rather than degrade."""
    if not receipt.verify_hash():
        raise ValueError("refusing to sign a receipt whose hash does not match its payload")
    message = RECEIPT_SIGNATURE_DOMAIN + receipt.receipt_hash.encode("ascii")
    return SignedControlPlaneReceipt(
        receipt=receipt,
        algorithm=signer.algorithm,
        key_id=signer.key_id,
        public_key_hex=signer.public_key_hex(),
        signature=signer.sign(message),
    )
