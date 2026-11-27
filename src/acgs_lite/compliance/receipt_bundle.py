"""Deterministic compliance receipt bundle exporter and offline verifier.

Produces self-contained, SHA-256-manifested decision/outcome audit bundles for
``ca-admt-2027`` (California CPPA ADMT / Colorado SB 26-189, 2027-01-01) and
``eu-ai-act-art12-26`` (EU AI Act Art. 12 logging & Art. 26(2)/(6) deployer
oversight, 2027-12-02) from signed ``acgs-lite`` 4.x receipts.

These bundles provide cryptographically verifiable runtime decision/outcome
evidence and do not constitute legal advice or regulatory certification.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from acgs_lite.legitimacy.identity import receipt_identity, signed_envelope_identity
from acgs_lite.legitimacy.outcome import SignedOutcomeReceipt
from acgs_lite.legitimacy.signing import ReceiptSigningUnavailable, SignedReceipt

BUNDLE_SCHEMA_VERSION = "acgs-compliance-bundle-v1"
PROFILE_CA_ADMT_2027 = "ca-admt-2027"
PROFILE_EU_AI_ACT_ART12_26 = "eu-ai-act-art12-26"
SUPPORTED_BUNDLE_PROFILES = frozenset({PROFILE_CA_ADMT_2027, PROFILE_EU_AI_ACT_ART12_26})
EU_AI_ACT_RETENTION_FLOOR_DAYS = 180

ADVERSE_DECISION_STATES = frozenset(
    {
        "DENY_GOAL",
        "DENY_OPERATION_WITH_ALTERNATIVE",
        "HARD_DENY",
        "STRUCTURED_REVIEW_REQUIRED",
    }
)

SELF_ASSESSMENT_NOTICE = (
    "Cryptographically verifiable runtime decision/outcome record bundle; "
    "not legal advice or third-party regulatory certification."
)

_PROFILE_METADATA: dict[str, dict[str, str]] = {
    PROFILE_CA_ADMT_2027: {
        "framework": "California CPPA ADMT / Colorado SB 26-189",
        "effective_date": "2027-01-01",
    },
    PROFILE_EU_AI_ACT_ART12_26: {
        "framework": "EU AI Act Art. 12 & Art. 26(2)/(6)",
        "effective_date": "2027-12-02",
    },
}


class BundleExportError(ValueError):
    """Raised when compliance bundle export fails closed on untrusted or invalid inputs."""


@dataclass(frozen=True)
class ComplianceReceiptBundle:
    """Immutable, SHA-256-manifested regulatory evidence bundle."""

    schema_version: str
    profile: str
    system_id: str
    generated_at: str
    self_assessment_notice: str
    decisions: tuple[dict[str, Any], ...]
    adverse_decisions: tuple[dict[str, Any], ...]
    outcomes: tuple[dict[str, Any], ...]
    oversight: dict[str, Any]
    section_digests: dict[str, str]
    bundle_digest: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete bundle to a JSON-compatible dictionary."""
        return {
            "schema_version": self.schema_version,
            "profile": self.profile,
            "system_id": self.system_id,
            "generated_at": self.generated_at,
            "self_assessment_notice": self.self_assessment_notice,
            "decisions": copy.deepcopy(list(self.decisions)),
            "adverse_decisions": copy.deepcopy(list(self.adverse_decisions)),
            "outcomes": copy.deepcopy(list(self.outcomes)),
            "oversight": copy.deepcopy(self.oversight),
            "section_digests": dict(self.section_digests),
            "bundle_digest": self.bundle_digest,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Render the bundle as canonical or formatted JSON."""
        if indent is None:
            return _canonical_json(self.to_dict())
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False)


@dataclass(frozen=True)
class ReceiptBundleVerification:
    """Offline verification result returned by :func:`verify_receipt_bundle`."""

    valid: bool
    profile: str | None
    bundle_digest: str | None
    verified_decision_count: int
    verified_outcome_count: int
    reasons: tuple[str, ...]


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _sha256_prefixed(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _normalize_records(items: Sequence[Mapping[str, Any]], label: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise BundleExportError(f"{label}[{idx}] must be a mapping")
        normalized = json.loads(_canonical_json(dict(item)))
        if not isinstance(normalized, dict):
            raise BundleExportError(f"{label}[{idx}] must normalize to a JSON object")
        out.append(normalized)
    return out


def _escalation_has_distinct_human_overseer(record: Mapping[str, Any]) -> bool:
    approver = record.get("approver_id")
    proposer = record.get("proposer_id")
    if not isinstance(approver, str) or not approver.strip():
        return False
    return not (isinstance(proposer, str) and proposer.strip() and approver == proposer)


def _verify_trusted_keys(trusted_public_keys: Mapping[str, str]) -> None:
    if not isinstance(trusted_public_keys, Mapping) or not trusted_public_keys:
        raise BundleExportError(
            "trusted_public_keys must be a non-empty mapping of key_id -> hex key"
        )
    for key_id, hex_key in trusted_public_keys.items():
        if not isinstance(key_id, str) or not key_id.strip():
            raise BundleExportError("trusted_public_keys contains an empty key_id")
        if not isinstance(hex_key, str) or not hex_key.strip():
            raise BundleExportError(
                f"trusted_public_keys[{key_id!r}] must be a non-empty hex string"
            )


def export_receipt_bundle(
    decision_receipts: Sequence[SignedReceipt],
    *,
    profile: str,
    trusted_public_keys: Mapping[str, str],
    system_id: str,
    outcome_receipts: Sequence[SignedOutcomeReceipt] = (),
    retention_days: int | None = None,
    escalations: Sequence[Mapping[str, Any]] = (),
    halt_events: Sequence[Mapping[str, Any]] = (),
    generated_at: str | None = None,
) -> ComplianceReceiptBundle:
    """Validate signed receipts fail-closed and assemble a verifiable compliance bundle."""
    if profile not in SUPPORTED_BUNDLE_PROFILES:
        raise BundleExportError(
            f"Unsupported compliance bundle profile {profile!r}; "
            f"expected one of {sorted(SUPPORTED_BUNDLE_PROFILES)}"
        )
    if not isinstance(system_id, str) or not system_id.strip():
        raise BundleExportError("system_id must be a non-empty string")
    if retention_days is not None and (type(retention_days) is not int or retention_days <= 0):
        raise BundleExportError("retention_days must be a positive integer when provided")
    _verify_trusted_keys(trusted_public_keys)

    verified_decision_ids: set[str] = set()
    decision_entries: list[dict[str, Any]] = []
    escalation_records = _normalize_records(escalations, "escalations")
    halt_records = _normalize_records(halt_events, "halt_events")

    escalation_by_ref: dict[str, dict[str, Any]] = {}
    for esc in escalation_records:
        for ref_key in ("decision_identity", "request_id", "escalation_id"):
            ref_val = esc.get(ref_key)
            if isinstance(ref_val, str) and ref_val:
                escalation_by_ref[ref_val] = esc

    for idx, signed in enumerate(decision_receipts):
        if not isinstance(signed, SignedReceipt):
            raise BundleExportError(f"decision_receipts[{idx}] must be a SignedReceipt")
        trusted_key = trusted_public_keys.get(signed.key_id)
        if trusted_key is None:
            raise BundleExportError(
                f"Untrusted signing key_id {signed.key_id!r} in decision_receipts[{idx}]"
            )
        if not signed.verify(trusted_key):
            raise BundleExportError(
                f"Signature or hash verification failed for decision_receipts[{idx}]"
            )
        rec_id = receipt_identity(signed.receipt)
        env_id = signed_envelope_identity(signed)
        verified_decision_ids.add(rec_id)
        verified_decision_ids.add(env_id)

        adverse = signed.receipt.decision_type in ADVERSE_DECISION_STATES
        decision_entries.append(
            {
                "decision_identity": rec_id,
                "signed_envelope_identity": env_id,
                "request_id": signed.receipt.request_id,
                "proposed_method": signed.receipt.proposed_method,
                "decision_type": signed.receipt.decision_type,
                "adverse_or_consequential": adverse,
                "matched_constraints": list(signed.receipt.matched_constraints),
                "denial_or_review_rationale": signed.receipt.denial_or_review_rationale,
                "issued_at": signed.receipt.issued_at,
                "signed_receipt": signed.to_dict(),
            }
        )

    adverse_entries: list[dict[str, Any]] = []
    for entry in decision_entries:
        if not entry["adverse_or_consequential"]:
            continue
        matched_esc = (
            escalation_by_ref.get(str(entry["decision_identity"]))
            or escalation_by_ref.get(str(entry["signed_envelope_identity"]))
            or escalation_by_ref.get(str(entry["request_id"]))
        )
        adverse_entries.append(
            {
                "decision_identity": entry["decision_identity"],
                "signed_envelope_identity": entry["signed_envelope_identity"],
                "request_id": entry["request_id"],
                "proposed_method": entry["proposed_method"],
                "decision_type": entry["decision_type"],
                "matched_constraints": entry["matched_constraints"],
                "denial_or_review_rationale": entry["denial_or_review_rationale"],
                "issued_at": entry["issued_at"],
                "human_review": (
                    {
                        "decision": matched_esc.get("decision"),
                        "approver_id": matched_esc.get("approver_id"),
                        "decided_at": matched_esc.get("decided_at"),
                        "rationale": matched_esc.get("rationale"),
                    }
                    if matched_esc is not None
                    else None
                ),
            }
        )

    outcome_entries: list[dict[str, Any]] = []
    for idx, signed_outcome in enumerate(outcome_receipts):
        if not isinstance(signed_outcome, SignedOutcomeReceipt):
            raise BundleExportError(f"outcome_receipts[{idx}] must be a SignedOutcomeReceipt")
        trusted_key = trusted_public_keys.get(signed_outcome.key_id)
        if trusted_key is None:
            raise BundleExportError(
                f"Untrusted signing key_id {signed_outcome.key_id!r} in outcome_receipts[{idx}]"
            )
        if not signed_outcome.verify(trusted_key):
            raise BundleExportError(f"Signature verification failed for outcome_receipts[{idx}]")
        dec_ref = signed_outcome.receipt.decision_receipt_identity
        if dec_ref not in verified_decision_ids:
            raise BundleExportError(
                f"outcome_receipts[{idx}] references unbundled decision_receipt_identity {dec_ref!r}"
            )
        outcome_entries.append(signed_outcome.to_dict())

    distinct_human_overseer = all(
        _escalation_has_distinct_human_overseer(esc) for esc in escalation_records
    )
    retention_floor_met = (
        retention_days is not None and retention_days >= EU_AI_ACT_RETENTION_FLOOR_DAYS
    )
    meta = _PROFILE_METADATA[profile]
    oversight_section: dict[str, Any] = {
        "framework": meta["framework"],
        "effective_date": meta["effective_date"],
        "retention_days": retention_days,
        "retention_floor_days": (
            EU_AI_ACT_RETENTION_FLOOR_DAYS if profile == PROFILE_EU_AI_ACT_ART12_26 else None
        ),
        "retention_meets_art26_6_floor": retention_floor_met,
        "every_escalation_has_distinct_human_overseer": distinct_human_overseer,
        "decision_count": len(decision_entries),
        "adverse_decision_count": len(adverse_entries),
        "outcome_count": len(outcome_entries),
        "paired_chain_count": len(outcome_entries),
        "escalations": escalation_records,
        "halt_events": halt_records,
    }

    section_digests = {
        "decisions": _sha256_prefixed(decision_entries),
        "adverse_decisions": _sha256_prefixed(adverse_entries),
        "outcomes": _sha256_prefixed(outcome_entries),
        "oversight": _sha256_prefixed(oversight_section),
    }

    timestamp = generated_at or datetime.now(timezone.utc).isoformat()
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise BundleExportError("generated_at must be a non-empty ISO 8601 string")

    unsigned_bundle: dict[str, Any] = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "profile": profile,
        "system_id": system_id,
        "generated_at": timestamp,
        "self_assessment_notice": SELF_ASSESSMENT_NOTICE,
        "decisions": decision_entries,
        "adverse_decisions": adverse_entries,
        "outcomes": outcome_entries,
        "oversight": oversight_section,
        "section_digests": section_digests,
    }
    bundle_digest = _sha256_prefixed(unsigned_bundle)

    return ComplianceReceiptBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        profile=profile,
        system_id=system_id,
        generated_at=timestamp,
        self_assessment_notice=SELF_ASSESSMENT_NOTICE,
        decisions=tuple(decision_entries),
        adverse_decisions=tuple(adverse_entries),
        outcomes=tuple(outcome_entries),
        oversight=oversight_section,
        section_digests=section_digests,
        bundle_digest=bundle_digest,
    )


def verify_receipt_bundle(
    bundle: Mapping[str, Any],
    *,
    trusted_public_keys: Mapping[str, str],
) -> ReceiptBundleVerification:
    """Verify a serialized compliance receipt bundle completely offline (never raises)."""
    reasons: list[str] = []
    if not isinstance(bundle, Mapping):
        return ReceiptBundleVerification(
            valid=False,
            profile=None,
            bundle_digest=None,
            verified_decision_count=0,
            verified_outcome_count=0,
            reasons=("bundle must be a mapping",),
        )
    if not isinstance(trusted_public_keys, Mapping) or not trusted_public_keys:
        return ReceiptBundleVerification(
            valid=False,
            profile=bundle.get("profile") if isinstance(bundle.get("profile"), str) else None,
            bundle_digest=(
                bundle.get("bundle_digest")
                if isinstance(bundle.get("bundle_digest"), str)
                else None
            ),
            verified_decision_count=0,
            verified_outcome_count=0,
            reasons=("trusted_public_keys must be a non-empty mapping",),
        )

    profile = bundle.get("profile")
    bundle_digest = bundle.get("bundle_digest")
    profile_str = profile if isinstance(profile, str) else None
    digest_str = bundle_digest if isinstance(bundle_digest, str) else None

    if bundle.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        reasons.append(f"unexpected schema_version: {bundle.get('schema_version')!r}")
    if profile_str not in SUPPORTED_BUNDLE_PROFILES:
        reasons.append(f"unsupported profile: {profile!r}")
    if bundle.get("self_assessment_notice") != SELF_ASSESSMENT_NOTICE:
        reasons.append("self_assessment_notice missing or modified")
    if not isinstance(digest_str, str) or not digest_str.startswith("sha256:"):
        reasons.append("bundle_digest missing or malformed")
    else:
        unsigned = {k: v for k, v in bundle.items() if k != "bundle_digest"}
        try:
            expected_digest = _sha256_prefixed(unsigned)
        except (TypeError, ValueError) as exc:
            reasons.append(f"bundle is not canonical JSON: {exc}")
        else:
            if not hmac.compare_digest(expected_digest, digest_str):
                reasons.append("bundle_digest mismatch")

    decisions_raw = bundle.get("decisions")
    adverse_raw = bundle.get("adverse_decisions")
    outcomes_raw = bundle.get("outcomes")
    oversight_raw = bundle.get("oversight")
    section_digests = bundle.get("section_digests")

    if not isinstance(section_digests, Mapping):
        reasons.append("section_digests must be a mapping")
    else:
        for name, section in (
            ("decisions", decisions_raw),
            ("adverse_decisions", adverse_raw),
            ("outcomes", outcomes_raw),
            ("oversight", oversight_raw),
        ):
            recorded = section_digests.get(name)
            if not isinstance(recorded, str):
                reasons.append(f"section_digests[{name!r}] missing")
                continue
            try:
                computed = _sha256_prefixed(section)
            except (TypeError, ValueError) as exc:
                reasons.append(f"section {name!r} invalid JSON: {exc}")
            else:
                if not hmac.compare_digest(computed, recorded):
                    reasons.append(f"section_digests[{name!r}] mismatch")

    verified_decision_ids: set[str] = set()
    verified_decision_count = 0
    adverse_expected_ids: list[str] = []
    if not isinstance(decisions_raw, list):
        reasons.append("decisions must be a list")
    else:
        for idx, item in enumerate(decisions_raw):
            if not isinstance(item, Mapping) or not isinstance(item.get("signed_receipt"), Mapping):
                reasons.append(f"decisions[{idx}] missing signed_receipt")
                continue
            try:
                signed = SignedReceipt.from_dict(item["signed_receipt"])
            except ValueError as exc:
                reasons.append(f"decisions[{idx}] invalid signed_receipt: {exc}")
                continue
            trusted_key = trusted_public_keys.get(signed.key_id)
            if not isinstance(trusted_key, str):
                reasons.append(f"decisions[{idx}] untrusted key_id {signed.key_id!r}")
                continue
            try:
                ok = signed.verify(trusted_key)
            except ReceiptSigningUnavailable as exc:
                reasons.append(f"decisions[{idx}] crypto unavailable: {exc}")
                continue
            if not ok:
                reasons.append(f"decisions[{idx}] signature or hash verification failed")
                continue
            rec_id = receipt_identity(signed.receipt)
            env_id = signed_envelope_identity(signed)
            verified_decision_ids.add(rec_id)
            verified_decision_ids.add(env_id)
            verified_decision_count += 1
            if signed.receipt.decision_type in ADVERSE_DECISION_STATES:
                adverse_expected_ids.append(rec_id)

    if not isinstance(adverse_raw, list):
        reasons.append("adverse_decisions must be a list")
    else:
        adverse_actual_ids: list[str] = [
            str(item["decision_identity"])
            for item in adverse_raw
            if isinstance(item, Mapping) and isinstance(item.get("decision_identity"), str)
        ]
        if len(adverse_actual_ids) != len(adverse_raw) or sorted(adverse_actual_ids) != sorted(
            adverse_expected_ids
        ):
            reasons.append("adverse_decisions does not match verified adverse decisions")

    verified_outcome_count = 0
    if not isinstance(outcomes_raw, list):
        reasons.append("outcomes must be a list")
    else:
        for idx, item in enumerate(outcomes_raw):
            if not isinstance(item, Mapping):
                reasons.append(f"outcomes[{idx}] must be a mapping")
                continue
            try:
                signed_outcome = SignedOutcomeReceipt.from_dict(item)
            except ValueError as exc:
                reasons.append(f"outcomes[{idx}] invalid signed outcome: {exc}")
                continue
            trusted_key = trusted_public_keys.get(signed_outcome.key_id)
            if not isinstance(trusted_key, str):
                reasons.append(f"outcomes[{idx}] untrusted key_id {signed_outcome.key_id!r}")
                continue
            if not signed_outcome.verify(trusted_key):
                reasons.append(f"outcomes[{idx}] signature verification failed")
                continue
            if signed_outcome.receipt.decision_receipt_identity not in verified_decision_ids:
                reasons.append(f"outcomes[{idx}] references unverified or missing decision receipt")
                continue
            verified_outcome_count += 1

    return ReceiptBundleVerification(
        valid=not reasons,
        profile=profile_str,
        bundle_digest=digest_str,
        verified_decision_count=verified_decision_count,
        verified_outcome_count=verified_outcome_count,
        reasons=tuple(reasons),
    )


__all__ = [
    "ADVERSE_DECISION_STATES",
    "BUNDLE_SCHEMA_VERSION",
    "EU_AI_ACT_RETENTION_FLOOR_DAYS",
    "PROFILE_CA_ADMT_2027",
    "PROFILE_EU_AI_ACT_ART12_26",
    "SELF_ASSESSMENT_NOTICE",
    "SUPPORTED_BUNDLE_PROFILES",
    "BundleExportError",
    "ComplianceReceiptBundle",
    "ReceiptBundleVerification",
    "export_receipt_bundle",
    "verify_receipt_bundle",
]
