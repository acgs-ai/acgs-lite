# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""RFC 9052 SCITT ``COSE_Sign1`` EdDSA exporter and offline verifier.

Produces and verifies self-contained CBOR Tag 18 (``COSE_Sign1``, RFC 9052)
signed envelopes with SCITT protected CWT claims (``draft-ietf-scitt-architecture``,
header parameter ``15``) over ``acgs-lite`` signed decision receipts, signed
outcome receipts, compliance receipt bundles, or arbitrary JSON governance
objects using deterministic RFC 8949 CBOR (§4.2.1) with zero extra runtime
dependencies beyond ``acgs-lite[crypto]`` for Ed25519 operations.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from acgs_lite.compliance.receipt_bundle import ComplianceReceiptBundle
from acgs_lite.legitimacy.outcome import SignedOutcomeReceipt
from acgs_lite.legitimacy.signing import (
    SIGNATURE_ALGORITHM,
    ReceiptSigner,
    ReceiptSigningUnavailable,
    SignedReceipt,
    verify_signature,
)

SCITT_COSE_SIGN1_TAG = 18
COSE_HEADER_ALG = 1
COSE_HEADER_CONTENT_TYPE = 3
COSE_HEADER_KID = 4
COSE_HEADER_CWT_CLAIMS = 15
COSE_ALG_EDDSA = -8

CWT_CLAIM_ISS = 1
CWT_CLAIM_SUB = 2
CWT_CLAIM_IAT = 6

MEDIA_TYPE_DECISION_RECEIPT = "application/acgs-decision-receipt+json"
MEDIA_TYPE_OUTCOME_RECEIPT = "application/acgs-outcome-receipt+json"
MEDIA_TYPE_COMPLIANCE_BUNDLE = "application/acgs-compliance-bundle+json"
MEDIA_TYPE_JSON = "application/json"

_HEX64_RE = re.compile(r"[0-9a-fA-F]{64}")
_HEX128_RE = re.compile(r"[0-9a-fA-F]{128}")
_MAX_CBOR_DEPTH = 32


class SCITTExportError(ValueError):
    """Raised when SCITT ``COSE_Sign1`` export fails closed on invalid input."""


class _CBORDecodeError(ValueError):
    """Raised when CBOR bytes are malformed, non-canonical, or exceed bounds."""


@dataclass(frozen=True)
class _CborTag:
    """Internal CBOR Major 6 semantic tag wrapper."""

    tag: int
    value: Any


def _encode_uint(major: int, value: int) -> bytes:
    if type(value) is not int or value < 0 or value >= (1 << 64):
        raise ValueError(f"CBOR unsigned integer out of range: {value!r}")
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    if value <= 0xFFFF:
        return struct.pack(">BH", prefix | 25, value)
    if value <= 0xFFFFFFFF:
        return struct.pack(">BI", prefix | 26, value)
    return struct.pack(">BQ", prefix | 27, value)


def _cbor_encode(value: Any, *, _depth: int = 0) -> bytes:
    """Encode a Python value using RFC 8949 §4.2.1 deterministic CBOR."""
    if _depth > _MAX_CBOR_DEPTH:
        raise ValueError("CBOR encoding depth exceeded")
    if value is None:
        return b"\xf6"
    if type(value) is bool:
        return b"\xf5" if value else b"\xf4"
    if type(value) is int:
        if value >= 0:
            return _encode_uint(0, value)
        return _encode_uint(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return _encode_uint(2, len(raw)) + raw
    if isinstance(value, str):
        utf8 = value.encode("utf-8")
        return _encode_uint(3, len(utf8)) + utf8
    if isinstance(value, (list, tuple)):
        header = _encode_uint(4, len(value))
        parts = [_cbor_encode(item, _depth=_depth + 1) for item in value]
        return header + b"".join(parts)
    if isinstance(value, Mapping):
        encoded_pairs: list[tuple[bytes, bytes]] = []
        seen_keys: set[tuple[type[Any], Any]] = set()
        for key, item in value.items():
            if type(key) not in (int, str, bytes):
                raise TypeError(f"unsupported CBOR map key type: {type(key).__name__}")
            typed_key = (type(key), key)
            if typed_key in seen_keys:
                raise ValueError(f"duplicate CBOR map key: {key!r}")
            seen_keys.add(typed_key)
            key_bytes = _cbor_encode(key, _depth=_depth + 1)
            val_bytes = _cbor_encode(item, _depth=_depth + 1)
            encoded_pairs.append((key_bytes, val_bytes))
        # RFC 8949 §4.2.1 bytewise lexicographical ordering of encoded keys.
        encoded_pairs.sort(key=lambda pair: pair[0])
        header = _encode_uint(5, len(encoded_pairs))
        return header + b"".join(k + v for k, v in encoded_pairs)
    if isinstance(value, _CborTag):
        if type(value.tag) is not int or value.tag < 0:
            raise ValueError(f"invalid CBOR tag number: {value.tag!r}")
        return _encode_uint(6, value.tag) + _cbor_encode(value.value, _depth=_depth + 1)
    raise TypeError(f"unsupported CBOR type: {type(value).__name__}")


class _CBORDecoder:
    """Fail-closed bounded CBOR decoder enforcing minimal-length integers."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0
        self._length = len(data)

    def _read_exact(self, n: int) -> bytes:
        if n < 0 or self._pos + n > self._length:
            raise _CBORDecodeError("truncated CBOR input")
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def _read_arg(self, ai: int) -> int:
        if ai < 24:
            return ai
        if ai == 24:
            val = self._read_exact(1)[0]
            if val < 24:
                raise _CBORDecodeError("non-canonical 1-byte CBOR integer")
            return val
        if ai == 25:
            (val,) = struct.unpack(">H", self._read_exact(2))
            if val < 256:
                raise _CBORDecodeError("non-canonical 2-byte CBOR integer")
            return val
        if ai == 26:
            (val,) = struct.unpack(">I", self._read_exact(4))
            if val < 65536:
                raise _CBORDecodeError("non-canonical 4-byte CBOR integer")
            return val
        if ai == 27:
            (val,) = struct.unpack(">Q", self._read_exact(8))
            if val < 4294967296:
                raise _CBORDecodeError("non-canonical 8-byte CBOR integer")
            return val
        raise _CBORDecodeError(f"unsupported CBOR additional info: {ai}")

    def decode_root(self) -> Any:
        value = self.decode_item(depth=0)
        if self._pos != self._length:
            raise _CBORDecodeError("trailing bytes after CBOR root item")
        return value

    def decode_item(self, *, depth: int) -> Any:
        if depth > _MAX_CBOR_DEPTH:
            raise _CBORDecodeError("CBOR nesting depth exceeded")
        initial = self._read_exact(1)[0]
        major = initial >> 5
        ai = initial & 0x1F

        if major == 7:
            if ai == 20:
                return False
            if ai == 21:
                return True
            if ai == 22:
                return None
            raise _CBORDecodeError(f"unsupported CBOR simple/float value ai={ai}")

        arg = self._read_arg(ai)
        remaining = self._length - self._pos

        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            if arg > remaining:
                raise _CBORDecodeError("CBOR byte string exceeds remaining input")
            return self._read_exact(arg)
        if major == 3:
            if arg > remaining:
                raise _CBORDecodeError("CBOR text string exceeds remaining input")
            raw = self._read_exact(arg)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _CBORDecodeError(f"invalid UTF-8 in CBOR text string: {exc}") from exc
        if major == 4:
            if arg > remaining:
                raise _CBORDecodeError("CBOR array count exceeds remaining input")
            return [self.decode_item(depth=depth + 1) for _ in range(arg)]
        if major == 5:
            if arg * 2 > remaining:
                raise _CBORDecodeError("CBOR map count exceeds remaining input")
            out: dict[Any, Any] = {}
            seen_keys: set[tuple[type[Any], Any]] = set()
            for _ in range(arg):
                key = self.decode_item(depth=depth + 1)
                if type(key) not in (int, str, bytes):
                    raise _CBORDecodeError(f"unsupported decoded CBOR map key type: {type(key).__name__}")
                typed_key = (type(key), key)
                if typed_key in seen_keys:
                    raise _CBORDecodeError(f"duplicate CBOR map key: {key!r}")
                seen_keys.add(typed_key)
                out[key] = self.decode_item(depth=depth + 1)
            return out
        if major == 6:
            return _CborTag(tag=arg, value=self.decode_item(depth=depth + 1))
        raise _CBORDecodeError(f"unknown CBOR major type: {major}")  # pragma: no cover


def _cbor_decode(data: bytes) -> Any:
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise _CBORDecodeError("CBOR input must be non-empty bytes")
    return _CBORDecoder(bytes(data)).decode_root()


@dataclass(frozen=True)
class SCITTReceiptEnvelope:
    """Serialized RFC 9052 Tag 18 ``COSE_Sign1`` envelope with SCITT metadata."""

    cose_bytes: bytes
    key_id: str
    algorithm: str
    content_type: str
    payload_sha256: str
    issuer: str | None = None
    subject: str | None = None
    issued_at: int | None = None

    def to_base64(self) -> str:
        """Encode the ``COSE_Sign1`` bytes as standard Base64 ASCII."""
        return base64.b64encode(self.cose_bytes).decode("ascii")

    def to_hex(self) -> str:
        """Encode the ``COSE_Sign1`` bytes as lowercase hexadecimal."""
        return self.cose_bytes.hex()

    def to_metadata_dict(self) -> dict[str, Any]:
        """Serialize non-binary envelope metadata to a JSON-compatible dictionary."""
        return {
            "cose_tag": SCITT_COSE_SIGN1_TAG,
            "cose_alg": COSE_ALG_EDDSA,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "content_type": self.content_type,
            "payload_sha256": self.payload_sha256,
            "issuer": self.issuer,
            "subject": self.subject,
            "issued_at": self.issued_at,
            "byte_length": len(self.cose_bytes),
        }


@dataclass(frozen=True)
class SCITTVerificationResult:
    """Fail-closed offline verification outcome for a SCITT ``COSE_Sign1`` statement."""

    valid: bool
    errors: tuple[str, ...]
    key_id: str | None
    content_type: str | None
    payload_sha256: str | None
    issuer: str | None
    subject: str | None
    issued_at: int | None
    payload: dict[str, Any] | None


def _canonical_json_bytes(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _extract_payload(
    payload: SignedReceipt | SignedOutcomeReceipt | ComplianceReceiptBundle | Mapping[str, Any],
    content_type: str | None,
) -> tuple[bytes, str]:
    if isinstance(payload, SignedReceipt):
        if not payload.verify_integrity():
            raise SCITTExportError("refusing to export tampered or unverifiable SignedReceipt")
        resolved_cty = MEDIA_TYPE_DECISION_RECEIPT if content_type is None else content_type
        raw = payload.to_dict()
    elif isinstance(payload, SignedOutcomeReceipt):
        if not payload.verify(payload.public_key):
            raise SCITTExportError(
                "refusing to export tampered or unverifiable SignedOutcomeReceipt"
            )
        resolved_cty = MEDIA_TYPE_OUTCOME_RECEIPT if content_type is None else content_type
        raw = payload.to_dict()
    elif isinstance(payload, ComplianceReceiptBundle):
        resolved_cty = MEDIA_TYPE_COMPLIANCE_BUNDLE if content_type is None else content_type
        raw = payload.to_dict()
    elif isinstance(payload, Mapping):
        resolved_cty = MEDIA_TYPE_JSON if content_type is None else content_type
        raw = dict(payload)
    else:
        raise SCITTExportError(
            "payload must be SignedReceipt, SignedOutcomeReceipt, "
            "ComplianceReceiptBundle, or a Mapping"
        )

    if not isinstance(resolved_cty, str) or not resolved_cty.strip():
        raise SCITTExportError("content_type must be a non-empty string")
    try:
        payload_bytes = _canonical_json_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise SCITTExportError(f"payload is not valid strict JSON: {exc}") from exc
    return payload_bytes, resolved_cty


def export_scitt_cose_sign1(
    payload: SignedReceipt | SignedOutcomeReceipt | ComplianceReceiptBundle | Mapping[str, Any],
    signer: ReceiptSigner,
    *,
    content_type: str | None = None,
    issuer: str | None = None,
    subject: str | None = None,
    issued_at: int | None = None,
    external_aad: bytes = b"",
) -> SCITTReceiptEnvelope:
    """Wrap an ACGS receipt, bundle, or JSON mapping in a SCITT ``COSE_Sign1`` envelope.

    Args:
        payload: Verified receipt, compliance bundle, or JSON-compatible mapping.
        signer: Ed25519 signer implementing :class:`~acgs_lite.legitimacy.signing.ReceiptSigner`.
        content_type: Optional override for COSE protected header ``3`` (``content_type``).
        issuer: Optional CWT ``iss`` claim (key ``1`` in protected header ``15``).
        subject: Optional CWT ``sub`` claim (key ``2`` in protected header ``15``).
        issued_at: Optional CWT ``iat`` numeric epoch seconds (key ``6`` in header ``15``).
        external_aad: Optional COSE ``external_aad`` bytes bound into ``Sig_structure``.

    Raises:
        SCITTExportError: On invalid payload, unsupported signer algorithm, or bad claims.
    """
    if getattr(signer, "algorithm", None) != SIGNATURE_ALGORITHM:
        raise SCITTExportError(
            f"SCITT export requires {SIGNATURE_ALGORITHM!r} signer, "
            f"got {getattr(signer, 'algorithm', None)!r}"
        )
    key_id = getattr(signer, "key_id", None)
    if not isinstance(key_id, str) or not key_id.strip():
        raise SCITTExportError("signer.key_id must be a non-empty string")
    if not isinstance(external_aad, bytes):
        raise SCITTExportError("external_aad must be bytes")

    cwt_claims: dict[int, Any] = {}
    if issuer is not None:
        if not isinstance(issuer, str) or not issuer.strip():
            raise SCITTExportError("issuer must be a non-empty string")
        cwt_claims[CWT_CLAIM_ISS] = issuer
    if subject is not None:
        if not isinstance(subject, str) or not subject.strip():
            raise SCITTExportError("subject must be a non-empty string")
        cwt_claims[CWT_CLAIM_SUB] = subject
    if issued_at is not None:
        if type(issued_at) is not int or issued_at < 0 or issued_at >= (1 << 64):
            raise SCITTExportError("issued_at must be a non-negative 64-bit integer")
        cwt_claims[CWT_CLAIM_IAT] = issued_at

    payload_bytes, resolved_cty = _extract_payload(payload, content_type)
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()

    protected_map: dict[int, Any] = {
        COSE_HEADER_ALG: COSE_ALG_EDDSA,
        COSE_HEADER_CONTENT_TYPE: resolved_cty,
        COSE_HEADER_KID: key_id.encode("utf-8"),
    }
    if cwt_claims:
        protected_map[COSE_HEADER_CWT_CLAIMS] = cwt_claims

    protected_bstr = _cbor_encode(protected_map)
    sig_structure = _cbor_encode(["Signature1", protected_bstr, external_aad, payload_bytes])
    sig_hex = signer.sign(sig_structure)
    if not isinstance(sig_hex, str) or _HEX128_RE.fullmatch(sig_hex) is None:
        raise SCITTExportError("signer.sign did not return a 64-byte Ed25519 signature hex")
    sig_bytes = bytes.fromhex(sig_hex)

    cose_bytes = _cbor_encode(
        _CborTag(
            tag=SCITT_COSE_SIGN1_TAG,
            value=[protected_bstr, {}, payload_bytes, sig_bytes],
        )
    )
    return SCITTReceiptEnvelope(
        cose_bytes=cose_bytes,
        key_id=key_id,
        algorithm=SIGNATURE_ALGORITHM,
        content_type=resolved_cty,
        payload_sha256=payload_sha256,
        issuer=issuer,
        subject=subject,
        issued_at=issued_at,
    )


def _fail_result(
    *errors: str,
    key_id: str | None = None,
    content_type: str | None = None,
    payload_sha256: str | None = None,
    issuer: str | None = None,
    subject: str | None = None,
    issued_at: int | None = None,
    payload: dict[str, Any] | None = None,
) -> SCITTVerificationResult:
    return SCITTVerificationResult(
        valid=False,
        errors=tuple(errors),
        key_id=key_id,
        content_type=content_type,
        payload_sha256=payload_sha256,
        issuer=issuer,
        subject=subject,
        issued_at=issued_at,
        payload=payload,
    )


def _verify_embedded_payload(
    content_type: str,
    payload_obj: dict[str, Any],
) -> str | None:
    if content_type == MEDIA_TYPE_DECISION_RECEIPT:
        try:
            signed = SignedReceipt.from_dict(payload_obj)
        except ValueError as exc:
            return f"invalid embedded SignedReceipt: {exc}"
        if not signed.verify_integrity():
            return "embedded SignedReceipt failed integrity verification"
        return None

    if content_type == MEDIA_TYPE_OUTCOME_RECEIPT:
        try:
            outcome = SignedOutcomeReceipt.from_dict(payload_obj)
        except ValueError as exc:
            return f"invalid embedded SignedOutcomeReceipt: {exc}"
        if not outcome.verify(outcome.public_key):
            return "embedded SignedOutcomeReceipt failed signature verification"
        return None

    if content_type == MEDIA_TYPE_COMPLIANCE_BUNDLE:
        digest = payload_obj.get("bundle_digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
            return "embedded ComplianceReceiptBundle missing valid bundle_digest"
        try:
            unsigned = {k: v for k, v in payload_obj.items() if k != "bundle_digest"}
            expected = "sha256:" + hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest()
        except (TypeError, ValueError) as exc:
            return f"embedded ComplianceReceiptBundle canonical JSON error: {exc}"
        if not hmac.compare_digest(expected.encode("ascii"), digest.lower().encode("ascii")):
            return "embedded ComplianceReceiptBundle bundle_digest mismatch"
    return None


def verify_scitt_cose_sign1(
    cose_bytes: bytes,
    trusted_verifiers: Mapping[str, str],
    *,
    expected_content_type: str | None = None,
    expected_issuer: str | None = None,
    external_aad: bytes = b"",
) -> SCITTVerificationResult:
    """Verify an RFC 9052 Tag 18 ``COSE_Sign1`` SCITT statement offline, fail-closed.

    Never raises on malformed CBOR, tampered payloads, untrusted keys, or bad
    signatures; returns :class:`SCITTVerificationResult` with ``valid=False``.
    Propagates :class:`~acgs_lite.legitimacy.signing.ReceiptSigningUnavailable`
    if ``cryptography`` is not installed.
    """
    if not isinstance(trusted_verifiers, Mapping) or not trusted_verifiers:
        return _fail_result("trusted_verifiers must be a non-empty mapping")
    if not isinstance(external_aad, bytes):
        return _fail_result("external_aad must be bytes")
    if not isinstance(cose_bytes, bytes) or not cose_bytes:
        return _fail_result("cose_bytes must be non-empty bytes")

    try:
        root = _cbor_decode(cose_bytes)
    except _CBORDecodeError as exc:
        return _fail_result(f"invalid CBOR envelope: {exc}")

    if not isinstance(root, _CborTag) or root.tag != SCITT_COSE_SIGN1_TAG:
        return _fail_result(f"expected CBOR tag {SCITT_COSE_SIGN1_TAG} (COSE_Sign1)")
    arr = root.value
    if not isinstance(arr, list) or len(arr) != 4:
        return _fail_result("COSE_Sign1 must be a 4-element CBOR array")

    protected_bstr, unprotected_map, payload_bstr, signature_bstr = arr
    if (
        not isinstance(protected_bstr, bytes)
        or not protected_bstr
        or not isinstance(unprotected_map, dict)
        or not isinstance(payload_bstr, bytes)
        or not isinstance(signature_bstr, bytes)
    ):
        return _fail_result("COSE_Sign1 array element types are invalid")

    try:
        protected = _cbor_decode(protected_bstr)
    except _CBORDecodeError as exc:
        return _fail_result(f"invalid COSE protected header CBOR: {exc}")

    if not isinstance(protected, dict):
        return _fail_result("COSE protected header must decode to a CBOR map")

    errors: list[str] = []
    alg = protected.get(COSE_HEADER_ALG)
    if type(alg) is not int or alg != COSE_ALG_EDDSA:
        errors.append(f"unsupported COSE alg {alg!r}; expected {COSE_ALG_EDDSA} (EdDSA)")

    cty_raw = protected.get(COSE_HEADER_CONTENT_TYPE)
    content_type = cty_raw if isinstance(cty_raw, str) and cty_raw.strip() else None
    if content_type is None:
        errors.append("COSE protected header missing valid content_type (key 3)")

    kid_raw = protected.get(COSE_HEADER_KID)
    key_id: str | None = None
    if isinstance(kid_raw, bytes) and kid_raw:
        try:
            decoded_kid = kid_raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append("COSE protected header kid (key 4) is not valid UTF-8")
        else:
            if decoded_kid.strip():
                key_id = decoded_kid
            else:
                errors.append("COSE protected header kid (key 4) must be non-empty")
    else:
        errors.append("COSE protected header missing kid byte string (key 4)")

    issuer: str | None = None
    subject: str | None = None
    issued_at: int | None = None
    if COSE_HEADER_CWT_CLAIMS in protected:
        cwt = protected[COSE_HEADER_CWT_CLAIMS]
        if not isinstance(cwt, dict):
            errors.append("COSE CWT claims header (key 15) must be a CBOR map")
        else:
            if CWT_CLAIM_ISS in cwt:
                iss_val = cwt[CWT_CLAIM_ISS]
                if isinstance(iss_val, str) and iss_val.strip():
                    issuer = iss_val
                else:
                    errors.append("CWT claim iss (1) must be a non-empty string")
            if CWT_CLAIM_SUB in cwt:
                sub_val = cwt[CWT_CLAIM_SUB]
                if isinstance(sub_val, str) and sub_val.strip():
                    subject = sub_val
                else:
                    errors.append("CWT claim sub (2) must be a non-empty string")
            if CWT_CLAIM_IAT in cwt:
                iat_val = cwt[CWT_CLAIM_IAT]
                if type(iat_val) is int and iat_val >= 0:
                    issued_at = iat_val
                else:
                    errors.append("CWT claim iat (6) must be a non-negative int")

    if expected_content_type is not None and content_type != expected_content_type:
        errors.append(
            f"unexpected content_type {content_type!r}; expected {expected_content_type!r}"
        )
    if expected_issuer is not None and issuer != expected_issuer:
        errors.append(f"unexpected issuer {issuer!r}; expected {expected_issuer!r}")

    if len(signature_bstr) != 64:
        errors.append("COSE_Sign1 EdDSA signature must be exactly 64 bytes")

    expected_pubkey: str | None = None
    if key_id is not None:
        candidate = trusted_verifiers.get(key_id)
        if not isinstance(candidate, str) or _HEX64_RE.fullmatch(candidate) is None:
            errors.append(f"untrusted or malformed verifier key for key_id {key_id!r}")
        else:
            expected_pubkey = candidate

    if expected_pubkey is not None and len(signature_bstr) == 64:
        sig_structure = _cbor_encode(["Signature1", protected_bstr, external_aad, payload_bstr])
        try:
            sig_ok = verify_signature(
                SIGNATURE_ALGORITHM,
                expected_pubkey,
                sig_structure,
                signature_bstr.hex(),
            )
        except ReceiptSigningUnavailable:
            raise
        except ValueError as exc:
            errors.append(f"signature verification error: {exc}")
        else:
            if not sig_ok:
                errors.append("COSE_Sign1 EdDSA signature verification failed")

    payload_sha256 = hashlib.sha256(payload_bstr).hexdigest()
    parsed_payload: dict[str, Any] | None = None
    try:
        decoded_json = json.loads(payload_bstr.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"payload is not valid UTF-8 JSON: {exc}")
    else:
        if not isinstance(decoded_json, dict):
            errors.append("JSON payload must decode to a JSON object")
        else:
            parsed_payload = decoded_json
            if content_type is not None:
                embedded_err = _verify_embedded_payload(content_type, parsed_payload)
                if embedded_err is not None:
                    errors.append(embedded_err)

    return SCITTVerificationResult(
        valid=not errors,
        errors=tuple(errors),
        key_id=key_id,
        content_type=content_type,
        payload_sha256=payload_sha256,
        issuer=issuer,
        subject=subject,
        issued_at=issued_at,
        payload=parsed_payload if not errors else None,
    )


__all__ = [
    "COSE_ALG_EDDSA",
    "COSE_HEADER_ALG",
    "COSE_HEADER_CONTENT_TYPE",
    "COSE_HEADER_CWT_CLAIMS",
    "COSE_HEADER_KID",
    "CWT_CLAIM_IAT",
    "CWT_CLAIM_ISS",
    "CWT_CLAIM_SUB",
    "MEDIA_TYPE_COMPLIANCE_BUNDLE",
    "MEDIA_TYPE_DECISION_RECEIPT",
    "MEDIA_TYPE_JSON",
    "MEDIA_TYPE_OUTCOME_RECEIPT",
    "SCITTExportError",
    "SCITTReceiptEnvelope",
    "SCITTVerificationResult",
    "SCITT_COSE_SIGN1_TAG",
    "export_scitt_cose_sign1",
    "verify_scitt_cose_sign1",
]
