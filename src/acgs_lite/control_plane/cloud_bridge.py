"""SDK client for the commercial ``acgs-control-plane`` bridge APIs.

Implements fail-closed HTTP clients matching the v1 commercial bridge contracts:
- ``POST /v1/orgs/{org_id}/receipts/ingest`` (signed decision/outcome receipt batch)
- ``GET /v1/orgs/{org_id}/policies/active/bundle`` (ETag/304 + Ed25519 verified policy sync)
- ``POST /v1/orgs/{org_id}/escalations/{escalation_id}/decide`` (MACI-checked human decision)

Uses Python's stdlib ``urllib`` only (no extra runtime dependencies) with
pluggable ``BridgeHttpTransport`` for deterministic testing.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from acgs_lite.legitimacy.signing import (
    SIGNATURE_ALGORITHM,
    ReceiptSigningUnavailable,
    verify_signature,
)

POLICY_BUNDLE_SIGNING_DOMAIN = b"acgs-policy-bundle-v1\x00"


class CloudBridgeError(RuntimeError):
    """Raised when a control-plane bridge call or input validation fails closed."""


class PolicyBundleVerificationError(CloudBridgeError):
    """Raised when a synced active policy bundle fails digest or Ed25519 verification."""


@dataclass(frozen=True)
class BridgeResponse:
    """Raw HTTP response returned by a :class:`BridgeHttpTransport`."""

    status: int
    headers: Mapping[str, str]
    body: bytes


class BridgeHttpTransport(Protocol):
    """Minimal HTTP transport protocol for the commercial bridge client."""

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> BridgeResponse:
        """Send an HTTP request and return a :class:`BridgeResponse`."""


@dataclass(frozen=True)
class CloudBridgeConfig:
    """Validated connection configuration for :class:`ControlPlaneBridgeClient`."""

    base_url: str
    org_id: str
    api_key: str
    trusted_control_plane_keys: Mapping[str, str] = field(default_factory=dict)
    timeout_seconds: float = 10.0
    max_batch_size: int = 100
    allow_insecure_http: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.org_id, str) or not self.org_id.strip():
            raise CloudBridgeError("org_id must be a non-empty string")
        if not isinstance(self.api_key, str) or not self.api_key.strip():
            raise CloudBridgeError("api_key must be a non-empty string")
        if type(self.max_batch_size) is not int or not (1 <= self.max_batch_size <= 100):
            raise CloudBridgeError("max_batch_size must be an integer between 1 and 100")
        if isinstance(self.timeout_seconds, bool) or not (
            isinstance(self.timeout_seconds, (int, float)) and self.timeout_seconds > 0
        ):
            raise CloudBridgeError("timeout_seconds must be a positive number")
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise CloudBridgeError("base_url must be a valid http(s) URL")
        host = (parsed.hostname or "").lower()
        is_local = host in ("localhost", "127.0.0.1", "::1")
        if parsed.scheme != "https" and not is_local and not self.allow_insecure_http:
            raise CloudBridgeError(
                "Refusing plaintext HTTP base_url for non-localhost endpoints; "
                "set allow_insecure_http=True only in local/trusted test environments"
            )
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail closed on HTTP redirects so API keys never cross origins or protocol boundaries."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if fp is not None:
            fp.close()
        raise CloudBridgeError(
            f"Control-plane redirect refused (HTTP {code}): "
            "automatic redirects are disabled to prevent credential leakage"
        )


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


class UrllibBridgeTransport:
    """Stdlib ``urllib.request`` implementation of :class:`BridgeHttpTransport`."""

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> BridgeResponse:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("https", "http"):
            raise CloudBridgeError(f"Unsupported URL scheme: {parsed.scheme!r}")
        req = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers=dict(headers),
        )
        try:
            with _NO_REDIRECT_OPENER.open(req, timeout=timeout_seconds) as resp:  # noqa: S310
                return BridgeResponse(
                    status=int(getattr(resp, "status", 200)),
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=resp.read(),
                )
        except urllib.error.HTTPError as exc:
            return BridgeResponse(
                status=int(exc.code),
                headers={k.lower(): v for k, v in exc.headers.items()} if exc.headers else {},
                body=exc.read(),
            )
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise CloudBridgeError(f"Control-plane transport error: {exc}") from exc


@dataclass(frozen=True)
class ReceiptIngestResult:
    """Structured result from ``POST /v1/orgs/{org_id}/receipts/ingest``."""

    accepted_count: int
    deduplicated_count: int
    rejected_count: int
    raw: dict[str, Any]


@dataclass(frozen=True)
class PolicyBundleSyncResult:
    """Structured result from ``GET /v1/orgs/{org_id}/policies/active/bundle``."""

    not_modified: bool
    environment_id: str
    etag: str | None
    policy_digest: str | None
    issued_at: str | None
    key_id: str | None
    bundle: dict[str, Any] | None


@dataclass(frozen=True)
class EscalationDecisionResult:
    """Structured result from ``POST /v1/orgs/{org_id}/escalations/{id}/decide``."""

    escalation_id: str
    status: str
    decision_receipt: dict[str, Any] | None
    resume_token: str | None
    raw: dict[str, Any]


def canonical_json_str(value: Any) -> str:
    """Serialize *value* as compact canonical JSON."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def policy_bundle_signing_message(
    *,
    org_id: str,
    environment_id: str,
    policy_digest: str,
    issued_at: str,
) -> bytes:
    """Return the exact Ed25519 signing message authenticating an active policy bundle."""
    payload = canonical_json_str(
        {
            "environment_id": environment_id,
            "issued_at": issued_at,
            "org_id": org_id,
            "policy_digest": policy_digest,
        }
    )
    return POLICY_BUNDLE_SIGNING_DOMAIN + payload.encode("utf-8")


def _parse_json_object(body: bytes, *, context: str) -> dict[str, Any]:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloudBridgeError(f"{context}: invalid JSON response ({exc})") from exc
    if not isinstance(parsed, dict):
        raise CloudBridgeError(f"{context}: expected JSON object response")
    return parsed


def _header_ci(headers: Mapping[str, str], name: str) -> str | None:
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


class ControlPlaneBridgeClient:
    """Client for ACGS-Lite <-> ACGS Control Plane commercial bridge endpoints."""

    def __init__(
        self,
        config: CloudBridgeConfig,
        transport: BridgeHttpTransport | None = None,
    ) -> None:
        self._config = config
        self._transport: BridgeHttpTransport = (
            transport if transport is not None else UrllibBridgeTransport()
        )

    @property
    def config(self) -> CloudBridgeConfig:
        return self._config

    def _org_segment(self) -> str:
        return urllib.parse.quote(self._config.org_id, safe="")

    def _base_headers(self, *, content_type_json: bool = True) -> dict[str, str]:
        headers = {
            "X-API-Key": self._config.api_key,
            "Accept": "application/json",
        }
        if content_type_json:
            headers["Content-Type"] = "application/json"
        return headers

    def ingest_receipts(
        self,
        items: Sequence[Mapping[str, Any]],
        *,
        idempotency_key: str | None = None,
    ) -> ReceiptIngestResult:
        """Upload a bounded batch of signed decision/outcome receipts to the Cloud ledger."""
        if not items:
            raise CloudBridgeError("ingest_receipts requires at least 1 item")
        if len(items) > self._config.max_batch_size:
            raise CloudBridgeError(
                f"Batch size {len(items)} exceeds max_batch_size={self._config.max_batch_size}"
            )
        serialized_items: list[dict[str, Any]] = []
        for idx, item in enumerate(items):
            if not isinstance(item, Mapping):
                raise CloudBridgeError(f"items[{idx}] must be a mapping")
            serialized_items.append(dict(item))

        headers = self._base_headers(content_type_json=True)
        if idempotency_key is not None:
            if not idempotency_key.strip():
                raise CloudBridgeError("idempotency_key cannot be blank")
            headers["Idempotency-Key"] = idempotency_key

        url = f"{self._config.base_url}/v1/orgs/{self._org_segment()}/receipts/ingest"
        body = canonical_json_str({"items": serialized_items}).encode("utf-8")
        resp = self._transport.request(
            method="POST",
            url=url,
            headers=headers,
            body=body,
            timeout_seconds=self._config.timeout_seconds,
        )
        if not (200 <= resp.status < 300):
            raise CloudBridgeError(
                f"ingest_receipts failed with HTTP {resp.status}: "
                f"{resp.body.decode('utf-8', errors='replace')[:300]}"
            )
        data = _parse_json_object(resp.body, context="ingest_receipts")
        return ReceiptIngestResult(
            accepted_count=int(data.get("accepted_count", len(serialized_items))),
            deduplicated_count=int(data.get("deduplicated_count", 0)),
            rejected_count=int(data.get("rejected_count", 0)),
            raw=data,
        )

    def fetch_active_policy_bundle(
        self,
        *,
        environment_id: str,
        cached_etag: str | None = None,
    ) -> PolicyBundleSyncResult:
        """Fetch and cryptographically verify the active signed policy bundle."""
        if not isinstance(environment_id, str) or not environment_id.strip():
            raise CloudBridgeError("environment_id must be a non-empty string")
        headers = self._base_headers(content_type_json=False)
        if cached_etag is not None and cached_etag.strip():
            headers["If-None-Match"] = cached_etag.strip()

        query = urllib.parse.urlencode({"environment_id": environment_id})
        url = (
            f"{self._config.base_url}/v1/orgs/{self._org_segment()}/policies/active/bundle?{query}"
        )
        resp = self._transport.request(
            method="GET",
            url=url,
            headers=headers,
            body=None,
            timeout_seconds=self._config.timeout_seconds,
        )
        etag = _header_ci(resp.headers, "etag")
        if resp.status == 304:
            return PolicyBundleSyncResult(
                not_modified=True,
                environment_id=environment_id,
                etag=etag or cached_etag,
                policy_digest=None,
                issued_at=None,
                key_id=None,
                bundle=None,
            )
        if not (200 <= resp.status < 300):
            raise CloudBridgeError(
                f"fetch_active_policy_bundle failed with HTTP {resp.status}: "
                f"{resp.body.decode('utf-8', errors='replace')[:300]}"
            )
        data = _parse_json_object(resp.body, context="fetch_active_policy_bundle")
        bundle = data.get("bundle")
        policy_digest = data.get("policy_digest")
        issued_at = data.get("issued_at")
        algorithm = data.get("algorithm", SIGNATURE_ALGORITHM)
        key_id = data.get("key_id")
        signature = data.get("signature")

        if not isinstance(bundle, dict):
            raise PolicyBundleVerificationError("Policy bundle payload missing 'bundle' object")
        for field_name, val in (
            ("policy_digest", policy_digest),
            ("issued_at", issued_at),
            ("key_id", key_id),
            ("signature", signature),
        ):
            if not isinstance(val, str) or not val.strip():
                raise PolicyBundleVerificationError(
                    f"Policy bundle response missing non-empty {field_name}"
                )
        if not isinstance(algorithm, str) or algorithm != SIGNATURE_ALGORITHM:
            raise PolicyBundleVerificationError(
                f"Unsupported policy bundle signature algorithm: {algorithm!r}"
            )

        assert isinstance(policy_digest, str)
        assert isinstance(issued_at, str)
        assert isinstance(key_id, str)
        assert isinstance(signature, str)

        computed_digest = (
            "sha256:" + hashlib.sha256(canonical_json_str(bundle).encode("utf-8")).hexdigest()
        )
        if not hmac.compare_digest(computed_digest, policy_digest):
            raise PolicyBundleVerificationError(
                f"Policy bundle digest mismatch: expected {computed_digest}, got {policy_digest}"
            )

        trusted_pk = self._config.trusted_control_plane_keys.get(key_id)
        if not isinstance(trusted_pk, str) or not trusted_pk.strip():
            raise PolicyBundleVerificationError(f"Untrusted control-plane key_id {key_id!r}")

        message = policy_bundle_signing_message(
            org_id=self._config.org_id,
            environment_id=environment_id,
            policy_digest=policy_digest,
            issued_at=issued_at,
        )
        try:
            sig_ok = verify_signature(algorithm, trusted_pk, message, signature)
        except (ReceiptSigningUnavailable, ValueError) as exc:
            raise PolicyBundleVerificationError(
                f"Policy signature verification failed: {exc}"
            ) from exc
        if not sig_ok:
            raise PolicyBundleVerificationError("Invalid Ed25519 signature on active policy bundle")

        return PolicyBundleSyncResult(
            not_modified=False,
            environment_id=environment_id,
            etag=etag or policy_digest,
            policy_digest=policy_digest,
            issued_at=issued_at,
            key_id=key_id,
            bundle=bundle,
        )

    def decide_escalation(
        self,
        escalation_id: str,
        *,
        decision: str,
        rationale: str,
        display_digest: str,
    ) -> EscalationDecisionResult:
        """Submit an explicit human approve/deny decision bound to ``display_digest``."""
        if not isinstance(escalation_id, str) or not escalation_id.strip():
            raise CloudBridgeError("escalation_id must be a non-empty string")
        if decision not in ("approve", "deny"):
            raise CloudBridgeError("decision must be 'approve' or 'deny'")
        if not isinstance(rationale, str) or not rationale.strip():
            raise CloudBridgeError("rationale must be a non-empty string")
        if not isinstance(display_digest, str) or not display_digest.strip():
            raise CloudBridgeError("display_digest must be a non-empty string")

        esc_seg = urllib.parse.quote(escalation_id, safe="")
        url = f"{self._config.base_url}/v1/orgs/{self._org_segment()}/escalations/{esc_seg}/decide"
        body = canonical_json_str(
            {
                "decision": decision,
                "display_digest": display_digest,
                "rationale": rationale,
            }
        ).encode("utf-8")
        resp = self._transport.request(
            method="POST",
            url=url,
            headers=self._base_headers(content_type_json=True),
            body=body,
            timeout_seconds=self._config.timeout_seconds,
        )
        if not (200 <= resp.status < 300):
            raise CloudBridgeError(
                f"decide_escalation failed with HTTP {resp.status}: "
                f"{resp.body.decode('utf-8', errors='replace')[:300]}"
            )
        data = _parse_json_object(resp.body, context="decide_escalation")
        dec_receipt = data.get("decision_receipt")
        resume_tok = data.get("resume_token")
        return EscalationDecisionResult(
            escalation_id=str(data.get("escalation_id", escalation_id)),
            status=str(data.get("status", decision)),
            decision_receipt=dec_receipt if isinstance(dec_receipt, dict) else None,
            resume_token=resume_tok if isinstance(resume_tok, str) else None,
            raw=data,
        )


__all__ = [
    "POLICY_BUNDLE_SIGNING_DOMAIN",
    "BridgeHttpTransport",
    "BridgeResponse",
    "CloudBridgeConfig",
    "CloudBridgeError",
    "ControlPlaneBridgeClient",
    "EscalationDecisionResult",
    "PolicyBundleSyncResult",
    "PolicyBundleVerificationError",
    "ReceiptIngestResult",
    "UrllibBridgeTransport",
    "canonical_json_str",
    "policy_bundle_signing_message",
]
