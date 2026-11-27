"""Tests for SDK control-plane commercial bridge client."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from acgs_lite.control_plane.cloud_bridge import (
    BridgeResponse,
    CloudBridgeConfig,
    CloudBridgeError,
    ControlPlaneBridgeClient,
    PolicyBundleVerificationError,
    UrllibBridgeTransport,
    canonical_json_str,
    policy_bundle_signing_message,
)
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner


class _RecordingTransport:
    def __init__(self, responses: list[BridgeResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Any,
        body: bytes | None,
        timeout_seconds: float,
    ) -> BridgeResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_seconds": timeout_seconds,
            }
        )
        return self._responses.pop(0)


def test_config_validation_fails_closed() -> None:
    with pytest.raises(CloudBridgeError, match="org_id"):
        CloudBridgeConfig(base_url="https://api.acgs.ai", org_id="  ", api_key="k")
    with pytest.raises(CloudBridgeError, match="api_key"):
        CloudBridgeConfig(base_url="https://api.acgs.ai", org_id="org-1", api_key="")
    with pytest.raises(CloudBridgeError, match="max_batch_size"):
        CloudBridgeConfig(
            base_url="https://api.acgs.ai", org_id="org-1", api_key="k", max_batch_size=101
        )
    with pytest.raises(CloudBridgeError, match="timeout_seconds"):
        CloudBridgeConfig(
            base_url="https://api.acgs.ai", org_id="org-1", api_key="k", timeout_seconds=0
        )
    with pytest.raises(CloudBridgeError, match="base_url"):
        CloudBridgeConfig(base_url="ftp://api.acgs.ai", org_id="org-1", api_key="k")
    with pytest.raises(CloudBridgeError, match="plaintext HTTP"):
        CloudBridgeConfig(base_url="http://remote.example.com", org_id="org-1", api_key="k")

    local = CloudBridgeConfig(base_url="http://127.0.0.1:8080/", org_id="org-1", api_key="k")
    assert local.base_url == "http://127.0.0.1:8080"


def test_ingest_receipts_and_decide_escalation() -> None:
    resp_ingest = BridgeResponse(
        status=200,
        headers={"content-type": "application/json"},
        body=json.dumps(
            {"accepted_count": 1, "deduplicated_count": 0, "rejected_count": 0}
        ).encode(),
    )
    resp_decide = BridgeResponse(
        status=200,
        headers={"content-type": "application/json"},
        body=json.dumps(
            {
                "escalation_id": "esc-1",
                "status": "approved",
                "decision_receipt": {"receipt": {"decision_type": "ALLOW_WITH_CONTROLS"}},
                "resume_token": "tok-abc",
            }
        ).encode(),
    )
    transport = _RecordingTransport([resp_ingest, resp_decide])
    cfg = CloudBridgeConfig(base_url="https://cloud.acgs.ai", org_id="org/1", api_key="sec-key")
    client = ControlPlaneBridgeClient(cfg, transport=transport)

    with pytest.raises(CloudBridgeError, match="at least 1"):
        client.ingest_receipts([])
    with pytest.raises(CloudBridgeError, match="idempotency_key"):
        client.ingest_receipts([{"a": 1}], idempotency_key=" ")
    with pytest.raises(CloudBridgeError, match="must be a mapping"):
        client.ingest_receipts(["bad"])  # type: ignore[list-item]

    res = client.ingest_receipts([{"receipt_id": "r1"}], idempotency_key="batch-1")
    assert res.accepted_count == 1
    assert transport.calls[0]["url"] == "https://cloud.acgs.ai/v1/orgs/org%2F1/receipts/ingest"
    assert transport.calls[0]["headers"]["Idempotency-Key"] == "batch-1"
    assert transport.calls[0]["headers"]["X-API-Key"] == "sec-key"

    with pytest.raises(CloudBridgeError, match="escalation_id"):
        client.decide_escalation("", decision="approve", rationale="ok", display_digest="sha256:aa")
    with pytest.raises(CloudBridgeError, match="'approve' or 'deny'"):
        client.decide_escalation("e1", decision="maybe", rationale="ok", display_digest="sha256:aa")
    with pytest.raises(CloudBridgeError, match="rationale"):
        client.decide_escalation("e1", decision="approve", rationale="", display_digest="sha256:aa")
    with pytest.raises(CloudBridgeError, match="display_digest"):
        client.decide_escalation("e1", decision="approve", rationale="ok", display_digest="")

    dec = client.decide_escalation(
        "esc-1", decision="approve", rationale="verified", display_digest="sha256:1234"
    )
    assert dec.status == "approved"
    assert dec.resume_token == "tok-abc"
    assert (
        transport.calls[1]["url"]
        == "https://cloud.acgs.ai/v1/orgs/org%2F1/escalations/esc-1/decide"
    )


def test_ingest_batch_limit_and_http_errors() -> None:
    cfg = CloudBridgeConfig(
        base_url="https://cloud.acgs.ai", org_id="o1", api_key="k1", max_batch_size=1
    )
    transport = _RecordingTransport(
        [
            BridgeResponse(status=403, headers={}, body=b"forbidden"),
            BridgeResponse(status=409, headers={}, body=b"conflict maci"),
        ]
    )
    client = ControlPlaneBridgeClient(cfg, transport=transport)

    with pytest.raises(CloudBridgeError, match="max_batch_size"):
        client.ingest_receipts([{"a": 1}, {"a": 2}])
    with pytest.raises(CloudBridgeError, match="HTTP 403"):
        client.ingest_receipts([{"a": 1}])
    with pytest.raises(CloudBridgeError, match="HTTP 409"):
        client.decide_escalation(
            "e1", decision="deny", rationale="nope", display_digest="sha256:aa"
        )


def test_fetch_active_policy_bundle_verifies_ed25519_and_handles_304() -> None:
    pytest.importorskip("cryptography")
    import hashlib

    signer = Ed25519ReceiptSigner.from_seed(b"\x31" * 32, key_id="cp-key-1")
    other = Ed25519ReceiptSigner.from_seed(b"\x32" * 32, key_id="cp-key-2")
    bundle_obj = {
        "name": "prod-rules",
        "rules": [{"id": "R1", "keywords": ["wire"], "severity": "critical"}],
    }
    policy_digest = (
        "sha256:" + hashlib.sha256(canonical_json_str(bundle_obj).encode("utf-8")).hexdigest()
    )
    issued_at = "2026-11-27T12:00:00Z"
    sig = signer.sign(
        policy_bundle_signing_message(
            org_id="org-1",
            environment_id="prod",
            policy_digest=policy_digest,
            issued_at=issued_at,
        )
    )
    ok_payload = {
        "bundle": bundle_obj,
        "policy_digest": policy_digest,
        "issued_at": issued_at,
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "signature": sig,
    }
    resp_200 = BridgeResponse(
        status=200,
        headers={"ETag": f'"{policy_digest}"'},
        body=json.dumps(ok_payload).encode(),
    )
    resp_304 = BridgeResponse(status=304, headers={}, body=b"")
    bad_digest_payload = {**ok_payload, "policy_digest": "sha256:" + "0" * 64}
    resp_bad_digest = BridgeResponse(
        status=200, headers={}, body=json.dumps(bad_digest_payload).encode()
    )
    unknown_key_payload = {**ok_payload, "key_id": other.key_id}
    resp_unknown_key = BridgeResponse(
        status=200, headers={}, body=json.dumps(unknown_key_payload).encode()
    )
    bad_sig_payload = {**ok_payload, "signature": "00" * 64}
    resp_bad_sig = BridgeResponse(status=200, headers={}, body=json.dumps(bad_sig_payload).encode())
    bad_alg_payload = {**ok_payload, "algorithm": "rsa"}
    resp_bad_alg = BridgeResponse(status=200, headers={}, body=json.dumps(bad_alg_payload).encode())
    resp_err = BridgeResponse(status=500, headers={}, body=b"oops")

    transport = _RecordingTransport(
        [
            resp_200,
            resp_304,
            resp_bad_digest,
            resp_unknown_key,
            resp_bad_sig,
            resp_bad_alg,
            resp_err,
        ]
    )
    cfg = CloudBridgeConfig(
        base_url="https://cloud.acgs.ai",
        org_id="org-1",
        api_key="k1",
        trusted_control_plane_keys={signer.key_id: signer.public_key_hex()},
    )
    client = ControlPlaneBridgeClient(cfg, transport=transport)

    with pytest.raises(CloudBridgeError, match="environment_id"):
        client.fetch_active_policy_bundle(environment_id=" ")

    res = client.fetch_active_policy_bundle(environment_id="prod")
    assert res.not_modified is False
    assert res.bundle == bundle_obj
    assert res.policy_digest == policy_digest

    cached = client.fetch_active_policy_bundle(environment_id="prod", cached_etag=res.etag)
    assert cached.not_modified is True
    assert transport.calls[1]["headers"]["If-None-Match"] == res.etag

    with pytest.raises(PolicyBundleVerificationError, match="digest mismatch"):
        client.fetch_active_policy_bundle(environment_id="prod")
    with pytest.raises(PolicyBundleVerificationError, match="Untrusted control-plane"):
        client.fetch_active_policy_bundle(environment_id="prod")
    with pytest.raises(PolicyBundleVerificationError, match="Invalid Ed25519"):
        client.fetch_active_policy_bundle(environment_id="prod")
    with pytest.raises(PolicyBundleVerificationError, match="Unsupported policy bundle"):
        client.fetch_active_policy_bundle(environment_id="prod")
    with pytest.raises(CloudBridgeError, match="HTTP 500"):
        client.fetch_active_policy_bundle(environment_id="prod")


def test_urllib_bridge_transport_against_loopback_http() -> None:
    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            if self.path.endswith("/decide"):
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b'{"detail":"maci_conflict"}')
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"accepted_count": 1, "deduplicated_count": 0, "rejected_count": 0}')

        def log_message(self, format: str, *args: Any) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = CloudBridgeConfig(
            base_url=f"http://127.0.0.1:{port}",
            org_id="org-loop",
            api_key="loop-key",
        )
        client = ControlPlaneBridgeClient(cfg, transport=UrllibBridgeTransport())
        ok = client.ingest_receipts([{"id": "1"}])
        assert ok.accepted_count == 1
        with pytest.raises(CloudBridgeError, match="HTTP 409"):
            client.decide_escalation(
                "esc", decision="approve", rationale="r", display_digest="sha256:aa"
            )
        with pytest.raises(CloudBridgeError, match="Unsupported URL scheme"):
            UrllibBridgeTransport().request(
                method="GET", url="ftp://127.0.0.1/x", headers={}, body=None, timeout_seconds=1.0
            )
    finally:
        server.shutdown()
        server.server_close()
