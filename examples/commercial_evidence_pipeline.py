# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""End-to-end offline commercial evidence pipeline demonstration.

Walks through all five commercial verification stages offline with zero API keys
or external network services:
1. Constitutional enforcement + FENCEABLE effect reservation & signed receipts
2. Experimental OpenTelemetry GenAI semantic convention span attributes
3. Deterministic CA ADMT 2027 compliance receipt bundle export & verification
4. RFC 9052 SCITT COSE_Sign1 EdDSA statement export & tamper verification
5. Commercial ControlPlaneBridgeClient flow (receipt ingest, signed policy sync
   with 304 ETag caching, and fail-closed MACI escalation approval)

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import urllib.parse
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from acgs_lite.compliance import (
    PROFILE_CA_ADMT_2027,
    export_receipt_bundle,
    export_scitt_cose_sign1,
    verify_receipt_bundle,
    verify_scitt_cose_sign1,
)
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.control_plane.cloud_bridge import (
    BridgeResponse,
    CloudBridgeConfig,
    CloudBridgeError,
    ControlPlaneBridgeClient,
    canonical_json_str,
    policy_bundle_signing_message,
)
from acgs_lite.engine.core import GovernanceEngine
from acgs_lite.integrations.otel import GEN_AI_OPERATION_EXECUTE_TOOL, GenAIGovernanceTracer
from acgs_lite.legitimacy import (
    ContractedEffectStore,
    DecisionReceipt,
    Ed25519ReceiptSigner,
    EffectOutcome,
    EffectRequest,
    EffectStore,
    ExecutionAuthority,
    ExecutionBoundary,
    ProviderContract,
    ProviderContractClass,
    ProviderContractRegistry,
    ProviderResult,
    bind_invocation,
    bind_policy,
    local_grant_identity,
    outcome_from_record,
    sign_execution_authorization,
    sign_outcome,
    sign_receipt,
)
from acgs_lite.legitimacy.authorization import (
    authorization_envelope_json,
    build_issue_receipt,
    engine_decision_from_results,
)


def _charge_customer(operation: str, *, scope: str, subject: str) -> dict[str, str]:
    return {"operation": operation, "scope": scope, "subject": subject}


class _InMemoryPaymentProvider:
    contract = ProviderContract(
        provider_id="stripe-demo",
        contract_class=ProviderContractClass.FENCEABLE,
        version="1.0",
        dedup_by_key=True,
        atomic_query_fence=True,
    )

    def __init__(self) -> None:
        self.sends: list[EffectRequest] = []

    @property
    def provider_id(self) -> str:
        return self.contract.provider_id

    def send(self, request: EffectRequest) -> ProviderResult:
        self.sends.append(request)
        return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE, fenced=True)

    def query_and_fence(self, request: EffectRequest) -> ProviderResult:
        return ProviderResult(request.key, self.provider_id, EffectOutcome.NOT_DONE, fenced=True)


class _InMemoryControlPlaneTransport:
    """In-memory mock of acgs-control-plane v1 commercial bridge endpoints."""

    def __init__(self, *, org_id: str, cp_signer: Ed25519ReceiptSigner) -> None:
        self._org_id = org_id
        self._cp_signer = cp_signer
        self._policy = {
            "name": "commercial-prod-policy",
            "version": "2026.11",
            "rules": [{"id": "NO-RAW-SSN", "severity": "critical"}],
        }
        self._policy_digest = (
            "sha256:" + hashlib.sha256(canonical_json_str(self._policy).encode("utf-8")).hexdigest()
        )
        self._issued_at = "2026-11-27T12:00:00Z"
        self.ingested_batches: list[list[dict[str, Any]]] = []

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,  # noqa: ARG002
    ) -> BridgeResponse:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path

        if method == "POST" and path.endswith("/receipts/ingest"):
            payload = json.loads((body or b"{}").decode("utf-8"))
            items = payload.get("items", [])
            self.ingested_batches.append(items)
            ingest_resp: dict[str, Any] = {
                "accepted_count": len(items),
                "deduplicated_count": 0,
                "rejected_count": 0,
            }
            return BridgeResponse(
                status=200,
                headers={"Content-Type": "application/json"},
                body=canonical_json_str(ingest_resp).encode("utf-8"),
            )

        if method == "GET" and path.endswith("/policies/active/bundle"):
            if headers.get("If-None-Match") == self._policy_digest:
                return BridgeResponse(status=304, headers={"ETag": self._policy_digest}, body=b"")
            params = urllib.parse.parse_qs(parsed.query)
            env_id = params.get("environment_id", ["prod"])[0]
            msg = policy_bundle_signing_message(
                org_id=self._org_id,
                environment_id=env_id,
                policy_digest=self._policy_digest,
                issued_at=self._issued_at,
            )
            policy_resp: dict[str, Any] = {
                "algorithm": self._cp_signer.algorithm,
                "bundle": self._policy,
                "issued_at": self._issued_at,
                "key_id": self._cp_signer.key_id,
                "policy_digest": self._policy_digest,
                "signature": self._cp_signer.sign(msg),
            }
            return BridgeResponse(
                status=200,
                headers={"Content-Type": "application/json", "ETag": self._policy_digest},
                body=canonical_json_str(policy_resp).encode("utf-8"),
            )

        if method == "POST" and path.endswith("/escalations/esc-self-conflict/decide"):
            return BridgeResponse(
                status=409,
                headers={"Content-Type": "application/json"},
                body=b'{"detail":"MACI conflict: approver equals proposer"}',
            )

        if method == "POST" and path.endswith("/decide"):
            decide_resp: dict[str, Any] = {
                "escalation_id": "esc-commercial-1",
                "status": "approved",
                "decision_receipt": {"receipt": {"decision_type": "ALLOW_WITH_CONTROLS"}},
                "resume_token": "resume-commercial-demo-1",
            }
            return BridgeResponse(
                status=200,
                headers={"Content-Type": "application/json"},
                body=canonical_json_str(decide_resp).encode("utf-8"),
            )

        return BridgeResponse(status=404, headers={}, body=b"not found")


def run_pipeline() -> dict[str, Any]:
    """Run all five commercial governance and cryptographic evidence stages offline."""
    org_signer = Ed25519ReceiptSigner.from_seed(
        b"commercial-org-signer-2026-11".ljust(32, b"!")[:32], key_id="org-k1"
    )
    cp_signer = Ed25519ReceiptSigner.from_seed(
        b"commercial-cp-signer-2026-11".ljust(32, b"!")[:32], key_id="cp-k1"
    )
    trusted_org_keys = {org_signer.key_id: org_signer.public_key_hex()}

    constitution = Constitution(
        name="commercial-pipeline-demo",
        version="2026.11",
        rules=[
            Rule(
                id="NO-RAW-SSN",
                text="Block unredacted SSN transmission",
                severity=Severity.CRITICAL,
                keywords=["raw_ssn"],
            )
        ],
    )
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    provider = _InMemoryPaymentProvider()
    registry = ProviderContractRegistry()
    registry.register(provider.contract)

    # Stage 1: Governed execution + FENCEABLE effect + signed DecisionReceipt & OutcomeReceipt
    allow_op = "refund order ord-9001"
    allow_result = engine.validate(allow_op, agent_id="agent-proposer")
    invocation = bind_invocation(
        _charge_customer,
        (allow_op,),
        {"scope": "prod-billing", "subject": "acct-9001"},
    )
    policy = bind_policy(constitution)
    decision = engine_decision_from_results([allow_result])
    grant_id = authority.allocate_grant_id()
    try:
        decision_receipt = build_issue_receipt(
            func=_charge_customer,
            invocation=invocation,
            policy=policy,
            decision=decision,
            grant_id=grant_id,
        )
        signed_decision = sign_execution_authorization(
            decision_receipt,
            org_signer,
            authorization_json=authorization_envelope_json(invocation, policy, grant_id=grant_id),
        )
        grant = authority.issue(
            receipt=decision_receipt,
            invocation=invocation,
            policy=policy,
            grant_id=grant_id,
            signed_receipt=signed_decision,
        )
    finally:
        authority.release_grant_id(grant_id)

    with tempfile.TemporaryDirectory(prefix="acgs-commercial-pipeline-") as tmp_dir:
        effect_store = EffectStore(Path(tmp_dir) / "effects.sqlite3")
        effect_store.create_budget("billing", 100)
        contracted = ContractedEffectStore(effect_store, registry)

        record = effect_store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(grant),
            action={"op": allow_op, "order_id": "ord-9001"},
            budget_id="billing",
            amount=1,
        )
        settled = contracted.send(record.key, provider, grant=grant)
        outcome_receipt = outcome_from_record(
            settled,
            store=contracted,
            provider=provider,
            grant=grant,
            provider_reference="ch_commercial_9001",
            recorded_at=datetime.now(timezone.utc).isoformat(),
        )
        signed_outcome = sign_outcome(outcome_receipt, org_signer)

    # Blocked call triggers zero provider dispatches
    sends_before_deny = len(provider.sends)
    deny_result = engine.validate("export raw_ssn dump", agent_id="agent-proposer")
    deny_receipt = DecisionReceipt.create(
        request_id="req-deny-raw-ssn",
        goal="export raw_ssn dump",
        proposed_method="_charge_customer",
        decision_type="DENY_GOAL",
        authority_basis=constitution.hash,
        matched_constraints=("NO-RAW-SSN",),
        policy_version=constitution.version,
        denial_or_review_rationale="Blocked by rule NO-RAW-SSN",
        execution_boundary=ExecutionBoundary(
            allowed_method="_charge_customer",
            allowed_scope="prod-billing",
            allowed_subjects=("acct-9001",),
            expires_at="2027-12-31T00:00:00Z",
            single_use=True,
        ),
    )
    signed_deny = sign_receipt(deny_receipt, org_signer)
    deny_zero_dispatch = not deny_result.valid and len(provider.sends) == sends_before_deny

    # Stage 2: Experimental OpenTelemetry GenAI semantic spans (safe noop if SDK absent)
    tracer = GenAIGovernanceTracer()
    span_attrs = tracer.record_receipt_span(
        tool_name="_charge_customer",
        signed_receipt=signed_decision,
        signed_outcome=signed_outcome,
        agent_id="agent-proposer",
        contract_class="FENCEABLE",
    )
    otel_ok = (
        span_attrs["gen_ai.operation.name"] == GEN_AI_OPERATION_EXECUTE_TOOL
        and span_attrs["acgs.outcome.status"] == "DONE"
        and "ch_commercial_9001" not in repr(span_attrs)
    )

    # Stage 3: Deterministic CA ADMT 2027 compliance receipt bundle
    bundle = export_receipt_bundle(
        [signed_decision, signed_deny],
        outcome_receipts=[signed_outcome],
        profile=PROFILE_CA_ADMT_2027,
        trusted_public_keys=trusted_org_keys,
        system_id="billing-pipeline",
        retention_days=365,
    )
    bundle_ver = verify_receipt_bundle(bundle.to_dict(), trusted_public_keys=trusted_org_keys)

    # Stage 4: RFC 9052 SCITT COSE_Sign1 wrapper & offline verification
    cose_env = export_scitt_cose_sign1(
        bundle,
        org_signer,
        issuer="did:web:acgs.example",
        subject="system:billing-pipeline",
    )
    scitt_ver = verify_scitt_cose_sign1(
        cose_env.cose_bytes,
        trusted_org_keys,
        expected_issuer="did:web:acgs.example",
    )

    # Stage 5: Commercial Cloud Bridge client workflow
    transport = _InMemoryControlPlaneTransport(org_id="acme-fin", cp_signer=cp_signer)
    bridge = ControlPlaneBridgeClient(
        CloudBridgeConfig(
            base_url="https://cloud.acgs.ai",
            org_id="acme-fin",
            api_key="demo-bridge-key",
            trusted_control_plane_keys={cp_signer.key_id: cp_signer.public_key_hex()},
        ),
        transport=transport,
    )
    ingest_res = bridge.ingest_receipts(
        [signed_decision.to_dict(), signed_outcome.to_dict()],
        idempotency_key="batch-commercial-1",
    )
    sync_200 = bridge.fetch_active_policy_bundle(environment_id="prod")
    sync_304 = bridge.fetch_active_policy_bundle(
        environment_id="prod",
        cached_etag=sync_200.etag,
    )
    decide_ok = bridge.decide_escalation(
        "esc-commercial-1",
        decision="approve",
        rationale="Verified distinct human operator approval",
        display_digest="sha256:" + "a" * 64,
    )
    maci_conflict_blocked = False
    try:
        bridge.decide_escalation(
            "esc-self-conflict",
            decision="approve",
            rationale="Attempted self-approval",
            display_digest="sha256:" + "b" * 64,
        )
    except CloudBridgeError:
        maci_conflict_blocked = True

    all_passed = all(
        (
            signed_decision.verify(trusted_org_keys[org_signer.key_id]),
            signed_outcome.verify(trusted_org_keys[org_signer.key_id]),
            deny_zero_dispatch,
            otel_ok,
            bundle_ver.valid,
            scitt_ver.valid,
            ingest_res.accepted_count == 2,
            not sync_200.not_modified and sync_200.bundle is not None,
            sync_304.not_modified,
            decide_ok.status == "approved" and decide_ok.resume_token is not None,
            maci_conflict_blocked,
        )
    )
    return {
        "all_passed": all_passed,
        "provider_sends": len(provider.sends),
        "deny_zero_dispatch": deny_zero_dispatch,
        "otel_span_operation": span_attrs["gen_ai.operation.name"],
        "bundle_digest": bundle.bundle_digest,
        "bundle_valid": bundle_ver.valid,
        "scitt_payload_sha256": cose_env.payload_sha256,
        "scitt_valid": scitt_ver.valid,
        "bridge_ingested_count": ingest_res.accepted_count,
        "bridge_policy_cached_304": sync_304.not_modified,
        "bridge_maci_conflict_blocked": maci_conflict_blocked,
    }


def main() -> int:
    summary = run_pipeline()
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
