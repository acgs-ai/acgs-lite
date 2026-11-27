"""Signed outbound webhook FENCEABLE reference provider and conformance suite.

Demonstrates ACGS-Lite 4.x ``ContractedEffectStore`` + chained signed
``OutcomeReceipt`` for idempotent HMAC-SHA256-signed webhooks with atomic
``query_and_fence`` timeout recovery.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from acgs_lite import Constitution, GovernanceEngine, Rule, Severity
from acgs_lite.legitimacy import (
    ActualCall,
    ContractedEffectStore,
    Ed25519ReceiptSigner,
    EffectOutcome,
    EffectRequest,
    EffectState,
    EffectStore,
    ExecutionAuthority,
    ExecutionGrant,
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
    validate_receipt_for_execution,
)
from acgs_lite.legitimacy.authorization import (
    authorization_envelope_json,
    build_issue_receipt,
    engine_decision_from_results,
)


class WebhookIdempotencyConflictError(RuntimeError):
    """Raised when an idempotency key is reused with a different webhook payload."""


class WebhookTransport(Protocol):
    """Minimal outbound signed-webhook transport protocol."""

    def deliver(
        self,
        *,
        idempotency_key: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Deliver or idempotently retrieve a signed webhook event."""

    def retrieve_and_fence(self, *, idempotency_key: str) -> tuple[EffectOutcome, str | None, bool]:
        """Query delivery status or atomically fence an uncommitted key."""


class InMemoryWebhookReceiver:
    """In-memory signed webhook receiver enforcing HMAC, dedup, and timeout fencing."""

    def __init__(self, *, signing_secret: bytes = b"acgs-webhook-demo-secret-32bytes") -> None:
        self._secret = signing_secret
        self._lock = threading.Lock()
        self._seq = 0
        self._deliveries_by_key: dict[str, dict[str, Any]] = {}
        self._digests_by_key: dict[str, str] = {}
        self._fenced_keys: set[str] = set()
        self._timeout_modes: dict[str, str] = {}
        self.http_post_calls = 0
        self.http_query_calls = 0

    def inject_timeout_once(self, idempotency_key: str, *, commit_before_timeout: bool) -> None:
        with self._lock:
            self._timeout_modes[idempotency_key] = (
                "after_commit" if commit_before_timeout else "before_commit"
            )

    def _signature_for(self, body: bytes) -> str:
        return "sha256=" + hmac.new(self._secret, body, hashlib.sha256).hexdigest()

    def _record_delivery(
        self, idempotency_key: str, event_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        self._seq += 1
        canonical = json.dumps(
            {"event_type": event_type, "payload": payload},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        record = {
            "delivery_id": f"whd_{self._seq:06d}",
            "status": "delivered",
            "idempotency_key": idempotency_key,
            "event_type": event_type,
            "signature": self._signature_for(canonical),
        }
        self._deliveries_by_key[idempotency_key] = record
        self._digests_by_key[idempotency_key] = digest
        return record

    def deliver(
        self,
        *,
        idempotency_key: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        canonical = json.dumps(
            {"event_type": event_type, "payload": payload},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        with self._lock:
            self.http_post_calls += 1
            if idempotency_key in self._fenced_keys:
                raise RuntimeError(f"webhook key {idempotency_key} is permanently fenced")
            existing = self._deliveries_by_key.get(idempotency_key)
            if existing is not None:
                if self._digests_by_key[idempotency_key] != digest:
                    raise WebhookIdempotencyConflictError(
                        "X-Idempotency-Key reused with differing webhook payload"
                    )
                return dict(existing)

            timeout_mode = self._timeout_modes.pop(idempotency_key, None)
            if timeout_mode == "after_commit":
                self._record_delivery(idempotency_key, event_type, payload)
                raise TimeoutError("Webhook receiver read timeout after delivery ACK")
            if timeout_mode == "before_commit":
                raise TimeoutError("Webhook receiver connection timeout before delivery")

            return dict(self._record_delivery(idempotency_key, event_type, payload))

    def retrieve_and_fence(self, *, idempotency_key: str) -> tuple[EffectOutcome, str | None, bool]:
        with self._lock:
            self.http_query_calls += 1
            existing = self._deliveries_by_key.get(idempotency_key)
            if existing is not None:
                return EffectOutcome.DONE, str(existing["delivery_id"]), False
            self._fenced_keys.add(idempotency_key)
            return EffectOutcome.NOT_DONE, None, True


class LiveWebhookTransport:
    """Real HTTPS outbound signed-webhook transport using stdlib ``urllib.request``."""

    def __init__(
        self,
        endpoint_url: str,
        *,
        signing_secret: bytes,
        timeout_seconds: float = 10.0,
    ) -> None:
        parsed = urllib.parse.urlsplit(endpoint_url)
        host = (parsed.hostname or "").lower()
        is_local = host in ("localhost", "127.0.0.1", "::1")
        if parsed.scheme != "https" and not is_local:
            raise ValueError("LiveWebhookTransport requires an https:// endpoint URL")
        if not signing_secret:
            raise ValueError("LiveWebhookTransport requires a non-empty signing_secret")
        self._endpoint_url = endpoint_url.rstrip("/")
        self._secret = signing_secret
        self._timeout = timeout_seconds

    def _signature_for(self, body: bytes) -> str:
        return "sha256=" + hmac.new(self._secret, body, hashlib.sha256).hexdigest()

    def deliver(
        self,
        *,
        idempotency_key: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        body = json.dumps(
            {"event_type": event_type, "payload": payload},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self._endpoint_url}/deliveries",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Idempotency-Key": idempotency_key,
                "X-ACGS-Signature-256": self._signature_for(body),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                return dict(json.loads(resp.read().decode("utf-8")))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            if exc.code == 409:
                raise WebhookIdempotencyConflictError(err_body) from exc
            raise

    def retrieve_and_fence(self, *, idempotency_key: str) -> tuple[EffectOutcome, str | None, bool]:
        query = urllib.parse.urlencode({"idempotency_key": idempotency_key})
        req = urllib.request.Request(
            f"{self._endpoint_url}/deliveries/fence?{query}",
            method="POST",
            data=b"",
            headers={"X-Idempotency-Key": idempotency_key},
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
        delivery_id = str(data.get("delivery_id")) if data.get("delivery_id") else None
        status = str(data.get("status", ""))
        fenced = data.get("fenced") is True
        if status == "delivered":
            return EffectOutcome.DONE, delivery_id, False
        if status in ("canceled", "fenced") and fenced:
            return EffectOutcome.NOT_DONE, delivery_id, True
        return EffectOutcome.UNKNOWN, delivery_id, False


class WebhookDeliveryProvider:
    """``EffectProvider`` adapter for signed outbound webhooks under a FENCEABLE contract."""

    contract = ProviderContract(
        provider_id="signed-webhooks",
        contract_class=ProviderContractClass.FENCEABLE,
        version="2026-11",
        dedup_by_key=True,
        atomic_query_fence=True,
    )

    def __init__(self, transport: WebhookTransport | None = None) -> None:
        self._transport: WebhookTransport = (
            transport if transport is not None else InMemoryWebhookReceiver()
        )
        self._references: dict[str, str] = {}

    @property
    def provider_id(self) -> str:
        return self.contract.provider_id

    @property
    def transport(self) -> WebhookTransport:
        return self._transport

    def reference_for(self, effect_key: str) -> str | None:
        return self._references.get(effect_key)

    def send(self, request: EffectRequest) -> ProviderResult:
        payload = json.loads(request.action_json)
        res = self._transport.deliver(
            idempotency_key=request.key,
            event_type=str(payload["event_type"]),
            payload=dict(payload.get("data", {})),
        )
        ref = res.get("delivery_id")
        if isinstance(ref, str) and ref:
            self._references[request.key] = ref
        status = str(res.get("status", ""))
        if status == "delivered":
            return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE, fenced=True)
        if status in ("canceled", "fenced"):
            return ProviderResult(
                request.key, self.provider_id, EffectOutcome.NOT_DONE, fenced=True
            )
        return ProviderResult(request.key, self.provider_id, EffectOutcome.UNKNOWN, fenced=False)

    def query_and_fence(self, request: EffectRequest) -> ProviderResult:
        outcome, ref, fenced = self._transport.retrieve_and_fence(idempotency_key=request.key)
        if ref is not None:
            self._references[request.key] = ref
        return ProviderResult(request.key, self.provider_id, outcome, fenced=fenced)


def _emit_webhook(event_type: str, target: str, *, scope: str, subject: str) -> None:
    """Callable identity bound into ACGS execution grants."""


def _mint_grant(
    *,
    engine: GovernanceEngine,
    constitution: Constitution,
    authority: ExecutionAuthority,
    signer: Ed25519ReceiptSigner,
    event_type: str,
    target: str,
    scope: str,
) -> ExecutionGrant:
    action_text = f"emit webhook {event_type} to {target}"
    result = engine.validate(action_text, agent_id="webhook-agent")
    if not result.valid:
        raise ValueError(f"blocked by constitution: {[v.rule_id for v in result.violations]}")
    invocation = bind_invocation(
        _emit_webhook, (event_type, target), {"scope": scope, "subject": target}
    )
    policy = bind_policy(constitution)
    decision = engine_decision_from_results([result])
    grant_id = authority.allocate_grant_id()
    try:
        receipt = build_issue_receipt(
            func=_emit_webhook,
            invocation=invocation,
            policy=policy,
            decision=decision,
            grant_id=grant_id,
        )
        signed = sign_execution_authorization(
            receipt,
            signer,
            authorization_json=authorization_envelope_json(invocation, policy, grant_id=grant_id),
        )
        grant = authority.issue(
            receipt=receipt,
            invocation=invocation,
            policy=policy,
            grant_id=grant_id,
            signed_receipt=signed,
        )
    finally:
        authority.release_grant_id(grant_id)

    validate_receipt_for_execution(
        grant.receipt,
        actual_call=ActualCall(method="_emit_webhook", scope=scope, subjects=(target,)),
    )
    return grant


@dataclass(frozen=True)
class WebhookConformanceResult:
    """Structured conformance summary from :func:`run_webhook_conformance_suite`."""

    all_passed: bool
    a1_dedup_single_delivery: bool
    a2_timeout_committed_reconciles_done: bool
    a2_timeout_uncommitted_reconciles_fenced_not_done: bool
    deny_zero_provider_calls: bool
    outcome_signatures_verified: bool
    contract_identity: str


def run_webhook_conformance_suite(db_path: Path | None = None) -> WebhookConformanceResult:
    """Run offline A1/A2/DENY conformance checks against InMemoryWebhookReceiver."""
    receiver = InMemoryWebhookReceiver()
    provider = WebhookDeliveryProvider(receiver)
    signer = Ed25519ReceiptSigner.from_seed(b"acgs-webhook-conformance-2026-1!"[:32])
    pub = signer.public_key_hex()
    constitution = Constitution(
        name="webhook-conformance",
        version="2026.11",
        rules=[
            Rule(
                id="no-exfiltrate",
                text="Block raw PII exfiltration webhooks",
                severity=Severity.CRITICAL,
                keywords=["exfiltrate", "raw_ssn"],
            )
        ],
    )
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    registry = ProviderContractRegistry()
    contract = registry.register(provider.contract)

    def _exec(path: Path) -> WebhookConformanceResult:
        store = EffectStore(path)
        store.create_budget("webhook-conformance", 100)
        contracted = ContractedEffectStore(store, registry)

        # 1. A1 dedup
        g1 = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            event_type="invoice.paid",
            target="https://hooks.example.test/acct_1",
            scope="prod-webhooks",
        )
        e1 = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(g1),
            action={"event_type": "invoice.paid", "data": {"invoice_id": "in_1"}},
            budget_id="webhook-conformance",
            amount=1,
        )
        rec1 = contracted.send(e1.key, provider, grant=g1)
        dup = receiver.deliver(
            idempotency_key=e1.key,
            event_type="invoice.paid",
            payload={"invoice_id": "in_1"},
        )
        o1 = sign_outcome(
            outcome_from_record(
                rec1,
                store=contracted,
                provider=provider,
                grant=g1,
                provider_reference=provider.reference_for(e1.key),
            ),
            signer,
        )
        a1_ok = (
            rec1.state is EffectState.DONE
            and dup["delivery_id"] == provider.reference_for(e1.key)
            and o1.verify(pub)
        )

        # 2. A2 timeout committed -> reconcile across store reopen -> DONE
        g2 = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            event_type="invoice.paid",
            target="https://hooks.example.test/acct_2",
            scope="prod-webhooks",
        )
        e2 = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(g2),
            action={"event_type": "invoice.paid", "data": {"invoice_id": "in_2"}},
            budget_id="webhook-conformance",
            amount=1,
        )
        receiver.inject_timeout_once(e2.key, commit_before_timeout=True)
        a2_done_ok = False
        o2_ok = False
        try:
            contracted.send(e2.key, provider, grant=g2)
        except TimeoutError:
            reopened = ContractedEffectStore(EffectStore(path), registry)
            rec2 = reopened.reconcile(e2.key, provider)
            o2 = sign_outcome(
                outcome_from_record(
                    rec2,
                    store=reopened,
                    provider=provider,
                    grant=g2,
                    provider_reference=provider.reference_for(e2.key),
                ),
                signer,
            )
            a2_done_ok = rec2.state is EffectState.DONE
            o2_ok = o2.verify(pub)

        # 3. A2 timeout uncommitted -> reconcile fences -> NOT_DONE
        g3 = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            event_type="invoice.paid",
            target="https://hooks.example.test/acct_3",
            scope="prod-webhooks",
        )
        e3 = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(g3),
            action={"event_type": "invoice.paid", "data": {"invoice_id": "in_3"}},
            budget_id="webhook-conformance",
            amount=1,
        )
        receiver.inject_timeout_once(e3.key, commit_before_timeout=False)
        a2_not_done_ok = False
        o3_ok = False
        try:
            contracted.send(e3.key, provider, grant=g3)
        except TimeoutError:
            rec3 = contracted.reconcile(e3.key, provider)
            o3 = sign_outcome(
                outcome_from_record(rec3, store=contracted, provider=provider, grant=g3),
                signer,
            )
            a2_not_done_ok = rec3.state is EffectState.NOT_DONE
            o3_ok = o3.verify(pub)

        # 4. DENY zero dispatch
        before_calls = receiver.http_post_calls
        deny_ok = False
        try:
            _mint_grant(
                engine=engine,
                constitution=constitution,
                authority=authority,
                signer=signer,
                event_type="exfiltrate raw_ssn",
                target="https://hooks.example.test/acct_4",
                scope="prod-webhooks",
            )
        except ValueError:
            deny_ok = receiver.http_post_calls == before_calls

        sigs_ok = o1.verify(pub) and o2_ok and o3_ok
        all_passed = a1_ok and a2_done_ok and a2_not_done_ok and deny_ok and sigs_ok
        return WebhookConformanceResult(
            all_passed=all_passed,
            a1_dedup_single_delivery=a1_ok,
            a2_timeout_committed_reconciles_done=a2_done_ok,
            a2_timeout_uncommitted_reconciles_fenced_not_done=a2_not_done_ok,
            deny_zero_provider_calls=deny_ok,
            outcome_signatures_verified=sigs_ok,
            contract_identity=contract.identity,
        )

    if db_path is not None:
        return _exec(db_path)
    with tempfile.TemporaryDirectory(prefix="acgs-webhook-") as tmp_dir:
        return _exec(Path(tmp_dir) / "webhook_effects.sqlite")


def run_live_webhook_verification(
    transport: WebhookTransport,
    *,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Exercise a live or local HTTPS WebhookTransport end-to-end."""
    provider = WebhookDeliveryProvider(transport)
    signer = Ed25519ReceiptSigner.from_seed(b"acgs-webhook-live-verify-2026-1!"[:32])
    constitution = Constitution(
        name="webhook-live",
        version="2026.11",
        rules=[
            Rule(
                id="no-exfiltrate",
                text="Block raw PII exfiltration webhooks",
                severity=Severity.CRITICAL,
                keywords=["exfiltrate"],
            )
        ],
    )
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    registry = ProviderContractRegistry()
    registry.register(provider.contract)

    def _run(path: Path) -> dict[str, Any]:
        store = EffectStore(path)
        store.create_budget("webhook-live", 100)
        contracted = ContractedEffectStore(store, registry)
        grant = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            event_type="acgs.smoke",
            target="https://hooks.example.test/smoke",
            scope="test-webhooks",
        )
        effect = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(grant),
            action={"event_type": "acgs.smoke", "data": {"ok": True}},
            budget_id="webhook-live",
            amount=1,
        )
        try:
            rec = contracted.send(effect.key, provider, grant=grant)
            dup = transport.deliver(
                idempotency_key=effect.key,
                event_type="acgs.smoke",
                payload={"ok": True},
            )
            outcome, _, _ = transport.retrieve_and_fence(idempotency_key=effect.key)
        except Exception as exc:
            return {
                "transport": type(transport).__name__,
                "effect_key": effect.key,
                "passed": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        ref = provider.reference_for(effect.key)
        dedup_ok = isinstance(ref, str) and bool(ref) and dup.get("delivery_id") == ref
        return {
            "transport": type(transport).__name__,
            "effect_key": effect.key,
            "state": rec.state.value,
            "provider_reference": ref,
            "idempotent_dedup_matched": dedup_ok,
            "reconcile_outcome": outcome.value,
            "passed": rec.state is EffectState.DONE and dedup_ok,
        }

    if db_path is not None:
        return _run(db_path)
    with tempfile.TemporaryDirectory(prefix="acgs-webhook-live-") as tmp_dir:
        return _run(Path(tmp_dir) / "webhook_live.sqlite")


def main() -> int:
    res = run_webhook_conformance_suite()
    live_url = os.environ.get("ACGS_WEBHOOK_TEST_URL")
    if not live_url:
        print(json.dumps(res.__dict__, indent=2))
        return 0 if res.all_passed else 1

    secret = os.environ.get("ACGS_WEBHOOK_TEST_SECRET", "test-secret").encode("utf-8")
    try:
        transport = LiveWebhookTransport(live_url, signing_secret=secret)
        live = run_live_webhook_verification(transport)
    except Exception as exc:
        live = {
            "transport": "LiveWebhookTransport",
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    all_passed = bool(res.all_passed and live["passed"])
    print(
        json.dumps(
            {
                "all_passed": all_passed,
                "sandbox_conformance": res.__dict__,
                "live_verification": live,
            },
            indent=2,
        )
    )
    return 0 if all_passed else 1
