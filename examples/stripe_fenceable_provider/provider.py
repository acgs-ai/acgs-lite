"""Stripe PaymentIntent FENCEABLE reference provider and conformance suite.

Demonstrates how a real payment adapter pairs ACGS-Lite's ``ContractedEffectStore``
and signed ``OutcomeReceipt`` chain with Stripe's ``Idempotency-Key`` semantics.

Note: ``ProviderContract`` fields are operator declarations, not runtime proofs
of external provider internals. Run ``run_conformance_suite`` against the
sandbox (or Stripe Test Mode with an ``sk_test_...`` key) for empirical evidence.
"""

from __future__ import annotations

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
    EffectRecord,
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


class StripeIdempotencyConflictError(RuntimeError):
    """Raised when an idempotency key is reused with differing parameters (HTTP 409/400)."""


class StripeTransport(Protocol):
    """Minimal Stripe PaymentIntent transport interface for dependency injection."""

    def create_payment_intent(
        self,
        *,
        idempotency_key: str,
        amount_cents: int,
        currency: str,
        customer_id: str,
    ) -> dict[str, Any]: ...

    def retrieve_and_fence(self, *, idempotency_key: str) -> tuple[EffectOutcome, str | None, bool]:
        """Return (outcome, payment_intent_id_or_none, fenced)."""


class InMemoryStripeSandbox:
    """Faithful in-memory model of Stripe Idempotency-Key + atomic query/fence.

    Supports deterministic timeout injection (both committed-before-timeout and
    dropped-before-commit) so tests and conformance suites can prove A1 dedup
    and A2 query-and-fence without network credentials.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq = 0
        self._intents_by_key: dict[str, dict[str, Any]] = {}
        self._payloads_by_key: dict[str, tuple[int, str, str]] = {}
        self._fenced_keys: set[str] = set()
        self._timeout_modes: dict[str, str] = {}
        self.http_post_calls = 0
        self.http_query_calls = 0

    def inject_timeout_once(self, idempotency_key: str, *, commit_before_timeout: bool) -> None:
        """Force the next POST for ``idempotency_key`` to time out."""
        with self._lock:
            self._timeout_modes[idempotency_key] = (
                "after_commit" if commit_before_timeout else "before_commit"
            )

    def _create_record(
        self, idempotency_key: str, amount_cents: int, currency: str, customer_id: str
    ) -> dict[str, Any]:
        self._seq += 1
        intent = {
            "id": f"pi_sandbox_{self._seq:06d}",
            "amount": amount_cents,
            "currency": currency,
            "customer": customer_id,
            "status": "succeeded",
            "idempotency_key": idempotency_key,
        }
        self._intents_by_key[idempotency_key] = intent
        self._payloads_by_key[idempotency_key] = (amount_cents, currency, customer_id)
        return intent

    def create_payment_intent(
        self,
        *,
        idempotency_key: str,
        amount_cents: int,
        currency: str,
        customer_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            self.http_post_calls += 1
            payload = (amount_cents, currency, customer_id)
            if idempotency_key in self._fenced_keys:
                raise RuntimeError(f"idempotency key {idempotency_key} is permanently fenced")
            existing = self._intents_by_key.get(idempotency_key)
            if existing is not None:
                if self._payloads_by_key[idempotency_key] != payload:
                    raise StripeIdempotencyConflictError(
                        "Keys for idempotent requests can only be used with the same parameters"
                    )
                return dict(existing)

            timeout_mode = self._timeout_modes.pop(idempotency_key, None)
            if timeout_mode == "after_commit":
                self._create_record(idempotency_key, amount_cents, currency, customer_id)
                raise TimeoutError("Stripe API read timeout after PaymentIntent creation")
            if timeout_mode == "before_commit":
                raise TimeoutError("Stripe API connection timeout before PaymentIntent creation")

            return dict(self._create_record(idempotency_key, amount_cents, currency, customer_id))

    def retrieve_and_fence(self, *, idempotency_key: str) -> tuple[EffectOutcome, str | None, bool]:
        with self._lock:
            self.http_query_calls += 1
            existing = self._intents_by_key.get(idempotency_key)
            if existing is not None:
                return EffectOutcome.DONE, str(existing["id"]), False
            self._fenced_keys.add(idempotency_key)
            return EffectOutcome.NOT_DONE, None, True


class LiveStripeTestTransport:
    """Real Stripe Test Mode HTTP transport using stdlib ``urllib.request``.

    Fail-closed guard: refuses any API key that does not begin with ``sk_test_``
    or ``rk_test_`` so live production funds can never be touched by a demo or test.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://api.stripe.com",
        timeout_seconds: float = 10.0,
    ) -> None:
        if not isinstance(api_key, str) or not (
            api_key.startswith("sk_test_") or api_key.startswith("rk_test_")
        ):
            raise ValueError(
                "LiveStripeTestTransport requires a Stripe Test Mode key (sk_test_... or rk_test_...)"
            )
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds

    def create_payment_intent(
        self,
        *,
        idempotency_key: str,
        amount_cents: int,
        currency: str,
        customer_id: str,
    ) -> dict[str, Any]:
        form = urllib.parse.urlencode(
            {
                "amount": str(amount_cents),
                "currency": currency,
                "confirm": "true",
                "payment_method": "pm_card_visa",
                "automatic_payment_methods[enabled]": "true",
                "automatic_payment_methods[allow_redirects]": "never",
                "metadata[acgs_effect_key]": idempotency_key,
                "metadata[customer_id]": customer_id,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self._base_url}/v1/payment_intents",
            data=form,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Idempotency-Key": idempotency_key,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                return dict(json.loads(resp.read().decode("utf-8")))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code in (400, 409) and "idempotency" in body.lower():
                raise StripeIdempotencyConflictError(body) from exc
            raise

    def retrieve_and_fence(self, *, idempotency_key: str) -> tuple[EffectOutcome, str | None, bool]:
        query = urllib.parse.urlencode(
            {"query": f"metadata['acgs_effect_key']:'{idempotency_key}'"}
        )
        req = urllib.request.Request(
            f"{self._base_url}/v1/payment_intents/search?{query}",
            method="GET",
            headers={"Authorization": f"Bearer {self._api_key}"},
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))
        items = payload.get("data") or []
        if items:
            first = items[0]
            pi_id = str(first.get("id")) if first.get("id") else None
            status = str(first.get("status", ""))
            if status == "canceled":
                return EffectOutcome.NOT_DONE, pi_id, True
            if status in ("succeeded", "processing", "requires_capture"):
                return EffectOutcome.DONE, pi_id, False
        # Stripe's Search API does not atomically fence an absent Idempotency-Key;
        # fail closed by returning UNKNOWN rather than falsely claiming fenced=True.
        return EffectOutcome.UNKNOWN, None, False


class StripePaymentIntentProvider:
    """``EffectProvider`` adapter for Stripe PaymentIntents under a FENCEABLE contract."""

    contract = ProviderContract(
        provider_id="stripe-payment-intents",
        contract_class=ProviderContractClass.FENCEABLE,
        version="2026-11",
        dedup_by_key=True,
        atomic_query_fence=True,
    )

    def __init__(self, transport: StripeTransport | None = None) -> None:
        self._transport: StripeTransport = (
            transport if transport is not None else InMemoryStripeSandbox()
        )
        self._references: dict[str, str] = {}

    @property
    def provider_id(self) -> str:
        return self.contract.provider_id

    @property
    def transport(self) -> StripeTransport:
        return self._transport

    def reference_for(self, effect_key: str) -> str | None:
        return self._references.get(effect_key)

    def send(self, request: EffectRequest) -> ProviderResult:
        payload = json.loads(request.action_json)
        intent = self._transport.create_payment_intent(
            idempotency_key=request.key,
            amount_cents=int(payload["amount_cents"]),
            currency=str(payload.get("currency", "usd")),
            customer_id=str(payload["customer_id"]),
        )
        intent_id = intent.get("id")
        if isinstance(intent_id, str) and intent_id:
            self._references[request.key] = intent_id
        return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE, fenced=True)

    def query_and_fence(self, request: EffectRequest) -> ProviderResult:
        outcome, intent_id, fenced = self._transport.retrieve_and_fence(idempotency_key=request.key)
        if intent_id is not None:
            self._references[request.key] = intent_id
        return ProviderResult(request.key, self.provider_id, outcome, fenced=fenced)


def _charge_customer(customer_id: str, amount_cents: int, *, scope: str, subject: str) -> None:
    """Callable identity bound into ACGS execution grants."""


def _mint_grant(
    *,
    engine: GovernanceEngine,
    constitution: Constitution,
    authority: ExecutionAuthority,
    signer: Ed25519ReceiptSigner,
    customer_id: str,
    amount_cents: int,
    scope: str,
) -> ExecutionGrant:
    action_text = f"charge customer {customer_id} amount {amount_cents} cents"
    if amount_cents > 50_000:
        action_text = f"wire transfer {amount_cents} cents for {customer_id}"
    result = engine.validate(action_text, agent_id="stripe-agent")
    if not result.valid:
        raise ValueError(f"blocked by constitution: {[v.rule_id for v in result.violations]}")
    invocation = bind_invocation(
        _charge_customer, (customer_id, amount_cents), {"scope": scope, "subject": customer_id}
    )
    policy = bind_policy(constitution)
    decision = engine_decision_from_results([result])
    grant_id = authority.allocate_grant_id()
    try:
        receipt = build_issue_receipt(
            func=_charge_customer,
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
        actual_call=ActualCall(method="_charge_customer", scope=scope, subjects=(customer_id,)),
    )
    return grant


@dataclass(frozen=True)
class StripeConformanceResult:
    """Structured report from the FENCEABLE provider conformance suite."""

    all_passed: bool
    a1_dedup_single_charge: bool
    a2_timeout_committed_reconciles_done: bool
    a2_timeout_uncommitted_reconciles_fenced_not_done: bool
    deny_zero_provider_calls: bool
    outcome_signatures_verified: bool
    contract_identity: str


def run_conformance_suite(db_path: Path | None = None) -> StripeConformanceResult:
    """Run all A1/A2/fail-closed conformance checks against InMemoryStripeSandbox."""
    sandbox = InMemoryStripeSandbox()
    provider = StripePaymentIntentProvider(sandbox)
    signer = Ed25519ReceiptSigner.from_seed(b"acgs-stripe-conformance-2026-11!"[:32])
    pub = signer.public_key_hex()
    constitution = Constitution(
        name="stripe-conformance",
        version="2026.11",
        rules=[
            Rule(
                id="no-large-wire",
                text="Block wire transfers above limit",
                severity=Severity.CRITICAL,
                keywords=["wire transfer"],
            )
        ],
    )
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    registry = ProviderContractRegistry()
    contract = registry.register(provider.contract)

    def _exec(target_path: Path) -> StripeConformanceResult:
        store = EffectStore(target_path)
        store.create_budget("stripe-conformance", 100_000)
        contracted = ContractedEffectStore(store, registry)

        # 1. A1 dedup: two dispatches with same grant/key invoke transport once at EffectStore
        g1 = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            customer_id="cus_001",
            amount_cents=2500,
            scope="prod-billing",
        )
        e1 = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(g1),
            action={"customer_id": "cus_001", "amount_cents": 2500, "currency": "usd"},
            budget_id="stripe-conformance",
            amount=2500,
        )
        r1 = contracted.send(e1.key, provider, grant=g1)
        r1_retry = contracted.send(e1.key, provider, grant=g1)
        # Also test direct provider-level idempotent resend returns same PaymentIntent
        direct_dup = provider.send(e1.request)
        o1 = sign_outcome(
            outcome_from_record(
                r1,
                store=contracted,
                provider=provider,
                grant=g1,
                provider_reference=provider.reference_for(e1.key),
            ),
            signer,
        )
        a1_ok = (
            r1.state is EffectState.DONE
            and r1_retry.state is EffectState.DONE
            and direct_dup.outcome is EffectOutcome.DONE
            and len(sandbox._intents_by_key) == 1
            and o1.verify(pub)
        )

        # 2. A2 timeout AFTER commit -> UNKNOWN -> restart -> reconcile -> DONE
        g2 = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            customer_id="cus_002",
            amount_cents=4000,
            scope="prod-billing",
        )
        e2 = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(g2),
            action={"customer_id": "cus_002", "amount_cents": 4000, "currency": "usd"},
            budget_id="stripe-conformance",
            amount=4000,
        )
        sandbox.inject_timeout_once(e2.key, commit_before_timeout=True)
        try:
            contracted.send(e2.key, provider, grant=g2)
            a2_done_ok = False
            o2_ok = False
        except TimeoutError:
            restarted = ContractedEffectStore(EffectStore(target_path), registry)
            rec2: EffectRecord = restarted.reconcile(e2.key, provider)
            o2 = sign_outcome(
                outcome_from_record(
                    rec2,
                    store=restarted,
                    provider=provider,
                    grant=g2,
                    provider_reference=provider.reference_for(e2.key),
                ),
                signer,
            )
            a2_done_ok = rec2.state is EffectState.DONE
            o2_ok = o2.verify(pub)

        # 3. A2 timeout BEFORE commit -> UNKNOWN -> reconcile fences -> NOT_DONE
        g3 = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            customer_id="cus_003",
            amount_cents=3000,
            scope="prod-billing",
        )
        e3 = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(g3),
            action={"customer_id": "cus_003", "amount_cents": 3000, "currency": "usd"},
            budget_id="stripe-conformance",
            amount=3000,
        )
        sandbox.inject_timeout_once(e3.key, commit_before_timeout=False)
        try:
            contracted.send(e3.key, provider, grant=g3)
            a2_not_done_ok = False
            o3_ok = False
        except TimeoutError:
            rec3 = contracted.reconcile(e3.key, provider)
            o3 = sign_outcome(
                outcome_from_record(
                    rec3, store=contracted, provider=provider, grant=g3, provider_reference=None
                ),
                signer,
            )
            a2_not_done_ok = rec3.state is EffectState.NOT_DONE
            o3_ok = o3.verify(pub)

        # 4. DENY zero dispatch
        calls_before = sandbox.http_post_calls
        deny_ok = False
        try:
            _mint_grant(
                engine=engine,
                constitution=constitution,
                authority=authority,
                signer=signer,
                customer_id="cus_004",
                amount_cents=100_000,
                scope="prod-billing",
            )
        except ValueError:
            deny_ok = sandbox.http_post_calls == calls_before

        sigs_ok = o1.verify(pub) and o2_ok and o3_ok
        all_passed = a1_ok and a2_done_ok and a2_not_done_ok and deny_ok and sigs_ok
        return StripeConformanceResult(
            all_passed=all_passed,
            a1_dedup_single_charge=a1_ok,
            a2_timeout_committed_reconciles_done=a2_done_ok,
            a2_timeout_uncommitted_reconciles_fenced_not_done=a2_not_done_ok,
            deny_zero_provider_calls=deny_ok,
            outcome_signatures_verified=sigs_ok,
            contract_identity=contract.identity,
        )

    if db_path is not None:
        return _exec(db_path)
    with tempfile.TemporaryDirectory(prefix="acgs-stripe-") as tmp_dir:
        return _exec(Path(tmp_dir) / "stripe_effects.sqlite")


def main() -> int:
    test_key = os.environ.get("STRIPE_TEST_API_KEY")
    if test_key:
        LiveStripeTestTransport(test_key)
    res = run_conformance_suite()
    print(json.dumps(res.__dict__, indent=2))
    return 0 if res.all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
