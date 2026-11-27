# Stripe PaymentIntent `FENCEABLE` Reference Provider

Demonstrates ACGS-Lite 4.0 **Receipted Effects** with a Stripe-compatible `EffectProvider`:

- Pre-execution decision receipt (`DecisionReceipt` v2 + `Ed25519ReceiptSigner`)
- At-most-once execution keyed by `EffectStore` `acgs:effect:v1:<sha256>` -> Stripe `Idempotency-Key`
- Per-key `UNKNOWN` quarantine on timeout, with `ContractedEffectStore.reconcile()` across restarts
- Signed `OutcomeReceipt` chained to the decision receipt and contract digest

## Important Honesty Disclaimer

> **`ProviderContract` capability fields (`dedup_by_key`, `atomic_query_fence`) are self-declared operator assertions, not cryptographic runtime guarantees of external provider internals.**
>
> This conformance suite provides repeatable empirical evidence against `InMemoryStripeSandbox` (and optional `STRIPE_TEST_API_KEY=sk_test_...` verification). When `LiveStripeTestTransport.query_and_fence` cannot prove an atomic fence on an absent Search API query, it fails closed by returning `EffectOutcome.UNKNOWN` rather than falsely claiming `fenced=True`.

## Quickstart (Offline Sandbox)

```bash
PYTHONPATH=src:. python -m examples.stripe_fenceable_provider
pytest tests/test_stripe_provider_conformance.py -v
```

## Optional Stripe Test Mode

`LiveStripeTestTransport` enforces fail-closed validation rejecting any key that does not start with `sk_test_` or `rk_test_`:

```bash
STRIPE_TEST_API_KEY=sk_test_... PYTHONPATH=src:. python -m examples.stripe_fenceable_provider
```
