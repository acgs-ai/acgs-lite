# Signed Outbound Webhook `FENCEABLE` Reference Provider

Demonstrates ACGS-Lite 4.x **Receipted Effects** for HMAC-SHA256-signed webhooks with `X-Idempotency-Key` deduplication and atomic timeout fencing.

## Quickstart (Offline)

```bash
PYTHONPATH=src:. python -m examples.webhook_fenceable_provider
pytest tests/test_webhook_provider_conformance.py -v
```

## Optional Live Test Mode

Set `ACGS_WEBHOOK_TEST_URL` (HTTPS required for non-localhost endpoints) and `ACGS_WEBHOOK_TEST_SECRET` to exercise `LiveWebhookTransport` end-to-end:

```bash
ACGS_WEBHOOK_TEST_URL=https://hooks.example.test ACGS_WEBHOOK_TEST_SECRET=secret PYTHONPATH=src:. python -m examples.webhook_fenceable_provider
```
