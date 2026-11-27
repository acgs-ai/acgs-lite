"""Conformance tests for the signed outbound webhook FENCEABLE reference provider."""

from __future__ import annotations

import io
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from acgs_lite import Constitution, GovernanceEngine, Rule, Severity  # noqa: E402
from acgs_lite.legitimacy import (  # noqa: E402
    ContractedEffectStore,
    Ed25519ReceiptSigner,
    EffectOutcome,
    EffectState,
    EffectStore,
    ExecutionAuthority,
    ProviderContractRegistry,
    local_grant_identity,
    outcome_from_record,
    sign_outcome,
)
from examples.webhook_fenceable_provider import (  # noqa: E402
    InMemoryWebhookReceiver,
    LiveWebhookTransport,
    WebhookDeliveryProvider,
    WebhookIdempotencyConflictError,
    run_webhook_conformance_suite,
)
from examples.webhook_fenceable_provider.provider import _mint_grant, main  # noqa: E402


def test_webhook_conformance_suite_passes_end_to_end(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    res = run_webhook_conformance_suite(db_path=tmp_path / "webhook.sqlite")
    assert res.all_passed is True
    assert res.a1_dedup_single_delivery is True
    assert res.a2_timeout_committed_reconciles_done is True
    assert res.a2_timeout_uncommitted_reconciles_fenced_not_done is True
    assert res.deny_zero_provider_calls is True
    assert res.outcome_signatures_verified is True


def test_a1_webhook_dedup_and_payload_conflict() -> None:
    receiver = InMemoryWebhookReceiver()
    first = receiver.deliver(idempotency_key="wk1", event_type="invoice.paid", payload={"id": "1"})
    second = receiver.deliver(idempotency_key="wk1", event_type="invoice.paid", payload={"id": "1"})
    assert first["delivery_id"] == second["delivery_id"]
    assert first["signature"].startswith("sha256=")
    with pytest.raises(WebhookIdempotencyConflictError):
        receiver.deliver(idempotency_key="wk1", event_type="invoice.paid", payload={"id": "2"})


def test_a2_webhook_timeout_before_commit_fences_key(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    db = tmp_path / "wh.sqlite"
    receiver = InMemoryWebhookReceiver()
    provider = WebhookDeliveryProvider(receiver)
    signer = Ed25519ReceiptSigner.from_seed(b"\x08" * 32)
    constitution = Constitution(
        name="wh-test",
        version="2026.11",
        rules=[Rule(id="r1", text="block", severity=Severity.CRITICAL, keywords=["exfiltrate"])],
    )
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    registry = ProviderContractRegistry()
    registry.register(provider.contract)

    store = EffectStore(db)
    store.create_budget("wh", 100)
    contracted = ContractedEffectStore(store, registry)

    grant = _mint_grant(
        engine=engine,
        constitution=constitution,
        authority=authority,
        signer=signer,
        event_type="invoice.paid",
        target="https://hooks.example.test/t1",
        scope="prod",
    )
    effect = store.reserve(
        provider_id=provider.provider_id,
        grant_identity=local_grant_identity(grant),
        action={"event_type": "invoice.paid", "data": {"id": "1"}},
        budget_id="wh",
        amount=1,
    )
    receiver.inject_timeout_once(effect.key, commit_before_timeout=False)
    with pytest.raises(TimeoutError):
        contracted.send(effect.key, provider, grant=grant)

    reopened = ContractedEffectStore(EffectStore(db), registry)
    rec = reopened.reconcile(effect.key, provider)
    assert rec.state is EffectState.NOT_DONE
    signed = sign_outcome(
        outcome_from_record(rec, store=reopened, provider=provider, grant=grant),
        signer,
    )
    assert signed.verify(signer.public_key_hex()) is True

    with pytest.raises(RuntimeError, match="permanently fenced"):
        receiver.deliver(idempotency_key=effect.key, event_type="invoice.paid", payload={"id": "1"})


def test_live_webhook_transport_https_and_status_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="https://"):
        LiveWebhookTransport("http://remote.example.com", signing_secret=b"sec")
    with pytest.raises(ValueError, match="non-empty"):
        LiveWebhookTransport("https://hooks.example.com", signing_secret=b"")

    class _FakeResp:
        def __init__(self, body: dict[str, object]) -> None:
            self._body = json.dumps(body).encode("utf-8")

        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return self._body

    transport = LiveWebhookTransport("https://hooks.example.com", signing_secret=b"secret")
    for status, fenced_flag, expected in [
        ("delivered", False, EffectOutcome.DONE),
        ("canceled", True, EffectOutcome.NOT_DONE),
        ("canceled", "false", EffectOutcome.UNKNOWN),
        ("queued", False, EffectOutcome.UNKNOWN),
    ]:
        monkeypatch.setattr(
            urllib.request,
            "urlopen",
            lambda req, timeout=10.0, _s=status, _f=fenced_flag: _FakeResp(
                {"delivery_id": "whd_1", "status": _s, "fenced": _f}
            ),
        )
        outcome, _, _ = transport.retrieve_and_fence(idempotency_key="acgs:effect:v1:abc")
        assert outcome is expected


def test_webhook_send_requires_explicit_boolean_fenced_confirmation() -> None:
    class _UnconfirmedCancelTransport:
        def deliver(self, **_: object) -> dict[str, object]:
            return {"delivery_id": "whd_x", "status": "canceled", "fenced": False}

        def retrieve_and_fence(self, **_: object) -> tuple[EffectOutcome, str | None, bool]:
            return EffectOutcome.UNKNOWN, None, False

    from acgs_lite.legitimacy import EffectRequest

    provider = WebhookDeliveryProvider(_UnconfirmedCancelTransport())  # type: ignore[arg-type]
    req = EffectRequest(
        key="acgs:effect:v1:" + "1" * 64,
        provider_id=provider.provider_id,
        grant_identity="grant-1",
        action_json='{"event_type":"invoice.paid","data":{}}',
    )
    res = provider.send(req)
    assert res.outcome is EffectOutcome.UNKNOWN
    assert res.fenced is False


def test_webhook_main_with_live_url_fails_on_http_error_and_succeeds_when_ok(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("cryptography")
    monkeypatch.setenv("ACGS_WEBHOOK_TEST_URL", "https://hooks.example.test")
    monkeypatch.setenv("ACGS_WEBHOOK_TEST_SECRET", "top-secret")

    def _fail(req: object, timeout: float = 10.0) -> object:
        raise urllib.error.HTTPError(
            "https://hooks.example.test/deliveries",
            502,
            "Bad Gateway",
            {},  # type: ignore[arg-type]
            io.BytesIO(b"bad gateway"),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _fail)
    assert main() == 1
    fail_out = json.loads(capsys.readouterr().out)
    assert fail_out["all_passed"] is False
    assert fail_out["live_verification"]["passed"] is False

    class _FakeResp:
        def __init__(self, body: dict[str, object]) -> None:
            self._body = json.dumps(body).encode("utf-8")

        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return self._body

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=10.0: _FakeResp(
            {"delivery_id": "whd_live_1", "status": "delivered", "fenced": False}
        ),
    )
    assert main() == 0
    ok_out = json.loads(capsys.readouterr().out)
    assert ok_out["all_passed"] is True
    assert ok_out["live_verification"]["passed"] is True
    assert ok_out["live_verification"]["idempotent_dedup_matched"] is True

    # Live transport whose fence endpoint returns unknown after deliver must NOT pass
    from examples.webhook_fenceable_provider.provider import run_live_webhook_verification

    class _BrokenFenceTransport:
        def deliver(self, **_: object) -> dict[str, object]:
            return {"delivery_id": "whd_broken", "status": "delivered", "fenced": False}

        def retrieve_and_fence(self, **_: object) -> tuple[EffectOutcome, str | None, bool]:
            return EffectOutcome.UNKNOWN, "whd_broken", False

    broken = run_live_webhook_verification(_BrokenFenceTransport())  # type: ignore[arg-type]
    assert broken["reconcile_outcome"] == "unknown"
    assert broken["passed"] is False
