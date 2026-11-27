"""Conformance tests for the Stripe-compatible FENCEABLE reference provider."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import pytest

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from acgs_lite import Constitution, GovernanceEngine, Rule, Severity  # noqa: E402
from acgs_lite.legitimacy import (
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
from examples.stripe_fenceable_provider import (  # noqa: E402
    InMemoryStripeSandbox,
    LiveStripeTestTransport,
    StripeIdempotencyConflictError,
    StripePaymentIntentProvider,
    run_conformance_suite,
)
from examples.stripe_fenceable_provider.provider import _mint_grant, main  # noqa: E402


def test_conformance_suite_passes_end_to_end(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    res = run_conformance_suite(db_path=tmp_path / "stripe.sqlite")
    assert res.all_passed is True
    assert res.a1_dedup_single_charge is True
    assert res.a2_timeout_committed_reconciles_done is True
    assert res.a2_timeout_uncommitted_reconciles_fenced_not_done is True
    assert res.deny_zero_provider_calls is True
    assert res.outcome_signatures_verified is True


def test_a1_same_key_dedups_and_conflicting_payload_fails() -> None:
    sandbox = InMemoryStripeSandbox()
    first = sandbox.create_payment_intent(
        idempotency_key="k1", amount_cents=1200, currency="usd", customer_id="cus_a"
    )
    second = sandbox.create_payment_intent(
        idempotency_key="k1", amount_cents=1200, currency="usd", customer_id="cus_a"
    )
    assert first["id"] == second["id"]
    with pytest.raises(StripeIdempotencyConflictError):
        sandbox.create_payment_intent(
            idempotency_key="k1", amount_cents=9999, currency="usd", customer_id="cus_a"
        )


def test_a2_timeout_before_commit_fences_and_blocks_late_send(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    db = tmp_path / "effects.sqlite"
    sandbox = InMemoryStripeSandbox()
    provider = StripePaymentIntentProvider(sandbox)
    signer = Ed25519ReceiptSigner.from_seed(b"\x04" * 32)
    constitution = Constitution(
        name="stripe-test",
        version="2026.11",
        rules=[Rule(id="r1", text="block wire", severity=Severity.CRITICAL, keywords=["wire"])],
    )
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    registry = ProviderContractRegistry()
    registry.register(provider.contract)

    store = EffectStore(db)
    store.create_budget("stripe", 50_000)
    contracted = ContractedEffectStore(store, registry)

    grant = _mint_grant(
        engine=engine,
        constitution=constitution,
        authority=authority,
        signer=signer,
        customer_id="cus_late",
        amount_cents=3500,
        scope="prod",
    )
    effect = store.reserve(
        provider_id=provider.provider_id,
        grant_identity=local_grant_identity(grant),
        action={"customer_id": "cus_late", "amount_cents": 3500, "currency": "usd"},
        budget_id="stripe",
        amount=3500,
    )
    sandbox.inject_timeout_once(effect.key, commit_before_timeout=False)
    with pytest.raises(TimeoutError):
        contracted.send(effect.key, provider, grant=grant)
    assert store.get(effect.key).state is EffectState.UNKNOWN

    # Restart store and reconcile -> NOT_DONE + fenced
    reopened = ContractedEffectStore(EffectStore(db), registry)
    rec = reopened.reconcile(effect.key, provider)
    assert rec.state is EffectState.NOT_DONE
    signed = sign_outcome(
        outcome_from_record(rec, store=reopened, provider=provider, grant=grant),
        signer,
    )
    assert signed.verify(signer.public_key_hex()) is True

    # A late delayed send to the sandbox for that fenced key is refused
    with pytest.raises(RuntimeError, match="permanently fenced"):
        sandbox.create_payment_intent(
            idempotency_key=effect.key, amount_cents=3500, currency="usd", customer_id="cus_late"
        )


def test_live_stripe_transport_rejects_live_keys() -> None:
    for bad in ("", "sk_live_secret123", "pk_test_123", "bearer_token"):
        with pytest.raises(ValueError, match="Test Mode"):
            LiveStripeTestTransport(bad)
    ok = LiveStripeTestTransport("sk_test_1234567890")
    assert ok is not None


def test_live_stripe_transport_unknown_when_absent_on_search(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
        urllib.request, "urlopen", lambda req, timeout=10.0: _FakeResp({"data": []})
    )
    transport = LiveStripeTestTransport("sk_test_abc")
    outcome, pi_id, fenced = transport.retrieve_and_fence(idempotency_key="acgs:effect:v1:abc")
    assert outcome is EffectOutcome.UNKNOWN
    assert pi_id is None
    assert fenced is False


@pytest.mark.parametrize(
    ("status", "expected_outcome", "expected_fenced"),
    [
        ("succeeded", EffectOutcome.DONE, False),
        ("canceled", EffectOutcome.NOT_DONE, True),
        ("processing", EffectOutcome.UNKNOWN, False),
        ("requires_capture", EffectOutcome.UNKNOWN, False),
        ("requires_action", EffectOutcome.UNKNOWN, False),
    ],
)
def test_live_stripe_transport_status_mapping(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    expected_outcome: EffectOutcome,
    expected_fenced: bool,
) -> None:
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
        lambda req, timeout=10.0: _FakeResp({"data": [{"id": "pi_test_1", "status": status}]}),
    )
    transport = LiveStripeTestTransport("sk_test_abc")
    outcome, pi_id, fenced = transport.retrieve_and_fence(idempotency_key="acgs:effect:v1:xyz")
    assert outcome is expected_outcome
    assert pi_id == "pi_test_1"
    assert fenced is expected_fenced


@pytest.mark.parametrize("incomplete_status", ["processing", "requires_capture"])
def test_provider_send_keeps_incomplete_payment_in_unknown(
    tmp_path: Path, incomplete_status: str
) -> None:
    pytest.importorskip("cryptography")

    class _StatusTransport:
        def create_payment_intent(
            self,
            *,
            idempotency_key: str,
            amount_cents: int,
            currency: str,
            customer_id: str,
        ) -> dict[str, object]:
            return {"id": "pi_pending_1", "status": incomplete_status}

        def retrieve_and_fence(
            self, *, idempotency_key: str
        ) -> tuple[EffectOutcome, str | None, bool]:
            return EffectOutcome.UNKNOWN, "pi_pending_1", False

    provider = StripePaymentIntentProvider(_StatusTransport())
    signer = Ed25519ReceiptSigner.from_seed(b"\x07" * 32)
    constitution = Constitution(
        name="stripe-pending",
        version="2026.11",
        rules=[Rule(id="r1", text="block wire", severity=Severity.CRITICAL, keywords=["wire"])],
    )
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    registry = ProviderContractRegistry()
    registry.register(provider.contract)
    store = EffectStore(tmp_path / "pending.sqlite")
    store.create_budget("stripe", 50_000)
    contracted = ContractedEffectStore(store, registry)

    grant = _mint_grant(
        engine=engine,
        constitution=constitution,
        authority=authority,
        signer=signer,
        customer_id="cus_pending",
        amount_cents=1500,
        scope="prod",
    )
    effect = store.reserve(
        provider_id=provider.provider_id,
        grant_identity=local_grant_identity(grant),
        action={"customer_id": "cus_pending", "amount_cents": 1500, "currency": "usd"},
        budget_id="stripe",
        amount=1500,
    )
    rec = contracted.send(effect.key, provider, grant=grant)
    assert rec.state is EffectState.UNKNOWN


def test_main_with_live_test_key_fails_on_http_error_and_succeeds_when_ok(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("cryptography")
    import io
    import urllib.error

    monkeypatch.setenv("STRIPE_TEST_API_KEY", "sk_test_dummy")

    def _fail_urlopen(req: object, timeout: float = 10.0) -> object:
        raise urllib.error.HTTPError(
            "https://api.stripe.com/v1/payment_intents",
            401,
            "Unauthorized",
            {},  # type: ignore[arg-type]
            io.BytesIO(b'{"error":{"message":"Invalid API Key"}}'),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _fail_urlopen)
    rc_fail = main()
    out_fail = json.loads(capsys.readouterr().out)
    assert rc_fail == 1
    assert out_fail["all_passed"] is False
    assert out_fail["live_verification"]["passed"] is False
    assert "HTTPError" in out_fail["live_verification"]["error"]

    class _FakeResp:
        def __init__(self, body: dict[str, object]) -> None:
            self._body = json.dumps(body).encode("utf-8")

        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return self._body

    def _ok_urlopen(req: urllib.request.Request, timeout: float = 10.0) -> _FakeResp:
        if "/payment_intents/search" in req.full_url:
            return _FakeResp({"data": [{"id": "pi_live_mock_1", "status": "succeeded"}]})
        return _FakeResp({"id": "pi_live_mock_1", "status": "succeeded"})

    monkeypatch.setattr(urllib.request, "urlopen", _ok_urlopen)
    rc_ok = main()
    out_ok = json.loads(capsys.readouterr().out)
    assert rc_ok == 0
    assert out_ok["all_passed"] is True
    assert out_ok["live_verification"]["passed"] is True
    assert out_ok["live_verification"]["idempotent_dedup_matched"] is True
