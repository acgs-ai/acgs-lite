"""Criterion 13: Ed25519 execution signatures are mandatory on the production path.

Every test drives the decorated function (the dispatcher); a denial must leave
``calls == []``. Construction rules are checked through ``GovernedCallable``.
"""

from __future__ import annotations

import json
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

pytest.importorskip("cryptography")

from acgs_lite.constitution import Constitution  # noqa: E402
from acgs_lite.governed import GovernedCallable  # noqa: E402
from acgs_lite.legitimacy import (  # noqa: E402
    AuthorizationProfile,
    LegitimacyInvariantError,
    TrustedExecutionContext,
)
from acgs_lite.legitimacy.authorization import (  # noqa: E402
    EngineDecision,
    authorization_envelope_json,
    build_issue_receipt,
    parse_authorization_envelope,
)
from acgs_lite.legitimacy.invocation import bind_invocation, bind_policy  # noqa: E402
from acgs_lite.legitimacy.receipt import BASELINE_CONSTRAINT_MARKER  # noqa: E402
from acgs_lite.legitimacy.signing import (  # noqa: E402
    SIGNATURE_SCOPE_EXECUTION,
    Ed25519ReceiptSigner,
    SignedReceipt,
    sign_execution_authorization,
    sign_receipt,
)

SIGNER = Ed25519ReceiptSigner.from_seed(bytes(range(32)), key_id="pinned")
OTHER = Ed25519ReceiptSigner.from_seed(bytes(range(1, 33)), key_id="other")
PINS = {"pinned": SIGNER.public_key_hex()}
_ALLOW = EngineDecision("ALLOW", (BASELINE_CONSTRAINT_MARKER,), (), None, 1)


def _guard(**options: Any) -> GovernedCallable:
    kwargs: dict[str, Any] = {"receipt_signer": SIGNER, "trusted_execution_keys": PINS}
    kwargs.update(options)
    return GovernedCallable(
        Constitution.default(), authorization_profile=AuthorizationProfile.PRODUCTION, **kwargs
    )


def _protected(guard: GovernedCallable, calls: list[str]) -> Any:
    def transfer(account_id: str) -> str:
        calls.append(account_id)
        return f"sent:{account_id}"

    return transfer, guard(transfer)


def _expiry(seconds: float = 300.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _forge(
    guard: GovernedCallable,
    func: Any,
    *args: Any,
    decision: EngineDecision = _ALLOW,
    grant_id: str = "a" * 32,
    envelope: dict[str, Any] | None = None,
    receipt_expires_at: str | None = "default",
    signer: Any = SIGNER,
    policy_constitution: Constitution | None = None,
    v2: bool = True,
    receipt_invocation: dict[str, Any] | None = None,
    receipt_policy_constitution: Constitution | None = None,
    receipt_context_digest: str | None = None,
) -> SignedReceipt:
    """Sign, with ``signer``, a receipt and envelope for the live call, then apply overrides.

    ``receipt_*`` overrides change only the receipt's bindings; the envelope still
    matches the live call, isolating the receipt-side half of each binding check.
    """
    invocation = bind_invocation(func, args, {}, include_receiver=True, strict_context=True)
    policy = bind_policy(policy_constitution or guard.constitution)
    expires_at = _expiry() if receipt_expires_at == "default" else receipt_expires_at
    receipt = build_issue_receipt(
        func=func,
        invocation=replace(invocation, **(receipt_invocation or {})),
        policy=bind_policy(receipt_policy_constitution) if receipt_policy_constitution else policy,
        decision=decision,
        grant_id=grant_id if v2 else None,
        context_digest=receipt_context_digest,
        expires_at=expires_at,
    )
    payload = parse_authorization_envelope(
        authorization_envelope_json(invocation, policy, grant_id=grant_id, expires_at=expires_at)
    )
    payload.update(envelope or {})
    payload = {key: value for key, value in payload.items() if value is not _DROP}
    return sign_execution_authorization(
        receipt, signer, authorization_json=json.dumps(payload, sort_keys=True)
    )


_DROP = object()


def _deny(wrapped: Any, calls: list[str], match: str, *args: Any, **kwargs: Any) -> None:
    with pytest.raises(LegitimacyInvariantError, match=match):
        wrapped(*args, **kwargs)
    assert calls == []


# --- construction ------------------------------------------------------------


def test_production_without_signer_is_refused() -> None:
    with pytest.raises(LegitimacyInvariantError, match="requires an Ed25519 receipt signer"):
        GovernedCallable(
            Constitution.default(), authorization_profile=AuthorizationProfile.PRODUCTION
        )


def test_ephemeral_generated_key_is_refused_even_when_pinned() -> None:
    ephemeral = Ed25519ReceiptSigner.generate(key_id="eph")
    assert ephemeral.ephemeral is True
    assert SIGNER.ephemeral is False
    with pytest.raises(LegitimacyInvariantError, match="ephemeral"):
        _guard(
            receipt_signer=ephemeral,
            trusted_execution_keys={"eph": ephemeral.public_key_hex()},
        )


@pytest.mark.parametrize(
    "pins",
    [
        {},
        {"pinned": OTHER.public_key_hex()},
        {"pinned": 7},
        {"pinned": "é" * 64},
    ],
)
def test_signer_key_must_be_pinned_for_execution(pins: dict[str, Any]) -> None:
    with pytest.raises(LegitimacyInvariantError, match="pinned in trusted_execution_keys"):
        _guard(trusted_execution_keys=pins)


def test_issuer_key_pin_is_not_an_execution_pin() -> None:
    with pytest.raises(LegitimacyInvariantError, match="pinned in trusted_execution_keys"):
        _guard(trusted_execution_keys=None, trusted_issuer_keys=PINS)


def test_non_ed25519_signer_is_refused() -> None:
    class HmacSigner:
        algorithm = "hmac-sha256"
        key_id = "pinned"

        def public_key_hex(self) -> str:
            return PINS["pinned"]

        def sign(self, message: bytes) -> str:
            return "00"

    with pytest.raises(LegitimacyInvariantError, match="must be Ed25519"):
        _guard(receipt_signer=HmacSigner())


@pytest.mark.parametrize("ttl", [0, -1.0, float("inf"), float("nan"), True, "300"])
def test_grant_ttl_must_be_positive_finite(ttl: Any) -> None:
    with pytest.raises(LegitimacyInvariantError, match="grant_ttl_seconds"):
        _guard(grant_ttl_seconds=ttl)


@pytest.mark.parametrize(
    "option",
    [{"receipt_signer": SIGNER}, {"trusted_execution_keys": PINS}, {"grant_ttl_seconds": 30}],
)
def test_signing_options_outside_production_are_refused(option: dict[str, Any]) -> None:
    with pytest.raises(LegitimacyInvariantError, match="require the production profile"):
        GovernedCallable(Constitution.default(), **option)


def test_compatibility_grants_stay_unsigned_and_unexpiring() -> None:
    calls: list[str] = []
    guard = GovernedCallable(Constitution.default())
    _func, wrapped = _protected(guard, calls)
    grant = wrapped.issue_grant("acct-1")
    assert grant.signed_receipt is None
    assert grant.expires_at is None
    assert wrapped("acct-1", execution_grant=grant) == "sent:acct-1"


# --- every production execution is signed and verified ------------------------


def test_every_production_grant_carries_a_valid_v2_execution_signature() -> None:
    calls: list[str] = []
    guard = _guard()
    _func, wrapped = _protected(guard, calls)
    grant = wrapped.issue_grant("acct-1")
    signed = grant.signed_receipt
    assert isinstance(signed, SignedReceipt)
    assert signed.verify(PINS["pinned"])
    assert signed.signature_scope == SIGNATURE_SCOPE_EXECUTION
    assert signed.receipt is grant.receipt
    assert signed.receipt.schema_version == 2
    envelope = parse_authorization_envelope(signed.authorization_json or "")
    assert envelope["grant_id"] == grant.grant_id == signed.receipt.grant_id
    assert envelope["expires_at"] == grant.expires_at
    assert envelope["expires_at"] == signed.receipt.execution_boundary.expires_at
    lifetime = datetime.fromisoformat(envelope["expires_at"]) - datetime.now(timezone.utc)
    assert timedelta(seconds=290) < lifetime <= timedelta(seconds=300)
    assert envelope["policy_digest"] == bind_policy(guard.constitution).digest


def _spy(monkeypatch: pytest.MonkeyPatch, guard: GovernedCallable) -> list[object]:
    seen: list[object] = []
    original = guard._verify_signed_production

    def spy(signed: object, *args: Any) -> Any:
        seen.append(signed)
        return original(signed, *args)

    monkeypatch.setattr(guard, "_verify_signed_production", spy)
    return seen


def test_grant_branch_runs_once_through_signature_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    guard = _guard()
    _func, wrapped = _protected(guard, calls)
    seen = _spy(monkeypatch, guard)
    grant = wrapped.issue_grant("acct-1")
    assert wrapped("acct-1", execution_grant=grant) == "sent:acct-1"
    assert seen == [grant.signed_receipt]
    with pytest.raises(LegitimacyInvariantError, match="already consumed"):
        wrapped("acct-1", execution_grant=grant)
    assert calls == ["acct-1"]


def test_signed_receipt_branch_runs_once_and_refuses_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    guard = _guard()
    _func, wrapped = _protected(guard, calls)
    seen = _spy(monkeypatch, guard)
    grant = wrapped.issue_grant("acct-1")
    wire = SignedReceipt.from_dict(json.loads(json.dumps(grant.signed_receipt.to_dict())))
    assert wrapped("acct-1", signed_receipt=wire) == "sent:acct-1"
    assert seen == [wire]
    with pytest.raises(LegitimacyInvariantError, match="already consumed"):
        wrapped("acct-1", signed_receipt=wire)
    with pytest.raises(LegitimacyInvariantError, match="already consumed"):
        wrapped("acct-1", execution_grant=grant)
    assert calls == ["acct-1"]


def test_grant_then_signed_receipt_is_a_replay() -> None:
    calls: list[str] = []
    _func, wrapped = _protected(_guard(), calls)
    grant = wrapped.issue_grant("acct-1")
    wrapped("acct-1", execution_grant=grant)
    with pytest.raises(LegitimacyInvariantError, match="already consumed"):
        wrapped("acct-1", signed_receipt=grant.signed_receipt)
    assert calls == ["acct-1"]


async def test_async_signed_receipt_branch_is_verified() -> None:
    calls: list[str] = []
    guard = _guard()

    @guard
    async def transfer(account_id: str) -> str:
        calls.append(account_id)
        return "sent"

    grant = transfer.issue_grant("acct-1")
    assert await transfer("acct-1", signed_receipt=grant.signed_receipt) == "sent"
    with pytest.raises(LegitimacyInvariantError, match="authenticity"):
        await transfer(
            "acct-1",
            signed_receipt=replace(grant.signed_receipt, signature="00" * 64),
        )
    assert calls == ["acct-1"]


# --- negative cases: each denies before the callable runs ----------------------


def test_tampered_signature_denies_on_both_branches() -> None:
    calls: list[str] = []
    _func, wrapped = _protected(_guard(), calls)
    grant = wrapped.issue_grant("acct-1")
    sig = grant.signed_receipt.signature
    tampered = replace(grant.signed_receipt, signature=("0" if sig[0] != "0" else "1") + sig[1:])
    _deny(wrapped, calls, "authenticity", "acct-1", signed_receipt=tampered)
    _deny(
        wrapped,
        calls,
        "authenticity",
        "acct-1",
        execution_grant=replace(grant, signed_receipt=tampered),
    )


def test_tampered_authorization_envelope_denies() -> None:
    calls: list[str] = []
    _func, wrapped = _protected(_guard(), calls)
    grant = wrapped.issue_grant("acct-1")
    envelope = parse_authorization_envelope(grant.signed_receipt.authorization_json or "")
    envelope["expires_at"] = _expiry(86_400)
    tampered = replace(grant.signed_receipt, authorization_json=json.dumps(envelope))
    _deny(wrapped, calls, "authenticity", "acct-1", signed_receipt=tampered)


def test_receipt_scope_signature_by_pinned_key_denies() -> None:
    calls: list[str] = []
    _func, wrapped = _protected(_guard(), calls)
    grant = wrapped.issue_grant("acct-1")
    receipt_scope = sign_receipt(grant.receipt, SIGNER)
    _deny(
        wrapped, calls, "unsigned receipt is not executable", "acct-1", signed_receipt=receipt_scope
    )


def test_unpinned_key_denies_even_when_pinned_as_issuer() -> None:
    calls: list[str] = []
    guard = _guard(trusted_issuer_keys={"other": OTHER.public_key_hex()})
    func, wrapped = _protected(guard, calls)
    grant = wrapped.issue_grant("acct-1")
    resigned = sign_execution_authorization(
        grant.receipt, OTHER, authorization_json=grant.signed_receipt.authorization_json or ""
    )
    _deny(wrapped, calls, "not pinned for execution", "acct-1", signed_receipt=resigned)
    _deny(
        wrapped,
        calls,
        "not pinned for execution",
        "acct-1",
        signed_receipt=replace(grant.signed_receipt, key_id=["pinned"]),
    )
    # A pinned key id presenting a different public key fails authenticity.
    impostor = replace(resigned, key_id="pinned")
    _deny(wrapped, calls, "authenticity", "acct-1", signed_receipt=impostor)


@pytest.mark.parametrize(
    ("decision_type", "rule"),
    [("DENY_GOAL", "no-x"), ("STRUCTURED_REVIEW_REQUIRED", "review-x"), ("HARD_DENY", "halt")],
)
def test_non_executable_decision_signed_by_pinned_key_denies(decision_type: str, rule: str) -> None:
    calls: list[str] = []
    guard = _guard()
    func, wrapped = _protected(guard, calls)
    decision = EngineDecision(decision_type, (rule,), (), "engine refused", 1)  # type: ignore[arg-type]
    forged = _forge(guard, func, "acct-1", decision=decision)
    _deny(wrapped, calls, "does not permit execution", "acct-1", signed_receipt=forged)


def test_v1_receipt_with_execution_signature_denies() -> None:
    calls: list[str] = []
    guard = _guard()
    func, wrapped = _protected(guard, calls)
    forged = _forge(guard, func, "acct-1", v2=False)
    assert forged.receipt.schema_version is None
    _deny(wrapped, calls, "only v2 receipts", "acct-1", signed_receipt=forged)


def test_expired_signature_denies_on_both_branches() -> None:
    calls: list[str] = []
    _func, wrapped = _protected(_guard(grant_ttl_seconds=0.01), calls)
    grant = wrapped.issue_grant("acct-1")
    time.sleep(0.05)
    _deny(wrapped, calls, "expired", "acct-1", signed_receipt=grant.signed_receipt)
    _deny(wrapped, calls, "expired", "acct-1", execution_grant=grant)


def test_monotonic_deadline_denies_after_wall_clock_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    _func, wrapped = _protected(_guard(), calls)
    grant = wrapped.issue_grant("acct-1")
    real = time.monotonic
    # The wall clock still says the grant is fresh; the monotonic deadline has passed.
    monkeypatch.setattr(time, "monotonic", lambda: real() + 3_600)
    _deny(wrapped, calls, "expired", "acct-1", signed_receipt=grant.signed_receipt)


@pytest.mark.parametrize(
    ("receipt_expires_at", "envelope", "match"),
    [
        (None, {"expires_at": _DROP}, "has no expiry"),
        ("default", {"expires_at": "2999-01-01T00:00:00+00:00"}, "does not match receipt"),
        ("not-a-date", {"expires_at": "not-a-date"}, "not parseable"),
        ("2999-01-01T00:00:00", {"expires_at": "2999-01-01T00:00:00"}, "must carry a timezone"),
    ],
)
def test_malformed_expiry_denies(
    receipt_expires_at: str | None, envelope: dict[str, Any], match: str
) -> None:
    calls: list[str] = []
    guard = _guard()
    func, wrapped = _protected(guard, calls)
    forged = _forge(guard, func, "acct-1", receipt_expires_at=receipt_expires_at, envelope=envelope)
    _deny(wrapped, calls, match, "acct-1", signed_receipt=forged)


def test_context_digest_mismatch_denies() -> None:
    calls: list[str] = []

    def context(actor: str) -> TrustedExecutionContext:
        return TrustedExecutionContext(
            actor_id=actor, scope="tenant-a", allowed_subjects=frozenset({"acct-1"})
        )

    def transfer(account_id: str, *, scope: str) -> str:
        calls.append(account_id)
        return "sent"

    issuer = _guard(trusted_execution_context=context("alice"))(transfer)
    other = _guard(trusted_execution_context=context("mallory"))(transfer)
    grant = issuer.issue_grant("acct-1", scope="tenant-a")
    _deny(
        other,
        calls,
        "trusted execution context binding mismatch",
        "acct-1",
        scope="tenant-a",
        signed_receipt=grant.signed_receipt,
    )


def test_grant_id_mismatch_between_envelope_and_receipt_denies() -> None:
    calls: list[str] = []
    guard = _guard()
    func, wrapped = _protected(guard, calls)
    forged = _forge(guard, func, "acct-1", envelope={"grant_id": "b" * 32})
    _deny(wrapped, calls, "grant id does not match receipt", "acct-1", signed_receipt=forged)


def test_signed_receipt_for_different_arguments_denies() -> None:
    calls: list[str] = []
    _func, wrapped = _protected(_guard(), calls)
    grant = wrapped.issue_grant("acct-1")
    _deny(
        wrapped, calls, "invocation binding mismatch", "acct-2", signed_receipt=grant.signed_receipt
    )


@pytest.mark.parametrize(
    ("envelope", "match"),
    [
        ({"method_id": "other:method"}, "method identity mismatch"),
        ({"scope": "tenant-b"}, "scope mismatch"),
        ({"subjects": ["acct-9"]}, "subjects mismatch"),
    ],
)
def test_envelope_binding_mismatch_denies(envelope: dict[str, Any], match: str) -> None:
    calls: list[str] = []
    guard = _guard()
    func, wrapped = _protected(guard, calls)
    forged = _forge(guard, func, "acct-1", envelope=envelope)
    _deny(wrapped, calls, match, "acct-1", signed_receipt=forged)


def test_policy_digest_mismatch_denies() -> None:
    calls: list[str] = []
    guard = _guard()
    func, wrapped = _protected(guard, calls)
    stale = Constitution.from_yaml_str("rules:\n  - {id: r, text: r, keywords: [zzz]}")
    forged = _forge(guard, func, "acct-1", policy_constitution=stale)
    _deny(wrapped, calls, "policy binding mismatch", "acct-1", signed_receipt=forged)


def test_signature_not_issued_by_this_instance_denies() -> None:
    calls: list[str] = []
    guard = _guard()
    func, wrapped = _protected(guard, calls)
    # Pinned key, ALLOW, every binding correct -- but this instance never issued it.
    forged = _forge(guard, func, "acct-1")
    _deny(wrapped, calls, "not issued by this governed callable", "acct-1", signed_receipt=forged)
    # A second instance with the same pinned key shares no ledger and refuses it too.
    issued = _protected(_guard(), [])[1].issue_grant("acct-1")
    _deny(
        wrapped,
        calls,
        "not issued by this governed callable",
        "acct-1",
        signed_receipt=issued.signed_receipt,
    )


def test_same_qualname_different_function_denies() -> None:
    calls: list[str] = []
    guard = _guard()

    def original(account_id: str) -> str:
        calls.append(f"original:{account_id}")
        return "original"

    def alternate(account_id: str) -> str:
        calls.append(f"alternate:{account_id}")
        return "alternate"

    alternate.__qualname__ = original.__qualname__
    protected = guard(original)
    impostor = guard(alternate)
    grant = protected.issue_grant("acct-1")
    with pytest.raises(LegitimacyInvariantError, match="^grant callable identity mismatch$"):
        impostor("acct-1", signed_receipt=grant.signed_receipt)
    assert calls == []


def test_grant_without_or_with_foreign_signature_denies() -> None:
    calls: list[str] = []
    _func, wrapped = _protected(_guard(), calls)
    grant = wrapped.issue_grant("acct-1")
    other = wrapped.issue_grant("acct-1")
    _deny(
        wrapped,
        calls,
        "carries no execution signature",
        "acct-1",
        execution_grant=replace(grant, signed_receipt=None),
    )
    _deny(
        wrapped,
        calls,
        "does not sign the grant receipt",
        "acct-1",
        execution_grant=replace(grant, signed_receipt=other.signed_receipt),
    )


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"algorithm": "rsa"}, "must be Ed25519"),
        ({"authorization_json": None}, "missing an authorization envelope"),
    ],
)
def test_malformed_signed_carrier_denies(change: dict[str, Any], match: str) -> None:
    calls: list[str] = []
    _func, wrapped = _protected(_guard(), calls)
    grant = wrapped.issue_grant("acct-1")
    _deny(wrapped, calls, match, "acct-1", signed_receipt=replace(grant.signed_receipt, **change))
    _deny(wrapped, calls, "Invalid signed receipt type", "acct-1", signed_receipt=grant.receipt)


def test_authority_refuses_signature_over_a_different_receipt() -> None:
    guard = _guard()
    func, wrapped = _protected(guard, [])
    grant = wrapped.issue_grant("acct-1")
    invocation = bind_invocation(func, ("acct-1",), {}, include_receiver=True, strict_context=True)
    policy = bind_policy(guard.constitution)
    grant_id = guard._authority.allocate_grant_id()
    receipt = build_issue_receipt(
        func=func, invocation=invocation, policy=policy, decision=_ALLOW, grant_id=grant_id
    )
    with pytest.raises(LegitimacyInvariantError, match="does not sign this grant's receipt"):
        guard._authority.issue(
            receipt=receipt,
            invocation=invocation,
            policy=policy,
            grant_id=grant_id,
            signed_receipt=grant.signed_receipt,
        )


# --- issued-receipt binding: grant id alone never authorizes ------------------

TWO_PINS = {"pinned": SIGNER.public_key_hex(), "other": OTHER.public_key_hex()}


def test_second_pinned_key_cannot_reuse_a_live_grant_id() -> None:
    calls: list[str] = []
    guard = _guard(trusted_execution_keys=TWO_PINS)
    func, wrapped = _protected(guard, calls)
    grant = wrapped.issue_grant("benign")
    live_gid = grant.grant_id
    forged = _forge(guard, func, "evil", grant_id=live_gid, signer=OTHER)
    _deny(
        wrapped,
        calls,
        "^signed receipt key did not issue this grant$",
        "evil",
        signed_receipt=forged,
    )
    # The issued receipt re-signed by the other pinned key: same receipt hash, wrong key.
    resigned = sign_execution_authorization(
        grant.receipt, OTHER, authorization_json=grant.signed_receipt.authorization_json or ""
    )
    _deny(
        wrapped,
        calls,
        "^signed receipt key did not issue this grant$",
        "benign",
        signed_receipt=resigned,
    )
    # Even the issuing key cannot mint a different receipt under a live grant id.
    rebound = _forge(guard, func, "evil", grant_id=live_gid, signer=SIGNER)
    _deny(
        wrapped,
        calls,
        "^signed receipt is not the receipt issued for this grant$",
        "evil",
        signed_receipt=rebound,
    )
    # The forgeries never reached the ledger: the legitimate grant still executes once.
    assert wrapped("benign", execution_grant=grant) == "sent:benign"
    assert calls == ["benign"]


def test_from_private_bytes_key_is_accepted_as_documented() -> None:
    # "Ephemeral" is detectable only for generate(); a loaded key is trusted to be
    # provisioned out of band. Pin that documented behaviour.
    loaded = Ed25519ReceiptSigner.from_private_bytes(bytes(range(2, 34)), key_id="loaded")
    assert loaded.ephemeral is False
    calls: list[str] = []
    guard = _guard(
        receipt_signer=loaded, trusted_execution_keys={"loaded": loaded.public_key_hex()}
    )
    _func, wrapped = _protected(guard, calls)
    assert wrapped("acct-1", execution_grant=wrapped.issue_grant("acct-1")) == "sent:acct-1"


# --- expiry blocks new executions, never recovery of a recorded attempt --------


def test_expired_grant_denies_a_new_attempt() -> None:
    calls: list[str] = []
    _func, wrapped = _protected(_guard(grant_ttl_seconds=0.01), calls)
    grant = wrapped.issue_grant("acct-1")
    time.sleep(0.05)
    _deny(wrapped, calls, "expired", "acct-1", execution_grant=grant, execution_attempt_id="att-1")
    _deny(
        wrapped,
        calls,
        "expired",
        "acct-1",
        signed_receipt=grant.signed_receipt,
        execution_attempt_id="att-1",
    )


def test_expired_grant_recovers_a_completed_attempt_without_a_new_call() -> None:
    calls: list[str] = []
    guard = _guard(grant_ttl_seconds=0.2)
    _func, wrapped = _protected(guard, calls)
    grant = wrapped.issue_grant("acct-1")
    assert wrapped("acct-1", execution_grant=grant, execution_attempt_id="att-1") == "sent:acct-1"
    time.sleep(0.3)
    # A later issue prunes expired registry entries; a consumed one must survive it.
    wrapped.issue_grant("acct-2")
    assert grant.grant_id in guard._signed_grants
    assert wrapped("acct-1", execution_grant=grant, execution_attempt_id="att-1") == "sent:acct-1"
    assert (
        wrapped("acct-1", signed_receipt=grant.signed_receipt, execution_attempt_id="att-1")
        == "sent:acct-1"
    )
    assert calls == ["acct-1"]
    # Recovery still verifies everything except the clock.
    sig = grant.signed_receipt.signature
    tampered = replace(grant.signed_receipt, signature=("0" if sig[0] != "0" else "1") + sig[1:])
    with pytest.raises(LegitimacyInvariantError, match="authenticity"):
        wrapped("acct-1", signed_receipt=tampered, execution_attempt_id="att-1")
    with pytest.raises(LegitimacyInvariantError, match="invocation binding mismatch"):
        wrapped("acct-2", signed_receipt=grant.signed_receipt, execution_attempt_id="att-1")
    # A different attempt id is a new execution, and expiry blocks it.
    with pytest.raises(LegitimacyInvariantError, match="expired"):
        wrapped("acct-1", execution_grant=grant, execution_attempt_id="att-2")
    assert calls == ["acct-1"]


def test_issue_prunes_expired_unconsumed_grants_and_keeps_live_ones() -> None:
    guard = _guard(grant_ttl_seconds=0.05)
    _func, wrapped = _protected(guard, [])
    stale = wrapped.issue_grant("acct-1")
    time.sleep(0.1)
    live = wrapped.issue_grant("acct-2")
    assert stale.grant_id not in guard._signed_grants
    assert live.grant_id in guard._signed_grants


# --- the grant branch's own signature-side expiry checks -----------------------


def _authority_without_expiry(monkeypatch: pytest.MonkeyPatch, guard: GovernedCallable) -> None:
    original = guard._authority.verify

    def verify(grant: Any, **kwargs: Any) -> None:
        original(grant, **{**kwargs, "enforce_expiry": False})

    monkeypatch.setattr(guard._authority, "verify", verify)


def test_grant_branch_wall_clock_signature_expiry_is_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    guard = _guard(grant_ttl_seconds=0.01)
    _func, wrapped = _protected(guard, calls)
    _authority_without_expiry(monkeypatch, guard)
    grant = wrapped.issue_grant("acct-1")
    time.sleep(0.05)
    _deny(wrapped, calls, "^execution signature has expired$", "acct-1", execution_grant=grant)


def test_grant_branch_monotonic_deadline_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    guard = _guard()
    _func, wrapped = _protected(guard, calls)
    grant = wrapped.issue_grant("acct-1")
    real = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real() + 3_600)
    match = "^execution signature monotonic deadline has expired$"
    _deny(wrapped, calls, match, "acct-1", execution_grant=grant)
    _deny(wrapped, calls, match, "acct-1", signed_receipt=grant.signed_receipt)


# --- decision types and receipt-side binding halves ----------------------------


def test_allow_with_controls_executes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    guard = _guard()
    _func, wrapped = _protected(guard, calls)
    decision = EngineDecision(
        "ALLOW_WITH_CONTROLS", (BASELINE_CONSTRAINT_MARKER,), ("LOG_REVIEW",), None, 1
    )
    monkeypatch.setattr(guard, "_evaluate_invocation", lambda _args, _kwargs: decision)
    grant = wrapped.issue_grant("acct-1")
    assert grant.receipt.decision_type == "ALLOW_WITH_CONTROLS"
    assert wrapped("acct-1", execution_grant=grant) == "sent:acct-1"
    assert calls == ["acct-1"]


def test_unknown_decision_type_is_not_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    import acgs_lite.governed as governed_module

    calls: list[str] = []
    _func, wrapped = _protected(_guard(), calls)
    grant = wrapped.issue_grant("acct-1")

    def unknown(_value: object) -> str:
        raise ValueError("unknown decision")

    monkeypatch.setattr(governed_module, "canonicalize_decision_state", unknown)
    _deny(wrapped, calls, "^Unknown decision type is not allow$", "acct-1", execution_grant=grant)


@pytest.mark.parametrize(
    ("receipt_override", "match"),
    [
        ({"receipt_invocation": {"method_id": "other:method"}}, "method identity mismatch"),
        ({"receipt_invocation": {"argument_digest": "0" * 64}}, "invocation binding mismatch"),
        ({"receipt_invocation": {"scope": "tenant-b"}}, "scope mismatch"),
        ({"receipt_invocation": {"subjects": ("acct-9",)}}, "subjects mismatch"),
        ({"receipt_context_digest": "c" * 64}, "trusted execution context binding mismatch"),
        (
            {
                "receipt_policy_constitution": Constitution.from_yaml_str(
                    "rules:\n  - {id: r, text: r, keywords: [zzz]}"
                )
            },
            "policy binding mismatch",
        ),
    ],
)
def test_receipt_side_binding_mismatch_denies(receipt_override: dict[str, Any], match: str) -> None:
    calls: list[str] = []
    guard = _guard()
    func, wrapped = _protected(guard, calls)
    forged = _forge(guard, func, "acct-1", **receipt_override)
    envelope = parse_authorization_envelope(forged.authorization_json or "")
    live = bind_invocation(func, ("acct-1",), {}, include_receiver=True, strict_context=True)
    assert envelope["argument_digest"] == live.argument_digest
    _deny(wrapped, calls, match, "acct-1", signed_receipt=forged)
