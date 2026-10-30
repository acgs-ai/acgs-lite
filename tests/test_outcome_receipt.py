"""Outcome receipts: canonical form, strict wire format, signing and tamper evidence."""

import hashlib
import json
from dataclasses import replace
from datetime import datetime
from threading import Lock

import pytest

from acgs_lite.legitimacy import (
    BASELINE_CONSTRAINT_MARKER,
    OUTCOME_RECEIPT_SCHEMA,
    RECEIPT_SCHEMA_V2,
    ContractedEffectStore,
    DecisionReceipt,
    EffectOutcome,
    EffectState,
    EffectStore,
    ExecutionBoundary,
    OutcomeReceipt,
    ProviderContract,
    ProviderContractClass,
    ProviderContractRegistry,
    ProviderNotDispatchable,
    ProviderResult,
    SignedOutcomeReceipt,
    outcome_from_record,
    receipt_identity,
    sign_outcome,
    sign_receipt,
    signed_envelope_identity,
)

DECISION = "acgs:receipt:v1:sha256:" + "a" * 64
KEY = "acgs:effect:v1:" + "b" * 64
WHEN = "2026-10-29T12:00:00+00:00"


class Provider:
    """FENCEABLE spy: dedup by key, atomic query-and-fence."""

    provider_id = "payments"

    def __init__(self):
        self.sends = []
        self.done = set()
        self.fenced = set()
        self.lock = Lock()
        self.error = None
        self.land_before_error = True

    def send(self, request):
        with self.lock:
            self.sends.append(request)
            if request.key not in self.fenced and self.land_before_error:
                self.done.add(request.key)
            if self.error:
                raise self.error
            outcome = EffectOutcome.DONE if request.key in self.done else EffectOutcome.NOT_DONE
            return ProviderResult(request.key, self.provider_id, outcome, fenced=True)

    def query_and_fence(self, request):
        with self.lock:
            if request.key in self.done:
                return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE)
            self.fenced.add(request.key)
            return ProviderResult(
                request.key, self.provider_id, EffectOutcome.NOT_DONE, fenced=True
            )


def contract(provider_id="payments"):
    return ProviderContract(provider_id, ProviderContractClass.FENCEABLE, "1", True, True)


def receipt(**changes):
    args = dict(
        effect_key=KEY,
        provider_id="payments",
        provider_contract_digest=contract().digest,
        decision_receipt_identity=DECISION,
        outcome=EffectOutcome.DONE,
        recorded_at=WHEN,
        provider_reference="ch_123",
    )
    args.update(changes)
    return OutcomeReceipt(**args)


def signer():
    pytest.importorskip("cryptography")
    from acgs_lite.legitimacy import Ed25519ReceiptSigner

    return Ed25519ReceiptSigner.from_seed(b"\x01" * 32, key_id="outcome-test")


@pytest.fixture
def contracted(tmp_path):
    store = EffectStore(tmp_path / "effects.sqlite")
    store.create_budget("budget", 10)
    registry = ProviderContractRegistry()
    registry.register(contract())
    return ContractedEffectStore(store, registry)


def reserve(contracted, grant="grant"):
    return contracted.store.reserve(
        provider_id="payments",
        grant_identity=grant,
        action={"amount": 4},
        budget_id="budget",
        amount=4,
    )


def test_canonical_bytes_hash_and_identity():
    value = receipt()
    assert value.schema_version == OUTCOME_RECEIPT_SCHEMA
    canonical = json.dumps(
        value.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert value.canonical_bytes() == b"acgs-outcome-receipt-v1\x00" + canonical
    assert value.outcome_hash == hashlib.sha256(value.canonical_bytes()).hexdigest()
    assert value.identity == f"acgs:outcome:v1:sha256:{value.outcome_hash}"
    assert receipt().identity == value.identity
    assert "ü".encode() in receipt(provider_reference="ref-ü").canonical_bytes()


@pytest.mark.parametrize(
    "changes",
    [
        dict(outcome=EffectOutcome.NOT_DONE),
        dict(decision_receipt_identity="acgs:signed-envelope:v1:sha256:" + "c" * 64),
        dict(decision_receipt_identity="acgs:receipt:v2:sha256:" + "c" * 64),
        dict(provider_contract_digest="d" * 64),
        dict(provider_reference=None),
        dict(recorded_at="2026-10-29T12:00:01+00:00"),
        dict(effect_key="acgs:effect:v1:" + "e" * 64),
        dict(provider_id="payments-2"),
    ],
)
def test_hash_changes_with_every_field(changes):
    assert receipt(**changes).outcome_hash != receipt().outcome_hash


@pytest.mark.parametrize(
    "changes",
    [
        dict(outcome=EffectOutcome.UNKNOWN),
        dict(outcome="done"),
        dict(decision_receipt_identity=""),
        dict(decision_receipt_identity="acgs:receipt:"),
        dict(decision_receipt_identity="acgs:policy:v1:sha256:" + "a" * 64),
        dict(decision_receipt_identity=None),
        dict(effect_key="key"),
        dict(effect_key="acgs:effect:v1:" + "B" * 64),
        dict(provider_id=""),
        dict(provider_contract_digest="abc"),
        dict(provider_contract_digest=None),
        dict(provider_reference=""),
        dict(provider_reference=7),
        dict(recorded_at=""),
        dict(recorded_at="yesterday"),
        dict(recorded_at="2026-10-29T12:00:00"),
        dict(recorded_at="2026-10-29T12:00:00+02:00"),
        dict(recorded_at=None),
        dict(schema_version="acgs-outcome-receipt-v2"),
    ],
)
def test_invalid_receipts_raise(changes):
    with pytest.raises(ValueError):
        receipt(**changes)


def test_zulu_timestamp_accepted_on_all_supported_versions():
    assert receipt(recorded_at="2026-10-29T12:00:00Z").recorded_at.endswith("Z")


def test_receipt_dict_round_trip_and_strict_fields():
    value = receipt()
    assert OutcomeReceipt.from_dict(value.to_dict()) == value
    assert OutcomeReceipt.from_dict(json.loads(json.dumps(value.to_dict()))) == value
    missing = value.to_dict()
    del missing["provider_reference"]
    extra = {**value.to_dict(), "settled_amount": 4}
    unknown = {**value.to_dict(), "outcome": "maybe"}
    pending = {**value.to_dict(), "outcome": "unknown"}
    for payload in (missing, extra, unknown, pending, [], "x"):
        with pytest.raises(ValueError):
            OutcomeReceipt.from_dict(payload)


def test_outcome_from_record_requires_terminal_matching_provider(contracted):
    effect = reserve(contracted)
    with pytest.raises(ValueError, match="not terminal"):
        outcome_from_record(effect, contract=contract(), decision_receipt_identity=DECISION)
    for state in (EffectState.IN_FLIGHT, EffectState.UNKNOWN):
        with pytest.raises(ValueError, match="not terminal"):
            outcome_from_record(
                replace(effect, state=state),
                contract=contract(),
                decision_receipt_identity=DECISION,
            )
    done = replace(effect, state=EffectState.DONE)
    with pytest.raises(ValueError, match="different provider"):
        outcome_from_record(done, contract=contract("refunds"), decision_receipt_identity=DECISION)
    with pytest.raises(ValueError, match="decision receipt"):
        outcome_from_record(done, contract=contract(), decision_receipt_identity="")
    with pytest.raises(TypeError):
        outcome_from_record(object(), contract=contract(), decision_receipt_identity=DECISION)
    with pytest.raises(TypeError):
        outcome_from_record(done, contract=object(), decision_receipt_identity=DECISION)
    built = outcome_from_record(done, contract=contract(), decision_receipt_identity=DECISION)
    assert built.outcome is EffectOutcome.DONE
    assert built.provider_contract_digest == contract().digest
    assert datetime.fromisoformat(built.recorded_at).utcoffset().total_seconds() == 0


def test_fenceable_send_done_signed_outcome_verifies(contracted):
    key = signer()
    provider = Provider()
    effect = reserve(contracted)
    record = contracted.send(effect.key, provider)
    assert record.state is EffectState.DONE
    pinned = contracted.contract_for(effect.key, provider)
    outcome = outcome_from_record(
        record,
        contract=pinned,
        decision_receipt_identity=DECISION,
        provider_reference="ch_1",
        recorded_at=WHEN,
    )
    signed = sign_outcome(outcome, key)
    assert signed.verify(key.public_key_hex()) is True
    assert signed.key_id == "outcome-test"
    restored = SignedOutcomeReceipt.from_dict(json.loads(json.dumps(signed.to_dict())))
    assert restored == signed
    assert restored.verify(key.public_key_hex()) is True


@pytest.mark.parametrize(
    ("lands", "expected"),
    [
        (True, EffectOutcome.DONE),
        (False, EffectOutcome.NOT_DONE),
    ],
)
def test_timeout_unknown_has_no_receipt_until_reconciled(contracted, lands, expected):
    key = signer()
    provider = Provider()
    provider.error = TimeoutError()
    provider.land_before_error = lands
    effect = reserve(contracted)
    with pytest.raises(TimeoutError):
        contracted.send(effect.key, provider)
    record = contracted.store.get(effect.key)
    assert record.state is EffectState.UNKNOWN
    with pytest.raises(ValueError, match="not terminal"):
        outcome_from_record(record, contract=contract(), decision_receipt_identity=DECISION)
    reconciled = contracted.reconcile(effect.key, provider)
    assert reconciled.state.value == expected.value
    outcome = outcome_from_record(
        reconciled, contract=contract(), decision_receipt_identity=DECISION
    )
    assert outcome.outcome is expected
    assert sign_outcome(outcome, key).verify(key.public_key_hex()) is True
    assert len(provider.sends) == 1


@pytest.mark.parametrize(
    "changes",
    [
        dict(outcome=EffectOutcome.NOT_DONE),
        dict(decision_receipt_identity="acgs:receipt:v1:sha256:" + "f" * 64),
        dict(provider_contract_digest="0" * 64),
        dict(provider_reference="ch_other"),
    ],
)
def test_tampered_receipt_fields_fail_verification(changes):
    key = signer()
    signed = sign_outcome(receipt(), key)
    tampered = replace(signed, receipt=replace(signed.receipt, **changes))
    assert tampered.verify(key.public_key_hex()) is False


def test_tampered_envelope_fails_without_raising():
    key = signer()
    signed = sign_outcome(receipt(), key)
    flipped = ("0" if signed.signature[0] != "0" else "1") + signed.signature[1:]
    other = type(key).from_seed(b"\x02" * 32)
    for candidate, pinned in (
        (replace(signed, signature=flipped), key.public_key_hex()),
        (replace(signed, signature="00"), key.public_key_hex()),
        (replace(signed, algorithm="rsa"), key.public_key_hex()),
        (replace(signed, public_key=other.public_key_hex()), other.public_key_hex()),
        (replace(signed, public_key="abcd"), "abcd"),
        (signed, other.public_key_hex()),
        (signed, "é"),
        (signed, None),
    ):
        assert candidate.verify(pinned) is False


def test_key_id_and_algorithm_are_signed():
    key = signer()
    signed = sign_outcome(receipt(), key)
    assert replace(signed, key_id="attacker-chosen").verify(key.public_key_hex()) is False
    payload = signed.to_dict()
    payload["key_id"] = "attacker-chosen"
    assert SignedOutcomeReceipt.from_dict(payload).verify(key.public_key_hex()) is False
    unicode_id = type(key).from_seed(b"\x03" * 32, key_id="schlüssel")
    assert sign_outcome(receipt(), unicode_id).verify(unicode_id.public_key_hex()) is True


@pytest.mark.parametrize("field", ["signature", "public_key"])
@pytest.mark.parametrize(
    "rewrite",
    [
        str.upper,
        lambda value: " ".join(value[i : i + 2] for i in range(0, len(value), 2)),
        lambda value: value + "0",
        lambda value: "",
        lambda value: "zz",
    ],
)
def test_hex_fields_have_one_serialization(field, rewrite):
    signed = sign_outcome(receipt(), signer())
    with pytest.raises(ValueError, match="lowercase hexadecimal"):
        replace(signed, **{field: rewrite(getattr(signed, field))})
    payload = {**signed.to_dict(), field: rewrite(getattr(signed, field))}
    with pytest.raises(ValueError):
        SignedOutcomeReceipt.from_dict(payload)


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-29T00:00:00-00:00",
        "2026-10-29 00:00:00+00:00",
        "20261029T000000+0000",
        "2026-W44-4T00:00:00+00:00",
        "2026-10-29T00:00:00+00:00:00.5",
        "2026-10-29T00:00+00:00",
        "2026-10-29T00:00:00.1234567+00:00",
        "2026-10-29T00:00:00.5+00:00",
        "2026-10-29T00:00:00.500+00:00",
        "2026-10-29T00:00:00z",
        "2026-13-29T00:00:00+00:00",
        "\u0662026-10-29T00:00:00+00:00",
    ],
)
def test_non_canonical_timestamps_rejected(value):
    with pytest.raises(ValueError):
        receipt(recorded_at=value)


@pytest.mark.parametrize(
    "value",
    ["2026-10-29T00:00:00Z", "2026-10-29T00:00:00+00:00", "2026-10-29T00:00:00.123456+00:00"],
)
def test_canonical_timestamps_accepted(value):
    assert receipt(recorded_at=value).recorded_at == value


def test_outcome_from_record_rejects_empty_recorded_at(contracted):
    done = replace(reserve(contracted), state=EffectState.DONE)
    with pytest.raises(ValueError, match="recorded_at"):
        outcome_from_record(
            done, contract=contract(), decision_receipt_identity=DECISION, recorded_at=""
        )


@pytest.mark.parametrize(
    "identity",
    [
        "acgs:receipt: \n<anything>",
        "acgs:receipt:v1:sha256:" + "a" * 63,
        "acgs:receipt:v1:sha256:" + "A" * 64,
        "acgs:receipt:v1:sha256:" + "a" * 64 + "\n",
        "acgs:receipt:v1:sha512:" + "a" * 64,
        "acgs:receipt:v3:sha256:" + "a" * 64,
        "acgs:signed-envelope:v1:" + "a" * 64,
        "acgs:signed-envelope:v2:sha256:" + "a" * 64,
        "acgs:outcome:v1:sha256:" + "a" * 64,
    ],
)
def test_decision_identity_grammar_enforced(identity):
    with pytest.raises(ValueError, match="decision receipt"):
        receipt(decision_receipt_identity=identity)


def test_v2_decision_receipt_and_envelope_identities_accepted(contracted):
    key = signer()
    decision = DecisionReceipt.create(
        request_id="req-v2",
        goal="tools/call refund",
        proposed_method="refund",
        decision_type="ALLOW",
        authority_basis="acgs-constitution:default",
        matched_constraints=(BASELINE_CONSTRAINT_MARKER,),
        policy_version="v1",
        execution_boundary=ExecutionBoundary(
            allowed_method="refund",
            allowed_scope="call-digest:sha256:" + "1" * 64,
            allowed_subjects=(),
            expires_at=None,
            single_use=True,
        ),
        schema_version=RECEIPT_SCHEMA_V2,
        grant_id="grant-v2",
        policy_digest="2" * 64,
        method_id="refund",
        argument_digest="1" * 64,
    )
    v2_identity = receipt_identity(decision)
    assert v2_identity.startswith("acgs:receipt:v2:sha256:")
    envelope_identity = signed_envelope_identity(sign_receipt(decision, key))
    assert envelope_identity.startswith("acgs:signed-envelope:v1:sha256:")
    done = replace(reserve(contracted), state=EffectState.DONE)
    for identity in (v2_identity, envelope_identity):
        built = outcome_from_record(done, contract=contract(), decision_receipt_identity=identity)
        assert built.decision_receipt_identity == identity
        assert sign_outcome(built, key).verify(key.public_key_hex()) is True


@pytest.mark.parametrize(
    "refused",
    [
        ProviderContract("payments", ProviderContractClass.UNBOUNDED, "1", False, False),
        ProviderContract("payments", ProviderContractClass.BOUNDED, "1", True, False, 30),
    ],
)
def test_outcome_from_record_requires_fenceable_contract(contracted, refused):
    done = replace(reserve(contracted), state=EffectState.DONE)
    with pytest.raises(ValueError, match="FENCEABLE"):
        outcome_from_record(done, contract=refused, decision_receipt_identity=DECISION)


def test_restart_with_other_contract_version_cannot_receipt(tmp_path):
    path = tmp_path / "effects.sqlite"
    store = EffectStore(path)
    store.create_budget("budget", 10)
    registry = ProviderContractRegistry()
    registry.register(contract())
    before = ContractedEffectStore(store, registry)
    provider = Provider()
    effect = reserve(before)
    assert before.send(effect.key, provider).state is EffectState.DONE

    swapped = ProviderContractRegistry()
    swapped.register(ProviderContract("payments", ProviderContractClass.FENCEABLE, "2", True, True))
    after = ContractedEffectStore(EffectStore(path), swapped)
    with pytest.raises(ProviderNotDispatchable, match="different contract"):
        after.contract_for(effect.key, provider)
    with pytest.raises(ProviderNotDispatchable, match="different contract"):
        after.reconcile(effect.key, provider)

    same = ProviderContractRegistry()
    same.register(contract())
    restarted = ContractedEffectStore(EffectStore(path), same)
    assert restarted.contract_for(effect.key, provider) == contract()


def test_signed_from_dict_rejects_malformed_payloads():
    key = signer()
    payload = sign_outcome(receipt(), key).to_dict()
    missing = {k: v for k, v in payload.items() if k != "key_id"}
    extra = {**payload, "signed_at": WHEN}
    bad_type = {**payload, "signature": 5}
    bad_receipt = {**payload, "receipt": {**payload["receipt"], "outcome": "unknown"}}
    nested_extra = {**payload, "receipt": {**payload["receipt"], "x": 1}}
    for value in (missing, extra, bad_type, bad_receipt, nested_extra, None):
        with pytest.raises(ValueError):
            SignedOutcomeReceipt.from_dict(value)


def test_signed_constructor_and_sign_type_checks():
    with pytest.raises(TypeError):
        SignedOutcomeReceipt({"x": 1}, "ed25519", "k", "00", "00")
    with pytest.raises(TypeError):
        SignedOutcomeReceipt(receipt(), "ed25519", None, "00", "00")
    with pytest.raises(TypeError):
        sign_outcome(receipt().to_dict(), object())
