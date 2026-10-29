"""Provider contract validation, digest pinning and fail-closed dispatch gating."""

import hashlib
import json
from dataclasses import replace
from threading import Lock

import pytest

from acgs_lite.legitimacy import (
    ContractedEffectStore,
    EffectOutcome,
    EffectState,
    EffectStore,
    ProviderContract,
    ProviderContractClass,
    ProviderContractRegistry,
    ProviderNotDispatchable,
    ProviderResult,
)


class SpyProvider:
    def __init__(self, provider_id="payments"):
        self.provider_id = provider_id
        self.sends = []
        self.queries = []
        self.lock = Lock()

    def send(self, request):
        with self.lock:
            self.sends.append(request)
            return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE, fenced=True)

    def query_and_fence(self, request):
        with self.lock:
            self.queries.append(request)
            return ProviderResult(
                request.key, self.provider_id, EffectOutcome.NOT_DONE, fenced=True
            )


def fenceable(provider_id="payments", **changes):
    args = dict(
        provider_id=provider_id,
        contract_class=ProviderContractClass.FENCEABLE,
        version="2026-10-29",
        dedup_by_key=True,
        atomic_query_fence=True,
    )
    args.update(changes)
    return ProviderContract(**args)


@pytest.fixture
def store(tmp_path):
    value = EffectStore(tmp_path / "effects.sqlite")
    value.create_budget("budget", 10)
    return value


def reserve(store, provider_id="payments", grant="grant"):
    return store.reserve(
        provider_id=provider_id,
        grant_identity=grant,
        action={"amount": 4},
        budget_id="budget",
        amount=4,
    )


def test_valid_contract_classes():
    assert fenceable().contract_class is ProviderContractClass.FENCEABLE
    bounded = ProviderContract("mail", ProviderContractClass.BOUNDED, "1", False, False, 30)
    assert bounded.delivery_bound_seconds == 30
    unbounded = ProviderContract("sms", ProviderContractClass.UNBOUNDED, "1", False, False)
    assert unbounded.delivery_bound_seconds is None


@pytest.mark.parametrize(
    "changes",
    [
        dict(dedup_by_key=False),
        dict(atomic_query_fence=False),
        dict(contract_class=ProviderContractClass.BOUNDED),
        dict(contract_class=ProviderContractClass.BOUNDED, delivery_bound_seconds=0),
        dict(delivery_bound_seconds=-1),
        dict(delivery_bound_seconds=True),
        dict(delivery_bound_seconds=1.5),
        dict(dedup_by_key=1),
        dict(atomic_query_fence="yes"),
        dict(contract_class="fenceable"),
        dict(provider_id=""),
        dict(provider_id="  "),
        dict(version=""),
        dict(version=None),
    ],
)
def test_invalid_contracts_raise(changes):
    with pytest.raises(ValueError):
        fenceable(**changes)


def test_digest_is_stable_and_domain_separated():
    contract = fenceable()
    assert contract.digest == fenceable().digest
    assert len(contract.digest) == 64
    assert contract.identity == f"acgs:provider-contract:v1:sha256:{contract.digest}"
    canonical = json.dumps(
        contract.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert (
        contract.digest
        == hashlib.sha256(b"acgs-provider-contract-v1\x00" + canonical.encode("utf-8")).hexdigest()
    )
    assert contract.digest != hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@pytest.mark.parametrize(
    "changes",
    [
        dict(provider_id="payments-2"),
        dict(version="2026-10-30"),
        dict(delivery_bound_seconds=5),
        dict(contract_class=ProviderContractClass.UNBOUNDED),
        dict(contract_class=ProviderContractClass.UNBOUNDED, dedup_by_key=False),
        dict(contract_class=ProviderContractClass.UNBOUNDED, atomic_query_fence=False),
    ],
)
def test_digest_changes_with_every_field(changes):
    assert replace(fenceable(), **changes).digest != fenceable().digest


def test_non_ascii_digest_is_utf8():
    assert (
        fenceable(provider_id="zahlungen-ü").digest != fenceable(provider_id="zahlungen-u").digest
    )


def test_registry_register_get_and_conflict():
    registry = ProviderContractRegistry()
    assert registry.get("payments") is None
    contract = registry.register(fenceable())
    assert registry.register(fenceable()) is contract
    assert registry.get("payments") == contract
    with pytest.raises(ValueError, match="already registered"):
        registry.register(fenceable(version="other"))
    with pytest.raises(TypeError):
        registry.register({"provider_id": "payments"})
    assert registry.require_dispatchable("payments") == contract


@pytest.mark.parametrize(
    "contract",
    [
        None,
        ProviderContract("payments", ProviderContractClass.BOUNDED, "1", True, False, 30),
        ProviderContract("payments", ProviderContractClass.UNBOUNDED, "1", False, False),
    ],
)
def test_refused_classes_never_call_provider(store, contract):
    registry = ProviderContractRegistry()
    if contract is not None:
        registry.register(contract)
    with pytest.raises(ProviderNotDispatchable):
        registry.require_dispatchable("payments")
    contracted = ContractedEffectStore(store, registry)
    effect = reserve(store)
    provider = SpyProvider()
    with pytest.raises(ProviderNotDispatchable):
        contracted.send(effect.key, provider)
    store._claim(effect.key, "payments")
    with pytest.raises(ProviderNotDispatchable):
        contracted.reconcile(effect.key, provider)
    assert provider.sends == [] and provider.queries == []
    assert store.get(effect.key).state is EffectState.IN_FLIGHT
    assert store.budget("budget").reserved == 4


def test_record_provider_mismatch_refused(store):
    registry = ProviderContractRegistry()
    registry.register(fenceable("payments"))
    registry.register(fenceable("refunds"))
    contracted = ContractedEffectStore(store, registry)
    effect = reserve(store, provider_id="refunds")
    provider = SpyProvider("payments")
    with pytest.raises(ProviderNotDispatchable, match="different provider"):
        contracted.send(effect.key, provider)
    assert provider.sends == []
    assert store.get(effect.key).state is EffectState.RESERVED


def test_unregistered_record_provider_refused_even_if_caller_registered(store):
    registry = ProviderContractRegistry()
    registry.register(fenceable("payments"))
    contracted = ContractedEffectStore(store, registry)
    effect = reserve(store, provider_id="sms")
    provider = SpyProvider("sms")
    with pytest.raises(ProviderNotDispatchable):
        contracted.send(effect.key, provider)
    assert provider.sends == []


def test_fenceable_dispatch_and_reconcile(store):
    registry = ProviderContractRegistry()
    contract = registry.register(fenceable())
    contracted = ContractedEffectStore(store, registry)
    provider = SpyProvider()
    effect = reserve(store)
    assert contracted.contract_for(effect.key, provider) == contract
    assert contracted.send(effect.key, provider).state is EffectState.DONE
    assert len(provider.sends) == 1
    second = reserve(store, grant="grant2")
    store._claim(second.key, "payments")
    assert contracted.reconcile(second.key, provider).state is EffectState.NOT_DONE
    assert len(provider.queries) == 1


def test_constructor_type_checks(store):
    with pytest.raises(TypeError):
        ContractedEffectStore(object(), ProviderContractRegistry())
    with pytest.raises(TypeError):
        ContractedEffectStore(store, object())
