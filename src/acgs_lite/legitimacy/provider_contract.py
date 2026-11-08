"""Pinned provider contracts that gate external-effect dispatch; fail closed.

A contract records which delivery assumptions a provider adapter claims to meet
(``reports/tla/README.md``): FENCEABLE means A1 durable dedup by a stable effect
key plus A2 atomic query-and-fence; BOUNDED means a delivery bound ``D`` (A4-A6);
UNBOUNDED means neither. The contract digest pins those claims as evidence. A
contract is a declaration by the trusted host, not a check of the provider.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum

from acgs_lite.legitimacy.authorization import ExecutionGrant
from acgs_lite.legitimacy.effects import (
    EffectProvider,
    EffectRecord,
    EffectState,
    EffectStore,
)
from acgs_lite.legitimacy.identity import local_grant_identity, receipt_identity
from acgs_lite.legitimacy.receipt import RECEIPT_SCHEMA_V2

_CONTRACT_DOMAIN = b"acgs-provider-contract-v1\x00"
PROVIDER_CONTRACT_SCHEMA = "acgs-provider-contract-v1"


class ProviderContractClass(str, Enum):
    FENCEABLE = "fenceable"
    BOUNDED = "bounded"
    UNBOUNDED = "unbounded"


class ProviderNotDispatchable(ValueError):
    """Raised when a provider has no contract or its class may not be dispatched."""


def _nonempty(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


@dataclass(frozen=True)
class ProviderContract:
    """Immutable, digest-pinned provider capability claims.

    FENCEABLE requires ``dedup_by_key`` and ``atomic_query_fence``. BOUNDED
    requires a positive integer ``delivery_bound_seconds``. Any other combination
    is accepted only as declared evidence and never widens dispatch.
    """

    provider_id: str
    contract_class: ProviderContractClass
    version: str
    dedup_by_key: bool
    atomic_query_fence: bool
    delivery_bound_seconds: int | None = None

    def __post_init__(self) -> None:
        _nonempty(self.provider_id, "provider_id")
        if unicodedata.normalize("NFC", self.provider_id) != self.provider_id:
            raise ValueError("provider_id must be NFC-normalized Unicode")
        _nonempty(self.version, "version")
        if not isinstance(self.contract_class, ProviderContractClass):
            raise ValueError("contract_class must be a ProviderContractClass")
        for name in ("dedup_by_key", "atomic_query_fence"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a bool")
        bound = self.delivery_bound_seconds
        if bound is not None and (type(bound) is not int or bound <= 0):
            raise ValueError("delivery_bound_seconds must be a positive integer or None")
        if self.contract_class is ProviderContractClass.FENCEABLE and not (
            self.dedup_by_key and self.atomic_query_fence
        ):
            raise ValueError("FENCEABLE requires dedup_by_key and atomic_query_fence")
        if self.contract_class is ProviderContractClass.BOUNDED and bound is None:
            raise ValueError("BOUNDED requires a positive delivery_bound_seconds")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": PROVIDER_CONTRACT_SCHEMA,
            "provider_id": self.provider_id,
            "contract_class": self.contract_class.value,
            "version": self.version,
            "dedup_by_key": self.dedup_by_key,
            "atomic_query_fence": self.atomic_query_fence,
            "delivery_bound_seconds": self.delivery_bound_seconds,
        }

    @property
    def digest(self) -> str:
        """sha256 over the domain prefix and canonical JSON.

        Canonical JSON sorts keys, uses compact separators and keeps non-ASCII
        characters unescaped (``ensure_ascii=False``), encoded as UTF-8.
        """
        canonical = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return hashlib.sha256(_CONTRACT_DOMAIN + canonical.encode("utf-8")).hexdigest()

    @property
    def identity(self) -> str:
        return f"acgs:provider-contract:v1:sha256:{self.digest}"


class ProviderContractRegistry:
    """Process-local, append-only mapping from provider_id to one contract.

    Re-registering an identical contract is a no-op; a different contract for
    the same provider raises, so a pinned digest cannot be swapped in place.
    """

    def __init__(self) -> None:
        self._contracts: dict[str, ProviderContract] = {}
        self._lock = threading.Lock()

    def register(self, contract: ProviderContract) -> ProviderContract:
        if not isinstance(contract, ProviderContract):
            raise TypeError("contract must be a ProviderContract")
        with self._lock:
            existing = self._contracts.get(contract.provider_id)
            if existing is not None:
                if existing != contract:
                    raise ValueError("provider contract is already registered")
                return existing
            self._contracts[contract.provider_id] = contract
            return contract

    def get(self, provider_id: str) -> ProviderContract | None:
        with self._lock:
            return self._contracts.get(provider_id)

    def require_dispatchable(self, provider_id: str) -> ProviderContract:
        """Return the contract only for a FENCEABLE provider; otherwise refuse.

        BOUNDED and UNBOUNDED are refused in this slice because the owner has not
        decided their UNKNOWN-resolution default (PRODUCT-SLICE-2026-10-26 §7
        item 3, HOLD vs CHARGE) and no timer-based resolution is implemented.
        Unregistered providers are refused (fail closed).
        """
        contract = self.get(provider_id)
        if contract is None:
            raise ProviderNotDispatchable("provider has no registered contract")
        if contract.contract_class is not ProviderContractClass.FENCEABLE:
            raise ProviderNotDispatchable(
                f"provider contract class {contract.contract_class.value!r} is not dispatchable"
            )
        return contract


class ContractedEffectStore:
    """Compose an EffectStore with a contract registry; EffectStore is unchanged.

    ``send`` and ``reconcile`` call the provider only when the provider and the
    effect record both bind a registered FENCEABLE contract. Reconcile is gated
    too, because query-and-fence is assumption A2. The registry is process-local,
    so after a restart contracts must be registered again before reconciling.

    The first gated ``send`` of a RESERVED effect durably binds its key to the
    contract digest, in a side table of the same SQLite file, before any provider
    I/O. Only a RESERVED record can be bound: ``send``, ``reconcile`` and
    :meth:`contract_for` refuse any other record without a binding (for example
    one dispatched through the raw ``store``, or already terminal), and refuse a
    binding to a different digest, so an effect cannot be reconciled or receipted
    under a contract it was not dispatched under. After a restart, register the
    same contract again.
    """

    def __init__(self, store: EffectStore, registry: ProviderContractRegistry) -> None:
        if not isinstance(store, EffectStore):
            raise TypeError("store must be an EffectStore")
        if not isinstance(registry, ProviderContractRegistry):
            raise TypeError("registry must be a ProviderContractRegistry")
        self.store = store
        self.registry = registry
        with self._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS effect_contract_bindings (
                key TEXT PRIMARY KEY, contract_digest TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS effect_decision_bindings (
                key TEXT PRIMARY KEY, decision_identity TEXT NOT NULL)""")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.store.path, timeout=30, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _bound_digest(
        self, key: str, bind: ProviderContract | None, decision_identity: str | None = None
    ) -> str | None:
        with self._transaction() as db:
            if bind is not None:
                # Re-check RESERVED inside this write transaction: the caller's
                # store.get() may be stale if a raw store.send() dispatched since.
                db.execute(
                    "INSERT OR IGNORE INTO effect_contract_bindings (key, contract_digest) "
                    "SELECT key, ? FROM external_effects WHERE key=? AND state=?",
                    (bind.digest, key, EffectState.RESERVED.value),
                )
            row = db.execute(
                "SELECT contract_digest FROM effect_contract_bindings WHERE key=?", (key,)
            ).fetchone()
            if bind is not None and row is not None and row[0] != bind.digest:
                raise ProviderNotDispatchable("effect was dispatched under a different contract")
            if decision_identity is not None:
                if bind is not None:
                    db.execute(
                        "INSERT OR IGNORE INTO effect_decision_bindings (key, decision_identity) "
                        "SELECT key, ? FROM external_effects WHERE key=? AND state=?",
                        (decision_identity, key, EffectState.RESERVED.value),
                    )
                decision = db.execute(
                    "SELECT decision_identity FROM effect_decision_bindings WHERE key=?", (key,)
                ).fetchone()
                if decision is None or decision[0] != decision_identity:
                    raise ProviderNotDispatchable("effect has no matching durable decision binding")
            return None if row is None else row[0]

    def _checked(
        self,
        key: str,
        provider: EffectProvider,
        *,
        bind: bool,
        decision_identity: str | None = None,
    ) -> ProviderContract:
        contract = self.registry.require_dispatchable(provider.provider_id)
        record = self.store.get(key)
        if record.request.provider_id != contract.provider_id:
            raise ProviderNotDispatchable("effect record is bound to a different provider")
        bind = bind and record.state is EffectState.RESERVED
        bound = self._bound_digest(key, contract if bind else None, decision_identity)
        if bound is None:
            raise ProviderNotDispatchable("effect has no durable contract binding")
        if bound != contract.digest:
            raise ProviderNotDispatchable("effect was dispatched under a different contract")
        return contract

    def contract_for(self, key: str, provider: EffectProvider) -> ProviderContract:
        """Return the dispatchable contract that binds this effect and provider.

        Refuses when the effect has no durable binding (it was never sent through
        this wrapper) or is bound to a different contract digest.
        """
        return self._checked(key, provider, bind=False)

    def decision_for(self, key: str) -> str | None:
        """Decision identity bound before dispatch, never inferred after the effect."""
        with self._transaction() as db:
            row = db.execute(
                "SELECT decision_identity FROM effect_decision_bindings WHERE key=?", (key,)
            ).fetchone()
            return None if row is None else row[0]

    def send(
        self, key: str, provider: EffectProvider, *, grant: ExecutionGrant | None = None
    ) -> EffectRecord:
        """Dispatch; supply the original authenticated grant to enable outcome receipts.

        The trusted host authorizes the grant before calling. This records evidence
        of that association; it does not authenticate a process-local capability.
        """
        decision = None
        if grant is not None:
            if not isinstance(grant, ExecutionGrant):
                raise TypeError("grant must be an ExecutionGrant")
            if self.store.get(key).request.grant_identity != local_grant_identity(grant):
                raise ProviderNotDispatchable("effect record is bound to a different grant")
            if (
                grant.receipt.schema_version != RECEIPT_SCHEMA_V2
                or grant.receipt.grant_id != grant.grant_id
            ):
                raise ProviderNotDispatchable("decision receipt must bind the originating grant")
            decision = receipt_identity(grant.receipt)
        self._checked(key, provider, bind=True, decision_identity=decision)
        return self.store.send(key, provider)

    def reconcile(self, key: str, provider: EffectProvider) -> EffectRecord:
        # Never bind here: only the first gated send() may create a binding.
        self._checked(key, provider, bind=False)
        return self.store.reconcile(key, provider)


__all__ = [
    "PROVIDER_CONTRACT_SCHEMA",
    "ContractedEffectStore",
    "ProviderContract",
    "ProviderContractClass",
    "ProviderContractRegistry",
    "ProviderNotDispatchable",
]
