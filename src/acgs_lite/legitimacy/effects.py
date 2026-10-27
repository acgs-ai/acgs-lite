"""Opt-in durable external-effect evidence; not an authorization boundary.

The trusted host must validate/consume execution authority before using this API.
Provider adapters must enforce durable key deduplication and atomic query/fencing.
These contracts are assumptions, not guarantees supplied by a local SQLite file.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol


class EffectState(str, Enum):
    RESERVED = "reserved"
    IN_FLIGHT = "in_flight"
    UNKNOWN = "unknown"
    DONE = "done"
    NOT_DONE = "not_done"


class EffectOutcome(str, Enum):
    UNKNOWN = "unknown"
    DONE = "done"
    NOT_DONE = "not_done"


@dataclass(frozen=True)
class EffectRequest:
    key: str
    provider_id: str
    grant_identity: str
    action_json: str


@dataclass(frozen=True)
class ProviderResult:
    key: str
    provider_id: str
    outcome: EffectOutcome
    fenced: bool = False


class EffectProvider(Protocol):
    """Trusted adapter, with atomic send-vs-query/fence serialization per key.

    DONE means permanently completed; NOT_DONE means permanently fenced against
    all delayed/future sends. Absence or a pending request must return UNKNOWN
    unless the provider atomically fences it. Terminal answers never conflict.
    """

    @property
    def provider_id(self) -> str: ...

    def send(self, request: EffectRequest) -> ProviderResult: ...

    def query_and_fence(self, request: EffectRequest) -> ProviderResult: ...


@dataclass(frozen=True)
class EffectRecord:
    request: EffectRequest
    budget_id: str
    amount: int
    state: EffectState

    @property
    def key(self) -> str:
        return self.request.key


@dataclass(frozen=True)
class EffectBudget:
    capacity: int
    reserved: int
    settled: int


def _text(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("identifier must be a nonempty string")


def _units(value: int) -> None:
    if type(value) is not int or not 0 < value <= 2**63 - 1:
        raise ValueError("units must be a positive signed 64-bit integer")


def _json_value(value: object) -> None:
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _json_value(item)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _json_value(item)
        return
    raise ValueError("action must contain only finite JSON values with string keys")


class EffectStore:
    """Durable reservations and one-dispatch coordination for a trusted host.

    Each operation owns a separate connection and closes it before provider I/O.
    Opening a store never resets IN_FLIGHT: another process may still be sending.
    SQLite and its filesystem must provide durable, exclusive transaction locks.
    """

    def __init__(self, path: str | Path) -> None:
        if not str(path).strip() or str(path) == ":memory:":
            raise ValueError("a persistent SQLite file path is required")
        self.path = Path(path).absolute()
        with self._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS effect_budgets (
                id TEXT PRIMARY KEY, capacity INTEGER NOT NULL CHECK(capacity > 0),
                reserved INTEGER NOT NULL DEFAULT 0 CHECK(reserved >= 0),
                settled INTEGER NOT NULL DEFAULT 0 CHECK(settled >= 0),
                CHECK(reserved <= capacity - settled))""")
            db.execute("""CREATE TABLE IF NOT EXISTS external_effects (
                key TEXT PRIMARY KEY, provider_id TEXT NOT NULL,
                grant_identity TEXT NOT NULL UNIQUE, action_json TEXT NOT NULL,
                budget_id TEXT NOT NULL REFERENCES effect_budgets(id),
                amount INTEGER NOT NULL CHECK(amount > 0),
                state TEXT NOT NULL CHECK(state IN
                    ('reserved','in_flight','unknown','done','not_done')))""")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _get(db: sqlite3.Connection, key: str) -> EffectRecord:
        row = db.execute("SELECT * FROM external_effects WHERE key=?", (key,)).fetchone()
        if row is None:
            raise ValueError("unknown effect key")
        return EffectRecord(
            EffectRequest(row["key"], row["provider_id"], row["grant_identity"], row["action_json"]),
            row["budget_id"], row["amount"], EffectState(row["state"]),
        )

    def get(self, key: str) -> EffectRecord:
        with self._transaction() as db:
            return self._get(db, key)

    def create_budget(self, budget_id: str, capacity: int) -> None:
        _text(budget_id)
        _units(capacity)
        with self._transaction() as db:
            row = db.execute("SELECT capacity FROM effect_budgets WHERE id=?", (budget_id,)).fetchone()
            if row is not None and row[0] != capacity:
                raise ValueError("budget capacity is immutable")
            db.execute("INSERT OR IGNORE INTO effect_budgets(id,capacity) VALUES (?,?)",
                       (budget_id, capacity))

    def budget(self, budget_id: str) -> EffectBudget:
        with self._transaction() as db:
            row = db.execute("SELECT * FROM effect_budgets WHERE id=?", (budget_id,)).fetchone()
            if row is None:
                raise ValueError("unknown budget")
            return EffectBudget(row["capacity"], row["reserved"], row["settled"])

    def reserve(self, *, provider_id: str, grant_identity: str, action: object,
                budget_id: str, amount: int) -> EffectRecord:
        """Bind an opaque evidence reference once; this does not validate a grant."""
        for value in (provider_id, grant_identity, budget_id):
            _text(value)
        _units(amount)
        _json_value(action)
        canonical = json.dumps(action, sort_keys=True, separators=(",", ":"), allow_nan=False)
        digest = hashlib.sha256(b"acgs-effect-action-v1\x00" + canonical.encode()).hexdigest()
        binding = json.dumps([provider_id, grant_identity, digest], separators=(",", ":"))
        key = "acgs:effect:v1:" + hashlib.sha256(
            b"acgs-provider-effect-v1\x00" + binding.encode()
        ).hexdigest()
        with self._transaction() as db:
            row = db.execute("SELECT key FROM external_effects WHERE grant_identity=?",
                             (grant_identity,)).fetchone()
            if row is not None:
                record = self._get(db, row[0])
                if (record.request != EffectRequest(key, provider_id, grant_identity, canonical)
                        or record.budget_id != budget_id or record.amount != amount):
                    raise ValueError("grant effect binding is immutable")
                return record
            updated = db.execute("""UPDATE effect_budgets SET reserved=reserved+?
                WHERE id=? AND ? <= capacity - settled - reserved""", (amount, budget_id, amount))
            if updated.rowcount != 1:
                raise ValueError("unknown budget or insufficient capacity")
            db.execute("INSERT INTO external_effects VALUES (?,?,?,?,?,?,?)",
                       (key, provider_id, grant_identity, canonical, budget_id, amount, "reserved"))
            return self._get(db, key)

    def _claim(self, key: str, provider_id: str) -> tuple[EffectRecord, bool]:
        with self._transaction() as db:
            record = self._get(db, key)
            if record.request.provider_id != provider_id:
                raise ValueError("provider binding mismatch")
            if record.state is not EffectState.RESERVED:
                return record, False
            db.execute("UPDATE external_effects SET state='in_flight' WHERE key=?", (key,))
            return self._get(db, key), True

    def _unknown(self, key: str) -> None:
        # If persistence itself fails, the committed IN_FLIGHT still holds exposure.
        try:
            with self._transaction() as db:
                db.execute(
                    "UPDATE external_effects SET state='unknown' WHERE key=? AND state='in_flight'",
                    (key,),
                )
        except Exception:
            logging.getLogger(__name__).exception(
                "Could not persist UNKNOWN for effect %s; retain exposure and reconcile", key
            )

    def _finish(self, request: EffectRequest, result: ProviderResult) -> EffectRecord:
        if (not isinstance(result, ProviderResult) or result.key != request.key
                or result.provider_id != request.provider_id
                or not isinstance(result.outcome, EffectOutcome) or type(result.fenced) is not bool
                or (result.outcome is EffectOutcome.NOT_DONE and not result.fenced)):
            raise ValueError("invalid or unfenced provider outcome")
        target = EffectState(result.outcome.value)
        with self._transaction() as db:
            record = self._get(db, request.key)
            if record.state in (EffectState.DONE, EffectState.NOT_DONE):
                if target is not EffectState.UNKNOWN and target is not record.state:
                    raise ValueError("conflicting terminal provider outcome")
                return record
            if record.state not in (EffectState.IN_FLIGHT, EffectState.UNKNOWN):
                raise ValueError("effect has not been dispatched")
            if target is not EffectState.UNKNOWN:
                settled = record.amount if target is EffectState.DONE else 0
                db.execute("""UPDATE effect_budgets SET reserved=reserved-?, settled=settled+?
                    WHERE id=?""", (record.amount, settled, record.budget_id))
            db.execute("UPDATE external_effects SET state=? WHERE key=?", (target.value, request.key))
            return self._get(db, request.key)

    def send(self, key: str, provider: EffectProvider) -> EffectRecord:
        """Commit IN_FLIGHT, then invoke once with the persisted immutable request."""
        record, proceed = self._claim(key, provider.provider_id)
        if not proceed:
            return record
        try:
            return self._finish(record.request, provider.send(record.request))
        except BaseException:
            self._unknown(key)
            raise

    def reconcile(self, key: str, provider: EffectProvider) -> EffectRecord:
        """Resolve uncertainty only through the trusted provider's atomic fence."""
        record = self.get(key)
        if record.request.provider_id != provider.provider_id:
            raise ValueError("provider binding mismatch")
        if record.state in (EffectState.DONE, EffectState.NOT_DONE):
            return record
        if record.state is EffectState.RESERVED:
            raise ValueError("effect has not been dispatched")
        try:
            return self._finish(record.request, provider.query_and_fence(record.request))
        except BaseException:
            self._unknown(key)
            raise
