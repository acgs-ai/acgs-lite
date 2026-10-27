"""Durable effect accounting and provider-boundary regressions."""

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event, Lock

import pytest

from acgs_lite.legitimacy.effects import (
    EffectOutcome,
    EffectState,
    EffectStore,
    ProviderResult,
)


class Provider:
    provider_id = "payments"

    def __init__(self):
        self.calls = []
        self.done = set()
        self.fenced = set()
        self.lock = Lock()
        self.error = None
        self.unknown = False

    def send(self, request):
        with self.lock:
            self.calls.append(request)
            if request.key not in self.fenced:
                self.done.add(request.key)
            if self.error:
                raise self.error
            outcome = EffectOutcome.DONE if request.key in self.done else EffectOutcome.NOT_DONE
            return ProviderResult(request.key, self.provider_id, outcome, fenced=True)

    def query_and_fence(self, request):
        with self.lock:
            if self.unknown:
                return ProviderResult(request.key, self.provider_id, EffectOutcome.UNKNOWN)
            if request.key in self.done:
                return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE)
            self.fenced.add(request.key)
            return ProviderResult(request.key, self.provider_id, EffectOutcome.NOT_DONE, fenced=True)


@pytest.fixture
def store(tmp_path):
    value = EffectStore(tmp_path / "effects.sqlite")
    value.create_budget("budget", 10)
    return value


def reserve(store, grant="grant", **changes):
    args = dict(provider_id="payments", grant_identity=grant, action={"amount": 4},
                budget_id="budget", amount=4)
    args.update(changes)
    return store.reserve(**args)


def test_persisted_action_stable_key_and_rebinding(store):
    payload = {"b": 2, "a": [1]}
    first = reserve(store, action=payload)
    payload["a"].append(2)
    assert reserve(store, action={"a": [1], "b": 2}) == first
    for change in ({"action": payload}, {"amount": 5}, {"budget_id": "other"},
                   {"provider_id": "other"}):
        with pytest.raises(ValueError, match="binding"):
            reserve(store, **change)
    provider = Provider()
    assert store.send(first.key, provider).state is EffectState.DONE
    assert json.loads(provider.calls[0].action_json) == {"a": [1], "b": 2}
    assert store.send(first.key, provider).state is EffectState.DONE
    assert len(provider.calls) == 1
    assert store.budget("budget").settled == 4
    assert store.budget("budget").reserved == 0


@pytest.mark.parametrize("error", [TimeoutError(), asyncio.CancelledError(), KeyboardInterrupt()])
def test_timeout_reopen_done_and_no_resend(store, error):
    effect = reserve(store)
    provider = Provider()
    provider.error = error
    with pytest.raises(type(error)):
        store.send(effect.key, provider)
    reopened = EffectStore(store.path)
    assert reopened.get(effect.key).state is EffectState.UNKNOWN
    assert reopened.send(effect.key, provider).state is EffectState.UNKNOWN
    assert len(provider.calls) == 1
    assert reopened.budget("budget").reserved == 4
    assert reopened.reconcile(effect.key, provider).state is EffectState.DONE
    assert reopened.reconcile(effect.key, provider).state is EffectState.DONE
    assert reopened.budget("budget").settled == 4


def test_crash_before_dispatch_reconcile_fences_delayed_send(store):
    effect = reserve(store)
    started, proceed = store._claim(effect.key, "payments")
    assert proceed
    reopened = EffectStore(store.path)
    assert reopened.get(effect.key).state is EffectState.IN_FLIGHT
    provider = Provider()
    assert reopened.reconcile(effect.key, provider).state is EffectState.NOT_DONE
    assert provider.send(started.request).outcome is EffectOutcome.NOT_DONE
    assert not provider.done
    assert reopened.budget("budget").reserved == 0
    assert reopened.budget("budget").settled == 0


def test_crash_after_provider_completed(store):
    effect = reserve(store)
    started, _ = store._claim(effect.key, "payments")
    provider = Provider()
    provider.send(started.request)
    reopened = EffectStore(store.path)
    assert reopened.reconcile(effect.key, provider).state is EffectState.DONE
    assert reopened.budget("budget").settled == 4


def test_unknown_is_per_key_and_retains_exposure(store):
    first, second = reserve(store), reserve(store, "grant2")
    provider = Provider()
    store._claim(first.key, "payments")
    provider.unknown = True
    assert store.reconcile(first.key, provider).state is EffectState.UNKNOWN
    assert store.send(second.key, provider).state is EffectState.DONE
    budget = store.budget("budget")
    assert (budget.capacity, budget.reserved, budget.settled) == (10, 4, 4)
    with pytest.raises(ValueError, match="capacity"):
        reserve(store, "grant3")


@pytest.mark.parametrize("change", [dict(key="wrong"), dict(provider_id="wrong"),
    dict(outcome="done"), dict(outcome=EffectOutcome.NOT_DONE, fenced=False),
    dict(fenced=1)])
def test_invalid_provider_outcomes_retain_reservation(store, change):
    effect = reserve(store)
    provider = Provider()
    provider.send = lambda request: replace(
        ProviderResult(request.key, "payments", EffectOutcome.DONE), **change)
    with pytest.raises(ValueError):
        store.send(effect.key, provider)
    assert store.get(effect.key).state is EffectState.UNKNOWN
    assert store.budget("budget").reserved == 4


@pytest.mark.parametrize("amount", [True, False, 0, -1, 1.5, "4", 2**63])
def test_invalid_units(store, amount):
    with pytest.raises(ValueError):
        reserve(store, amount=amount)
    with pytest.raises(ValueError):
        store.create_budget("other", amount)


@pytest.mark.parametrize("payload", [{1: "x"}, {"x": float("nan")}, {"x": object()},
                                       {"x": (1, 2)}])
def test_invalid_action(store, payload):
    with pytest.raises(ValueError):
        reserve(store, action=payload)


def test_concurrent_clients_single_dispatch_and_budget_conservation(store):
    provider = Provider()
    def work(number):
        client = EffectStore(store.path)
        effect = reserve(client)
        return client.send(effect.key, provider)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(work, range(16)))
    assert len(provider.calls) == 1
    assert store.budget("budget").settled == 4
    def reserve_other(number):
        try:
            return reserve(EffectStore(store.path), f"g{number}")
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(x is not None for x in pool.map(reserve_other, range(16))) == 1
    assert store.budget("budget").reserved == 4


def test_live_send_can_be_fenced_during_reconciliation(store):
    effect = reserve(store)
    provider = Provider()
    entered, release = Event(), Event()
    original = provider.send
    def delayed(request):
        entered.set()
        assert release.wait(5)
        return original(request)
    provider.send = delayed
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(store.send, effect.key, provider)
        assert entered.wait(5)
        other = EffectStore(store.path)
        assert other.get(effect.key).state is EffectState.IN_FLIGHT
        try:
            assert other.reconcile(effect.key, provider).state is EffectState.NOT_DONE
        finally:
            release.set()
        assert future.result().state is EffectState.NOT_DONE
    assert not provider.done
    assert store.budget("budget").reserved == 0


def test_failed_database_claim_prevents_callback(store, monkeypatch):
    effect = reserve(store)
    provider = Provider()
    def fail(*args):
        raise OSError("disk failure")
    monkeypatch.setattr(store, "_claim", fail)
    with pytest.raises(OSError):
        store.send(effect.key, provider)
    assert provider.calls == []


def test_wrong_provider_and_reserved_reconciliation_fail_closed(store):
    effect = reserve(store)
    provider = Provider()
    with pytest.raises(ValueError):
        store.reconcile(effect.key, provider)
    provider.provider_id = "other"
    with pytest.raises(ValueError):
        store.send(effect.key, provider)
    assert provider.calls == []
    assert store.get(effect.key).state is EffectState.RESERVED


@pytest.mark.parametrize("result", [None, {}, ProviderResult("wrong", "payments", EffectOutcome.DONE),
    ProviderResult("placeholder", "wrong", EffectOutcome.DONE),
    ProviderResult("placeholder", "payments", EffectOutcome.NOT_DONE)])
def test_bad_reconciliation_never_releases_money(store, result):
    effect = reserve(store)
    store._claim(effect.key, "payments")
    provider = Provider()
    if isinstance(result, ProviderResult) and result.key == "placeholder":
        result = replace(result, key=effect.key)
    provider.query_and_fence = lambda request: result
    with pytest.raises(ValueError):
        store.reconcile(effect.key, provider)
    assert store.get(effect.key).state is EffectState.UNKNOWN
    assert store.budget("budget").reserved == 4


def test_concurrent_reconciliation_settles_once(store):
    effect = reserve(store)
    request, _ = store._claim(effect.key, "payments")
    provider = Provider()
    provider.send(request.request)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: EffectStore(store.path).reconcile(effect.key, provider), range(24)))
    assert all(result.state is EffectState.DONE for result in results)
    assert store.budget("budget").settled == 4
    assert store.budget("budget").reserved == 0


def test_conflicting_terminal_evidence_rejected(store):
    effect = reserve(store)
    provider = Provider()
    store.send(effect.key, provider)
    with pytest.raises(ValueError, match="conflicting"):
        store._finish(effect.request, ProviderResult(effect.key, "payments", EffectOutcome.NOT_DONE, True))
    assert store.get(effect.key).state is EffectState.DONE
    assert store.budget("budget").settled == 4


def test_reservation_and_settlement_rollback_atomically(store):
    with sqlite3.connect(store.path) as db:
        db.execute("CREATE TRIGGER fail_insert BEFORE INSERT ON external_effects BEGIN SELECT RAISE(ABORT, 'fail'); END")
    with pytest.raises(sqlite3.IntegrityError):
        reserve(store)
    assert store.budget("budget").reserved == 0
    with sqlite3.connect(store.path) as db:
        db.execute("DROP TRIGGER fail_insert")
    effect = reserve(store)
    with sqlite3.connect(store.path) as db:
        db.execute("CREATE TRIGGER fail_finish BEFORE UPDATE ON external_effects WHEN NEW.state='done' BEGIN SELECT RAISE(ABORT, 'fail'); END")
    provider = Provider()
    with pytest.raises(sqlite3.IntegrityError):
        store.send(effect.key, provider)
    assert store.budget("budget").reserved == 4
    assert store.budget("budget").settled == 0
    with sqlite3.connect(store.path) as db:
        db.execute("DROP TRIGGER fail_finish")
    assert store.reconcile(effect.key, provider).state is EffectState.DONE


def test_capacity_immutable_and_maximum_conserved(store):
    with pytest.raises(ValueError):
        store.create_budget("budget", 11)
    store.create_budget("max", 2**63 - 1)
    effect = reserve(store, budget_id="max", amount=2**63 - 1)
    with pytest.raises(ValueError):
        reserve(store, "another", budget_id="max", amount=1)
    store.send(effect.key, Provider())
    assert store.budget("max").settled == 2**63 - 1
    assert store.budget("max").reserved == 0


def test_uncertainty_persistence_failure_preserves_original_error(store, monkeypatch, caplog):
    effect = reserve(store)
    provider = Provider()
    original = TimeoutError("provider timeout")
    def fail_transaction():
        raise sqlite3.OperationalError("disk unavailable")
    def fail_send(request):
        monkeypatch.setattr(store, "_transaction", fail_transaction)
        raise original
    provider.send = fail_send
    with pytest.raises(TimeoutError) as raised:
        store.send(effect.key, provider)
    assert raised.value is original
    assert "Could not persist UNKNOWN" in caplog.text
    reopened = EffectStore(store.path)
    assert reopened.get(effect.key).state is EffectState.IN_FLIGHT
    assert reopened.budget("budget").reserved == 4


@pytest.mark.parametrize("path", ["", " ", ":memory:"])
def test_requires_persistent_database(path):
    with pytest.raises(ValueError):
        EffectStore(path)


@pytest.mark.parametrize("completed", [False, True])
def test_abrupt_process_exit_recovery_with_durable_provider(store, tmp_path, completed):
    """The child dies inside send; provider completion survives in a separate DB."""
    effect = reserve(store)
    provider_path = tmp_path / "provider.sqlite"
    with sqlite3.connect(provider_path) as db:
        db.execute("CREATE TABLE effects (key TEXT PRIMARY KEY)")
    program = '''
import os, sqlite3, sys
from acgs_lite.legitimacy.effects import EffectStore
class Provider:
    provider_id = "payments"
    def send(self, request):
        if sys.argv[4] == "True":
            with sqlite3.connect(sys.argv[2]) as db:
                db.execute("INSERT INTO effects VALUES (?)", (request.key,))
        os._exit(17)
EffectStore(sys.argv[1]).send(sys.argv[3], Provider())
'''
    result = subprocess.run([sys.executable, "-c", program, str(store.path), str(provider_path),
                             effect.key, str(completed)], env=os.environ.copy(), timeout=10)
    assert result.returncode == 17
    reopened = EffectStore(store.path)
    assert reopened.get(effect.key).state is EffectState.IN_FLIGHT
    class DurableQuery(Provider):
        def query_and_fence(self, request):
            with sqlite3.connect(provider_path) as db:
                db.execute("BEGIN IMMEDIATE")
                found = db.execute("SELECT key FROM effects WHERE key=?", (request.key,)).fetchone()
                db.execute("CREATE TABLE IF NOT EXISTS fences (key TEXT PRIMARY KEY)")
                if not found:
                    db.execute("INSERT OR IGNORE INTO fences VALUES (?)", (request.key,))
            return ProviderResult(request.key, "payments",
                EffectOutcome.DONE if found else EffectOutcome.NOT_DONE, fenced=not found)
    state = reopened.reconcile(effect.key, DurableQuery()).state
    assert state is (EffectState.DONE if completed else EffectState.NOT_DONE)
    assert reopened.budget("budget").settled == (4 if completed else 0)
    assert reopened.budget("budget").reserved == 0
