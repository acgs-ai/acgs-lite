# Durable external effects (opt-in)

`acgs_lite.legitimacy.EffectStore` is a trusted host persistence and coordination
API. It does **not** authorize execution, verify grants, consume capabilities, or
automatically integrate with decorators. The trusted host must perform existing
authorization and grant consumption before reserving/sending. An opaque
`grant_identity` (including `local_grant_identity(grant)`) is evidence, not a
capability. Existing `InProcessGrantLedger` and `AttemptStatus.PARTIAL` semantics
are unchanged; external `UNKNOWN` expresses a different fact.

```python
from acgs_lite.legitimacy import EffectStore, local_grant_identity

# After the host validates and consumes the real execution grant:
store = EffectStore("effects.sqlite")
store.create_budget("payments-2026", 10000)  # immutable positive integer units
effect = store.reserve(
    provider_id=provider.provider_id,
    grant_identity=local_grant_identity(grant),
    action={"method": "transfer", "recipient": "account-123", "units": 400},
    budget_id="payments-2026",
    amount=400,
)
result = store.send(effect.key, provider)
# On timeout/cancellation/crash: reopen the same file and reconcile, never resend.
# result = EffectStore("effects.sqlite").reconcile(effect.key, provider)
```

`action` is finite JSON data (string-keyed objects, lists, strings, numbers,
booleans, null). The coordinator persists sorted compact JSON and sends that
immutable `EffectRequest.action_json`, not later caller arguments. Include the
operation and every provider parameter in this payload. The host is responsible
for matching the amount and action to its authorized intent; the coordinator
cannot infer costs. Amount and capacity must be positive signed 64-bit integers;
booleans/floats are rejected.

This lifecycle models fixed, all-or-nothing effects only: the trusted host must
ensure budget units and the reserved amount cover actual provider exposure.
Variable costs and partial external execution are outside this contract. Include
the amount in the persisted action envelope when the provider needs it; adapters
consume `action_json`, not separately supplied execution arguments.
Stable versioned keys bind provider, grant reference
and a domain-separated action digest. A grant reference cannot be rebound to a
different provider, action, budget or amount, including after settlement.

## State and accounting

`RESERVED -> IN_FLIGHT -> DONE | NOT_DONE | UNKNOWN`.
`IN_FLIGHT` and `UNKNOWN` can reconcile to `DONE`, fenced `NOT_DONE`, or `UNKNOWN`.
Terminal states never move. `send` invokes a provider only for a newly claimed
reservation; duplicate calls return persisted evidence without dispatch.
`reconcile` rejects `RESERVED`, and returns terminal records without another query.

Reservation insertion and budget reservation share one SQLite transaction.
Before provider I/O, `IN_FLIGHT` commits durably. `DONE` atomically moves reserved
units to settled; fenced `NOT_DONE` releases reserved units without settling.
`UNKNOWN`, exceptions, cancellation, invalid results and failed settlement retain
exposure. If writing `UNKNOWN` itself fails, persisted `IN_FLIGHT` remains
recoverable; this secondary persistence failure is logged. The original exception
is re-raised. Independent connections use
`BEGIN IMMEDIATE` and full synchronous commits; no database lock is held during
provider I/O. At all times `0 <= reserved + settled <= capacity`.

Opening the file never rewrites `IN_FLIGHT`: another worker might still be
sending. Explicit recovery uses provider fencing even for the crash window
between the durable claim and dispatch. No automatic resend, expiration,
budget replenishment or garbage collection is provided. Retain durable records
and grant identity uniqueness for at least the provider's deduplication horizon.
Deleting/rolling back the database destroys these guarantees. File permissions,
reliable SQLite filesystem locking and durable storage are host responsibilities.

## Required provider contract and limitations

Implement the typed `EffectProvider` protocol: stable `provider_id`,
`send(EffectRequest) -> ProviderResult` and
`query_and_fence(EffectRequest) -> ProviderResult`.
Every result must match the exact key and provider and use `EffectOutcome`.
`DONE` is irrevocable completion. `NOT_DONE` must carry `fenced=True` and means the
provider atomically prevented every delayed or future send for this key.
An absent lookup alone is insufficient. A provider unable to prove either answer
must return `UNKNOWN`. Query/fence must serialize atomically with sends, durably
deduplicate the same key, bind it to the same payload, and never return conflicting
terminal outcomes. Concurrent reconciliation settles locally at most once.

These are **trusted adapter assumptions**, not proof of any real provider's
guarantees. The local result shape is not a signed provider receipt. A4 adapter
conformance, provider attestations, signed delivery evidence and A5 composition of
approval/revocation with external effects remain separate work. Simulated-provider tests
demonstrate the local boundary and fencing model only. Neo4j is optional and is
not a runtime dependency.
