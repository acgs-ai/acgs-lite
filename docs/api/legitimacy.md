# Runtime Legitimacy Kernel

The Runtime Legitimacy Kernel is the stable pre-execution surface for the
ACGS membrane:

```text
constitutional check -> decision receipt -> governed execution
```

The invariant is fail-closed:

> No valid constitutional authorization, no side effect.

Executors must verify a receipt at the side-effect boundary. Missing, stale,
tampered, denied, mismatched, or audit-unverifiable evidence blocks execution.

## Public API

Import stable names from `acgs_lite.legitimacy`:

```python
from acgs_lite.legitimacy import (
    CANONICAL_DECISION_STATES,
    DecisionReceipt,
    ExecutionBoundary,
    LegitimacyInvariantError,
    canonicalize_decision_state,
    is_allow_state,
    normalize_actual_call,
    route_ambiguous_decision,
    validate_receipt_for_execution,
)
```

The exported compatibility helpers are also stable:

- `BASELINE_CONSTRAINT_MARKER`
- `ActualCall`
- `DecisionState`
- `call_matches`
- `to_receipt_dict`

## Evidence identity adapters

The public helpers `policy_identity`, `receipt_identity`,
`signed_envelope_identity`, and `local_grant_identity` return versioned,
namespace-separated string references for indexing evidence. They grant no
execution authority and add no storage or Neo4j dependency.

- Policy: `acgs:policy:v1:sha256:<full digest>` uses the PolicyBinding digest,
  not its display/version label.
- Receipt: `acgs:receipt:v1:sha256:<receipt hash>` for v1 receipts and
  `acgs:receipt:v2:sha256:<receipt hash>` for schema v2 receipts. It preserves the
  existing commitment and checks payload/hash consistency.
- Signed envelope: `acgs:signed-envelope:v1:sha256:<digest>` hashes
  `b"acgs-signed-envelope-identity-v1\x00"` (including one trailing NUL byte)
  followed by UTF-8 canonical JSON
  of `SignedReceipt.to_dict()` (sorted keys, compact separators, ASCII escapes).
  It includes metadata `key_id` and `signed_at` that existing signatures do
  **not** authenticate. This identifies serialized evidence; it does not
  verify a signature or a trusted issuer. The raw `authorization_json` string
  stays unchanged, and legacy omitted fields follow the existing serializer.
- Grant: `acgs:local-grant:v1:<issuer_id>:<grant_id>` is a process-local
  evidence reference, excluding `binding_mac`. Both identifiers must contain
  only ASCII letters, digits, underscore or hyphen. The reference cannot replace
  the original grant or its issuing authority's validation.

Digest and signature hex must be full-length lowercase hex. Unsupported policy
algorithms, signature algorithms/scopes and malformed identifiers fail closed.
The identity helpers do not change receipt/grant dataclasses, serializers or
signed payloads. Receipt schema v2 is described under [Receipt Fields](#receipt-fields).

## Decision Taxonomy

`CANONICAL_DECISION_STATES` contains the canonical decision states:

```text
ALLOW
ALLOW_WITH_CONTROLS
TRANSFORM_REQUIRED
REPLAN_REQUIRED
STRUCTURED_REVIEW_REQUIRED
DENY_OPERATION_WITH_ALTERNATIVE
DENY_GOAL
HARD_DENY
```

Only `ALLOW` and `ALLOW_WITH_CONTROLS` are allow-class decisions. The
production profile refuses controlled authorization carriers because this
package has no general trusted control-verification service. The historical
compatibility profile has weaker control handling, as described below.
Unknown, ambiguous, denied, review, transform, replan, and hard-deny states
are not executable by default.

Use `canonicalize_decision_state()` to map known legacy strings into the
canonical taxonomy. Use `route_ambiguous_decision()` when confidence is missing
or below threshold; it routes to `STRUCTURED_REVIEW_REQUIRED`, never `ALLOW`.

## Receipt Fields

`DecisionReceipt` is the stable receipt type. It is immutable after creation and
its `receipt_hash` is derived from the canonical payload.

Required receipt fields:

| Field | Purpose |
| --- | --- |
| `request_id` | Correlates the decision with the proposed action. |
| `goal` | Human-readable purpose that was evaluated. |
| `proposed_method` | Method/tool/action name authorized by the decision. |
| `decision_type` | Canonical decision state. |
| `authority_basis` | Non-empty basis for why this actor/action is authorized. |
| `matched_constraints` | Non-empty proof that policy constraints were evaluated. |
| `policy_version` | Non-empty version/hash of the governing policy state. |
| `required_controls` | Extra controls that must be satisfied before execution. |
| `transformation_applied` | Transformation details when the decision required one. |
| `denial_or_review_rationale` | Rationale for deny/review states. |
| `execution_boundary` | Boundary the actual executor call must match. |
| `issued_at` | Receipt issuance timestamp. |
| `receipt_hash` | Integrity hash over the canonical receipt payload. |

`ExecutionBoundary` fields:

| Field | Purpose |
| --- | --- |
| `allowed_method` | Required method/action name, or `None` for no method constraint. |
| `allowed_scope` | Required tenant/workspace/scope, or `None` for no scope constraint. |
| `allowed_subjects` | Subjects/resources the actual call may touch. |
| `expires_at` | ISO timestamp after which the receipt is stale. |
| `single_use` | Compatibility field for callers that track replay externally. |

Create receipts with `DecisionReceipt.create(...)`; direct construction is
reserved for deserialization paths that must still satisfy the same invariants.

### Receipt schema v2

`GovernedCallable.issue_grant` mints schema v2 receipts only. A v2 receipt adds:

| Field | Purpose |
| --- | --- |
| `schema_version` | `2`. A missing or `null` value always means v1; v2 is never inferred. |
| `grant_id` | Random server-side id from `ExecutionAuthority.allocate_grant_id()`, committed before the grant is minted. Callers cannot supply one. |
| `policy_digest` | Full `PolicyBinding.digest` of the policy that decided. |
| `method_id` | Identity of the bound callable. |
| `argument_digest` | Digest of the canonical bound arguments. |
| `context_digest` | Trusted-context digest, or absent when no trusted context is bound. |

v2 hashes are domain-separated: SHA-256 over `RECEIPT_HASH_DOMAIN_V2`
(`b"acgs-receipt-v2\x00"`) followed by the canonical JSON of the v1 keys,
`schema_version` and the non-null v2 keys. v1 receipts keep their byte-identical
hash and wire shape, and no v1 bytes verify as v2 or vice versa. v2 fields on a
v1 receipt, or v2 keys on the wire without `schema_version: 2`, are refused.
The v2 wire schema is closed: unknown receipt or `execution_boundary` keys are
refused, while v1 parsing keeps ignoring extra keys. One receipt mints at most
one grant. `build_issue_receipt` takes the engine decision as a required
keyword-only `decision` argument, and receipts record that decision rather than
a fixed stamp. `RECEIPT_HASH_DOMAIN_V2` is exported from `acgs_lite.legitimacy`.

## Execution Boundary Binding

Before a wrapped callable executes, `GovernedCallable` removes authorization
metadata and checks the actual bound invocation.

The verifier normalizes the actual call into `ActualCall(method, scope,
subjects)` and compares it to the receipt boundary:

- the method must match `allowed_method` when set;
- the scope must match `allowed_scope` when set;
- each actual subject must be inside `allowed_subjects` when set;
- a non-empty subject boundary requires actual subject evidence;
- `expires_at` must parse and must not be in the past.

Explicit `governance_method`, `governance_scope`, and `governance_subjects`
metadata take precedence. For `GovernedCallable`, positional and keyword
arguments are also bound to the wrapped function signature so common subject
parameters such as `customer_id`, `account_id`, `subject_id`, `resource_id`, and
`user_id` cannot bypass the boundary by being passed positionally.

`authorization_profile="production"` requires an Ed25519 execution signer at
construction (`crypto` extra) and an `ExecutionGrant` issued by that exact
`GovernedCallable` instance.

| Constructor argument | Meaning |
|---|---|
| `receipt_signer` | Required. A non-ephemeral Ed25519 `ReceiptSigner`. Keys from `Ed25519ReceiptSigner.generate()` are refused; load a persistent key with `from_private_bytes()` (or `from_seed()` for fixtures), or back the protocol with a KMS/HSM. Only `generate()` is detected as ephemeral: a key object cannot prove where its bytes came from, so provisioning the key and its pin out of band is the operator's responsibility. |
| `trusted_execution_keys` | Required. `key_id -> public key hex` pinned with execution scope, supplied from outside the signer. The signer's key must be pinned here. `trusted_issuer_keys` never authorizes execution. |
| `grant_ttl_seconds` | Signed grant lifetime, default 300. Must be positive and finite. |

Missing, ephemeral, unpinned, or non-Ed25519 signers raise
`LegitimacyInvariantError`, and so does any of these arguments under the
compatibility profile. Every production grant carries `grant.signed_receipt`: a
v2 receipt signed with execution scope over an envelope that commits the method,
argument, policy and trusted-context digests, scope, subjects, grant id and
expiry. Before the ledger consume, both the `execution_grant=` and the
`signed_receipt=` carriers are verified against the live call: the key must be
pinned in `trusted_execution_keys`, the signature valid, the receipt v2 with an
`ALLOW` or `ALLOW_WITH_CONTROLS` decision, unexpired on both the wall clock and a
monotonic deadline, issued by this instance for this exact callable, and every
envelope and receipt binding equal to the call. The grant id is not a secret:
each issued grant id is bound to the exact receipt hash and the key that signed
it, so a receipt signed by another pinned key, or a different receipt reusing a
live grant id, is refused and never consumes the real grant. A receipt-scope
signature, an unpinned key, a denied decision, an expired or mismatched
envelope, and a second use all deny before the callable runs.

Expiry blocks new executions only. Retrying with the same grant and the
`execution_attempt_id` the ledger already recorded for it is answered from the
ledger after expiry (the completed result, or the recorded status) and never
runs the callable again; the signature, key pin and bindings are still checked.

Governed arguments and return values must be JSON-native: exact `dict` with `str`
keys, `list`, `tuple`, `str`, `int`, `bool`, finite `float`, `None`, and
`bytes`/`bytearray` that decode as strict UTF-8. Text and dictionary keys containing
C0 controls other than tab, newline and carriage return are rejected, because JSON
escaping would conceal those characters from rule matching. The governance
projector, the argument digest and the output digest admit exactly these values,
matched by exact type. Anything else (`Enum` members, dataclasses, pydantic
models, `datetime`, `UUID`, paths, `Decimal`, sets, subclasses of the accepted
types, non-`str` keys, NaN and infinities) denies with
`GOVERNANCE-PAYLOAD-UNEVALUABLE` or `ArgumentNotDigestible` before the call, and
after the call for a return value (attempt `PARTIAL`, result withheld). Convert
rich objects before the call, for example `model.model_dump(mode="json")`,
`value.isoformat()` or `str(uuid)`.

The grant binds the current policy
digest, canonical arguments, method identifier, and exact callable object. It
is single-use through the instance's in-process ledger. An attempt identifier
cannot be reused for a different grant, and a terminal or cancelled attempt is
never executed again. An undigestible result immediately leaves the attempt
`PARTIAL` and raises an unknown-result error, before recording completion.
Completed result recovery verifies the recorded output digest; later mutation
also changes the attempt to `PARTIAL` instead of returning unverifiable success.
The grant retains its exact callable, whose process-local identity is covered
by the MAC. Arbitrary `functools.wraps` layers are not removed for authorization.
The issuer's signed-grant registry is pruned whenever a new production grant is
issued: a never-consumed grant is dropped once it expires, and a consumed grant
whose attempt has settled is dropped once one further `grant_ttl_seconds` has
passed after the later of its deadline and the attempt's settlement (monotonic
clock), so an attempt that outlives its grant stays recoverable for a full TTL
after it finishes. A grant whose attempt is still running is never dropped. After a consumed grant is pruned, a recovery retry with it is refused,
never re-executed. Consumed attempt records and recovery results in the instance
ledger are never pruned, which is what keeps every reuse refused; the ledger is
not an automatically bounded or durable history store.

`TrustedExecutionContext(actor_id, scope, allowed_subjects)` optionally binds a
grant to a host-supplied actor and tenant snapshot. The host is responsible for
authenticating those values; acgs-lite only binds them to the grant and actual
call. `allowed_subjects` must be a non-empty `frozenset`, and every actual
subject must be inside it. Set `require_trusted_context=True` to reject a missing
context. Trusted-context and durable-audit requirements are production-profile
features; configuring them under the compatibility profile fails at
construction instead of silently weakening the request. A wrapper represents
one stable actor/tenant context and is not a dynamic multi-tenant identity
provider. Do not expose its `issue_grant()` method to untrusted callers.

Production binding and execution share the same signature-derived identity
rules. Recognized scope aliases (including `tenant_id`) must agree; conflicting
values are refused. All recognized subject aliases (including `account_id`,
`customer_id`, and `subjects`) are checked together, including those bound inside
`**kwargs`. An explicit `subjects` value cannot hide another resource argument.
The host must still map application-specific resource fields to this contract;
the package does not infer identity from arbitrary nested payloads.

Production receiver methods are currently refused because this implementation
cannot bind a grant to an exact `self` or `cls` instance. Free functions and
static methods remain supported. Required arguments must be present when a
grant is issued, while declared defaults are applied consistently during grant
issuance and execution-boundary validation. Ordinary parameters named `self`
or `cls`, including keyword-only parameters, are bound like every other value
in production. Actual bound or descriptor receiver methods are refused.

This ledger has process-instance scope. It does not provide restart recovery,
distributed exclusion, or general exactly-once delivery to external APIs.
`require_durable_execution=True` and `require_restart_recovery=True` therefore
fail closed instead of implying those guarantees. A receipt-scope
`SignedReceipt` is evidence that can be independently verified, but the
production executor refuses it. An execution-scope `SignedReceipt` executes only
on the instance that issued it, once, through the same in-process ledger as the
grant; a different process holding the same pinned key does not share that
ledger and refuses it.

Production grants currently carry no required controls. An authorization
carrier with controls that cannot be verified at the execution boundary is not
accepted by the production path. Compatibility receipt validation retains its
historical structured human-approval behavior and must not be described as a
general trusted control-verification service.

## Audit Evidence Expectations

`AuditLog` is tamper-evident within its documented retained segment. Execution
paths that carry audit evidence verify the chain before side effects.
`GovernedCallable(require_durable_audit=True, audit_log=...)` also records and
confirms an `execution_authorized` entry through `record_durable()` before user
code runs. Unsupported backends and write/flush/rollback uncertainty fail
closed. This acknowledgement is separate from durable execution-result storage.
When enabled, required formal-verification exemptions and the terminal
`execution_completed` record also use the strict durable append. If terminal
confirmation fails after user code ran, the attempt becomes `PARTIAL` and no
result is reported or replayed as success.
The terminal ledger commit precedes the durable completion record, with
concurrent recovery excluded until both confirmations finish. If the ledger
cannot even record the uncertain outcome, that wrapper disables further grant
issuance and execution. This coordination is process-local and does not provide
an atomic transaction across crashes or a durable execution ledger.

Once wrapped user code starts, an exception or output-policy rejection cannot
prove that no external effect occurred. The in-process ledger records that case
as `PARTIAL`; it does not automatically retry. Cancellation is terminal as well,
but does not by itself prove rollback of an external operation.

Receipts and audit logs are complementary:

- the receipt proves authorization for this proposed execution boundary;
- the audit log detects alteration within the supplied retained segment; without
  an external trusted anchor it cannot detect whole-history deletion or rewrite;
- either proof becoming missing or unverifiable is a fail-closed condition.

## Signed, Replay-Verifiable Receipts (optional)

The `receipt_hash` proves a receipt was not *altered*. It does not prove *who*
issued it — anyone who can recompute the hash can mint a fresh one. The optional
`crypto` extra (`pip install "acgs-lite[crypto]"`) binds the receipt's commitment
to an Ed25519 signature so an independent party, holding only the signer's public
key, can establish authenticity and replay the decision.

```python
from acgs_lite.legitimacy import Ed25519ReceiptSigner, sign_receipt, replay_and_verify

signer = Ed25519ReceiptSigner.generate()        # or .from_seed(...) for determinism
signed = sign_receipt(receipt, signer)          # -> SignedReceipt
trusted_pubkey = signer.public_key_hex()

signed.verify(trusted_pubkey)                    # authenticity (REQUIRES a trusted key)
signed.verify_integrity()                        # self-consistency only — NOT authenticity

result = replay_and_verify(signed, evaluator, expected_public_key=trusted_pubkey)
result.ok                                        # signature + hash + verdict all reproduce
```

Public names (require the `crypto` extra at runtime):

- `Ed25519ReceiptSigner` — `generate()`, `from_seed(bytes)`, `from_private_bytes(bytes)`,
  `public_key_hex()`, `sign_receipt(receipt)`.
- `SignedReceipt` — `verify(expected_public_key)`, `verify_integrity()`,
  `to_dict()` / `from_dict()` for the wire.
- `sign_receipt(receipt, signer)`, `verify_signature(algorithm, public_key, message, signature)`.
- `replay_and_verify(signed, evaluator, *, expected_public_key)` -> `ReplayVerification`
  (`hash_valid`, `signature_valid`, `verdict_reproduced`, `recorded_decision`,
  `rederived_decision`, `mismatches`, `ok`). The `evaluator` receives a
  `ReplayInputs` and returns a decision state.

Boundaries (fail closed, by design):

- `verify(expected_public_key)` requires a trust anchor the caller already holds;
  an unpinned signature only proves *someone* signed it. `verify_integrity()`
  exists for the self-consistency check and must never be treated as authenticity.
- Signing requires `cryptography`; without it, signer construction and
  verification raise `ReceiptSigningUnavailable` rather than degrading to a
  symmetric scheme.
- The signing key is held in process memory. Back `Ed25519ReceiptSigner` with a
  KMS/HSM before relying on receipts for non-repudiation.
- Signature validity alone does not provide single-use consumption. The
  production profile pairs each execution signature with its issuing instance's
  in-process ledger; externally signed carriers need a separately qualified
  consumption protocol.

## Failure Contract

`validate_receipt_for_execution()` raises `LegitimacyInvariantError` before
execution when evidence is missing or invalid. Callers must treat this as a hard
deny at the side-effect boundary.

The stable contract is covered by `tests/test_legitimacy_contract.py`, including
stale receipts, tampered hashes, method/scope/subject mismatch, missing
authority basis, unknown decisions, and unverifiable audit evidence.

## Reference

::: acgs_lite.legitimacy

## Durable external effects

For opt-in SQLite reservations and provider reconciliation, see
[Durable external effects](external-effects.md). This trusted host lifecycle
does not replace execution authorization or change `AttemptStatus.PARTIAL`.
