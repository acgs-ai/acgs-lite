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

Only `ALLOW` and `ALLOW_WITH_CONTROLS` can reach execution, and
`ALLOW_WITH_CONTROLS` must still satisfy every required control. Unknown,
ambiguous, denied, review, transform, replan, and hard-deny states are not
executable by default.

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

## Execution Boundary Binding

Before a wrapped callable executes, `GovernedCallable` removes
`decision_receipt`/`acgs_receipt` and checks it with
`validate_receipt_for_execution()`.

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

## Audit Evidence Expectations

`AuditLog` is tamper-evident. Execution paths that carry audit evidence must
verify the audit chain before side effects. `GovernedCallable` passes its audit
log into `validate_receipt_for_execution()`, and a failed `verify_chain()` blocks
the wrapped callable before user code runs.

Receipts and audit logs are complementary:

- the receipt proves authorization for this proposed execution boundary;
- the audit log provides tamper-evident, hash-chained evidence that recorded entries were not altered;
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
- Receipts carry no nonce or timestamp in the signed bytes; enforce `request_id`
  uniqueness at the application layer to prevent replay of a valid receipt.

## Failure Contract

`validate_receipt_for_execution()` raises `LegitimacyInvariantError` before
execution when evidence is missing or invalid. Callers must treat this as a hard
deny at the side-effect boundary.

The stable contract is covered by `tests/test_legitimacy_contract.py`, including
stale receipts, tampered hashes, method/scope/subject mismatch, missing
authority basis, unknown decisions, and unverifiable audit evidence.

## Reference

::: acgs_lite.legitimacy
