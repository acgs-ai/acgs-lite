---
documentLanguage: en
---

# Glossary

One entry per term: definition, boundaries, one resolved ambiguity. Agents write here the moment a term is settled. Vocabulary here is law for all specs, tickets, and code naming. Ship-specific terms only: a concept any sea chart carries does not get an entry.

## constitutional hash
- Definition: `Constitution.hash` (`src/acgs_lite/constitution/constitution.py`) is a 16-hex-character sha256 prefix computed once over each rule's id, text, severity, hardcoded flag and sorted keywords. `hash_versioned` renders it as `sha256:v1:<hash>`.
- Boundary: it is a short label for a rule set. It is not a collision-resistant policy identity (that is the **policy digest**), and changes to patterns, `enabled`, `workflow_action` or `condition` leave it unchanged.
- Avoid: policy digest, constitution ID.
- Resolved ambiguity: `CONSTITUTIONAL_HASH = "608508a9bd224290"` in `src/acgs_lite/_meta.py` is a fixed package stamp, also hardcoded in the CDP records. It is not computed from any loaded constitution.

## policy digest
- Definition: `bind_policy(constitution)` (`src/acgs_lite/legitimacy/invocation.py`) returns `PolicyBinding(version, algorithm="sha256", digest)`. The digest is sha256 over the `acgs-policy-v1\x00` domain prefix plus the canonical JSON of the whole constitution. `policy_identity()` renders it as `acgs:policy:v1:sha256:<digest>`.
- Boundary: it is the full, domain-separated content digest. It is not `Constitution.hash`, and it is not `PolicyBinding.version`, which only carries a display label.
- Avoid: constitutional hash, policy hash, policy version (used as an identity).
- Resolved ambiguity: grants and attempt records bind `policy_digest`, and the code explicitly says not to reuse the truncated `Constitution.hash`. A label change keeps the identity, while a content change alters it.

## MACIRole
- Definition: `MACIRole` (`src/acgs_lite/maci/roles.py`) has exactly four members: PROPOSER, VALIDATOR, EXECUTOR and OBSERVER. A verb is permitted only if it is in the role's allow set and not in its deny set. OBSERVER may read, query, export and observe only.
- Boundary: it is lite's separation-of-powers enum. It is not enhanced-agent-bus's `MACIToolRole` vocabulary.
- Avoid: MONITOR, AUDITOR, admin, approver (`approve` is a denied verb, not a role).
- Resolved ambiguity: this enum has no MONITOR or AUDITOR member; those names come from the separate enhanced-agent-bus package. Lite's read-only role is OBSERVER, so do not add MONITOR or AUDITOR here.

## DecisionReceipt
- Definition: `DecisionReceipt` (`src/acgs_lite/legitimacy/receipt.py`) is a frozen, replayable decision record emitted before execution and addressed by `receipt_hash`. `verify_hash()` recomputes the hash, and `receipt_identity()` refuses to build an `acgs:receipt:v1:sha256:` reference from a receipt whose hash does not verify.
- Boundary: it is hash-addressed evidence of a decision. It is not a signature (**SignedReceipt**), not execution authority (**ExecutionGrant**), and not an outcome receipt, which is design-only.
- Avoid: governance receipt, outcome receipt, proof, approval.
- Resolved ambiguity: a receipt records a decision and grants nothing. Execution authority comes from an ExecutionGrant that embeds the receipt.

## SignedReceipt
- Definition: `SignedReceipt` (`src/acgs_lite/legitimacy/signing.py`) wraps a DecisionReceipt in an asymmetric signature. Its `signature_scope` is either `"receipt"` (the default) or `"execution"`. Execution scope requires `authorization_json`, which is signed as opaque bytes and never parsed.
- Boundary: it is a signature over a receipt. Under scope `"receipt"` it is not an authorization.
- Avoid: signed decision, attestation, signed grant.
- Resolved ambiguity: `signed_envelope_identity()` hashes `key_id` and `signed_at`, which the signature does not cover. An envelope identity is therefore an evidence reference, not proof of authenticity.

## ExecutionGrant
- Definition: `ExecutionAuthority.issue()` (`src/acgs_lite/legitimacy/authorization.py`) mints an `ExecutionGrant` binding the receipt, method, argument digest, policy digest, scope, subjects, context and expiry. It is single-use by default and authenticated by a `binding_mac` keyed with a per-instance secret.
- Boundary: it is a process-local capability, verifiable only by the `ExecutionAuthority` instance that issued it. It is not a portable token, and it is not its evidence reference (`local_grant_identity`).
- Avoid: token, permit, approval, signed grant.
- Resolved ambiguity: grants do not survive a restart and cannot be verified by a second process. Durable or cross-process authority is not implemented.

## evidence identity
- Definition: versioned reference strings built by `src/acgs_lite/legitimacy/identity.py`: `acgs:policy:v1:`, `acgs:receipt:v1:`, `acgs:signed-envelope:v1:` and `acgs:local-grant:v1:<issuer_id>:<grant_id>`. Building one leaves hashes, signature payloads and serializers unchanged.
- Boundary: it is a stable pointer to evidence. It is not a capability, not a signature check, and not a replacement for an ExecutionGrant.
- Avoid: grant (for the string), credential, proof, ID token.
- Resolved ambiguity: `local_grant_identity` excludes the capability MAC, so holding the string authorizes nothing. `EffectStore.reserve` stores it as an opaque `grant_identity` without validating any grant.

## AuditEntry
- Definition: a row of `AuditLog` (`src/acgs_lite/audit.py`). `record(entry)` appends it under the log lock and returns a chain hash over the previous hash and the entry hash. `JSONLAuditBackend` writes `_chain_hash` and `_format_version` (`sha256-v1` or `legacy-sha256-16`).
- Boundary: it is a hash-chained governance log row. It is not a DecisionReceipt, and writing it with `record()` does not guarantee it is persisted.
- Avoid: audit receipt, audit event, log line.
- Resolved ambiguity: `record()` only logs a backend write failure as a warning. Use `record_durable()` for fail-closed persistence. Adapter payloads rename the entry's `constitutional_hash` to `policy_hash` (`to_receipt_dict`), so the same value appears under two names.

## external effect
- Definition: one provider dispatch tracked by `EffectStore` (`src/acgs_lite/legitimacy/effects.py`), an opt-in SQLite lifecycle with the `EffectState` values RESERVED, IN_FLIGHT, UNKNOWN, DONE and NOT_DONE. `send()` commits IN_FLIGHT before calling the provider, and any exception moves the effect to UNKNOWN. `reconcile()` settles only through `EffectProvider.query_and_fence`, and it accepts NOT_DONE only when the effect was fenced (`fenced=True`).
- Boundary: it is durable evidence that runs from reservation to settlement, for fixed all-or-nothing side effects. It is not authorization: the host validates and consumes authority first, and the store is not wired into decorators.
- Avoid: transaction, job, "authorized effect".
- Resolved ambiguity: the in-process `AttemptStatus.PARTIAL` (`src/acgs_lite/legitimacy/ledger.py`) is a different state. PARTIAL is not UNKNOWN, so keep the two separate.

## effect key
- Definition: the key `EffectStore.reserve()` derives as `acgs:effect:v1:` + sha256 over `acgs-provider-effect-v1\0` and the canonical JSON of `[provider_id, grant_identity, action_digest]`. In the same transaction it reserves `amount` on an `EffectBudget` only if it fits within `capacity - settled - reserved`.
- Boundary: it is a grant-bound, immutable provider key with an atomic integer hold on a fixed budget. It is not a caller-chosen idempotency token, and `EffectBudget` is not `CostBudget` (compute accounting).
- Avoid: idempotency key, request ID, dedupe token, quota.
- Resolved ambiguity: one `grant_identity` maps to one effect forever. A replay with identical bindings returns the existing record, any changed binding raises "grant effect binding is immutable", DONE settles the amount and NOT_DONE releases it.
