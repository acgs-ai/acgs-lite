# Roadmap

This roadmap translates [Goal v1.0](GOAL.md) into milestones for `acgs-lite` as
a lightweight constitutional governance membrane before agent side effects. It is
a direction of travel, not a claim that `acgs-lite` is already the default layer
or production-certified for every deployment.

Core invariant:

> No valid constitutional authorization, no side effect.

## Milestones

### Runtime Legitimacy Kernel

Define the small runtime contract that every side-effectful action must pass:
declared goal, proposed method, authority basis, active constitution, policy
version, execution boundary, decision, and receipt.

Expected outcomes:

- fail-closed behavior for missing constitution state, policy version, authority,
  receipt, or execution boundary;
- clear ALLOW / DENY / TRANSFORM-style adapter outcomes mapped to the canonical
  internal decision taxonomy;
- executor-side receipt validation that binds receipts to actual method, scope,
  subjects, and policy version;
- tests for missing, stale, malformed, or unverifiable governance state.

### Receipt and Audit Evidence

Make every governed decision inspectable after the fact without implying that an
action was legitimate merely because it was logged.

Expected outcomes:

- receipt hashing and canonical serialization;
- audit entries for allowed, denied, transformed, and failed-closed decisions;
- evidence fields that identify the active constitution, matched constraints,
  authority basis, and execution boundary;
- examples showing how audit evidence supports debugging and review.

### Replay Verification

Let operators and tests replay evidence and reject tampering.

Expected outcomes:

- replay checks for receipt hash integrity and audit-chain integrity;
- rejection of substituted arguments, mismatched execution boundaries, and
  tampered audit evidence;
- small CLI or API affordances for inspecting a receipt and verifying the audit
  evidence behind it;
- documented gaps where evidence is in-memory or best-effort rather than durable.

### Framework Adapters

Keep `acgs-lite` callable from agent frameworks rather than turning it into one.

Expected outcomes:

- thin adapters for common agent/tool runtimes;
- a stable pre-execution hook pattern for tool calls, API calls, file writes,
  transactions, and workflows;
- copy-paste examples that wrap existing agent logic without taking over
  planning, memory, model calls, or tool selection;
- in-memory side-effect examples so the membrane can be tested without external
  services.

### Shareable Constitutions

Make constitutions versioned, reviewable, testable, and portable.

Expected outcomes:

- reusable example constitutions for common domains;
- schema checks and linting for malformed policy files;
- diff, migration, and lifecycle documentation for constitution updates;
- clear guidance for pinning active policy versions in receipts.

### Cryptographic Anchoring

Make evidence externally checkable when deployments need stronger assurance.

Expected outcomes:

- optional receipt and audit signing;
- append-only evidence export formats;
- anchoring designs that let external verifiers detect tampering without seeing
  private action contents;
- clear separation between lightweight local receipts and higher-assurance
  deployments.

### Production Hardening

Improve operational safety without claiming production readiness beyond what is
verified in the repository.

Expected outcomes:

- deployment profiles for authentication, authorization, storage, retention, and
  rollback;
- failure-mode tests for unavailable stores, malformed receipts, stale policies,
  audit write failures, and replay failures;
- guidance on fail-closed persistence when durable audit evidence is required;
- documented limits for in-memory demos versus durable deployments.

### Ecosystem Standardization

Help other tools adopt the membrane contract with minimal coupling.

Expected outcomes:

- stable vocabulary for proposed action, constitutional check, decision receipt,
  replay verification, and governed execution;
- adapter compatibility notes for agent frameworks and MCP-style tool servers;
- community contribution paths for new framework integrations and constitution
  templates;
- no inflated claims about current adoption, regulatory approval, compliance
  certification, or universal production readiness.

## Related Planning Documents

The existing planning documents remain useful as implementation context:

- [`planning/next-milestones.md`](planning/next-milestones.md) tracks release
  and near-term engineering work.
- [`planning/community-roadmap.md`](planning/community-roadmap.md) tracks
  contributor and community work.
- [`GOVERNANCE.md`](GOVERNANCE.md) describes project roles and decision-making.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) explains how to propose changes.
