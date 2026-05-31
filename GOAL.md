# Goal v1.0: Constitutional Governance Membrane

## Default-Layer Ambition

Make `acgs-lite` the default open-source constitutional governance layer that
agent builders can place immediately before side-effectful execution. The goal is
not to claim that status today; it is to earn it by making constitutional
authorization easy to add, hard to bypass, and easy to verify.

The adoption wedge is narrow and executable:

> Developers should be able to place `acgs-lite` immediately before any
> side-effectful agent action and get a verifiable ALLOW / DENY / TRANSFORM
> decision with a receipt.

## Core Invariant

> No valid constitutional authorization, no side effect.

The runtime must fail closed whenever authorization, constitution version, policy
state, receipt integrity, or audit evidence cannot be verified.

## Product Boundary

`acgs-lite` is not an agent framework. It does not own model calls, prompting,
planning, memory, tool selection, retries, scheduling, or workflow orchestration.
Those remain the responsibility of the host agent runtime.

`acgs-lite` is the governance membrane before execution:

```text
LLM reasoning → constitutional check → decision receipt → governed execution
```

Agent frameworks decide what action they want to take. `acgs-lite` decides
whether that proposed side effect is constitutionally authorized under versioned
rules, emits a receipt for the executor to verify, and records audit evidence for
inspection and replay.

## What the Membrane Must Provide

- A simple pre-execution API that accepts a proposed action and active
  constitution state.
- Deterministic ALLOW / DENY / TRANSFORM-style outcomes mapped to the canonical
  decision taxonomy.
- Receipts bound to the proposed method, scope, subjects, authority basis,
  policy version, and execution boundary.
- Executor-side refusal when the receipt is missing, malformed, tampered with,
  stale, denied, or mismatched against substituted arguments.
- Audit evidence that can be inspected and replay-verified, with tampering
  rejected rather than treated as a successful log.
- A path from lightweight in-process use to stronger storage, signing,
  cryptographic anchoring, and operational controls.

## Non-Goals

`acgs-lite` should not become:

- a new agent framework;
- a passive logging system that observes side effects after the fact;
- a compliance-claim generator;
- a large demo application;
- a marketing layer that claims default adoption, production readiness,
  regulatory approval, or certification without evidence.

## Long-Term Success Criteria

- Developers can wrap existing agent execution without rewriting their agent
  logic.
- Side-effectful actions are checked against a versioned constitution before
  execution.
- Executors refuse work unless a valid decision receipt matches the actual
  method, scope, subjects, policy version, and execution boundary.
- Denials, transformations, approvals, and fail-closed states leave inspectable
  audit evidence.
- Tampered receipts, audit trails, substituted arguments, missing constitutions,
  and stale policy state are detected and fail closed.
- Constitutions are portable enough to share, review, test, and evolve across
  tools and organizations.
- Higher-assurance deployments can add formal checks, cryptographic anchoring,
  and external verification without changing the membrane model.
