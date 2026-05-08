# Architecture: Governed Execution Lifecycle

**Meta Description**: Deep dive into the ACGS-Lite architecture. Learn about the Governance Engine, the validation lifecycle, and how MACI roles enforce separation of powers.

---

ACGS-Lite is built on the principle of **Deterministic Runtime Governance**. Unlike "safety tuning" or "system prompts" which are probabilistic and can be bypassed, ACGS-Lite interposes a hard, code-level boundary between an agent and its environment.

## 🏛️ System Overview

The core of ACGS-Lite is the **Verification Kernel**, which manages the interaction between the cognitive layer (the LLM) and the execution layer (tools/APIs).

```mermaid
graph TD
    A[User / Orchestrator] --> B[GovernedAgent]
    B --> C{Validate Input}
    C -- Violation --> D[Block & Log]
    C -- Valid --> E[LLM / Agent Logic]
    E -- Proposed Action --> F{Validate Output/Tool}
    F -- Violation --> D
    F -- Valid --> G[Execute Action]
    G --> H[Audit Log]
    H --> I[Chained Decision Records]
```

---

## 🛡️ Core Components

### 1. The Constitution
The **Constitution** is an immutable set of `Rule` objects. Every rule has an `id`, a `pattern` (Regex), a `severity`, and an optional `condition` (Python expression).
*   **Constitutional Hash**: A SHA-256 hash of the entire rule set. This ensures that the governance logic hasn't been tampered with during deployment.

### 2. The Governance Engine
The `GovernanceEngine` is the deterministic "Judge." It evaluates text (input or output) against the Constitution and returns a `ValidationResult`.
*   **Fail-Closed Design**: If the engine encounters an internal error (e.g., a malformed regex or memory issue), it defaults to `valid=False`. Missing or unverifiable governance proof never becomes execution authority.

### 3. Governed Wrappers
The library provides `GovernedAgent`, `GovernedCallable`, and framework-specific adapters (OpenAI, Anthropic, etc.). These wrappers intercept calls and manage the validation lifecycle automatically.

---

## 🚦 The Validation Lifecycle

Every action in ACGS-Lite follows a 4-step lifecycle:

1.  **Intercept**: The call is paused before execution.
2.  **Verify**: The engine checks the action against the active Constitution.
3.  **Audit**: The result (Pass/Fail) is recorded in the `AuditLog` with a cryptographic signature.
4.  **Act**: If passed, the action executes. If failed, a `ConstitutionalViolationError` is raised.

---

## ⚖️ MACI: Separation of Powers

In mission-critical systems, a single agent should not have the power to both propose and approve an action. ACGS-Lite enforces **MACI (Monitor-Approve-Control-Inspect)** roles:

| Role | Responsibility | Implementation |
| :--- | :--- | :--- |
| **Proposer** | Generates the action | The LLM/Agent |
| **Validator** | Checks against the rules | The ACGS `GovernanceEngine` |
| **Executor** | Performs the approved task | The `GovernedAgent` wrapper |
| **Observer** | Records the history | The `AuditLog` backend |

By separating these roles, ACGS-Lite prevents a Proposer (the agent) from approving its own high-risk action through the governed execution path.

---

## 📈 Advanced Features

### Governance Circuit Breaker
To prevent "recursive failure loops" where an agent repeatedly tries to violate a policy, ACGS-Lite includes a **Circuit Breaker**. If an agent hits X violations within Y minutes, the circuit breaker trips and blocks all further actions from that `agent_id` until a human reset.

### Formal Verification (Z3)
For financial or safety-critical logic, ACGS-Lite supports the **Z3 SMT Solver**. This allows you to define mathematical constraints (e.g., `balance >= withdrawal_amount`) that are proven safe before execution.

### Leanstral Proof Certificates
For high-assurance environments, the `LeanstralVerifier` can generate Lean 4 proof certificates using Mistral models, providing machine-verifiable evidence for selected governance decisions.

## Cloud Run

If you need a remote governance endpoint instead of an in-process wrapper, package the ACGS runtime behind a small HTTP service and deploy it to Cloud Run. The important constraints are:

- Keep the governance engine fail-closed on internal errors so transport retries never bypass validation.
- Expose health and audit endpoints separately from action execution so operators can inspect the system without widening the execution surface.
- Pin the constitutional hash and configuration through environment variables or a mounted config bundle so every deployed revision is auditable.
- Emit audit logs and latency telemetry to a durable backend before acknowledging requests, which keeps compliance evidence intact across container restarts.

Cloud Run is a good fit when you want autoscaling, private service-to-service auth, and a single governance plane shared by multiple agents or MCP clients.

---

## 🔄 Constitution Lifecycle

The Constitution Lifecycle system manages how governance rules evolve safely over time without downtime. It introduces a bundle-based saga pattern that keeps MACI role separation in the update path itself.

### Bundle Saga

A `ConstitutionBundle` moves through a defined set of statuses:

```text
draft → review → eval → approve → staged → active
                        ↓               ↓
                     rejected       rolled_back
              (at any point) withdrawn
```

Each transition is gated: only the originating proposer can submit, a reviewer advances
`review -> eval`, an approver advances `eval -> approve`, a validator can reject, and
an operator handles staging, activation, and rollback.

### Key Components

- **`ConstitutionLifecycle`** — the core service that owns the saga logic and enforces MACI role checks on every transition.
- **`SQLiteBundleStore`** — persistent store using WAL journal mode and `BEGIN EXCLUSIVE` transactions. A partial unique index enforces one `ACTIVE` bundle per tenant at the database level.
- **`BundleAwareGovernanceEngine`** — wraps `ConstitutionLifecycle` to return a `GovernanceEngine` built from the tenant's active bundle. Engine instances are cached by `(tenant_id, bundle_hash)`. Host applications must call `invalidate(tenant_id)` after lifecycle changes that should refresh the bound engine.
- **FastAPI lifecycle router** — thirteen REST endpoints under `/constitution/lifecycle/` expose the full saga over HTTP (10 `POST` mutation endpoints + 3 `GET` read endpoints). When configured, all lifecycle endpoints require `X-API-Key`; mutation endpoints also require `X-Actor-ID`. See [Constitution Lifecycle API](api/lifecycle.md) for the full reference.

### Governed Self-Evolution

Self-evolution is implemented as a proposal-and-gate layer on top of the lifecycle, not as direct self-modification. `SelfEvolutionEngine` analyzes decision records for uncovered denials, hot rules, and low-confidence allows, then emits scored `EvolutionCandidate` objects. Candidates are simulated against an action corpus for blast radius, weighted transition risk, and deny-to-allow regressions before any amendment is drafted. Passing candidates then enter `AmendmentProtocol` for MACI voting, ratification, enforcement, and lifecycle rollout. See [Governed Self-Evolution](self-evolution.md) for the operating model.

---

## Next Steps
- Learn how to [Configure Your First Rules](quickstart.md).
- See [2026 Regulatory Compliance](compliance-2026.md) mappings.
- Explore the [Industry Use Cases](use-cases.md).
