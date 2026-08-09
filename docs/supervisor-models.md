# Advanced Governance Patterns: Verification Kernels & Supervisor Models

**Meta Description**: Explore advanced AI safety architectures like Verification Kernels and Supervisor Models using ACGS-Lite to ensure robust governance for autonomous agents.

---

In 2026, production-grade AI systems have moved beyond single-model architectures. High-stakes applications (Finance, Healthcare, Critical Infrastructure) now utilize **Multi-Model Verification Kernels**—a safety pattern where an independent "Supervisor" system monitors and validates the primary agent.

ACGS-Lite is designed to be the foundation of these Verification Kernels.

## The Verification Kernel Pattern

A Verification Kernel acts as a "Trusted Computing Base" for your agent. The primary agent (the Proposer) might be a massive, creative model (like Claude 3.5 Sonnet or GPT-4o), while the Verification Kernel is a deterministic engine backed by a smaller, specialized "Judge" model.

```
[ Primary Agent ] --(Action Proposal)--> [ ACGS Verification Kernel ]
                                           |  1. Deterministic Rule Check
                                           |  2. LLM-Based Policy Check
                                           |  3. Formal Verification (Z3)
                                           v
[ Environment ] <---(Approved Action)------ [ Gatekeeper ]
```

---

## Pattern 1: The "Supervisor" Model

In this pattern, ACGS-Lite calls a second model to evaluate complex, nuance-heavy policies that regex or keyword matching cannot catch (e.g., "Is this medical advice being given without a disclaimer?").

### Implementation with ACGS-Lite
You can implement this by creating a custom `Rule` with a `condition` that calls a supervisor model, or by using the `GovernedAgent` in a multi-agent setup.

```python
from acgs_lite import GovernedAgent, Constitution, MACIRole

# The Supervisor Constitution
supervisor_constitution = Constitution.from_yaml("ethics.yaml")

# The Supervisor Agent (wrapped in ACGS)
supervisor = GovernedAgent(
    ethics_model,
    constitution=supervisor_constitution,
    maci_role=MACIRole.VALIDATOR,
)

# The Primary Agent uses the Supervisor as its Validator
agent = GovernedAgent(
    primary_llm,
    constitution=main_rules,
    maci_role=MACIRole.EXECUTOR,
    validator_agent=supervisor  # Advanced Pattern: Multi-agent handoff
)
```

## Pattern 2: Deterministic Capability Gating

Capability Gating ensures that an agent is unable to invoke a governed tool wrapper unless the Verification Kernel has issued a cryptographically signed "Token of Approval."

### How ACGS Enforces Gating
1.  **Tool Interception**: Every tool in your agent's toolbox is wrapped in a `GovernedCallable`.
2.  **Context Injection**: The Kernel injects runtime context (user role, time of day, current risk tier) into the validation.
3.  **Fail-Closed Execution**: If the Kernel doesn't explicitly return `valid=True`, the tool wrapper raises a `GovernanceViolationError` before the tool logic even executes.

## Pattern 3: Formal Verification with Z3

For mathematical and logic-based constraints (e.g., "Never allow a transaction to exceed the account balance"), ACGS-Lite supports the **Z3 SMT Solver**.

This moves governance from "highly likely safe" to a deterministically checked path for the constraints it models.

```python
from acgs_lite.verification import Z3ConstraintVerifier

# Define a formal constraint
# "transaction_amount + current_usage <= daily_limit"
verifier = Z3ConstraintVerifier(
    constraints=["amount + usage <= 1000"],
    variables={"amount": "int", "usage": "int"}
)

# Validate at runtime
result = verifier.verify({"amount": 500, "usage": 200})
assert result.is_safe == True
```

---

## Summary of Benefits

| Pattern | Complexity | Best For |
| :--- | :--- | :--- |
| **Supervisor Model** | Medium | Nuanced policy (Ethics, Tone, Medical advice) |
| **Capability Gating** | Low | Hard security (DB access, Shell execution) |
| **Formal Verification** | High | Financial/Safety-Critical (Payments, IoT control) |

## Next Steps
- Learn more about [Z3 Integration](architecture.md#formal-verification-z3) in the Architecture doc.
- See how to use [MACI Roles](maci.md) to separate Proposer and Supervisor.
- Explore [Industry Use Cases](use-cases.md) for these patterns.
