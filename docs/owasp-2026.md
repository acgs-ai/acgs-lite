# OWASP Top 10 for Agentic Applications (2026): Mitigation with ACGS-Lite

**Meta Description**: Learn how to mitigate the 2026 OWASP Top 10 risks for agentic AI using ACGS-Lite's constitutional governance, MACI role separation, and tamper-evident audit logs.

---

In 2026, securing AI is no longer about simple prompt filtering. As agents gain autonomy and access to powerful tools, the risk landscape has shifted toward **Goal Hijacking**, **Tool Misuse**, and **Cascading Failures**. 

The **OWASP Top 10 for Agentic Applications** defines the critical security risks of the modern agentic stack. ACGS-Lite is designed to mitigate these risks at the protocol level.

## Risk Mitigation Matrix

| OWASP ID | Risk | ACGS-Lite Mitigation Strategy |
| :--- | :--- | :--- |
| **ASI01** | **Agent Goal Hijack** | **Governed execution boundary**: Validates a proposed action against the Constitution *before* any tool is called. |
| **ASI02** | **Tool Misuse** | **Deterministic Rule Engine**: Blocks specific high-risk tool patterns (e.g., `DROP TABLE`) regardless of agent intent. |
| **ASI03** | **Privilege Abuse** | **MACI Role Separation**: Structural separation of Proposer (Agent) and Validator (Governance) prevents self-escalation. |
| **ASI04** | **Supply Chain** | **Constitutional Hashing**: Ensures the safety rules haven't been tampered with in the deployment pipeline. |
| **ASI05** | **Unsafe Code Execution** | **Fail-Closed Design**: The `@fail_closed` decorator ensures any governance failure defaults to blocking the execution. |
| **ASI06** | **Context Poisoning** | **Runtime Sanitization**: Every input and output is re-validated, preventing "poisoned" memory from triggering actions. |
| **ASI07** | **Insecure Inter-Agent Comm.** | **MCP Governance Server**: Provides a centralized, authenticated governance endpoint for all agents in a mesh. |
| **ASI08** | **Cascading Failures** | **Governance Circuit Breaker**: Automatically halts an agent if it exceeds a violation threshold, preventing a "domino effect." |
| **ASI09** | **Human-Agent Trust** | **Audit Trail Integrity**: Provides mathematical proof of agent decisions, allowing humans to verify reasoning. |
| **ASI10** | **Rogue Agents** | **Article 14 Kill-Switch**: A deterministic, non-AI hard stop built into the `GovernedAgent` wrapper. |

---

## Deep Dive: Critical Mitigations

### 1. Goal Hijacking (ASI01)
Attackers use indirect prompt injection (e.g., in a retrieved document) to redirect an agent's mission.
*   **ACGS Solution**: By wrapping your agent in `GovernedAgent`, every proposed action is intercepted. The `GovernanceEngine` doesn't care *why* the agent wants to perform an action; it only cares if the action violates the Constitution.

### 2. Tool Misuse & Exploitation (ASI02)
An agent uses a legitimate file-reader to exfiltrate `/etc/passwd`.
*   **ACGS Solution**: Use the `Rule` engine to define "Forbidden Patterns" for specific tools.
    ```python
    Rule(id="no-system-files", pattern="/etc/|/var/|/proc/", severity=Severity.CRITICAL)
    ```

### 3. Identity & Privilege Abuse (ASI03)
Agents inheriting high-privilege credentials and acting without oversight.
*   **ACGS Solution**: **MACI (Monitor-Approve-Control-Inspect)** ensures that the agent (Proposer) never has the authority to approve its own high-risk actions. High-risk actions must be signed off by a `VALIDATOR` role.

### 4. Cascading Failures (ASI08)
A single error in an automated workflow triggers a chain reaction of destructive API calls.
*   **ACGS Solution**: The `GovernanceCircuitBreaker` monitors the violation rate. If an agent starts hitting safety rules repeatedly (indicating it's "lost the plot" or is under attack), the circuit breaker trips and blocks all further actions until a human reviews the logs.

---

## Next Steps
- Review the [MACI Architecture](maci.md) to understand role-based safety.
- See [2026 Regulatory Compliance](compliance-2026.md) for EU AI Act and regional law mappings.
- Implement a [Governance Circuit Breaker](architecture.md#governance-circuit-breaker) in your production agent.
