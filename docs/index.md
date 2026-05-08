# ACGS -- Fail-Closed Legitimacy for Agent Action

ACGS converts a declared goal and proposed method into a governed decision before side effects run. Receipt-enforced execution paths can also bind that decision to a replayable receipt and executor boundary.

ACGS is a fail-closed legitimacy layer for AI-agent action. It resolves authority, constraints, policy version, and execution boundary before execution. If that proof is missing, ambiguous, unknown, or unverifiable, ACGS blocks execution.

ACGS makes agent action decisions explicit, authorized, constrained, transformable, deniable, bounded, and replayable before execution.

The standard `GovernedAgent` path provides deterministic input/output validation and audit logging. For receipt-enforced execution paths, ACGS can require:

1. A canonical decision from the approved taxonomy
2. A replayable receipt issued before execution
3. An execution boundary the executor must match
4. Fail-closed behavior on missing or unverifiable receipt proof

## 5-Line Quickstart

```python
from acgs_lite import Constitution, GovernedAgent

# 1. Load rules from your Constitution
constitution = Constitution.from_yaml("rules.yaml")

# 2. Wrap your existing agent
agent = GovernedAgent(my_llm_agent, constitution=constitution)

# 3. Execute through deterministic validation
result = agent.run("Process this request")
```

## Compliance Mapping Examples

ACGS can map governance constraints to global regulatory frameworks to support audits and risk assessments.

| Framework | Business Risk | Mapped Controls |
|---|---|---|
| **EU AI Act** | 7% global revenue penalty | 5/9 |
| **NIST AI RMF** | US Federal procurement gate | 7/16 |
| **ISO/IEC 42001** | International audit failure | 9/18 |
| **SOC 2 + AI** | Enterprise gate / lost contracts | 10/16 |
| **HIPAA + AI** | $1.5M fine per violation | 9/15 |
| **GDPR Art. 22** | 4% global revenue | 10/12 |
| **ECOA/FCRA** | Unlimited damages | 6/12 |
| **NYC LL 144** | $1,500/day | 6/12 |
| **OECD AI** | Baseline standard | 10/15 |

**Run `acgs assess` to see coverage for your jurisdiction and domain.**

## Next Steps & Guides

Explore the architecture and setup guides to integrate ACGS into your agentic workflows:

- [Why Constitutional Governance?](why-governance.md) -- Understand fail-closed legitimacy boundaries for agent action
- [Industry Use Cases](use-cases.md) -- Healthcare, Finance, and Legal in practice
- [OWASP 2026 Mitigation](owasp-2026.md) -- Mitigating the Top 10 risks for agents
- [2026 Regulatory Compliance](compliance-2026.md) -- EU AI Act, SB 205, and TRAIGA
- [MCP Governance Server](mcp.md) -- Shared governance for side-effectful tool calls
- [Advanced Governance Patterns](supervisor-models.md) -- Verification Kernels & Supervisor Models
- [MCP Governance Guide](mcp-guide.md) -- Master the Model Context Protocol
- [Testing Governance](testing-governance.md) -- Verifying fail-closed governance behavior
- [Quickstart](quickstart.md) -- Install and govern your first agent
- [Integrations](integrations.md) -- Guides for Anthropic, OpenAI, LangChain, AutoGen, CrewAI, and more
- [Telegram Webhook Integration](telegram-webhook.md) -- Safe Telegram bot intake with path-secret + header-token verification
- [Compliance](compliance.md) -- Deep dive into multi-framework assessment
- [MACI Architecture](maci.md) -- Implementing separation of powers for AI
- [Architecture Overview](architecture.md) -- Internal engine and validation lifecycle
- [CLI Reference](cli.md) -- All CLI commands for CI/CD and terminal use
- [Constitution Lifecycle API](api/lifecycle.md) -- HTTP endpoints for draft, review, eval, activation, and rollback

---
!!! info "Constitutional Hash"
    `608508a9bd224290` -- documented constitutional hash for this release line. `acgs verify` currently validates license key integrity only.
