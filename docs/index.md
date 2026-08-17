# ACGS -- Fail-Closed Legitimacy for Agent Action

ACGS converts a declared goal and proposed method into a governed decision before side effects run. Receipt-enforced execution paths can also bind that decision to a replayable receipt and executor boundary.

ACGS is a fail-closed legitimacy layer for AI-agent action. It resolves authority, constraints, policy version, and execution boundary before execution. If that proof is missing, ambiguous, unknown, or unverifiable, ACGS blocks execution.

In receipt-enforced paths, ACGS leads with three concrete checks: a canonical
decision, a receipt issued before execution, and a bounded executor.

The standard `GovernedAgent` path provides deterministic input/output validation and audit logging. For receipt-enforced execution paths, ACGS can require:

1. A canonical decision from the approved taxonomy
2. A replayable receipt issued before execution
3. An execution boundary the executor must match
4. Fail-closed behavior on missing or unverifiable receipt proof

## Quickstart

`pip install` does not ship `examples/`. Start with the
[5-minute membrane](guides/five-minute-membrane.md) (receipt + executor
refusal), or wrap an existing callable:

```python
from acgs_lite import Constitution, GovernedAgent, MACIRole

# 1. Load rules from your Constitution
constitution = Constitution.from_yaml("rules.yaml")

# 2. Wrap your existing agent with an explicit MACI execution role
agent = GovernedAgent(
    my_llm_agent,
    constitution=constitution,
    maci_role=MACIRole.EXECUTOR,
)

# 3. Execute through deterministic validation with per-call authorization
result = agent.run("Process this request", governance_action="execute")
```

## Compliance Mapping Examples

ACGS can map governance constraints to global regulatory frameworks to support
audits and risk assessments. The ratios below are SELF-ASSESSED mapping
coverage only; they are not certification, regulatory approval, adoption proof,
or a substitute for legal review.

| Framework | Mapping Coverage | Review Context |
|---|---|---|
| **EU AI Act** | SELF-ASSESSED mapping coverage: 5/9 | Risk classification, transparency, human oversight, and documentation mapping |
| **NIST AI RMF** | SELF-ASSESSED mapping coverage: 7/16 | Governance, mapping, measurement, and management functions |
| **ISO/IEC 42001** | SELF-ASSESSED mapping coverage: 9/18 | AI management-system controls and audit-preparation evidence |
| **SOC 2 + AI** | SELF-ASSESSED mapping coverage: 10/16 | Security, availability, processing integrity, confidentiality, and privacy mappings |
| **HIPAA + AI** | SELF-ASSESSED mapping coverage: 9/15 | Privacy, security, breach-notification, and PHI-handling safeguards; penalty exposure is tiered and inflation-adjusted, so verify current HHS/OCR amounts with legal review |
| **GDPR Art. 22** | SELF-ASSESSED mapping coverage: 10/12 | Automated decision-making, explanation, and data-protection mapping |
| **ECOA/FCRA** | SELF-ASSESSED mapping coverage: 6/12 | Fair-lending, adverse-action, and model-documentation mapping |
| **NYC LL 144** | SELF-ASSESSED mapping coverage: 6/12 | Bias-audit, candidate-notice, and public-reporting mapping |
| **OECD AI** | SELF-ASSESSED mapping coverage: 10/15 | Transparency, accountability, robustness, and human-oversight mapping |

**Run `acgs assess` to see self-assessed mapping coverage for your jurisdiction and domain.**

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
- [5-minute membrane](guides/five-minute-membrane.md) -- pip-only ALLOW / DENY / TRANSFORM + receipt refusal
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
