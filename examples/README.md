# ACGS-Lite Examples

Runnable quickstarts covering the core runtime-governance and MACI patterns in `acgs-lite`.
**No API keys are required** for the canonical demo path.

## Canonical demo path

If you only try four things, do them in this order:

### 1. Check a side effect before execution

`pip install` does **not** ship this directory. After install, copy
[docs/guides/five-minute-membrane.md](../docs/guides/five-minute-membrane.md).
From a clone:

```bash
python examples/membrane_5min.py
```

Richer walkthrough: [`governed_execution_membrane.py`](./governed_execution_membrane.py).

This is the Goal v1.0 path: LLM reasoning -> constitutional check -> decision
receipt -> governed execution. The executor refuses to run without a valid
receipt (`No legitimacy receipt, no execution`).

### 2. Block an unsafe action
Run [`basic_governance/`](./basic_governance/) first.

```bash
python examples/basic_governance/main.py
```

This is the fastest proof that `acgs-lite` is real: safe requests pass, harmful requests are blocked, and PII-like input is denied.

### 3. Inspect the audit evidence
Run [`audit_trail/`](./audit_trail/).

```bash
python examples/audit_trail/main.py
```

This shows that governance decisions are not just transient checks, they become tamper-evident evidence.

### 4. Run governance as infrastructure
Run [`mcp_agent_client.py`](./mcp_agent_client.py).

```bash
pip install "acgs-lite[mcp]"
python examples/mcp_agent_client.py
```

This is the shared-service story: agent actions can be validated against a governance server before execution.

## Quickstart

```bash
# Clone required — PyPI does not ship examples/
python examples/membrane_5min.py
python examples/basic_governance/main.py

# Optional: MCP example
pip install "acgs-lite[mcp]"
python examples/mcp_agent_client.py
```

## Examples by goal

| Example | What it teaches | Difficulty |
|---------|----------------|------------|
| [`membrane_5min.py`](membrane_5min.py) | Pip-only 5-minute membrane: ALLOW / TRANSFORM / DENY / missing-receipt refusal | ⭐ Beginner |
| [`governed_execution_membrane.py`](governed_execution_membrane.py) | Goal v1.0 side-effect membrane: ALLOW / DENY / TRANSFORM, receipts, executor refusal, audit evidence | ⭐ Beginner |
| [`agent_quickstart/`](agent_quickstart/) | **AI-agent install verify**: `GovernedCallable` + MACI + AuditLog in one script; exits 0 on success | ⭐ Beginner |
| [`mcp_agent_client.py`](mcp_agent_client.py) | **MCP Governance Hub**: Connect an agent to a centralized safety server | ⭐⭐ Intermediate |
| [`basic_governance/`](basic_governance/) | Wrap any callable with a `Constitution` + `Rule` objects | ⭐ Beginner |
| [`compliance_eu_ai_act/`](compliance_eu_ai_act/) | EU AI Act risk-tier inference and article-level gap assessment | ⭐⭐ Intermediate |
| [`eu_ai_act_runtime/`](eu_ai_act_runtime/) | **EU AI Act runtime enforcement**: signed Art 12 receipts + tamper detection, Art 14 fail-closed human oversight, Art 15 injection → incident | ⭐⭐ Intermediate |
| [`maci_separation/`](maci_separation/) | Proposer → Validator → Executor role gates; Golden Rule enforcement | ⭐⭐ Intermediate |
| [`audit_trail/`](audit_trail/) | Tamper-evident audit chain; query + JSON export | ⭐⭐ Intermediate |
| [`mock_stub_testing/`](mock_stub_testing/) | `typing.Protocol` + `InMemory*` stub pattern for production-grade testing | ⭐⭐⭐ Advanced |
| [`lean_runtime/`](lean_runtime/) | Lean runtime wrapper + `acgs lean-smoke` setup for real Lean/Lake projects | ⭐⭐ Intermediate |

## Integration Demos

| File | Description |
|------|-------------|
| [`quickstart.py`](quickstart.py) | 5-minute core API walkthrough |
| [`eu_ai_act_quickstart.py`](eu_ai_act_quickstart.py) | EU AI Act regulatory tool demo |
| [`gitlab_mr_governance.py`](gitlab_mr_governance.py) | GitLab MR governance CI/CD integration |
| [`quickstart_healthcare.py`](quickstart_healthcare.py) | Healthcare-specific rules and PII protection |

## Learning path

```text
governed_execution_membrane  →  basic_governance  →  audit_trail  →  mcp_agent_client
                              ↓
                      maci_separation   →  compliance_eu_ai_act  →  mock_stub_testing
```

For production deployments, see [`CONTRIBUTING.md`](../CONTRIBUTING.md), the
`InMemory*` stub pattern in [`mock_stub_testing/`](mock_stub_testing/), and the
Lean toolchain wrapper example in [`lean_runtime/`](lean_runtime/).
To learn more about the 2026 safety standards, see [`docs/owasp-2026.md`](../docs/owasp-2026.md).
