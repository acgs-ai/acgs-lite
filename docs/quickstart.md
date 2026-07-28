# Quickstart

Get ACGS running in a few minutes with the same API surface exercised by
[`examples/quickstart.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/quickstart.py).

## 1. Install

Install the core package:

```bash
pip install acgs-lite
```

Install an extra only when you need a specific integration:

```bash
pip install "acgs-lite[anthropic]"  # Claude integration
pip install "acgs-lite[mcp]"        # MCP governance server
pip install "acgs-lite[otel]"       # OpenTelemetry export
```

## 2. Add a Constitution

Create `constitution.yaml`:

```yaml
# constitutional_hash: "608508a9bd224290"  # pin this in production
rules:
  - id: no-pii
    text: "Block PII leakage"
    patterns:
      - "\\bSSN\\b|\\bsocial security\\b|\\bpassport number\\b"
    severity: CRITICAL

  - id: no-destructive
    text: "Block destructive operations"
    patterns:
      - "\\bdelete\\b|\\bdrop\\s+table\\b|\\brm\\s+-[rRfF]\\b"
    severity: HIGH

  - id: require-approval
    text: "Financial actions require human approval"
    patterns:
      - "\\bwire\\s+transfer\\b|\\b(send|initiate)\\s+payment\\b"
    severity: HIGH
```

> **Schema notes:** Each rule requires `id`, `text`, and `patterns` (a list of regex strings).
> The `constitutional_hash` is optional but recommended for production — pin it to
> `"608508a9bd224290"` to detect any constitution drift at runtime.

## 3. Govern a Callable

```python
from acgs_lite import Constitution, GovernedAgent, MACIRole


def my_agent(prompt: str) -> str:
    return f"Processed: {prompt}"


constitution = Constitution.from_yaml("constitution.yaml")
agent = GovernedAgent(
    my_agent,
    constitution=constitution,
    agent_id="demo-agent",
    maci_role=MACIRole.EXECUTOR,
)

result = agent.run("Summarize the quarterly report", governance_action="execute")
print(result)
```

## 4. See Blocking Behavior

```python
from acgs_lite import ConstitutionalViolationError

try:
    agent.run("My social security number is 123-45-6789", governance_action="execute")
except ConstitutionalViolationError as exc:
    print(f"Blocked: {exc}")
```

## 5. Run the Examples

For a self-verifying install check that covers `GovernedCallable`, MACI role gates,
and tamper-evident audit in one script:

```bash
python examples/agent_quickstart/run.py
```

Expected: all assertions pass, exits 0. This is the recommended starting point for
AI coding agents (Codex, Claude Code, etc.) verifying a fresh install.

For a broader walkthrough covering default constitutions, custom rules, MACI
enforcement, audit stats, and the decorator API:

```bash
python examples/quickstart.py
```

## 6. CLI Bootstrap

Scaffold a starter `rules.yaml` and CI governance job:

```bash
acgs init
```

Check your environment and license state:

```bash
acgs status
```

## 7. MCP Server

If you installed the `mcp` extra, run the governance server over stdio:

```bash
python -m acgs_lite.integrations.mcp_server --constitution constitution.yaml
```

## Next Steps

- Read the [MCP Governance Guide](mcp-guide.md).
- Review [MACI Architecture](maci.md).
- Run an [EU AI Act assessment](compliance-2026.md).
- Explore more runnable examples in
  [`examples/README.md`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/README.md).
