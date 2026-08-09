# MCP Governance Server: Centralized Safety for the Agentic Mesh

**Meta Description**: Use ACGS-Lite as a Model Context Protocol (MCP) server to provide a centralized, deterministic governance layer for all agents in your infrastructure.

---

In 2026, the **Model Context Protocol (MCP)** has become the universal standard for how agents interact with tools, data, and *governance*. 

By running ACGS-Lite as an MCP server, you can provide a "Single Source of Truth" for safety rules across your entire organization. Whether you are using Claude Desktop, VS Code, Cursor, or a custom multi-agent mesh, they can all call the same governance tools so the same safety rules are applied consistently everywhere.

## Why Use an MCP Governance Server?

1.  **Centralized Rules**: Update your `rules.yaml` in one place, and every agent in your "mesh" is immediately governed by the new standards.
2.  **Cross-Client Safety**: The same governance that protects your production backend also protects your developers' IDE agents.
3.  **Language Agnostic**: Any agent that speaks MCP (Python, TypeScript, Go, etc.) can use ACGS-Lite governance.
4.  **Audit Consolidation**: All agents report to the same tamper-evident audit log.

---

## 🛠️ Setting Up the MCP Server

### 1. Installation
Ensure you have the `mcp` extra installed:
```bash
pip install "acgs-lite[mcp]"
```

### 2. Run the Server
You can run the server directly from the CLI. It uses **stdio** as the transport layer by default, making it easy to plug into most agents.

```bash
python -m acgs_lite.integrations.mcp_server --constitution rules.yaml
```

### 3. Register with Your Agent
To use ACGS-Lite with **Claude Desktop**, add it to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "acgs-governance": {
      "command": "python",
      "args": ["-m", "acgs_lite.integrations.mcp_server", "--constitution", "/path/to/rules.yaml"]
    }
  }
}
```

---

## 🧰 Available MCP Tools

Once connected, your agent will have access to the following governance tools:

| Tool | Purpose |
| :--- | :--- |
| `validate_action` | Validates text against the constitution and returns a pass/fail result before execution. |
| `check_compliance` | A fast, non-logging check to see if a text snippet contains any violations. |
| `get_constitution` | Returns the active rules, their severity, and the **Constitutional Hash**. |
| `get_audit_log` | Retrieves recent decisions for real-time monitoring. |
| `governance_stats` | Returns metrics on compliance rates and engine latency. |

---

## 💡 Example: Guarding a Code Agent

Imagine an agent is using a `write_file` tool. Before it executes, it can use the `acgs-governance` server to self-check (or be forced to check by an orchestrator).

**Agent Thought**: *"I want to update the database config. I should check if this is allowed."*

**Agent Tool Call**:
```json
{
  "name": "validate_action",
  "arguments": {
    "action": "Update database password in config.php",
    "agent_id": "coding-agent-alpha"
  }
}
```

**ACGS-Lite Response**:
```json
{
  "compliant": false,
  "violations": [
    {
      "rule_id": "no-secrets-in-code",
      "severity": "CRITICAL",
      "message": "Direct update of passwords in source files is prohibited."
    }
  ]
}
```

---

## Next Steps
- Learn how to [Deploy to Cloud Run](architecture.md#cloud-run) for a scalable governance API.
- See how [MACI Role Separation](maci.md) works over MCP.
- Read about [OWASP 2026 Mitigation](owasp-2026.md) using MCP.
