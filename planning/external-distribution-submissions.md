# External Distribution Submissions for `acgs-lite`

Date: 2026-04-10

Use this file as the reusable source for curated-list submissions, launch posts, and comparison contexts.

## One-line description

`acgs-lite` is an open-source Python governance layer for AI agents that blocks unsafe actions before execution, enforces MACI separation of powers, and keeps tamper-evident audit trails.

## Short curated-list blurb

`acgs-lite` is a Python governance layer for AI agents that enforces allow/block decisions before execution, supports MACI-style role separation, and keeps tamper-evident audit trails.

## Defensive / guardrail tools blurb

`acgs-lite` is an open-source governance engine for AI agents. It validates actions before execution, blocks violations instead of just logging them, and adds audit evidence plus separation of powers to agent workflows.

## MCP / agent infrastructure blurb

`acgs-lite` can also run as shared governance infrastructure for agent systems, with an MCP path for centralized policy enforcement and auditability.

## How `acgs-lite` differs

Unlike prompt-only guardrails, `acgs-lite` is aimed at deterministic pre-execution governance in the runtime path. The key wedge is:

- block before execution, not just advise
- MACI separation of powers, not single-agent self-approval
- tamper-evident audit evidence, not only transient traces
- Python-first package with runnable no-key demos

## Best category fit by target

- `awesome-llm-security` → **Defensive & Guardrail Tools**
- `awesome-ai-agents-security` → **Agent Firewalls & Gateways (Runtime Protection)**
- agent-security roundups → **agent runtime governance / policy enforcement**
- MCP security roundups → **MCP governance / policy enforcement layer**

## Submission links to use

- Repo: https://github.com/dislovelhl/acgs-lite
- PyPI: https://pypi.org/project/acgs-lite/
- Quick proof path: `examples/basic_governance/`, `examples/audit_trail/`, `examples/mcp_agent_client.py`
