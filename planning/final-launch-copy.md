# Final Launch Copy for `acgs-lite`

Date: 2026-04-10

Use this as the posting-ready copy set for the first concentrated launch window. Keep the copy concrete, technical, and demo-led.

## Positioning anchor

`acgs-lite` is the governance layer between your LLM agent and production.
It blocks unsafe actions before execution, enforces MACI separation of powers, and leaves tamper-evident audit trails.

The first proof is the blocked-action demo, not the philosophy.

---

## Hacker News

### Title

**Show HN: acgs-lite, block unsafe LLM agent actions before they execute**

### Body

We just open-sourced `acgs-lite`, a Python package for governing agent actions before they execute.

The core idea is simple:
- define rules in YAML
- validate actions before execution
- block violations instead of just logging them
- separate proposer / validator / executor roles with MACI
- keep tamper-evident audit logs

The fastest proof path in the repo is:
- run `python examples/basic_governance/main.py`
- watch a safe request pass and unsafe requests get blocked
- inspect the audit trail example
- try the MCP path if you want shared governance infrastructure

Repo: https://github.com/dislovelhl/acgs-lite
PyPI: https://pypi.org/project/acgs-lite/

I’d especially love feedback on:
- whether blocked-before-execution is the right wedge
- whether the MCP/shared-governance path is compelling
- which integration would make this most useful in real agent stacks

---

## Reddit

## Primary target: r/OpenSourceAI

### Title

**Open-sourced a Python governance layer for AI agents that blocks unsafe actions before execution**

### Body

Built this because a lot of agent safety tooling still feels advisory instead of enforceable.

`acgs-lite` sits in the runtime path and lets you:
- define governance rules in YAML
- allow or block actions before they run
- enforce proposer / validator / executor separation with MACI
- keep tamper-evident audit logs

There’s a simple no-key proof path in the repo:
- `python examples/basic_governance/main.py`
- see a safe request pass and unsafe requests get blocked
- then inspect the audit trail and MCP examples

Repo: https://github.com/dislovelhl/acgs-lite
PyPI: https://pypi.org/project/acgs-lite/

If you build agent infrastructure, I’d love blunt feedback on:
- whether this solves a real runtime problem
- whether the current demo proves the right thing
- which integration should come next

---

## Secondary target: r/mcp

### Title

**Open-source governance layer for MCP-connected AI agents**

### Body

I’ve been working on `acgs-lite`, a Python governance layer that can sit between an agent and execution.

The wedge is not better prompting. It is deterministic runtime governance:
- validate actions before execution
- block policy violations in the runtime path
- enforce MACI-style separation of powers
- keep tamper-evident audit evidence

The repo includes a basic blocked-action demo plus an MCP path for shared governance infrastructure.

Repo: https://github.com/dislovelhl/acgs-lite
PyPI: https://pypi.org/project/acgs-lite/

Curious whether people here find the MCP/shared-governance angle useful, or whether this should stay framed more broadly as agent runtime policy enforcement.

---

## Short X post

Open-sourced `acgs-lite`.

It’s a Python governance layer for AI agents:
- block unsafe actions before execution
- enforce MACI separation of powers
- keep tamper-evident audit trails

Runnable demos, no-key proof path, MCP support.

GitHub: https://github.com/dislovelhl/acgs-lite
PyPI: https://pypi.org/project/acgs-lite/

---

## Comment-reply anchor

If people ask how this differs from guardrails tools: the shortest answer is that `acgs-lite` is aimed at deterministic pre-execution governance in the runtime path, with separation of powers and audit evidence, not just prompt/output filtering.
