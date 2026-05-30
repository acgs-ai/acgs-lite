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

---

# Stage 1 community seeds (Ignition)

Added 2026-05-30. These are **content-first** seeds for the three highest-density venues from
the community roadmap. Lead with the "what gets blocked" walkthrough
(`docs/blog/what-got-blocked.md`) — show the demo, don't pitch. Engage in replies; don't
drive-by post.

**Canonical artifacts to link:**
- Walkthrough: `docs/blog/what-got-blocked.md` (publish as a gist/blog or link the repo file)
- LangChain guide: `docs/guides/langchain.md`
- Repo: https://github.com/dislovelhl/acgs-lite · PyPI: https://pypi.org/project/acgs-lite/

## OWASP GenAI Security Project — Slack `#project-top10-for-llm`

> Built a small open-source thing for the runtime-enforcement side of the LLM Top 10
> (LLM02 insecure output, LLM06 excessive agency): `acgs-lite` blocks an unsafe agent action
> *before* it executes and writes a SHA-256-chained audit trail of every decision. 60-second,
> no-API-key walkthrough of what gets blocked + the audit receipt: <link>. Would love feedback
> from anyone doing agent runtime protection — especially on the MACI separation-of-powers model.

## MLSecOps Community (community.mlsecops.com / podcast)

> Sharing a runtime guardrail for agentic pipelines in case it's useful: `acgs-lite` denies
> unsafe agent actions pre-execution (not prompt-only advice) and keeps tamper-evident audit
> evidence mapped to EU AI Act / NIST AI RMF. Here's a short "what got blocked" demo with the
> audit trail: <link>. Happy to do a deeper writeup or walkthrough if there's interest.

## AI Alignment Forum / LessWrong

> A practical take on constitutional enforcement: instead of training a model to follow a
> constitution, `acgs-lite` enforces one deterministically in the execution path — proposer ≠
> approver (MACI), fail-closed, replayable audit trail. It's narrow and boring on purpose.
> Walkthrough + reasoning about why pre-execution enforcement complements (not replaces)
> alignment-time approaches: <link>. Curious where people think deterministic gates help vs.
> where they give false assurance.

## Reddit (r/LocalLLaMA, r/MachineLearning "[P]", r/ControlProblem)

> **Title:** I built an open-source layer that blocks unsafe AI-agent actions *before* they run (Python, no API key to try)
>
> **Body:** Prompt-only guardrails advise; this decides. `acgs-lite` validates an agent's
> proposed action against a constitution, blocks it pre-execution if it violates, and records a
> tamper-evident audit trail. 60-second walkthrough of what gets blocked: <link>. Apache-2.0,
> `pip install acgs-lite`. Feedback welcome — particularly on rule ergonomics and the MACI model.

## Hacker News (Show HN)

> **Title:** Show HN: ACGS-Lite – block unsafe AI-agent actions before they execute (Python)
>
> **Body:** It's a fail-closed governance layer for LLM agents: declared action → allow/block
> decision → replayable audit receipt, all before execution. MACI separation of powers
> (proposer ≠ validator ≠ executor) and a SHA-256-chained audit trail. No-API-key demo: <link>.
> Apache-2.0. I'd love feedback on where deterministic pre-execution gates are the right tool
> vs. where they create false confidence.

## X / LinkedIn (short)

> Most "AI guardrails" advise. acgs-lite *decides* — it blocks an unsafe agent action before it
> runs and leaves a tamper-evident audit trail. 60-sec, no-API-key demo of what gets blocked 👇
> <link>  #AIsafety #LLM #AIgovernance
