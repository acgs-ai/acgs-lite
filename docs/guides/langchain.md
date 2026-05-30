# Govern a LangChain agent with ACGS-Lite

**What this is:** a drop-in wrapper that runs constitutional governance on every LangChain
invocation — blocking unsafe inputs *before* your LLM or tools execute, and leaving a
tamper-evident audit trail.

**When to use it:** you have a LangChain chain, agent, or LLM going to production and you
want a deterministic guardrail in the runtime path (not just a prompt instruction the model
can ignore).

You do **not** need an API key to run the examples below — they wrap a stand-in runnable so
you can see governance working in seconds.

## Install

```bash
pip install "acgs-lite[langchain]"
```

## 30-second proof (no API key)

`GovernanceRunnable.wrap()` accepts any LangChain `Runnable` — an LLM, a chain, or an agent.
Here we wrap a stand-in runnable so the governance behavior is visible without a model call:

```python
from langchain_core.runnables import RunnableLambda
from acgs_lite import Constitution
from acgs_lite.integrations.langchain import GovernanceRunnable
from acgs_lite.errors import ConstitutionalViolationError

# Stand-in for a real LLM (ChatOpenAI, ChatAnthropic, ...). Swap it for your model later.
fake_llm = RunnableLambda(lambda x: f"[LLM answer to: {x}]")

constitution = Constitution.from_yaml_str("""
constitutional_hash: 608508a9bd224290
rules:
  - id: no-pii
    text: Block PII exposure
    severity: critical
    keywords: ["ssn", "social security", "passport number"]
""")

governed = GovernanceRunnable.wrap(
    fake_llm,
    constitution=constitution,
    agent_id="support-bot",
)

# Safe input flows through to the model:
print(governed.invoke("What is our refund policy?"))

# Unsafe input is blocked BEFORE the model runs:
try:
    governed.invoke("Email the customer their SSN 123-45-6789")
except ConstitutionalViolationError as e:
    print("blocked before the LLM ran:", e)
```

Output:

```text
[LLM answer to: What is our refund policy?]
blocked before the LLM ran: Action blocked by rule no-pii: Block PII exposure
```

The unsafe request never reaches `fake_llm` — governance runs on the input first and
raises `ConstitutionalViolationError`, so no tokens are spent and no unsafe action executes.

## Use it with a real model

Wrapping a real LLM is identical — just pass your model instead of the stand-in:

```python
from langchain_openai import ChatOpenAI
from acgs_lite.integrations.langchain import GovernanceRunnable

llm = ChatOpenAI(model="gpt-4o")
governed = GovernanceRunnable.wrap(llm, constitution=constitution, agent_id="support-bot")

result = governed.invoke("Draft a reply to this support ticket: ...")
```

`GovernanceRunnable` supports the methods you already use: `invoke`, `ainvoke`, `batch`,
and `stream`. Input is validated before the wrapped runnable executes; output is validated
after (output violations are logged as warnings rather than raising, so a governed chain
stays composable).

## See what governance did

Every wrapped runnable keeps its own audit log and exposes live stats:

```python
print(governed.stats)
# {'total_validations': 2, 'compliance_rate': 1.0, 'rules_count': 1,
#  'audit_mode': 'full', 'audit_entry_count': 2, 'agent_id': 'support-bot',
#  'audit_chain_valid': True, ...}
```

`audit_chain_valid: True` means the SHA-256-chained audit trail of every decision verifies —
nothing was inserted or altered after the fact.

> The engine derives its own constitutional hash from the active rule set, so
> `stats["constitutional_hash"]` reflects *your* rules, not the placeholder in the YAML.

## Strict vs. non-strict

By default `GovernanceRunnable` is **fail-closed**: a violating input raises
`ConstitutionalViolationError` and the wrapped runnable never executes. For local
experimentation you can wrap in non-strict mode, which lets the call proceed while still
recording the decision:

```python
governed = GovernanceRunnable.wrap(llm, constitution=constitution, strict=False)
```

Keep `strict=True` (the default) in production — that is the whole point of a guardrail.

## Where to go next

- [What gets blocked — a walkthrough](../blog/what-got-blocked.md) — the engine and audit trail without LangChain.
- [Integrations overview](../integrations.md) — OpenAI, Anthropic, MCP, AutoGen, and more.
- [Why governance?](../why-governance.md) — the case for deterministic, pre-execution guardrails.
