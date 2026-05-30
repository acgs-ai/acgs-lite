# What gets blocked: a 60-second walkthrough

Most "AI guardrails" advise. ACGS-Lite **decides** — it blocks an unsafe agent action
*before* it executes and writes a tamper-evident record of every decision. Here is exactly
what that looks like, end to end, with no API key required.

## The setup

A constitution is a small set of rules. Each rule has an id, a human-readable `text`, a
severity, and the `keywords` (or regex `patterns`) that trip it:

```python
from acgs_lite import Constitution, GovernanceEngine, AuditLog

constitution = Constitution.from_yaml_str("""
constitutional_hash: 608508a9bd224290
rules:
  - id: no-pii
    text: Block requests that expose personally identifiable information
    severity: critical
    keywords: ["ssn", "social security", "passport number"]
  - id: no-destructive
    text: Block destructive database operations
    severity: high
    keywords: ["drop table", "rm -rf", "delete from"]
""")

log = AuditLog()
engine = GovernanceEngine(constitution, audit_log=log, audit_mode="full")
```

## Three agents try to act

```python
actions = [
    ("Summarize the Q4 revenue report",          "analyst-agent"),
    ("Clean up staging: DROP TABLE users;",       "ops-agent"),
    ("Email the customer their SSN 123-45-6789",  "support-agent"),
]

for action, agent in actions:
    result = engine.validate(action, agent_id=agent, strict=False)
    if result.valid:
        print(f"ALLOWED  [{agent}] {action}")
    else:
        v = result.violations[0]
        print(f"BLOCKED  [{agent}] {action}  -> {v.rule_id} ({v.severity})")
```

Output:

```text
ALLOWED  [analyst-agent] Summarize the Q4 revenue report
BLOCKED  [ops-agent]     Clean up staging: DROP TABLE users;       -> no-destructive (Severity.HIGH)
BLOCKED  [support-agent] Email the customer their SSN 123-45-6789  -> no-pii (Severity.CRITICAL)
```

The harmless summary passes. The destructive SQL and the PII leak are stopped — and because
this runs *before* execution, the `DROP TABLE` never reaches your database and the SSN never
leaves in an email.

> **Fail-closed by default.** Here we used `strict=False` to get a `ValidationResult` we can
> inspect. In production, leave strict mode on (the default): a violation raises
> `ConstitutionalViolationError` and the action is blocked, not silently passed.

## The receipt: a tamper-evident audit trail

Every decision — allowed or blocked — is appended to a SHA-256-chained log:

```python
log.flush()
for e in log.entries:
    verdict = "ALLOW" if e.valid else "BLOCK"
    print(f"#{e.id[:8]}  {verdict}  {e.agent_id:<14}  rules={e.violations or '-'}")

print("decisions recorded:", len(log))
print("chain verified:", log.verify_chain())
```

Output:

```text
#1  ALLOW  analyst-agent   rules=-
#2  BLOCK  ops-agent       rules=['no-destructive']
#3  BLOCK  support-agent   rules=['no-pii']
decisions recorded: 3
chain verified: True
```

`verify_chain()` returning `True` means no entry was inserted, removed, or altered after the
fact. That is the difference between a *log* and *evidence* — exactly what an EU AI Act or
NIST AI RMF auditor asks for.

## Why this matters

- **Block, don't advise.** Prompt-only guardrails ask the model nicely. This denies the action in the runtime path.
- **Separation of powers.** With [MACI](../maci.md), the agent that proposes an action cannot also approve it.
- **Evidence, not vibes.** Every decision is replayable and verifiable.

## Try it in 30 seconds

```bash
pip install acgs-lite
```

Then paste the snippets above — no API key needed. To govern a real agent framework, see the
[LangChain guide](../guides/langchain.md) or the [integrations overview](../integrations.md).

If this is useful, [star the repo](https://github.com/dislovelhl/acgs-lite) — it materially
helps early discovery — and tell us [what *your* agents should never do](https://github.com/dislovelhl/acgs-lite/discussions).
