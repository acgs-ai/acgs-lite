# Agent Quickstart

A self-verifying ACGS-Lite demo designed for AI coding agents.

Run this single script to confirm ACGS-Lite is correctly installed and
all three core capabilities work end-to-end.

```bash
# Clone required — PyPI does not ship examples/
pip install -e .
python examples/agent_quickstart/run.py
```

For a pip-only membrane (no clone), use
[docs/guides/five-minute-membrane.md](../../docs/guides/five-minute-membrane.md).

Exit code `0` = all assertions passed.
Exit code `1` = one or more assertions failed — investigate the output.

## What is verified

| Section | What it proves |
|---------|---------------|
| **1. Governed Callable** | Safe requests pass; PII and destructive operations are blocked |
| **1b. YAML constitution** | `constitution.yaml` loads correctly; rules enforced from file |
| **2. MACI Role Separation** | Proposer / Validator / Executor roles enforced; Golden Rule held |
| **3. Audit Trail** | Decisions recorded; chain integrity verified |

## Expected output

```
============================================================
  ACGS-Lite Agent Quickstart — Verification Suite
============================================================

============================================================
  Section 1: Governed Callable
============================================================

── 1a. Inline constitution ───────────────────────────────────
  ✅  safe request passes through
  ✅  Allowed:  Response to: What is the capital of France?
  🚫  Blocked:  no-pii — ...
  ✅  PII blocked by rule 'no-pii'
  🚫  Blocked:  no-destructive — ...
  ✅  destructive op blocked by 'no-destructive'

── 1b. YAML constitution (production pattern) ────────────────
  ✅  YAML loads 3 rules
  ✅  safe request passes via YAML constitution
  ✅  YAML load OK — rules: 3
  🚫  YAML block: no-pii — still enforced from file
  ✅  YAML PII rule enforced

============================================================
  Section 2: MACI Role Separation
============================================================
  ✅  Proposer can propose
  🚫  Blocked: Proposer CANNOT self-validate
  ...

── Golden Rule: no self-validation ──────────────────────────
  ✅  Golden Rule: proposer cannot validate own output

============================================================
  Section 3: Audit Trail
============================================================
  ✅  Audit log: 3 entries recorded
  ✅  Chain integrity: verified
  ✅  Violations in log: ['ev-002']
  ✅  verify_chain(tampered) returns bool: ...

============================================================
  ✅  All assertions passed — ACGS-Lite is correctly installed.
  Exit code: 0
```

## What this proves

- A `GovernedCallable` allows a safe prompt and blocks PII / destructive
  keywords before the wrapped function returns.
- A YAML constitution loads and still enforces those rules.
- MACI refuses a proposer validating its own output.
- An in-memory `AuditLog` records decisions and `verify_chain()` passes.

## What this does not claim

- Not a production install check for a pip-only user. This script lives in
  `examples/` and is not on PyPI.
- In-memory audit only. Not a durable or independently hosted store.
- Keyword/regex rules, not semantic policy.
- Not certification, not independent production use.

## Agent prompt (copy-paste into Claude Code or Codex CLI)

```
TASK: Verify ACGS-Lite from a source checkout.

1. Clone https://github.com/acgs-ai/acgs-lite
2. pip install -e .
3. python examples/agent_quickstart/run.py

Expected: all ✅ lines, exit code 0.
If any ❌ appears, report the failing assertion text.
Do NOT set strict=False to fix failures — investigate root cause.
For a pip-only proof without cloning, follow docs/guides/five-minute-membrane.md.
```

## No API keys required

This example runs fully offline. No `OPENAI_API_KEY` or other credentials needed.
