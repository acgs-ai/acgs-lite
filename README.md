# ACGS-Lite: Constitutional Governance Membrane for Agent Execution

[![PyPI](https://img.shields.io/pypi/v/acgs-lite?color=blue&style=for-the-badge)](https://pypi.org/project/acgs-lite/)
[![Python](https://img.shields.io/pypi/pyversions/acgs-lite?style=for-the-badge)](https://pypi.org/project/acgs-lite/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg?style=for-the-badge)](https://www.apache.org/licenses/LICENSE-2.0)
[![CI](https://img.shields.io/github/actions/workflow/status/dislovelhl/acgs-lite/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/dislovelhl/acgs-lite/actions)
[![Coverage](https://img.shields.io/badge/tests-passing-brightgreen?style=for-the-badge)](https://github.com/dislovelhl/acgs-lite/actions)
[![Documentation](https://img.shields.io/badge/docs-acgs.ai-brightgreen?style=for-the-badge)](https://acgs.ai/docs)
[![GitHub stars](https://img.shields.io/github/stars/dislovelhl/acgs-lite?style=social)](https://github.com/dislovelhl/acgs-lite/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/dislovelhl/acgs-lite?style=social)](https://github.com/dislovelhl/acgs-lite/network/members)
[![Star History](https://img.shields.io/badge/star%20history-chart-yellow?style=social)](https://star-history.com/#dislovelhl/acgs-lite)


**acgs-lite** is a lightweight constitutional governance runtime for agent
execution. It is not an agent framework. Agent frameworks keep responsibility
for reasoning, planning, model calls, memory, and tool selection; `acgs-lite`
sits between that reasoning and real-world side effects.

Core invariant:

> No valid constitutional authorization, no side effect.

The governed execution flow is:

```text
LLM reasoning → constitutional check → decision receipt → governed execution
```

Use `acgs-lite` before executing tools, workflows, API calls, file operations,
transactions, or other side effects. It checks the proposed action against a
versioned constitution, returns an explicit decision, issues a receipt the
executor can verify, and records audit evidence for later inspection.

A tamper-evident audit log proves a record was not *altered*. With the optional
`crypto` extra, `acgs-lite` goes further: every decision receipt can be
**Ed25519-signed and independently replay-verifiable**, so a third party holding
only the signer's public key can prove *who* decided and re-derive the
ALLOW / DENY / TRANSFORM verdict — without trusting the operator. See
[Signed, Replay-Verifiable Receipts](#signed-replay-verifiable-receipts).

Try the membrane locally:

```bash
pip install acgs-lite
python examples/governed_execution_membrane.py
```

The example keeps side effects in memory, but exercises the adoption wedge:
ALLOW executes with a valid receipt, TRANSFORM redacts before execution, DENY is
blocked, receiptless execution is refused, and audit evidence is replay-checked.

Start with [GOAL.md](./GOAL.md) for the Goal v1.0 product boundary and
[ROADMAP.md](./ROADMAP.md) for the implementation milestones.
The stable Runtime Legitimacy Kernel public API is documented in
[`docs/api/legitimacy.md`](./docs/api/legitimacy.md).

Non-goals:

- ACGS does not approve raw goals as executable authority.
- ACGS does not replace human review for decisions that require structured approval.
- ACGS does not own the agent planner, model runtime, memory layer, or tool
  orchestration loop.

For every governed side-effect path, ACGS aims to provide:

```text
1. One explicit decision
2. A replayable receipt emitted before execution
3. An execution boundary the executor must match
4. Fail-closed behavior on missing or unverifiable inputs
```

Decision taxonomy:

```text
ALLOW
ALLOW_WITH_CONTROLS
TRANSFORM_REQUIRED
REPLAN_REQUIRED
STRUCTURED_REVIEW_REQUIRED
DENY_OPERATION_WITH_ALTERNATIVE
DENY_GOAL
HARD_DENY
```

The minimal side-effect membrane example is
[`examples/governed_execution_membrane.py`](./examples/governed_execution_membrane.py).
The Phoenix example under
[`examples/phoenix_acgs_governed_agent/`](./examples/phoenix_acgs_governed_agent/)
shows `request -> decision -> receipt -> bounded execution` telemetry; its
`governance.decision.*` span attributes are experimental.

**Current status:** the currently published package on PyPI is `2.10.1`; the
repository also contains `2.11.0` work-in-progress and a fresh-venv proof path.
PyPI publication remains an owner-gated external action. Production deployment
properties depend on your constitution, storage, authentication, and operational
controls, and the project does not claim independent production users or
compliance certification.

## Security Disclosure

Please report suspected ACGS-Lite governance or security vulnerabilities
privately to `security@acgs.ai` instead of opening a public issue. The canonical
supported-version, scope, and disclosure-window policy is in
[`SECURITY.md`](./SECURITY.md), with a mirrored docs page at
[`docs/security.md`](./docs/security.md).

<img width="1280" height="680" alt="ACGS_Lite" src="https://github.com/user-attachments/assets/0d6deeef-40fe-4e8e-9dc0-537744162dff" />

## Recommended starting points

Start here for the shortest local verification paths:

- **Agent readiness gate** — `python3 scripts/agent_ready.py --run-tests`
  verifies the repo `agent-index.json` loads through `AgentRegistry`, confirms
  the governance-review route ranks first, and runs the focused agent-discovery
  tests without requiring `make`
- **AI-agent install verify** — [`examples/agent_quickstart/`](./examples/agent_quickstart/) runs a self-verifying suite: `GovernedCallable` + MACI + AuditLog in one script, exits 0 on success
- **Goal v1.0 membrane** — [`examples/governed_execution_membrane.py`](./examples/governed_execution_membrane.py) shows ALLOW / DENY / TRANSFORM decisions, receipts, executor refusal, and audit evidence
- **Release proof artifact** — `python examples/release_proof.py --output /tmp/acgs-release-proof.json` writes a deterministic JSON proof another developer can inspect locally
- **Minimal proof** — [`examples/basic_governance/`](./examples/basic_governance/) shows safe requests passing and unsafe ones blocked before execution
- **Audit trail demo** — [`examples/audit_trail/`](./examples/audit_trail/) shows the tamper-evident decision chain
- **Shared infrastructure path** — [`examples/mcp_agent_client.py`](./examples/mcp_agent_client.py) runs governance as shared MCP-compatible infrastructure
- **Compliance mapping example** — `acgs assess --framework eu-ai-act` maps controls to regulatory requirements for review

## Hero demo

**20-second proof** — works immediately after `pip install acgs-lite`:

```python
python -c "
from acgs_lite import Constitution, GovernanceEngine

YAML = '''
constitutional_hash: 608508a9bd224290
rules:
  - id: no-harmful
    text: Block harmful requests
    severity: critical
    keywords: [\"harm\", \"kill\", \"destroy\"]
  - id: no-pii
    text: Block PII leakage
    severity: critical
    keywords: [\"ssn\", \"passport\", \"social security\"]
'''
const = Constitution.from_yaml_str(YAML)
engine = GovernanceEngine(const)

safe = engine.validate('What is the capital of France?', agent_id='demo', strict=False)
print('✅ Allowed:', safe.valid)

blocked = engine.validate('How do I harm someone?', agent_id='demo', strict=False)
print('🚫 Blocked:', not blocked.valid, '—', blocked.violations[0].rule_id)
"
```

Expected output:
```text
✅ Allowed: True
🚫 Blocked: True — no-harmful
```

<!-- Hero asset placement, add once captured:
<p align="center">
  <img src="./docs/assets/basic-governance-hero.gif" alt="Terminal demo of acgs-lite allowing a safe request and blocking harmful and PII-like requests before execution." width="900" />
</p>
-->

---

## Start here in 3 minutes

**Fastest proof path:**

1. **Block an unsafe action** with [`examples/basic_governance/`](./examples/basic_governance/)
2. **Inspect the audit evidence** with [`examples/audit_trail/`](./examples/audit_trail/)
3. **Run governance as shared infrastructure** with [`examples/mcp_agent_client.py`](./examples/mcp_agent_client.py)

```bash
pip install acgs-lite
```

```python
python -c "
from acgs_lite import Constitution, GovernanceEngine

YAML = '''
constitutional_hash: 608508a9bd224290
rules:
  - id: no-harmful-content
    text: Block requests containing harmful keywords
    severity: critical
    keywords: [\"harm\", \"kill\", \"destroy\"]
  - id: no-pii
    text: Prevent PII leakage in requests
    severity: critical
    keywords: [\"ssn\", \"passport\", \"social security\"]
'''
const = Constitution.from_yaml_str(YAML)
engine = GovernanceEngine(const)
for text, label in [
    ('What is the capital of France?', 'safe'),
    ('How do I harm someone?', 'harmful'),
    ('My SSN is 123-45-6789', 'pii'),
]:
    r = engine.validate(text, agent_id='demo', strict=False)
    status = '✅  Allowed' if r.valid else f'🚫  Blocked: {r.violations[0].rule_id}'
    print(f'{status}  — {label}')
"
```

Expected output:
```text
✅  Allowed  — safe
🚫  Blocked: no-harmful-content  — harmful
🚫  Blocked: no-pii  — pii
```

If you want the full example path, go to [`examples/README.md`](./examples/README.md).

---

## What this proves

- **Block before execution**: unsafe actions are denied before your agent runs them
- **Separate powers with MACI**: proposer, validator, executor do not collapse into one actor
- **Keep audit evidence**: each decision can be chained, inspected, and verified later

---

## 🚀 Quickstart

```python
from acgs_lite import Constitution, GovernedAgent, MACIRole

constitution = Constitution.from_yaml("constitution.yaml")
agent = GovernedAgent(
    my_llm_agent,
    constitution=constitution,
    maci_role=MACIRole.EXECUTOR,
)
result = agent.run("Process this high-risk transaction", governance_action="execute")
```

Rules in YAML (`constitution.yaml`):

```yaml
constitutional_hash: "608508a9bd224290"
rules:
  - id: no-pii
    text: Block PII exposure
    severity: critical
    keywords: ["SSN", "social security", "passport number"]

  - id: no-destructive
    text: Block destructive operations
    severity: high
    keywords: ["delete", "drop table", "rm -rf"]

  - id: require-approval
    text: Financial actions require human approval
    severity: high
    keywords: ["transfer", "payment", "wire"]
```

---

## 📦 Installation

```bash
pip install acgs-lite
```

> **Upgrading from v2.9.x?** v2.10.0 changed `require_auth` to default to `True`.
> If you call `create_governance_app()` without an `api_key`, you'll get a `ValueError` at startup.
> Pass `api_key=os.environ["ACGS_API_KEY"]` or set `require_auth=False` for local dev.
> See [CHANGELOG](./CHANGELOG.md) for full details.

With framework integrations:

```bash
pip install "acgs-lite[openai]"       # OpenAI
pip install "acgs-lite[anthropic]"    # Anthropic Claude
pip install "acgs-lite[langchain]"    # LangChain / LangGraph
pip install "acgs-lite[mcp]"          # Model Context Protocol server
pip install "acgs-lite[autogen]"      # AutoGen / AG2
pip install "acgs-lite[a2a]"          # Google A2A protocol
pip install "acgs-lite[agno]"         # Agno agent framework
pip install "acgs-lite[server]"       # FastAPI lifecycle HTTP server
pip install "acgs-lite[all]"          # All integrations
```

---

## 🤖 For AI Agents (Claude Code / Codex CLI)

Copy the prompt below directly into Claude Code, Codex CLI, or any AI coding agent.
It installs acgs-lite, runs the self-verifying quickstart, and reports pass/fail — no API keys required.

For Claude Code `PreToolUse` governance, use the canonical hook at
[`integrations/claude_code/acgs-governance-preuse.sh`](./integrations/claude_code/acgs-governance-preuse.sh)
and the setup guide in [`integrations/claude_code/README.md`](./integrations/claude_code/README.md).
The hook calls a configurable governance sidecar before `Bash`, `Write`, `Edit`,
and `MultiEdit` run; the default `/x402/check` URL is an external sidecar
contract, not a bundled acgs-lite server route.

### One-shot install + verify prompt

```
TASK: Install and verify ACGS-Lite constitutional AI governance.

STEPS:
1. Install the package:
   pip install acgs-lite

2. Run the self-verifying quickstart:
   python examples/agent_quickstart/run.py

3. Expected outcome — every line should show ✅:
   ✅  safe request passes through
   ✅  PII blocked by rule 'no-pii'
   ✅  destructive op blocked by 'no-destructive'
   ✅  YAML loads 3 rules
   ✅  Proposer can propose
   ✅  Golden Rule: proposer cannot validate own output
   ✅  Audit log: 3 entries recorded
   ✅  Chain integrity: verified
   ✅  All assertions passed — ACGS-Lite is correctly installed.
   Exit code: 0

4. If any ❌ appears, report the failing assertion and the full traceback.
   Do NOT set strict=False to work around failures — diagnose root cause.

CONSTRAINTS:
- No OpenAI or Anthropic API key is required for this verification step.
- Constitutional hash 608508a9bd224290 must appear in validation output.
- Run from the repo root (packages/acgs-lite/) if cloned from source.
```

### Implement governance in 5 lines (follow-up prompt)

```
TASK: Add ACGS-Lite governance to this codebase.

STEPS:
1. pip install acgs-lite

2. Create constitution.yaml at the project root:

constitutional_hash: "608508a9bd224290"
rules:
  - id: no-pii
    text: Block PII exposure
    severity: critical
    keywords: ["SSN", "social security", "passport number"]
  - id: no-destructive
    text: Block destructive operations
    severity: high
    keywords: ["delete", "drop table", "rm -rf"]
  - id: require-approval
    text: Financial actions require human approval
    severity: high
    keywords: ["transfer", "payment", "wire"]

3. Wrap the agent/LLM call with GovernedAgent:

from acgs_lite import Constitution, GovernanceEngine, AuditLog
from acgs_lite.governed import GovernedCallable

constitution = Constitution.from_yaml("constitution.yaml")
audit_log    = AuditLog()
engine       = GovernanceEngine(constitution, audit_log=audit_log)

@GovernedCallable(engine=engine, agent_id="my-agent")
def run_agent(prompt: str) -> str:
    return your_llm_call(prompt)   # replace with your LLM call

4. Verify the audit chain after every session:
   assert audit_log.verify_chain()

CONSTRAINTS:
- Engine is fail-closed by default — unsafe actions raise ConstitutionalViolationError.
- Never set strict=False in production.
- Run examples/agent_quickstart/run.py to confirm the installation is healthy.
```

### Source installation (from this repo)

```bash
git clone https://github.com/dislovelhl/acgs-lite
cd acgs-lite/packages/acgs-lite
pip install -e ".[dev]"
python examples/agent_quickstart/run.py   # exit 0 = all clear
```

See [`examples/agent_quickstart/`](./examples/agent_quickstart/) for the full self-verifying suite.

---

## 🛡️ Core Concepts

### Governance Engine

The `GovernanceEngine` sits between your agent and its tools. Every action passes through it before execution. Matching rules block or flag the action; the result is an immutable `ValidationResult`.

```python
from acgs_lite import Constitution, GovernanceEngine, Rule, Severity

constitution = Constitution.from_rules([
    Rule(id="no-pii", text="Block PII exposure", severity=Severity.CRITICAL, keywords=["SSN", "passport"]),
    Rule(id="no-delete", text="Block destructive operations", severity=Severity.HIGH, keywords=["delete", "drop"]),
])

engine = GovernanceEngine(constitution)
result = engine.validate("summarize the quarterly report", agent_id="analyst-01")

if not result.valid:
    for v in result.violations:
        print(f"[{v.severity}] {v.rule_id}: {v.description}")
```

### GovernedAgent — Drop-in Wrapper

```python
from acgs_lite import Constitution, GovernedAgent

@GovernedAgent.decorate(constitution=constitution, agent_id="summarizer")
def summarize(text: str) -> str:
    return my_llm.complete(f"Summarize: {text}")

# Raises ConstitutionalViolationError if text contains violations
result = summarize("Q4 revenue was $4.2M")
```

### MACI — Separation of Powers

MACI prevents a single agent from proposing, validating, and executing the same action:

```python
from acgs_lite import MACIEnforcer, MACIRole

enforcer = MACIEnforcer()

# Assign roles
enforcer.assign(agent_id="planner",   role=MACIRole.PROPOSER)
enforcer.assign(agent_id="reviewer",  role=MACIRole.VALIDATOR)
enforcer.assign(agent_id="executor",  role=MACIRole.EXECUTOR)

# Proposer creates; Validator checks; Executor runs — never the same agent
proposal = enforcer.propose("planner", action="deploy v2.1 to production")
approval = enforcer.validate("reviewer", proposal)
enforcer.execute("executor", approval)
```

### Tamper-Evident Audit Trail

Every governance decision is written to an append-only, SHA-256-chained log:

```python
from acgs_lite import AuditLog

log = AuditLog()
engine = GovernanceEngine(constitution, audit_log=log)

engine.validate("send email to user@example.com", agent_id="mailer")

for entry in log.entries:
    print(entry.id, entry.valid, entry.constitutional_hash)

# Verify chain integrity
assert log.verify_chain(), "Audit log tampered!"
```

### Signed, Replay-Verifiable Receipts

A tamper-evident audit log proves a record was not *altered*. A signed,
replay-verifiable receipt additionally proves *who* decided and that the verdict
*re-derives* — without trusting the operator. `acgs-lite` provides both.

Every `DecisionReceipt` already commits to its full payload through a SHA-256
`receipt_hash`. With the optional `crypto` extra you can bind that commitment to
an Ed25519 signature, so an independent party — holding only the signer's public
key — can verify the receipt's authenticity and re-derive its decision from the
recorded inputs:

```python
# pip install "acgs-lite[crypto]"
from acgs_lite.legitimacy import Ed25519ReceiptSigner, sign_receipt, replay_and_verify

signer = Ed25519ReceiptSigner.generate()       # bring your own key store / KMS
signed = sign_receipt(receipt, signer)         # Ed25519 over the receipt commitment
trusted_pubkey = signer.public_key_hex()       # distributed out-of-band to verifiers

# An auditor, holding only the trusted public key, verifies authenticity...
assert signed.verify(trusted_pubkey)

# ...and re-derives the recorded verdict from the inputs (not just the hash):
result = replay_and_verify(signed, policy_evaluator, expected_public_key=trusted_pubkey)
assert result.ok   # signature valid, hash intact, AND the verdict reproduced
```

Honest boundaries:

- Signing is **optional** (`crypto` extra, Ed25519 via `cryptography`). The core
  membrane and audit log do not require it.
- Verification **requires a trusted public key**. `verify(expected_public_key)`
  is mandatory; `verify_integrity()` only checks self-consistency and is *not*
  authenticity.
- The signing key is held in process memory. For production non-repudiation,
  back `Ed25519ReceiptSigner` with your own KMS/HSM.
- Receipts carry no anti-replay nonce; enforce `request_id` uniqueness at the
  application layer.

See [`docs/api/legitimacy.md`](./docs/api/legitimacy.md) for the full receipt and
replay-verification API.

---

## 🌉 gove-zone kernel bridge (Experimental)

`acgs_lite.gove` lets a `GovernanceEngine` constitution act as a
[gove-zone](https://pypi.org/project/gove-zone/) `Policy`, so an existing
constitution can gate calls through gove-zone's signed `execute_with_receipt`
executor. This bridge is **Experimental**: it is a new adapter seam, not a
replacement for the legitimacy receipt pipeline above, and it has not been
run in production.

Install (Python >= 3.11 only; `gove-zone` is not yet published to PyPI, so
the extra resolves to nothing until then — treat it as workspace/monorepo-only
in the interim):

```bash
pip install "acgs-lite[gove]"
```

Minimal usage — a real constitution evaluating a `gove_zone.tool.ToolCall`:

```python
from acgs_lite import Constitution, GovernanceEngine
from acgs_lite.gove.policy import ConstitutionPolicy
from gove_zone.tool import ToolCall

policy = ConstitutionPolicy(GovernanceEngine(Constitution.default(), strict=False), version="1.0.0")
record = policy.evaluate(ToolCall(name="deploy_feature", args={"env": "staging"}, goal="deploy to staging", actor="agent-1"))
```

`record` is a `gove_zone.decision.DecisionRecord`; hand it to gove-zone's own
`ChainHashAuditStore` / `DecisionReceipt.from_record` / `execute_with_receipt`
to reach a signed, gated execution — see
[`tests/gove/test_conformance_e2e.py`](./tests/gove/test_conformance_e2e.py)
for the full, working chain.

Honest limitations:

- **Legacy `legitimacy` receipts and gove-zone receipts are distinct formats
  with incompatible canonicalizations.** They are not interchangeable and the
  bridge does not convert between them.
- **The bridge does not translate old evidence.** Legitimacy `DecisionReceipt`
  records already on disk are not migrated or replayed into gove-zone's audit
  chain; each governance pipeline keeps its own history.
- **Single-use / expiry enforcement comes from gove-zone's own ledger, not
  from `ExecutionBoundary.single_use`.** The legacy `ExecutionBoundary`
  dataclass's `single_use` field is not read or enforced anywhere in this
  bridge; replay/expiry protection for gove-zone-gated calls is entirely
  gove-zone's responsibility.
- The 8-state acgs-lite decision taxonomy is projected onto gove-zone's 4
  verdicts (`decision_state_to_gove`); the original state is preserved as a
  `reason` prefix, not as a first-class gove-zone field.
- `ConstitutionPolicy` matches on a deterministic text projection of the
  `ToolCall` (`name` + canonical JSON of `args` + `goal`), not on the
  structured arguments directly — constitutions authored for prose actions
  should target tool names and argument keys to match reliably.
- `gove-zone` itself is pre-1.0 (`0.1.0a1`); its API may change before a
  stable release.

---

## 🔒 Safety Defaults

`acgs-lite` is **fail-closed by default**. This is a design principle, not a configuration option.

| Guarantee | Behavior |
|-----------|----------|
| **Engine exception** | Validation raises `ConstitutionalViolationError`; the action is blocked, not silently passed |
| **Missing constitution** | Engine refuses to initialize; no degraded-mode passthrough |
| **Rule match** | Action is blocked unless the rule explicitly sets `workflow_action: warn` |
| **Audit write failure** | Logged at warning level; does not unblock the action |
| **MACI misconfiguration** | Governed execution denies before side effects unless a role and per-call `governance_action` are present |
| **MCP server strict-mode** | MCP tools call `validate(strict=False)` per request and do not mutate `engine.strict`; exceptions cannot leave strict mode permanently disabled |

> **Note:** The MCP integration above is non-mutating: it passes `validate(strict=False)` per call
> and never touches `engine.strict`, so concurrent callers and shared engines are unaffected.
> Other integrations that need per-call non-strict validation should prefer
> `engine.validate(..., strict=False)` over `engine.non_strict()` for the same reason —
> `non_strict()` mutates shared state and is unsafe under concurrency.

To opt into fail-open (e.g., for testing), you must set it explicitly:

```python
engine = GovernanceEngine(constitution, strict=False)  # explicit; off by default
```

Enforcement actions progress from least to most restrictive:
`warn` → `block` → `block_and_notify` → `require_human_review` → `escalate_to_senior` → `halt_and_alert`

---

## 🗺️ Component Stability

Not all layers are equally hardened. Use this table to calibrate trust in each area:

| Component | Status | Notes |
|-----------|--------|-------|
| `GovernanceEngine` — rule validation | ✅ **Stable** | Core hot path; Aho-Corasick matcher, fail-closed exceptions |
| `Constitution` — YAML loading, rule parsing | ✅ **Stable** | Hash-pinned; schema-validated |
| `Rule`, `Severity`, `ValidationResult` | ✅ **Stable** | Stable data model; additive changes only |
| `MACIEnforcer` — role separation | ✅ **Stable** | Role checks are enforced by default in `GovernedAgent`; pass a MACI role plus per-call `governance_action` |
| `AuditLog` — SHA-256 chained trail | ✅ **Stable** | Thread-safe append-only; chain verification tested |
| Signed receipts (`SignedReceipt`, `replay_and_verify`) | 🔶 **Beta** | Optional `crypto` extra; Ed25519 over the receipt commitment + verdict replay; tested; in-memory key (bring your own KMS) |
| `GovernedAgent` — drop-in wrapper | ✅ **Stable** | Synchronous and async paths covered |
| OpenAI / Anthropic / LangChain adapters | ✅ **Stable** | Thin validated wrappers; covers completions and streaming |
| Constitution lifecycle API (HTTP) | 🔶 **Beta** | Draft/review/activate/rollback endpoints are functional; API may evolve |
| SQLite bundle store, lifecycle persistence | 🔶 **Beta** | WAL-mode; covers single-node; multi-writer not yet hardened |
| `acgs assess` compliance mapping | 🔶 **Beta** | 18-framework coverage; control mappings improve with each release |
| MCP server integration | 🔶 **Beta** | Single-node; production use requires your own transport hardening |
| Intervention / quarantine / halt workflow | 🔶 **Beta** | Full path functional; thread-safety hardened; API may evolve |
| Z3 constraint verifier | 🧪 **Experimental** | Useful for high-risk scenarios; requires separate Z3 install |
| Lean 4 / Leanstral proof certificates | 🧪 **Experimental** | Requires `mistralai` extra and external Lean kernel |
| Newer framework adapters (Agno, A2A, LiteLLM, Mistral) | 🧪 **Experimental** | Community-contributed; test coverage varies |
| `acgs_lite.gove` — gove-zone kernel bridge | 🧪 **Experimental** | Optional `gove` extra (Python >= 3.11); `gove-zone` not yet on PyPI; distinct receipt format from `legitimacy`, not translated |

---

## Stable surfaces today (2.10.1 published; 2.11.0 pending)

This table describes library surfaces with stable APIs and test coverage. It is
not a blanket production-readiness claim for every deployment.

| Layer | Status | What you get |
|-------|--------|--------------|
| `GovernanceEngine` | Stable | YAML rules, deterministic validation, fail-closed enforcement |
| MACI role separation | Stable | Proposer / Validator / Executor enforced at runtime |
| Audit Trail | Stable | SHA-256 chained, SQLite-backed, queryable, exportable |
| `GovernedAgent` wrapper | Stable | Drop-in decorator for OpenAI, Anthropic, LangChain, MCP, etc. |
| Intervention & Quarantine | Stable | `require_human_review`, `halt_and_alert`, `quarantine` actions |
| CLI (`acgs validate`, `audit`, `halt`) | Stable | Full local & CI usage |

**Everything else** (constitution lifecycle API, formal verification with Z3/Lean, 18-framework compliance mapping) is **Beta / Experimental** and clearly marked in the Component Stability table above.

---

## 🏭 Production users

No independently confirmed production users yet.

---

## 🌐 Integrations

### OpenAI

```python
from acgs_lite.integrations.openai import GovernedOpenAI
from openai import OpenAI

client = GovernedOpenAI(OpenAI(), constitution=constitution)
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Analyze the contract"}],
)
```

### Anthropic Claude

```python
from acgs_lite.integrations.anthropic import GovernedAnthropic
import anthropic

client = GovernedAnthropic(anthropic.Anthropic(), constitution=constitution)
message = client.messages.create(
    model="claude-opus-4-5",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Review this code"}],
)
```

### LangChain

```python
from acgs_lite.integrations.langchain import GovernanceRunnable
from langchain_openai import ChatOpenAI

governed_llm = GovernanceRunnable(
    ChatOpenAI(model="gpt-4o"),
    constitution=constitution,
)
result = governed_llm.invoke("Translate this document")
```

### MCP Server

Start a governance server that any MCP-compatible agent can query:

```bash
acgs serve --host 0.0.0.0 --port 8080
```

```python
from acgs_lite.integrations.mcp_server import create_mcp_server
app = create_mcp_server(constitution=constitution)
```

---

## 📋 Compliance Coverage

ACGS maps governance controls to 18 regulatory frameworks. Run `acgs assess` to generate a compliance report:

```bash
acgs assess --framework eu-ai-act --output report.pdf
```

| Framework | Coverage | Key Controls |
|-----------|----------|--------------|
| **EU AI Act (High-Risk)** | Art. 9, 10, 13, 14, 17 | Risk management, human oversight, transparency |
| **NIST AI RMF** | 7 / 16 functions | Govern, Map, Measure, Manage |
| **SOC 2 + AI** | 10 / 16 criteria | CC6, CC7, CC9 trust service criteria |
| **HIPAA + AI** | 9 / 15 safeguards | PHI detection, access controls, audit controls |
| **GDPR Art. 22** | 10 / 12 requirements | Automated decision-making, right to explanation |
| **CCPA / CPRA** | 8 / 10 rights | Opt-out, data minimisation, transparency |
| **ISO 42001** | Clause 6, 8, 9, 10 | AI management system controls |
| **OWASP LLM Top 10** | 9 / 10 risks | Prompt injection, insecure output, data poisoning |

---

## 🔬 Advanced: Formal Verification

For the highest-risk scenarios, ACGS supports mathematical proof of safety properties.

### Z3 SMT Solver

```python
from acgs_lite.integrations.z3_verifier import Z3ConstraintVerifier

verifier = Z3ConstraintVerifier()
result = verifier.verify(
    action="transfer $50,000 to external account",
    constraints=["amount <= 10000", "recipient in approved_list"],
)
print(result.satisfiable, result.counterexample)
```

### Lean 4 Proof Certificates (Leanstral)

```python
from acgs_lite import LeanstralVerifier

verifier = LeanstralVerifier()  # requires mistralai extra
certificate = await verifier.verify(
    property="∀ action : Action, action.amount ≤ 10000",
    context={"action": "transfer $5,000"},
)
print(certificate.kernel_verified)  # True only if Lean kernel accepted proof
print(certificate.to_audit_dict())  # attach to AuditEntry
```

---

## ⚡ Performance

| Operation | Latency | Notes |
|-----------|---------|-------|
| Rule validation (Python) | Measured per workload | Aho-Corasick multi-pattern; depends on rules and text size |
| Rule validation (Rust) | Measured per workload | Optional Rust extension; benchmark your target hardware |
| Engine batch (100 rules) | Reference benchmark only | Depends on rule count, severities, and context size |
| Audit write (JSONL) | Reference benchmark only | Append-only, SHA-256 chained; storage latency matters |
| Compliance report | Reference benchmark only | Framework count, cache state, and report scope affect latency |

---

## 🖥️ CLI

```bash
# Validate a single action
acgs validate "send email to user@corp.com" --constitution rules.yaml

# Run governance status check
acgs status

# Generate compliance report
acgs assess --framework hipaa --output hipaa_report.pdf

# Audit log inspection
acgs audit --tail 20
acgs audit --verify-chain

# Start MCP governance server
acgs serve --port 8080

# EU AI Act Art. 14(3) kill switch
acgs halt --agent-id agent-01 --reason "anomalous behaviour detected"
acgs resume --agent-id agent-01
```

---

## 📖 Documentation

| Guide | Description |
|-------|-------------|
| [Examples](./examples/README.md) | Canonical demo path: block, audit, then MCP |
| [Constitution Templates](./examples/constitutions/README.md) | Reusable constitutions for content moderation, customer service, healthcare, hiring, and lending |
| [Quickstart](https://acgs.ai/docs/quickstart) | Up and running in 5 minutes |
| [Architecture](https://acgs.ai/docs/architecture) | Engine internals, MACI deep dive |
| [Integrations](https://acgs.ai/docs/integrations) | OpenAI, Anthropic, LangChain, MCP, A2A |
| [Integration Decision Guide](./docs/integration-decision-guide.md) | Which adapter when: native vs. framework, streaming, async, MCP vs. in-process |
| [Compliance](https://acgs.ai/docs/compliance-2026) | 18-framework regulatory mapping |
| [CLI Reference](https://acgs.ai/docs/cli) | Full command reference |
| [Why Governance?](https://acgs.ai/docs/why-governance) | The case for deterministic guardrails |
| [OWASP LLM Top 10](https://acgs.ai/docs/owasp-2026) | ACGS coverage of each risk |
| [Testing Guide](https://acgs.ai/docs/testing-governance) | Testing governed agents |
| [Constitution Lifecycle API](./docs/api/lifecycle.md) | HTTP endpoints for draft, review, eval, activation, rollback, and reject |

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/dislovelhl/acgs-lite
cd acgs-lite/packages/acgs-lite
pip install -e ".[dev]"
pytest tests/ --import-mode=importlib
```

---

## 📄 License

Apache-2.0. See [LICENSE](LICENSE) for details.

Commercial enterprise licences (SLA, support, air-gapped deployment) available at [acgs.ai](https://acgs.ai).

---

*Constitutional Hash: `608508a9bd224290` — embedded in every validation path.*
