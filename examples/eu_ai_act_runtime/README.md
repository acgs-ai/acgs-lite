# EU AI Act Runtime Enforcement

Reference implementation for teams preparing high-risk AI systems during the
EU AI Act's preparation period. Under the Digital Omnibus, most Annex III
high-risk obligations are deferred to **2027-12-02**; this preparation window
is the time to wire runtime enforcement in before the obligations bind.

acgs-lite **supports compliance measures, does not by itself make a system
compliant.** These demos show verifiable runtime *evidence* — signed
receipts, fail-closed gates, tamper-evident audit trails — that a governance
control actually ran, not a legal compliance determination.

This directory complements two other in-repo resources:

- [`../eu_ai_act_quickstart.py`](../eu_ai_act_quickstart.py) — in-process API
  walkthrough of risk classification, Article 12 logging, Article 14
  oversight, Article 13 transparency, and a conformity checklist.
- [`../compliance_eu_ai_act/`](../compliance_eu_ai_act/) — static risk-tier
  inference and article-level gap assessment.

Where those two show the *compliance-mapping* surface, this set shows
**runtime enforcement evidence**: what happens the moment an agent tries to
act, and what artifact proves a control fired.

## Demos

### Article 12 — Record-keeping ([`art12_record_keeping.py`](art12_record_keeping.py))

```bash
python examples/eu_ai_act_runtime/art12_record_keeping.py
```

Wraps three simulated high-risk agent actions in an `Article12Logger`
tamper-evident record chain, then issues a signed `AttestationRegistry`
receipt for the same decision. The receipt is tampered with after issuance
to show that verification fails once content changes.

**Takeaway:** automatic, tamper-evident logging and independently verifiable
attestation receipts are two different integrity mechanisms — a chain that
detects internal tampering, and a signature that detects external tampering
of a single exported artifact. Both must hold for a credible audit trail.

### Article 14 — Human oversight ([`art14_human_oversight.py`](art14_human_oversight.py))

```bash
python examples/eu_ai_act_runtime/art14_human_oversight.py
```

An unapproved mock payment is blocked twice before it ever executes: a
constitutional rule (`CK-002`) rejects the raw action text outright, and a
`HumanOversightGateway` keeps the side effect pending until a human reviewer
approves it. The deny path runs first — the system fails closed by default.

**Takeaway:** oversight is only meaningful if the executor *cannot* act
without an `APPROVED` decision. Gating the side effect on the outcome value,
not on a boolean flag an upstream caller could forge, is what makes the
control enforceable rather than advisory.

### Article 15 — Robustness ([`art15_robustness.py`](art15_robustness.py))

```bash
python examples/eu_ai_act_runtime/art15_robustness.py
```

A prompt-injection attempt is intercepted at the governance boundary before
it reaches any tool or LLM call. Interception opens a tracked incident and
writes a tamper-evident `failure_mode` audit entry; a benign input passes the
same boundary and is recorded as an ordinary `validation` entry.

**Takeaway:** robustness against manipulation isn't just "block the bad
input" — it's producing an incident record and an audit trail entry in the
same motion, so the interception itself becomes evidence rather than a
silent no-op.

## Running all three

```bash
python examples/eu_ai_act_runtime/art12_record_keeping.py
python examples/eu_ai_act_runtime/art14_human_oversight.py
python examples/eu_ai_act_runtime/art15_robustness.py
```

Each script is self-contained, requires no external services or API keys,
and exits `0` on success.
