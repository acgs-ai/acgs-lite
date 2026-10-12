# ACGS-Lite social launch kit

Prepared: 2026-10-12. Status: **drafts for review; nothing posted or scheduled**.

These drafts introduce the existing **3.0.1 PyPI release**, not a new release.
The execution-grant, trusted-context, durable-audit, and recovery APIs in the
current source candidate are unreleased and absent from that wheel.

Use the GitHub-hosted guide below. At this audit, `acgs.ai/docs` redirected to
marketing resources. Check destinations again before publishing.

## Shared destinations and evidence

- Repository: <https://github.com/acgs-ai/acgs-lite>
- Package: <https://pypi.org/project/acgs-lite/3.0.1/>
- Guide: <https://github.com/acgs-ai/acgs-lite/blob/main/docs/guides/five-minute-membrane.md>
- Community: <https://github.com/acgs-ai/acgs-lite/discussions>
- Contributions: <https://github.com/acgs-ai/acgs-lite/blob/main/CONTRIBUTING.md>

Claim sources: [README](../README.md),
[five-minute guide](../docs/guides/five-minute-membrane.md), and [license](../LICENSE).
The updated README's published-package snippet was tested against the 3.0.1 wheel
during this audit: it prints `True`, then catches and prints
`ConstitutionalViolationError` for the matching wire-transfer rule. The guide
demonstrates receipt checks with a simulated side effect, not a live tool.

No draft claims certification, independent production adoption, performance
superiority, or universal prevention of unsafe actions. Publish references to the
updated README only after its changes are merged and the public snippet is checked.

## GitHub Discussions announcement

**Title:** Try ACGS-Lite 3.0.1: policy checks before an agent tool runs

**Body:**

ACGS-Lite is an Apache-2.0 Python library for checking proposed agent actions
against explicit rules. The published 3.0.1 package is beta.

Start with `pip install acgs-lite==3.0.1` and the
[README quickstart](https://github.com/acgs-ai/acgs-lite#minimal-quickstart).
The example allows an invoice-email description and raises
`ConstitutionalViolationError` for a description containing `wire transfer`.

Then try the
[five-minute guide](https://github.com/acgs-ai/acgs-lite/blob/main/docs/guides/five-minute-membrane.md).
It connects the policy result to an executor check: allow an invoice message,
redact a sample SSN, refuse a denied receipt, and refuse a missing receipt.
The simulated execution returns a string; it does not send mail or money.

A policy check only affects actions routed through it. Keyword and regex rules
cover the patterns you define and can miss paraphrases. The demo's in-memory
audit chain is not a hosted or durable audit service. Newer production-profile
grant APIs in the repository are unreleased and absent from the 3.0.1 wheel.

We would value a small reproducible example from your own tool boundary:

- What action should your policy allow or deny?
- Where does the check sit relative to the actual tool call?
- Which input or integration behavior surprised you?

Share a minimal example with synthetic data. Send suspected vulnerabilities
through the private reporting instructions in
[SECURITY.md](https://github.com/acgs-ai/acgs-lite/blob/main/SECURITY.md).

## LinkedIn post

What should happen between an agent choosing a tool and that tool running?

ACGS-Lite puts an explicit policy check at that boundary. It is an Apache-2.0
Python library, currently beta, with version 3.0.1 available on PyPI.

The smallest example checks two action descriptions: an invoice email passes;
a wire-transfer description matching a critical rule raises an exception.

The five-minute walkthrough goes further: issue a decision receipt, check it
at the executor, redact a sample SSN, and refuse denied or missing receipts.
It uses simulated execution so you can inspect the flow without API keys.

Its protection depends on the rules you write and on routing tool calls through
the gate. Newer grant and durable-audit work in the repository is unreleased
and absent from the published 3.0.1 wheel.

Try it and share a policy case or integration gap:
https://github.com/acgs-ai/acgs-lite

Walkthrough:
https://github.com/acgs-ai/acgs-lite/blob/main/docs/guides/five-minute-membrane.md

## X standalone post

Copy only the block. **229 Unicode characters**, or **216** counting its URL
as 23 characters; both are below 280.

```text
ACGS-Lite 3.0.1 is a beta Python library for policy checks before agent actions. Try a small example: allow an invoice email, block a matching wire-transfer rule. Apache-2.0; feedback welcome. https://github.com/acgs-ai/acgs-lite
```

## Show HN submission

**Title:** Show HN: ACGS-Lite, Python policy checks before agent tool execution

**Submission URL:** <https://github.com/acgs-ai/acgs-lite>

**Introductory comment:**

Full disclosure: I'm the maintainer of acgs-lite.

I want proposed tool actions to pass an explicit policy check before an executor
runs them. ACGS-Lite is a Python library for that pattern, released under
Apache-2.0. The current published package is 3.0.1 and is beta.

The README has a small example you can run after installing the pinned package.
An invoice-email description passes; a wire-transfer description matching a
critical rule raises an exception. The next walkthrough adds a receipt check
at a simulated executor and refuses denied and missing receipts:
https://github.com/acgs-ai/acgs-lite/blob/main/docs/guides/five-minute-membrane.md

The demo executes a string-returning function, its audit chain lives in memory,
and keyword/regex rules miss inputs outside their patterns. It does not
demonstrate isolation from malicious code in the same process or certify a
deployment. Newer execution-grant and durable-audit source features are
unreleased and absent from the 3.0.1 wheel.

What would make this easier to put in front of a real tool call, and what
minimal example would expose an unclear policy decision?

## Developer community post

**Title:** A small Python demo of policy checks and receipt-gated execution

**Body:**

Full disclosure: I'm the maintainer of acgs-lite.

I put together a walkthrough for connecting a policy decision to the code that
performs an agent action. The published `acgs-lite==3.0.1` package is beta and
Apache-2.0 licensed. Its README validates action descriptions against a YAML rule.
The longer guide checks a decision receipt at a simulated executor, refuses
denied and missing receipts, and redacts a sample SSN.

You can run it without API keys. It does not call an LLM or send email. The
example policy is narrow: a paraphrase that avoids a keyword can pass. Inspect
that limit when deciding what your own policy covers.

Repository: https://github.com/acgs-ai/acgs-lite

Guide: https://github.com/acgs-ai/acgs-lite/blob/main/docs/guides/five-minute-membrane.md

A minimal failing example or a description of your tool-call boundary would
help. Please use synthetic data. Newer grant and durable-audit APIs are
unreleased source work, not features of the pinned PyPI demo.

## Demo script: approximately 45–60 seconds

Record the pinned package and updated README snippet. Show actual terminal
output; do not substitute staged output for a failed run.

| Time | Visual | Spoken copy |
| --- | --- | --- |
| 0–8s | README and `acgs-lite==3.0.1` | “Here is a small policy check for an agent action, using the beta ACGS-Lite package.” |
| 8–20s | Highlight `wire transfer` and critical severity | “This rule blocks descriptions containing ‘wire transfer.’ It covers this pattern, not a general understanding of financial risk.” |
| 20–32s | Run snippet; show `True` and caught exception | “An invoice-email description passes. The matching transfer raises a constitutional violation.” |
| 32–45s | Five-minute guide's executor | “The next guide puts a receipt check before simulated execution and refuses denied or missing receipts.” |
| 45–58s | Repository and guide links | “Try the pinned example and share a policy case. Newer grant APIs in the source tree are unreleased.” |

**Caption:** ACGS-Lite 3.0.1 beta: an explicit rule, an allowed description,
and a blocked matching description. The longer walkthrough uses simulated
execution. Repository and runnable guide linked above.

## Publishing handoff

These are draft assets only. A maintainer can publish the first-person versions;
another contributor must change the disclosure to their actual role. Confirm
each community's current submission rules before adapting and posting there.
Do not solicit coordinated votes or imply third-party endorsement.

Before posting, check the pinned package, public README, guide, and destination
links agree. Record the final post URL and technical corrections. Use reproducible
feedback to improve examples; do not present engagement targets as achieved results.
