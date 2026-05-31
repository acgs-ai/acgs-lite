# Goal v1.0: Constitutional Governance Membrane

## Default-Layer Ambition

Make `acgs-lite` the default open-source constitutional governance layer that
agent builders can place immediately before side-effectful execution. The goal is
not to claim that status today; it is to earn it by making constitutional
authorization easy to add, hard to bypass, and easy to verify.

The adoption wedge is narrow and executable:

> Developers should be able to place `acgs-lite` immediately before any
> side-effectful agent action and get a verifiable ALLOW / DENY / TRANSFORM
> decision with a receipt.

## Core Invariant

> No valid constitutional authorization, no side effect.

The runtime must fail closed whenever authorization, constitution version, policy
state, receipt integrity, or audit evidence cannot be verified.

## Product Boundary

`acgs-lite` is not an agent framework. It does not own model calls, prompting,
planning, memory, tool selection, retries, scheduling, or workflow orchestration.
Those remain the responsibility of the host agent runtime.

`acgs-lite` is the governance membrane before execution:

```text
LLM reasoning → constitutional check → decision receipt → governed execution
```

Agent frameworks decide what action they want to take. `acgs-lite` decides
whether that proposed side effect is constitutionally authorized under versioned
rules, emits a receipt for the executor to verify, and records audit evidence for
inspection and replay.

## What the Membrane Must Provide

- A simple pre-execution API that accepts a proposed action and active
  constitution state.
- Deterministic ALLOW / DENY / TRANSFORM-style outcomes mapped to the canonical
  decision taxonomy.
- Receipts bound to the proposed method, scope, subjects, authority basis,
  policy version, and execution boundary.
- Executor-side refusal when the receipt is missing, malformed, tampered with,
  stale, denied, or mismatched against substituted arguments.
- Audit evidence that can be inspected and replay-verified, with tampering
  rejected rather than treated as a successful log.
- A path from lightweight in-process use to stronger storage, signing,
  cryptographic anchoring, and operational controls.

## Non-Goals

`acgs-lite` should not become:

- a new agent framework;
- a passive logging system that observes side effects after the fact;
- a compliance-claim generator;
- a large demo application;
- a marketing layer that claims default adoption, production readiness,
  regulatory approval, or certification without evidence.

## Long-Term Success Criteria

- Developers can wrap existing agent execution without rewriting their agent
  logic.
- Side-effectful actions are checked against a versioned constitution before
  execution.
- Executors refuse work unless a valid decision receipt matches the actual
  method, scope, subjects, policy version, and execution boundary.
- Denials, transformations, approvals, and fail-closed states leave inspectable
  audit evidence.
- Tampered receipts, audit trails, substituted arguments, missing constitutions,
  and stale policy state are detected and fail closed.
- Constitutions are portable enough to share, review, test, and evolve across
  tools and organizations.
- Higher-assurance deployments can add formal checks, cryptographic anchoring,
  and external verification without changing the membrane model.

---

## Definition of Success — Measurable (defined 2026-05-31)

> The section above states the *product boundary* and qualitative ambition. This
> section makes "success" falsifiable and time-bound. It was defined 2026-05-31
> from a 15-agent review+stress-test of this repo. Portfolio context (how
> acgs-lite relates to the commercial CaLegal product) lives in
> `../PORTFOLIO_GOALS.md`. **Money is explicitly not the bar** — adoption and
> verifiable trust are. Commercial licensing at acgs.ai is a separate downstream
> concern.

acgs-lite succeeds when independent developers — not the maintainer — actually
*invoke* the membrane at a real side-effect boundary in their own systems, and
can trust it because the core invariant is empirically proven against meaningful
adversarial attack on real (not simulated) infrastructure, the public surfaces
carry zero unsubstantiated claims, governance is never silently re-opened by a
later commit, and the project has moved off bus factor 1.

### Success Criteria

| Criterion | Metric | Current | Target | By when |
|---|---|---|---|---|
| Usage-as-governance (primary, maps to North Star) | Independent (non-maintainer) repos/services that import `acgs_lite` and invoke a governance decision at a real side-effect boundary, verified by public source or written confirmation | 0 | ≥3 independent projects, with ≥1 still integrated at 90 days (retention) | 2026-12-31 |
| Core invariant empirically proven with a meaningfulness floor | ≥3 experiments on a REAL LLM + real AuditLog (not seeded RNG) using a recognized dataset (real HumanEval/SWE-bench subset, stated min sample size, ≥2 model providers), headline X1 hypothesis resolved to a non-zero interpretable result or explicitly retired, with committed `*_results.json` + `summary.json` | 0 real experiments (all 6 are simulations, no result JSON committed); X1 currently delta 0.0 | ≥3 real experiments meeting the floor + X1 resolved/retired | 2026-10-31 |
| Adversarial bypass coverage incl. out-of-distribution attack | Committed adversarial suite covering all five fail-closed triggers (authorization, constitution version, policy staleness, receipt integrity, audit-evidence verifiability) — not just carrier/receipt vectors — incl. ≥1 externally-contributed/OOD attack the maintainer did not author; 0 successful bypasses | Hardening exists in src; no committed pass/fail artifact; vectors are self-authored and carrier/receipt-only | 0 bypasses across all five trigger classes incl. ≥1 external attack | 2026-10-31 |
| Fail-closed is the DEFAULT | MACI hard-enforced without `enforce_maci=True`; bundled Claude Code hook route (no external `/x402/check` sidecar) without owning orchestration; Legitimacy Kernel graded Stable with passing tests | MACI advisory by default; hook depends on unbundled sidecar; kernel partially realized, not Stable | All three closed | 2026-10-31 |
| Governance-regression safety (no silent weakening) | Adversarial suite runs in CI on every PR; constitutional hash + receipt-binding invariants asserted unchanged unless explicitly versioned; no release may re-open a previously-closed bypass vector | No regression/mutation gate; ~47 unreleased hardening commits unguarded | CI regression gate live; 0 reopened vectors | 2026-09-30 |
| Zero unsupported claims on public surfaces (precondition) | Live "Featured in Awesome LLM Security" badge unless inclusion confirmed; "community favorites" framing; empty production table presented as social proof; self-assessed compliance percentages surfaced as adoption proof; unlabeled simulations | Badge live (unconfirmed), "most shared" framing vs 2 stars, empty production table, compliance % on README, X1–X6 unlabeled | 0 unverified claims; "recommended starting points" framing; production table populated or honestly reframed; compliance framed as self-assessment only; every research result line prefixed "SIMULATION (seed=42), not empirical benchmark" or replaced with real results | 2026-08-01 |
| Security-disclosure posture | Presence of SECURITY.md + working vulnerability-disclosure channel + stated triage/disclosure window | None | SECURITY.md live; disclosure channel working; window committed | 2026-09-30 |
| Bus factor exceeds 1 with responsive maintenance | External merged contributors; median time-to-first-response over a trailing 30-day window with a minimum-N denominator | 0 external contributors; TTFR unmeasured (no inbound) | Bus factor ≥2 (≥1 external merged PR) AND median TTFR ≤48h once N≥3 inbound items in window | 2026-12-31 |
| Canonical release shipped, positioning committed | Released version (>v2.10.1) on PyPI capturing the unreleased hardening with a populated CHANGELOG; GOAL.md + `governed_execution_membrane.py` committed; clean install verified from a fresh venv | v2.10.1 latest tag, ~47 unreleased commits, empty CHANGELOG, PyPI token expired (403), positioning dirty | v2.11.0+ published, CHANGELOG filled, positioning committed, fresh-venv install verified | 2026-08-31 |

### Critical Path

1. Run the **honesty pass** (strip/confirm badge, replace "favorites" framing,
   reframe production table and compliance %, label all X1–X6 as simulations).
   Highest-leverage, gates everything downstream and must precede any traffic.
2. Renew the PyPI token (external, account-gated) and verify a clean release from
   a fresh venv.
3. Commit membrane positioning + cut v2.11.0 with a populated CHANGELOG capturing
   the unreleased commits.
4. Make fail-closed the default (MACI, bundled hook, Legitimacy Kernel Stable) and
   add the CI governance-regression gate.
5. Wire ≥3 real-LLM + real-AuditLog experiments meeting the meaningfulness floor;
   build the five-trigger adversarial suite incl. one OOD attack; commit
   reproducible artifacts.
6. Capture the hero GIF and hoist runnable proof above theory (the conversion
   gate); add SECURITY.md.
7. Submit to curated lists, track de-bot-screened PyPI installs, stand up ≤48h
   responsive maintenance and good-first-issues to convert the first external
   contributor and the first independent integrator.

### Buildable vs. external (for autonomous work)

Buildable here (the `/goal` surface): the honesty pass, fail-closed-by-default,
the CI regression gate, the adversarial suite + experiment harness, SECURITY.md,
CHANGELOG, and release packaging. **Not buildable** (owner/third-party gated, do
not promise on a clock): PyPI token renewal, curated-list acceptance, strangers
starring/contributing, and any third party agreeing to integrate or be named.

### Vanity-metric guardrail

GitHub stars, raw PyPI counts, curated-list inclusion, single blog mentions,
compliance-coverage %, and commit velocity are leading indicators capped at ≤20%
of effort — never success endpoints, and never counted unless screened for
authenticity. Hitting any numeric target via inauthentic means (bought/bot stars,
upvote coordination, undisclosed self-promotion) does not count.
