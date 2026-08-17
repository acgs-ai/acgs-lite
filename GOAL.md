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

| Criterion | Metric | Current (2026-08-17) | Target | By when |
|---|---|---|---|---|
| Usage-as-governance (primary, maps to North Star) | Independent (non-maintainer) repos/services that import `acgs_lite` and invoke a governance decision at a real side-effect boundary, verified by public source or written confirmation | 0 independently confirmed | ≥3 independent projects, with ≥1 still integrated at 90 days (retention) | 2026-12-31 |
| Core invariant empirically proven with a meaningfulness floor | ≥3 experiments on a REAL LLM + real AuditLog (not seeded RNG) using a recognized dataset (real HumanEval/SWE-bench subset, stated min sample size, ≥2 model providers), headline X1 hypothesis resolved to a non-zero interpretable result or explicitly retired, with committed `*_results.json` + `summary.json` | Harness exists; committed `research/results/real_llm/summary.json` is a placeholder (`simulated: true`, `experiments: []`). X1 not resolved/retired | ≥3 real experiments meeting the floor + X1 resolved/retired | 2026-10-31 |
| Adversarial bypass coverage incl. out-of-distribution attack | Committed adversarial suite covering all five fail-closed triggers (authorization, constitution version, policy staleness, receipt integrity, audit-evidence verifiability) — not just carrier/receipt vectors — incl. ≥1 externally-contributed/OOD attack the maintainer did not author; 0 successful bypasses | `docs/evidence/governance-regression/` records 6 self-authored cases, 5 trigger classes, 0 bypasses (2026-05-31). No external/OOD case | 0 bypasses across all five trigger classes incl. ≥1 external attack | 2026-10-31 |
| Fail-closed is the DEFAULT | MACI hard-enforced without `enforce_maci=True`; bundled Claude Code hook route (no external `/x402/check` sidecar) without owning orchestration; Legitimacy Kernel graded Stable with passing tests | Shipped in 2.12.0: `GovernedAgent` defaults `enforce_maci=True`; bundled hook route; legitimacy kernel is a documented stable surface. Explicit opt-outs remain (`enforce_maci=False`, `strict=False`) | All three closed; remaining advisory opt-outs inventoried | 2026-10-31 |
| Governance-regression safety (no silent weakening) | Adversarial suite runs in CI on every PR; constitutional hash + receipt-binding invariants asserted unchanged unless explicitly versioned; no release may re-open a previously-closed bypass vector | CI job `governance-regression` runs `make test-governance` (includes `scripts/run_governance_regression.py --check`) on PRs to `main`. Branch-protection “required” pinning not independently re-audited here | CI regression gate live and required; 0 reopened vectors | 2026-09-30 |
| Zero unsupported claims on public surfaces (precondition) | Live "Featured in Awesome LLM Security" badge unless inclusion confirmed; "community favorites" framing; empty production table presented as social proof; self-assessed compliance percentages surfaced as adoption proof; unlabeled simulations | Badge/favorites framing removed; production users line is honest; research X1–X6 labeled simulations. Remaining work: keep pip-only first-run honest (`examples/` is not on PyPI) and keep compliance ratios labeled SELF-ASSESSED | 0 unverified claims; pip-only first-run works; compliance framed as self-assessment only | 2026-08-01 (overdue; honesty pass continues) |
| Security-disclosure posture | Presence of SECURITY.md + working vulnerability-disclosure channel + stated triage/disclosure window | `SECURITY.md` live; `security@acgs.ai`; 2.12.x supported. Mailbox staffing / live triage not independently verified | SECURITY.md live; disclosure channel working; window committed | 2026-09-30 |
| Bus factor exceeds 1 with responsive maintenance | External merged contributors; median time-to-first-response over a trailing 30-day window with a minimum-N denominator | Primary maintainer still dominates. Additional GitHub accounts exist (including bots). Not claimed as bus factor ≥2. TTFR unmeasured | Bus factor ≥2 (≥1 external merged PR) AND median TTFR ≤48h once N≥3 inbound items in window | 2026-12-31 |
| Canonical release shipped, positioning committed | Released version (>v2.10.1) on PyPI capturing the unreleased hardening with a populated CHANGELOG; GOAL.md + `governed_execution_membrane.py` committed; clean install verified from a fresh venv | **Met:** PyPI `2.12.0`; CHANGELOG populated; trusted publishing. Positioning/honesty pass still in flight on the first-run path | Keep published line current; do not treat release as the remaining bottleneck | 2026-08-31 |

### Critical Path

1. Keep the **honesty pass** closed on every public surface: pip-only first-run
   (no `examples/` after `pip install`), fail-closed default engine in the hero,
   compliance ratios labeled SELF-ASSESSED, no invented users or certification.
   This still gates outbound traffic.
2. ~~Renew the PyPI token / cut v2.11.0.~~ **Done:** `2.12.0` is on PyPI via
   trusted publishing.
3. Convert the first installer with the 5-minute membrane page; do not send
   traffic to a first command that requires a clone.
4. Inventory remaining advisory opt-outs (`strict=False`, `enforce_maci=False`)
   so “fail-closed is the default” stays literally true.
5. Wire ≥3 real-LLM + real-AuditLog experiments meeting the meaningfulness floor,
   or retire X1 in writing; add ≥1 external/OOD fail-closed case.
6. Confirm the `governance-regression` CI job is a required check on `main`.
7. Stand up ≤48h responsive maintenance and good-first-issues to convert the
   first external contributor and the first independent integrator. Curated-list
   submissions stay owner-gated and must follow the honesty pass.

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
