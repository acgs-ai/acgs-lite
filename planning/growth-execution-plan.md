# Growth Execution Plan — `acgs-lite`

Date: 2026-05-31
Status: **active** · supersedes the channel/metric stance of [`planning/community-roadmap.md`](./community-roadmap.md) (2026-05-30)
Owner legend: **You** = human orchestrator (publishing, account actions, anything that posts to a third party or touches a live account). **Claude** = code/docs/asset work in-repo.

---

## TL;DR

- **The bet:** Go **Discord-first** for community and run an **active, authentic star-growth** push, **timed to the EU AI Act 2 Aug 2026 transparency milestone** — instead of the GitHub-Discussions-first, stars-as-leading-indicator posture in the 2026-05-30 community roadmap.
- **Why now:** the product is launch-ready (v2.10.1 published, hero demo runs, EU AI Act tooling ships) but discovery is the bottleneck (2 stars, 39 views / 11 uniques, bus factor 1). We are compressing timeline and raising channel + star emphasis, on purpose.
- **The one blocker we fix first:** the hero GIF (`docs/assets/basic-governance-hero.gif`) does not exist and the README leads with ~50 lines of theory before any runnable proof. **We do not drive traffic to a repo that doesn't convert.**
- **The order:** P1 convert → P2 channels (with self-promo guardrails baked in) → P3 authentic stars → P4 EU AI Act timing → P5 integration guides + good-first-issues.

### Strategic override (read this)

> This plan **deliberately overrides** [`planning/community-roadmap.md`](./community-roadmap.md). It is an **eyes-open exception, not a refutation** of the contributor-first thesis. The roadmap's §4 "Hard rule: do not launch Discord before Stage 3" (line 129) and §9 anti-patterns "Premature Discord" + "Star-chasing over user depth" (lines 199–200) are **retired/amended** by this plan. See the Conflict ledger (§8).

**What we are betting:** that a small, well-run Discord with a **guaranteed weekly ritual + day-one moderators** plus an **EU-AI-Act-timed launch** will buy discovery faster than the slow Discussions-first funnel — and that authentic stars are a real top-of-funnel input (GitHub search weights stars; HN/Reddit produce measurable star bursts), not pure vanity.

**The accepted risk (named honestly — verdict 5):**
- **Star-vanity vs. bus-factor tension.** Stars correlate with contributors only *moderately* (Valente et al., JSS 2018, ρ≈0.50) and weakly with commits. Bus factor = 1 is still the binding constraint. Elevating stars to a *primary near-term emphasis* is exactly the failure mode the old roadmap names. We accept it **only** under the guardrails below.
- **Ghost-town Discord** at 2 stars / 0 contributors actively harms credibility (the old roadmap's documented reason for deferral).
- **Astroturf reputational blast radius.** This is a *trust/governance* product; any whiff of fake stars or undisclosed promotion is disproportionately damaging. AI/LLM repos are the #1 non-malicious fake-star target (CMU ICSE'26); GitHub deleted 90.42% of flagged repos.

**The de-risking guardrails we adopt (non-negotiable):**

| Guardrail | Rule |
| --- | --- |
| G1 · Discord is not a ghost town | Launch **only with a pre-committed weekly ritual** ("governance scenario of the week" / office hours) **and 2–3 day-one moderators**. If we can't staff the ritual, we don't open it yet. |
| G2 · Stars are an **input**, not the scoreboard | Keep a protected north-star pair: **bus factor → ≥ 2** and **time-to-first-response ≤ 48h**. Stars sit in a "discovery inputs" row, never alone. |
| G3 · Authentic asks only (GitHub AUP) | Only real humans who could plausibly care. **No** bought/exchanged/bot stars, **no** star-for-star rings, **no** reward-incentivized starring (gifts/giveaways/"star to unlock"). Verdict 2 confirms authentic asks are AUP-compliant; these tactics are not. |
| G4 · No vote/upvote coordination | Never use Discord to solicit HN/Reddit upvotes or coordinated star bursts — that is vote manipulation. Star asks live on **owned surfaces only** (README CTA, docs, talks). |
| G5 · Disclose authorship everywhere | "Full disclosure: I'm the maintainer of acgs-lite" in every Reddit/Discord/Show-HN post. Undisclosed self-promo is the behavior Reddit punishes harshest. |
| G6 · Self-correcting | If stars climb but external contributors / Discussion threads / time-to-second-PR don't move in 8–12 weeks, **auto-deprioritize** star tactics and reallocate to onboarding. Star marketing capped at **≤ 20% of weekly OSS hours**; warm first-response + good-first-issue upkeep scheduled **first**. |
| G7 · Governance stays searchable | **Keep GitHub Discussions enabled** for async governance/roadmap decisions (GOVERNANCE.md / ROADMAP.md need a record). Discord = real-time chat, **not** the system of record. |

---

## 1. Grounded current state

**Metrics (from `planning/community-roadmap.md:18-29`, both planning docs agree):**

| Signal | Value | Reading |
| --- | --- | --- |
| GitHub stars | 2 | Pre-traction |
| Forks / watchers | 0 / 1 | No external code activity |
| External contributors | 0 (bus factor = 1) | The binding constraint |
| Repo traffic | 39 views / 11 uniques | Discovery is the bottleneck |
| GitHub Discussions | **enabled, 0 posts** (community-infra grounding; all 6 categories exist) | Surface exists, unseeded |
| Open good-first-issues | 7 (`#55-#61`), 0 assigned | Funnel slots open; **#57 already shipped → must close** |
| Discord | does not exist; `docs/contributing-integrations.md:13,207` already links a phantom `#integrations` | Dangling promise to fix or remove |

**What is already built (cite-and-reuse):**

| Asset | Path / command | Status |
| --- | --- | --- |
| Runnable hero demo | `examples/basic_governance/main.py` (+ `constitution.yaml`) | VERIFIED exit 0; the script the hero GIF records |
| Hero-GIF spec | `planning/hero-demo-capture-plan.md` (target `docs/assets/basic-governance-hero.gif`) | Plan exists; **asset + `docs/assets/` dir do not** |
| EU AI Act one-shot | `acgs eu-ai-act --system-id <id> --domain healthcare --markdown` (`src/acgs_lite/commands/eu_ai_act.py`) | VERIFIED; writes 15KB auditor report |
| EU single-framework | `acgs assess --framework eu_ai_act --domain hr_recruitment` (`src/acgs_lite/commands/assess.py`) | VERIFIED (note: **underscore** `eu_ai_act`) |
| EU runtime walkthrough | `python examples/eu_ai_act_quickstart.py` | VERIFIED exit 0, no API keys |
| Integration template | `src/acgs_lite/integrations/smolagents.py` | Lazy duck-typed import; clone for new guides |
| LangChain guide (half-built) | `docs/guides/langchain.md` + `src/acgs_lite/integrations/langchain.py` (`GovernanceRunnable.wrap()`) | Guide exists, **no `examples/` file** |
| Claude adapter (half-built) | `src/acgs_lite/integrations/anthropic.py` (`GovernedAnthropic`) + `examples/gitlab_anthropic_demo.py` | Live example, **no standalone guide** |
| Launch machinery (reuse) | `planning/oss-growth-playbook.md` (48h window, HN/Reddit/X, star CTA, 0→1,000 map) | Already star-aligned; **promote, don't override** |
| Distribution blurbs (reuse) | `planning/external-distribution-submissions.md`, `planning/final-launch-copy.md` | Reuse verbatim for posts |
| Canonical wedge (reuse verbatim) | "blocks unsafe agent actions **before execution**, enforces separation of powers with MACI, and leaves a tamper-evident audit trail." | Use unchanged everywhere |

---

## 2. P1 — README converts (the one real gap)

**Why first:** inbound social traffic lands at the top of the README, hits ~50 lines of legitimacy theory + an 8-item decision taxonomy before the first runnable line (line 72), and has **zero path back to the community**. Fix conversion before spending attention to drive traffic.

| Task | Owner | Grounded reference | De-risk note |
| --- | --- | --- | --- |
| Create `docs/assets/` and capture the hero GIF (allow → block → block) | Claude (capture) / You (commit) | `planning/hero-demo-capture-plan.md`; record `examples/basic_governance/main.py` via `OPENAI_API_KEY=test-key-for-unit-tests ANTHROPIC_API_KEY=test-key-for-unit-tests .venv/bin/python examples/basic_governance/main.py` | This is the single conversion asset gap; every channel post cites it. Do **not** launch P2 without it. |
| Un-comment + wire the hero GIF block | Claude | `README.md:106` (commented `<img>` → `./docs/assets/basic-governance-hero.gif`) | Keep it above the fold per `hero-demo-capture-plan.md`. |
| Hoist 20-second runnable proof above the formal MVP/taxonomy; collapse the 8-item taxonomy into `<details>` | Claude | `README.md:19-49` (theory) vs `README.md:72` (first runnable) | Don't delete the theory — fold it. Compliance audience still wants it, just not above the fold. |
| Add a **Discord CTA** (badge in the `:3-12` badge cluster + a line near `:55`/`:57`) | Claude (copy) / You (paste real invite) | `README.md:55` (sole star CTA), `README.md:57` (`## ❤️ Community favorites`) | Invite URL is a **You** action; leave a placeholder until the server exists (P2). |
| Strengthen + repeat the star CTA (above-the-fold + a second near README end) | Claude | `README.md:55`, star-history badge `README.md:11` | Frame as honest request, never gated/incentivized (G3). |
| Reframe empty "Used in production at…" as "Early adopters wanted" or move below fold | Claude | `README.md:482` | Empty table broadcasts zero adopters — negative social proof for inbound traffic. |
| Surface good-first-issues + Discussions + Discord from `## 🤝 Contributing` | Claude / You (Discord link) | `README.md:659` | Highest-traffic entry point currently links only `CONTRIBUTING.md` generically. |
| Re-verify clean-venv install promise before any push | You | `pip install acgs-lite==2.10.1` + hero demo | HN/Reddit run it immediately; a broken install or import-time `OPENAI_API_KEY` error dominates the thread (risk). |

**P1 exit gate:** hero GIF live in README · Discord + star CTAs present · taxonomy folded · clean-venv install reproduced.

---

## 3. P2 — Stand up distribution channels (rules baked in)

**Why:** with conversion fixed, open channels — Discord-first, then sanctioned showcase venues. Every row carries the self-promo guardrail inline so we can't forget it at post time.

### 3a. Discord (the pivot's center of gravity)

| Task | Owner | Grounded reference | De-risk note |
| --- | --- | --- | --- |
| Create the server + channels (incl. `#integrations` so existing docs links resolve) | **You** | `docs/contributing-integrations.md:13,207` (phantom `#integrations`); reuse channel spec there | G1: open **only** with the weekly ritual scheduled + 2–3 moderators named. |
| Pre-commit the weekly ritual: "governance scenario of the week" ("would acgs-lite block this?") | **You** (run) / Claude (seed scenarios from examples) | Content hierarchy "what got blocked" (`community-roadmap.md:165-172`); `examples/maci_separation`, `examples/audit_trail` | Ghost-town mitigation. If you can't staff it weekly, delay the server (G1). |
| Recruit day-one moderators from the ranked personas | **You** | personas `community-roadmap.md:39-42`; venues `community-roadmap.md:151-159` | 2–3 people before public invite. |
| Seed GitHub Discussions (pinned Welcome + Q&A starter) so README/CONTRIBUTING links don't hit an empty room | Claude (drafts) / You (posts) | Discussions enabled, 0 posts (community-infra grounding) | G7: governance stays in Discussions; don't move the ghost-town risk from Discord to Discussions. |
| Close shipped good-first-issue **#57** linking the implementing commit | **You** | `src/acgs_lite/integrations/smolagents.py` resolves `#57` | Stale funnel entry would frustrate the first newcomer. |
| Add `.github/ISSUE_TEMPLATE/config.yml` (`blank_issues_enabled: false` + contact_links → Discord invite + Discussions) | Claude (file) / You (invite URL) | existing `.github/ISSUE_TEMPLATE/bug_report.yml` as pattern | Highest-leverage funnel fix; surfaces Discord on the New Issue chooser. |
| Update `docs/contributing-integrations.md`, `CONTRIBUTING.md`, `ROADMAP.md` "where to ask" pointers to add Discord | Claude / You (invite URL) | `CONTRIBUTING.md` (Discussions-first today), `ROADMAP.md:36-38` | G7: Discord for chat, Discussions stays for decisions; don't orphan GOVERNANCE/ROADMAP links. |

### 3b. Reddit + Show HN (sanctioned showcase, guardrails inline)

| Task | Owner | Grounded reference | De-risk note |
| --- | --- | --- | --- |
| Warm up the posting account 2–4 weeks (genuine answers in r/AI_Agents, r/LangChain, r/LocalLLaMA) | **You** | distribution-rules: 90/10 rule, karma/age gates | A fresh/low-karma account pushing a link is the exact AutoModerator/shadowban profile (verdict 1). |
| **Read live subreddit rules + pinned posts the day of posting** | **You** | verdict 1 (live rules could not be fetched; must re-check) | Rules/flair/weekly-thread cadence change without notice; r/LangChain is **restrictive**, not permissive. |
| Post to **r/AI_Agents first** (build-show framing + GIF + first-comment disclosure) | **You** | `planning/external-distribution-submissions.md` blurbs; hero GIF from P1 | G5 disclosure mandatory. r/LangChain only as value-first help, soft mention. |
| Show HN: "Show HN: acgs-lite — blocks unsafe agent actions before execution (MACI + tamper-evident audit)" linking the **repo**, not docs | **You** | wedge sentence; `pip install acgs-lite==2.10.1` | Show HN must be the runnable thing — never the docs/landing page (off-topic → flagged). Author first-comment + in-thread for 2–3h. |
| **Do not** solicit upvotes from Discord/friends; **do not** sockpuppet | **You** | G4; distribution-rules HN/Reddit prohibitions | Single "this is a shill" top comment can define the launch for a trust product. |
| Check for shadowban from a logged-out browser after each Reddit post | **You** | verdict 1 de-risking | Shadowbanned post looks normal to you, invisible to others. |

### 3c. LangChain community (venue corrected per verdict 3)

| Task | Owner | Grounded reference | De-risk note |
| --- | --- | --- | --- |
| Share the integration via **LangChain Slack/Forum** (verified-official), not an unverified "official Discord" | **You** | verdict 3 (langchain.com/join-community = Slack + Forum; Discord unverified) | Frame as contribution + working snippet, post only in showcase/vendor channel; "immediate ban for promotional content" otherwise. |

**P2 exit gate:** Discord live with a scheduled ritual + moderators · `#57` closed · `config.yml` merged · accounts warmed · r/AI_Agents + Show HN posted with disclosure.

---

## 4. P3 — Authentic star growth (no astroturfing)

**Why:** verdict 2 **confirms** authentic star asks are GitHub-AUP-compliant; the only thing that turns it into a violation is *how* the asks are sourced. Stars stay an input (G2), wired to conversion (G6).

| Task | Owner | Grounded reference | De-risk note |
| --- | --- | --- | --- |
| Keep README "Star this repo" CTA as an honest request (above-fold + repeated) | Claude | `README.md:55` | Never gate functionality/downloads behind a star (edges into incentivized). |
| Embed a star-history.com chart in README | Claude | `README.md:11` (existing badge) | Visualization only — creates no stars, triggers no rank abuse (verdict 2). |
| Pace + diversify asks across owned channels over time | **You** | verdict 2 de-risking | Avoid a single burst from new/zero-activity accounts — the pattern detectors flag for AI repos. |
| Wire every push to a conversion mechanism (a curated good-first-issue + a "what got blocked" CTA ships with each post) | Claude (issues/demo) / You (posts) | good-first-issues `#55-#61`; content hierarchy `community-roadmap.md:165-172` | G6: instrument referral → view → clone/install → issue, not just star delta. |
| Add a one-line "all our stars are organic / we comply with GitHub AUP" note to CONTRIBUTING/docs | Claude | verdict 2 de-risking | Defensible standard + reputational insurance for a trust product. |
| Periodically sanity-check star sources for unsolicited fake-star spikes | **You** | verdict 2 (third-party fake-star detectors exist) | An attacker buying fake stars to harm a rival is not your violation — but be ready to report. |
| **Prohibited (write into governance):** bought/exchanged/bot stars, star-for-star rings, reward-incentivized starring, upvote coordination | **You** | G3, G4; verdict 2 evidence | The few star behaviors the AUP names explicitly. |

**P3 exit gate:** star-history chart live · organic-stars note published · per-post conversion instrumentation defined · prohibitions documented.

---

## 5. P4 — EU AI Act timing play (correct timeline)

**Why:** a dated buying trigger no pure-guardrail competitor answers — **but the urgency hook must be accurate**, or it backfires with the exact compliance-savvy audience we target.

> **Timeline (verified — verdict 4 + research):** 2 Feb 2025 = prohibited practices + AI literacy (**live**). 2 Aug 2025 = GPAI + governance (**live**, bites model providers). **2 Aug 2026 = Article 50 transparency obligations + Commission enforcement powers go live** — this is the headline milestone for agent builders. **2 Dec 2027 = standalone Annex III high-risk** (postponed by the Digital Omnibus provisional agreement of 7 May 2026). 2 Aug 2028 = embedded-product high-risk.

| Task | Owner | Grounded reference | De-risk note |
| --- | --- | --- | --- |
| Author a flagship **EU AI Act guide** tying runtime primitives → the one-shot command → the report | Claude | `src/acgs_lite/eu_ai_act/` (Article12Logger / RiskClassifier / HumanOversightGateway); `acgs eu-ai-act ... --markdown`; harvest `docs/compliance.md`, `docs/compliance-2026.md` (fix drifted commands) | Lead with `--markdown` (works everywhere); flag `acgs-lite[pdf]` (fpdf2 not installed by default). Use **verified** commands only. |
| Anchor the hook on **Article 50 transparency**, not "high-risk deadline" | Claude (copy) / You (posts) | verdict 4: "If your agent talks to humans or generates content, you owe disclosure/marking duties from 2 Aug 2026." | **Do NOT** say "Aug 2026 high-risk crunch" — false post-Omnibus; a self-inflicted credibility wound for a compliance product. |
| Add a dated, sourced caveat + non-legal-advice disclaimer to every EU asset | Claude | verdict 4 (Omnibus provisional; OJ publication ~July 2026) | Converts the moving-target risk into a trust signal; cite Consilium/Commission/artificialintelligenceact.eu, not law-firm blogs alone. |
| CTA = run the artifact, not panic | Claude / You | `acgs assess --framework eu_ai_act`; `python examples/eu_ai_act_quickstart.py` | Value-led survives further Omnibus changes (product value is date-independent). |
| Avoid known defects in examples (don't show `spam_filter` tier; the eu-ai-act report omits `eu_ai_act` from its own framework score) | Claude | eu-ai-act-capability gaps | Use `healthcare`/`hr_recruitment` domains; explain the checklist-vs-score split in the guide. |
| Relationship play: join EU AI Pact + IAPP; pitch artificialintelligenceact.eu to feature acgs-lite | **You** | distribution-rules (EU-AI-PACT@ec.europa.eu; IAPP peer groups) | Credibility/lead play over weeks — **not** a launch-week star driver; never drop a bare product link there. |

**P4 exit gate:** flagship guide merged with verified commands + dated caveat · Article-50-anchored copy ready · no high-risk-deadline overclaims.

---

## 6. P5 — Integration guides + good-first-issue momentum

**Why:** integration guides are the #1 help-wanted (`ROADMAP.md:24`) and a standing distribution channel into each framework community; they also feed Discord "pick-a-task" onboarding.

| Task | Owner | Grounded reference | De-risk note |
| --- | --- | --- | --- |
| Finish the **LangChain** half: add a runnable `examples/` file to match `docs/guides/langchain.md` | Claude | `docs/guides/langchain.md`; `GovernanceRunnable.wrap()` (`langchain.py:41`) | No-API-key proof exists in the guide; mirror it as a runnable example. |
| Finish the **Claude** half: add a standalone guide to match the live example | Claude | `examples/gitlab_anthropic_demo.py:383,653`; `GovernedAnthropic` (`anthropic.py:452`) | Reuse simulation+live-mode pattern. |
| Use `smolagents.py` as the template for new adapter guides | Claude | `src/acgs_lite/integrations/smolagents.py` | Lazy duck-typed import + GovernedBase mixin = the canonical pattern. |
| Curate 5–10 good-first-issues continuously (seed adapter-example + doc-fix tasks; fix `GovernedAgent`→`GovernedPydanticAgent` doc bug) | Claude (drafts) / You (files) | `#55-#61`; `docs/integrations.md:20` doc bug | Net inventory is 6 after closing `#57`; keep the menu full for Discord onboarding. |
| Protect the retention levers (scheduled first, G6) | **You** | `community-roadmap.md:86-89,138-140` | ≤48h warm first response + weekly visible activity beat reach at bus factor 1. |

**P5 exit gate:** LangChain example + Claude guide merged · ≥5 good-first-issues open and current · doc bug fixed · first external contributor onboarded via Discord.

---

## 7. Sequencing rationale

- **Conversion before traffic (P1 → everything).** Driving paid attention to a README that buries proof under 50 lines of theory and offers no community on-ramp wastes the spike. The hero GIF is the one real asset gap; it gates the whole push.
- **Rules before posting (P2/P3 guardrails inline).** HN and Reddit punish coordinated upvoting and undisclosed promotion; for a *trust* product the blast radius of an astroturf accusation is existential. The self-promo and AUP rules are embedded in the task rows, not relegated to an appendix, so they can't be skipped at post time.
- **Discord with a ritual, not Discord alone (P2/G1).** The old roadmap's de-risking mechanism (weekly ritual + day-one moderators) is the *answer* to its own "premature Discord" objection — we adopt the mechanism while moving the timing.
- **Accurate urgency (P4).** The EU AI Act hook is timed but truthful (Article 50, 2 Aug 2026) — a false "high-risk deadline" would discredit us with the buyers it targets.
- **Momentum last (P5).** Integration guides + good-first-issues convert the traffic the earlier phases generate into contributors — the only thing that moves bus factor, the metric the override agrees still matters.

---

## 8. Conflict ledger (what this overrides in `planning/community-roadmap.md`)

| # | Roadmap location | Current stance | This plan |
| --- | --- | --- | --- |
| C1 | `:6-12` header / `planning/README.md` doc map | "GitHub-Discussions-first (not Discord)"; three-doc split assumes Discussions-first | Discord-first for chat; **Discussions retained for governance** (G7). Doc map updated so the override doesn't read as inconsistency. |
| C2 | `:104-108` Stage 3 "Launch Discord only now… 150–300 active users *or* a guaranteed weekly event" | Discord gated to Stage 3 | Discord launches **now**, gated instead on the **ritual + moderators** (G1) — the same de-risking, relocated. |
| C3 | `:126` channel table "Discord — Stage 3 only" | Stage-3-only row | Amend row to "Stage 0, **conditional on weekly ritual + 2–3 moderators**." |
| C4 | `:129-130` "**Hard rule:** do not launch Discord before Stage 3" | Bolded prohibition | **Retired**, replaced by the G1 conditional launch rule. |
| C5 | `:199` anti-pattern "Premature Discord" | Named anti-pattern | **Amended** to "Unstaffed Discord (no ritual/mods)" — the failure mode is *unstaffed*, not *early*. |
| C6 | `:200` anti-pattern "Star-chasing over user depth" | Named anti-pattern | **Amended**: star growth is a sequenced discovery input under G2/G6, auto-expiring at bus factor ≥ 2. |
| C7 | `:183-193` metrics ("stars… leading indicators only / not the scoreboard") | Stars demoted | Stars promoted to a **primary near-term emphasis** while bus factor + ≤48h response remain the protected north star (G2). |
| C8 | `:65-68`, `:225-230` "do before any marketing push" gate | No traffic until Discussions + good-first-issues + ladder exist | **Parallelized**: P1 conversion + P2 community-hardening run alongside the push; the spike lands on seeded Discussions + curated issues, not on nothing. |
| C9 | `ROADMAP.md:36-38` proposal link (Discussions-only) | Discussions-only inbound | Add Discord to "where to ask"; Discussions stays canonical for proposals (G7). |

---

## 9. Owner-only (publishing / account) actions

All third-party posting and account creation is **You**. Claude prepares copy/assets/issues in-repo; Claude never posts.


---

## Appendix A — Roadmap amendments (APPLIED 2026-05-31)

_These edits were **applied** on 2026-05-31 to `planning/community-roadmap.md` (A1–A7), `ROADMAP.md` (A8), and `planning/README.md` (A9), anchored to the verified current text of each file. The current/proposed pairs below are retained as the change record. One placeholder remains: `<INVITE_URL>` in `ROADMAP.md` must be replaced with the real Discord invite (a You action) before that file is committed._

### A1. `planning/community-roadmap.md:11-12 (header)`

- **Why:** The override (verdict 5, eyes-open) promotes stars to a primary near-term input; the header must reflect that without erasing the bus-factor north star, so the docs don't self-contradict.

- **Current:**

  > Stars are a *trust amplifier*; this doc treats them as a leading indicator, not the goal. The goal is a self-sustaining community of users and contributors that outlives any single maintainer.

- **Proposed:**

  > Stars are a *trust amplifier* and, per the 2026-05-31 growth-execution-plan override, a deliberate near-term discovery EMPHASIS — wired to conversion and capped so they never displace the north star. The north star remains a self-sustaining community that outlives any single maintainer (bus factor >= 2, then >= 3).

### A2. `planning/community-roadmap.md:47-49 (What kind of community)`

- **Why:** This line is the load-bearing 'Discussions-first, not Discord' statement the pivot reverses; it must be amended, not merely contradicted (gap: self-contradicting strategy docs).

- **Current:**

  > That choice dictates everything downstream: GitHub-Discussions-first (not Discord), small contribution units (rules/validators/integrations, not core-framework PRs), and evidence-driven content ("what got blocked").

- **Proposed:**

  > That choice dictates small contribution units and evidence-driven content. Channel timing is overridden by the 2026-05-31 growth-execution-plan: Discord-FIRST for real-time chat (launched with a guaranteed weekly ritual + day-one moderators), with GitHub Discussions RETAINED as the searchable system of record for governance and roadmap decisions.

### A3. `planning/community-roadmap.md:104-108 (Stage 3 — Self-sustaining)`

- **Why:** Relocates the Discord launch while preserving the roadmap's own de-risking mechanism (ritual + moderators) as the new gate — answers the ghost-town objection rather than ignoring it.

- **Current:**

  > **Launch Discord only now** — and only with a confirmed **weekly recurring ritual**... Threshold from the evidence: 150–300 active users *or* a guaranteed weekly event. Appoint 2–3 active members as moderators on day one.

- **Proposed:**

  > Discord is launched in Stage 0 per the 2026-05-31 override — NOT gated on active-user count, but gated on the SAME de-risking mechanism: a confirmed weekly recurring ritual ('governance scenario of the week' / office hours) AND 2–3 day-one moderators. If the ritual cannot be staffed weekly, the server is not opened.

### A4. `planning/community-roadmap.md:126 (channel table, Discord row)`

- **Why:** The Stage-3-only row directly contradicts the executed pivot; updating the condition from 'active users' to 'staffed ritual' keeps the credibility safeguard.

- **Current:**

  > | **Discord** | **Stage 3 only** | Below 150–300 active users (or a guaranteed weekly event), a ghost-town Discord *actively harms* credibility. Discord's own OSS directory needs 1,000 members / 1,000 stars. |

- **Proposed:**

  > | **Discord** | **Stage 0 (now), conditional** | Launch only WITH a guaranteed weekly ritual + 2–3 day-one moderators. The failure mode is an UNSTAFFED Discord, not an early one. Governance/decisions stay in GitHub Discussions. |

### A5. `planning/community-roadmap.md:129-130 (Hard rule)`

- **Why:** This bolded prohibition is the single line the pivot most directly reverses; leaving it as-is creates a self-contradicting hard rule in the repo.

- **Current:**

  > **Hard rule:** do not launch Discord before Stage 3. This is the most common, most credibility-damaging failure mode for projects this size.

- **Proposed:**

  > **Hard rule (revised 2026-05-31):** do not launch an UNSTAFFED Discord. Launching Discord early is fine and intended; launching one with no weekly ritual and no day-one moderators is the credibility-damaging failure mode to avoid.

### A6. `planning/community-roadmap.md:199-200 (anti-patterns)`

- **Why:** The pivot is, by the doc's own framing, doing these two named anti-patterns; they must be re-scoped to the actual failure modes (unstaffed, inorganic/dead-end) so the evidence-based risk analysis is answered, not ignored.

- **Current:**

  > - **Premature Discord** → ghost-town spiral; harms credibility. *Defer to Stage 3.*
  > - **Star-chasing over user depth** → vanity metric that misleads governance decisions.

- **Proposed:**

  > - **Unstaffed Discord** → ghost-town spiral; harms credibility. *Launch only with a weekly ritual + day-one moderators.*
  > - **Inorganic / dead-end star-chasing** → stars are a discovery INPUT wired to conversion (good-first-issue + demo per push) and capped at <=20% of OSS hours; never bought/exchanged/incentivized, and auto-deprioritized if contributors don't follow within 8–12 weeks.

### A7. `planning/community-roadmap.md:190-193 (metrics close)`

- **Why:** Promoting stars to a primary near-term goal requires re-baselining the metrics table while keeping the protected north star, per verdict 5's self-correcting guardrail.

- **Current:**

  > | Stars · PyPI installs · referral traffic | leading indicators only | Discovery |
  > 
  > Stars and installs are *inputs to trust*, not the scoreboard. A project with 50 engaged users filing detailed issues is healthier than one with 5,000 stars and zero contributors.

- **Proposed:**

  > | Stars · PyPI installs · referral traffic | PRIMARY near-term discovery emphasis (2026-05-31 override), wired to conversion; auto-deprioritized at bus factor >= 2 | Discovery |
  > 
  > Stars are a sequenced discovery input, not the final scoreboard: the PROTECTED north-star pair remains bus factor (-> >= 2, then >= 3) and time-to-first-response (<= 48h). A spike that doesn't convert to contributors within 8–12 weeks triggers reallocation to onboarding.

### A8. `ROADMAP.md:36-38 (Proposing roadmap changes)`

- **Why:** Public artifact currently routes inbound only to Discussions and has no Discord path; the pivot needs the on-ramp added while keeping Discussions canonical for decisions (governance-coupling de-risk, G7).

- **Current:**

  > Have an idea for a direction not listed here? Open a [Discussion](https://github.com/acgs-ai/acgs-lite/discussions) in the **Ideas** category. Significant direction changes follow the decision process in [`GOVERNANCE.md`](GOVERNANCE.md).

- **Proposed:**

  > Have an idea? Chat with us in real time on [Discord](<INVITE_URL>), or — for anything that needs a durable record — open a [Discussion](https://github.com/acgs-ai/acgs-lite/discussions) in the **Ideas** category. Significant direction changes are decided in Discussions/Issues per [`GOVERNANCE.md`](GOVERNANCE.md); Discord is for conversation, not the system of record.

### A9. `planning/README.md:13-22 (companion-doc map)`

- **Why:** The doc-relationship map must point to the new authoritative plan so the override doesn't read as an inconsistency between three Discussions-first-framed docs.

- **Current:**

  > - [`community-roadmap.md`](community-roadmap.md) — staged plan for growing contributors and community. ... - [`oss-growth-playbook.md`](oss-growth-playbook.md) — 0→1 stars/launch playbook.

- **Proposed:**

  > Add a line: '- [`growth-execution-plan.md`](growth-execution-plan.md) — ACTIVE Discord-first + active-star-growth execution plan (2026-05-31). Supersedes the channel/metric stance of community-roadmap.md; read it first for current strategy.'


---

## Appendix B — Open questions (decide before/within execution)

1. Discord staffing (G1): who are the 2–3 day-one moderators, and can the maintainer commit to running a weekly ritual indefinitely at bus factor 1? If not, the server should not open — this is the load-bearing assumption of the whole pivot.

2. Account readiness for the timed launch: is there an established (non-throwaway, sufficient-karma) Reddit account, and can the 2–4 week warm-up complete before the desired EU-AI-Act launch date? If the timeline collides, which gives — launch date or account warm-up?

3. Real Discord invite URL: README, ROADMAP.md, config.yml, and contributing docs all need the actual invite before P1/P2 merge — placeholder until the server exists.

4. Launch-date anchoring vs. Omnibus volatility: the EU AI Act Digital Omnibus is provisional (OJ publication ~July 2026). Do we anchor the campaign to a fixed date now, or gate the date on a final-check of the implementation timeline immediately before launch (recommended)?

5. GOVERNANCE.md coupling: GOVERNANCE.md routes promotions/decisions through Discussions ('announced in Discussions'). Do we add a Discord cross-post for announcements, or keep all governance announcements in Discussions only (recommended for a searchable record)?

6. Stage-3 tactics bundled with Discord: conference talks, the gamified Gandalf-style web challenge, and subsystem delegation were coupled to Discord at Stage 3. Do these move to Stage 0/1 with Discord, or stay gated by their own dependencies (e.g., delegation still needs a second reviewer first)?

7. Hero-GIF capture environment: can the GIF be captured headlessly/reliably in this environment, or does it need a human-driven terminal recording? This blocks P1 and therefore the whole push.


---

## Appendix C — Owner-only checklist (You; Claude never posts)

- [ ] Create the Discord server and its channels (including #integrations so docs/contributing-integrations.md:13,207 links resolve), and obtain the real invite URL.

- [ ] Recruit and confirm 2–3 day-one Discord moderators before any public invite (G1).

- [ ] Schedule and run the weekly Discord ritual ('governance scenario of the week' / office hours) — the ghost-town mitigation.

- [ ] Warm up the Reddit posting account for 2–4 weeks with genuine participation in r/AI_Agents, r/LangChain, r/LocalLLaMA before any link post.

- [ ] Read each subreddit's live rules + pinned posts on the day of posting (flair, weekly-thread, karma/age gates) before submitting.

- [ ] Post to r/AI_Agents (primary) with the GIF + first-comment author disclosure; post to Show HN linking the repo; manage both threads in real time for the first 2–3 hours.

- [ ] Share the integration on LangChain's verified-official Slack/Forum (showcase/vendor channel only), framed as a contribution — not the unverified 'official LangChain Discord'.

- [ ] After each Reddit post, check for a shadowban from a logged-out browser; if shadowbanned, appeal via modmail rather than reposting.

- [ ] Re-verify a clean-venv `pip install acgs-lite==2.10.1` + hero demo on a fresh machine before any distribution push.

- [ ] Close shipped good-first-issue #57 linking the smolagents implementing commit; file/curate the remaining good-first-issues.

- [ ] Paste the real Discord invite URL into README, ROADMAP.md, .github/ISSUE_TEMPLATE/config.yml, CONTRIBUTING.md, and docs/contributing-integrations.md (Claude leaves placeholders).

- [ ] Join the EU AI Pact (email EU-AI-PACT@ec.europa.eu) and IAPP peer/affinity groups; pitch artificialintelligenceact.eu's editors to feature acgs-lite — relationship plays, no bare product links.

- [ ] Final-check the EU AI Act implementation timeline / Official Journal status immediately before publishing any dated campaign asset, and again right before send.

- [ ] Commit and push the P1–P5 repo changes (the orchestrator decides when to commit/push, per repo policy).
