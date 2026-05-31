# Community Roadmap for `acgs-lite`

Date: 2026-05-30
Status: proposed plan

> Companion docs — read together, do not duplicate:
> - [`oss-growth-playbook.md`](./oss-growth-playbook.md) — **stars & launch** (0 → 1,000 stars, conversion, launch bursts)
> - [`next-milestones.md`](./next-milestones.md) — **product** roadmap (releases, API stability)
> - **This doc** — **community**: contributors, retention, governance, channels, venues, DevRel.
>
> Stars are a *trust amplifier* and — per the 2026-05-31 [`growth-execution-plan.md`](./growth-execution-plan.md)
> override — a deliberate near-term discovery **emphasis**, wired to conversion and capped so they never displace
> the north star. The north star remains a self-sustaining community of users and contributors that outlives any
> single maintainer (bus factor ≥ 2, then ≥ 3).

---

## 1. Where we actually are (grounded)

| Signal | Value (2026-05-30) | Reading |
| --- | --- | --- |
| GitHub stars | 2 | Pre-traction |
| Forks | 0 | No external code activity yet |
| Watchers | 1 | No notification audience |
| External contributors | 0 (solo + dependabot/Copilot bots) | **Bus factor = 1** |
| Open human issues | 0 | No inbound discussion surface |
| Repo traffic (recent window) | 39 views / 11 uniques | Discovery is the bottleneck |
| GitHub Discussions | **disabled** | No async community surface exists |
| CONTRIBUTING / COC / SECURITY | present | Onramp files exist |
| GOVERNANCE.md / ROADMAP.md | **absent** | No public roles or contribution ladder |
| Package quality | polished README, PyPI, CI, 18-framework compliance | **Product is launch-ready; community scaffolding is not** |

**Diagnosis:** This is a *0 → 1 community* problem, not an optimization problem. The product is more mature
than the community around it. The single highest-risk fact is **bus factor = 1**: every roadmap goal below
is ultimately about reducing that number.

---

## 2. Strategy: who, what wedge, what kind of community

**Who we are building for (in priority order):**
1. **AI agent builders** shipping LLM agents to production who need a runtime guardrail (LangChain / AutoGen / CrewAI / MCP users).
2. **AI security & red-team practitioners** (OWASP GenAI, MLSecOps) who evaluate defensive tooling.
3. **AI governance / compliance engineers** facing EU AI Act, NIST AI RMF, ISO 42001 obligations.

**The community wedge** (one sentence, reused everywhere): *"`acgs-lite` blocks unsafe agent actions
**before execution**, enforces separation of powers with MACI, and leaves a tamper-evident audit trail."*

**What kind of community** — a **developer-infrastructure** community, not a research forum. That choice
dictates small contribution units (rules/validators/integrations, not core-framework PRs) and evidence-driven
content ("what got blocked"). **Channel timing is overridden** by the 2026-05-31
[`growth-execution-plan.md`](./growth-execution-plan.md): **Discord-first** for real-time chat (launched with a
guaranteed weekly ritual + 2–3 day-one moderators), with **GitHub Discussions retained** as the searchable
system of record for governance and roadmap decisions.

**Underserved positioning the evidence surfaced (use it):** none of the comparable projects
(NeMo Guardrails, Guardrails AI, Llama Guard, Garak, Inspect) own the intersection of **runtime
pre-execution enforcement + tamper-evident audit + EU AI Act / NIST mapping**. The EU AI Pact (230+
enterprise signatories) is a buyer community actively seeking exactly this. That is our differentiated
community claim.

---

## 3. The roadmap — four stages, gated by health not vanity

Each stage has an **entry gate** (don't start the next stage's tactics until met), a **focus**, and
**exit metrics**. Targets are calibrated to the CHAOSS Starter Project Health model and contributor-funnel
research, not aspiration.

### Stage 0 — Foundations (Weeks 1–4) · *do before any marketing push*
**Gate to enter:** now.
**Focus:** make the project *contributable and conversational* before driving traffic. A viral spike that
lands on a project with no Discussions, no good-first-issues, and no contribution ladder is wasted.

- Enable **GitHub Discussions** (Q&A, Ideas, Show-and-tell, Announcements categories).
- Add **`GOVERNANCE.md`** + a contribution ladder in `CONTRIBUTING.md` (contributor → reviewer → maintainer) *before* the first external contributor arrives.
- Add **`ROADMAP.md`** (or link `next-milestones.md`) so newcomers see the project is alive and directed.
- File **5–10 genuine "good first issues"** — CHAOSS definition: completable by a newcomer in < 1 day, full context in the issue body, no tribal knowledge required.
- Write a **"minimum viable maintenance" statement** in `CONTRIBUTING.md` (what you will/won't respond to, expected response time) to pre-empt burnout.
- Confirm cold-start UX: `pip install acgs-lite` → first blocked-action demo in < 5 minutes (already strong; verify on a clean machine).

**Exit metrics:** Discussions live · 8+ good-first-issues open · GOVERNANCE.md + contribution ladder merged · response-time policy published.

### Stage 1 — Ignition (Months 1–3) · *first humans in the door*
**Gate to enter:** Stage 0 complete.
**Focus:** first external contributors and the first content that compounds. Depth over reach.

- Ship the **first "what got blocked" demo post** (standalone gist/blog: a real agent action denied, audit trail visible). This is *the* format that travels in security circles (Lakera Gandalf, Guardrails validators).
- Ship the **first integration guide: LangChain + `acgs-lite`** — highest-leverage because it is a standing distribution channel into the largest agent-builder community.
- Seed the three highest-density venues *with content, not announcements* (see §6): OWASP GenAI Slack `#project-top10-for-llm`, MLSecOps community, LessWrong/AI Alignment Forum.
- **Respond to every first-time issue/PR within 48h** — even "read this, will address by <date>." Research finding: second-contribution likelihood is driven by first-response quality. This is the single highest-leverage retention action for a solo maintainer.
- Weekly visible activity: a release, changelog entry, or merged PR every week (sparse contribution graphs deter contributors).

**Exit metrics (0–6mo CHAOSS-realistic):** 3–5 external contributors · 5–15 Discussion threads · ≤ 48h time-to-first-response · 1 release/month · first integration guide published.

### Stage 2 — Compounding (Months 4–12) · *turn users into a flywheel*
**Gate to enter:** ≥ 3 external contributors AND ≤ 48h response time sustained.
**Focus:** make contribution small and repeatable; get third-party validation.

- **Lower the contribution unit** to a "rule pack / constitution template" model (the Guardrails Hub lesson): one community-contributed constitution or integration = one small PR, not a framework change. Each one is also a new distribution node.
- Publish 2–3 more **integration guides** (AutoGen, CrewAI, MCP) — each opens a new community.
- Publish a **compliance-mapping doc** ("`acgs-lite` → NIST AI RMF 1.1–4.2", "→ EU AI Act Art. 9/14") as repo-resident markdown — ranks for compliance search and signals seriousness to procurement.
- Get **one third-party tutorial/endorsement** (OWASP contributor, MLSecOps podcast guest, or an Inspect AI contributor). External endorsement > self-authored content (the Ruff/Astral and Guardrails/DeepLearning.AI lesson: high-status adoption validates faster than marketing).
- Target **adoption by 3–5 visible dependent projects** (the Ruff playbook) — get named agent projects to wire `acgs-lite` in.
- Promote the first repeat contributor to **reviewer** (exercise the ladder; start lowering bus factor).

**Exit metrics (6–18mo):** 50–200 stars · 1–2 repeat contributors · ≥ 1 reviewer besides the founder · 3+ integration guides · 1 conference talk or podcast appearance · **Contributor Absence Factor ≥ 2**.

### Stage 3 — Self-sustaining (Months 12–36) · *community outlives the founder*
**Gate to enter:** ≥ 1 reviewer besides founder AND a recurring community ritual exists.
**Focus:** distributed ownership, governance maturity, and (only now) real-time chat.

- **Discord is launched in Stage 0** per the 2026-05-31 [`growth-execution-plan.md`](./growth-execution-plan.md) override — **not** gated on active-user count, but gated on the **same** de-risking mechanism: a confirmed **weekly recurring ritual** ("governance scenario of the week" / office hours) **and 2–3 day-one moderators**. If the ritual cannot be staffed weekly, the server is not opened. *(Original Stage-3 threshold, kept for context: 150–300 active users or a guaranteed weekly event.)*
- Conference presence: submit talks to **DEF CON AI Village, RSA (MLSecOps track), PyCon/EuroPython, AI safety summits**.
- Delegate **subsystem ownership** (integrations, compliance mappings, Rust extension) to named maintainers — bus factor ≥ 3 is the target.
- Mature governance toward a meritocratic model (CNCF/Apache-style); consider Linux Foundation **AI Alliance** alignment given the governance positioning.
- Consider a **gamified standalone demo** (a "would `acgs-lite` block this agent action?" web challenge) — the Lakera Gandalf pattern: viral distribution + crowdsourced real-world governance scenarios + enterprise inbound.

**Exit metrics (18–36mo):** 500+ stars · defined, *exercised* contribution ladder · GitHub Discussions as primary async channel · **Contributor Absence Factor ≥ 3** · no release gap > 3 months.

---

## 4. Channel plan (and what NOT to launch yet)

| Channel | When | Why |
| --- | --- | --- |
| **GitHub Discussions** | **Stage 0 (now)** | Co-located with code, async, searchable, zero overhead, developer-primary. Correct for a small dev-infra project at any size. |
| **GitHub Issues (good-first-issues)** | **Stage 0** | Primary user→contributor conversion mechanism for infra projects. |
| Newsletter / changelog cadence | Stage 1 | Weekly visible activity beats monthly blogs for community signal. |
| **Slack (invite-only)** | Stage 2, optional | The Inspect AI model — power users/contributors first; scales for async technical depth before opening broadly. |
| **Discord** | **Stage 0 (now), conditional** | Launch **only with** a guaranteed weekly ritual + 2–3 day-one moderators (2026-05-31 override). The failure mode is an *unstaffed* Discord, not an early one. Governance/decisions stay in GitHub Discussions. |
| Discourse | Not planned (500+ users) | High moderation overhead; only when Discussions search becomes a real bottleneck. |

**Hard rule (revised 2026-05-31):** do not launch an *unstaffed* Discord. Launching Discord early is fine and
intended; launching one with no weekly ritual and no day-one moderators is the credibility-damaging failure
mode to avoid.

---

## 5. Contributor funnel (user → contributor → maintainer)

The mechanics, in order of leverage:

1. **Good-first-issues, curated continuously** — completable in < 1 day, full context, labelled. Keep 5–10 open at all times.
2. **Warm, fast first response** — every first-time PR gets a constructive reply within 48h. Highest-leverage retention lever; negative/ignoring first responses are the documented #1 reason contributors don't return.
3. **Small contribution units** — rule packs, constitution templates, integration adapters, compliance mappings. Not "rewrite the matcher."
4. **Visible contribution ladder** — `contributor → reviewer → maintainer`, written in `GOVERNANCE.md`, with the criteria for each step. Publish *before* contributors arrive.
5. **Recognition** — all-contributors-style acknowledgment, release-note shout-outs, "used in production at…" table in the README (already scaffolded).
6. **Delegate early** — treat handing off a subsystem as a *goal*, not a someday-milestone. Bus factor is the north-star health metric.

---

## 6. Venues & communities to engage (named — content, not spam)

Engage with *useful content* ("what got blocked" demos, integration guides), never drive-by promotion.

**Highest-density first three (Stage 1):**
- **OWASP GenAI Security Project** — Slack `#project-top10-for-llm`, bi-weekly calls, ~8,000 members. Join via genai.owasp.org. Direct fit (OWASP LLM Top 10 coverage is already in the README).
- **MLSecOps Community** — community.mlsecops.com + podcast. Premier AI/ML security practitioner hub; pitch a "what got blocked" demo or podcast appearance.
- **AI Alignment Forum / LessWrong** — high-signal long-form; the *constitutional AI* framing resonates here.

**Secondary (Stage 1–2):**
- Inspect AI Slack (frontier-lab + safety-institute researchers) · EleutherAI Discord (OSS AI early adopters) · r/ControlProblem · ENAIS (European AI safety) · EU AI Pact Pillar I webinars (enterprise compliance buyers).

**Conferences (Stage 2–3):** DEF CON AI Village · RSA (AI/MLSecOps track) · PyCon US / EuroPython (Python distribution) · NeurIPS/ICLR safety workshops · CHAOSScon (community-health practitioners).

---

## 7. Content & DevRel engine

Content hierarchy by evidenced conversion, highest first:

1. **"What got blocked" demos** — real agent action denied + audit trail. The share-driving format for security audiences. Consider a recurring monthly "what our users blocked this month" aggregate digest (the Cloudflare/Fail2Ban transparency-report pattern; aggregate block data is non-sensitive but instructive).
2. **Integration guides** — one per framework (LangChain → AutoGen → CrewAI → MCP). Each is a permanent distribution channel into that framework's community.
3. **Compliance-mapping docs** — repo-resident markdown mapping controls to NIST AI RMF / EU AI Act / ISO 42001. Enterprise top-of-funnel; no comparable project has published this cleanly.
4. **Third-party tutorials** — convince *one* visible practitioner to write the tutorial. Worth more than ten self-authored posts.
5. **AI-discoverability formatting** — every doc page opens with "What does this do? When do you use it?" (FAQ-first), which measurably increases LLM-answer citation.

**Cadence rule:** weekly *visible* GitHub activity (release / changelog / merged PR) matters more than a monthly blog. The contribution graph is a passive trust signal.

---

## 8. Metrics & health (CHAOSS, not vanity)

Track these monthly. **Bold = north star.**

| Metric | Target | Source model |
| --- | --- | --- |
| **Contributor Absence (bus) factor** | → ≥ 3 by Stage 3 | CHAOSS |
| Time to first response (issues/PRs) | ≤ 48h (≤ 2 business days) | CHAOSS |
| Change-request closure ratio | ~parity, no growing backlog | CHAOSS |
| Release frequency | no gap > 3 months | CHAOSS |
| External contributors | 3–5 (6mo) → repeat contributors (18mo) | Contributor funnel |
| First-contribution → second-contribution rate | rising | Empirical OSS research |
| Discussion threads / monthly active participants | growing | Engagement |
| Stars · PyPI installs · referral traffic | **primary near-term discovery emphasis** (2026-05-31 override), wired to conversion; auto-deprioritized at bus factor ≥ 2 | Discovery |

Stars are a *sequenced discovery input*, not the final scoreboard: the **protected north-star pair** remains
bus factor (→ ≥ 2, then ≥ 3) and time-to-first-response (≤ 48h). A spike that doesn't convert to contributors
within 8–12 weeks triggers reallocation to onboarding. (A project with 50 engaged users filing detailed issues
is still healthier than one with 5,000 stars and zero contributors.)

---

## 9. Anti-patterns to avoid (each cost a comparable project dearly)

- **Unstaffed Discord** → ghost-town spiral; harms credibility. *Launch only with a weekly ritual + day-one moderators.*
- **Inorganic / dead-end star-chasing** → stars are a discovery **input** wired to conversion (a good-first-issue + demo ship with each push) and capped at ≤ 20% of OSS hours; never bought/exchanged/incentivized, and auto-deprioritized if contributors don't follow within 8–12 weeks.
- **Ignoring / harshly criticizing first contributors** → documented #1 reason contributors don't return. *48h warm response, always.*
- **No written governance from day one** → bottlenecks and founder burnout as the project scales. *Ship GOVERNANCE.md in Stage 0.*
- **Solo-maintainer burnout** → 44% of departing maintainers cite burnout. *Define minimum-viable-maintenance; delegate early.*
- **Marketing before the cold-start works** → a viral spike on a rough install experience is wasted. *Verify < 5-min first demo before any push.*

---

## 10. First 30 days — concrete checklist

> All are Stage 0 / early Stage 1. None requires spend. Items map to existing repo gaps found on 2026-05-30.

- [ ] Enable GitHub Discussions (Q&A · Ideas · Show-and-tell · Announcements).
- [ ] Add `GOVERNANCE.md` with the `contributor → reviewer → maintainer` ladder + decision process.
- [ ] Add a contribution-ladder section + "minimum viable maintenance" / response-time policy to `CONTRIBUTING.md`.
- [ ] Add `ROADMAP.md` (or link `next-milestones.md`) at repo root.
- [ ] File 8 "good first issues" with full context (rule packs, an integration adapter, doc FAQs, a test).
- [ ] Verify clean-machine cold start: `pip install acgs-lite` → blocked-action demo < 5 min.
- [ ] Draft + publish the first **"what got blocked"** demo post.
- [ ] Draft the **LangChain + `acgs-lite`** integration guide.
- [ ] Join OWASP GenAI Slack, MLSecOps community, AI Alignment Forum — observe first, then share the demo post.
- [ ] Set a personal SLA: triage every new issue/PR within 48h.

---

## Single best insight

The product is ahead of the community. The fastest path to a *large* community is not more reach — it is
**making the project contributable and conversational (Stage 0) before driving traffic**, then relentlessly
converting the first handful of users into the first handful of contributors with sub-48h warm responses and
small, well-scoped contribution units. Everything else compounds from a bus factor that climbs above 1.
