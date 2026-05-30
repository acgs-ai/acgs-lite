# OSS Growth Playbook for `acgs-lite`

Date: 2026-04-09

## Why this exists

`acgs-lite` is technically real, publishable, and credible enough for promotion, but it is still early in social proof and discovery.

Observed live repo state at research time:
- GitHub stars: 2
- forks: 0
- watchers: 0
- open issues: 0
- repo age: very new

That means this is a **0 → 1 traction problem**, not a late-stage optimization problem.

## Executive takeaway

The fastest path to traction is not "more features."
It is:

1. make the repo convert better,
2. define one hero story,
3. create a concentrated launch window,
4. keep visible weekly activity after launch.

For `acgs-lite`, the best hero story is not generic governance theory. It is:

**"This package blocks unsafe agent actions before execution, with audit evidence and separation of powers."**

That is concrete, demoable, and legible to both developers and buyers.

---

## Current strengths

### The repo already has enough substance to launch
- clear positioning near the top of the README
- working package name and PyPI presence
- framework extras for OpenAI, Anthropic, MCP, LangChain, AutoGen, A2A
- multiple examples already exist
- CI/release posture is becoming credible
- docs surface is broad enough to support deeper evaluation

### The repo already contains launch material, just not shaped correctly
There are already examples for:
- basic governance
- MACI separation
- audit trail
- MCP integration
- compliance/EU AI Act

That means the problem is not lack of material. The problem is lack of a **single obvious first proof path**.

---

## Main weaknesses blocking traction

### 1. Above-the-fold conversion still needs proof density
The README is stronger than before, but the top section still lives or dies on proof.

Highest-value elements near the top:
- visual proof artifact (GIF / screenshot / architecture card)
- explicit star CTA
- one obvious canonical first demo
- one "why now" line for agent infrastructure teams

### 2. Example surface is broad but not curated for conversion
There are many examples, but a new visitor does not instantly know:
- which one proves the core value fastest,
- which one is the safest first run,
- which one maps to real production adoption.

### 3. No launch system is visible yet
Right now the repo is available, but not clearly arranged for:
- a 48-hour public launch burst,
- Hacker News / Reddit / X distribution,
- GitHub Trending velocity,
- follow-on weekly momentum.

### 4. No visible social proof loop yet
At 2 stars and no issue/discussion activity, the repo still looks pre-traction.
That is normal, but it means every public touchpoint must work harder.

---

## Hero narrative

Use this as the core repo and launch message:

> `acgs-lite` is the governance layer between your LLM agent and production. It blocks unsafe actions before execution, enforces separation of powers with MACI, and leaves tamper-evident audit trails.

That message is better than broader claims because it is:
- concrete,
- technically legible,
- easy to demonstrate,
- defensible in comments.

---

## Highest-priority execution sequence

## Phase 1, conversion assets

### A. Add one proof artifact above the fold
Best option:
- short terminal GIF of a blocked unsafe action, followed by audit output

Status:
- README placement prepared
- capture plan drafted
- asset still needs to be produced

Good alternatives:
- minimal sequence diagram: request → governance engine → block/allow → audit log
- animated MCP governance demo

Best recommendation:
- make the GIF the first proof asset
- make the diagram the second proof asset

### B. Add explicit star CTA near the top of the README
Use simple language, no hype.
Example:

> If this helps you build safer agents, please star the repo. It materially helps early discovery.

### C. Curate exactly three canonical examples
Do not lead with the full example sprawl. Lead with three.

Recommended canonical examples:
1. **Blocked action demo**
   - show an unsafe request being denied
2. **Audit trail demo**
   - show evidence and tamper checks
3. **MCP governance server demo**
   - show how this becomes shared infrastructure

These map to:
- immediate intuition,
- trust/compliance value,
- platform story.

### D. Add one opinionated "start here" path
At the top of examples and README:
- Step 1: run blocked-action demo
- Step 2: inspect audit trail
- Step 3: try MCP mode

That sequence tells the story instead of making users infer it.

---

## Phase 2, launch preparation

### Required launch assets
Before public push, have these ready:

1. **Hero GIF**
2. **README top-section patch**
3. **Three canonical examples clearly named**
4. **One launch post draft**
5. **One technical article/tutorial**
6. **One HN title + body**
7. **Two Reddit post variants**
8. **Issue templates and discussion prompts**

### Launch angle options
Pick one primary angle only.

#### Best primary angle
**Open-source governance layer for LLM agents**

#### Good secondary angles
- MACI for agent execution safety
- auditability and compliance for production agents
- MCP-compatible policy enforcement

Do not launch with all angles equally. That muddies the story.

---

## Phase 3, 48-hour launch window

### Day 0, ignition
Goal: first 100–300 stars from real existing network and direct outreach.

Actions:
- direct-message trusted technical contacts individually
- ask only people likely to genuinely care
- do not spray low-signal audience pools
- ensure English-first public launch surface if global credibility matters most

### Day 1, public burst
Within a tight 24–48 hour window:
- ship a meaningful tagged release
- publish GitHub release notes
- post HN with technical framing
- post 1–2 targeted Reddit submissions
- post X/thread or LinkedIn technical summary if useful
- publish or cross-link one tutorial/article

### Day 2, comment war room
For 24 hours after public launch:
- answer every meaningful comment quickly
- clarify positioning without defensiveness
- collect objections for README/FAQ patches
- patch documentation the same day if confusion repeats

That responsiveness is part of the product signal.

---

## Phase 4, weekly cadence after launch

The repo should look alive every week.

Minimum visible cadence:
- 1 release or release candidate per week
- 1 content artifact per week
- issue replies within 24 hours when possible
- README/example improvements driven by repeated questions

Examples of weekly content:
- OpenAI governed example walkthrough
- MCP governance server tutorial
- "what got blocked and why" demo note
- EU AI Act / audit trail use-case post

---

## Concrete repo changes to make next

### README changes
1. add hero GIF above the fold
2. add explicit star CTA near the top
3. add "Start here in 3 minutes"
4. add one canonical blocked-action demo snippet near the top
5. keep compliance table lower, not as the first proof asset

Status on this list:
- 2, 3, and 4 are now in place
- 1 is prepared but waiting on the actual GIF asset
- 5 should be preserved during future README edits

### Example changes
1. rename or promote one demo as the default proof path
2. make one no-API-key blocked-action demo extremely obvious
3. ensure output screenshots/GIF source from that demo
4. add an examples decision table: prove block / prove audit / prove infrastructure

### Community/repo hygiene changes
1. add issue templates if not present
2. enable Discussions if useful
3. create a lightweight roadmap or "next milestones" note
4. keep release notes crisp and concrete

---

## Metrics that actually matter

Primary:
- stars
- star velocity during launch window
- README to example-run conversion
- PyPI installs
- issue/discussion activity

Secondary:
- forks
- contributors
- traffic from HN/Reddit/X
- docs visits
- number of users who make it through first demo

Do not treat stars as the only KPI.
For this repo, stars are mostly a **trust amplifier**.

---

## 0 → 1,000 stars milestone map

### 0 → 50
- fix README conversion
- prepare proof asset
- get first real external reactions

### 50 → 200
- direct network ignition
- launch canonical demo
- collect and patch objections fast

### 200 → 500
- coordinated public burst
- secure first meaningful forum traction
- improve README based on comments

### 500 → 1,000
- Trending becomes plausible if burst is concentrated enough
- weekly cadence begins to matter more than launch novelty
- examples and docs should widen slightly after the hero path works

---

## Best immediate next moves

1. patch README for proof + CTA
2. choose and polish one blocked-action demo as the hero example
3. generate a short terminal GIF from that demo
4. prepare launch copy for HN, Reddit, and one article/tutorial
5. set a deliberate 48-hour launch window around a meaningful version tag

## Best single insight

`acgs-lite` does not need more abstract claims. It needs a **proof-first growth surface**: one convincing demo, one clear story, one concentrated launch, then visible weekly maintenance.
