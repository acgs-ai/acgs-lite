export const meta = {
  name: 'acgs-growth-plan',
  description: 'Build a grounded Discord-first + star-growth execution plan for acgs-lite, overriding the prior Discussions-first roadmap',
  phases: [
    { title: 'Ground', detail: 'parallel repo readers + web researchers establish reality' },
    { title: 'Verify', detail: 'adversarially de-risk the riskiest strategy assumptions' },
    { title: 'Synthesize', detail: 'compose the sequenced execution-plan document' },
  ],
}

const REPO = '/home/martin/Documents/acgs-lite'

const FACTS = [
  'VERIFIED FACTS (already confirmed by the orchestrator - treat as ground truth, do NOT re-derive, but DO cite/extend):',
  '- acgs-lite v2.10.1 is published to PyPI AND on main AND tagged v2.10.1 - fully in sync. NO version skew. README hero demo runs against the published package.',
  '- README.md (~680 lines) already has: a runnable 20-second hero demo (Constitution.from_yaml_str + GovernanceEngine.validate(..., strict=False).valid), badges, a "Community favorites" section, a 3-minute path, and a "Star this repo" CTA. There is a COMMENTED-OUT placeholder for docs/assets/basic-governance-hero.gif (the one real conversion gap).',
  '- A grounded community roadmap exists at planning/community-roadmap.md (dated 2026-05-30): metrics = 2 stars, 0 forks, 0 external contributors (bus factor = 1), GitHub Discussions DISABLED, 39 views/11 uniques. It DELIBERATELY chose GitHub-Discussions-first over Discord and treats stars as a leading indicator, NOT the goal.',
  '- THE USER IS NOW OVERRIDING THAT: the new strategy is Discord-first + active star-growth. This is a deliberate, eyes-open pivot. The plan must COMMIT to it (not relitigate it) while honestly de-risking it.',
  '- Correct API: Constitution.from_yaml_str(str) for YAML strings; from_yaml(path) for files. Rule schema uses text:/keywords:/patterns:. engine.validate() raises ConstitutionalViolationError by default; strict=False returns a ValidationResult with .valid + .violations.',
  "- 'acgs assess --framework eu-ai-act' EXISTS (src/acgs_lite/commands/assess.py); examples/compliance_eu_ai_act/ and examples/eu_ai_act_quickstart.py exist; 18-framework compliance mapping exists.",
  '- A smolagents governance adapter shipped on the current branch (src/acgs_lite/integrations/smolagents.py) - usable as the template pattern for new integration guides.',
  '- The wedge sentence the project uses: "acgs-lite blocks unsafe agent actions BEFORE execution, enforces separation of powers with MACI, and leaves a tamper-evident audit trail."',
  '- Repo path: ' + REPO + '. GitHub: github.com/dislovelhl/acgs-lite.',
].join('\n')

const GROUNDING_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['area', 'findings', 'gaps', 'reusable_assets'],
  properties: {
    area: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['claim', 'evidence'],
        properties: {
          claim: { type: 'string' },
          evidence: { type: 'string', description: 'file:line, command output, or URL backing the claim' },
        },
      },
    },
    gaps: { type: 'array', items: { type: 'string' }, description: 'what is missing / blocking that the plan must address' },
    reusable_assets: { type: 'array', items: { type: 'string' }, description: 'concrete files/commands/docs the plan can reuse, with paths' },
  },
}

const WEB_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['topic', 'findings', 'actionable_dos', 'actionable_donts', 'risks'],
  properties: {
    topic: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['claim', 'source_url', 'confidence'],
        properties: {
          claim: { type: 'string' },
          source_url: { type: 'string' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
      },
    },
    actionable_dos: { type: 'array', items: { type: 'string' } },
    actionable_donts: { type: 'array', items: { type: 'string' } },
    risks: { type: 'array', items: { type: 'string' } },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['claim', 'verdict', 'reasoning', 'evidence', 'de_risking'],
  properties: {
    claim: { type: 'string' },
    verdict: { type: 'string', enum: ['confirmed', 'partly-true', 'refuted', 'uncertain'] },
    reasoning: { type: 'string' },
    evidence: { type: 'array', items: { type: 'string' }, description: 'sources / URLs / quotes' },
    de_risking: { type: 'array', items: { type: 'string' }, description: 'concrete mitigations so the plan can proceed safely' },
  },
}

const DOC_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['document', 'proposed_roadmap_amendments', 'open_questions', 'orchestrator_only_actions'],
  properties: {
    document: { type: 'string', description: 'the FULL markdown of planning/growth-execution-plan.md' },
    proposed_roadmap_amendments: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['location', 'current', 'proposed', 'why'],
        properties: {
          location: { type: 'string', description: 'file + section/line of the existing roadmap to change' },
          current: { type: 'string' },
          proposed: { type: 'string' },
          why: { type: 'string' },
        },
      },
    },
    open_questions: { type: 'array', items: { type: 'string' } },
    orchestrator_only_actions: { type: 'array', items: { type: 'string' }, description: 'steps only the human can do (publishing, account actions)' },
  },
}

phase('Ground')

const repoReaders = [
  {
    label: 'ground:strategy-override',
    prompt: FACTS + '\n\nRead these files IN FULL and extract the current community/growth strategy so we can OVERRIDE it to Discord-first + star-growth:\n- ' + REPO + '/planning/community-roadmap.md\n- ' + REPO + '/planning/oss-growth-playbook.md (if present)\n- ' + REPO + '/ROADMAP.md\n- ' + REPO + '/GOVERNANCE.md\n- ' + REPO + '/planning/next-milestones.md (if present)\n\nYour job: pinpoint EVERY statement that commits to (a) Discussions-over-Discord, (b) stars-as-leading-indicator-not-goal, (c) contributor-funnel-first sequencing - because we are overriding those. Quote each with file + line number so amendments can be authored precisely. Also capture: stated audience priority, the wedge sentence, named stages, any metrics. Set area=strategy-to-override. In gaps, list what the override breaks or leaves unresolved. In reusable_assets, list parts of the existing roadmap that SURVIVE the override (audience, wedge, governance ladder).',
  },
  {
    label: 'ground:readme-conversion',
    prompt: FACTS + '\n\nRead ' + REPO + '/README.md IN FULL. Map the onboarding/conversion surface a new visitor hits: hero demo, badges, quickstart paths, Community favorites, the Star this repo CTA wording, and the hero-GIF placeholder. Identify the single biggest CONVERSION gap (something that would lose a visitor we drove from Discord/Reddit). Also note install-promise accuracy. area=readme-conversion. reusable_assets = exact example dirs/paths the README links. gaps = what blocks high conversion of inbound traffic.',
  },
  {
    label: 'ground:eu-ai-act-capability',
    prompt: FACTS + '\n\nInventory what acgs-lite can do TODAY for EU AI Act / compliance, by reading:\n- ' + REPO + '/src/acgs_lite/commands/assess.py\n- ' + REPO + '/examples/compliance_eu_ai_act/ (list + read key files)\n- ' + REPO + '/examples/eu_ai_act_quickstart.py\n- ' + REPO + '/docs/compliance-2026.md and ' + REPO + '/docs/compliance.md\nDetermine the exact user-facing capability (commands, outputs, frameworks covered) we can package as a flagship EU AI Act compliance layer guide. area=eu-ai-act-capability. reusable_assets=concrete commands+paths. gaps=what is missing for a polished flagship guide.',
  },
  {
    label: 'ground:integrations-inventory',
    prompt: FACTS + '\n\nList ' + REPO + '/src/acgs_lite/integrations/ and cross-reference ' + REPO + '/examples/. Produce: which agent frameworks have adapters (langchain, anthropic/claude, openai, smolagents, a2a, crewai, autogen, semantic-kernel, etc.), and which adapters ship WITHOUT a runnable example. This grounds (a) the LangChain + Claude integration guides and (b) good first issue seeds. area=integrations. findings=one per adapter (covered? has example?). reusable_assets=adapter paths + the smolagents template. gaps=adapters lacking examples/guides.',
  },
  {
    label: 'ground:community-infra',
    prompt: FACTS + '\n\nEstablish the GitHub community-infrastructure state that the funnel depends on. Read ' + REPO + '/.github/ (issue templates, discussion templates, config), ' + REPO + '/CONTRIBUTING.md. Run (best-effort, report if it fails): "gh issue list --repo dislovelhl/acgs-lite --label \'good first issue\' --state open" and "gh label list --repo dislovelhl/acgs-lite" and "gh api repos/dislovelhl/acgs-lite --jq .has_discussions". Determine: are Discussions enabled now? Do good-first-issue ISSUES actually exist behind the label, or just the label? area=community-infra. gaps=funnel blockers. reusable_assets=existing templates/labels.',
  },
]

const webResearch = [
  {
    label: 'ground:distribution-rules',
    prompt: FACTS + '\n\nUse web search (load WebSearch/WebFetch via ToolSearch: query "select:WebSearch,WebFetch"). Research the ACTUAL self-promotion rules and norms (2025-2026) for distributing an open-source dev-infra project:\n- r/LangChain and r/AI_Agents subreddit rules on self-promotion / showcase posts (find the rules pages / wiki).\n- The official LangChain Discord: does it have a showcase / community-projects channel; self-promo norms.\n- Hacker News Show HN guidelines.\n- 1-2 EU AI compliance / AI governance communities worth posting in.\nGoal: concrete do/dont so we distribute without getting banned or flagged as spam. topic=distribution-rules. Populate actionable_dos / actionable_donts / risks thoroughly.',
  },
  {
    label: 'ground:eu-ai-act-timeline',
    prompt: FACTS + '\n\nUse web search (ToolSearch "select:WebSearch,WebFetch"). Establish the PRECISE EU AI Act enforcement timeline and verify whether "August 2026 enforcement hits hard" is accurate for AI AGENT builders. Pin down what applied Feb 2025 (prohibited practices), Aug 2025 (GPAI / governance), Aug 2026 (?), Aug 2027 (?). Cite official sources (EUR-Lex, European Commission, artificialintelligenceact.eu). Be precise about which obligations land in/around Aug 2026 and whether they bite agent builders or only GPAI/high-risk providers. topic=eu-ai-act-timeline. The plan timing claim must be CORRECT, not vibes.',
  },
  {
    label: 'ground:competitive-wedge',
    prompt: FACTS + '\n\nUse web search (ToolSearch "select:WebSearch,WebFetch"). Map competing/adjacent open-source agent guardrail/governance projects: Guardrails AI, NVIDIA NeMo Guardrails, Meta Llama Guard, Invariant Labs, Lakera, LangChain native guardrails, and any agent governance / policy enforcement tools. For each: one-line positioning + rough GitHub star magnitude + what they DO NOT do. Then articulate the defensible wedge acgs-lite can own (fail-closed BEFORE execution + MACI separation-of-powers + tamper-evident audit receipts + multi-framework compliance mapping). topic=competitive-wedge. actionable_dos=positioning/messaging moves; risks=where competitors are stronger.',
  },
]

const groundingThunks = []
for (const r of repoReaders) {
  groundingThunks.push(() => agent(r.prompt, { label: r.label, phase: 'Ground', schema: GROUNDING_SCHEMA }))
}
for (const w of webResearch) {
  groundingThunks.push(() => agent(w.prompt, { label: w.label, phase: 'Ground', schema: WEB_SCHEMA }))
}

const grounding = (await parallel(groundingThunks)).filter(Boolean)
log('Ground complete: ' + grounding.length + '/' + groundingThunks.length + ' agents returned')

phase('Verify')

const RISK_CLAIMS = [
  'Project self-promotion is PERMITTED on r/LangChain and r/AI_Agents (via showcase threads, flair, or weekly self-promo threads) without violating subreddit rules or risking a ban.',
  'Soliciting GitHub stars (ask friends to star, a Star this repo CTA, star-history charts) is acceptable and does NOT violate GitHub Acceptable Use Policies on inauthentic/automated/astroturfed activity - provided asks are authentic.',
  'The official LangChain Discord has an appropriate venue (e.g. a showcase/community-projects channel) for sharing a third-party governance library, and doing so is tolerated.',
  'There is a material EU AI Act enforcement milestone in/around August 2026 that affects AI AGENT builders specifically, strong enough to anchor a timed launch campaign - versus the milestone mainly hitting GPAI/high-risk providers on a different date.',
  'For a dev-infra OSS project at bus-factor=1 with 2 stars, making STAR GROWTH the primary near-term metric is a sound strategy - versus it being a vanity metric that starves the real bottleneck (contributor acquisition). Steelman BOTH sides and state how to de-risk the override.',
]

const verdictThunks = RISK_CLAIMS.map((claim, i) => () =>
  agent(
    FACTS + '\n\nYou are an adversarial verifier. Use web search where useful (ToolSearch "select:WebSearch,WebFetch"). Try HARD to REFUTE or qualify this claim before accepting it; default to skepticism. The user has chosen this strategy, so your job is NOT to veto it - it is to surface exactly what is true, what is risky, and how to proceed SAFELY.\n\nCLAIM TO VERIFY:\n' + claim + '\n\nReturn a verdict, evidence (with sources), and concrete de_risking mitigations the execution plan must include.',
    { label: 'verify:' + (i + 1), phase: 'Verify', schema: VERDICT_SCHEMA },
  )
)

const verdicts = (await parallel(verdictThunks)).filter(Boolean)
log('Verify complete: ' + verdicts.length + '/' + RISK_CLAIMS.length + ' verdicts')

phase('Synthesize')

const synthPrompt = FACTS +
  '\n\nYou are the lead author. Using ALL grounding and verification results below, write planning/growth-execution-plan.md - a sequenced, concrete execution plan that COMMITS to the user chosen override: Discord-first distribution + active star-growth, timed to the EU AI Act window. The user chose this knowingly; do NOT relitigate it - execute it well and de-risk it honestly.\n\nGROUNDING (repo + web reality):\n' +
  JSON.stringify(grounding) +
  '\n\nVERIFICATION VERDICTS (de-risking the chosen strategy):\n' +
  JSON.stringify(verdicts) +
  '\n\nHARD REQUIREMENTS for the document:\n' +
  '1. Open with a TL;DR + an explicit "Strategic override" callout: this supersedes the 2026-05-30 Discussions-first roadmap; state the bet, the accepted risk (esp. the star-vanity-vs-bus-factor tension from verdict 5), and the de-risking guardrails we adopt.\n' +
  '2. A "Grounded current state" section (real metrics + what is already built - pull from grounding, cite paths).\n' +
  '3. The re-sequenced plan as PHASES, Discord-first. Suggested spine (adapt to grounding): (P1) README final polish + hero GIF - the one conversion gap, because you do not drive traffic to a repo that does not convert; (P2) stand up distribution channels (Discord presence, Reddit showcase posts, Show HN) WITH the exact self-promo guardrails from the distribution-rules research baked in; (P3) authentic star-growth tactics (NOT astroturfing - honor the GitHub-AUP de-risking from verdict 2); (P4) EU AI Act timing play using the CORRECT timeline from research (do not overstate Aug 2026 if research says otherwise) + the existing acgs assess capability; (P5) integration guides (LangChain + Claude, reusing the smolagents adapter) + seed good-first-issues for momentum.\n' +
  '4. Every phase: a task table with columns Task | Owner (Claude vs You) | Grounded reference (real path/command from grounding ONLY - invent NO paths) | De-risk note. Mark publishing/account actions as Owner=You.\n' +
  '5. A "Conflict ledger" section listing what this overrides in planning/community-roadmap.md, feeding proposed_roadmap_amendments.\n' +
  '6. A short "Sequencing rationale" explaining why this order (conversion-before-traffic, rules-before-posting).\n' +
  '7. Keep it tight and skimmable - tables and bullets over prose. Cite only paths/commands present in the grounding.\n\n' +
  'Also return: proposed_roadmap_amendments (precise edits to planning/community-roadmap.md / ROADMAP.md to reflect the override - current vs proposed text), open_questions, and orchestrator_only_actions (publishing steps only the human can do).'

const doc = await agent(synthPrompt, { label: 'synthesize-plan', phase: 'Synthesize', schema: DOC_SCHEMA })

return {
  document: doc.document,
  proposed_roadmap_amendments: doc.proposed_roadmap_amendments,
  open_questions: doc.open_questions,
  orchestrator_only_actions: doc.orchestrator_only_actions,
  groundingCount: grounding.length,
  verdicts: verdicts,
}
