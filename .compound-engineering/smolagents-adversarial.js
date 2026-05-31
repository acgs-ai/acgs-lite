export const meta = {
  name: 'smolagents-adversarial',
  description: 'Adversarially hunt for new/remaining fail-opens introduced by the smolagents review fixes',
  phases: [{ title: 'Attack', detail: '4 skeptics, distinct angles' }],
}

const REPO = '/home/martin/Documents/acgs-lite'

const SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['angle', 'found_issue', 'severity', 'detail', 'repro_or_evidence'],
  properties: {
    angle: { type: 'string' },
    found_issue: { type: 'boolean', description: 'true if a real bypass/regression was found' },
    severity: { type: 'string', enum: ['none', 'low', 'medium', 'high', 'critical'] },
    detail: { type: 'string', description: 'what you found, or why the code is sound after trying to break it' },
    repro_or_evidence: { type: 'string', description: 'concrete repro (code/command + observed result) or file:line evidence' },
  },
}

const COMMON = 'You are an adversarial security reviewer for ACGS-Lite, a fail-CLOSED agent-governance library. The branch feature/smolagents-integration just fixed a 30-finding review (docs/reviews/smolagents-branch-review.md). Your job: TRY HARD to break the fixes — find a NEW or REMAINING fail-open (dangerous code reaching execution) or a regression. Read the current code and, where useful, run a quick repro with the venv: `cd ' + REPO + ' && OPENAI_API_KEY=test-key-for-unit-tests ANTHROPIC_API_KEY=test-key-for-unit-tests .venv/bin/python -c "..."`. Be concrete and skeptical; default to assuming a bypass exists until you have evidence it does not. YOU MUST call the StructuredOutput tool with your result. Files: ' + REPO + '/src/acgs_lite/integrations/smolagents.py, ' + REPO + '/src/acgs_lite/integrations/base.py, ' + REPO + '/src/acgs_lite/engine/code_analysis.py, ' + REPO + '/src/acgs_lite/engine/core.py.'

const angles = [
  { label: 'attack:m6-exec-paths', q: 'M6 angle: GovernedPythonExecutor gates __call__ and a hardcoded set {run, execute, run_code} via __getattr__. Find a code-EXECUTION entry point that bypasses _gate: e.g. other execution method names on real smolagents executors, properties, attribute access that triggers execution, send_variables/state mutation that later executes, or accessing the inner executor directly. Does _gate run BEFORE delegation in every execution path? Try to reach inner(...) with dangerous code without raising.' },
  { label: 'attack:failclosed-falseneg', q: 'Fail-closed angle: code_analysis.analyze() now returns blocking CODE-UNPARSEABLE/CODE-ANALYSIS-ERROR/CODE-TOO-LARGE/CODE-UNANALYZABLE instead of []. (a) Can dangerous code STILL slip through to valid=True (false negative) — e.g. a payload ast.parse accepts but ast.walk under-inspects, or a dangerous construct not in any check? (b) Does fail-closed now WRONGLY block legitimate non-code natural-language text? Trace as_engine_validator trigger gate (action_type==code) and which seams pass that context vs not. Verify non-code text never reaches analyze().' },
  { label: 'attack:m7-enforcement', q: 'M7 angle: custom validators now run unconditionally (core.py ~683 and ~1078) instead of being skipped when a CRITICAL string rule already matched. Verify this did NOT (a) change any previously-ALLOWED action to blocked, (b) duplicate/inflate audit entries or total_validations, (c) break the enforcement decision (the CRITICAL short-circuit must still raise/block exactly once). Run a repro mixing a CRITICAL keyword rule + a code action and inspect the result + audit.' },
  { label: 'attack:output-failopen', q: 'Output-governance angle: _coerce_answer_text returns "" on total coercion failure, and final_answer_check returns True (ACCEPT) when text is empty. Is that a fail-open — a violating answer accepted because coercion produced ""? Also scrutinize _validate_nonstrict returning None on HALT → final_answer_check returns False but step_callback just continues: any path where a BLOCK/HALT on produced content is silently accepted/executed? And the alias_map/partition logic in _check_call for edge cases (multi-dot, shadowed names).' },
]

phase('Attack')
const results = (await parallel(angles.map(a => () =>
  agent(COMMON + '\n\nYOUR ANGLE:\n' + a.q, { label: a.label, phase: 'Attack', schema: SCHEMA })
))).filter(Boolean)

return { results }
