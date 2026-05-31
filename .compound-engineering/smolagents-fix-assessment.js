export const meta = {
  name: 'smolagents-fix-assessment',
  description: 'Map each of the 30 smolagents branch-review findings to its current code state (done/partial/missing)',
  phases: [
    { title: 'Assess', detail: 'parallel readers cross-reference findings vs current code' },
  ],
}

const REPO = '/home/martin/Documents/acgs-lite'
const REVIEW = REPO + '/docs/reviews/smolagents-branch-review.md'

const STATUS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['bucket', 'findings'],
  properties: {
    bucket: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'status', 'evidence', 'remaining_work'],
        properties: {
          id: { type: 'string', description: 'finding id e.g. H1, M2, L6, T1' },
          status: { type: 'string', enum: ['done', 'partial', 'missing', 'n/a'] },
          evidence: { type: 'string', description: 'current file:line + what the code does now' },
          remaining_work: { type: 'string', description: 'exact remaining change needed, or "none"' },
        },
      },
    },
  },
}

const COMMON = 'You are assessing whether in-progress fixes on branch feature/smolagents-integration have addressed specific review findings. Read the full review for context: ' + REVIEW + '. Then read the CURRENT state of the listed source file(s) and, for EACH finding id in your bucket, determine status: "done" (fully fixed + matches the review\'s suggested fix intent), "partial" (some but not all of the fix present), "missing" (not addressed), or "n/a" (not applicable). Give concrete evidence (current file:line and what the code does NOW, not what the review said). For remaining_work, state the EXACT change still needed (function, line, logic) or "none". Be rigorous and skeptical — verify by reading the actual current code, do not assume the WIP fixed it. This is governance-critical fail-closed code; a wrong "done" is dangerous.'

const buckets = [
  { label: 'assess:A-executor', files: [REPO + '/src/acgs_lite/integrations/smolagents.py'],
    ids: 'H1 (strict=False executor gate fail-open: __call__ must raise/force-strict before delegating), M4 (wrap non-list hook sequences fail-open), M6 (__getattr__ forwards inner executor run/execute methods ungoverned), M8 (consistent agent_id scheme across seams), L6 (build_governed_code_agent cannot configure code_validator/allowlist), L7 (analyze_code=False silent governance reduction), L8 (wrap() hook dedup/idempotency)' },
  { label: 'assess:B-failclosed', files: [REPO + '/src/acgs_lite/engine/code_analysis.py'],
    ids: 'H2 (RecursionError/MemoryError escapes analyze() guard; must fail closed + size cap), H3 (unparseable code returns [] = fail-open; must emit blocking CODE-UNPARSEABLE when action_type==code), L4 (pre-parse size bound), L5 (non-str actions raise TypeError / bytes path; add isinstance guard)' },
  { label: 'assess:C-importchecks', files: [REPO + '/src/acgs_lite/engine/code_analysis.py'],
    ids: 'M2 (from X import member never inspects member names for private/dunder/critical), M3 (relative-import node.level ignored, absolute allowlist mis-applied), L2 (getattr/setattr/delattr WARN-only + string-literal dunder targets invisible), L3 (dangerous-call detection name-bound, alias-evaded), L12 (private C-accelerator modules bypass CRITICAL tier; root excluded from private scan)' },
  { label: 'assess:D-hooks', files: [REPO + '/src/acgs_lite/integrations/base.py', REPO + '/src/acgs_lite/integrations/smolagents.py'],
    ids: 'M1 (non-blocking hooks raise on HALT; _validate_nonstrict must catch ConstitutionalViolationError and return None), M5 (final_answer_check raises when answer __str__ raises; guard str() coercion), L9 (final_answer str() coercion lets structured content bypass matching), L10 (non-HALT BLOCK on output advisory-only), L11 (step/final seams pass no context so AST validator never fires on produced content)' },
  { label: 'assess:E-core', files: [REPO + '/src/acgs_lite/engine/core.py'],
    ids: 'M7 (custom-validator skip-if-CRITICAL gate drops AST findings from audit trail; collect unconditionally, short-circuit only for enforcement decision)' },
  { label: 'assess:F-lazyimport', files: [REPO + '/src/acgs_lite/integrations/smolagents.py'],
    ids: 'CK-001/L1 (import smolagents at module load inside try/except contradicts docstring; use importlib.util.find_spec)' },
  { label: 'assess:G-tests', files: [REPO + '/tests/test_smolagents_integration.py', REPO + '/tests/test_code_analysis.py'],
    ids: 'T1 (final_answer_check rejection path return False untested), T2 (MEDIUM->WARN->non-blocking through strict executor untested: assert no raise + inner IS called), T3 (as_engine_validator exception-safety through closure untested: bad syntax with action_type==code returns []). ALSO check for regression tests covering H1 (strict=False bypass now raises), H2/H3 (deeply-nested + unparseable now blocks), M1 (workflow_action=halt rule does not crash hooks), M2 (from x import _priv / __import__)' },
  { label: 'assess:H-docs', files: [REPO + '/examples/ai-agent-instructions.md', REPO + '/docs/research/smolagents-adaptation.md'],
    ids: 'L13/docs-parity (ai-agent-instructions.md references nonexistent ValidationResult.decision ~line 38; should use action_taken / violations[0].rule_id), docstring-parity (smolagents.py module docstring claims no import at load)' },
]

phase('Assess')

const thunks = buckets.map(b => () =>
  agent(
    COMMON + '\n\nBUCKET: ' + b.label + '\nFILE(S) TO READ (current state): ' + b.files.join(', ') +
    '\n\nFINDINGS TO ASSESS:\n' + b.ids,
    { label: b.label, phase: 'Assess', schema: STATUS_SCHEMA }
  )
)

const results = (await parallel(thunks)).filter(Boolean)

return { results }
