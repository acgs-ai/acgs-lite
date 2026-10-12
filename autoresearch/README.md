# Research regression assets

This directory restores the test dependencies omitted when acgs-lite was extracted
from the monorepo. `PROVENANCE.json` records the original commit and SHA-256
checksums of the exact historical constitution, scenarios, annotations, candidate
pack, and paper extraction maps. These fixtures are unchanged; the 3,290-row frozen
scenario corpus has not been redefined or replaced with newly invented data.

The paper maps are historical research notes, not newly verified source claims.
Candidate scenarios remain separate from the frozen corpus. The promotion patch
is retained as a fixture and has not been applied. The raw dataset samples under
`tests/fixtures/raw_datasets/` are adapter test inputs, not proof of a live dataset
benchmark or performance on medical, financial, or other real-world decisions.

Run from the repository root in the development environment:

```bash
python -m autoresearch.run_raw_dataset_manifest --manifest tests/fixtures/raw_datasets/sample_manifest.json
python -m autoresearch.eval_rules --output-dir /tmp/acgs-rule-evaluation
```

The raw-case evaluator now calls `GovernanceEngine` against the frozen constitution.
The original script inferred predictions from synthesis profiles and even fell
back to the expected label. That shortcut is removed. Current sample-manifest
accuracy is 10/24, not the historical artificial 24/24: the frozen constitution
does not implement all synthetic adapter scenarios. Keep these errors visible;
changing benchmark labels or rules to make them pass would invalidate comparison.

The historical three-way benchmark taxonomy maps nonblocking warning findings to
`escalate`. This means a review-worthy benchmark outcome; it does not claim that
the runtime blocked execution or delivered an escalation. The restored harness
reads both `violations` and `warnings` from the current result API.

The full rule-evaluation command above currently reports 3,297 passing and 17
failing cases out of 3,314, with zero errors or skips, and exits 1. The frozen
3,290 scenarios pass; the additional historical adversarial sidecar contains 16
decision mismatches and one rule-trigger assertion mismatch. These are measured
limitations, not skipped tests or successful benchmark results. The CLI now
returns nonzero for mismatches, errors, skipped cases, or an empty evaluation.

Optional experiment runners and prior execution logs are not restored. This work
restores regression dependencies, not an active optimization experiment.
