# Research Implementation: Automated CLI Evaluation Harnesses for Constitutional AI Governance

**Branch:** feat/cli-anything-harness-refine
**Constitutional Hash:** 608508a9bd224290

## Source Inventory (Grounded in Code)

| Source | Type | Core Claim | Relevance |
|---|---|---|---|
| S1: Bai et al. (Anthropic, 2022) | Paper | Constitutional AI reduces harm via AI feedback | Defines rule paradigm |
| S2: Chen et al. (OpenAI, 2021) | Paper | pass@k for code functional correctness | Metric schema |
| S3: Jimenez et al. (2023) | Repo | SWE-bench CLI for real GitHub issues | Harness pattern |
| S4: UK AISI Inspect (2024) | Repo | Modular LLM eval with logging | Gov-grade analog |
| S5: NIST AI RMF 1.0 (2023) | Standard | Tamper-evident audit trails required | Audit standard |
| S6: EU AI Act (2024/1689) | Regulation | Logs and monitoring for high-risk AI | Legal mandate |
| S7: Lee et al. (Google, 2023) | Paper | RLAIF scales RLHF alignment | Auto feedback |
| S8: ACGS-lite (2026) | Repo | MACI roles + bundle binding | Implementation target |

## Code-Grounded Extraction

### E1: Constitutional Principles (S1)
- **Method:** RL with AI feedback and constitutional critique
- **Dataset:** HH RLHF + constitutional prompts
- **Key Result:** CAI lowers harm with fewer human labels
- **Limitation:** Dialogue only; no code or CLI harness
- **Confidence:** 0.95

### E2: pass@k Metrics (S2)
- **Method:** Unbiased estimator for k samples vs unit tests
- **Dataset:** 164 HumanEval Python problems
- **Key Result:** pass@1/pass@100 baselines for Codex
- **Limitation:** Python only; no governance
- **Confidence:** 0.95

### E3: SWE-bench Harness (S3)
- **Method:** Dockerized env + test execution
- **Dataset:** 2294 SWE-bench issues
- **Key Result:** GPT-4 resolves 14%; fully reproducible
- **Limitation:** No MACI or constitutional checks
- **Confidence:** 0.92

### E4: Inspect Framework (S4)
- **Method:** Task/solver/score/log architecture
- **Dataset:** Built-in tasks
- **Key Result:** Model-agnostic evals with transcript logs
- **Limitation:** No MACI or constitutional engine
- **Confidence:** 0.88

### E5: NIST AI RMF (S5)
- **Method:** Framework analysis
- **Dataset:** NIST AI RMF 1.0
- **Key Result:** Traceability and regular validation mandatory
- **Limitation:** Not prescriptive on CLI or benchmarks
- **Confidence:** 0.90

### E6: EU AI Act (S6)
- **Method:** Regulatory review (Articles 8-11)
- **Dataset:** EU AI Act 2024/1689
- **Key Result:** Logs and post-market monitoring required
- **Limitation:** No pass@k or harness architecture
- **Confidence:** 0.85

### E7: RLAIF (S7)
- **Method:** RLAIF vs RLHF comparison
- **Dataset:** Google internal + public PM data
- **Key Result:** RLAIF matches RLHF on auto metrics
- **Limitation:** Auto metrics miss code nuance
- **Confidence:** 0.88

### E8: ACGS-lite MACI (S8)
- **Method:** Runtime role checks + bundle binding
- **Dataset:** src/acgs_lite/maci.py, src/acgs_lite/audit.py
- **Key Result:** Proposer/validator/auditor with SHA256 chain hashes
- **Limitation:** No CLI eval yet; WIP branch
- **Confidence:** 0.90

## Gap Analysis

### G1: No benchmark combines constitutional rules with pass@k code eval
- **Type:** benchmark
- **Evidence:** E1 (CAI is dialogue-only), E2 (pass@k is Python-only)
- **Impact:** Cannot quantitatively compare constitutional coding assistants
- **Cost:** low | **Impact:** high | **Priority:** 1

### G2: No CLI harness validates MACI separation-of-powers
- **Type:** product
- **Evidence:** E4 (Inspect has no MACI), E8 (ACGS has MACI but no eval harness)
- **Impact:** Prevents governance drift and role bypass
- **Cost:** medium | **Impact:** high | **Priority:** 2

### G3: Missing audit schema linking evals to constitutional bundles
- **Type:** governance
- **Evidence:** E5 (NIST wants traceability), E6 (EU wants docs), E8 (ACGS has audit.py)
- **Impact:** Required for NIST/EU interoperability
- **Cost:** medium | **Impact:** medium | **Priority:** 3

### G4: No public dataset of constitutional violations in code repair
- **Type:** research
- **Evidence:** E1 (CAI violations are dialogue), E3 (SWE-bench has no rule violations)
- **Impact:** Blocks training violation-aware models
- **Cost:** low | **Impact:** medium | **Priority:** 4

### G5: Cost and latency models for governance evals undefined
- **Type:** commercial
- **Evidence:** E3 (SWE-bench is expensive), E7 (RLAIF is cheaper but code nuance)
- **Impact:** SaaS pricing needs predictable economics
- **Cost:** low | **Impact:** medium | **Priority:** 5

## Micro-Experiments (Implemented Below)

| ID | Gap | Hypothesis | Status |
|---|---|---|---|
| X1 | G1 | Constitutional filter reduces pass@1 not pass@100 | Script created |
| X2 | G1 | Security SWE-bench issues harder under rules | Script created |
| X3 | G2 | MACI reduces invalid decisions by >50% | Script created |
| X4 | G2 | MACI adds <100ms latency per episode | Script created |
| X5 | G3 | ACGS logs export to PROV-JSON with >95% coverage | Script created |
| X6 | G3 | Diff audit detects drift between model versions | Script created |
| Real LLM Harness | G1/G3 | Core invariant can be evaluated on real providers with real `AuditLog` evidence | Harness created; no empirical artifact yet because API keys are external |

## Real LLM + Real AuditLog Harness

`research/real_llm/` adds an opt-in runner for real-provider experiments. It
records each provider execution through the real `acgs_lite.audit.AuditLog`,
writes per-experiment `*_results.json`, exports audit JSON/JSONL evidence, and
updates `research/results/real_llm/summary.json`.

The harness enforces the honesty floor before any artifact may be marked
`simulated:false`:

- at least two distinct non-simulated providers must actually execute;
- `sample_count` must meet the configured minimum, default `30`;
- the recognized dataset adapter must load rather than fall back;
- deterministic mock providers and unavailable providers force
  `simulated:true`;
- `--fail-if-simulated` exits non-zero when those conditions are not met.

Real runs require external credentials and optional SDKs, for example:

```bash
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
export OPENAI_MODEL=...
export ANTHROPIC_MODEL=...

python -m research.real_llm.runner \
  --provider openai:${OPENAI_MODEL} \
  --provider anthropic:${ANTHROPIC_MODEL} \
  --dataset humaneval \
  --limit 30 \
  --fail-if-simulated
```

No real-provider artifact is committed here. The committed
`research/results/real_llm/summary.json` is a placeholder marked
`simulated:true` and documents the missing credential-gated step.

## 14-Day Study Plan

| Day | Objective | Tasks | Deliverable |
|---|---|---|---|
| 1 | Install deps | pip install ACGS-lite, inspect_ai, datasets | env_log.txt |
| 2 | HumanEval baseline | Run pass@1/pass@100 | baseline.json |
| 3 | Integrate rules | Write constitution.yaml, patch harness | constitution.yaml |
| 4 | Execute X1 | Run HumanEval with ACGS rules | x1_results.json |
| 5 | SWE subset | Filter 20 secret-pattern issues | swe_subset.json |
| 6 | Execute X2 | Run SWE-lite with secrets rule | x2_results.json |
| 7 | Synthetic data | Create 20 approval scenarios | synthetic_decisions.json |
| 8 | MACI sim | Subclass roles + SQLite sink | maci_sim.py |
| 9 | Execute X3 | Run 100 trials single vs MACI | x3_results.json |
| 10 | Inspect bridge | Write inspect_bridge wrapper | inspect_bridge.py |
| 11 | Execute X4 | Measure latency on 50 samples | x4_results.json |
| 12 | PROV exporter | Map ACGS audit to PROV-JSON | prov_export.py |
| 13 | Execute X5/X6 | Validate coverage and diff audit | x5_x6_results.json |
| 14 | Final compile | Run revision checklist | final_report.json |

## Revision Checklist

- [ ] All sources have stable URLs (arXiv, NIST, GitHub)
- [ ] Search queries yield >=5 results each
- [ ] Extraction rows link to source IDs (E* -> S*)
- [ ] Gap evidence matches extraction IDs (G* -> E*)
- [ ] Experiments list versions (Docker/model/commit)
- [ ] Thresholds cite baselines (S2/S3)
- [ ] Compliance aligns with EU AI Act / NIST RMF
- [ ] Self-feedback names at least one conflicting source

## Self-Feedback

1. **Over-relies on Anthropic/OpenAI papers.** Severity: medium. Add AI2 or MPI-SWS sources. Recheck: S1, S2.
2. **ACGS branch is WIP; latency claims extrapolated.** Severity: high. Run on target hardware before finalizing X4. Recheck: S8.
3. **pass@k as governance metric is analogical, not causal.** Severity: medium. Add source linking correctness to policy adherence, or downgrade confidence. Recheck: S2, S5.
