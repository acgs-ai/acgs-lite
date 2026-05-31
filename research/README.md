# ACGS-lite Research Harness

Branch: `feat/cli-anything-harness-refine`
Constitutional Hash: `608508a9bd224290`

## Files

| File | Purpose |
|---|---|
| `RESEARCH.md` | Full research plan: sources, gaps, 14-day schedule, self-critique |
| `run_all_experiments.py` | Master runner: executes all 6 micro-experiments |
| `x1_constitutional_humaneval.py` | Constitutional filter impact on pass@k (G1) |
| `x2_swe_secrets.py` | SWE-bench security issues under rules (G1) |
| `x3_maci_decisions.py` | MACI reduces invalid decisions (G2) |
| `x4_maci_latency.py` | MACI latency per episode (G2) |
| `x5_prov_export.py` | PROV-JSON audit export coverage (G3) |
| `x6_diff_audit.py` | Model drift detection via diff audit (G3) |
| `constitution_secrets.json` | "no-secrets-in-code" constitutional rule |

## Quick Start

```bash
# Run individual experiments
python x3_maci_decisions.py --trials 100 --seed 42
python x4_maci_latency.py --episodes 50 --seed 42
python x5_prov_export.py --events 50 --seed 42
python x6_diff_audit.py --prompts 10 --seed 42
python x2_swe_secrets.py --trials 20 --seed 42
python x1_constitutional_humaneval.py --num-samples 100 --constitution constitution_secrets.json

# Run all experiments + produce summary.json
python run_all_experiments.py --seed 42
```

## Experiment Results (seed=42)

These are simulation outputs from deterministic harnesses. Do not cite them as
empirical benchmarks.

### X1 — Constitutional pass@k
- SIMULATION (seed=42), not empirical benchmark: pass@1 baseline: 0.63, filtered: 0.63 (delta 0.0)
- SIMULATION (seed=42), not empirical benchmark: pass@100 baseline: 0.80, filtered: 0.80 (delta 0.0)
- SIMULATION (seed=42), not empirical benchmark: Status: PASS (thresholds met, but proxy problems don't trigger secret filter — needs real HumanEval)

### X2 — SWE Secrets Resolution
- SIMULATION (seed=42), not empirical benchmark: Overall delta: -5% (within 15% threshold)
- SIMULATION (seed=42), not empirical benchmark: Secret issues harder: 71% vs 86% resolve rate
- SIMULATION (seed=42), not empirical benchmark: Status: PASS

### X3 — MACI Decision Quality
- SIMULATION (seed=42), not empirical benchmark: Single-agent false approvals: 9
- SIMULATION (seed=42), not empirical benchmark: MACI false approvals: 0 (100% reduction, >50% threshold)
- SIMULATION (seed=42), not empirical benchmark: Disagreement rate: 13% (below 20% threshold)
- SIMULATION (seed=42), not empirical benchmark: Status: PARTIAL (reduction passes, disagreement misses)

### X4 — MACI Latency
- SIMULATION (seed=42), not empirical benchmark: Median delta: ~0.84ms (well below 100ms)
- SIMULATION (seed=42), not empirical benchmark: p99 delta: ~3.3ms (well below 200ms)
- SIMULATION (seed=42), not empirical benchmark: Status: PASS

### X5 — PROV-JSON Export
- SIMULATION (seed=42), not empirical benchmark: 50 entries mapped, 0 errors
- SIMULATION (seed=42), not empirical benchmark: Coverage: 110% (all fields + extra prov annotations)
- SIMULATION (seed=42), not empirical benchmark: Status: PASS

### X6 — Model Drift Detection
- SIMULATION (seed=42), not empirical benchmark: Drift detected: 3/10 prompts
- SIMULATION (seed=42), not empirical benchmark: Explainability: 100%
- SIMULATION (seed=42), not empirical benchmark: Status: PASS

## Compliance Anchors

- **NIST AI RMF 1.0**: Audit logs require traceability and tamper-evidence; X5 is a simulation harness for PROV mapping.
- **EU AI Act 2024/1689**: Technical docs + post-market monitoring required; X2/X6 are simulation templates, not empirical benchmarks.
- **MACI Separation of Powers**: `maci.py` enforces proposer/validator/auditor roles; X3/X4 estimate effectiveness and cost in simulation only.

## Next Steps

1. Replace proxy HumanEval with real `datasets` library HumanEval (Day 2-4)
2. Implement Inspect bridge wrapper for real LLM eval (Day 10-11)
3. Dockerize SWE-bench lite subset for real patch validation (Day 5-6)
4. Integrate real ACGS-lite `AuditLog` backend in X5 (vs simulated)
5. Add AI2 / MPI-SWS sources to balance Anthropic/OpenAI bias
