"""X3: MACI reduces invalid decisions by >50%.

Hypothesis: 3-role MACI (proposer/validator/auditor) catches >50% of
invalid decisions that a single-agent would approve.

Metrics:
  - false_approval reduction >= 50%
  - disagree rate >= 20%

Failure: False approval unchanged or latency > 500ms.

Command:
  python x3_maci_decisions.py --trials 100 --seed 42
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any


def _simulation_metadata(seed: int) -> dict[str, object]:
    return {
        "label": f"SIMULATION (seed={seed}), not empirical benchmark",
        "seed": seed,
        "empirical_benchmark": False,
    }


def _make_scenario(rng: random.Random, index: int) -> dict[str, Any]:
    """Generate a synthetic governance decision scenario."""
    # 30% of scenarios are actually bad (contain secret or destructive action)
    is_bad = rng.random() < 0.3
    action = rng.choice(
        [
            "deploy to production",
            "read user profile",
            "delete all records",
            "export audit log",
            "rotate API key",
            "modify billing rate",
            "truncate database",
            "query metrics",
            "grant admin access",
            "send notification",
        ]
    )
    if is_bad:
        action = rng.choice(
            [
                "delete all records",
                "truncate database",
                "grant admin access",
                "self-validate output",
                "bypass validation checks",
                "disable audit logging",
            ]
        )
    return {
        "id": f"scenario-{index}",
        "action": action,
        "is_bad": is_bad,
    }


def single_agent_decide(scenario: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    """Single agent: occasionally misses bad actions."""
    is_bad = scenario["is_bad"]
    # Single agent detects bad with 70% accuracy
    detected = rng.random() < 0.7 if is_bad else True
    return {
        "approved": not is_bad or not detected,
        "detected": detected,
        "false_positive": not is_bad and not detected,
        "false_negative": is_bad and not detected,
    }


def maci_decide(scenario: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    """3-role MACI: proposer suggests, validator checks, auditor observes."""
    is_bad = scenario["is_bad"]
    # Proposer: just suggests (no decision power)
    proposer_flag = is_bad and rng.random() < 0.6  # proposer may self-report

    # Validator: stronger detection (85%) if independent
    validator_detected = is_bad and rng.random() < 0.85

    # Auditor: catch anything missed (extra 10% on what validator missed)
    auditor_detected = is_bad and not validator_detected and rng.random() < 0.10

    detected = validator_detected or auditor_detected or proposer_flag
    approved = not is_bad or not detected

    return {
        "approved": approved,
        "detected": detected,
        "proposer_flag": proposer_flag,
        "validator_detected": validator_detected,
        "auditor_detected": auditor_detected,
        "false_positive": not is_bad and not detected,  # actually not a FP in this model
        "false_negative": is_bad and not detected,
        "disagreement": is_bad and (proposer_flag != validator_detected),
    }


def run_trials(num_trials: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    scenarios = [_make_scenario(rng, i) for i in range(num_trials)]

    single_results = [single_agent_decide(s, rng) for s in scenarios]
    maci_results = [maci_decide(s, rng) for s in scenarios]

    single_false_approvals = sum(1 for r in single_results if r["false_negative"])
    maci_false_approvals = sum(1 for r in maci_results if r["false_negative"])
    disagreements = sum(1 for r in maci_results if r["disagreement"])

    reduction = 0.0
    if single_false_approvals > 0:
        reduction = (single_false_approvals - maci_false_approvals) / single_false_approvals

    return {
        "simulation": _simulation_metadata(seed),
        "trials": num_trials,
        "seed": seed,
        "single_false_approvals": single_false_approvals,
        "maci_false_approvals": maci_false_approvals,
        "reduction_ratio": reduction,
        "disagreements": disagreements,
        "disagreement_rate": disagreements / num_trials,
        "pass": {
            "reduction_ge_50": reduction >= 0.50,
            "disagreement_ge_20": (disagreements / num_trials) >= 0.20,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="X3: MACI decision quality")
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default="x3_results.json")
    args = parser.parse_args()

    result = run_trials(args.trials, args.seed)
    Path(args.output).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
