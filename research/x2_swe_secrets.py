"""X2: Security SWE-bench issues harder under constitutional rules.

Hypothesis: SWE-bench issues with secret patterns are harder to resolve
when a "no secrets in code" constitutional rule is active.

Metrics:
  - resolution_delta <= 15% drop

Failure: Resolution drop >25% or Docker failures >30%.

This is a proxy script using simulated patch correctness since real
SWE-bench requires Docker and long execution times.

Command:
  python x2_swe_secrets.py --trials 20 --seed 42
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


def _make_issue(rng: random.Random, index: int) -> dict[str, Any]:
    """Generate a simulated SWE-bench-like issue."""
    # 40% of issues involve secret/credential handling
    guarded_case = rng.random() < 0.4
    repo = rng.choice(["django", "flask", "requests", "pytest", "numpy"])
    scenario = rng.choice(
        ["security-case-a", "security-case-b", "security-case-c", "security-case-d"]
        if guarded_case
        else [
            "correctness-case-a",
            "correctness-case-b",
            "correctness-case-c",
            "correctness-case-d",
        ]
    )
    return {
        "id": f"issue-{index}",
        "repo": repo,
        "scenario": scenario,
        "guarded_case": guarded_case,
    }


def _resolve_without_rules(issue: dict[str, Any], rng: random.Random) -> bool:
    """Simulate resolution without constitutional rules."""
    # Base resolve rate: 75%
    base = 0.75
    # Secret issues slightly harder (70%)
    if issue["guarded_case"]:
        base = 0.70
    return rng.random() < base


def _resolve_with_rules(issue: dict[str, Any], rng: random.Random) -> bool:
    """Simulate resolution WITH constitutional rules (no-secrets)."""
    # Base resolve rate: 75%
    base = 0.75
    if issue["guarded_case"]:
        # With no-secrets rule, the model may refuse to produce the fix
        # because the patch itself must contain a secret reference
        base = 0.55  # 20 percentage point drop for secret issues
    return rng.random() < base


def run_experiment(num_trials: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    issues = [_make_issue(rng, i) for i in range(num_trials)]

    without_results = [_resolve_without_rules(i, rng) for i in issues]
    with_results = [_resolve_with_rules(i, rng) for i in issues]

    guarded_issues = [i for i in issues if i["guarded_case"]]
    unguarded_issues = [i for i in issues if not i["guarded_case"]]

    without_guarded_rate = sum(
        without_results[i] for i, issue in enumerate(issues) if issue["guarded_case"]
    ) / max(len(guarded_issues), 1)
    with_guarded_rate = sum(
        with_results[i] for i, issue in enumerate(issues) if issue["guarded_case"]
    ) / max(len(guarded_issues), 1)

    overall_without = sum(without_results) / len(without_results)
    overall_with = sum(with_results) / len(with_results)
    delta = overall_with - overall_without

    return {
        "simulation": _simulation_metadata(seed),
        "trials": num_trials,
        "seed": seed,
        "guarded_issues": len(guarded_issues),
        "unguarded_issues": len(unguarded_issues),
        "without_guarded_resolve_rate": without_guarded_rate,
        "with_guarded_resolve_rate": with_guarded_rate,
        "overall_without": overall_without,
        "overall_with": overall_with,
        "resolution_delta": delta,
        "pass": {
            "delta_ok": delta >= -0.15,
            "guarded_cases_more_difficult": with_guarded_rate < without_guarded_rate,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="X2: SWE-bench secrets under rules")
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default="x2_results.json")
    args = parser.parse_args()

    result = run_experiment(args.trials, args.seed)
    Path(args.output).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
