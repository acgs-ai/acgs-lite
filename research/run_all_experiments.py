#!/usr/bin/env python3
"""ACGS-lite Research Harness — Run all 6 micro-experiments.

Usage:
    python run_all_experiments.py [--seed 42]

Produces:
    x1_results.json, x2_results.json, x3_results.json,
    x4_results.json, x5_results.json, x6_results.json

+ a combined summary.json.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _simulation_metadata(seed: int) -> dict[str, object]:
    return {
        "label": f"SIMULATION (seed={seed}), not empirical benchmark",
        "seed": seed,
        "empirical_benchmark": False,
    }


def _run(script: str, extra_args: list[str] | None = None) -> dict[str, object]:
    cmd = [sys.executable, script]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[FAIL] {script}: {result.stderr}", file=sys.stderr)
        return {"script": script, "status": "failed", "error": result.stderr.strip()}
    try:
        data = json.loads(result.stdout)
        return {"script": script, "status": "passed", "result": data}
    except json.JSONDecodeError:
        return {"script": script, "status": "passed", "raw": result.stdout.strip()}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run all research experiments")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default="summary.json")
    args = parser.parse_args()

    experiments = [
        (
            "x1_constitutional_humaneval.py",
            ["--seed", str(args.seed), "--constitution", "constitution_secrets.json"],
        ),
        ("x2_swe_secrets.py", ["--seed", str(args.seed)]),
        ("x3_maci_decisions.py", ["--seed", str(args.seed)]),
        ("x4_maci_latency.py", ["--seed", str(args.seed)]),
        ("x5_prov_export.py", ["--seed", str(args.seed)]),
        ("x6_diff_audit.py", ["--seed", str(args.seed)]),
    ]

    results = []
    for script, extra in experiments:
        print(f"Running {script} ...")
        results.append(_run(script, extra))

    all_passed = all(
        r.get("status") == "passed"
        and r.get("result", {}).get("pass", {}).get("pass@1_delta_ok", True)
        for r in results
    )

    summary = {
        "simulation": _simulation_metadata(args.seed),
        "experiments": results,
        "all_passed": all_passed,
        "seed": args.seed,
    }

    Path(args.output).write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
