#!/usr/bin/env python3
"""Correctness-gated self-improvement benchmark for acgs-lite.

The self-improve loop merges winners on ``benchmark_score`` alone. On a
constitutional governance engine the cheapest throughput wins are exactly the
enforcement-weakening shortcuts the package forbids (see acgs-lite CLAUDE.md:
"never change matcher.py hot-path behavior without targeted tests", "never
bypass MACI enforcement"). A score-only gate would happily merge such a winner
as long as the three benchmark cases still pass.

This wrapper closes that hole by making correctness a hard precondition of the
score:

  1. Run the FULL correctness suite (every test except ``benchmark``/``e2e``).
  2. If ANY test fails  -> emit primary=0.0, correctness_passed=false, exit 1.
     (Guaranteed-losing score AND non-zero exit -> the loop can never merge it,
      regardless of how the executor interprets the result.)
  3. Only if correctness holds -> emit the validate() throughput score.

Worktree correctness: paths are resolved from this file's own location, NOT a
hardcoded checkout, so each experiment worktree benchmarks its OWN ``src/``.
``tests/conftest.py`` force-inserts ``<pkg>/src`` at the front of sys.path, so
running pytest with cwd=PKG_ROOT imports the worktree-local engine.

Output contract (last stdout line is JSON):
  {"primary": <float>, "sub_scores": {...}, "correctness_passed": <bool>}
"primary" is in k-OPS (higher_is_better).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Resolve the package root from THIS file's location so the wrapper benchmarks
# whatever checkout/worktree it lives in (scripts/ -> package root).
PKG_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = PKG_ROOT / "tests"
BENCHMARK_FILE = TESTS_DIR / "test_benchmark_engine.py"

# Mirror the Makefile TEST_ENV so unit tests that look for API keys are satisfied.
TEST_ENV = {
    "OPENAI_API_KEY": "test-key-for-unit-tests",
    "ANTHROPIC_API_KEY": "test-key-for-unit-tests",
}

# Zeroed sub-scores used when the correctness gate fails.
_ZERO_SUB_SCORES = {"allow_ops_k": 0.0, "deny_ops_k": 0.0, "construct_ops": 0.0}


def _subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(TEST_ENV)
    return env


def run_correctness_gate() -> int:
    """Run the full correctness suite (excluding benchmark/e2e markers).

    Returns the pytest return code. 0 == all passed.
    """
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(TESTS_DIR),
        f"--rootdir={PKG_ROOT}",
        "--import-mode=importlib",
        "-m",
        "not benchmark and not e2e",
        "-q",
        "-p",
        "no:cacheprovider",
    ]
    result = subprocess.run(
        cmd,
        cwd=str(PKG_ROOT),
        env=_subprocess_env(),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Surface a bounded tail so failure_analysis has something to record.
        tail = "\n".join(result.stdout.splitlines()[-25:])
        print(
            f"CORRECTNESS_GATE_FAILED (pytest rc={result.returncode}):\n{tail}",
            file=sys.stderr,
        )
    return result.returncode


def run_benchmark() -> dict:
    """Run the pytest-benchmark microbenchmarks and return the raw JSON."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        output_path = f.name

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(BENCHMARK_FILE),
        "-m",
        "benchmark",
        "--benchmark-json",
        output_path,
        f"--rootdir={PKG_ROOT}",
        "--import-mode=importlib",
        "-q",
        "--no-header",
        "-p",
        "no:cacheprovider",
    ]
    result = subprocess.run(
        cmd,
        cwd=str(PKG_ROOT),
        env=_subprocess_env(),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Benchmark failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    with open(output_path) as f:
        data = json.load(f)

    Path(output_path).unlink(missing_ok=True)
    return data


def extract_scores(data: dict) -> tuple[float, dict]:
    benchmarks = {b["name"].split("::")[-1]: b["stats"] for b in data.get("benchmarks", [])}

    allow_ops = benchmarks.get("test_validate_allow_path_default_constitution", {}).get("ops", 0.0)
    deny_ops = benchmarks.get("test_validate_deny_path_default_constitution", {}).get("ops", 0.0)
    construct_ops = benchmarks.get("test_engine_construction_default_constitution", {}).get(
        "ops", 0.0
    )

    # Primary: weighted composite of the two hot paths (normalised to k-OPS).
    # Weight: 60% allow (main path), 40% deny (rejection path).
    primary = (0.6 * allow_ops + 0.4 * deny_ops) / 1_000.0

    sub_scores = {
        "allow_ops_k": round(allow_ops / 1_000.0, 3),
        "deny_ops_k": round(deny_ops / 1_000.0, 3),
        "construct_ops": round(construct_ops, 3),
    }
    return round(primary, 3), sub_scores


def main() -> None:
    # --- Gate 1: correctness is a hard precondition of any score. ---
    rc = run_correctness_gate()
    if rc != 0:
        print(
            json.dumps(
                {
                    "primary": 0.0,
                    "sub_scores": _ZERO_SUB_SCORES,
                    "correctness_passed": False,
                    "correctness_returncode": rc,
                }
            )
        )
        sys.exit(1)

    # --- Gate 2: only now measure throughput. ---
    data = run_benchmark()
    primary, sub_scores = extract_scores(data)
    print(
        json.dumps(
            {
                "primary": primary,
                "sub_scores": sub_scores,
                "correctness_passed": True,
            }
        )
    )


if __name__ == "__main__":
    main()
