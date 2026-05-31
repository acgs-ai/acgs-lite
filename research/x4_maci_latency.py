"""X4: MACI latency per episode < 100ms.

Hypothesis: Adding MACI role checks adds < 100ms median latency per
governance episode vs single-agent baseline.

Metrics:
  - median_ms < 100
  - p99_ms < 200

Failure: Median >100ms or p99 >500ms.

Note: This measures ONLY governance overhead (role checks + audit logging),
excluding LLM generation time.

Command:
  python x4_maci_latency.py --episodes 50 --seed 42
"""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path
from typing import Any


def _simulation_metadata(seed: int) -> dict[str, object]:
    return {
        "label": f"SIMULATION (seed={seed}), not empirical benchmark",
        "seed": seed,
        "empirical_benchmark": False,
    }


class SingleAgentGovernance:
    """Baseline: single agent with no role checks."""

    def check(self, action: str) -> dict[str, Any]:
        t0 = time.perf_counter()
        # Minimal work: just log the action
        result = {"allowed": True, "role": "single"}
        latency = time.perf_counter() - t0
        return {**result, "latency_ms": latency * 1000}


class MACIGovernance:
    """ACGS-lite-style MACI: proposer/validator/auditor with audit log."""

    def __init__(self) -> None:
        self._assignments: dict[str, str] = {}
        self._audit: list[dict[str, Any]] = []

    def assign(self, agent_id: str, role: str) -> None:
        self._assignments[agent_id] = role

    def _role_permits(self, role: str, action: str) -> bool:
        # Fast path: exact verb matching
        allowed: dict[str, set[str]] = {
            "proposer": {"propose", "draft", "suggest", "amend", "read", "query"},
            "validator": {"validate", "review", "audit", "verify", "read", "query"},
            "executor": {"execute", "deploy", "apply", "run", "read", "query"},
            "auditor": {"read", "query", "export", "observe"},
        }
        denied: dict[str, set[str]] = {
            "proposer": {"validate", "execute", "approve"},
            "validator": {"propose", "execute", "deploy"},
            "executor": {"validate", "propose", "approve"},
            "auditor": {"propose", "validate", "execute", "deploy", "approve"},
        }
        return action in allowed.get(role, set()) and action not in denied.get(role, set())

    def check(self, agent_id: str, action: str) -> dict[str, Any]:
        t0 = time.perf_counter()
        role = self._assignments.get(agent_id, "auditor")
        permitted = self._role_permits(role, action)

        # Audit log entry (simulating ACGS audit.py chain hash)
        entry = {
            "agent_id": agent_id,
            "action": action,
            "role": role,
            "allowed": permitted,
            "timestamp": time.time(),
        }
        self._audit.append(entry)

        latency = time.perf_counter() - t0
        return {"allowed": permitted, "role": role, "latency_ms": latency * 1000}


def _make_action(rng: random.Random) -> str:
    return rng.choice(
        [
            "read",
            "query",
            "propose",
            "validate",
            "execute",
            "deploy",
            "audit",
            "amend",
            "review",
            "suggest",
        ]
    )


def run_experiment(num_episodes: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed)

    single = SingleAgentGovernance()
    maci = MACIGovernance()
    maci.assign("agent-p", "proposer")
    maci.assign("agent-v", "validator")
    maci.assign("agent-e", "executor")
    maci.assign("agent-a", "auditor")

    single_latencies: list[float] = []
    maci_latencies: list[float] = []

    for _ in range(num_episodes):
        action = _make_action(rng)
        agent = rng.choice(["agent-p", "agent-v", "agent-e", "agent-a"])

        single_result = single.check(action)
        maci_result = maci.check(agent, action)

        single_latencies.append(single_result["latency_ms"])
        maci_latencies.append(maci_result["latency_ms"])

    single_latencies.sort()
    maci_latencies.sort()

    def _percentile(arr: list[float], p: float) -> float:
        idx = int(len(arr) * p)
        return arr[min(idx, len(arr) - 1)]

    deltas = [m - s for m, s in zip(maci_latencies, single_latencies, strict=True)]
    deltas.sort()

    return {
        "simulation": _simulation_metadata(seed),
        "episodes": num_episodes,
        "seed": seed,
        "single": {
            "median_ms": _percentile(single_latencies, 0.5),
            "p99_ms": _percentile(single_latencies, 0.99),
            "max_ms": single_latencies[-1],
        },
        "maci": {
            "median_ms": _percentile(maci_latencies, 0.5),
            "p99_ms": _percentile(maci_latencies, 0.99),
            "max_ms": maci_latencies[-1],
        },
        "delta": {
            "median_ms": _percentile(deltas, 0.5),
            "p99_ms": _percentile(deltas, 0.99),
            "max_ms": deltas[-1],
        },
        "pass": {
            "median_ok": _percentile(deltas, 0.5) < 100,
            "p99_ok": _percentile(deltas, 0.99) < 200,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="X4: MACI latency overhead")
    parser.add_argument("--episodes", type=int, default=50)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default="x4_results.json")
    args = parser.parse_args()

    result = run_experiment(args.episodes, args.seed)
    Path(args.output).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
