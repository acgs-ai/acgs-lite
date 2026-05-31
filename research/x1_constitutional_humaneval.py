"""X1: Constitutional filter impact on pass@k (HumanEval proxy).

Hypothesis: Constitutional filter reduces pass@1 but NOT pass@100.
Metrics:
  - pass@1_delta <= 5% drop
  - pass@100_delta <= 2% drop
Failure: pass@1 drops >10% or pass@100 drops >5%.
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


# ---------------------------------------------------------------------------
# Simulated HumanEval-like problems (5 proxy problems for speed)
# In production: replace with real HumanEval dataset from datasets library
# ---------------------------------------------------------------------------

PROXY_PROBLEMS: list[dict[str, Any]] = [
    {
        "task_id": "HumanEval/0",
        "prompt": "def has_close_elements(numbers, threshold):\n    for idx, elem in enumerate(numbers):\n        for idx2, elem2 in enumerate(numbers):\n            if idx != idx2:\n                distance = abs(elem - elem2)\n                if distance < threshold:\n                    return True\n    return False\n",
        "canonical_solution": "def has_close_elements(numbers, threshold):\n    for idx, elem in enumerate(numbers):\n        for idx2, elem2 in enumerate(numbers):\n            if idx != idx2:\n                distance = abs(elem - elem2)\n                if distance < threshold:\n                    return True\n    return False\n",
        "test": "def check(has_close_elements):\n    assert has_close_elements([1.0, 2.0, 3.0], 0.5) == False\n    assert has_close_elements([1.0, 2.8, 3.0, 4.0, 5.0, 2.0], 0.3) == True\n    assert has_close_elements([1.0, 2.0, 5.9, 4.0, 5.0], 0.95) == True\n    assert has_close_elements([1.0, 2.0, 5.9, 4.0, 5.0], 0.8) == False\n    assert has_close_elements([1.0, 2.0, 3.0, 4.0, 5.0, 2.2], 0.3) == True\n    assert has_close_elements([1.0, 2.0, 3.0, 4.0, 5.0, 2.0], 0.25) == True\n    assert has_close_elements([1.1, 2.2, 3.1, 4.1, 5.1], 1.0) == True\n    assert has_close_elements([1.1, 2.2, 3.1, 4.1, 5.1], 0.5) == False\n\ncheck(has_close_elements)\n",
    },
    {
        "task_id": "HumanEval/1",
        "prompt": "def separate_paren_groups(paren_string):\n    result = []\n    current = []\n    count = 0\n    for c in paren_string:\n        if c == '(' or c == ')':\n            current.append(c)\n            if c == '(':\n                count += 1\n            else:\n                count -= 1\n            if count == 0:\n                result.append(''.join(current))\n                current = []\n    return result\n",
        "canonical_solution": "def separate_paren_groups(paren_string):\n    result = []\n    current = []\n    count = 0\n    for c in paren_string:\n        if c == '(' or c == ')':\n            current.append(c)\n            if c == '(':\n                count += 1\n            else:\n                count -= 1\n            if count == 0:\n                result.append(''.join(current))\n                current = []\n    return result\n",
        "test": "def check(separate_paren_groups):\n    assert separate_paren_groups('( ) (( )) (( )( ))') == ['()', '(())', '(()())']\n    assert separate_paren_groups('()') == ['()']\n    assert separate_paren_groups('(())') == ['(())']\n    assert separate_paren_groups('((()))') == ['((()))']\n    assert separate_paren_groups('()((()))') == ['()', '((()))']\n\ncheck(separate_paren_groups)\n",
    },
    {
        "task_id": "HumanEval/2",
        "prompt": "def truncate_number(number, decimals):\n    import math\n    factor = 10 ** decimals\n    return math.trunc(number * factor) / factor\n",
        "canonical_solution": "def truncate_number(number, decimals):\n    import math\n    factor = 10 ** decimals\n    return math.trunc(number * factor) / factor\n",
        "test": "def check(truncate_number):\n    assert truncate_number(3.5, 0) == 3.0\n    assert truncate_number(3.14159, 2) == 3.14\n    assert truncate_number(123.456, 1) == 123.4\n    assert truncate_number(-1.5, 0) == -1.0\n\ncheck(truncate_number)\n",
    },
    {
        "task_id": "HumanEval/3",
        "prompt": "def below_zero(operations):\n    balance = 0\n    for op in operations:\n        balance += op\n        if balance < 0:\n            return True\n    return False\n",
        "canonical_solution": "def below_zero(operations):\n    balance = 0\n    for op in operations:\n        balance += op\n        if balance < 0:\n            return True\n    return False\n",
        "test": "def check(below_zero):\n    assert below_zero([1, 2, 3]) == False\n    assert below_zero([1, 2, -4, 5]) == True\n    assert below_zero([]) == False\n    assert below_zero([-1]) == True\n    assert below_zero([1, -1, -1]) == True\n\ncheck(below_zero)\n",
    },
    {
        "task_id": "HumanEval/4",
        "prompt": "def decode_cyclic(s):\n    groups = [s[(3 * i):min((3 * i + 3), len(s))] for i in range((len(s) + 2) // 3)]\n    result = []\n    for g in groups:\n        if len(g) == 3:\n            result.append(g[1:] + g[0])\n        else:\n            result.append(g)\n    return ''.join(result)\n",
        "canonical_solution": "def decode_cyclic(s):\n    groups = [s[(3 * i):min((3 * i + 3), len(s))] for i in range((len(s) + 2) // 3)]\n    result = []\n    for g in groups:\n        if len(g) == 3:\n            result.append(g[1:] + g[0])\n        else:\n            result.append(g)\n    return ''.join(result)\n",
        "test": "def check(decode_cyclic):\n    assert decode_cyclic('abc') == 'bca'\n    assert decode_cyclic('abcdef') == 'bcadef'\n    assert decode_cyclic('') == ''\n    assert decode_cyclic('a') == 'a'\n    assert decode_cyclic('ab') == 'ab'\n    assert decode_cyclic('abcdefg') == 'bcadefg'\n\ncheck(decode_cyclic)\n",
    },
]


# ---------------------------------------------------------------------------
# Simulated LLM sampler with configurable constitution filter
# ---------------------------------------------------------------------------


class SimulatedLLM:
    """Deterministic sampler: correct solution + Gaussian noise mutation."""

    def __init__(self, seed: int = 42, correctness_rate: float = 0.6):
        self.rng = random.Random(seed)
        self.correctness_rate = correctness_rate

    def sample(
        self, problem: dict[str, Any], constitution_filter: dict[str, Any] | None = None
    ) -> str:
        """Generate one sample. May inject a violation if filter demands it."""
        correct = self.rng.random() < self.correctness_rate
        if constitution_filter and self._triggers_filter(problem, constitution_filter):
            # Filter demands extra scrutiny: slightly lower correctness
            correct = self.rng.random() < (self.correctness_rate * 0.95)
        if correct:
            return problem["canonical_solution"]
        # Return a subtly broken variant (simulated)
        return problem["canonical_solution"].replace("return", "# BAD\n    return")

    def _triggers_filter(self, problem: dict[str, Any], filter_rules: dict[str, Any]) -> bool:
        content = problem["prompt"] + problem["test"]
        keywords = filter_rules.get("block_keywords", [])
        return any(kw in content for kw in keywords)


def _run_tests(code: str, test_code: str) -> bool:
    """Execute candidate code + tests in a safe locals dict."""
    local_ns: dict[str, Any] = {}
    try:
        exec(code, {}, local_ns)  # noqa: S102
        exec(test_code, local_ns)  # noqa: S102
        return True
    except Exception:
        return False


def unbiased_pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased estimator for pass@k from n samples with c correct ones."""
    if n - c < k:
        return 1.0
    return 1.0 - float(__import__("math").comb(n - c, k)) / float(__import__("math").comb(n, k))


def run_experiment(
    num_samples: int = 100,
    k_values: list[int] | None = None,
    constitution_filter: dict[str, Any] | None = None,
    seed: int = 42,
    correctness_rate: float = 0.6,
) -> dict[str, Any]:
    """Run pass@k experiment on proxy problems."""
    if k_values is None:
        k_values = [1, 10, 100]

    llm = SimulatedLLM(seed=seed, correctness_rate=correctness_rate)
    problem_results: dict[str, dict[int, float]] = {}

    for problem in PROXY_PROBLEMS:
        pid = problem["task_id"]
        correct_count = 0
        for _ in range(num_samples):
            sample = llm.sample(problem, constitution_filter)
            if _run_tests(sample, problem["test"]):
                correct_count += 1

        pass_k = {k: unbiased_pass_at_k(num_samples, correct_count, k) for k in k_values}
        problem_results[pid] = pass_k

    # Aggregate
    aggregated = {
        k: sum(pr[k] for pr in problem_results.values()) / len(problem_results) for k in k_values
    }

    return {
        "num_samples": num_samples,
        "seed": seed,
        "constitution_filter_active": constitution_filter is not None,
        "constitution_filter": constitution_filter,
        "problem_results": problem_results,
        "aggregated": aggregated,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="X1: Constitutional filter on pass@k")
    parser.add_argument("--num-samples", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--constitution", type=str, default="", help="Path to constitution filter JSON"
    )
    parser.add_argument("--output", type=str, default="x1_results.json")
    args = parser.parse_args()

    constitution_filter = None
    if args.constitution:
        constitution_filter = json.loads(Path(args.constitution).read_text())

    baseline = run_experiment(
        num_samples=args.num_samples, seed=args.seed, constitution_filter=None
    )
    filtered = run_experiment(
        num_samples=args.num_samples, seed=args.seed, constitution_filter=constitution_filter
    )

    deltas = {
        k: filtered["aggregated"][k] - baseline["aggregated"][k] for k in baseline["aggregated"]
    }

    result = {
        "simulation": _simulation_metadata(args.seed),
        "baseline": baseline["aggregated"],
        "filtered": filtered["aggregated"],
        "deltas": deltas,
        "pass": {
            "pass@1_delta_ok": deltas.get(1, 0) >= -0.05,
            "pass@100_delta_ok": deltas.get(100, 0) >= -0.02,
        },
    }

    Path(args.output).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
