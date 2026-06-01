#!/usr/bin/env python3
# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Deep observation pattern analysis.

Consumes ~/.acgs/observations.jsonl and produces statistical reports
matching the deep-observation-pattern-analysis skill methodology.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from acgs_lite.observability.session_observer import ToolObservation

EXPLORATION_TOOLS = frozenset(
    {
        "task",
        "grep",
        "glob",
        "bash",
        "ast_grep_search",
        "websearch",
        "webfetch",
        "context7_resolve",
        "context7_query",
        "claude-mem_mcp",
        "rg",
    }
)
PRODUCTION_TOOLS = frozenset({"edit", "write"})
PREPARATION_TOOLS = frozenset({"read", "skill"})
COORDINATION_TOOLS = frozenset(
    {"todowrite", "background_output", "background_cancel", "question", "lsp_diagnostics"}
)
CATEGORY_TOOL_SETS: dict[str, frozenset[str]] = {
    "exploration_tools": EXPLORATION_TOOLS,
    "production_tools": PRODUCTION_TOOLS,
    "preparation_tools": PREPARATION_TOOLS,
    "coordination_tools": COORDINATION_TOOLS,
}


def load_observations(path: Path) -> list[ToolObservation]:
    if not path.exists():
        return []
    return [
        ToolObservation.from_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _category_stats(
    observations: list[ToolObservation],
    tools_set: frozenset[str],
) -> dict[str, Any]:
    category_observations = [
        observation for observation in observations if observation.tool_type in tools_set
    ]
    category_total = len(category_observations)
    category_successes = sum(1 for observation in category_observations if observation.success)
    category_errors = Counter(
        observation.error_type for observation in category_observations if observation.error_type
    )
    tool_frequencies = {
        tool_name: sum(
            1 for observation in category_observations if observation.tool_type == tool_name
        )
        for tool_name in sorted(tools_set)
    }
    return {
        "total": category_total,
        "tool_frequencies": tool_frequencies,
        "success_rate": category_successes / category_total if category_total > 0 else 0.0,
        "error_types": dict(category_errors.most_common()),
    }


def analyze(obs: list[ToolObservation]) -> dict[str, Any]:
    total = len(obs)
    tool_counts = Counter(o.tool_type for o in obs)
    success_count = sum(1 for o in obs if o.success)
    error_counts = Counter(o.error_type for o in obs if o.error_type)
    categories = {
        category_name: _category_stats(obs, tools_set)
        for category_name, tools_set in CATEGORY_TOOL_SETS.items()
    }

    exploration_stats = categories["exploration_tools"]
    production_stats = categories["production_tools"]
    preparation_stats = categories["preparation_tools"]
    coordination_stats = categories["coordination_tools"]

    exploration = exploration_stats["total"]
    production = production_stats["total"]
    preparation = preparation_stats["total"]
    coordination = coordination_stats["total"]

    sessions = Counter(o.session_id for o in obs if o.session_id)

    edit_test_cycles: list[int] = []
    for sid in sessions:
        session_obs = [o for o in obs if o.session_id == sid]
        edits = 0
        for o in session_obs:
            if o.tool_type in PRODUCTION_TOOLS:
                edits += 1
            elif (
                o.tool_type == "test"
                or o.metadata.get("command", "").startswith(("pytest", "make test"))
            ) and edits > 0:
                edit_test_cycles.append(edits)
                edits = 0

    grep_count = tool_counts.get("grep", 0)
    rg_count = tool_counts.get("rg", 0)
    simple_grep = sum(
        1 for o in obs if o.tool_type == "grep" and len(o.metadata.get("command", "")) < 200
    )
    complex_grep = sum(
        1 for o in obs if o.tool_type == "grep" and len(o.metadata.get("command", "")) >= 200
    )
    grep_errors = sum(1 for o in obs if o.tool_type == "grep" and not o.success)

    reads = tool_counts.get("read", 0)
    edits = tool_counts.get("edit", 0) + tool_counts.get("write", 0)

    sed_i = sum(
        1 for o in obs if o.tool_type == "bash" and "sed -i" in o.metadata.get("command", "")
    )

    return {
        "total": total,
        "success_rate": success_count / total if total > 0 else 0.0,
        "error_types": dict(error_counts.most_common()),
        "categories": categories,
        "sessions": dict(sessions),
        "tool_distribution": dict(tool_counts.most_common()),
        "exploration": exploration,
        "production": production,
        "preparation": preparation,
        "coordination": coordination,
        "exploration_to_production_ratio": exploration / production if production else float("inf"),
        "grep": {
            "total": grep_count,
            "ripgrep": rg_count,
            "simple": simple_grep,
            "complex": complex_grep,
            "errors": grep_errors,
            "complex_error_rate": (grep_errors / complex_grep if complex_grep else 0),
        },
        "read_before_edit": {
            "reads": reads,
            "edits": edits,
            "adequate": reads >= edits,
        },
        "sed_i_usage": sed_i,
        "edit_test_cycles": edit_test_cycles,
    }


def print_report(result: dict, verbose: bool = False) -> None:
    if "error" in result:
        print(result["error"])
        return

    print("=" * 60)
    print("DEEP OBSERVATION PATTERN ANALYSIS")
    print(f"Total observations: {result['total']}")
    print(f"Sessions: {len(result['sessions'])}")
    print("=" * 60)

    print("\n## 1. EXPLORATION vs PRODUCTION")
    print(f"  Exploration:  {result['exploration']}")
    print(f"  Production:   {result['production']}")
    print(f"  Preparation:  {result['preparation']}")
    print(f"  Coordination: {result['coordination']}")
    ratio = result["exploration_to_production_ratio"]
    print(f"\n  Ratio: {ratio:.1f}:1")
    if ratio < 4.1:
        print("  Status: IMPROVED vs baseline (4.1:1)")
    else:
        print("  Status: SAME/WORSE vs baseline (4.1:1)")

    print("\n## 2. TOOL DISTRIBUTION")
    for tool, count in sorted(result["tool_distribution"].items(), key=lambda x: -x[1])[:15]:
        pct = count / result["total"] * 100
        bar = "#" * int(pct / 2)
        print(f"  {tool:25s} {count:4d}  ({pct:5.1f}%) {bar}")

    print("\n## 3. GREP USAGE")
    g = result["grep"]
    print(f"  grep calls:      {g['total']}")
    print(f"  ripgrep (rg):    {g['ripgrep']}")
    print(f"  simple:          {g['simple']}")
    print(f"  complex:         {g['complex']}")
    print(f"  grep errors:     {g['errors']}")
    if g["complex"] > 0:
        print(f"  complex error rate: {g['complex_error_rate']:.0%}")
    if g["ripgrep"] == 0 and g["total"] > 0:
        print("  Status: FAIL — still zero ripgrep usage")
    else:
        print("  Status: OK")

    print("\n## 4. READ BEFORE EDIT")
    rbe = result["read_before_edit"]
    print(f"  Reads:  {rbe['reads']}")
    print(f"  Edits:  {rbe['edits']}")
    print(f"  Status: {'PASS' if rbe['adequate'] else 'FAIL'}")

    print("\n## 5. SED -I USAGE")
    print(f"  Instances: {result['sed_i_usage']}")
    print(f"  Status: {'FAIL' if result['sed_i_usage'] > 0 else 'PASS'}")

    print("\n## 6. ERROR TYPES")
    for err, count in result["error_types"].items():
        print(f"  {err:30s} {count}")

    if result["edit_test_cycles"]:
        print("\n## 7. EDIT-TEST CYCLES")
        cycles = result["edit_test_cycles"]
        print(f"  Average edits before test: {sum(cycles) / len(cycles):.1f}")
        print(f"  Max edits before test: {max(cycles)}")

    if verbose:
        print("\n## 8. SESSION BREAKDOWN")
        for sid, count in result["sessions"].items():
            print(f"  {sid}: {count} observations")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze AI coding session observations")
    parser.add_argument("--path", help="Path to observations.jsonl")
    parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Include session breakdown")
    args = parser.parse_args()

    path = Path(args.path) if args.path else Path.home() / ".acgs" / "observations.jsonl"
    observations = load_observations(path)
    result = analyze(observations)

    if args.json_out:
        print(json.dumps(result, indent=2))
    else:
        print_report(result, verbose=args.verbose)


if __name__ == "__main__":
    main()
