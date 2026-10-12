#!/usr/bin/env python3
"""Per-rule eval harness for the ACGS governance engine.

Loads the frozen autoresearch scenarios, joins with sidecar rule annotations
by content hash, runs GovernanceTestSuite with strict=False, and outputs
per-rule precision/recall/F1 + scenario-level accuracy.

Usage:
    python autoresearch/eval_rules.py
    python autoresearch/eval_rules.py --output-dir eval_results
    python autoresearch/eval_rules.py --annotations autoresearch/eval_data/rule_annotations.yaml

Does NOT modify the frozen benchmark corpus (scenarios/, constitution.yaml, benchmark.py).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

# Add acgs-lite to path
REPO_ROOT = Path(__file__).resolve().parents[0].parent
ACGS_LITE = REPO_ROOT / "src"
sys.path.insert(0, str(ACGS_LITE))

from acgs_lite.constitution import Constitution, Severity
from acgs_lite.constitution.rule_metrics import EvalReport, compute_eval_report
from acgs_lite.constitution.test_suite import GovernanceTestCase, GovernanceTestSuite
from acgs_lite.engine import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError

SCENARIOS_DIR = Path(__file__).parent / "scenarios"
EXTRA_SCENARIOS_DIR = Path(__file__).parent / "eval_data"
CONSTITUTION_FILE = Path(__file__).parent / "constitution.yaml"
DEFAULT_ANNOTATIONS = Path(__file__).parent / "eval_data" / "rule_annotations.yaml"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "eval_results"


def content_hash(action: str, context: dict[str, Any]) -> str:
    """Deterministic SHA256 hash of (action + sorted context) for join key."""
    parts = [action]
    for k in sorted(context.keys()):
        parts.append(f"{k}={context[k]}")
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def load_scenarios() -> list[dict[str, Any]]:
    """Load frozen test scenarios + extra eval scenarios from JSON files."""
    scenarios: list[dict[str, Any]] = []
    for search_dir in [SCENARIOS_DIR, EXTRA_SCENARIOS_DIR]:
        for f in sorted(search_dir.glob("*.json")):
            with open(f) as fh:
                data = json.load(fh)
                if isinstance(data, list):
                    scenarios.extend(data)
                else:
                    scenarios.append(data)
    return scenarios


def load_annotations(path: Path) -> dict[str, dict[str, Any]]:
    """Load sidecar rule annotations keyed by content hash.

    Returns: {content_hash: {expected_rules: [...], not_expected_rules: [...]}}.
    """
    if not path.exists():
        return {}
    try:
        import yaml
    except ImportError:
        # Fallback: try JSON format
        if path.suffix == ".json":
            with open(path) as f:
                data = json.load(f)
            return {item["hash"]: item for item in data} if isinstance(data, list) else data
        print(f"WARNING: PyYAML not installed, cannot load {path}", file=sys.stderr)
        return {}

    with open(path) as f:
        data = yaml.safe_load(f)

    if data is None:
        return {}

    # Support both list-of-dicts and dict-by-hash formats
    if isinstance(data, list):
        return {item["hash"]: item for item in data}
    return data


def validate_annotations(
    annotations: dict[str, dict[str, Any]],
    active_rule_ids: set[str],
) -> list[str]:
    """Validate that all rule IDs in annotations exist in the constitution.

    Returns list of error messages. Empty = valid.
    """
    errors: list[str] = []
    for chash, ann in annotations.items():
        for rid in ann.get("expected_rules", []):
            if rid.upper() not in active_rule_ids:
                errors.append(
                    f"Annotation {chash}: rule '{rid}' not in active constitution "
                    f"(known: {sorted(active_rule_ids)})"
                )
        for rid in ann.get("not_expected_rules", []):
            if rid.upper() not in active_rule_ids:
                errors.append(
                    f"Annotation {chash}: negative rule '{rid}' not in active constitution"
                )
    return errors


def make_engine_fn(engine: GovernanceEngine):
    """Create a test-suite-compatible engine function.

    Returns a callable that maps validate() results to the dict format
    GovernanceTestSuite expects: {decision: str, triggered_rules: [{id: str}]}.
    """

    def engine_fn(text: str, context: dict[str, Any]) -> dict[str, Any]:
        try:
            result = engine.validate(text, context=context)
        except ConstitutionalViolationError as exc:
            return {"decision": "deny", "triggered_rules": [{"id": exc.rule_id}]}

        # Map to decision
        if result.valid and not result.violations and not result.warnings:
            decision = "allow"
        elif any(v.severity == Severity.CRITICAL for v in result.violations):
            decision = "deny"
        elif result.violations or result.warnings:
            # Historical benchmark classification of nonblocking findings.
            decision = "escalate"
        else:
            decision = "allow"

        triggered_rules = [{"id": v.rule_id} for v in result.violations + result.warnings]
        return {"decision": decision, "triggered_rules": triggered_rules}

    return engine_fn


def build_test_cases(
    scenarios: list[dict[str, Any]],
    annotations: dict[str, dict[str, Any]],
) -> list[GovernanceTestCase]:
    """Build GovernanceTestCase instances from scenarios + annotations."""
    cases: list[GovernanceTestCase] = []
    for i, scenario in enumerate(scenarios):
        action = scenario["action"]
        expected = scenario["expected"]
        context = scenario.get("context", {})
        chash = content_hash(action, context)

        ann = annotations.get(chash, {})

        case = GovernanceTestCase(
            name=f"s{i:04d}-{chash}",
            input_text=action,
            expected_decision=expected,
            context=context,
            expected_rules_triggered=[rid.upper() for rid in ann.get("expected_rules", [])],
            expected_rules_not_triggered=[rid.upper() for rid in ann.get("not_expected_rules", [])],
            tags=ann.get("tags", []),
        )
        cases.append(case)
    return cases


def run_eval(
    *,
    annotations_path: Path = DEFAULT_ANNOTATIONS,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> EvalReport:
    """Run the full eval pipeline."""
    start = time.monotonic()

    # Load constitution and build engine (strict=False to capture all violations)
    constitution = Constitution.from_yaml(str(CONSTITUTION_FILE))
    engine = GovernanceEngine(constitution, strict=False)
    active_rule_ids = {r.id.upper() for r in constitution.active_rules()}

    print(f"Constitution: {len(active_rule_ids)} active rules")
    print(f"Rules: {sorted(active_rule_ids)}")

    # Load scenarios
    scenarios = load_scenarios()
    print(f"Scenarios: {len(scenarios)} loaded from {SCENARIOS_DIR}")

    # Load annotations
    annotations = load_annotations(annotations_path)
    print(f"Annotations: {len(annotations)} loaded from {annotations_path}")

    # Validate annotations
    if annotations:
        errors = validate_annotations(annotations, active_rule_ids)
        if errors:
            print("\nERROR: Invalid annotations:", file=sys.stderr)
            for err in errors:
                print(f"  {err}", file=sys.stderr)
            sys.exit(1)

    # Build test cases
    cases = build_test_cases(scenarios, annotations)

    # Build expected rules maps for metrics computation
    expected_rules_map: dict[str, list[str]] = {}
    not_expected_rules_map: dict[str, list[str]] = {}
    for case in cases:
        if case.expected_rules_triggered:
            expected_rules_map[case.name] = case.expected_rules_triggered
        if case.expected_rules_not_triggered:
            not_expected_rules_map[case.name] = case.expected_rules_not_triggered

    # Run test suite
    engine_fn = make_engine_fn(engine)
    suite = GovernanceTestSuite(engine=engine_fn, name="autoresearch-eval")
    suite.add_cases(cases)

    print(f"\nRunning {len(cases)} test cases...")
    report = suite.run()
    print(report.summary())

    # Compute eval metrics
    eval_report = compute_eval_report(
        report,
        all_rule_ids=list(active_rule_ids),
        expected_rules_map=expected_rules_map,
        not_expected_rules_map=not_expected_rules_map,
    )

    elapsed = time.monotonic() - start

    # Write outputs
    output_dir.mkdir(parents=True, exist_ok=True)

    metrics_path = output_dir / "rule_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(eval_report.to_dict(), f, indent=2)
    print(f"\nMetrics written to {metrics_path}")

    summary_path = output_dir / "summary.md"
    with open(summary_path, "w") as f:
        f.write(eval_report.to_markdown())
    print(f"Summary written to {summary_path}")

    print(f"\nCompleted in {elapsed:.2f}s")
    return eval_report


def generate_annotations(output_path: Path | None = None) -> None:
    """Auto-generate initial annotations by running the engine on all scenarios.

    Captures which rules actually fire for each scenario (ground truth from engine).
    Output is a YAML file that can be hand-verified and adjusted.
    """
    constitution = Constitution.from_yaml(str(CONSTITUTION_FILE))
    engine = GovernanceEngine(constitution, strict=False)

    scenarios = load_scenarios()
    annotations: list[dict[str, Any]] = []

    for scenario in scenarios:
        action = scenario["action"]
        context = scenario.get("context", {})
        expected = scenario["expected"]
        chash = content_hash(action, context)

        result = engine.validate(action, context=context)
        fired_rules = [v.rule_id for v in result.violations]

        ann: dict[str, Any] = {
            "hash": chash,
            "action_preview": action[:80],
            "expected_decision": expected,
        }
        if fired_rules:
            ann["expected_rules"] = fired_rules
        annotations.append(ann)

    if output_path is None:
        output_path = DEFAULT_ANNOTATIONS

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write as YAML if available, else JSON
    try:
        import yaml

        with open(output_path, "w") as f:
            yaml.dump(annotations, f, default_flow_style=False, sort_keys=False)
    except ImportError:
        json_path = output_path.with_suffix(".json")
        with open(json_path, "w") as f:
            json.dump(annotations, f, indent=2)
        output_path = json_path

    print(f"Generated {len(annotations)} annotations at {output_path}")
    print(f"  With rules: {sum(1 for a in annotations if a.get('expected_rules'))}")
    print(f"  Without rules (allow): {sum(1 for a in annotations if not a.get('expected_rules'))}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ACGS per-rule eval harness")
    parser.add_argument(
        "--annotations",
        type=Path,
        default=DEFAULT_ANNOTATIONS,
        help="Path to sidecar rule annotations file",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for eval output files",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="Auto-generate initial annotations from engine ground truth",
    )

    args = parser.parse_args()

    if args.generate:
        generate_annotations(args.annotations)
    else:
        report = run_eval(annotations_path=args.annotations, output_dir=args.output_dir)
        metrics = report.scenario_metrics
        if metrics.incorrect or metrics.errors or metrics.skipped or not metrics.total:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
