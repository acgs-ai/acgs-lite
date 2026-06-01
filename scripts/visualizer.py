"""
ACGS-Lite Visualizer
====================
Debug tool for inspecting constitutions, audit trails, and benchmark results.

Run from packages/acgs-lite/:

    python3 scripts/visualizer.py rules   -c examples/basic_governance/constitution.yaml
    python3 scripts/visualizer.py audit   -p examples/audit_trail/audit_sample.jsonl
    python3 scripts/visualizer.py audit   -p examples/audit_trail/audit_sample.jsonl --agent planner
    python3 scripts/visualizer.py bench   -p examples/bench_sample/
    python3 scripts/visualizer.py summary -c examples/basic_governance/constitution.yaml \\
                                          --audit examples/audit_trail/audit_sample.jsonl

Generate sample data:
    python examples/audit_trail/main.py   # runs in-memory; see audit_sample.jsonl
    make test-cov                         # produces htmlcov/ benchmark data
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# ── Colour helpers (no deps) ───────────────────────────────────────────────────


def _color(text: str, code: str) -> str:
    """ANSI colour — silently degrades when not a tty."""
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


RED = lambda t: _color(t, "31")  # noqa: E731
GREEN = lambda t: _color(t, "32")  # noqa: E731
YELLOW = lambda t: _color(t, "33")  # noqa: E731
CYAN = lambda t: _color(t, "36")  # noqa: E731
BOLD = lambda t: _color(t, "1")  # noqa: E731
DIM = lambda t: _color(t, "2")  # noqa: E731


# ── Bar chart helper ───────────────────────────────────────────────────────────


def _bar(value: int, total: int, width: int = 20, char: str = "█") -> str:
    filled = int(width * value / total) if total else 0
    return char * filled + DIM("░" * (width - filled))


# ── 1. Constitution / Rule Inspector ──────────────────────────────────────────


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        print("pyyaml required: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH": YELLOW,
    "MEDIUM": CYAN,
    "LOW": DIM,
    "INFO": DIM,
}


def cmd_rules(args: argparse.Namespace) -> None:
    """Display the rule tree for a constitution YAML."""
    path = Path(args.constitution)
    if not path.exists():
        print(f"File not found: {path.resolve()}", file=sys.stderr)
        print("Hint: run from packages/acgs-lite/ and use a path like", file=sys.stderr)
        print("      examples/basic_governance/constitution.yaml", file=sys.stderr)
        sys.exit(1)

    data = _load_yaml(path)
    name = data.get("name", path.stem)
    version = data.get("version", "?")
    rules = data.get("rules", [])

    print()
    print(BOLD(f"Constitution: {name}  v{version}"))
    print(DIM(f"  File    : {path}"))
    print(DIM(f"  Hash key: {data.get('constitutional_hash', 'not set')}"))
    print(DIM(f"  Rules   : {len(rules)}"))
    print()

    # Group by severity for the tree
    by_severity: dict[str, list[dict[str, Any]]] = {}
    for rule in rules:
        sev = str(rule.get("severity", "HIGH")).upper()
        by_severity.setdefault(sev, []).append(rule)

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for sev in order:
        group = by_severity.get(sev, [])
        if not group:
            continue
        colorize = SEVERITY_COLOR.get(sev, lambda x: x)
        print(colorize(f"  [{sev}] ({len(group)} rule{'s' if len(group) != 1 else ''})"))
        for rule in group:
            rid = rule.get("id", "?")
            text = rule.get("text", "")
            patterns = rule.get("patterns", [])
            blocking = rule.get("severity", "HIGH").upper() not in ("LOW", "INFO", "MEDIUM")
            flag = RED("⛔ blocks") if blocking else YELLOW("⚠  warns")
            print(f"    ├─ {BOLD(rid)}  {flag}")
            if text:
                print(f"    │    {DIM(text[:72])}")
            for i, p in enumerate(patterns[:3]):
                prefix = "    │    pattern: " if i < len(patterns) - 1 else "    └    pattern: "
                print(f"{prefix}{DIM(p[:60])}")
            if len(patterns) > 3:
                print(f"    │    {DIM(f'... +{len(patterns) - 3} more patterns')}")
        print()

    # Counts summary bar
    total = len(rules)
    print(BOLD("  Rule distribution"))
    for sev in order:
        count = len(by_severity.get(sev, []))
        if count:
            colorize = SEVERITY_COLOR.get(sev, lambda x: x)
            bar = _bar(count, total)
            print(f"    {colorize(f'{sev:<10}')} {bar}  {count}")
    print()


# ── 2. Audit Trail Viewer ──────────────────────────────────────────────────────


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                with contextlib.suppress(json.JSONDecodeError):
                    records.append(json.loads(line))
    return records


def cmd_audit(args: argparse.Namespace) -> None:
    """Display and summarise an audit trail JSONL file."""
    path = Path(args.path)
    if not path.exists():
        print(f"File not found: {path.resolve()}", file=sys.stderr)
        print("Hint: generate sample data with:", file=sys.stderr)
        print("  OPENAI_API_KEY=test-key python examples/audit_trail/main.py", file=sys.stderr)
        print("  # then use: -p examples/audit_trail/audit_sample.jsonl", file=sys.stderr)
        sys.exit(1)

    records = _read_jsonl(path)

    # Optional filters
    if args.agent:
        records = [r for r in records if r.get("agent_id") == args.agent]
    if args.type:
        records = [r for r in records if r.get("type") == args.type]

    total = len(records)
    allowed = sum(1 for r in records if r.get("valid", True))
    denied = total - allowed

    print()
    print(BOLD(f"Audit trail: {path}"))
    print(DIM(f"  Entries : {total}"))
    print(DIM(f"  Allowed : {allowed}") + (f"  {_bar(allowed, total, 15, '▓')}" if total else ""))
    print(DIM(f"  Denied  : {denied}") + (f"  {_bar(denied, total, 15, '░')}" if total else ""))

    if not records:
        print("  (no records match filters)")
        return

    # Agent breakdown
    agents = Counter(r.get("agent_id", "?") for r in records)
    if len(agents) > 1:
        print()
        print(BOLD("  By agent"))
        for agent, count in agents.most_common():
            agent_denied = sum(
                1 for r in records if r.get("agent_id") == agent and not r.get("valid", True)
            )
            bar = _bar(count, total, 12)
            deny_str = f"  {RED(f'{agent_denied} denied')}" if agent_denied else ""
            print(f"    {CYAN(f'{agent:<18}')} {bar}  {count}{deny_str}")

    # Rule hit breakdown (violations)
    # violations is list[str] (rule IDs) in the JSONL format
    violations = [r for r in records if not r.get("valid", True)]
    if violations:
        rule_hits: Counter[str] = Counter()
        for v in violations:
            for vi in v.get("violations", []):
                # vi is a rule_id string, not a dict
                rule_id = vi if isinstance(vi, str) else vi.get("rule_id", "?")
                rule_hits[rule_id] += 1
        print()
        print(BOLD(f"  Violations by rule ({len(violations)} total)"))
        for rule_id, count in rule_hits.most_common(10):
            bar = _bar(count, len(violations), 12)
            print(f"    {RED(f'{rule_id:<30}')} {bar}  {count}")

    # Timeline (last N)
    limit = min(args.tail, total)
    print()
    print(BOLD(f"  Last {limit} entries"))
    print(DIM(f"  {'ID':<8}  {'Agent':<16}  {'Type':<12}  {'Action':<24}  {'Result'}"))
    print(DIM("  " + "─" * 72))
    for r in records[-limit:]:
        eid = str(r.get("id", "?"))[:8]
        agent = str(r.get("agent_id", ""))[:16]
        etype = str(r.get("type", ""))[:12]
        action = str(r.get("action", ""))[:24]
        valid = r.get("valid", True)
        result = GREEN("✅ allowed") if valid else RED("🚫 denied")
        print(f"  {DIM(eid):<8}  {CYAN(agent):<16}  {etype:<12}  {DIM(action):<24}  {result}")

    # Chain integrity
    chain_hashes = [r.get("_chain_hash", "") for r in records]
    if any(chain_hashes):
        intact = all(h for h in chain_hashes)
        status = GREEN("✅ intact") if intact else RED("❌ gaps detected — possible tampering")
        print()
        print(BOLD("  Chain integrity"))
        print(f"    {status}")
    print()


# ── 3. Benchmark / Checkpoint Viewer ──────────────────────────────────────────


def _find_bench_files(base: Path) -> list[Path]:
    patterns = ["*.json", "benchmark*.jsonl", "results*.json"]
    found: list[Path] = []
    for pattern in patterns:
        found.extend(sorted(base.glob(pattern)))
    return found


def cmd_bench(args: argparse.Namespace) -> None:
    """Visualise benchmark score progression from checkpoint files."""
    base = Path(args.path)
    if not base.exists():
        print(f"Path not found: {base.resolve()}", file=sys.stderr)
        print("Hint: use the bundled sample data:", file=sys.stderr)
        print("  python3 scripts/visualizer.py bench -p examples/bench_sample/", file=sys.stderr)
        print("Or point to any directory containing *.json files with", file=sys.stderr)
        print("  latency_p50_us / latency_p99_us / score / throughput fields.", file=sys.stderr)
        sys.exit(0)

    files = _find_bench_files(base)
    if not files:
        print(f"No benchmark files found under {base}", file=sys.stderr)
        print("Expected: *.json with 'latency_p50_us', 'latency_p99_us', or 'score' fields")
        sys.exit(0)

    runs: list[dict[str, Any]] = []
    for f in files:
        try:
            data = json.loads(f.read_text())
            data["_file"] = f.name
            runs.append(data)
        except Exception:
            pass

    if not runs:
        print("Could not parse any benchmark files.")
        return

    print()
    print(BOLD(f"Benchmark history — {base}"))
    print(DIM(f"  {len(runs)} run(s) found"))
    print()

    # Detect available metric keys
    metric_keys = ["latency_p50_us", "latency_p99_us", "score", "throughput", "violations_per_sec"]
    present_keys = [k for k in metric_keys if any(k in r for r in runs)]

    if not present_keys:
        print(DIM("  No recognised metric keys found. Showing raw file contents:"))
        for run in runs[-5:]:
            print(
                f"  {run['_file']}: {json.dumps({k: v for k, v in run.items() if k != '_file'})[:80]}"
            )
        return

    # Score/latency trend chart
    for key in present_keys:
        values = [r[key] for r in runs if key in r]
        if not values:
            continue
        min_v = min(values)
        max_v = max(values)
        rng = max_v - min_v or 1
        is_latency = "latency" in key or "us" in key
        trend_char = "▼" if is_latency else "▲"

        print(BOLD(f"  {key}  (lower=better)" if is_latency else f"  {key}  (higher=better)"))
        print(DIM(f"  {'Run':<30}  {'Value':>10}  {'Chart'}"))
        print(DIM("  " + "─" * 60))

        for run, val in zip([r["_file"] for r in runs if key in r], values, strict=False):
            normalized = (val - min_v) / rng
            bar_len = int(normalized * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            # For latency, high value = bad (red); for score, high = good (green)
            colorize = (
                RED
                if (is_latency and normalized > 0.7)
                else GREEN
                if not is_latency and normalized > 0.7
                else YELLOW
            )
            val_str = f"{val:>10.1f}"
            print(f"  {DIM(run[:30]):<30}  {colorize(val_str)}  {colorize(bar)}")

        best = min(values) if is_latency else max(values)
        worst = max(values) if is_latency else min(values)
        current = values[-1]
        delta = current - best
        delta_str = f"{trend_char} best: {best:.1f}  worst: {worst:.1f}  current: {current:.1f}"
        if abs(delta) > 0.01:
            regress = delta > 0 if is_latency else delta < 0
            delta_str += f"  {'⚠ regression' if regress else '✓ improving'}"
        print(DIM(f"  {delta_str}"))
        print()


# ── 4. Summary — combined view ─────────────────────────────────────────────────


def cmd_summary(args: argparse.Namespace) -> None:
    """Combined: show rules + audit stats in one view."""
    if args.constitution:
        cmd_rules(args)
    if args.audit:
        # Reuse cmd_audit by injecting the path
        audit_args = argparse.Namespace(
            path=args.audit,
            agent=getattr(args, "agent", None),
            type=getattr(args, "type", None),
            tail=getattr(args, "tail", 20),
        )
        cmd_audit(audit_args)


# ── CLI ────────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="visualizer",
        description="ACGS-Lite debug visualizer — inspect constitutions, audit trails, and benchmarks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # rules
    r = sub.add_parser("rules", help="Display rule tree for a constitution YAML")
    r.add_argument(
        "--constitution", "-c", required=True, metavar="PATH", help="Path to constitution.yaml"
    )

    # audit
    a = sub.add_parser("audit", help="Display and summarise an audit trail JSONL")
    a.add_argument("--path", "-p", required=True, metavar="PATH", help="Path to audit.jsonl")
    a.add_argument("--agent", metavar="AGENT_ID", help="Filter to a specific agent ID")
    a.add_argument(
        "--type", metavar="TYPE", help="Filter to entry type (validation, maci_check, ...)"
    )
    a.add_argument(
        "--tail", type=int, default=20, metavar="N", help="Show last N entries (default: 20)"
    )

    # bench
    b = sub.add_parser("bench", help="Show benchmark score progression")
    b.add_argument(
        "--path",
        "-p",
        required=True,
        metavar="DIR",
        help="Directory containing benchmark JSON/JSONL files",
    )

    # summary
    s = sub.add_parser("summary", help="Combined rules + audit overview")
    s.add_argument("--constitution", "-c", metavar="PATH", help="Path to constitution.yaml")
    s.add_argument("--audit", metavar="PATH", help="Path to audit.jsonl")
    s.add_argument("--agent", metavar="AGENT_ID", help="Filter audit to a specific agent")
    s.add_argument(
        "--tail", type=int, default=20, metavar="N", help="Audit tail length (default: 20)"
    )

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "rules": cmd_rules,
        "audit": cmd_audit,
        "bench": cmd_bench,
        "summary": cmd_summary,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
