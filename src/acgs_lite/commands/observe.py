# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs observe / otel — governance telemetry exporter."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any
from urllib import request as urllib_request


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register observe and otel subcommands."""
    # observe
    p_observe = sub.add_parser(
        "observe", help="Export governance telemetry summary or Prometheus metrics"
    )
    _add_observe_args(p_observe)

    # otel
    p_otel = sub.add_parser("otel", help="Export OpenTelemetry-compatible governance telemetry")
    _add_observe_args(p_otel)


def _add_observe_args(p: argparse.ArgumentParser) -> None:
    """Add shared arguments for observe and otel subcommands."""
    p.add_argument("actions", nargs="*", help="Action texts to evaluate and record as telemetry")
    p.add_argument(
        "--actions-file", default=None, help="Newline-delimited file of actions to evaluate"
    )
    p.add_argument("--rules", default="rules.yaml", help="Path to rules YAML (default: rules.yaml)")
    p.add_argument(
        "--service-name",
        default=None,
        help="Service name in telemetry resource attributes (default: current directory)",
    )
    p.add_argument(
        "--environment",
        default="production",
        help="Deployment environment label (default: production)",
    )
    p.add_argument("--prometheus", action="store_true", help="Export Prometheus exposition format")
    p.add_argument("--json", dest="json_out", action="store_true", help="JSON summary")
    p.add_argument("--watch", action="store_true", help="Stream cumulative snapshots")
    p.add_argument(
        "--interval", type=float, default=2.0, help="Seconds between watch snapshots (default: 2.0)"
    )
    p.add_argument(
        "--iterations",
        type=int,
        default=0,
        help="Stop after N watch snapshots (default: unlimited)",
    )
    p.add_argument(
        "--bundle-dir",
        default=None,
        help="Write a telemetry bundle directory alongside normal output",
    )
    p.add_argument(
        "--otlp-endpoint",
        default=None,
        help="POST OTel JSON payloads to an OTLP/collector-compatible HTTP endpoint",
    )
    p.add_argument(
        "--otlp-header",
        action="append",
        default=None,
        help="Extra OTLP header (repeatable: --otlp-header 'Authorization: Bearer ...')",
    )
    p.add_argument(
        "--timeout-seconds",
        type=float,
        default=10.0,
        help="HTTP timeout for OTLP export (default: 10.0)",
    )
    p.add_argument("-o", "--output", default=None, help="Output file path")


def cmd_observe(args: argparse.Namespace) -> int:
    """Export governance telemetry summary / Prometheus metrics."""
    return _cmd_observe(args, default_format="summary")


def cmd_otel(args: argparse.Namespace) -> int:
    """Export governance telemetry in OpenTelemetry JSON format."""
    return _cmd_observe(args, default_format="otel")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_observe_actions(args: argparse.Namespace) -> list[str]:
    """Load inline actions and/or newline-delimited actions file."""
    actions = [str(a).strip() for a in getattr(args, "actions", []) if str(a).strip()]
    actions_file = getattr(args, "actions_file", None)
    if actions_file:
        path = Path(actions_file)
        if not path.exists():
            raise FileNotFoundError(f"{path} not found")
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                actions.append(stripped)
    return actions


def _render_observe_summary(summary: dict[str, Any], rule_counts: dict[str, int]) -> str:
    """Render a human-readable telemetry summary."""
    lines = [
        "  ACGS Governance Telemetry",
        "  " + "=" * 50,
        f"  Service:           {summary['resource'].get('service.name', 'acgs-lite')}",
        f"  Environment:       {summary['resource'].get('deployment.environment', 'production')}",
        f"  Constitution Hash: {summary['resource'].get('constitution.hash', '')}",
        f"  Decisions:         {summary['total_decisions']}",
        f"  Compliance Rate:   {summary['compliance_rate']:.0%}",
        f"  Mean Latency:      {summary['latency_mean_ms']:.4f}ms",
        f"  Traces Captured:   {summary['trace_count']}",
        "",
        "  Decisions by outcome:",
    ]
    for outcome, count in sorted(summary["decisions_by_outcome"].items()):
        lines.append(f"    {outcome:12s} {count}")
    if rule_counts:
        lines.extend(["", "  Rule trigger counts:"])
        for rule_id, count in sorted(rule_counts.items()):
            lines.append(f"    {rule_id:12s} {count}")
    lines.append("")
    return "\n".join(lines)


def _record_actions(exporter: Any, engine: Any, actions: list[str]) -> None:
    """Evaluate actions and record them as telemetry."""
    for action_text in actions:
        result = engine.validate(action_text)
        exporter.record_decision(
            action=action_text,
            outcome="allow" if result.valid else "deny",
            latency_ms=float(getattr(result, "latency_ms", 0.0) or 0.0),
            violations=[v.rule_id for v in result.violations],
        )


def _build_telemetry_payloads(exporter: Any, actions: list[str]) -> dict[str, Any]:
    """Build all telemetry payload variants from the current exporter state."""
    summary_payload = {
        **exporter.summary(),
        "rule_trigger_counts": exporter.rule_trigger_counts,
        "actions_sample": actions[:20],
    }
    otel_payload = exporter.otel_json()
    prometheus_text = exporter.prometheus_exposition()
    summary_text = _render_observe_summary(summary_payload, exporter.rule_trigger_counts)
    return {
        "summary_payload": summary_payload,
        "summary_text": summary_text,
        "prometheus_text": prometheus_text,
        "otel_payload": otel_payload,
    }


def _parse_otlp_headers(raw_headers: list[str] | None) -> dict[str, str]:
    """Parse repeatable Header: Value CLI arguments."""
    headers: dict[str, str] = {}
    for raw in raw_headers or []:
        if ":" not in raw:
            raise ValueError(f"invalid OTLP header '{raw}' (expected Name: Value)")
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def _post_otlp_json(
    endpoint: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 10.0,
) -> int:
    """POST telemetry payload to an OTLP/collector-compatible HTTP endpoint."""
    from urllib.parse import urlparse

    parsed = urlparse(endpoint)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"OTLP endpoint must use http or https scheme, got: {parsed.scheme!r}")
    data = json.dumps(payload).encode("utf-8")
    request = urllib_request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib_request.urlopen(request, timeout=timeout_seconds) as response:  # nosec B310 — scheme validated above
        status = getattr(response, "status", None)
        return int(status if status is not None else response.getcode())


def _write_telemetry_bundle(
    bundle_dir: Path, payloads: dict[str, Any], *, actions: list[str]
) -> list[Path]:
    """Write a portable telemetry bundle directory."""
    bundle_dir.mkdir(parents=True, exist_ok=True)

    summary_json = bundle_dir / "summary.json"
    summary_txt = bundle_dir / "summary.txt"
    metrics_prom = bundle_dir / "metrics.prom"
    otel_json = bundle_dir / "otel.json"
    actions_txt = bundle_dir / "actions.txt"
    manifest_json = bundle_dir / "manifest.json"

    summary_json.write_text(
        json.dumps(payloads["summary_payload"], indent=2) + "\n", encoding="utf-8"
    )
    summary_txt.write_text(payloads["summary_text"], encoding="utf-8")
    metrics_prom.write_text(payloads["prometheus_text"], encoding="utf-8")
    otel_json.write_text(json.dumps(payloads["otel_payload"], indent=2) + "\n", encoding="utf-8")
    actions_txt.write_text("\n".join(actions) + ("\n" if actions else ""), encoding="utf-8")

    manifest = {
        "format_version": 1,
        "generated_at": payloads["summary_payload"].get("generated_at"),
        "actions_count": len(actions),
        "files": {
            "summary_json": summary_json.name,
            "summary_text": summary_txt.name,
            "prometheus": metrics_prom.name,
            "otel_json": otel_json.name,
            "actions": actions_txt.name,
        },
    }
    manifest_json.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return [summary_json, summary_txt, metrics_prom, otel_json, actions_txt, manifest_json]


def _render_selected_format(
    payloads: dict[str, Any], fmt: str, *, watch_iteration: int | None
) -> str:
    """Render payloads in the selected CLI output format."""
    content: str
    if fmt == "prometheus":
        content = str(payloads["prometheus_text"])
        if watch_iteration is not None:
            content = f"# snapshot={watch_iteration}\n" + content
    elif fmt == "otel":
        if watch_iteration is None:
            content = json.dumps(payloads["otel_payload"], indent=2) + "\n"
        else:
            content = (
                json.dumps(
                    {"snapshot": watch_iteration, "otel": payloads["otel_payload"]},
                    separators=(",", ":"),
                )
                + "\n"
            )
    elif fmt == "json":
        if watch_iteration is None:
            content = json.dumps(payloads["summary_payload"], indent=2) + "\n"
        else:
            content = (
                json.dumps(
                    {"snapshot": watch_iteration, **payloads["summary_payload"]},
                    separators=(",", ":"),
                )
                + "\n"
            )
    else:
        content = str(payloads["summary_text"])
        if watch_iteration is not None:
            content = f"\n--- Snapshot {watch_iteration} ---\n{content}"
    return content if content.endswith("\n") else content + "\n"


def _write_observe_output(output_path: Path, content: str, *, watch: bool, iteration: int) -> None:
    """Write one observe/otel render to disk, appending watch snapshots after the first."""
    if watch and iteration > 1:
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(content)
        return
    output_path.write_text(content, encoding="utf-8")


def _resolve_observe_format(args: argparse.Namespace, default_format: str) -> str:
    """Resolve requested output format."""
    fmt = default_format
    if getattr(args, "prometheus", False):
        fmt = "prometheus"
    elif getattr(args, "json_out", False):
        fmt = "json"
    return fmt


def _cmd_observe(args: argparse.Namespace, *, default_format: str) -> int:
    """Export governance telemetry in summary, Prometheus, or OTel JSON format."""
    from acgs_lite.constitution import Constitution
    from acgs_lite.constitution.observability_exporter import GovernanceObservabilityExporter
    from acgs_lite.engine.core import GovernanceEngine

    rules_path = Path(getattr(args, "rules", "rules.yaml"))
    if not rules_path.exists():
        print(f"  ❌ {rules_path} not found. Run 'acgs init' first.", file=sys.stderr)
        return 1

    constitution = Constitution.from_yaml(str(rules_path))
    engine = GovernanceEngine(constitution, strict=False)
    exporter = GovernanceObservabilityExporter(
        service_name=getattr(args, "service_name", None) or Path.cwd().name,
        constitution_hash=constitution.hash,
        environment=getattr(args, "environment", "production"),
    )

    fmt = _resolve_observe_format(args, default_format)
    watch = bool(getattr(args, "watch", False))
    interval_seconds = float(getattr(args, "interval", 2.0) or 0.0)
    iterations = int(getattr(args, "iterations", 0) or 0)
    output = getattr(args, "output", None)
    bundle_dir_raw = getattr(args, "bundle_dir", None)
    otlp_endpoint = getattr(args, "otlp_endpoint", None)
    timeout_seconds = float(getattr(args, "timeout_seconds", 10.0) or 10.0)

    try:
        otlp_headers = _parse_otlp_headers(getattr(args, "otlp_header", None))
    except ValueError as exc:
        print(f"  ❌ {exc}", file=sys.stderr)
        return 1

    iteration = 0
    try:
        while True:
            iteration += 1
            try:
                actions = _load_observe_actions(args)
            except FileNotFoundError as exc:
                print(f"  ❌ {exc}", file=sys.stderr)
                return 1

            if not actions:
                print(
                    "  ❌ Provide one or more actions or --actions-file. "
                    'Example: acgs observe "hello world" "deploy a weapon"',
                    file=sys.stderr,
                )
                return 1

            _record_actions(exporter, engine, actions)
            payloads = _build_telemetry_payloads(exporter, actions)

            if bundle_dir_raw:
                bundle_dir = Path(bundle_dir_raw)
                _write_telemetry_bundle(bundle_dir, payloads, actions=actions)
                if not watch:
                    print(f"  ✅ Telemetry bundle written: {bundle_dir}")

            if otlp_endpoint:
                try:
                    status = _post_otlp_json(
                        otlp_endpoint,
                        payloads["otel_payload"],
                        headers=otlp_headers,
                        timeout_seconds=timeout_seconds,
                    )
                except OSError as exc:
                    print(f"  ❌ OTLP export failed: {exc}", file=sys.stderr)
                    return 1
                if not watch:
                    print(f"  ✅ OTLP export sent: {otlp_endpoint} (HTTP {status})")

            content = _render_selected_format(
                payloads, fmt, watch_iteration=(iteration if watch else None)
            )

            if output:
                output_path = Path(output)
                _write_observe_output(output_path, content, watch=watch, iteration=iteration)
                if not watch:
                    print(f"  ✅ Telemetry written: {output_path}")
            else:
                print(content, end="")

            if not watch:
                return 0
            if iterations > 0 and iteration >= iterations:
                return 0
            time.sleep(max(0.0, interval_seconds))
    except KeyboardInterrupt:
        print("\n  ℹ️  Stopped telemetry watch.")
        return 0
