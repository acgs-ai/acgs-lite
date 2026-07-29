# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs policygen — generate adaptive governance policy YAML from a pre-context."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from acgs_lite.policygen import AdaptivePolicyGenerator, PreContext, PreContextBuilder


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the policygen command group."""
    parser = sub.add_parser(
        "policygen",
        help="Generate adaptive governance policies",
        description="Generate adaptive governance policies",
    )
    policygen_sub = parser.add_subparsers(dest="policygen_command", required=True)

    generate = policygen_sub.add_parser(
        "generate",
        help="Generate a constitution YAML from a pre-context",
        description="Generate a constitution YAML from a pre-context",
    )
    generate.add_argument(
        "--brief",
        type=Path,
        default=None,
        help="Path to a JSON pre-context brief (mutually exclusive with --domain)",
    )
    generate.add_argument(
        "--domain",
        default=None,
        help="Governance domain to infer a pre-context for (required unless --brief is given)",
    )
    generate.add_argument("--description", default="", help="Free-text domain description")
    generate.add_argument(
        "--env", dest="environment", default="production", help="Deployment environment"
    )
    generate.add_argument(
        "--framework",
        dest="frameworks",
        action="append",
        default=[],
        help="Regulatory framework in scope (repeatable)",
    )
    generate.add_argument(
        "--risk-area",
        dest="risk_areas",
        action="append",
        default=[],
        help="Risk area in scope (repeatable)",
    )
    generate.add_argument(
        "--risk-level",
        default=None,
        help="Explicit domain risk level (minimal|limited|high|unacceptable)",
    )
    generate.add_argument(
        "--out", type=Path, required=True, help="Output path for the generated constitution YAML"
    )


def handler(args: argparse.Namespace) -> int:
    """Dispatch policygen subcommands."""
    command = args.policygen_command
    if command == "generate":
        return _generate(args)
    print(f"Unknown policygen command: {command}", file=sys.stderr)
    return 1


def _generate(args: argparse.Namespace) -> int:
    if args.brief is not None and args.domain is not None:
        print(
            "Error: --brief and --domain are mutually exclusive; provide one input source.",
            file=sys.stderr,
        )
        return 1

    try:
        precontext = _build_precontext(args)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    generator = AdaptivePolicyGenerator()
    try:
        generated = generator.generate(precontext)
    except ValueError as exc:
        print(f"Error: failed to generate policy: {exc}", file=sys.stderr)
        return 1

    try:
        out_path = generated.write(args.out)
    except OSError as exc:
        print(f"Error: could not write output to {args.out}: {exc}", file=sys.stderr)
        return 1

    payload = {
        "summary": generated.summary,
        "rationale": list(generated.rationale),
        "output_path": str(out_path),
    }
    print(json.dumps(payload, sort_keys=True))
    return 0


def _build_precontext(args: argparse.Namespace) -> PreContext:
    if args.brief is not None:
        try:
            raw_text = args.brief.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"could not read brief file {args.brief}: {exc}") from exc
        try:
            raw_data: Any = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in brief file {args.brief}: {exc}") from exc
        if not isinstance(raw_data, Mapping):
            raise ValueError(f"brief file {args.brief} must contain a JSON object")
        return PreContext.from_dict(raw_data)

    if not args.domain:
        raise ValueError("--domain is required when --brief is not provided")

    builder = PreContextBuilder(
        args.domain, description=args.description, environment=args.environment
    )
    if args.frameworks:
        builder.add_framework(*args.frameworks)
    if args.risk_areas:
        builder.add_risk_area(*args.risk_areas)
    if args.risk_level is not None:
        builder.with_risk_level(args.risk_level)
    builder.infer()
    return builder.build()
