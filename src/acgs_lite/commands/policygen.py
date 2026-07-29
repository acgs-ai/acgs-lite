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

from acgs_lite.policygen import (
    AdaptivePolicyGenerator,
    PreContext,
    PreContextBuilder,
    scan_manifests,
)


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

    scan = policygen_sub.add_parser(
        "scan",
        help="Scan a project's dependency manifests for governance risk-area evidence",
        description=(
            "Statically scan a project's dependency manifests (pyproject.toml, "
            "requirements.txt, package.json) and report risk-area evidence as a DRAFT "
            "artifact. This never activates or grants any capability."
        ),
    )
    scan.add_argument("path", type=Path, help="Project root directory to scan for manifests")
    scan.add_argument(
        "--domain",
        default="scanned-project",
        help="Governance domain label for the derived pre-context",
    )
    scan.add_argument(
        "--description", default=None, help="Free-text description override for the pre-context"
    )
    scan.add_argument(
        "--brief-out",
        type=Path,
        default=None,
        dest="brief_out",
        help="Write the derived PreContext brief JSON to this path (for later `generate --brief`)",
    )
    scan.add_argument(
        "--generate",
        action="store_true",
        help="Chain into the generate path using the scanned pre-context",
    )
    scan.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output path for the generated constitution YAML (required with --generate)",
    )


def handler(args: argparse.Namespace) -> int:
    """Dispatch policygen subcommands."""
    command = args.policygen_command
    if command == "generate":
        return _generate(args)
    if command == "scan":
        return _scan(args)
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

    return _generate_and_write(precontext, args.out)


def _scan(args: argparse.Namespace) -> int:
    try:
        result = scan_manifests(args.path, domain=args.domain, description=args.description)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not result.manifests:
        print(
            "Error: no supported manifest files (pyproject.toml, requirements.txt, "
            f"package.json) found under {args.path}",
            file=sys.stderr,
        )
        return 1

    if args.brief_out is not None:
        try:
            args.brief_out.write_text(
                json.dumps(result.precontext.to_dict(), sort_keys=True), encoding="utf-8"
            )
        except OSError as exc:
            print(f"Error: could not write brief to {args.brief_out}: {exc}", file=sys.stderr)
            return 1

    if args.generate:
        if args.out is None:
            print("Error: --out is required when --generate is set", file=sys.stderr)
            return 1
        return _generate_and_write(result.precontext, args.out)

    print(json.dumps(result.to_dict(), sort_keys=True))
    return 0


def _generate_and_write(precontext: PreContext, out: Path) -> int:
    """Generate a constitution YAML from ``precontext`` and print the JSON summary.

    Shared by ``generate`` (built from ``--brief``/flags) and ``scan --generate``
    (built from a manifest scan) so both verbs produce identical DRAFT-artifact
    output. This never submits, approves, or activates the resulting policy --
    that remains a separate, explicit lifecycle step.
    """
    generator = AdaptivePolicyGenerator()
    try:
        generated = generator.generate(precontext)
    except ValueError as exc:
        print(f"Error: failed to generate policy: {exc}", file=sys.stderr)
        return 1

    try:
        out_path = generated.write(out)
    except OSError as exc:
        print(f"Error: could not write output to {out}: {exc}", file=sys.stderr)
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
