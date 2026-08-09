#!/usr/bin/env python3
"""Produce a deterministic release-proof artifact for ACGS-Lite.

The script runs the existing governed-execution membrane example and emits a
JSON summary that can be inspected or archived as a reproducible proof artifact.
It does not require API keys or external services.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acgs_lite import __version__  # noqa: E402
from governed_execution_membrane import run_demo  # noqa: E402


def build_payload() -> dict[str, Any]:
    result = run_demo()
    return {
        "release": __version__,
        "proof_type": "governed_execution_membrane",
        "summary": {
            "decisions": result["decisions"],
            "executed_side_effects": len(result["outbox"]),
            "denied_execution_blocked": result["denied_blocked"],
            "receiptless_execution_blocked": result["receiptless_blocked"],
            "audit_entries": result["audit_entries"],
            "audit_chain_valid": result["audit_chain_valid"],
        },
        "audit_first_entry": result["first_audit_entry"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write the JSON payload to",
    )
    args = parser.parse_args()

    payload = build_payload()
    payload_json = json.dumps(payload, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload_json + "\n", encoding="utf-8")

    print(payload_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
