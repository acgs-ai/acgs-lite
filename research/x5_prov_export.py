"""X5: ACGS logs export to PROV-JSON with >95% coverage.

Hypothesis: ACGS audit entries map to W3C PROV-JSON with >95% field
coverage and zero schema errors.

Metrics:
  - coverage >= 95%
  - errors == 0

Failure: Coverage <80% or errors >5.

Command:
  python x5_prov_export.py --events 50 --seed 42
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


# ---------------------------------------------------------------------------
# Simulated ACGS audit entries
# ---------------------------------------------------------------------------


def _make_audit_entry(rng: random.Random, index: int) -> dict[str, Any]:
    entry_types = ["validation", "maci_check", "override", "governance_decision", "bundle_bind"]
    entry_type = rng.choice(entry_types)
    return {
        "id": f"entry-{index:04d}",
        "type": entry_type,
        "agent_id": f"agent-{rng.randint(1, 10):02d}",
        "action": rng.choice(
            ["propose", "validate", "execute", "deploy", "read", "audit", "bind", "override"]
        ),
        "valid": rng.random() < 0.8,
        "violations": ["MACI"] if entry_type == "maci_check" and rng.random() < 0.3 else [],
        "constitutional_hash": "608508a9bd224290",
        "pqc_signature": None,
        "latency_ms": rng.uniform(0.1, 500.0),
        "metadata": {"bundle_version": f"v{rng.randint(1, 5)}.0"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# ---------------------------------------------------------------------------
# PROV-JSON mapping
# ---------------------------------------------------------------------------

PROV_ENTITY_KEYS = {
    "id": "prov:id",
    "type": "prov:type",
    "agent_id": "prov:wasAttributedTo",
    "timestamp": "prov:generatedAtTime",
    "metadata": "prov:other",
}

PROV_ACTIVITY_KEYS = {
    "action": "prov:label",
    "latency_ms": "prov:duration",
    "valid": "acgs:validation_status",
    "violations": "acgs:violations",
}


def map_to_prov(entry: dict[str, Any]) -> dict[str, Any]:
    """Map one ACGS audit entry to a PROV-JSON fragment."""
    prov: dict[str, Any] = {"@context": "http://www.w3.org/ns/prov#"}

    # Map entity-level fields
    for acgs_key, prov_key in PROV_ENTITY_KEYS.items():
        if acgs_key in entry and entry[acgs_key] is not None:
            prov[prov_key] = entry[acgs_key]

    # Map activity-level fields
    for acgs_key, prov_key in PROV_ACTIVITY_KEYS.items():
        if acgs_key in entry and entry[acgs_key] is not None:
            prov[prov_key] = entry[acgs_key]

    # Constitutional hash as provenance entity identifier
    if entry.get("constitutional_hash"):
        prov["acgs:constitutional_hash"] = entry["constitutional_hash"]

    # PQC signature as provenance signature
    if entry.get("pqc_signature") is not None:
        prov["acgs:pqc_signature"] = entry["pqc_signature"]

    return prov


def validate_prov(prov: dict[str, Any]) -> list[str]:
    """Validate a PROV-JSON fragment. Returns list of error messages."""
    errors: list[str] = []
    if "prov:id" not in prov:
        errors.append("Missing prov:id")
    if "prov:type" not in prov:
        errors.append("Missing prov:type")
    if "prov:wasAttributedTo" not in prov:
        errors.append("Missing prov:wasAttributedTo")
    return errors


def run_experiment(num_events: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    entries = [_make_audit_entry(rng, i) for i in range(num_events)]

    mapped = [map_to_prov(e) for e in entries]
    errors = []
    for i, prov in enumerate(mapped):
        entry_errors = validate_prov(prov)
        if entry_errors:
            errors.append({"entry_index": i, "errors": entry_errors})

    # Coverage: count how many ACGS fields are represented in PROV
    acgs_fields = set()
    prov_fields = set()
    for entry in entries:
        acgs_fields.update(k for k in entry if entry[k] is not None)
    for prov in mapped:
        prov_fields.update(prov.keys())

    # Direct field coverage (approximate)
    coverage = len(prov_fields) / max(len(acgs_fields), 1)

    return {
        "simulation": _simulation_metadata(seed),
        "events": num_events,
        "seed": seed,
        "entries_mapped": len(mapped),
        "errors": len(errors),
        "error_details": errors[:5],  # cap output
        "coverage_estimate": coverage,
        "acgs_fields": sorted(acgs_fields),
        "prov_fields": sorted(prov_fields),
        "pass": {
            "coverage_ge_95": coverage >= 0.95,
            "errors_zero": len(errors) == 0,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="X5: PROV-JSON export coverage")
    parser.add_argument("--events", type=int, default=50)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default="x5_results.json")
    args = parser.parse_args()

    result = run_experiment(args.events, args.seed)
    Path(args.output).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
