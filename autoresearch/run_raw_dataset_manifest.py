"""Adapt and evaluate a manifest of local raw dataset exports."""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from autoresearch.evaluate_raw_dataset_cases import evaluate_cases
from autoresearch.raw_dataset_adapter import (
    DEFAULT_STRATIFY_BY,
    _load_rows,
    adapt_dataset_rows,
    synthesize_governance_cases,
)


def load_manifest(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Manifest must be a JSON array")
    return [dict(entry) for entry in payload]


def select_rows(
    rows: Sequence[dict[str, Any]],
    *,
    offset: int = 0,
    limit: int | None = None,
    sample_size: int | None = None,
    seed: int | None = None,
    stratify_by: str | None = None,
) -> list[dict[str, Any]]:
    """Apply manifest selection controls in the documented order."""
    selected = list(rows[max(offset, 0) :])

    if sample_size is not None and sample_size >= 0 and sample_size < len(selected):
        rng = random.Random(seed)
        if stratify_by:
            grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in selected:
                grouped[str(row.get(stratify_by, ""))].append(row)
            for group_rows in grouped.values():
                rng.shuffle(group_rows)
            ordered_keys = sorted(grouped)
            sampled: list[dict[str, Any]] = []
            while ordered_keys and len(sampled) < sample_size:
                next_keys: list[str] = []
                for key in ordered_keys:
                    bucket = grouped[key]
                    if bucket and len(sampled) < sample_size:
                        sampled.append(bucket.pop(0))
                    if bucket:
                        next_keys.append(key)
                ordered_keys = next_keys
            selected = sampled
        else:
            selected = rng.sample(selected, sample_size)

    if limit is not None:
        selected = selected[: max(limit, 0)]

    return selected


def _prepare_rows(dataset_slug: str, rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        if dataset_slug == "civil_comments":
            toxicity = float(item.get("toxicity", 0.0) or 0.0)
            if toxicity < 0.33:
                item["toxicity_bucket"] = "low"
            elif toxicity < 0.67:
                item["toxicity_bucket"] = "medium"
            else:
                item["toxicity_bucket"] = "high"
        prepared.append(item)
    return prepared


def build_cases_from_manifest_entries(
    manifest: Sequence[dict[str, Any]],
    *,
    base_dir: str | Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build synthesized cases and manifest metadata for each dataset entry."""
    root = Path(base_dir)
    all_cases: list[dict[str, Any]] = []
    datasets: list[dict[str, Any]] = []

    for entry in manifest:
        adapter_slug = str(entry.get("adapter_slug") or entry["dataset"])
        input_path = Path(str(entry["input"]))
        if not input_path.is_absolute():
            input_path = root / input_path

        offset = int(entry.get("offset", 0) or 0)
        limit = entry.get("limit")
        limit = None if limit is None else int(limit)
        sample_size = entry.get("sample_size")
        sample_size = None if sample_size is None else int(sample_size)
        seed = entry.get("seed")
        seed = None if seed is None else int(seed)
        stratify_by = entry.get("stratify_by")
        if stratify_by is None:
            stratify_by = DEFAULT_STRATIFY_BY.get(adapter_slug)
        profiles = list(entry.get("profiles", ["review", "escalate", "risky"]))

        raw_rows = _prepare_rows(adapter_slug, _load_rows(input_path))
        selected_rows = select_rows(
            raw_rows,
            offset=offset,
            limit=limit,
            sample_size=sample_size,
            seed=seed,
            stratify_by=stratify_by,
        )
        records = adapt_dataset_rows(adapter_slug, selected_rows)
        cases = synthesize_governance_cases(records, profiles=profiles)
        all_cases.extend(cases)
        datasets.append(
            {
                "dataset": adapter_slug,
                "adapter_slug": adapter_slug,
                "input": str(input_path),
                "records": len(records),
                "cases": len(cases),
                "profiles": profiles,
                "offset": offset,
                "limit": limit,
                "sample_size": sample_size,
                "seed": seed,
                "stratify_by": stratify_by,
            }
        )

    return all_cases, datasets


def run_manifest(
    manifest: Sequence[dict[str, Any]],
    *,
    base_dir: str | Path,
) -> dict[str, Any]:
    cases, datasets = build_cases_from_manifest_entries(manifest, base_dir=base_dir)
    summary = evaluate_cases(cases)
    summary["manifest_datasets"] = datasets
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    summary = run_manifest(manifest, base_dir=args.manifest.parent)
    rendered = json.dumps(summary, indent=2) + "\n"
    if args.output is None:
        print(rendered, end="")
        return
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
