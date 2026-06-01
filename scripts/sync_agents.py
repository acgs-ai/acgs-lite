#!/usr/bin/env python3
"""Generate per-agent manifests under ``agents/`` from the canonical ``agent-index.json``.

``agent-index.json`` (repo root) is the single source of truth for agent discovery: it
is loaded at runtime by :class:`acgs_lite.agents.AgentRegistry` and guarded against drift
by ``tests/test_agent_index.py``. The goal's per-agent ``agents/<id>.agent.yaml`` files are
a *derived view* of that index — human-browsable, one file per agent, with the agent-contract
fields flattened to the top level. They are generated, never hand-edited.

Usage::

    python3 scripts/sync_agents.py           # (re)generate agents/*.agent.yaml
    python3 scripts/sync_agents.py --check   # exit non-zero if any file is missing/stale/orphaned

``make agents-sync`` runs the generator; ``--check`` is wired into ``make validate`` and the
``scripts/agent_ready.py`` self-check so a drifted manifest fails CI instead of going unnoticed.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - PyYAML is a hard dependency (pyproject).
    yaml = None  # type: ignore[assignment]


GENERATED_BANNER = (
    "# GENERATED FILE — do not edit by hand.\n"
    "# Source of truth: agent-index.json (repo root). Regenerate with: make agents-sync\n"
)

# Top-level AgentCapabilityProfile fields, in a stable, readable order.
_PROFILE_KEYS = (
    "agent_id",
    "name",
    "description",
    "support_level",
    "stability",
    "is_active",
    "capabilities",
    "domains",
    "skills",
    "tags",
)
_PROFILE_COLLISION_KEYS = set(_PROFILE_KEYS) | {"metadata"}
_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_REQUIRED_METADATA_STRING_KEYS = (
    "purpose",
    "scope",
    "execution_command",
)
_REQUIRED_METADATA_LIST_KEYS = (
    "required_tools",
    "inputs",
    "outputs",
    "safety_constraints",
    "validation_checks",
    "expected_artifacts",
    "failure_modes",
)
_REQUIRED_METADATA_KEYS = _REQUIRED_METADATA_STRING_KEYS + _REQUIRED_METADATA_LIST_KEYS


def repo_root() -> Path:
    """Return the repository root (this script's parent's parent)."""
    return Path(__file__).resolve().parent.parent


def _load_index(index_path: Path) -> list[dict[str, Any]]:
    import json

    raw = json.loads(index_path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("agent-index.json must be a JSON list")
    entries: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each agent-index entry must be an object")
        entries.append(item)
    return entries


def build_manifest(entry: dict[str, Any]) -> dict[str, Any]:
    """Flatten one agent-index entry into a per-agent manifest dict.

    Top-level profile fields come first; the free-form ``metadata`` contract fields
    (purpose, scope, required_tools, inputs, outputs, safety_constraints,
    execution_command, validation_checks, expected_artifacts, ...) are merged in at the
    top level for readability. The flattening is deterministic so ``--check`` can compare
    a freshly-built manifest against the on-disk file by value.
    """
    manifest: dict[str, Any] = {}
    for key in _PROFILE_KEYS:
        if key in entry:
            manifest[key] = entry[key]
    metadata = entry.get("metadata", {})
    if isinstance(metadata, dict):
        for key, value in metadata.items():
            # Metadata never collides with profile keys (asserted by tests); be explicit.
            manifest.setdefault(key, value)
    return manifest


def validate_agent_index(index_path: Path) -> list[str]:
    """Return repo-owned agent-contract problems for ``agent-index.json``.

    ``AgentRegistry`` intentionally accepts lightweight capability profiles, but this
    repository's own agents must also be executable by future coding agents. That richer
    contract is enforced here, before generated manifests are compared or written.
    """
    problems: list[str] = []
    seen_ids: set[str] = set()
    for idx, entry in enumerate(_load_index(index_path)):
        label = str(entry.get("agent_id", f"#{idx}"))
        agent_id = entry.get("agent_id")
        if not isinstance(agent_id, str) or not _AGENT_ID_RE.fullmatch(agent_id):
            problems.append(f"agent '{label}' has unsafe or missing agent_id")
        elif agent_id in seen_ids:
            problems.append(f"agent '{agent_id}' is duplicated in agent-index.json")
        elif isinstance(agent_id, str):
            seen_ids.add(agent_id)

        metadata = entry.get("metadata")
        if not isinstance(metadata, dict):
            problems.append(f"agent '{label}' metadata must be an object")
            continue

        collisions = sorted(set(metadata) & _PROFILE_COLLISION_KEYS)
        if collisions:
            problems.append(
                f"agent '{label}' metadata collides with profile field(s): " + ", ".join(collisions)
            )

        for key in _REQUIRED_METADATA_STRING_KEYS:
            if not isinstance(metadata.get(key), str) or not metadata.get(key):
                problems.append(f"agent '{label}' metadata.{key} must be a non-empty string")
        for key in _REQUIRED_METADATA_LIST_KEYS:
            if key not in metadata:
                problems.append(f"agent '{label}' is missing metadata.{key}")
            elif not isinstance(metadata[key], list):
                problems.append(f"agent '{label}' metadata.{key} must be a list")

    return problems


def manifest_filename(entry: dict[str, Any]) -> str:
    """Return a safe generated-manifest filename for one agent-index entry."""
    agent_id = str(entry["agent_id"])
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise ValueError(f"unsafe agent_id for manifest filename: {agent_id!r}")
    return f"{agent_id}.agent.yaml"


def render_yaml(manifest: dict[str, Any]) -> str:
    """Render a manifest to deterministic YAML with the generated banner."""
    if yaml is None:  # pragma: no cover - guarded by caller.
        raise RuntimeError("PyYAML is required to render agent manifests")
    body = yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False, allow_unicode=True)
    return GENERATED_BANNER + body


def expected_manifests(index_path: Path) -> dict[str, dict[str, Any]]:
    """Return ``{filename: manifest}`` for every entry in the index."""
    problems = validate_agent_index(index_path)
    if problems:
        raise ValueError("; ".join(problems))
    return {manifest_filename(entry): build_manifest(entry) for entry in _load_index(index_path)}


def _parse_on_disk(path: Path) -> dict[str, Any]:
    if yaml is None:  # pragma: no cover - guarded by caller.
        raise RuntimeError("PyYAML is required to parse agent manifests")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def check(index_path: Path, agents_dir: Path) -> list[str]:
    """Return a list of drift problems; empty list means the manifests are in sync."""
    problems: list[str] = []
    contract_problems = validate_agent_index(index_path)
    if contract_problems:
        return contract_problems
    expected = expected_manifests(index_path)
    on_disk = {p.name for p in agents_dir.glob("*.agent.yaml")} if agents_dir.exists() else set()

    for orphan in sorted(on_disk - expected.keys()):
        problems.append(f"orphaned manifest (no matching agent-index entry): {orphan}")

    for filename, manifest in expected.items():
        path = agents_dir / filename
        if not path.exists():
            problems.append(f"missing manifest: {filename} (run: make agents-sync)")
            continue
        if _parse_on_disk(path) != manifest:
            problems.append(f"stale manifest: {filename} (run: make agents-sync)")
    return problems


def write(index_path: Path, agents_dir: Path) -> list[str]:
    """Regenerate all manifests; remove orphans. Return the list of written filenames."""
    agents_dir.mkdir(parents=True, exist_ok=True)
    expected = expected_manifests(index_path)
    for orphan in set(p.name for p in agents_dir.glob("*.agent.yaml")) - expected.keys():
        (agents_dir / orphan).unlink()
    written: list[str] = []
    for filename, manifest in sorted(expected.items()):
        (agents_dir / filename).write_text(render_yaml(manifest), encoding="utf-8")
        written.append(filename)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify sync instead of writing")
    args = parser.parse_args(argv)

    if yaml is None:
        print("PyYAML is required (pip install -e '.[dev]')", file=sys.stderr)
        return 2

    root = repo_root()
    index_path = root / "agent-index.json"
    agents_dir = root / "agents"

    if args.check:
        problems = check(index_path, agents_dir)
        if problems:
            print("agents/ is out of sync with agent-index.json:", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        print(f"agents/ in sync ({len(expected_manifests(index_path))} manifests)")
        return 0

    written = write(index_path, agents_dir)
    print(f"Wrote {len(written)} manifest(s) to {agents_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
