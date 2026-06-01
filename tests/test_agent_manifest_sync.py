"""Drift guard for generated per-agent manifests."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "sync_agents.py"


def _load_sync_agents_module():
    spec = importlib.util.spec_from_file_location("sync_agents", _SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_agent_manifests_match_agent_index() -> None:
    sync_agents = _load_sync_agents_module()

    problems = sync_agents.check(_REPO_ROOT / "agent-index.json", _REPO_ROOT / "agents")

    assert problems == []


def test_manifest_filename_rejects_path_traversal_agent_ids() -> None:
    sync_agents = _load_sync_agents_module()

    for agent_id in ("../outside", "nested/agent", r"nested\\agent", "..", "."):
        try:
            sync_agents.manifest_filename({"agent_id": agent_id})
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {agent_id!r}")


def test_validate_agent_index_rejects_missing_executable_metadata(tmp_path: Path) -> None:
    sync_agents = _load_sync_agents_module()
    index_path = tmp_path / "agent-index.json"
    index_path.write_text(
        """
[
  {
    "agent_id": "demo",
    "name": "Demo",
    "metadata": {
      "purpose": "Demo agent.",
      "scope": "Read-only.",
      "execution_command": "/demo",
      "required_tools": [],
      "inputs": [],
      "outputs": [],
      "safety_constraints": [],
      "validation_checks": [],
      "failure_modes": []
    }
  }
]
""".lstrip(),
        encoding="utf-8",
    )

    problems = sync_agents.validate_agent_index(index_path)

    assert problems == ["agent 'demo' is missing metadata.expected_artifacts"]


def test_validate_agent_index_rejects_metadata_profile_key_collisions(tmp_path: Path) -> None:
    sync_agents = _load_sync_agents_module()
    index_path = tmp_path / "agent-index.json"
    index_path.write_text(
        """
[
  {
    "agent_id": "demo",
    "name": "Demo",
    "metadata": {
      "agent_id": "shadow",
      "purpose": "Demo agent.",
      "scope": "Read-only.",
      "execution_command": "/demo",
      "required_tools": [],
      "inputs": [],
      "outputs": [],
      "safety_constraints": [],
      "validation_checks": [],
      "expected_artifacts": [],
      "failure_modes": []
    }
  }
]
""".lstrip(),
        encoding="utf-8",
    )

    problems = sync_agents.validate_agent_index(index_path)

    assert problems == ["agent 'demo' metadata collides with profile field(s): agent_id"]


def test_validate_agent_index_rejects_metadata_metadata_collision(tmp_path: Path) -> None:
    sync_agents = _load_sync_agents_module()
    index_path = tmp_path / "agent-index.json"
    index_path.write_text(
        """
[
  {
    "agent_id": "demo",
    "name": "Demo",
    "metadata": {
      "metadata": "shadow",
      "purpose": "Demo agent.",
      "scope": "Read-only.",
      "execution_command": "/demo",
      "required_tools": [],
      "inputs": [],
      "outputs": [],
      "safety_constraints": [],
      "validation_checks": [],
      "expected_artifacts": [],
      "failure_modes": []
    }
  }
]
""".lstrip(),
        encoding="utf-8",
    )

    problems = sync_agents.validate_agent_index(index_path)

    assert problems == ["agent 'demo' metadata collides with profile field(s): metadata"]
