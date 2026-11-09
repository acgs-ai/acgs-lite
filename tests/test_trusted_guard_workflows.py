"""Trusted workflows must never execute candidate code with write authority."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", ["immutable-core-guard", "immutable-core-authorize"])
def test_trusted_workflow_source_and_token_boundary(name: str) -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / f"{name}.yml").read_text())
    triggers = workflow.get("on", workflow.get(True))
    assert "pull_request" not in triggers
    assert "workflow_dispatch" in triggers
    assert workflow["permissions"]["contents"] == "read"
    for job in workflow["jobs"].values():
        assert job["if"] == "github.ref == 'refs/heads/main'"
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", step["uses"])
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["ref"] == "${{ github.sha }}"
                assert step["with"]["persist-credentials"] is False
            if "trusted_core_guard.py" in step.get("run", ""):
                assert "python -I scripts/trusted_core_guard.py" in step["run"]
            assert "pip install" not in step.get("run", "")
    if name == "immutable-core-authorize":
        assert "statuses" not in workflow["permissions"]
    else:
        assert triggers["pull_request_target"]["branches"] == ["main"]


def test_guard_inputs_and_policy_are_themselves_protected() -> None:
    policy = json.loads((ROOT / ".github" / "immutable-core-policy.json").read_text())
    for path in (
        ".github/immutable-core-policy.json",
        ".github/workflows/immutable-core-authorize.yml",
        ".github/workflows/immutable-core-guard.yml",
        "scripts/trusted_core_guard.py",
        "scripts/render_trusted_core_policy.py",
    ):
        assert any(
            re.fullmatch(row["regex"], path, row["flags"]) for row in policy["protected_paths"]
        ), path


def test_snapshot_covers_registry_when_control_plane_is_installed() -> None:
    if not (ROOT / "src/acgs_lite/control_plane/immutable_core.py").exists():
        pytest.skip("bootstrap precedes the control-plane package")
    result = subprocess.run(
        [sys.executable, "scripts/render_trusted_core_policy.py", "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
