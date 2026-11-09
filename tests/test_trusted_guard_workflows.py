"""Trusted workflows must never execute candidate code with write authority."""

from __future__ import annotations

import json
import os
import re
import shutil
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
        "mypy.ini",
        ".mypy.ini",
        "src/acgs_lite/observability.py",
        "src/acgs_lite/observability.pyc",
        "src/acgs_lite/observability.cpython-310-x86_64-linux-gnu.so",
        "src/acgs_lite/observability.pyd",
        "src/acgs_lite/__pycache__/observability.cpython-310.pyc",
        "acgs_lite.py",
        "acgs_lite.pyc",
        "acgs_lite.cpython-310-x86_64-linux-gnu.so",
        "acgs_lite.pyd",
        "acgs_lite/__init__.py",
        "acgs_lite/__init__.pyc",
        "acgs_lite/__init__.cpython-310-x86_64-linux-gnu.so",
        "acgs_lite/__init__.pyd",
        "yaml.py",
        "json.py",
        "pydantic/__init__.py",
        "src/acgs_lite/control_plane.py",
        "src/acgs_lite/control_plane.pyc",
        "src/acgs_lite/control_plane.cpython-310-x86_64-linux-gnu.so",
        "src/acgs_lite/control_plane.pyd",
        "src/acgs_lite/engine.py",
        "src/acgs_lite/engine.pyc",
        "src/acgs_lite/engine.cpython-310-x86_64-linux-gnu.so",
        "src/acgs_lite/engine.pyd",
        "src/acgs_lite/constitution.py",
        "src/acgs_lite/constitution.pyc",
        "src/acgs_lite/constitution.cpython-310-x86_64-linux-gnu.so",
        "src/acgs_lite/constitution.pyd",
        "src/acgs_lite/agents.py",
        "src/acgs_lite/agents.pyc",
        "src/acgs_lite/agents.cpython-310-x86_64-linux-gnu.so",
        "src/acgs_lite/agents.pyd",
        "src/acgs_lite/__pycache__/control_plane.cpython-310.pyc",
        "src/acgs_lite/__pycache__/engine.cpython-310.pyc",
        "src/acgs_lite/__pycache__/constitution.cpython-310.pyc",
        "src/acgs_lite/__pycache__/agents.cpython-310.pyc",
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


@pytest.mark.parametrize(
    "path",
    ["acgs_lite.py", "acgs_lite/__init__.py", "yaml.py", "json.py", "pydantic/__init__.py"],
)
def test_cwd_shadow_of_capability_gate_requires_core_authorization(
    tmp_path: Path, path: str
) -> None:
    shadow = tmp_path / path
    shadow.parent.mkdir(parents=True, exist_ok=True)
    shadow.write_text("print('shadowed capability gate'); raise SystemExit(0)\n")
    result = subprocess.run(
        [sys.executable, "-m", "acgs_lite.cli", "capabilities", "validate"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "shadowed capability gate"
    policy = json.loads((ROOT / ".github" / "immutable-core-policy.json").read_text())
    assert any(
        re.fullmatch(row["regex"], path, row["flags"]) for row in policy["protected_paths"]
    ), path


@pytest.mark.parametrize("path", ["workspace/feature.py", "workspace/package/__init__.py"])
def test_root_import_shadow_protection_does_not_freeze_workspace(path: str) -> None:
    policy = json.loads((ROOT / ".github" / "immutable-core-policy.json").read_text())
    assert not any(
        re.fullmatch(row["regex"], path, row["flags"]) for row in policy["protected_paths"]
    ), path


def test_namespace_ancestor_shadow_of_cli_requires_core_authorization(tmp_path: Path) -> None:
    source = tmp_path / "src"
    shutil.copytree(
        ROOT / "src/acgs_lite",
        source / "acgs_lite",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        symlinks=True,
    )
    path = "src/acgs_lite/observability.py"
    (tmp_path / path).write_text("print('namespace shadow executed'); raise SystemExit(0)\n")
    result = subprocess.run(
        [sys.executable, "-m", "acgs_lite.cli", "capabilities", "validate"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(source)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "namespace shadow executed"
    policy = json.loads((ROOT / ".github" / "immutable-core-policy.json").read_text())
    assert any(
        re.fullmatch(row["regex"], path, row["flags"]) for row in policy["protected_paths"]
    ), path
