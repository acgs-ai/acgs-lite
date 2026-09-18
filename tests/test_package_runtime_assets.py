from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).parents[1]
WORKFLOW_NAMES = {
    "action_validation.yaml",
    "agent_onboarding.yaml",
    "compliance_assessment.yaml",
}


def test_workflow_templates_are_declared_as_package_data() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"]["package-data"]
    assert package_data["acgs_lite.workflows"] == ["*.yaml"]


def test_workflow_template_sources_are_nonempty() -> None:
    directory = ROOT / "src" / "acgs_lite" / "workflows"
    assert {path.name for path in directory.glob("*.yaml")} == WORKFLOW_NAMES
    assert all((directory / name).stat().st_size > 0 for name in WORKFLOW_NAMES)


def test_agent_quickstart_runs_from_copied_source_example(tmp_path: Path) -> None:
    copied = tmp_path / "agent_quickstart"
    shutil.copytree(ROOT / "examples" / "agent_quickstart", copied)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(
        [sys.executable, str(copied / "run.py")],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
