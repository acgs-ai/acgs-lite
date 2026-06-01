"""Tests for the agent-oriented readiness check script."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "agent_ready.py"


def _load_agent_ready_module():
    spec = importlib.util.spec_from_file_location("agent_ready", _SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_agent_index_check_loads_root_manifest_and_ranks_governance_review() -> None:
    agent_ready = _load_agent_ready_module()

    result = agent_ready.check_agent_index(_REPO_ROOT)

    assert result.status == "passed"
    assert "governance-branch-review" in result.detail


def test_recommended_commands_include_make_free_and_make_paths() -> None:
    agent_ready = _load_agent_ready_module()

    commands = agent_ready.build_recommended_commands("python3")

    assert any("scripts/agent_ready.py --run-tests" in command for command in commands)
    assert any("tests/test_agent_registry.py" in command for command in commands)
    assert any(command.startswith("make ") for command in commands)


def test_collect_checks_without_running_tests_reports_skipped_targeted_tests() -> None:
    agent_ready = _load_agent_ready_module()

    results = agent_ready.collect_checks(_REPO_ROOT, python="python3", run_tests=False)
    by_name = {result.name: result for result in results}

    assert by_name["agent-index"].status == "passed"
    assert by_name["targeted-tests"].status == "skipped"
    assert by_name["recommended-commands"].status == "passed"


def test_json_cli_is_machine_readable_without_running_tests() -> None:
    completed = subprocess.run(
        [sys.executable, str(_SCRIPT_PATH), "--json", "--no-run-tests"],
        capture_output=True,
        check=False,
        cwd=_REPO_ROOT,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["status"] == "passed"
    assert {check["name"] for check in payload["checks"]} >= {
        "agent-index",
        "root-docs",
        "agent-contract",
        "agent-manifests",
        "tool-registry",
        "targeted-tests",
        "recommended-commands",
    }


def test_json_cli_loads_agent_index_from_source_tree_without_site_packages() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            str(_SCRIPT_PATH),
            "--json",
            "--no-run-tests",
            "--allow-skips",
        ],
        capture_output=True,
        check=False,
        cwd=_REPO_ROOT,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    by_name = {check["name"]: check for check in payload["checks"]}
    assert by_name["agent-index"]["status"] == "passed"


def test_json_cli_fails_on_skipped_required_integrity_checks_by_default() -> None:
    completed = subprocess.run(
        [sys.executable, "-S", str(_SCRIPT_PATH), "--json", "--no-run-tests"],
        capture_output=True,
        check=False,
        cwd=_REPO_ROOT,
        text=True,
    )

    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    assert payload["status"] == "failed"
    assert any(check["status"] == "skipped" for check in payload["checks"])


def test_workspace_integrity_checks_pass_in_prepared_environment() -> None:
    agent_ready = _load_agent_ready_module()

    results = agent_ready.collect_checks(_REPO_ROOT, python="python3", run_tests=False)
    by_name = {result.name: result for result in results}

    assert by_name["root-docs"].status == "passed"
    assert by_name["agent-contract"].status == "passed"
    assert by_name["agent-manifests"].status == "passed"
    assert by_name["tool-registry"].status == "passed"
