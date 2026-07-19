"""Tests for the EU AI Act runtime enforcement examples.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples" / "eu_ai_act_runtime"

ART12_PATH = EXAMPLES_DIR / "art12_record_keeping.py"
ART14_PATH = EXAMPLES_DIR / "art14_human_oversight.py"
ART15_PATH = EXAMPLES_DIR / "art15_robustness.py"


def _load_example(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_art12_record_keeping_demo_facts() -> None:
    module = _load_example(ART12_PATH)

    result = module.run_demo()

    assert result["records_logged"] == 3
    assert result["chain_valid_before"] is True
    assert result["receipt_verified_before"] is True
    assert result["receipt_verified_after_tamper"] is False
    assert result["tamper_detected"] is True


def test_art14_human_oversight_demo_facts() -> None:
    module = _load_example(ART14_PATH)

    result = module.run_demo()

    assert result["deny_path_blocked"] is True
    assert result["side_effects_before_approval"] == 0
    assert result["ck002_raised"] is True
    assert result["approved_outcome"] == "approved"
    assert result["side_effects_after_approval"] == 1


def test_art15_robustness_demo_facts() -> None:
    module = _load_example(ART15_PATH)

    result = module.run_demo()

    assert result["benign_allowed"] is True
    assert result["injection_intercepted"] is True
    assert result["incidents_open"] == 1
    assert result["audit_chain_valid"] is True
    assert result["failure_entry_valid"] is False


@pytest.mark.parametrize(
    "script",
    [ART12_PATH, ART14_PATH, ART15_PATH],
    ids=["art12_record_keeping", "art14_human_oversight", "art15_robustness"],
)
def test_example_runs_successfully(script: Path) -> None:
    """Each example script must exit 0 with no unhandled exceptions."""
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(Path.home()),
            "PYTHONPATH": str(EXAMPLES_DIR.parent.parent / "src"),
            "OPENAI_API_KEY": "test-key-for-unit-tests",
            "ANTHROPIC_API_KEY": "test-key-for-unit-tests",
        },
    )
    assert result.returncode == 0, (
        f"{script.name} failed (exit {result.returncode}):\n"
        f"STDOUT:\n{result.stdout[-500:]}\n"
        f"STDERR:\n{result.stderr[-500:]}"
    )
