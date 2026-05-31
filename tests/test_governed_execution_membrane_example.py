"""Tests for the minimal governed-execution membrane example."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

EXAMPLE_PATH = (
    Path(__file__).resolve().parent.parent / "examples" / "governed_execution_membrane.py"
)


def _load_example() -> ModuleType:
    spec = importlib.util.spec_from_file_location("governed_execution_membrane", EXAMPLE_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_membrane_demo_allows_transforms_denies_and_blocks_without_receipt() -> None:
    module = _load_example()

    result = module.run_demo()

    assert result["decisions"] == ["ALLOW", "TRANSFORM", "DENY"]
    assert result["receiptless_blocked"] is True
    assert result["denied_blocked"] is True
    assert len(result["outbox"]) == 2
    assert "Your invoice is ready" in result["outbox"][0]
    assert "[REDACTED-SSN]" in result["outbox"][1]
    assert "123-45-6789" not in result["outbox"][1]
    assert all("wire transfer" not in item for item in result["outbox"])


def test_membrane_demo_exposes_replayable_audit_evidence() -> None:
    module = _load_example()

    result = module.run_demo()

    assert result["audit_entries"] >= 4
    assert result["audit_chain_valid"] is True
    assert result["first_audit_entry"]["type"] == "validation"
    assert result["first_audit_entry"]["constitutional_hash"]
