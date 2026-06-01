"""Drift guard for the agent-executable tool registry."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "validate_tools.py"


def _load_validate_tools_module():
    spec = importlib.util.spec_from_file_location("validate_tools", _SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tool_registry_references_live_commands() -> None:
    validate_tools = _load_validate_tools_module()

    problems = validate_tools.validate(_REPO_ROOT)

    assert problems == []


def test_tool_registry_rejects_unknown_tool_fields(tmp_path: Path) -> None:
    validate_tools = _load_validate_tools_module()
    (tmp_path / "tools").mkdir()
    (tmp_path / "Makefile").write_text("demo:\n\t@true\n", encoding="utf-8")
    (tmp_path / "tools" / "registry.yaml").write_text(
        """
version: 1
tools:
  - name: demo
    purpose: Demo command.
    command: make demo
    validation: make demo
    owner_module: Makefile
    unexpected: nope
""".lstrip(),
        encoding="utf-8",
    )

    problems = validate_tools.validate(tmp_path)

    assert any("unknown field" in problem for problem in problems)


def test_tool_registry_rejects_missing_python_module_commands(tmp_path: Path) -> None:
    validate_tools = _load_validate_tools_module()
    (tmp_path / "tools").mkdir()
    (tmp_path / "Makefile").write_text("demo:\n\t@true\n", encoding="utf-8")
    (tmp_path / "tools" / "registry.yaml").write_text(
        """
version: 1
tools:
  - name: missing-module
    purpose: Missing module command.
    command: python3 -m does_not_exist.cli run
    validation: make demo
    owner_module: Makefile
""".lstrip(),
        encoding="utf-8",
    )

    problems = validate_tools.validate(tmp_path)

    assert any("missing python module" in problem for problem in problems)
