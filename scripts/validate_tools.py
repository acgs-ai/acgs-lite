#!/usr/bin/env python3
"""Validate ``tools/registry.yaml`` against its schema contract and live commands.

The registry is a catalog, not the source of truth: the Makefile and scripts are.
This validator keeps the catalog schema-compatible and proves it never describes
a dead tool by asserting that every ``make <target>`` and every ``scripts/<name>.py``
referenced by a tool's ``command`` or ``validation`` actually exists.

Usage::

    python3 scripts/validate_tools.py         # exit non-zero on any problem

Wired into ``make validate`` and ``scripts/agent_ready.py``. Importable: ``validate()``
returns a list of problem strings so callers can fold the result into a larger report.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - PyYAML is a hard dependency.
    yaml = None  # type: ignore[assignment]

_REQUIRED_KEYS = ("name", "purpose", "command", "validation", "owner_module")
_OPTIONAL_KEYS = ("env", "inputs", "outputs", "failure_modes", "retry")
_ALLOWED_KEYS = set(_REQUIRED_KEYS) | set(_OPTIONAL_KEYS)
_LIST_KEYS = ("env", "inputs", "outputs", "failure_modes")
_STRING_KEYS = ("name", "purpose", "command", "retry", "validation", "owner_module")
_MAKE_TARGET_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*):")
_SCRIPT_RE = re.compile(r"scripts/[A-Za-z0-9_./-]+\.py")
_PYTHON_TOKENS = {"python", "python3"}


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def makefile_targets(makefile: Path) -> set[str]:
    """Return the set of declared make target names."""
    targets: set[str] = set()
    if not makefile.exists():
        return targets
    for line in makefile.read_text(encoding="utf-8").splitlines():
        if line.startswith("\t") or line.startswith("#") or "=" in line.split(":", 1)[0]:
            continue
        match = _MAKE_TARGET_RE.match(line)
        if match and match.group(1) != ".PHONY":
            targets.add(match.group(1))
    return targets


def _referenced_make_targets(command: str) -> list[str]:
    """Extract target names following a ``make`` token in a command string."""
    tokens = command.replace("&&", " ").replace(";", " ").split()
    targets: list[str] = []
    for i, token in enumerate(tokens):
        if token == "make" and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            if not nxt.startswith("-"):  # skip flags like `make -C dir`
                targets.append(nxt)
    return targets


def _command_tokens(command: str) -> list[str]:
    """Return coarse shell tokens for registry command validation.

    The registry intentionally stores simple command strings, not arbitrary shell programs.
    Splitting on whitespace plus common separators is enough to catch dead references while
    staying dependency-free and side-effect-free.
    """
    return command.replace("&&", " ").replace(";", " ").split()


def _referenced_python_modules(command: str) -> list[str]:
    """Extract modules referenced by ``python -m <module>`` command fragments."""
    tokens = _command_tokens(command)
    modules: list[str] = []
    for idx, token in enumerate(tokens):
        executable = Path(token).name
        if executable not in _PYTHON_TOKENS:
            continue
        if idx + 2 >= len(tokens) or tokens[idx + 1] != "-m":
            continue
        module = tokens[idx + 2]
        if module and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", module):
            modules.append(module)
    return modules


def python_module_exists(module: str, base: Path) -> bool:
    """Return whether a ``python -m`` target is discoverable from this checkout.

    Prefer a source-tree path check for ``src/`` modules so validation does not import
    package ``__init__`` files or optional dependencies. Fall back to ``find_spec`` for
    stdlib/installed modules.
    """
    parts = module.split(".")
    module_path = Path(*parts)
    src_root = base / "src"
    if (src_root / module_path.with_suffix(".py")).exists():
        return True
    if (src_root / module_path / "__init__.py").exists():
        return True
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def load_registry(path: Path) -> dict:
    if yaml is None:  # pragma: no cover
        raise RuntimeError("PyYAML is required to load the tool registry")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("tools/registry.yaml must be a mapping with a 'tools' list")
    return data


def validate(root: Path | None = None) -> list[str]:
    """Return a list of problems; empty means the tool registry is valid and live."""
    base = root or repo_root()
    registry_path = base / "tools" / "registry.yaml"
    problems: list[str] = []

    if not registry_path.exists():
        return [f"missing tool registry: {registry_path}"]
    if yaml is None:
        return ["PyYAML unavailable — cannot validate tools/registry.yaml"]

    data = load_registry(registry_path)
    root_keys = set(data)
    if root_keys - {"version", "tools"}:
        problems.append(
            "tools/registry.yaml has unknown top-level fields: "
            + ", ".join(sorted(root_keys - {"version", "tools"}))
        )
    if not isinstance(data.get("version"), int):
        problems.append("tools/registry.yaml field 'version' must be an integer")

    tools = data.get("tools")
    if not isinstance(tools, list) or not tools:
        problems.append("tools/registry.yaml has no 'tools' list")
        return problems

    targets = makefile_targets(base / "Makefile")
    seen_names: set[str] = set()

    for idx, tool in enumerate(tools):
        if not isinstance(tool, dict):
            problems.append(f"tool #{idx} is not a mapping")
            continue
        name = str(tool.get("name", f"#{idx}"))
        unknown = set(tool) - _ALLOWED_KEYS
        if unknown:
            problems.append(f"tool '{name}' has unknown field(s): {', '.join(sorted(unknown))}")
        for key in _REQUIRED_KEYS:
            if not tool.get(key):
                problems.append(f"tool '{name}' is missing required field '{key}'")
        for key in _STRING_KEYS:
            if key in tool and not isinstance(tool[key], str):
                problems.append(f"tool '{name}' field '{key}' must be a string")
        for key in _LIST_KEYS:
            if key in tool and not isinstance(tool[key], list):
                problems.append(f"tool '{name}' field '{key}' must be a list")
        if name in seen_names:
            problems.append(f"duplicate tool name '{name}'")
        seen_names.add(name)

        for field in ("command", "validation"):
            command = str(tool.get(field, ""))
            if not command:
                continue
            for target in _referenced_make_targets(command):
                if target not in targets:
                    problems.append(
                        f"tool '{name}' {field} references missing make target '{target}'"
                    )
            for script in _SCRIPT_RE.findall(command):
                if not (base / script).exists():
                    problems.append(f"tool '{name}' {field} references missing script '{script}'")
            for module in _referenced_python_modules(command):
                if not python_module_exists(module, base):
                    problems.append(
                        f"tool '{name}' {field} references missing python module '{module}'"
                    )

        owner = str(tool.get("owner_module", ""))
        if owner and ("/" in owner or owner in {"Makefile", "pyproject.toml"}):
            if not (base / owner).exists():
                problems.append(f"tool '{name}' owner_module path does not exist: '{owner}'")

    return problems


def main(argv: list[str] | None = None) -> int:
    problems = validate()
    if problems:
        print("tools/registry.yaml validation failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("tools/registry.yaml is valid (all referenced targets and scripts exist)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
