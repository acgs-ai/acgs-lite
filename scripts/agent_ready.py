#!/usr/bin/env python3
"""Agent-oriented readiness checks for ACGS-Lite.

This script is intentionally stdlib-only so coding agents and humans have a
direct fallback when `make` is unavailable or the local virtualenv is stale.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import types
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

AGENT_TESTS = (
    "tests/test_agent_registry.py",
    "tests/test_governed_selector.py",
    "tests/test_agent_index.py",
)

TEST_ENV = {
    "OPENAI_API_KEY": "test-key-for-unit-tests",
    "ANTHROPIC_API_KEY": "test-key-for-unit-tests",
}

REQUIRED_DOCS = (
    "README.md",
    "AGENTS.md",
    "ARCHITECTURE.md",
    "PROJECT_MAP.md",
    "TOOLS.md",
    "TASKS.md",
    "DECISIONS.md",
    "CONTRIBUTING.md",
    "BLOCKERS.md",
)


class CheckResult(NamedTuple):
    """Machine-readable check result."""

    name: str
    status: str
    detail: str
    command: str | None = None


def repo_root_from(path: Path | None = None) -> Path:
    """Return the repository root, defaulting to this script's parent tree."""
    if path is not None:
        return path.resolve()
    return Path(__file__).resolve().parent.parent


def _source_module_path(repo_root: Path, relative: str) -> Path:
    return repo_root / "src" / "acgs_lite" / "agents" / relative


def _load_source_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_agent_registry_from_source(repo_root: Path):
    """Load AgentRegistry from source files without importing acgs_lite.__init__."""
    package_root = repo_root / "src" / "acgs_lite"
    agents_root = package_root / "agents"
    if not agents_root.exists():
        raise ModuleNotFoundError("source package not found at src/acgs_lite/agents")

    acgs_package = sys.modules.setdefault("acgs_lite", types.ModuleType("acgs_lite"))
    acgs_package.__path__ = [str(package_root)]  # type: ignore[attr-defined]
    agents_package = sys.modules.setdefault(
        "acgs_lite.agents", types.ModuleType("acgs_lite.agents")
    )
    agents_package.__path__ = [str(agents_root)]  # type: ignore[attr-defined]

    _load_source_module(
        "acgs_lite.agents.capability",
        _source_module_path(repo_root, "capability.py"),
    )
    registry_module = _load_source_module(
        "acgs_lite.agents.registry",
        _source_module_path(repo_root, "registry.py"),
    )
    return registry_module.AgentRegistry


def _load_agent_registry(repo_root: Path):
    """Return AgentRegistry from an installed package or this source checkout."""
    if _source_module_path(repo_root, "registry.py").exists():
        return _load_agent_registry_from_source(repo_root)

    from acgs_lite.agents import AgentRegistry

    return AgentRegistry


def _with_source_pythonpath(repo_root: Path, env: dict[str, str]) -> dict[str, str]:
    """Prepend repo src/ to PYTHONPATH for subprocesses run from a checkout."""
    src_path = repo_root / "src"
    if not src_path.exists():
        return env
    current = env.get("PYTHONPATH")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{current}" if current else str(src_path)
    return env


def build_recommended_commands(python: str = "python3") -> list[str]:
    """Return the smallest useful command ladder for agent-executable validation."""
    test_paths = " ".join(AGENT_TESTS)
    return [
        f"{python} scripts/agent_ready.py --run-tests",
        f"{python} -m pytest {test_paths} -q --import-mode=importlib",
        f"{python} scripts/sync_agents.py --check",
        f"{python} scripts/validate_tools.py",
        f"{python} -m ruff check .",
        f"{python} -m mypy src/acgs_lite --ignore-missing-imports",
        f"{python} -m build",
        "make test-quick",
        "make lint",
        "make typecheck",
        "make build",
    ]


def check_agent_index(repo_root: Path) -> CheckResult:
    """Load the repo agent index and verify governance review is discoverable."""
    index_path = repo_root / "agent-index.json"
    if not index_path.exists():
        return CheckResult("agent-index", "failed", f"missing {index_path}")

    try:
        AgentRegistry = _load_agent_registry(repo_root)
        registry = AgentRegistry.from_manifest(index_path)
        ranked = registry.candidates_for("review a branch for governance regressions")
    except Exception as exc:  # pragma: no cover - detail is exercised by callers.
        return CheckResult("agent-index", "failed", f"{type(exc).__name__}: {exc}")

    if not ranked:
        return CheckResult("agent-index", "failed", "no candidate ranked for governance review")

    top_agent = ranked[0][0].agent_id
    if top_agent != "governance-branch-review":
        return CheckResult(
            "agent-index",
            "failed",
            f"expected governance-branch-review first, got {top_agent}",
        )

    return CheckResult(
        "agent-index",
        "passed",
        f"{top_agent} ranks first from {index_path.name}",
    )


def check_root_docs(repo_root: Path) -> CheckResult:
    """Verify agent-facing root docs exist and are non-empty."""
    missing = [doc for doc in REQUIRED_DOCS if not (repo_root / doc).exists()]
    empty = [
        doc
        for doc in REQUIRED_DOCS
        if (repo_root / doc).exists() and not (repo_root / doc).read_text(encoding="utf-8").strip()
    ]
    problems = [f"missing: {', '.join(missing)}"] if missing else []
    if empty:
        problems.append(f"empty: {', '.join(empty)}")
    if problems:
        return CheckResult("root-docs", "failed", "; ".join(problems))
    return CheckResult("root-docs", "passed", f"{len(REQUIRED_DOCS)} root docs present")


def check_agent_contract(repo_root: Path) -> CheckResult:
    """Verify repo-owned agents include executable contract metadata."""
    script_path = repo_root / "scripts" / "sync_agents.py"
    if not script_path.exists():
        return CheckResult("agent-contract", "skipped", "scripts/sync_agents.py not present")

    try:
        sync_agents = _load_source_module("_agent_ready_sync_agents_contract", script_path)
        problems = sync_agents.validate_agent_index(repo_root / "agent-index.json")
    except Exception as exc:  # pragma: no cover - surfaced in CLI output.
        return CheckResult("agent-contract", "failed", f"{type(exc).__name__}: {exc}")

    if problems:
        return CheckResult("agent-contract", "failed", "; ".join(problems))
    count = len(sync_agents.expected_manifests(repo_root / "agent-index.json"))
    return CheckResult("agent-contract", "passed", f"{count} agents declare executable metadata")


def check_agent_manifests(repo_root: Path) -> CheckResult:
    """Verify generated agents/*.agent.yaml files match agent-index.json."""
    script_path = repo_root / "scripts" / "sync_agents.py"
    if not script_path.exists():
        return CheckResult("agent-manifests", "skipped", "scripts/sync_agents.py not present")

    try:
        sync_agents = _load_source_module("_agent_ready_sync_agents", script_path)
        problems = sync_agents.check(repo_root / "agent-index.json", repo_root / "agents")
    except RuntimeError as exc:
        if "PyYAML" in str(exc):
            return CheckResult("agent-manifests", "skipped", str(exc))
        return CheckResult("agent-manifests", "failed", f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # pragma: no cover - surfaced in CLI output.
        return CheckResult("agent-manifests", "failed", f"{type(exc).__name__}: {exc}")

    if problems:
        return CheckResult("agent-manifests", "failed", "; ".join(problems))
    count = len(sync_agents.expected_manifests(repo_root / "agent-index.json"))
    return CheckResult("agent-manifests", "passed", f"agents/ in sync ({count} manifests)")


def check_tool_registry(repo_root: Path) -> CheckResult:
    """Verify tools/registry.yaml references live Makefile targets and scripts."""
    script_path = repo_root / "scripts" / "validate_tools.py"
    if not script_path.exists():
        return CheckResult("tool-registry", "skipped", "scripts/validate_tools.py not present")

    try:
        validate_tools = _load_source_module("_agent_ready_validate_tools", script_path)
        problems = validate_tools.validate(repo_root)
    except Exception as exc:  # pragma: no cover - surfaced in CLI output.
        return CheckResult("tool-registry", "failed", f"{type(exc).__name__}: {exc}")

    if problems:
        if len(problems) == 1 and "PyYAML unavailable" in problems[0]:
            return CheckResult("tool-registry", "skipped", problems[0])
        return CheckResult("tool-registry", "failed", "; ".join(problems))
    return CheckResult("tool-registry", "passed", "tools/registry.yaml references live tools")


def check_tool_availability() -> CheckResult:
    """Report command availability without failing the readiness summary."""
    tools = ("python3", "make", "ruff", "mypy")
    found = [tool for tool in tools if shutil.which(tool)]
    missing = [tool for tool in tools if tool not in found]
    detail = f"found: {', '.join(found) or 'none'}; missing: {', '.join(missing) or 'none'}"
    return CheckResult("tool-availability", "passed", detail)


def run_targeted_tests(repo_root: Path, python: str) -> CheckResult:
    """Run the focused agent-discovery test gate."""
    command = [
        python,
        "-m",
        "pytest",
        *AGENT_TESTS,
        "-q",
        "--import-mode=importlib",
    ]
    env = os.environ.copy()
    env.update(TEST_ENV)
    env = _with_source_pythonpath(repo_root, env)
    completed = subprocess.run(
        command,
        check=False,
        cwd=repo_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output = completed.stdout.strip().splitlines()
    detail = output[-1] if output else "no pytest output"
    status = "passed" if completed.returncode == 0 else "failed"
    return CheckResult("targeted-tests", status, detail, " ".join(command))


def collect_checks(
    repo_root: Path | None = None,
    *,
    python: str = "python3",
    run_tests: bool = False,
) -> list[CheckResult]:
    """Collect readiness checks, optionally running the focused test gate."""
    root = repo_root_from(repo_root)
    results = [
        check_agent_index(root),
        check_root_docs(root),
        check_agent_contract(root),
        check_agent_manifests(root),
        check_tool_registry(root),
        check_tool_availability(),
        CheckResult(
            "recommended-commands",
            "passed",
            " | ".join(build_recommended_commands(python)),
        ),
    ]
    if run_tests:
        results.append(run_targeted_tests(root, python))
    else:
        results.append(
            CheckResult(
                "targeted-tests",
                "skipped",
                "pass --run-tests to execute the focused agent registry gate",
            )
        )
    return results


def _overall_status(results: Sequence[CheckResult]) -> str:
    return "failed" if any(result.status == "failed" for result in results) else "passed"


def _required_skips(results: Sequence[CheckResult]) -> list[CheckResult]:
    return [
        result
        for result in results
        if result.status == "skipped" and result.name != "targeted-tests"
    ]


def _to_payload(results: Sequence[CheckResult]) -> dict[str, object]:
    return {
        "status": _overall_status(results),
        "checks": [result._asdict() for result in results],
    }


def _print_human(results: Sequence[CheckResult]) -> None:
    print(f"ACGS-Lite agent readiness: {_overall_status(results)}")
    for result in results:
        suffix = f" ({result.command})" if result.command else ""
        print(f"- {result.name}: {result.status} — {result.detail}{suffix}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--run-tests", action="store_true", help="run focused agent tests")
    parser.add_argument(
        "--no-run-tests",
        action="store_false",
        dest="run_tests",
        help="skip focused agent tests (default)",
    )
    parser.add_argument(
        "--allow-skips",
        action="store_true",
        help="allow skipped integrity checks to keep a passed exit status",
    )
    parser.add_argument("--python", default=sys.executable or "python3", help="Python command")
    args = parser.parse_args(argv)

    results = collect_checks(python=args.python, run_tests=args.run_tests)
    required_skips = _required_skips(results)
    if required_skips and not args.allow_skips:
        results.append(
            CheckResult(
                "required-checks",
                "failed",
                "required integrity checks skipped: "
                + ", ".join(result.name for result in required_skips),
            )
        )
    if args.json:
        print(json.dumps(_to_payload(results), indent=2, sort_keys=True))
    else:
        _print_human(results)
    return 0 if _overall_status(results) == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
