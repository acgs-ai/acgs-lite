#!/usr/bin/env python3
"""Run offline, source-free smoke groups against an installed wheel environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

MARKED_BLOCK = re.compile(
    r"<!-- doc-test: (?P<name>[a-z0-9-]+) -->\s*```python\n(?P<code>.*?)\n```",
    re.DOTALL,
)


def _fenced_block_after_heading(markdown: str, heading: str, language: str) -> str:
    start = markdown.index(heading)
    fence = markdown.index(f"```{language}\n", start) + len(language) + 4
    end = markdown.index("\n```", fence)
    return markdown[fence:end]


def _run(
    name: str, command: list[str], cwd: Path, *, env: dict[str, str] | None = None
) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, env=env)
    return {
        "name": name,
        "collected": 1,
        "executed": 1,
        "passed": int(completed.returncode == 0),
        "failed": int(completed.returncode != 0),
        "skipped": 0,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def _junit_counts(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    collected = sum(int(suite.attrib.get("tests", 0)) for suite in suites)
    failed = sum(
        int(suite.attrib.get("failures", 0)) + int(suite.attrib.get("errors", 0))
        for suite in suites
    )
    skipped = sum(int(suite.attrib.get("skipped", 0)) for suite in suites)
    return {
        "collected": collected,
        "executed": collected - skipped,
        "passed": collected - skipped - failed,
        "failed": failed,
        "skipped": skipped,
    }


def _run_pytest(
    name: str,
    command: list[str],
    cwd: Path,
    junit: Path,
    *,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    group = _run(name, command, cwd, env=env)
    # Command success alone cannot establish pytest collection or qualification.
    group.update(collected=0, executed=0, passed=0, failed=1, skipped=0)
    try:
        group.update(_junit_counts(junit))
        group["junit_xml"] = junit.read_text(encoding="utf-8")
    except (OSError, ET.ParseError, ValueError) as exc:
        group["stderr"] += f"\nInvalid or missing JUnit evidence: {exc}"
    return group


def _group_passed(group: dict[str, Any]) -> bool:
    return (
        group.get("exit_code") == 0
        and group.get("collected", 0) > 0
        and group.get("executed") == group.get("passed")
        and group.get("failed") == 0
        and group.get("skipped") == 0
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def qualify(
    python: Path, source_root: Path, wheel: Path, *, require_lean: bool = False
) -> dict[str, Any]:
    wheel_hash = _sha256(wheel)
    with tempfile.TemporaryDirectory(prefix="acgs-lite-wheel-qualification-") as raw:
        work = Path(raw)
        examples = work / "examples"
        examples.mkdir()
        for name in ("quickstart.py", "governed_execution_membrane.py", "release_proof.py"):
            shutil.copy2(source_root / "examples" / name, examples / name)
        shutil.copytree(
            source_root / "examples" / "agent_quickstart", examples / "agent_quickstart"
        )

        location_code = (
            "import pathlib,site,acgs_lite; p=pathlib.Path(acgs_lite.__file__).resolve(); "
            f"root=pathlib.Path({str(source_root.resolve())!r}); "
            "roots=[pathlib.Path(x).resolve() for x in site.getsitepackages()]; "
            "assert root not in p.parents and any(x in p.parents for x in roots), (p,root,roots); print(p)"
        )
        groups = [_run("installed-import-location", [str(python), "-I", "-c", location_code], work)]
        workflow_assets_code = (
            "from importlib.resources import files; "
            "root=files('acgs_lite.workflows'); "
            "expected={'action_validation.yaml','agent_onboarding.yaml','compliance_assessment.yaml'}; "
            "found={p.name for p in root.iterdir() if p.name.endswith('.yaml')}; "
            "assert found == expected, (found, expected); "
            "assert all((root/name).read_bytes() for name in expected)"
        )
        groups.append(
            _run(
                "installed-workflow-assets",
                [str(python), "-I", "-c", workflow_assets_code],
                work,
            )
        )
        for name in ("quickstart.py", "governed_execution_membrane.py", "release_proof.py"):
            groups.append(_run(f"example:{name}", [str(python), "-I", str(examples / name)], work))
        groups.append(
            _run(
                "example:agent-quickstart",
                [str(python), "-I", str(examples / "agent_quickstart" / "run.py")],
                work,
            )
        )
        readme = (source_root / "README.md").read_text(encoding="utf-8")
        blocks = list(MARKED_BLOCK.finditer(readme))
        if not blocks:
            groups.append(
                {
                    "name": "README-marked",
                    "collected": 0,
                    "executed": 0,
                    "passed": 0,
                    "failed": 1,
                    "skipped": 0,
                    "exit_code": 1,
                    "stderr": "no marked blocks",
                }
            )
        for match in blocks:
            script = work / f"readme-{match.group('name')}.py"
            script.write_text(match.group("code") + "\n", encoding="utf-8")
            groups.append(
                _run(f"README:{match.group('name')}", [str(python), "-I", str(script)], work)
            )
        quickstart = (source_root / "docs" / "quickstart.md").read_text(encoding="utf-8")
        constitution_yaml = _fenced_block_after_heading(
            quickstart, "## 2. Add a Constitution", "yaml"
        )
        (work / "constitution.yaml").write_text(constitution_yaml + "\n", encoding="utf-8")
        quickstart_code = "\n\n".join(
            (
                _fenced_block_after_heading(quickstart, "## 3. Govern a Callable", "python"),
                _fenced_block_after_heading(quickstart, "## 4. See Blocking Behavior", "python"),
            )
        )
        quickstart_script = work / "docs-quickstart.py"
        quickstart_script.write_text(quickstart_code + "\n", encoding="utf-8")
        groups.append(
            _run("docs:quickstart-sections-3-4", [str(python), "-I", str(quickstart_script)], work)
        )
        membrane = (source_root / "docs" / "guides" / "five-minute-membrane.md").read_text(
            encoding="utf-8"
        )
        membrane_script = work / "five-minute-membrane.py"
        membrane_script.write_text(
            _fenced_block_after_heading(
                membrane, "Save the script as `membrane_5min.py`.", "python"
            )
            + "\n",
            encoding="utf-8",
        )
        groups.append(
            _run("docs:five-minute-membrane", [str(python), "-I", str(membrane_script)], work)
        )
        supervisor = (source_root / "docs" / "supervisor-models.md").read_text(encoding="utf-8")
        supervisor_blocks = {
            match.group("name"): match.group("code") for match in MARKED_BLOCK.finditer(supervisor)
        }
        supervisor_script = work / "supervisor-z3.py"
        supervisor_script.write_text(supervisor_blocks["supervisor-z3"] + "\n", encoding="utf-8")
        groups.append(_run("docs:supervisor-z3", [str(python), "-I", str(supervisor_script)], work))
        contract_tests = work / "tests"
        contract_tests.mkdir()
        shutil.copytree(source_root / "tests" / "gove", contract_tests / "gove")
        for name in (
            "test_audit_hardening.py",
            "test_execution_hardening.py",
            "test_execution_grant_ledger.py",
            "test_invocation_binding.py",
            "test_z3_fail_closed.py",
            "test_z3_verify_coverage.py",
            "test_lean_verify.py",
            "test_lean_qualification.py",
            "test_legitimacy_contract.py",
        ):
            shutil.copy2(source_root / "tests" / name, contract_tests / name)
        junit = work / "wheel-contracts.xml"
        contract = _run_pytest(
            "wheel-contracts",
            [
                str(python),
                "-I",
                "-m",
                "pytest",
                str(contract_tests / "test_audit_hardening.py"),
                str(contract_tests / "test_execution_hardening.py"),
                str(contract_tests / "test_execution_grant_ledger.py"),
                str(contract_tests / "test_invocation_binding.py"),
                str(contract_tests / "test_legitimacy_contract.py"),
                f"{contract_tests / 'test_z3_fail_closed.py'}::TestVerifierErrorStatesBlock::test_solver_unknown_blocks",
                f"{contract_tests / 'test_z3_fail_closed.py'}::TestVerifierErrorStatesBlock::test_missing_solver_blocks",
                f"{contract_tests / 'test_z3_verify_coverage.py'}::TestVerifierZ3Unavailable",
                str(contract_tests / "test_lean_verify.py"),
                str(contract_tests / "test_lean_qualification.py"),
                "-k",
                "not test_run_lean_runtime_smoke_check_real_toolchain",
                "--import-mode=importlib",
                "--asyncio-mode=auto",
                "-q",
                f"--junitxml={junit}",
            ],
            work,
            junit,
        )
        groups.append(contract)
        if not _group_passed(contract):
            contract["passed"] = 0
            contract["failed"] = max(1, contract["failed"])
        gove_junit = work / "wheel-gove-contracts.xml"
        gove_contract = _run_pytest(
            "wheel-gove-contracts",
            [
                str(python),
                "-I",
                "-m",
                "pytest",
                str(contract_tests / "gove"),
                "--import-mode=importlib",
                "--asyncio-mode=auto",
                "-q",
                f"--junitxml={gove_junit}",
            ],
            work,
            gove_junit,
        )
        groups.append(gove_contract)
        if require_lean:
            lean_junit = work / "wheel-lean.xml"
            lean_contract = _run_pytest(
                "real-lean-controlled-source",
                [
                    str(python),
                    "-I",
                    "-m",
                    "pytest",
                    str(contract_tests / "test_lean_qualification.py"),
                    f"{contract_tests / 'test_lean_verify.py'}::test_run_lean_runtime_smoke_check_real_toolchain",
                    "--import-mode=importlib",
                    "-q",
                    f"--junitxml={lean_junit}",
                ],
                work,
                lean_junit,
                env=dict(os.environ, LEAN_INTEGRATION="1"),
            )
            groups.append(lean_contract)
        final_hash = _sha256(wheel)
        return {
            "schema": "acgs-lite-wheel-qualification-v1",
            "status": "PASS_WITHIN_STATED_SCOPE"
            if all(_group_passed(group) for group in groups)
            else "FAIL",
            "groups": groups,
            "wheel": {"name": wheel.name, "sha256_before": wheel_hash, "sha256_after": final_hash},
            "not_run": [] if require_lean else ["real Lean qualification not requested"],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-lean", action="store_true")
    args = parser.parse_args(argv)
    python = Path(os.path.abspath(args.python))
    report = qualify(
        python, args.source_root.resolve(), args.wheel.resolve(), require_lean=args.require_lean
    )
    if report["wheel"]["sha256_before"] != report["wheel"]["sha256_after"]:
        report["status"] = "FAIL"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "groups": len(report["groups"])}, sort_keys=True))
    return 0 if report["status"] == "PASS_WITHIN_STATED_SCOPE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
