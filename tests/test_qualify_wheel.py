from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "qualify_wheel.py"
SPEC = importlib.util.spec_from_file_location("qualify_wheel", SCRIPT)
assert SPEC and SPEC.loader
qualify_wheel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualify_wheel)


def test_junit_testsuites_counts_all_tests(tmp_path: Path) -> None:
    junit = tmp_path / "tests.xml"
    junit.write_text(
        '<testsuites><testsuite tests="3" failures="0" errors="0" skipped="0" />'
        '<testsuite tests="2" failures="0" errors="0" skipped="0" /></testsuites>',
        encoding="utf-8",
    )
    assert qualify_wheel._junit_counts(junit) == {
        "collected": 5,
        "executed": 5,
        "passed": 5,
        "failed": 0,
        "skipped": 0,
    }
    assert qualify_wheel._group_passed({"exit_code": 0, **qualify_wheel._junit_counts(junit)})


def test_multi_test_group_passes_and_skipped_group_fails() -> None:
    assert qualify_wheel._group_passed(
        {
            "exit_code": 0,
            "collected": 213,
            "executed": 213,
            "passed": 213,
            "failed": 0,
            "skipped": 0,
        }
    )
    assert not qualify_wheel._group_passed(
        {
            "exit_code": 0,
            "collected": 213,
            "executed": 212,
            "passed": 212,
            "failed": 0,
            "skipped": 1,
        }
    )


def test_extracts_actual_quickstart_and_membrane_blocks() -> None:
    root = Path(__file__).parents[1]
    quickstart = (root / "docs" / "quickstart.md").read_text(encoding="utf-8")
    membrane = (root / "docs" / "guides" / "five-minute-membrane.md").read_text(encoding="utf-8")
    assert "GovernedAgent(" in qualify_wheel._fenced_block_after_heading(
        quickstart, "## 3. Govern a Callable", "python"
    )
    assert "No legitimacy receipt" in membrane
    assert "def main()" in qualify_wheel._fenced_block_after_heading(
        membrane, "Save the script as `membrane_5min.py`.", "python"
    )


def test_passing_junit_cannot_override_failed_process(tmp_path: Path) -> None:
    (tmp_path / "test_pass.py").write_text("def test_pass(): assert True\n")
    (tmp_path / "conftest.py").write_text(
        "def pytest_sessionfinish(session, exitstatus): session.exitstatus = 1\n"
    )
    junit = tmp_path / "tests.xml"
    group = qualify_wheel._run_pytest(
        "failed-session",
        [sys.executable, "-I", "-m", "pytest", "-q", f"--junitxml={junit}"],
        tmp_path,
        junit,
    )
    assert group["exit_code"] == 1
    counts = qualify_wheel._junit_counts(junit)
    assert counts["passed"] == 1 and counts["failed"] == 0
    group.update(counts)
    assert not qualify_wheel._group_passed(group)


def test_missing_process_status_is_not_qualification() -> None:
    assert not qualify_wheel._group_passed(
        {"collected": 1, "executed": 1, "passed": 1, "failed": 0, "skipped": 0}
    )


@pytest.mark.parametrize(
    "xml", [None, "invalid", '<testsuites><testsuite tests="0" /></testsuites>']
)
def test_pytest_requires_nonempty_junit(tmp_path: Path, xml: str | None) -> None:
    junit = tmp_path / "tests.xml"
    if xml is not None:
        junit.write_text(xml)
    group = qualify_wheel._run_pytest(
        "no-tests", [sys.executable, "-I", "-c", "pass"], tmp_path, junit
    )
    assert not qualify_wheel._group_passed(group)


def test_pytest_real_collection_is_accepted(tmp_path: Path) -> None:
    (tmp_path / "test_pass.py").write_text(
        "def test_one(): assert True\ndef test_two(): assert True\n"
    )
    junit = tmp_path / "tests.xml"
    group = qualify_wheel._run_pytest(
        "real-tests",
        [sys.executable, "-I", "-m", "pytest", "-q", f"--junitxml={junit}"],
        tmp_path,
        junit,
    )
    assert group["collected"] == 2
    assert qualify_wheel._group_passed(group)
