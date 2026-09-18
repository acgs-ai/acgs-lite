from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _marked_python_blocks(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(
        r"<!-- doc-test: ([a-z0-9-]+) -->\s*```python\n(.*?)\n```",
        re.DOTALL,
    )
    return {name: code for name, code in pattern.findall(text)}


def test_readme_marked_examples_execute_offline(tmp_path: Path) -> None:
    blocks = _marked_python_blocks(ROOT / "README.md")
    assert set(blocks) == {
        "governed-agent-wrapper",
        "local-production-profile",
        "published-engine-check",
        "z3-verifier",
    }
    for name, code in blocks.items():
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, f"{name}:\n{result.stdout}\n{result.stderr}"


def test_supervisor_z3_example_executes_offline(tmp_path: Path) -> None:
    blocks = _marked_python_blocks(ROOT / "docs" / "supervisor-models.md")
    assert set(blocks) == {"supervisor-z3"}
    result = subprocess.run(
        [sys.executable, "-c", blocks["supervisor-z3"]],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("path", "block"),
    [("README.md", "z3-verifier"), ("docs/supervisor-models.md", "supervisor-z3")],
)
def test_z3_examples_refuse_verification_without_solver(
    tmp_path: Path, path: str, block: str
) -> None:
    code = _marked_python_blocks(ROOT / path)[block]
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.modules['z3'] = None\n"
            + code
            + "\nassert result.status is VerificationStatus.UNAVAILABLE\n"
            + "assert result.verified is False\n",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "NOT VERIFIED" in result.stdout


def test_confirmed_readme_signature_errors_are_absent() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for invalid in (
        "GovernedCallable(engine=engine",
        "GovernedAgent.decorate",
        "GovernedOpenAI(OpenAI()",
        "GovernedAnthropic(anthropic.Anthropic()",
        "constraints=[",
        "certificate = await verifier.verify(",
    ):
        assert invalid not in text
