"""Real, controlled Lean inputs; no network/model calls and no sandbox claim."""

from __future__ import annotations

import hashlib
import os
import subprocess
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import pytest

from acgs_lite.lean_verify import LeanstralVerifier, _run_lean_check


@pytest.mark.parametrize(
    ("source", "accepted", "diagnostic", "exit_code"),
    [
        (
            "theorem action_compliant : True := by trivial",
            True,
            "'action_compliant' does not depend on any axioms",
            0,
        ),
        ("theorem action_compliant : False := by trivial", False, "error: invalid proof", 1),
        (
            "theorem action_compliant : False := by sorry",
            False,
            "'action_compliant' depends on axioms: [sorryAx]",
            0,
        ),
        (
            "axiom fabricated : False\ntheorem action_compliant : False := fabricated",
            False,
            "'action_compliant' depends on axioms: [fabricated]",
            0,
        ),
        (
            "theorem action_compliant (p : Prop) : p ∨ ¬p := Classical.em p",
            True,
            "'action_compliant' depends on axioms: [propext, Classical.choice, Quot.sound]",
            0,
        ),
        ("theorem other : True := by trivial", False, "error: unknown constant", 1),
    ],
)
def test_target_axiom_qualification(
    source: str, accepted: bool, diagnostic: str, exit_code: int
) -> None:
    # Unit mode tests parser contracts. The separate qualification lane sets
    # LEAN_INTEGRATION=1 and executes these same inputs with the real compiler.
    with ExitStack() as stack:
        if os.environ.get("LEAN_INTEGRATION") != "1":
            stack.enter_context(patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True))
            stack.enter_context(
                patch(
                    "acgs_lite.lean_verify.subprocess.run",
                    return_value=subprocess.CompletedProcess(["lean"], exit_code, diagnostic, ""),
                )
            )
        ok, errors = _run_lean_check(source, expected_theorem="action_compliant")
    assert ok is accepted, errors
    assert bool(errors) is not accepted


def test_certificate_hash_matches_exact_compiler_input() -> None:
    captured: list[bytes] = []

    def compiler(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append(Path(command[-1]).read_bytes())
        return subprocess.CompletedProcess(
            command, 0, "'action_compliant' does not depend on any axioms\n", ""
        )

    verifier = LeanstralVerifier(api_key="synthetic", max_attempts=1)
    with (
        patch("acgs_lite.lean_verify.MISTRAL_AVAILABLE", True),
        patch("acgs_lite.lean_verify._lean_runtime_available", return_value=True),
        patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True),
        patch("acgs_lite.lean_verify.subprocess.run", side_effect=compiler),
        patch.object(
            verifier,
            "_formalize_rules",
            return_value=("def acceptable (_ : String) : Prop := True\n", "", {"r": "acceptable"}),
        ),
        patch.object(verifier, "_chat", return_value="by trivial"),
    ):
        result = verifier.verify(action="test", rules=[{"id": "r", "text": "test"}])
    assert result.proved and result.certificate is not None
    assert result.certificate.proof_hash == hashlib.sha256(captured[-1]).hexdigest()


@pytest.mark.parametrize(
    "report",
    [
        "",
        "'other' does not depend on any axioms",
        "'action_compliant' unknown format",
        "'action_compliant' depends on axioms: []",
        "'action_compliant' does not depend on any axioms\n"
        "'action_compliant' does not depend on any axioms",
    ],
)
def test_missing_ambiguous_or_unknown_report_fails_closed(report: str) -> None:
    with (
        patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True),
        patch(
            "acgs_lite.lean_verify.subprocess.run",
            return_value=subprocess.CompletedProcess(["lean"], 0, report, ""),
        ),
    ):
        ok, errors = _run_lean_check(
            "theorem action_compliant : True := by trivial", expected_theorem="action_compliant"
        )
    assert not ok and errors


def test_invalid_target_is_rejected_before_compiler() -> None:
    with (
        patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True),
        patch("acgs_lite.lean_verify.subprocess.run") as compiler,
    ):
        ok, errors = _run_lean_check("", expected_theorem="x\n#eval 1")
    assert not ok and errors
    compiler.assert_not_called()


def test_allowed_report_cannot_override_compiler_failure() -> None:
    with (
        patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True),
        patch(
            "acgs_lite.lean_verify.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["lean"],
                1,
                "'action_compliant' does not depend on any axioms",
                "error: later failure",
            ),
        ),
    ):
        ok, errors = _run_lean_check("", expected_theorem="action_compliant")
    assert not ok and errors
