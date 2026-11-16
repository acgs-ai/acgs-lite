"""Boundary inputs of the Lean verifier: every failure path blocks.

No Lean binary and no Mistral client is used. The only subprocess stub raises, and a
proof the kernel did not check is never accepted: ``proved`` is False and there is no
certificate.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from acgs_lite import lean_verify
from acgs_lite.lean_verify import LeanstralVerifier

pytestmark = pytest.mark.unit

_THEOREM = "theorem t : True := trivial"


@pytest.fixture
def _no_lean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACGS_LEAN_CMD", raising=False)
    monkeypatch.delenv("ACGS_LEAN_WORKDIR", raising=False)
    monkeypatch.setattr(lean_verify, "LEAN_AVAILABLE", False)
    monkeypatch.setattr(lean_verify.shutil, "which", lambda name: None)


def _forbid_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("subprocess.run must not be reached")

    monkeypatch.setattr(lean_verify.subprocess, "run", _fail)


# --------------------------------------------------------------------------- #
# ACGS_LEAN_CMD parsing
# --------------------------------------------------------------------------- #

_JSON_FORM = "JSON form must be a non-empty array of strings"


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        ("[lake", "Invalid ACGS_LEAN_CMD JSON array"),
        ("[]", _JSON_FORM),
        ('["lean", ""]', _JSON_FORM),
        ("[1]", _JSON_FORM),
        ('lean "unterminated', "No closing quotation"),
        ("   ", "ACGS_LEAN_CMD must not be empty"),
    ],
)
def test_malformed_lean_command_blocks_the_check(
    monkeypatch: pytest.MonkeyPatch, _no_lean: None, value: str, fragment: str
) -> None:
    monkeypatch.setenv("ACGS_LEAN_CMD", value)
    _forbid_subprocess(monkeypatch)

    command, error = lean_verify._resolve_lean_command_with_error()
    ok, errors = lean_verify._run_lean_check(_THEOREM, expected_theorem="t")

    assert command is None
    assert error is not None
    assert fragment in error
    assert ok is False
    assert len(errors) == 1
    assert fragment in errors[0]


def test_smoke_check_reports_bad_override_as_not_ok(
    monkeypatch: pytest.MonkeyPatch, _no_lean: None
) -> None:
    monkeypatch.setenv("ACGS_LEAN_CMD", "[lake")
    _forbid_subprocess(monkeypatch)

    result = lean_verify.run_lean_runtime_smoke_check()

    assert result["ok"] is False
    assert result["command"] == []
    assert result["errors"][0].startswith("Invalid ACGS_LEAN_CMD JSON array")


def test_command_resolution_from_path(monkeypatch: pytest.MonkeyPatch, _no_lean: None) -> None:
    assert lean_verify._resolve_lean_command() is None

    # Resolution only: no Lean is run.
    monkeypatch.setattr(lean_verify.shutil, "which", lambda name: "/opt/lean/bin/lean")

    assert lean_verify._resolve_lean_command_with_error() == (["/opt/lean/bin/lean"], None)
    assert lean_verify._resolve_lean_command() == ["/opt/lean/bin/lean"]


def test_kernel_available_follows_command_resolution(
    monkeypatch: pytest.MonkeyPatch, _no_lean: None
) -> None:
    assert LeanstralVerifier().kernel_available is False

    monkeypatch.setattr(lean_verify.shutil, "which", lambda name: "/opt/lean/bin/lean")

    assert LeanstralVerifier().kernel_available is True


# --------------------------------------------------------------------------- #
# Diagnostics and execution failure
# --------------------------------------------------------------------------- #


def test_extract_errors_falls_back_to_raw_output() -> None:
    completed = subprocess.CompletedProcess(
        args=["lean"], returncode=1, stdout="", stderr="  plain crash output  "
    )

    assert lean_verify._extract_lean_errors(completed, ["lean"]) == ["plain crash output"]


def test_extract_errors_names_exit_code_when_output_is_empty() -> None:
    completed = subprocess.CompletedProcess(args=["lake"], returncode=137, stdout="", stderr="")

    assert lean_verify._extract_lean_errors(completed, ["lake", "env", "lean"]) == [
        "Lean exited with code 137 using lake env lean"
    ]


def test_extract_errors_is_empty_on_success() -> None:
    completed = subprocess.CompletedProcess(args=["lean"], returncode=0, stdout="", stderr="")

    assert lean_verify._extract_lean_errors(completed, ["lean"]) == []


def test_exec_failure_fails_closed(monkeypatch: pytest.MonkeyPatch, _no_lean: None) -> None:
    monkeypatch.setenv("ACGS_LEAN_CMD", '["/nonexistent/acgs-lean"]')

    def _raise(*args: Any, **kwargs: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(lean_verify.subprocess, "run", _raise)

    assert lean_verify._run_lean_check(_THEOREM, expected_theorem="t") == (
        False,
        ["Lean execution error via /nonexistent/acgs-lean: exec format error"],
    )


# --------------------------------------------------------------------------- #
# Theorem construction
# --------------------------------------------------------------------------- #


def test_snake_to_camel_keeps_separator_only_names() -> None:
    assert lean_verify._snake_to_camel("___") == "___"


@pytest.mark.parametrize(
    ("value", "rendered"),
    [(True, "true"), (False, "false"), (42, "42"), (1.5, '"1.5"')],
)
def test_lean_literal_rendering(value: Any, rendered: str) -> None:
    assert lean_verify._lean_literal(value) == rendered


def test_theorem_statement_skips_duplicate_and_unmatched_context() -> None:
    prelude = "structure ActionCtx where\n  action : String\n  agentRole : String\n"

    statement = lean_verify._build_theorem_statement(
        "deploy",
        {},
        prelude,
        {"action": "x", "unknown_key": 1, "agent_role": "admin"},
    )

    assert statement == (
        'theorem action_compliant (ctx : ActionCtx) (h_action : ctx.action = "deploy") '
        '(h_agentRole : ctx.agentRole = "admin") : True'
    )


# --------------------------------------------------------------------------- #
# Verifier refusals
# --------------------------------------------------------------------------- #


def test_no_client_without_mistralai(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lean_verify, "MISTRAL_AVAILABLE", False)

    with pytest.raises(ImportError, match="mistralai package not installed"):
        LeanstralVerifier()._get_client()


class _Message:
    def __init__(self, content: str | None) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str | None) -> None:
        self.message = _Message(content)


class _Response:
    def __init__(self, content: str | None) -> None:
        self.choices = [_Choice(content)]


class _ScriptedClient:
    """Fake chat client returning scripted replies in order."""

    def __init__(self, script: list[str | None]) -> None:
        self._script = list(script)
        self.chat = self

    def complete(self, model: str, **kwargs: Any) -> _Response:
        return _Response(self._script.pop(0))


_FORMAL = json.dumps(
    {
        "prelude": "structure ActionCtx where\n  action : String",
        "predicates": {"R1": "def r1 (ctx : ActionCtx) : Prop := True"},
    }
)
_RULES = [{"id": "R1", "text": "always"}]


def _verifier(
    monkeypatch: pytest.MonkeyPatch, script: list[str | None], max_attempts: int = 2
) -> LeanstralVerifier:
    monkeypatch.setattr(lean_verify, "MISTRAL_AVAILABLE", True)
    verifier = LeanstralVerifier(max_attempts=max_attempts)
    verifier._client = _ScriptedClient(script)
    return verifier


def test_empty_model_replies_are_not_a_proof(
    monkeypatch: pytest.MonkeyPatch, _no_lean: None
) -> None:
    verifier = _verifier(monkeypatch, [_FORMAL, None, ""])

    result = verifier.verify("deploy", _RULES)

    assert result.proved is False
    assert result.certificate is None
    assert result.attempts == 2
    assert result.lean_errors == [
        "Attempt 1: empty response from model",
        "Attempt 2: empty response from model",
    ]
    assert result.counterexample == "Proof failed after 2 attempts"


def test_unverified_fenced_proof_is_cleaned_but_refused(
    monkeypatch: pytest.MonkeyPatch, _no_lean: None
) -> None:
    verifier = _verifier(monkeypatch, [_FORMAL, "```lean\nby trivial\n```"])

    result = verifier.verify("deploy", _RULES)

    assert result.proved is False
    assert result.certificate is None
    assert result.proposed_proof == "by trivial"
    assert result.lean_errors == [
        "lean not installed — proof generated but not kernel-verified, so it is not accepted"
    ]


def test_certificate_is_refused_when_proof_loop_claims_success_without_kernel(
    monkeypatch: pytest.MonkeyPatch, _no_lean: None
) -> None:
    """Pins the guard in ``verify`` that recomputes kernel verification.

    The source comment says a future change to the proof loop must not quietly
    produce a certificate for text no kernel read. The loop is replaced on the
    instance only; no Lean output is faked.
    """
    verifier = _verifier(monkeypatch, [_FORMAL])
    monkeypatch.setattr(
        verifier, "_generate_and_verify_proof", lambda *args: (True, "by trivial", [], 1)
    )

    result = verifier.verify("deploy", _RULES)

    assert result.proved is False
    assert result.verified is False
    assert result.certificate is None
    assert result.error == "lean kernel did not verify this proof"
    assert result.counterexample == "Proof was not kernel-verified; refusing to certify"
    assert result.proposed_proof == "by trivial"
