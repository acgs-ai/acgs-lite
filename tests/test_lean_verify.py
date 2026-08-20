"""Tests for Leanstral formal verification module.

Tests the full pipeline: auto-formalization → proof generation → kernel verification.
All Mistral API calls are mocked. Lean kernel calls are mocked unless testing
kernel integration specifically.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from acgs_lite.lean_verify import (
    LeanstralVerifier,
    LeanVerifyResult,
    ProofCertificate,
    _build_formalization_prompt,
    _build_proof_prompt,
    _lean_escape,
    _lean_safe_name,
    _parse_json_response,
    _run_lean_check,
    run_lean_runtime_smoke_check,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_rules(n: int = 2) -> list[dict[str, str]]:
    """Create n governance rules for testing."""
    base = [
        {"id": "MACI-1", "text": "No agent may validate its own proposals"},
        {"id": "MACI-2", "text": "Role promotion requires judicial approval"},
        {"id": "MACI-3", "text": "All actions must be audited"},
        {"id": "MACI-4", "text": "Executive cannot act as validator"},
    ]
    return base[:n]


def _make_formalization_response() -> str:
    """Mock response from Leanstral's auto-formalization step."""
    return json.dumps(
        {
            "prelude": (
                "structure ActionCtx where\n"
                "  agentRole : String\n"
                "  targetRole : String\n"
                "  action : String"
            ),
            "predicates": {
                "MACI-1": (
                    "def maci_1_satisfied (ctx : ActionCtx) : Prop :=\n"
                    '  ctx.agentRole ≠ "validator" ∨ ctx.action ≠ "validate_own"'
                ),
                "MACI-2": (
                    "def maci_2_satisfied (ctx : ActionCtx) : Prop :=\n"
                    '  ctx.action ≠ "promote" ∨ ctx.agentRole = "judicial"'
                ),
            },
        }
    )


def _make_proof_response() -> str:
    """Mock response from Leanstral's proof generation step."""
    return "by\n  simp [maci_1_satisfied, maci_2_satisfied]\n  tauto"


LEAN_INTEGRATION_ENABLED = os.environ.get("LEAN_INTEGRATION") == "1"


def _mock_chat_responses(*responses: str) -> MagicMock:
    """Build a mock Mistral client that returns a sequence of responses."""
    client = MagicMock()
    side_effects = []
    for resp_text in responses:
        choice = MagicMock()
        choice.message.content = resp_text
        response = MagicMock()
        response.choices = [choice]
        response.model = "leanstral"
        side_effects.append(response)
    client.chat.complete.side_effect = side_effects
    return client


# ---------------------------------------------------------------------------
# ProofCertificate
# ---------------------------------------------------------------------------


class TestProofCertificate:
    def test_fields(self) -> None:
        cert = ProofCertificate(
            lean_statement="theorem t : True",
            lean_proof="by trivial",
            kernel_verified=True,
            rules_formalized={"R1": "def r1 : Prop := True"},
            proof_hash="abc123",
            model_used="leanstral",
            verification_time_ms=42.0,
        )
        assert cert.kernel_verified is True
        assert cert.proof_hash == "abc123"

    def test_to_audit_dict(self) -> None:
        cert = ProofCertificate(
            lean_statement="theorem t : True",
            lean_proof="by trivial",
            kernel_verified=False,
            rules_formalized={"R1": "def r1 : Prop := True"},
            proof_hash="abc123",
            model_used="leanstral",
            verification_time_ms=42.0,
        )
        d = cert.to_audit_dict()
        assert d["type"] == "lean4_proof_certificate"
        assert d["kernel_verified"] is False
        assert "lean_statement" in d
        assert "proof_hash" in d

    def test_immutable(self) -> None:
        cert = ProofCertificate(
            lean_statement="t",
            lean_proof="p",
            kernel_verified=True,
            rules_formalized={},
            proof_hash="h",
            model_used="m",
            verification_time_ms=0.0,
        )
        with pytest.raises(AttributeError):
            cert.kernel_verified = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# LeanVerifyResult
# ---------------------------------------------------------------------------


class TestLeanVerifyResult:
    def test_result_fields(self) -> None:
        result = LeanVerifyResult(
            proved=True,
            verified=True,
            certificate=None,
            counterexample=None,
            lean_errors=[],
            attempts=1,
            model_used="leanstral",
            verification_time_ms=42.0,
        )
        assert result.proved is True
        assert result.error is None

    def test_result_immutable(self) -> None:
        result = LeanVerifyResult(
            proved=False,
            verified=False,
            certificate=None,
            counterexample="MACI-1 violated",
            lean_errors=[],
            attempts=0,
            model_used="leanstral",
            verification_time_ms=0.0,
            error="test",
        )
        with pytest.raises(AttributeError):
            result.proved = True  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_lean_safe_name(self) -> None:
        assert _lean_safe_name("MACI-1") == "maci_1"
        assert _lean_safe_name("Rule With Spaces") == "rule_with_spaces"

    def test_lean_escape(self) -> None:
        assert _lean_escape('hello "world"') == 'hello \\"world\\"'
        assert _lean_escape("line\nbreak") == "line\\nbreak"
        assert _lean_escape("back\\slash") == "back\\\\slash"


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------


class TestBuildFormalizationPrompt:
    def test_includes_rules(self) -> None:
        prompt = _build_formalization_prompt(_make_rules(2))
        assert "MACI-1" in prompt
        assert "MACI-2" in prompt
        assert "No agent may validate" in prompt

    def test_includes_context(self) -> None:
        prompt = _build_formalization_prompt(_make_rules(1), context={"agent_role": "executive"})
        assert "agent_role" in prompt
        assert "executive" in prompt


class TestBuildProofPrompt:
    def test_includes_source_and_theorem(self) -> None:
        prompt = _build_proof_prompt("test action", "-- source", "theorem t : True")
        assert "-- source" in prompt
        assert "theorem t : True" in prompt

    def test_includes_previous_errors(self) -> None:
        prompt = _build_proof_prompt(
            "test",
            "-- src",
            "theorem t",
            previous_errors=["error: type mismatch"],
        )
        assert "type mismatch" in prompt
        assert "Fix the proof" in prompt

    def test_no_errors_on_first_attempt(self) -> None:
        prompt = _build_proof_prompt("test", "-- src", "theorem t")
        assert "Previous attempt" not in prompt


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


class TestParseJsonResponse:
    def test_valid_json(self) -> None:
        raw = json.dumps({"prelude": "test", "predicates": {"R1": "def r1"}})
        result = _parse_json_response(raw)
        assert result["prelude"] == "test"

    def test_json_in_code_fence(self) -> None:
        raw = '```json\n{"prelude": "test"}\n```'
        result = _parse_json_response(raw)
        assert result["prelude"] == "test"

    def test_empty(self) -> None:
        assert _parse_json_response(None) == {}
        assert _parse_json_response("") == {}

    def test_invalid_json(self) -> None:
        assert _parse_json_response("not json at all") == {}


# ---------------------------------------------------------------------------
# Lean kernel
# ---------------------------------------------------------------------------


class TestRunLeanCheck:
    @patch("acgs_lite.lean_verify.LEAN_AVAILABLE", False)
    def test_lean_not_installed(self) -> None:
        ok, errors = _run_lean_check("theorem t : True := by trivial")
        assert ok is False
        assert "not installed" in errors[0]

    @patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True)
    @patch("acgs_lite.lean_verify.subprocess.run")
    def test_lean_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        ok, errors = _run_lean_check("theorem t : True := by trivial")
        assert ok is True
        assert errors == []

    @patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True)
    @patch("acgs_lite.lean_verify.subprocess.run")
    def test_lean_failure(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="error: type mismatch\n  expected: Nat\n  got: String",
            stdout="",
        )
        ok, errors = _run_lean_check("bad source")
        assert ok is False
        assert any("type mismatch" in e for e in errors)

    @patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True)
    @patch("acgs_lite.lean_verify.subprocess.run")
    def test_lean_timeout(self, mock_run: MagicMock) -> None:
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("lean", 30)
        ok, errors = _run_lean_check("slow source", timeout_s=30)
        assert ok is False
        assert "timed out" in errors[0]

    @patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True)
    @patch("acgs_lite.lean_verify.subprocess.run")
    def test_run_lean_check_uses_command_override(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        with patch.dict("os.environ", {"ACGS_LEAN_CMD": "lake env lean"}, clear=False):
            ok, errors = _run_lean_check("theorem t : True := by trivial")

        assert ok is True
        assert errors == []
        assert mock_run.call_args.args[0][:3] == ["lake", "env", "lean"]

    @patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True)
    @patch("acgs_lite.lean_verify.subprocess.run")
    def test_run_lean_check_uses_json_command_override(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        with patch.dict(
            "os.environ",
            {"ACGS_LEAN_CMD": '["lake", "env", "lean"]'},
            clear=False,
        ):
            ok, errors = _run_lean_check("theorem t : True := by trivial")

        assert ok is True
        assert errors == []
        assert mock_run.call_args.args[0][:3] == ["lake", "env", "lean"]

    @patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True)
    @patch("acgs_lite.lean_verify.subprocess.run")
    def test_run_lean_check_uses_workdir_override(
        self,
        mock_run: MagicMock,
        tmp_path,
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        with patch.dict(
            "os.environ",
            {"ACGS_LEAN_CMD": "lean", "ACGS_LEAN_WORKDIR": str(tmp_path)},
            clear=False,
        ):
            ok, errors = _run_lean_check("theorem t : True := by trivial")

        assert ok is True
        assert errors == []
        assert mock_run.call_args.kwargs["cwd"] == tmp_path

    @patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True)
    @patch("acgs_lite.lean_verify.subprocess.run")
    def test_run_lean_check_reports_stdout_diagnostics(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="",
            stdout="error: unknown import\nwarning: fallback path used",
        )

        with patch.dict("os.environ", {"ACGS_LEAN_CMD": "lean"}, clear=False):
            ok, errors = _run_lean_check("bad source")

        assert ok is False
        assert any("unknown import" in error for error in errors)

    @patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True)
    def test_run_lean_check_rejects_invalid_workdir(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "ACGS_LEAN_CMD": "lean",
                "ACGS_LEAN_WORKDIR": "/definitely/not/a/real/lean/workdir",
            },
            clear=False,
        ):
            ok, errors = _run_lean_check("theorem t : True := by trivial")

        assert ok is False
        assert any("ACGS_LEAN_WORKDIR" in error for error in errors)

    @patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True)
    def test_run_lean_check_rejects_shell_syntax_override(self) -> None:
        with patch.dict(
            "os.environ",
            {"ACGS_LEAN_CMD": "lean | cat"},
            clear=False,
        ):
            ok, errors = _run_lean_check("theorem t : True := by trivial")

        assert ok is False
        assert any("wrapper script" in error.lower() for error in errors)

    def test_run_lean_runtime_smoke_check_fake_runtime(self, tmp_path) -> None:
        fake_lean = tmp_path / "fake-lean.py"
        fake_lean.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            "import sys\n"
            "proof_path = pathlib.Path(sys.argv[-1])\n"
            "content = proof_path.read_text()\n"
            "if 'theorem acgsLeanSmoke' not in content:\n"
            "    print('error: smoke theorem missing')\n"
            "    raise SystemExit(1)\n"
            "pathlib.Path('smoke_marker.txt').write_text(proof_path.name)\n"
            "print('lean smoke ok')\n"
        )
        fake_lean.chmod(0o755)

        with patch.dict(
            "os.environ",
            {
                "ACGS_LEAN_CMD": json.dumps([str(fake_lean)]),
                "ACGS_LEAN_WORKDIR": str(tmp_path),
            },
            clear=False,
        ):
            result = run_lean_runtime_smoke_check(timeout_s=5)

        assert result["ok"] is True
        assert result["command"] == [str(fake_lean)]
        assert result["workdir"] == str(tmp_path)
        assert (tmp_path / "smoke_marker.txt").read_text() == "Proof.lean"


# ---------------------------------------------------------------------------
# Verifier — unavailable
# ---------------------------------------------------------------------------


class TestLeanstralVerifierUnavailable:
    @patch("acgs_lite.lean_verify.MISTRAL_AVAILABLE", False)
    def test_not_installed(self) -> None:
        verifier = LeanstralVerifier()
        assert verifier.available is False
        result = verifier.verify("test", _make_rules(1))
        assert result.verified is False
        assert result.proved is False
        assert "not installed" in (result.error or "")

    @patch("acgs_lite.lean_verify.MISTRAL_AVAILABLE", True)
    def test_no_api_key(self) -> None:
        verifier = LeanstralVerifier(api_key=None)
        with patch.dict("os.environ", {}, clear=True):
            result = verifier.verify("test", _make_rules(1))
            assert result.verified is False
            assert "MISTRAL_API_KEY" in (result.error or "")


# ---------------------------------------------------------------------------
# Verifier — mocked pipeline (no Lean kernel)
# ---------------------------------------------------------------------------


@patch("acgs_lite.lean_verify.MISTRAL_AVAILABLE", True)
@patch("acgs_lite.lean_verify.LEAN_AVAILABLE", False)
class TestLeanstralVerifierMockedNoKernel:
    """Tests with Leanstral mocked and no Lean kernel."""

    def _make_verifier(self, mock_client: MagicMock) -> LeanstralVerifier:
        verifier = LeanstralVerifier(api_key="test-key")
        verifier._client = mock_client
        return verifier

    def test_full_pipeline_refuses_to_prove_without_a_kernel(self) -> None:
        """F5: a generated proof nobody checked must not be reported as proved."""
        client = _mock_chat_responses(
            _make_formalization_response(),
            _make_proof_response(),
        )
        verifier = self._make_verifier(client)

        result = verifier.verify(
            "read audit log",
            _make_rules(2),
            context={"agent_role": "judicial"},
        )

        assert result.proved is False, "unchecked proof reported as established"
        assert result.certificate is None, "certificate minted for an unverified proof"
        # The candidate is still returned, just not as an accepted proof.
        assert result.proposed_proof is not None
        assert result.proposed_theorem is not None
        assert "not kernel-verified" in " ".join(result.lean_errors)
        assert result.attempts == 1
        assert result.verification_time_ms > 0
        assert client.chat.complete.call_count == 2  # formalize + prove

    def test_no_certificate_reaches_the_audit_trail_without_a_kernel(self) -> None:
        """There must be nothing to serialize into an audit entry."""
        client = _mock_chat_responses(
            _make_formalization_response(),
            _make_proof_response(),
        )
        verifier = self._make_verifier(client)
        result = verifier.verify("test", _make_rules(2))

        assert result.certificate is None
        assert result.proved is False

    def test_formalization_failure(self) -> None:
        client = _mock_chat_responses(
            json.dumps({"prelude": "", "predicates": {}}),  # Empty predicates
        )
        verifier = self._make_verifier(client)
        result = verifier.verify("test", _make_rules(1))

        assert result.proved is False
        assert result.verified is True
        assert "Failed to formalize" in (result.counterexample or "")

    def test_api_error(self) -> None:
        client = MagicMock()
        client.chat.complete.side_effect = RuntimeError("API down")
        verifier = self._make_verifier(client)

        result = verifier.verify("test", _make_rules(1))
        assert result.proved is False
        assert result.verified is False
        assert "RuntimeError" in (result.error or "")

    def test_model_selection(self) -> None:
        client = _mock_chat_responses(
            _make_formalization_response(),
            _make_proof_response(),
        )
        verifier = LeanstralVerifier(api_key="test-key", model="codestral-latest")
        verifier._client = client

        verifier.verify("test", _make_rules(2))
        # Both calls should use the specified model
        for c in client.chat.complete.call_args_list:
            assert c.kwargs["model"] == "codestral-latest"

    def test_temperature_zero(self) -> None:
        client = _mock_chat_responses(
            _make_formalization_response(),
            _make_proof_response(),
        )
        verifier = self._make_verifier(client)
        verifier.verify("test", _make_rules(2))

        for c in client.chat.complete.call_args_list:
            assert c.kwargs["temperature"] == 0.0

    def test_multiple_rules_in_theorem(self) -> None:
        client = _mock_chat_responses(
            _make_formalization_response(),
            _make_proof_response(),
        )
        verifier = self._make_verifier(client)
        result = verifier.verify("test", _make_rules(2))

        assert result.proposed_theorem is not None
        # Theorem should conjoin both rules
        assert "maci_1_satisfied" in result.proposed_theorem
        assert "maci_2_satisfied" in result.proposed_theorem
        assert "∧" in result.proposed_theorem

    def test_theorem_uses_declared_predicate_names(self) -> None:
        client = _mock_chat_responses(
            json.dumps(
                {
                    "prelude": "structure ActionCtx where\n  action : String",
                    "predicates": {
                        "MACI-1": 'def validator_rule (ctx : ActionCtx) : Prop :=\n  ctx.action = "read"',
                        "MACI-2": 'abbrev judiciary_gate (ctx : ActionCtx) : Prop :=\n  ctx.action = "read"',
                    },
                }
            ),
            "by\n  simp [validator_rule, judiciary_gate]",
        )
        verifier = self._make_verifier(client)

        result = verifier.verify("read", _make_rules(2))

        assert result.proposed_theorem is not None
        assert "validator_rule ctx" in result.proposed_theorem
        assert "judiciary_gate ctx" in result.proposed_theorem
        assert "maci_1_satisfied" not in result.proposed_theorem

    def test_theorem_includes_context_assumptions(self) -> None:
        client = _mock_chat_responses(
            _make_formalization_response(),
            _make_proof_response(),
        )
        verifier = self._make_verifier(client)

        result = verifier.verify(
            "read audit log",
            _make_rules(2),
            context={"agent_role": "judicial", "target_role": "validator"},
        )

        assert result.proposed_theorem is not None
        assert 'h_agentRole : ctx.agentRole = "judicial"' in result.proposed_theorem
        assert 'h_targetRole : ctx.targetRole = "validator"' in result.proposed_theorem

    def test_theorem_includes_action_assumption(self) -> None:
        client = _mock_chat_responses(
            _make_formalization_response(),
            _make_proof_response(),
        )
        verifier = self._make_verifier(client)

        result = verifier.verify("read audit log", _make_rules(2))

        assert result.proposed_theorem is not None
        assert 'h_action : ctx.action = "read audit log"' in result.proposed_theorem

    def test_chat_falls_back_to_codestral_when_leanstral_unavailable(self) -> None:
        choice = MagicMock()
        choice.message.content = _make_formalization_response()
        response = MagicMock()
        response.choices = [choice]
        response.model = "codestral-latest"

        client = MagicMock()
        client.chat.complete.side_effect = [RuntimeError("model leanstral not found"), response]
        verifier = self._make_verifier(client)

        raw = verifier._chat(system="system", user="user")

        assert raw == _make_formalization_response()
        assert client.chat.complete.call_args_list[0].kwargs["model"] == "leanstral"
        assert client.chat.complete.call_args_list[1].kwargs["model"] == "codestral-latest"


# ---------------------------------------------------------------------------
# Verifier — mocked pipeline WITH Lean kernel
# ---------------------------------------------------------------------------


@patch("acgs_lite.lean_verify.MISTRAL_AVAILABLE", True)
@patch("acgs_lite.lean_verify.LEAN_AVAILABLE", True)
class TestLeanstralVerifierMockedWithKernel:
    """Tests with both Leanstral and Lean kernel mocked."""

    def _make_verifier(self, mock_client: MagicMock) -> LeanstralVerifier:
        verifier = LeanstralVerifier(api_key="test-key")
        verifier._client = mock_client
        return verifier

    @patch("acgs_lite.lean_verify.subprocess.run")
    def test_kernel_verified_proof(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        client = _mock_chat_responses(
            _make_formalization_response(),
            _make_proof_response(),
        )
        verifier = self._make_verifier(client)

        result = verifier.verify("test", _make_rules(2))

        assert result.proved is True
        assert result.certificate is not None
        assert result.proposed_theorem is not None
        assert result.certificate.kernel_verified is True
        assert result.attempts == 1

    @patch("acgs_lite.lean_verify.subprocess.run")
    def test_kernel_rejects_then_accepts(self, mock_run: MagicMock) -> None:
        """Feedback loop: first proof fails, second succeeds."""
        mock_run.side_effect = [
            # First attempt: kernel rejects
            MagicMock(returncode=1, stderr="error: type mismatch"),
            # Second attempt: kernel accepts
            MagicMock(returncode=0, stderr=""),
        ]
        client = _mock_chat_responses(
            _make_formalization_response(),
            "by simp  -- first attempt (will fail)",
            "by\n  constructor\n  · simp\n  · simp  -- fixed",
        )
        verifier = self._make_verifier(client)
        verifier._max_attempts = 3

        result = verifier.verify("test", _make_rules(2))

        assert result.proved is True
        assert result.attempts == 2
        assert result.certificate is not None
        assert result.proposed_theorem is not None
        assert result.certificate.kernel_verified is True
        assert len(result.lean_errors) > 0  # Has errors from first attempt

    @patch("acgs_lite.lean_verify.subprocess.run")
    def test_all_attempts_fail(self, mock_run: MagicMock) -> None:
        """All proof attempts rejected by kernel."""
        mock_run.return_value = MagicMock(returncode=1, stderr="error: unsolved goals")
        client = _mock_chat_responses(
            _make_formalization_response(),
            "by sorry  -- attempt 1",
            "by sorry  -- attempt 2",
            "by sorry  -- attempt 3",
        )
        verifier = self._make_verifier(client)
        verifier._max_attempts = 3

        result = verifier.verify("test", _make_rules(2))

        assert result.proved is False
        assert result.verified is True
        assert result.certificate is None
        assert result.attempts == 3
        assert "3 attempts" in (result.counterexample or "")


@pytest.mark.skipif(
    not LEAN_INTEGRATION_ENABLED,
    reason="set LEAN_INTEGRATION=1 to run real Lean toolchain smoke integration",
)
def test_run_lean_runtime_smoke_check_real_toolchain() -> None:
    result = run_lean_runtime_smoke_check(timeout_s=30)

    assert isinstance(result["command"], list)
    assert result["command"]
    assert isinstance(result["workdir"], str)
    assert result["timeout_s"] == 30
    assert result["ok"] is True, result["errors"]
    assert result["errors"] == []
