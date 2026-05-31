"""Claude Code hook coverage for the bundled governance route."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from acgs_lite import Constitution, Rule, Severity
from acgs_lite.engine import GovernanceEngine
from acgs_lite.server import create_governance_app

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK = REPO_ROOT / "integrations" / "claude_code" / "acgs-governance-preuse.sh"
CLAUDE_CODE_CHECK_ROUTE = "/integrations/claude-code/check"


def _write_curl_stub(
    tmp_path: Path, body: str = '{"compliant": true, "decision": "allow"}'
) -> Path:
    stub = tmp_path / "curl"
    stub.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                'printf "%s\\n" "$*" >> "${CURL_LOG}"',
                'for arg in "$@"; do',
                '  if [[ "$arg" == action@* ]]; then',
                '    printf "%s\\n" "${arg#action@}" >> "${CURL_LOG}"',
                '    cat "${arg#action@}" >> "${CURL_LOG}"',
                '    printf "\\n" >> "${CURL_LOG}"',
                "  fi",
                '  if [[ "$arg" == @* ]]; then',
                '    printf "%s\\n" "${arg#@}" >> "${CURL_LOG}"',
                '    cat "${arg#@}" >> "${CURL_LOG}"',
                '    printf "\\n" >> "${CURL_LOG}"',
                "  fi",
                "done",
                'if [[ "$*" == *"/health"* ]]; then',
                '  if [[ "${CURL_HEALTH_FAIL:-0}" == "1" ]]; then exit 7; fi',
                '  printf \'{"status":"healthy"}\'',
                "  exit 0",
                "fi",
                'if [[ "${CURL_CHECK_FAIL:-0}" == "1" ]]; then exit 22; fi',
                'printf "%s" "${CURL_CHECK_BODY}"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return stub


def _run_hook(
    payload: dict[str, object],
    tmp_path: Path,
    *,
    body: str = '{"compliant": true, "decision": "allow"}',
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    _write_curl_stub(tmp_path, body)
    curl_log = tmp_path / "curl.log"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "CURL_LOG": str(curl_log),
        "CURL_CHECK_BODY": body,
    }
    if extra_env:
        env.update(extra_env)

    return subprocess.run(
        ["bash", str(HOOK)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def test_hook_script_exists_and_is_executable() -> None:
    assert HOOK.exists()
    assert os.access(HOOK, os.X_OK)


def test_read_only_tools_skip_governance(tmp_path: Path) -> None:
    result = _run_hook({"tool_name": "Read", "tool_input": {"file_path": "README.md"}}, tmp_path)

    assert result.returncode == 0
    assert not (tmp_path / "curl.log").exists()


def test_unavailable_acgs_fails_closed_by_default(tmp_path: Path) -> None:
    result = _run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "echo hello"}},
        tmp_path,
        extra_env={"CURL_HEALTH_FAIL": "1"},
    )

    assert result.returncode == 2
    assert "ACGS governance engine required but unavailable" in result.stderr


def test_unavailable_acgs_fails_open_only_with_escape_hatch(tmp_path: Path) -> None:
    result = _run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "echo hello"}},
        tmp_path,
        extra_env={"ACGS_FAIL_OPEN": "1", "CURL_HEALTH_FAIL": "1"},
    )

    assert result.returncode == 0


def test_missing_side_effect_field_fails_closed_by_default(tmp_path: Path) -> None:
    result = _run_hook({"tool_name": "Bash", "tool_input": {}}, tmp_path)

    assert result.returncode == 2
    assert "invalid Claude Code hook payload" in result.stderr
    assert not (tmp_path / "curl.log").exists()


def test_constitutional_violation_blocks_tool_call(tmp_path: Path) -> None:
    body = json.dumps(
        {
            "compliant": False,
            "decision": "deny",
            "first_violation": {
                "rule_id": "SEC-001",
                "rule_text": "No hardcoded secrets",
            },
        }
    )
    result = _run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "export API_KEY=secret"}},
        tmp_path,
        body=body,
    )

    assert result.returncode == 2
    assert "SEC-001" in result.stderr
    assert "No hardcoded secrets" in result.stderr
    assert "Tool 'Bash' blocked" in result.stderr


@pytest.mark.parametrize(
    "decision",
    [
        "TRANSFORM_REQUIRED",
        "REPLAN_REQUIRED",
        "STRUCTURED_REVIEW_REQUIRED",
        "DENY_OPERATION_WITH_ALTERNATIVE",
        "DENY_GOAL",
        "HARD_DENY",
        "ALLOWED",
        "ALLOW_WITH_CONTROLS",
        "AUDIT_ONLY",
        "CONDITIONAL",
    ],
)
def test_canonical_non_executable_decisions_block_tool_call(tmp_path: Path, decision: str) -> None:
    body = json.dumps(
        {
            "compliant": True,
            "decision": decision,
            "rule_id": "LEGITIMACY-INVARIANT",
            "reason": "No valid constitutional authorization, no side effect.",
        }
    )
    result = _run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "touch /tmp/acgs-side-effect"}},
        tmp_path,
        body=body,
    )

    assert result.returncode == 2
    assert "LEGITIMACY-INVARIANT" in result.stderr
    assert "No valid constitutional authorization" in result.stderr


def test_multiedit_payload_is_sent_to_check_endpoint(tmp_path: Path) -> None:
    result = _run_hook(
        {
            "tool_name": "MultiEdit",
            "tool_input": {
                "edits": [
                    {"old_string": "a", "new_string": "first change"},
                    {"old_string": "b", "new_string": "second change"},
                ]
            },
        },
        tmp_path,
    )

    assert result.returncode == 0
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8")
    assert CLAUDE_CODE_CHECK_ROUTE in curl_log
    assert "first change" in curl_log
    assert "second change" in curl_log


def test_hook_forwards_api_key_to_check_endpoint(tmp_path: Path) -> None:
    result = _run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "echo hello"}},
        tmp_path,
        extra_env={"ACGS_API_KEY": "top-secret"},
    )

    assert result.returncode == 0
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8")
    assert "X-API-Key: top-secret" in curl_log


class TestBundledClaudeCodeRoute:
    def test_allow_valid_authorized_request(self) -> None:
        app = create_governance_app(api_key="top-secret")
        client = TestClient(app)

        response = client.post(
            CLAUDE_CODE_CHECK_ROUTE,
            headers={"X-API-Key": "top-secret"},
            json={"tool_name": "Bash", "tool_input": {"command": "echo hello"}},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "allow"
        assert body["status"] == "allowed"
        assert body["compliant"] is True
        assert body["first_violation"] is None
        assert body["tool_name"] == "Bash"
        assert body["action"] == "echo hello"

    def test_constitutional_denial_blocks_request(self) -> None:
        constitution = Constitution.from_rules(
            [
                Rule(
                    id="CC-001",
                    text="No self approval",
                    severity=Severity.HIGH,
                    keywords=["self-approve"],
                )
            ]
        )
        app = create_governance_app(constitution, api_key="top-secret")
        client = TestClient(app)

        response = client.post(
            CLAUDE_CODE_CHECK_ROUTE,
            headers={"X-API-Key": "top-secret"},
            json={"tool_name": "Bash", "tool_input": {"command": "self-approve merge"}},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "deny"
        assert body["status"] == "blocked"
        assert body["compliant"] is False
        assert body["first_violation"]["rule_id"] == "CC-001"

    def test_malformed_request_body_blocks_request(self) -> None:
        app = create_governance_app(api_key="top-secret")
        client = TestClient(app)

        response = client.post(
            CLAUDE_CODE_CHECK_ROUTE,
            headers={"X-API-Key": "top-secret", "Content-Type": "application/json"},
            content="{not-json",
        )

        assert response.status_code == 400
        body = response.json()
        assert body["decision"] == "deny"
        assert body["status"] == "blocked"
        assert body["compliant"] is False
        assert body["first_violation"]["rule_id"] == "CLAUDE_CODE_PAYLOAD"

    def test_auth_failure_blocks_request(self) -> None:
        app = create_governance_app(api_key="top-secret")
        client = TestClient(app)

        response = client.post(
            CLAUDE_CODE_CHECK_ROUTE,
            json={"tool_name": "Bash", "tool_input": {"command": "echo hello"}},
        )

        assert response.status_code == 401

    def test_engine_unavailable_blocks_request(self, monkeypatch: pytest.MonkeyPatch) -> None:
        app = create_governance_app(api_key="top-secret")
        client = TestClient(app)

        def unavailable(*args: object, **kwargs: object) -> object:
            raise RuntimeError("engine unavailable")

        monkeypatch.setattr(GovernanceEngine, "validate", unavailable)

        response = client.post(
            CLAUDE_CODE_CHECK_ROUTE,
            headers={"X-API-Key": "top-secret"},
            json={"tool_name": "Bash", "tool_input": {"command": "echo hello"}},
        )

        assert response.status_code == 503
        body = response.json()
        assert body["decision"] == "deny"
        assert body["status"] == "blocked"
        assert body["compliant"] is False
        assert body["first_violation"]["rule_id"] == "ENGINE_UNAVAILABLE"

    def test_deprecated_x402_alias_remains_local_compatibility_route(self) -> None:
        app = create_governance_app(api_key="top-secret")
        client = TestClient(app)

        response = client.get(
            "/x402/check",
            headers={"X-API-Key": "top-secret"},
            params={"action": "echo hello"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "allow"
        assert body["status"] == "allowed"
        assert body["deprecated"] is True
