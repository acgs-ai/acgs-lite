"""Claude Code hook coverage for the hackathon governance sidecar."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK = REPO_ROOT / "integrations" / "claude_code" / "acgs-governance-preuse.sh"


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
    assert "/x402/check" in curl_log
    assert "first change" in curl_log
    assert "second change" in curl_log
