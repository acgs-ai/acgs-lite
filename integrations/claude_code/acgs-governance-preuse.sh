#!/usr/bin/env bash
# Claude Code PreToolUse governance hook for ACGS-Lite.
#
# Reads the Claude Code hook payload from stdin, extracts the text that would be
# executed or written, and asks the local ACGS x402 /check endpoint whether to
# allow it. Exit 2 blocks the tool call in Claude Code.

set -uo pipefail

ACGS_BASE_URL="${ACGS_BASE_URL:-http://localhost:8000}"
ACGS_CHECK_URL="${ACGS_CHECK_URL:-${ACGS_BASE_URL%/}/x402/check}"
ACGS_HEALTH_URL="${ACGS_HEALTH_URL:-${ACGS_BASE_URL%/}/health}"
ACGS_HEALTH_TIMEOUT_SECONDS="${ACGS_HEALTH_TIMEOUT_SECONDS:-1}"
ACGS_CHECK_TIMEOUT_SECONDS="${ACGS_CHECK_TIMEOUT_SECONDS:-3}"
ACGS_FAIL_OPEN="${ACGS_FAIL_OPEN:-0}"

fail_open_enabled() {
  case "${ACGS_FAIL_OPEN}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

allow_when_unavailable() {
  local reason="$1"
  if fail_open_enabled; then
    exit 0
  fi
  echo "ACGS governance engine required but unavailable: ${reason}" >&2
  exit 2
}

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    allow_when_unavailable "missing required command '${command_name}'"
  fi
}

require_command python3
require_command curl

payload_file="$(mktemp "${TMPDIR:-/tmp}/acgs-claude-payload.XXXXXX")"
extracted_file="$(mktemp "${TMPDIR:-/tmp}/acgs-claude-extracted.XXXXXX")"
action_file="$(mktemp "${TMPDIR:-/tmp}/acgs-claude-action.XXXXXX")"
response_file="$(mktemp "${TMPDIR:-/tmp}/acgs-claude-response.XXXXXX")"
decision_file="$(mktemp "${TMPDIR:-/tmp}/acgs-claude-decision.XXXXXX")"
trap 'rm -f "${payload_file}" "${extracted_file}" "${action_file}" "${response_file}" "${decision_file}"' EXIT

python3 -c 'import sys; from pathlib import Path; Path(sys.argv[1]).write_text(sys.stdin.read(), encoding="utf-8")' "${payload_file}"

python3 - "${payload_file}" >"${extracted_file}" <<'PY'
import json
import sys
from pathlib import Path

payload = Path(sys.argv[1]).read_text(encoding="utf-8")
try:
    data = json.loads(payload)
except json.JSONDecodeError:
    print("parse_error", file=sys.stderr)
    raise SystemExit(2)

tool_name = data.get("tool_name") or data.get("tool") or data.get("name") or ""
tool_input = data.get("tool_input") or data.get("input") or {}

read_only_tools = {"Read", "Glob", "Grep", "LS"}
if tool_name in read_only_tools:
    print(json.dumps({"tool_name": tool_name, "action": "", "skip": True}))
    raise SystemExit(0)

action = ""
if tool_name == "Bash":
    action = str(tool_input.get("command") or "")
elif tool_name == "Write":
    action = str(tool_input.get("content") or "")
elif tool_name == "Edit":
    action = str(tool_input.get("new_string") or "")
elif tool_name == "MultiEdit":
    edits = tool_input.get("edits") or []
    action = "\n".join(str(edit.get("new_string") or "") for edit in edits if isinstance(edit, dict))
else:
    action = str(
        tool_input.get("command")
        or tool_input.get("content")
        or tool_input.get("new_string")
        or ""
    )

print(json.dumps({"tool_name": tool_name, "action": action, "skip": not action}))
PY
extract_status=$?

if [[ ${extract_status} -ne 0 ]]; then
  allow_when_unavailable "invalid Claude Code hook payload"
fi

tool_name="$(
  python3 - "${extracted_file}" <<'PY'
import json
import sys
from pathlib import Path

print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("tool_name", ""))
PY
)"
python3 - "${extracted_file}" "${action_file}" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
Path(sys.argv[2]).write_text(data.get("action", ""), encoding="utf-8")
PY
skip_check="$(
  python3 - "${extracted_file}" <<'PY'
import json
import sys
from pathlib import Path

print("1" if json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("skip") else "0")
PY
)"

if [[ "${skip_check}" == "1" ]]; then
  exit 0
fi

if ! curl -fsS --max-time "${ACGS_HEALTH_TIMEOUT_SECONDS}" "${ACGS_HEALTH_URL}" >/dev/null; then
  allow_when_unavailable "${ACGS_HEALTH_URL} did not return healthy"
fi

check_response="$(
  curl -fsS \
    --max-time "${ACGS_CHECK_TIMEOUT_SECONDS}" \
    -G \
    --data-urlencode "action@${action_file}" \
    "${ACGS_CHECK_URL}"
)"
check_status=$?

if [[ ${check_status} -ne 0 ]]; then
  allow_when_unavailable "${ACGS_CHECK_URL} did not return a governance decision"
fi

printf "%s" "${check_response}" >"${response_file}"

python3 - "${response_file}" >"${decision_file}" <<'PY'
import json
import sys
from pathlib import Path

try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except json.JSONDecodeError:
    print(json.dumps({"status": "parse_error"}))
    raise SystemExit(0)

compliant = data.get("compliant")
decision = str(data.get("decision", "")).strip().lower()
executable_decisions = {
    "allow",
    "allowed",
    "allow_with_controls",
    "audit_only",
    "conditional",
}
non_executable_decisions = {
    "deny",
    "block",
    "blocked",
    "reject",
    "rejected",
    "require_review",
    "review",
    "escalate",
    "transform_required",
    "replan_required",
    "structured_review_required",
    "deny_operation_with_alternative",
    "deny_goal",
    "hard_deny",
}
if compliant is False or decision in non_executable_decisions:
    blocked = True
elif compliant is True and decision in executable_decisions:
    blocked = False
else:
    print(json.dumps({"status": "parse_error"}))
    raise SystemExit(0)

violation = data.get("first_violation")
if isinstance(violation, dict):
    rule_id = str(violation.get("rule_id") or violation.get("id") or "unknown-rule")
    detail = str(
        violation.get("message")
        or violation.get("rule_text")
        or violation.get("description")
        or "constitutional violation detected"
    )
elif violation:
    rule_id = "unknown-rule"
    detail = str(violation)
else:
    rule_id = str(data.get("rule_id") or "unknown-rule")
    detail = str(data.get("message") or data.get("reason") or "constitutional violation detected")

print(json.dumps({"status": "blocked" if blocked else "allowed", "rule_id": rule_id, "detail": detail}))
PY

decision_status="$(
  python3 - "${decision_file}" <<'PY'
import json
import sys
from pathlib import Path

print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("status", "parse_error"))
PY
)"

if [[ "${decision_status}" == "parse_error" ]]; then
  allow_when_unavailable "${ACGS_CHECK_URL} returned malformed JSON"
fi

if [[ "${decision_status}" == "blocked" ]]; then
  rule_id="$(
    python3 - "${decision_file}" <<'PY'
import json
import sys
from pathlib import Path

print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("rule_id", "unknown-rule"))
PY
  )"
  detail="$(
    python3 - "${decision_file}" <<'PY'
import json
import sys
from pathlib import Path

print(
    json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get(
        "detail", "constitutional violation detected"
    )
)
PY
  )"
  echo "ACGS constitutional violation: rule ${rule_id} - ${detail}" >&2
  echo "Tool '${tool_name:-unknown}' blocked. Run 'acgs-lite assess' for details." >&2
  exit 2
fi

exit 0
