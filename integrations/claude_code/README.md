# ACGS Governance Hook for Claude Code

This directory contains the Claude Code `PreToolUse` hook that can send tool-call
text to the bundled ACGS-Lite FastAPI governance route before Claude Code executes it.

## Overview

The hook intercepts `Bash`, `Write`, `Edit`, and `MultiEdit` tool calls, extracts
the action text, calls `ACGS_CHECK_URL`, and blocks the call (exit 2) if the
response denies the action. By default `ACGS_CHECK_URL` is
`${ACGS_BASE_URL}/integrations/claude-code/check`, a route bundled by
`acgs_lite.server.create_governance_app()`. A deprecated local compatibility
alias remains available at `GET /x402/check?action=...` for older callers.

> **Fail-closed default:** If ACGS is not running, returns malformed data, or the `/health` endpoint does not respond within 1 second, the hook exits 2 and blocks the tool call. Development-only fail-open behavior requires the explicit escape hatch `ACGS_FAIL_OPEN=1`.

## Installation

### 1. Point Claude Code at the canonical hook script

The canonical script lives in this directory:

```text
packages/acgs-lite/integrations/claude_code/acgs-governance-preuse.sh
```

Keep this as the source of truth. Do not add a second repository copy under
`.claude/hooks`; configure Claude Code to invoke this script by absolute path.
If you are governing a different checkout, copy or symlink the script into that
project intentionally and keep the copied version synchronized with this
directory.

### 2. Register the hook in `.claude/settings.json`

Add the following entry to the `hooks.PreToolUse` array. It must appear **before** any other PreToolUse matchers so governance runs first:

```json
{
  "matcher": "Bash|Write|Edit|MultiEdit",
  "hooks": [
    {
      "type": "command",
      "command": "bash /absolute/path/to/packages/acgs-lite/integrations/claude_code/acgs-governance-preuse.sh",
      "timeout": 5
    }
  ]
}
```

Use the absolute path to the script. The `timeout` of 5 seconds covers the 1 s health-check plus 3 s governance call with margin.

## What it validates

| Tool | Extracted text |
|------|---------------|
| `Bash` | `tool_input.command` |
| `Write` | `tool_input.content` |
| `Edit` | `tool_input.new_string` |
| `MultiEdit` | `tool_input.new_string` of each edit block |

Read-only tools (`Read`, `Glob`, `Grep`, `LS`) are skipped unconditionally.

## Configuration

| Environment variable | Default | Purpose |
|----------------------|---------|---------|
| `ACGS_BASE_URL` | `http://localhost:8000` | Base URL used to derive the health and check endpoints |
| `ACGS_HEALTH_URL` | `${ACGS_BASE_URL}/health` | Health endpoint checked before enforcement |
| `ACGS_CHECK_URL` | `${ACGS_BASE_URL}/integrations/claude-code/check` | Bundled Claude Code governance decision endpoint |
| `ACGS_CHECK_API_KEY` | `${ACGS_API_KEY}` when set | API key forwarded as `X-API-Key` to protected ACGS servers |
| `ACGS_HEALTH_TIMEOUT_SECONDS` | `1` | Health-check timeout |
| `ACGS_CHECK_TIMEOUT_SECONDS` | `3` | Governance-check timeout |
| `ACGS_FAIL_OPEN` | `0` | Set to `1`, `true`, `yes`, or `on` to allow when ACGS is unavailable |

## Availability behavior

When ACGS is not running (no process on port 8000, or `/health` returns non-200), the hook exits 2 immediately. This keeps governance mandatory by default.

To opt into fail-open behavior for local testing, set:

```bash
export ACGS_FAIL_OPEN=1
```

## Bundled governance route contract

The hook calls `POST ${ACGS_CHECK_URL}` after a successful health check and sends
the original Claude Code PreToolUse payload as JSON:

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "echo hello"
  }
}
```

Compatible decision response:

```json
{
  "compliant": true,
  "decision": "allow",
  "risk_level": "low",
  "first_violation": null
}
```

The hook exits 0 only when `compliant` is `true` and `decision` is exactly
`"allow"` after case normalization. Any other decision, malformed JSON, HTTP
error, auth failure, or unavailable server blocks the tool call unless
`ACGS_FAIL_OPEN=1` is explicitly set.

## Example output when a violation is caught

When Claude Code attempts a `Bash` call that violates a constitutional rule, the hook prints to stderr and the tool call is blocked:

```
ACGS constitutional violation: rule AC-4 — prohibited data exfiltration pattern detected
Tool 'Bash' blocked. Run 'acgs-lite assess' for details.
```

Claude Code surfaces the stderr output to the user and aborts the tool call.
Audit persistence is handled by the ACGS-Lite server behind `ACGS_CHECK_URL`;
the shell hook itself does not write an audit log.

## Local smoke checks

Verify the hook script and focused tests from the repository root:

```bash
bash -n integrations/claude_code/acgs-governance-preuse.sh
python -m pytest tests/test_claude_code_integration.py -q --import-mode=importlib
```

If the bundled ACGS-Lite server is running on the default base URL, verify its
public health endpoint and compatible decision endpoint:

```bash
curl http://localhost:8000/health
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"Bash","tool_input":{"command":"echo hello"}}' \
  http://localhost:8000/integrations/claude-code/check
```

For older local callers, `GET /x402/check?action=echo+hello` is available as a
deprecated compatibility alias. New integrations should use
`POST /integrations/claude-code/check`.
