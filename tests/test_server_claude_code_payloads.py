"""Claude Code hook payload validation and extraction through the real app."""

from __future__ import annotations

import types
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from acgs_lite import Constitution, Rule, Severity, ViolationAction  # noqa: E402
from acgs_lite.engine import GovernanceEngine  # noqa: E402
from acgs_lite.server import create_governance_app  # noqa: E402

ROUTE = "/integrations/claude-code/check"
KEY = "top-secret"
HDR = {"X-API-Key": KEY}
SIDE_EFFECT_MSG = "Claude Code hook payload did not contain side-effect text"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ACGS_API_KEY",
        "ACGS_EVENTS_ENABLED",
        "ACGS_LIFECYCLE_ENABLED",
        "ACGS_FEDERATION_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_governance_app(api_key=KEY))


def _assert_payload_denied(resp: Any, message: str) -> None:
    assert resp.status_code == 400
    body = resp.json()
    assert body["decision"] == "deny"
    assert body["status"] == "blocked"
    assert body["compliant"] is False
    assert body["reason"] == "malformed_payload"
    assert body["first_violation"]["rule_id"] == "CLAUDE_CODE_PAYLOAD"
    assert body["first_violation"]["rule_text"] == message


@pytest.mark.unit
@pytest.mark.parametrize(
    ("payload", "message"),
    [
        pytest.param(
            {"tool_input": {"command": "ls"}},
            "'tool_name' must be a non-empty string",
            id="missing-tool-name",
        ),
        pytest.param(
            {"tool_name": "Bash", "tool_input": "ls"},
            "'tool_input' must be an object",
            id="tool-input-not-object",
        ),
        pytest.param(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}, "agent_id": 123},
            "'agent_id' must be a string when provided",
            id="agent-id-not-string",
        ),
        pytest.param(
            {"tool_name": "Bash", "tool_input": {"command": 7}},
            "'tool_input.command' must be a string for Bash",
            id="bash-command-not-string",
        ),
        pytest.param(
            {"tool_name": "Write", "tool_input": {"content": 1}},
            "'tool_input.content' must be a string for Write",
            id="write-content-not-string",
        ),
        pytest.param(
            {"tool_name": "Edit", "tool_input": {"new_string": None}},
            "'tool_input.new_string' must be a string for Edit",
            id="edit-new-string-not-string",
        ),
        pytest.param(
            {"tool_name": "MultiEdit", "tool_input": {"edits": "x"}},
            "'tool_input.edits' must be a list for MultiEdit",
            id="multiedit-edits-not-list",
        ),
        pytest.param(
            {"tool_name": "MultiEdit", "tool_input": {"edits": ["x"]}},
            "'tool_input.edits' entries must be objects",
            id="multiedit-entry-not-object",
        ),
        pytest.param(
            {"tool_name": "MultiEdit", "tool_input": {"edits": [{"new_string": 3}]}},
            "'tool_input.edits[].new_string' must be a string",
            id="multiedit-new-string-not-string",
        ),
        pytest.param(
            {"tool_name": "NotebookEdit", "tool_input": {"cell": 1}},
            SIDE_EFFECT_MSG,
            id="generic-tool-no-text",
        ),
        pytest.param(
            {"tool_name": "Write", "tool_input": {"content": "   "}},
            SIDE_EFFECT_MSG,
            id="blank-write-content",
        ),
    ],
)
def test_malformed_payload_is_denied(
    client: TestClient, payload: dict[str, Any], message: str
) -> None:
    _assert_payload_denied(client.post(ROUTE, headers=HDR, json=payload), message)


@pytest.mark.unit
def test_non_object_json_payload_is_denied(client: TestClient) -> None:
    resp = client.post(ROUTE, headers=HDR, json=[1, 2])

    assert resp.status_code == 400
    body = resp.json()
    assert body["decision"] == "deny"
    assert body["compliant"] is False
    assert body["reason"] == "malformed_payload"
    assert body["first_violation"]["rule_id"] == "CLAUDE_CODE_PAYLOAD"
    assert body["first_violation"]["rule_text"] == "Claude Code hook payload must be a JSON object."


@pytest.mark.unit
@pytest.mark.parametrize(
    ("payload", "tool_name", "action"),
    [
        pytest.param(
            {"tool_name": "Write", "tool_input": {"content": "hello world"}},
            "Write",
            "hello world",
            id="write",
        ),
        pytest.param(
            {"tool_name": "Edit", "tool_input": {"old_string": "a", "new_string": "updated text"}},
            "Edit",
            "updated text",
            id="edit",
        ),
        pytest.param(
            {
                "tool_name": "MultiEdit",
                "tool_input": {"edits": [{"new_string": "first"}, {"new_string": "second"}]},
            },
            "MultiEdit",
            "first\nsecond",
            id="multiedit",
        ),
        pytest.param(
            {"tool_name": "NotebookEdit", "tool_input": {"command": 5, "content": "cell body"}},
            "NotebookEdit",
            "cell body",
            id="generic-skips-non-string",
        ),
        pytest.param(
            {"tool_name": "Bash", "input": {"command": "echo hi"}},
            "Bash",
            "echo hi",
            id="input-alias",
        ),
    ],
)
def test_action_extraction_allows_benign_content(
    client: TestClient, payload: dict[str, Any], tool_name: str, action: str
) -> None:
    resp = client.post(ROUTE, headers=HDR, json=payload)

    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["compliant"] is True
    assert body["first_violation"] is None
    assert body["tool_name"] == tool_name
    assert body["action"] == action


@pytest.mark.unit
def test_read_only_tool_skips_engine(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, ...]] = []
    original = GovernanceEngine.validate

    def spy(self: Any, *args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(GovernanceEngine, "validate", spy)

    resp = client.post(
        ROUTE,
        headers=HDR,
        json={
            "tool_name": "Read",
            "tool_input": {"file_path": "README.md"},
            "session_id": "sess-1",
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["reason"] == "read_only_tool"
    assert body["action"] == ""
    assert body["agent_id"] == "sess-1"
    assert body["first_violation"] is None
    assert calls == []


@pytest.mark.unit
def test_hook_event_name_is_passed_to_engine_context(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[Any] = []
    original = GovernanceEngine.validate

    def spy(self: Any, *args: Any, **kwargs: Any) -> Any:
        captured.append(kwargs.get("context"))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(GovernanceEngine, "validate", spy)
    client = TestClient(create_governance_app(api_key=KEY))

    resp = client.post(
        ROUTE,
        headers=HDR,
        json={
            "tool_name": "Bash",
            "tool_input": {"command": "echo hi"},
            "hook_event_name": "PreToolUse",
        },
    )

    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"
    assert captured == [
        {"integration": "claude-code", "tool_name": "Bash", "hook_event_name": "PreToolUse"}
    ]


@pytest.mark.unit
def test_halt_rule_violation_is_denied_through_real_engine() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="CC-HALT",
                text="Never detonate anything",
                severity=Severity.CRITICAL,
                keywords=["detonate"],
                workflow_action=ViolationAction.HALT,
            )
        ]
    )
    client = TestClient(create_governance_app(constitution, api_key=KEY))

    resp = client.post(
        ROUTE,
        headers=HDR,
        json={"tool_name": "Bash", "tool_input": {"command": "detonate the payload"}},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert body["compliant"] is False
    assert body["reason"] == "constitutional_denial"
    assert body["first_violation"]["rule_id"] == "CC-HALT"

    benign = client.post(
        ROUTE,
        headers=HDR,
        json={"tool_name": "Bash", "tool_input": {"command": "echo hi"}},
    )
    assert benign.status_code == 200
    assert benign.json()["decision"] == "allow"


@pytest.mark.unit
def test_invalid_result_without_violations_is_denied_as_uncertain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def inconclusive(*args: object, **kwargs: object) -> object:
        return types.SimpleNamespace(
            valid=False,
            violations=[],
            constitutional_hash="h",
            request_id="r",
            rules_checked=0,
            latency_ms=0.0,
        )

    monkeypatch.setattr(GovernanceEngine, "validate", inconclusive)
    client = TestClient(create_governance_app(api_key=KEY))

    resp = client.post(
        ROUTE,
        headers=HDR,
        json={"tool_name": "Bash", "tool_input": {"command": "echo hi"}},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert body["status"] == "blocked"
    assert body["compliant"] is False
    assert body["first_violation"]["rule_id"] == "UNCERTAIN_VALIDATION"
    assert body["first_violation"]["category"] == "uncertain"


@pytest.mark.unit
def test_deprecated_x402_route_denies_blank_action(client: TestClient) -> None:
    resp = client.get("/x402/check", headers=HDR, params={"action": "   "})

    assert resp.status_code == 400
    assert resp.headers["Deprecation"] == "true"
    body = resp.json()
    assert body["decision"] == "deny"
    assert body["first_violation"]["rule_id"] == "CLAUDE_CODE_PAYLOAD"
