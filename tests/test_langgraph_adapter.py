from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from acgs_lite import (
    Constitution,
    GovernanceEngine,
    PolicyDeniedError,
    Rule,
    Severity,
    ViolationAction,
)
from acgs_lite.adapters import ExecutionReceipt, ExecutionReceiptSink
from acgs_lite.adapters.langgraph import make_awrap_tool_call, make_wrap_tool_call


def _rule(
    rule_id: str,
    keywords: list[str],
    *,
    severity: Severity = Severity.HIGH,
    workflow_action: ViolationAction = ViolationAction.BLOCK,
) -> Rule:
    return Rule(
        id=rule_id,
        text=f"Rule {rule_id}",
        keywords=keywords,
        severity=severity,
        workflow_action=workflow_action,
    )


def _engine(rules: list[Rule], *, strict: bool = True) -> GovernanceEngine:
    return GovernanceEngine(Constitution.from_rules(rules), strict=strict)


@dataclass
class _Runtime:
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Request:
    tool_call: dict[str, Any]
    runtime: _Runtime
    tool: Any = None


class _MemorySink:
    def __init__(self) -> None:
        self.receipts: list[ExecutionReceipt] = []

    def write(self, receipt: ExecutionReceipt) -> None:
        self.receipts.append(receipt)


def test_wrap_tool_call_allows_and_emits_receipt() -> None:
    engine = _engine([], strict=False)
    sink: ExecutionReceiptSink = _MemorySink()
    request = _Request(
        tool_call={"id": "call-1", "name": "search", "args": {"query": "review policy docs"}},
        runtime=_Runtime({"configurable": {"thread_id": "thread-1", "agent_id": "agent-9"}}),
    )

    result = make_wrap_tool_call(engine, sink=sink)(request, lambda _: {"ok": True})

    assert result == {"ok": True}
    assert isinstance(sink, _MemorySink)
    assert len(sink.receipts) == 1
    assert sink.receipts[0].action_id == "call-1"
    assert sink.receipts[0].decision == "ALLOW"
    assert sink.receipts[0].policy_hash == engine.constitution.hash
    assert sink.receipts[0].metadata["execution_status"] == "success"


def test_wrap_tool_call_warns_but_executes_with_controls_receipt() -> None:
    engine = _engine(
        [
            _rule(
                "W1",
                ["plaintext"],
                severity=Severity.MEDIUM,
                workflow_action=ViolationAction.WARN,
            )
        ],
        strict=False,
    )
    sink: ExecutionReceiptSink = _MemorySink()
    request = _Request(
        tool_call={"id": "call-2", "name": "send", "args": {"payload": "send data in plaintext"}},
        runtime=_Runtime({"configurable": {"thread_id": "thread-2"}}),
    )

    result = make_wrap_tool_call(engine, sink=sink)(request, lambda _: {"ok": True})

    assert result == {"ok": True}
    assert isinstance(sink, _MemorySink)
    assert sink.receipts[0].decision == "ALLOW_WITH_CONTROLS"
    assert sink.receipts[0].metadata["action_taken"] == "warn"
    assert sink.receipts[0].metadata["rule_ids"] == ["W1"]


def test_wrap_tool_call_denies_with_tool_message_without_executing() -> None:
    engine = _engine(
        [_rule("B1", ["plaintext"], severity=Severity.HIGH, workflow_action=ViolationAction.BLOCK)],
        strict=False,
    )
    request = _Request(
        tool_call={"id": "call-3", "name": "send", "args": {"payload": "send data in plaintext"}},
        runtime=_Runtime({"configurable": {"thread_id": "thread-3"}}),
    )
    executed: list[Any] = []

    message = make_wrap_tool_call(engine)(request, lambda req: executed.append(req))

    assert executed == []
    assert message.tool_call_id == "call-3"
    assert message.status == "error"
    assert message.artifact["rule_id"] == "B1"


def test_wrap_tool_call_uses_generated_tool_call_id_when_missing() -> None:
    engine = _engine(
        [_rule("B1", ["plaintext"], severity=Severity.HIGH, workflow_action=ViolationAction.BLOCK)],
        strict=False,
    )
    request = _Request(
        tool_call={"name": "send", "args": {"payload": "send data in plaintext"}},
        runtime=_Runtime(),
    )

    message = make_wrap_tool_call(engine)(request, lambda _: None)

    assert message.tool_call_id
    assert message.status == "error"


def test_wrap_tool_call_halt_raises_policy_denied_even_when_fail_open_disabled() -> None:
    engine = _engine(
        [
            _rule(
                "H1",
                ["plaintext"],
                severity=Severity.CRITICAL,
                workflow_action=ViolationAction.HALT,
            )
        ],
        strict=False,
    )
    request = _Request(
        tool_call={"id": "call-4", "name": "send", "args": {"payload": "send data in plaintext"}},
        runtime=_Runtime(),
    )

    with pytest.raises(PolicyDeniedError) as exc_info:
        make_wrap_tool_call(engine, fail_closed=False)(request, lambda _: {"ok": True})

    assert exc_info.value.rule_id == "H1"
    assert exc_info.value.enforcement_action is ViolationAction.HALT


def test_wrap_tool_call_fail_open_executes_and_marks_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExplodingEngine:
        constitution = SimpleNamespace(hash="hash-1")

        def validate(self, action: str, **_: Any) -> Any:
            raise RuntimeError(f"boom:{action}")

    sink: ExecutionReceiptSink = _MemorySink()
    request = _Request(
        tool_call={"id": "call-5", "name": "deploy", "args": {"target": "staging"}},
        runtime=_Runtime(),
    )

    result = make_wrap_tool_call(ExplodingEngine(), sink=sink, fail_closed=False)(
        request,
        lambda _: {"ok": True},
    )

    assert result == {"ok": True}
    assert isinstance(sink, _MemorySink)
    assert sink.receipts[0].decision == "ALLOW_WITH_CONTROLS"
    assert sink.receipts[0].metadata["fail_open"] is True
    assert sink.receipts[0].metadata["validation_error"] == "RuntimeError"


def test_wrap_tool_call_fail_closed_raises_policy_denied() -> None:
    class ExplodingEngine:
        constitution = SimpleNamespace(hash="hash-2")

        def validate(self, action: str, **_: Any) -> Any:
            raise RuntimeError(f"boom:{action}")

    request = _Request(
        tool_call={"id": "call-6", "name": "deploy", "args": {"target": "prod"}},
        runtime=_Runtime(),
    )

    with pytest.raises(PolicyDeniedError) as exc_info:
        make_wrap_tool_call(ExplodingEngine(), fail_closed=True)(request, lambda _: {"ok": True})

    assert exc_info.value.policy_hash == "hash-2"
    assert exc_info.value.rule_id == "policy-engine"


@pytest.mark.asyncio
async def test_awrap_tool_call_supports_async_execution() -> None:
    engine = _engine([], strict=False)
    sink: ExecutionReceiptSink = _MemorySink()
    request = _Request(
        tool_call={"id": "call-7", "name": "search", "args": {"query": "review audit logs"}},
        runtime=_Runtime({"configurable": {"thread_id": "thread-7"}}),
    )

    async def _execute(_: Any) -> dict[str, bool]:
        return {"ok": True}

    result = await make_awrap_tool_call(engine, sink=sink)(request, _execute)

    assert result == {"ok": True}
    assert isinstance(sink, _MemorySink)
    assert sink.receipts[0].action_id == "call-7"
    assert sink.receipts[0].metadata["execution_status"] == "success"
