from __future__ import annotations

import pytest

pytest.importorskip("gove_zone")

from gove_zone.decision import Decision
from gove_zone.tool import ToolCall

from acgs_lite.gove.policy import ConstitutionPolicy


class _Violation:
    def __init__(self, rule_id: str, rule_text: str) -> None:
        self.rule_id = rule_id
        self.rule_text = rule_text


class _Result:
    def __init__(self, valid: bool, violations=()) -> None:
        self.valid = valid
        self.violations = list(violations)


class _StubEngine:
    """Duck-typed stand-in for GovernanceEngine (same validate contract)."""

    def __init__(self, result=None, raises: Exception | None = None) -> None:
        self._result = result
        self._raises = raises
        self.seen_actions: list[str] = []
        self.seen_agent_ids: list[str] = []

    def validate(self, action: str, *, agent_id: str = "anonymous", **kwargs):
        self.seen_actions.append(action)
        self.seen_agent_ids.append(agent_id)
        if self._raises is not None:
            raise self._raises
        return self._result


CALL = ToolCall(name="send_email", args={"to": "a@b.c"}, goal="notify", actor="agent-7")


def test_valid_result_allows():
    policy = ConstitutionPolicy(_StubEngine(_Result(valid=True)), version="hash608")
    record = policy.evaluate(CALL)
    assert record.decision is Decision.ALLOW
    assert record.tool == "send_email"
    assert record.actor == "agent-7"
    assert record.policy_version == "acgs-lite-constitution/hash608"


def test_violations_deny_with_rule_ids():
    engine = _StubEngine(_Result(valid=False, violations=[_Violation("CK-001", "no exfil")]))
    record = ConstitutionPolicy(engine, version="hash608").evaluate(CALL)
    assert record.decision is Decision.DENY
    assert record.matched_rules == ("CK-001",)
    assert "no exfil" in record.reason


def test_engine_exception_fails_closed():
    engine = _StubEngine(raises=RuntimeError("constitution corrupted"))
    record = ConstitutionPolicy(engine, version="hash608").evaluate(CALL)
    assert record.decision is Decision.DENY
    assert "RuntimeError" in record.reason


def test_action_text_is_deterministic():
    engine = _StubEngine(_Result(valid=True))
    policy = ConstitutionPolicy(engine, version="hash608")
    policy.evaluate(CALL)
    policy.evaluate(CALL)
    assert engine.seen_actions[0] == engine.seen_actions[1]
    assert engine.seen_agent_ids == ["agent-7", "agent-7"]


def test_empty_version_rejected():
    with pytest.raises(ValueError):
        ConstitutionPolicy(_StubEngine(_Result(valid=True)), version="")
