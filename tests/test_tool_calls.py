"""Tests for acgs_lite.tool_calls (real engine, no stubs).

Ported unchanged from the adapter packages' tests for their private
``_governance`` module, which this module replaces. Only the import differs.
"""

from __future__ import annotations

import functools
import itertools
import logging
import time
from typing import Any

import pytest

from acgs_lite import (
    Constitution,
    ConstitutionalViolationError,
    Rule,
    Severity,
    ValidationResult,
    ViolationAction,
)
from acgs_lite.engine.models import Violation
from acgs_lite.tool_calls import (
    MAX_ARGUMENT_DEPTH,
    GovernanceDecision,
    ToolCallGovernor,
    Verdict,
    format_tool_call,
)


def _constitution(*rules: Rule) -> Constitution:
    return Constitution.from_rules(list(rules), name="test")


BLOCK = Rule(
    id="T-BLOCK", text="no deletes", severity=Severity.CRITICAL, keywords=["delete everything"]
)
NOTIFY = Rule(
    id="T-NOTIFY",
    text="no exfil",
    severity=Severity.CRITICAL,
    keywords=["exfiltrate"],
    workflow_action=ViolationAction.BLOCK_AND_NOTIFY,
)
HALT = Rule(
    id="T-HALT",
    text="no drops",
    severity=Severity.CRITICAL,
    keywords=["drop table"],
    workflow_action=ViolationAction.HALT,
)
REVIEW = Rule(
    id="T-REVIEW",
    text="refunds need review",
    severity=Severity.HIGH,
    keywords=["refund"],
    workflow_action=ViolationAction.REQUIRE_HUMAN_REVIEW,
)
ESCALATE = Rule(
    id="T-ESCALATE",
    text="wires escalate",
    severity=Severity.HIGH,
    keywords=["wire transfer"],
    workflow_action=ViolationAction.ESCALATE,
)
WARN = Rule(
    id="T-WARN",
    text="csv export noted",
    severity=Severity.HIGH,
    keywords=["export csv"],
    workflow_action=ViolationAction.WARN,
)
MEDIUM = Rule(
    id="T-MEDIUM", text="newsletter noted", severity=Severity.MEDIUM, keywords=["newsletter"]
)

ALL_RULES = _constitution(BLOCK, NOTIFY, HALT, REVIEW, ESCALATE, WARN, MEDIUM)


class TestFormatToolCall:
    def test_renders_name_and_sorted_arguments(self) -> None:
        text = format_tool_call("search", {"query": "weather", "limit": 3})
        assert text == "tool: search\narguments:\nlimit: 3\nquery: weather"

    def test_collapses_whitespace_so_phrases_spanning_lines_match(self) -> None:
        text = format_tool_call("note", {"body": "please disable\n\tlogging"})
        assert "body: please disable logging" in text

    def test_flattens_nested_mappings_and_sequences(self) -> None:
        text = format_tool_call(
            "q", {"filters": [{"field": "a", "ops": ["eq", None, True, 1.5]}], "empty": [], "e": {}}
        )
        assert "filters[0].field: a" in text
        assert "filters[0].ops[0]: eq" in text
        assert "filters[0].ops[1]: null" in text
        assert "filters[0].ops[2]: true" in text
        assert "filters[0].ops[3]: 1.5" in text
        assert "empty: []" in text
        assert "e: {}" in text

    def test_normalizes_identifiers(self) -> None:
        text = format_tool_call(
            "skip_audit", {"apiKey": "x", "mode": "auto_approve", "to": "a@example.com"}
        )
        assert text.splitlines()[-1] == "normalized: skip audit | api key | auto approve"

    def test_no_normalized_line_when_nothing_to_normalize(self) -> None:
        assert "normalized" not in format_tool_call("search", {"query": "plain words"})

    def test_empty_and_non_mapping_arguments(self) -> None:
        assert format_tool_call("ping", {}) == "tool: ping\narguments:\n(none)"
        assert format_tool_call("echo", "raw   text") == "tool: echo\narguments:\ninput: raw text"

    def test_non_json_values_use_str(self) -> None:
        class Custom:
            def __str__(self) -> str:
                return "custom\nvalue"

        assert "obj: custom value" in format_tool_call("t", {"obj": Custom()})
        assert "data: b'abc'" in format_tool_call("t", {"data": b"abc"})

    def test_rejects_excessive_nesting(self) -> None:
        nested: dict[str, Any] = {}
        cursor = nested
        for _ in range(MAX_ARGUMENT_DEPTH + 1):
            cursor["k"] = {}
            cursor = cursor["k"]
        with pytest.raises(ValueError, match="nested deeper"):
            format_tool_call("t", nested)


class TestVerdictMapping:
    @pytest.fixture
    def governor(self) -> ToolCallGovernor:
        return ToolCallGovernor(ALL_RULES, agent_id="test")

    def test_allow_when_nothing_matches(self, governor: ToolCallGovernor) -> None:
        decision = governor.evaluate("search", {"query": "weather in Paris"})
        assert decision == GovernanceDecision(
            verdict=Verdict.ALLOW, tool_name="search", reason="No blocking ACGS rule matched."
        )

    @pytest.mark.parametrize(
        ("text", "rule_id"), [("export csv", "T-WARN"), ("newsletter", "T-MEDIUM")]
    )
    def test_warn_rules_allow_and_are_reported(
        self, governor: ToolCallGovernor, text: str, rule_id: str
    ) -> None:
        decision = governor.evaluate("t", {"a": text})
        assert decision.verdict is Verdict.ALLOW
        assert decision.warning_rule_ids == (rule_id,)

    @pytest.mark.parametrize(
        ("text", "rule_id"), [("delete everything", "T-BLOCK"), ("exfiltrate", "T-NOTIFY")]
    )
    def test_block_actions_deny(self, governor: ToolCallGovernor, text: str, rule_id: str) -> None:
        decision = governor.evaluate("t", {"a": text})
        assert decision.verdict is Verdict.DENY
        assert decision.rule_ids == (rule_id,)
        assert rule_id in decision.reason
        assert text not in decision.reason  # argument values are never echoed back

    def test_halt_denies(self, governor: ToolCallGovernor) -> None:
        decision = governor.evaluate("sql", {"statement": "drop table users"})
        assert decision.verdict is Verdict.DENY
        assert decision.rule_ids == ("T-HALT",)
        assert decision.error is None

    @pytest.mark.parametrize(
        ("text", "rule_id"), [("refund order 7", "T-REVIEW"), ("wire transfer", "T-ESCALATE")]
    )
    def test_review_actions_review(
        self, governor: ToolCallGovernor, text: str, rule_id: str
    ) -> None:
        decision = governor.evaluate("t", {"a": text})
        assert decision.verdict is Verdict.REVIEW
        assert decision.rule_ids == (rule_id,)

    def test_block_is_never_downgraded_to_review(self, governor: ToolCallGovernor) -> None:
        # acgs-lite reports action_taken=REQUIRE_HUMAN_REVIEW here because review outranks block in its
        # priority order. The adapter must still deny, otherwise a reviewer could approve a blocked call.
        decision = governor.evaluate("t", {"a": "refund and delete everything"})
        assert decision.verdict is Verdict.DENY
        assert set(decision.rule_ids) == {"T-REVIEW", "T-BLOCK"}

    def test_mixed_match_names_only_blocking_rules_under_blocked_by(
        self, governor: ToolCallGovernor
    ) -> None:
        # Regression (0.1.0): the review rule was listed under "Blocked by" next to the blocking rule.
        decision = governor.evaluate("t", {"a": "refund and delete everything"})
        assert decision.reason == (
            "Blocked by ACGS rule T-BLOCK (no deletes). "
            "Review rules that also matched: ACGS rule T-REVIEW (refunds need review)."
        )

    def test_mixed_match_with_several_rules_of_each_kind(self, governor: ToolCallGovernor) -> None:
        decision = governor.evaluate(
            "t", {"a": "wire transfer refund, exfiltrate, then delete everything"}
        )
        assert decision.verdict is Verdict.DENY
        blocked, _, review = decision.reason.partition(" Review rules that also matched: ")
        assert blocked.startswith("Blocked by ")
        assert "T-BLOCK" in blocked
        assert "T-NOTIFY" in blocked
        assert "T-REVIEW" not in blocked
        assert "T-ESCALATE" not in blocked
        assert "T-REVIEW" in review
        assert "T-ESCALATE" in review
        assert "T-BLOCK" not in review
        assert "T-NOTIFY" not in review
        assert set(decision.rule_ids) == {"T-BLOCK", "T-NOTIFY", "T-REVIEW", "T-ESCALATE"}

    def test_block_only_reason_has_no_review_section(self, governor: ToolCallGovernor) -> None:
        decision = governor.evaluate("t", {"a": "delete everything"})
        assert decision.reason == "Blocked by ACGS rule T-BLOCK (no deletes)."

    def test_review_only_reason(self, governor: ToolCallGovernor) -> None:
        decision = governor.evaluate("t", {"a": "refund order 7"})
        assert (
            decision.reason == "Human review required by ACGS rule T-REVIEW (refunds need review)."
        )

    def test_default_constitution_is_used_when_none_given(self) -> None:
        governor = ToolCallGovernor(agent_id="x")
        assert governor.constitution.hash == Constitution.default().hash


class TestFailClosed:
    def test_formatter_exception_denies(self, caplog: pytest.LogCaptureFixture) -> None:
        def broken(tool_name: str, arguments: Any) -> str:
            msg = "boom"
            raise RuntimeError(msg)

        governor = ToolCallGovernor(ALL_RULES, agent_id="t", tool_call_formatter=broken)
        with caplog.at_level(logging.WARNING):
            decision = governor.evaluate("search", {"q": "fine"})
        assert decision.verdict is Verdict.DENY
        assert decision.error == "RuntimeError: boom"
        assert "fail-closed" in caplog.text

    @pytest.mark.parametrize("bad", ["", "   ", None, 42])
    def test_formatter_must_return_non_empty_string(self, bad: Any) -> None:
        governor = ToolCallGovernor(ALL_RULES, agent_id="t", tool_call_formatter=lambda _n, _a: bad)
        decision = governor.evaluate("search", {})
        assert decision.verdict is Verdict.DENY
        assert decision.error is not None
        assert decision.error.startswith("TypeError")

    def test_deeply_nested_arguments_deny(self) -> None:
        nested: dict[str, Any] = {}
        cursor = nested
        for _ in range(MAX_ARGUMENT_DEPTH + 5):
            cursor["k"] = {}
            cursor = cursor["k"]
        decision = ToolCallGovernor(ALL_RULES, agent_id="t").evaluate("t", nested)
        assert decision.verdict is Verdict.DENY
        assert decision.error is not None

    def test_engine_exception_denies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        governor = ToolCallGovernor(ALL_RULES, agent_id="t")

        def explode(*_args: Any, **_kwargs: Any) -> ValidationResult:
            msg = "engine unavailable"
            raise OSError(msg)

        monkeypatch.setattr(governor._engine, "validate", explode)
        decision = governor.evaluate("search", {"q": "fine"})
        assert decision.verdict is Verdict.DENY
        assert decision.error == "OSError: engine unavailable"

    def test_unknown_rule_id_denies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        governor = ToolCallGovernor(ALL_RULES, agent_id="t")
        violation = Violation("NOT-IN-CONSTITUTION", "x", Severity.HIGH, "x", "custom")
        result = ValidationResult(
            valid=False, constitutional_hash=ALL_RULES.hash, violations=[violation]
        )
        monkeypatch.setattr(governor._engine, "validate", lambda *_a, **_k: result)
        decision = governor.evaluate("t", {})
        assert decision.verdict is Verdict.DENY
        assert decision.rule_ids == ("NOT-IN-CONSTITUTION",)
        assert decision.reason == "Blocked by ACGS rule NOT-IN-CONSTITUTION."

    def test_unknown_rule_id_next_to_review_rule_is_listed_as_blocking(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = ToolCallGovernor(ALL_RULES, agent_id="t")
        violations = [
            Violation("T-REVIEW", "refunds need review", Severity.HIGH, "x", "custom"),
            Violation("NOT-IN-CONSTITUTION", "x", Severity.HIGH, "x", "custom"),
        ]
        result = ValidationResult(
            valid=False, constitutional_hash=ALL_RULES.hash, violations=violations
        )
        monkeypatch.setattr(governor._engine, "validate", lambda *_a, **_k: result)
        decision = governor.evaluate("t", {})
        assert decision.verdict is Verdict.DENY
        assert decision.rule_ids == ("T-REVIEW", "NOT-IN-CONSTITUTION")
        assert decision.reason == (
            "Blocked by ACGS rule NOT-IN-CONSTITUTION. "
            "Review rules that also matched: ACGS rule T-REVIEW (refunds need review)."
        )

    def test_invalid_result_without_violations_denies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        governor = ToolCallGovernor(ALL_RULES, agent_id="t")
        result = ValidationResult(valid=False, constitutional_hash=ALL_RULES.hash)
        monkeypatch.setattr(governor._engine, "validate", lambda *_a, **_k: result)
        decision = governor.evaluate("t", {})
        assert decision.verdict is Verdict.DENY
        assert decision.rule_ids == ()

    def test_halt_without_rule_id_denies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        governor = ToolCallGovernor(ALL_RULES, agent_id="t")

        def halt(*_a: Any, **_k: Any) -> ValidationResult:
            msg = "halt"
            raise ConstitutionalViolationError(msg, rule_id="")

        monkeypatch.setattr(governor._engine, "validate", halt)
        decision = governor.evaluate("t", {})
        assert decision.verdict is Verdict.DENY
        assert decision.rule_ids == ("unknown",)


# ── Identifier pattern (not in the adapter tests) ────────────────────────────

_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_LOWER_OR_DIGIT = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
_ALNUM = _LETTERS | frozenset("0123456789")


def _original_identifier_match(text: str) -> bool:
    """Reference for the adapters' original pattern, written without a regex.

    The original is a letter, then letters or digits, then one or more groups, where
    a group is a separator (``_`` or ``-``) plus letters or digits, or an upper-case
    letter plus lower-case letters or digits. It is spelled out here because the
    pattern itself backtracks exponentially.
    """
    size = len(text)

    @functools.cache
    def groups_from(start: int) -> bool:
        if start >= size:
            return False
        if text[start] in "_-":
            allowed = _ALNUM
        elif text[start] in _UPPER:
            allowed = _LOWER_OR_DIGIT
        else:
            return False
        end = start + 1
        while end < size and text[end] in allowed:
            end += 1
            if end == size or groups_from(end):
                return True
        return False

    if not text or text[0] not in _LETTERS:
        return False
    prefix_end = 1
    while True:
        if groups_from(prefix_end):
            return True
        if prefix_end < size and text[prefix_end] in _ALNUM:
            prefix_end += 1
        else:
            return False


def test_identifier_pattern_matches_the_same_strings_as_the_original() -> None:
    from acgs_lite.tool_calls import _IDENTIFIER_VALUE

    differences = [
        candidate
        for length in range(7)
        for candidate in map("".join, itertools.product("aA0-_!", repeat=length))
        if bool(_IDENTIFIER_VALUE.match(candidate)) != _original_identifier_match(candidate)
    ]
    assert differences == []


def test_identifier_pattern_does_not_backtrack_exponentially() -> None:
    from acgs_lite.tool_calls import _IDENTIFIER_VALUE

    # The original pattern roughly doubles its time with every repetition and
    # needs several seconds for this input.
    hostile = "A-" + "0A0-" * 25
    started = time.perf_counter()
    assert _IDENTIFIER_VALUE.match(hostile) is None
    assert time.perf_counter() - started < 1.0


def test_many_hostile_argument_values_are_evaluated_quickly() -> None:
    governor = ToolCallGovernor(_constitution(BLOCK), agent_id="agent")
    hostile = ("A-" + "0A0-" * 15)[:64]
    started = time.perf_counter()
    decision = governor.evaluate("tool", {f"k{index}": hostile for index in range(500)})
    assert decision.verdict is Verdict.ALLOW
    assert time.perf_counter() - started < 2.0


# ── Hidden control characters in argument values (not in the adapter tests) ──

_HIDDEN_WHITESPACE = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x1f", "\x85"]


class _Shouty:
    def __init__(self, text: str) -> None:
        self._text = text

    def __str__(self) -> str:
        return self._text


@pytest.mark.parametrize("hidden", _HIDDEN_WHITESPACE)
def test_hidden_control_inside_a_keyword_does_not_hide_it(hidden: str) -> None:
    # The engine drops these characters before matching. str.split() treats them as
    # whitespace, so collapsing whitespace first turned "del<VT>ete" into "del ete".
    governor = ToolCallGovernor(_constitution(BLOCK), agent_id="agent")
    decision = governor.evaluate("execute", {"value": f"del{hidden}ete everything"})
    assert decision.verdict is Verdict.DENY
    assert decision.rule_ids == ("T-BLOCK",)


@pytest.mark.parametrize("hidden", _HIDDEN_WHITESPACE)
def test_hidden_control_used_as_a_word_separator_is_still_denied(hidden: str) -> None:
    governor = ToolCallGovernor(_constitution(BLOCK), agent_id="agent")
    decision = governor.evaluate("execute", {"value": f"delete{hidden}everything"})
    assert decision.verdict is Verdict.DENY


def test_hidden_control_in_a_non_string_value_does_not_hide_a_keyword() -> None:
    governor = ToolCallGovernor(_constitution(BLOCK), agent_id="agent")
    decision = governor.evaluate("execute", {"value": _Shouty("del\x0bete everything")})
    assert decision.verdict is Verdict.DENY


def test_hidden_control_reading_is_added_as_a_second_line() -> None:
    text = format_tool_call("execute", {"value": "del\x0bete everything"})
    assert text.splitlines()[2:4] == ["value: del ete everything", "value: delete everything"]


def test_plain_values_are_rendered_once() -> None:
    text = format_tool_call("execute", {"value": "delete\n  everything\tnow", "n": 3})
    assert text.splitlines() == [
        "tool: execute",
        "arguments:",
        "n: 3",
        "value: delete everything now",
    ]


@pytest.mark.parametrize(
    "value",
    [
        "\x85delete\x85\xad everything",
        "de﻿le\x7fte\x1c\x1f\x7f everything",
        "\x00delete ﻿\x0beverything",
    ],
)
def test_mixed_hidden_characters_do_not_hide_a_keyword(value: str) -> None:
    # Found by fuzzing: the engine blocks each of these as raw text, so the
    # rendered tool call must be blocked too.
    governor = ToolCallGovernor(_constitution(BLOCK), agent_id="agent")
    assert governor.evaluate("execute", {"value": value}).verdict is Verdict.DENY
