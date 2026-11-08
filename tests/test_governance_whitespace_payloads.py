"""Whitespace in governed payloads cannot hide a rule match.

Two layers used to conceal ``\\t``/``\\n``/``\\r`` splices from ``\\s+``/``\\b`` rules:

* the JSON projection escaped them to the two characters ``\\t``/``\\n`` inside the
  blob, so ``{"q": "x\\nrm -rf /"}`` never showed ``rm -rf`` after a word boundary;
* the engine's literal prefilter gated ``\\bdrop\\s+table\\b`` on ``"drop table"`` and
  ``\\bdrop\\b`` on ``"drop "``, so ``drop\\ttable`` and ``please drop`` were skipped.

Every case is driven through the real entry points (``GovernedAgent.run``/``arun``,
``GovernedCallable`` issue_grant and direct sync/async calls), not only the helper.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from typing import Any

import pytest

from acgs_lite import GovernedAgent, MACIRole
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import DecisionReceipt, ExecutionBoundary
from acgs_lite.serialization import governance_payloads_for_enforcement


def _constitution() -> Constitution:
    return Constitution.from_rules(
        [
            Rule(
                id="NO-DROP",
                text="no drop table",
                patterns=[r"\bdrop\s+table\b"],
                severity=Severity.CRITICAL,
            ),
            Rule(
                id="NO-RMRF",
                text="no rm -rf",
                patterns=[r"\brm\s+-rf\b"],
                severity=Severity.CRITICAL,
            ),
        ]
    )


DENY_KWARGS = [
    pytest.param({"q": "x\nrm -rf /"}, id="newline-value"),
    pytest.param({"q": "x\ndrop table users"}, id="newline-drop"),
    pytest.param({"kw": "drop\ttable users"}, id="tab-value"),
    pytest.param({"q": "drop\r\ntable users"}, id="crlf-value"),
    pytest.param({"q": [{"a": ["go\nrm -rf /"]}]}, id="nested-list-dict"),
    pytest.param({"q": {"inner": ("ok", "go\trm -rf /")}}, id="nested-tuple"),
    pytest.param({"q": [b"go\nrm -rf /"]}, id="nested-bytes"),
    pytest.param({"q": {"drop\ttable users": 1}}, id="dict-key"),
    pytest.param({"q": {"a": {"go\nrm -rf /": None}}}, id="nested-dict-key"),
]

BENIGN_KWARGS = [
    pytest.param({"q": "line one\nline two\n\tindented\r\n"}, id="multi-line"),
    pytest.param({"q": {"notes": ["a\tb", "c\nd"], "k\ney": "v"}}, id="nested-multi-line"),
]


class _Stub:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, input: str, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        return "ok"

    async def arun(self, input: str, **kwargs: Any) -> str:
        return self.run(input, **kwargs)


def _agent(stub: _Stub) -> GovernedAgent:
    return GovernedAgent(stub, constitution=_constitution(), maci_role=MACIRole.EXECUTOR)


def _invoke(mode: str, agent: GovernedAgent, **kwargs: Any) -> Any:
    if mode == "run":
        return agent.run("hello", governance_action="execute", **kwargs)
    return asyncio.run(agent.arun("hello", governance_action="execute", **kwargs))


def _receipt(method: str) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-ws",
        goal="whitespace call",
        proposed_method=method,
        decision_type="ALLOW",
        authority_basis="role:test",
        matched_constraints=("test-constraint",),
        policy_version="policy-v1",
        execution_boundary=ExecutionBoundary(
            allowed_method=method,
            allowed_scope=None,
            allowed_subjects=(),
            expires_at=None,
            single_use=False,
        ),
    )


# --- GovernedAgent.run / arun -----------------------------------------------------


@pytest.mark.parametrize("mode", ["run", "arun"])
@pytest.mark.parametrize("kwargs", DENY_KWARGS)
def test_agent_kwargs_whitespace_splice_denies(mode: str, kwargs: dict[str, Any]) -> None:
    stub = _Stub()
    with pytest.raises(ConstitutionalViolationError) as excinfo:
        _invoke(mode, _agent(stub), **kwargs)
    assert excinfo.value.rule_id in {"NO-DROP", "NO-RMRF"}
    assert stub.calls == []


@pytest.mark.parametrize("mode", ["run", "arun"])
@pytest.mark.parametrize("kwargs", BENIGN_KWARGS)
def test_agent_benign_multiline_kwargs_pass(mode: str, kwargs: dict[str, Any]) -> None:
    stub = _Stub()
    assert _invoke(mode, _agent(stub), **kwargs) == "ok"
    assert stub.calls == [kwargs]


@pytest.mark.parametrize("mode", ["run", "arun"])
def test_agent_input_tab_splice_denies(mode: str) -> None:
    stub = _Stub()
    agent = _agent(stub)
    with pytest.raises(ConstitutionalViolationError):
        if mode == "run":
            agent.run("please drop\ttable users", governance_action="execute")
        else:
            asyncio.run(agent.arun("please drop\ttable users", governance_action="execute"))
    assert stub.calls == []


# --- GovernedCallable: issue_grant, sync call, async call -------------------------


def _sync_tool(calls: list[object]) -> Callable[..., str]:
    @GovernedCallable(_constitution())
    def tool(**kwargs: Any) -> str:
        calls.append(kwargs)
        return "done"

    return tool


def _async_tool(calls: list[object]) -> Callable[..., Any]:
    @GovernedCallable(_constitution())
    async def tool(**kwargs: Any) -> str:
        calls.append(kwargs)
        return "done"

    return tool


@pytest.mark.parametrize("kwargs", DENY_KWARGS)
def test_callable_kwargs_whitespace_splice_denies(kwargs: dict[str, Any]) -> None:
    calls: list[object] = []
    tool = _sync_tool(calls)
    with pytest.raises(ConstitutionalViolationError):
        tool.issue_grant(**kwargs)  # type: ignore[attr-defined]
    with pytest.raises(ConstitutionalViolationError):
        tool(decision_receipt=_receipt("tool"), **kwargs)
    async_tool = _async_tool(calls)
    with pytest.raises(ConstitutionalViolationError):
        asyncio.run(async_tool(decision_receipt=_receipt("tool"), **kwargs))
    assert calls == []


@pytest.mark.parametrize("kwargs", BENIGN_KWARGS)
def test_callable_benign_multiline_kwargs_pass(kwargs: dict[str, Any]) -> None:
    calls: list[object] = []
    assert _sync_tool(calls)(decision_receipt=_receipt("tool"), **kwargs) == "done"
    assert asyncio.run(_async_tool(calls)(decision_receipt=_receipt("tool"), **kwargs)) == "done"
    assert calls == [kwargs, kwargs]


def test_callable_output_whitespace_splice_is_withheld() -> None:
    @GovernedCallable(_constitution())
    def tool() -> object:
        return {"result": "ok\nrm -rf /"}

    with pytest.raises(ConstitutionalViolationError):
        tool(decision_receipt=_receipt("tool"))


# --- projection helper: raw leaves follow the JSON blob ---------------------------


@pytest.mark.parametrize("codepoint", [9, 10, 13])
def test_projection_returns_raw_text_for_json_escaped_whitespace(codepoint: int) -> None:
    text = "forbidden" + chr(codepoint) + "word"
    for value in ({"memo": text}, {text: "ok"}, [text], (text,), [text.encode()], {"a": [text]}):
        payloads = governance_payloads_for_enforcement(value)
        assert text in payloads, value
        assert not payloads[0].count(chr(codepoint)), "blob stays JSON-escaped"
    # A top-level string is already raw and is not duplicated.
    assert governance_payloads_for_enforcement(text) == [text]


def test_projection_returns_raw_text_for_quote_and_backslash() -> None:
    assert governance_payloads_for_enforcement({"q": 'say "x"', "p": "a\\b"}) == [
        '{"p": "a\\\\b", "q": "say \\"x\\""}',
        "q",
        'say "x"',
        "p",
        "a\\b",
    ]


def test_projection_deduplicates_raw_leaves() -> None:
    assert governance_payloads_for_enforcement(["a\nb", "a\nb", {"a\nb": "a\nb"}]) == [
        '["a\\nb", "a\\nb", {"a\\nb": "a\\nb"}]',
        "a\nb",
    ]


def test_projection_returns_every_text_leaf_and_key_raw() -> None:
    # Plain leaves too: inside the blob every leaf follows a quote, so ``^``/``$``
    # anchored rules only see it when it is evaluated on its own.
    assert governance_payloads_for_enforcement({"k": "v", "n": [1, "x y", ""]}) == [
        '{"k": "v", "n": [1, "x y", ""]}',
        "k",
        "v",
        "n",
        "x y",
    ]


# --- engine prefilter: anchors are literal substrings of every match --------------


@pytest.mark.parametrize(
    ("pattern", "text"),
    [
        (r"\bdrop\s+table\b", "drop\ttable"),
        (r"\bdrop\s+table\b", "drop  table"),
        (r"\bdrop\s+table\b", "DROP\nTABLE"),
        (r"\bdrop\b", "please drop"),
        (r"\bdrop\b", "drop."),
        (r"\bdrop\b", "drop\tit"),
        (r"\bfoo.bar\b", "foo_bar"),
        (r"\b(?:drop|truncate)\s+table\b", "truncate table"),
    ],
)
def test_engine_pattern_prefilter_does_not_skip_matches(pattern: str, text: str) -> None:
    rule = Rule(id="R", text="r", patterns=[pattern], severity=Severity.CRITICAL)
    engine = GovernanceEngine(Constitution.from_rules([rule]), strict=False)
    assert engine.validate("benign text").valid
    result = engine.validate(text)
    assert not result.valid
    assert [v.rule_id for v in result.violations] == ["R"]


def test_engine_alternation_pattern_is_never_anchor_gated() -> None:
    rule = Rule(id="R", text="r", patterns=[r"\b(?:drop|truncate)\b"], severity=Severity.CRITICAL)
    engine = GovernanceEngine(Constitution.from_rules([rule]), strict=False)
    assert engine._pat_anchor_dispatch == ()
    assert [ri for ri, _ in engine._no_anchor_patterns] == [0]


# --- anchored rules see every leaf as written -------------------------------------


def _anchored_agent(stub: _Stub) -> GovernedAgent:
    rule = Rule(id="NO-RMRF-START", text="r", patterns=[r"^rm\s+-rf"], severity=Severity.CRITICAL)
    return GovernedAgent(
        stub, constitution=Constitution.from_rules([rule]), maci_role=MACIRole.EXECUTOR
    )


@pytest.mark.parametrize("mode", ["run", "arun"])
@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"q": "rm -rf /"}, id="plain"),
        pytest.param({"q": "rm\t-rf /"}, id="tab"),
        pytest.param({"q": ["ok", {"cmd": "rm -rf /"}]}, id="nested"),
        pytest.param({"q": {"rm -rf /": 1}}, id="key"),
    ],
)
def test_agent_start_anchored_rule_sees_plain_leaves(mode: str, kwargs: dict[str, Any]) -> None:
    stub = _Stub()
    with pytest.raises(ConstitutionalViolationError) as excinfo:
        _invoke(mode, _anchored_agent(stub), **kwargs)
    assert excinfo.value.rule_id == "NO-RMRF-START"
    assert stub.calls == []


@pytest.mark.parametrize("mode", ["run", "arun"])
def test_agent_start_anchored_rule_allows_mid_text(mode: str) -> None:
    stub = _Stub()
    assert _invoke(mode, _anchored_agent(stub), q="never rm -rf /") == "ok"


# --- anchor soundness: the anchor is in every text the regex matches --------------

_REVIEW_CASES = [
    (r"\bdrops?\b", "please drop it"),
    (r"secrets?", "a secret"),
    (r"colou?r", "color"),
    (r"pass(word){0,1}", "pass"),
    (r"(dangerous)?payload", "payload"),
    (r"(?:please\s+)?delete\s+all", "delete all"),
    (r"(?<!not )allowed", "allowed"),
    (r"(?!xyz)abcdef", "abcdef"),
    (r"\bdrop\s+table\b", "drop\ttable"),
    (r"\b(?:drop|truncate)\s+table\b", "truncate table"),
    (r"secret", "a secret"),
    (r"disk", "disk"),
    (r"kill", "kill"),
]

_SAMPLE_TEXTS = [
    "123-45-6789",
    "token sk-" + "a" * 24,
    "ghp_" + "b" * 36,
    "glpat-" + "c" * 20,
    "x UNION   SELECT y",
    "<script src=x>",
    "eval (1)",
    "4111111111111111",
    "123456789",
    "A" * 40,
]


def _fold_variants(text: str) -> list[str]:
    """Case and Unicode-fold variants that re.IGNORECASE still matches."""
    return [
        text,
        text.upper(),
        text.replace("s", "ſ"),  # long s
        text.replace("i", "ı"),  # dotless i
        text.replace("i", "İ"),  # I with dot
        text.replace("k", "K"),  # Kelvin sign
    ]


def _repo_patterns() -> list[str]:
    patterns = [p for r in Constitution.default().rules for p in r.patterns]
    for domain in ("gitlab", "healthcare", "finance", "security", "general"):
        patterns += [p for r in Constitution.from_template(domain).rules for p in r.patterns]
    return list(dict.fromkeys(patterns))


def test_anchor_is_substring_of_every_match() -> None:
    from acgs_lite.engine.core import _match_variants, _required_literal_anchor

    patterns = [p for p, _ in _REVIEW_CASES] + _repo_patterns()
    corpus = [v for t in [t for _, t in _REVIEW_CASES] + _SAMPLE_TEXTS for v in _fold_variants(t)]
    checked = 0
    for pattern in patterns:
        compiled = re.compile(pattern, re.IGNORECASE)
        anchor = _required_literal_anchor(pattern)
        rule = Rule(id="R", text="r", patterns=[pattern], severity=Severity.CRITICAL)
        engine = GovernanceEngine(Constitution.from_rules([rule]), strict=False)
        for text in corpus:
            variants = _match_variants(text)
            if not any(compiled.search(v) for v in variants):
                continue
            checked += 1
            if anchor is not None:
                assert any(anchor in v for v in variants if compiled.search(v)), (
                    pattern,
                    text,
                    anchor,
                )
            assert not engine.validate(text).valid, (pattern, text, anchor)
    assert checked >= len(_REVIEW_CASES) * 3  # the corpus really exercises the patterns


@pytest.mark.parametrize(
    ("pattern", "anchor"),
    [
        (r"\bdrops?\b", "drop"),
        (r"colou?r", "colo"),
        (r"(?:please\s+)?delete\s+all", "delete"),
        (r"(?<!not )allowed", "allowed"),
        (r"(?!xyz)abcdef", "abcdef"),
        (r"(dangerous)?payload", "payload"),
        (r"secrets?", "ecret"),  # "s" can match U+017F, which survives lower()
        (r"pass(word){0,1}", None),
        (r"drop|truncate", None),
        (r"café", "caf"),  # a non-ASCII literal ends the run
        ("été", None),
        (r"[", None),  # unparseable
    ],
)
def test_required_literal_anchor(pattern: str, anchor: str | None) -> None:
    from acgs_lite.engine.core import _required_literal_anchor

    assert _required_literal_anchor(pattern) == anchor
