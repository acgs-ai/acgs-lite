"""Tests for the smolagents governance adapter (integrations/smolagents.py).

These use lightweight fakes for the smolagents executor/agent so they run
without ``smolagents`` installed — the blocking behaviour comes from ACGS-Lite's
own AST validator and engine, not from smolagents.
"""

from __future__ import annotations

import pytest

from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.integrations.smolagents import (
    GovernedPythonExecutor,
    SmolagentsGovernor,
)

pytestmark = pytest.mark.integration

# Code that the AST validator flags as CRITICAL → blocks in strict mode.
DANGEROUS_CODE = "import os\nos.system('rm -rf /')"
# Flagged by the AST validator (unauthorized import) but inert as plain text,
# so the default constitution alone does not block it.
AST_ONLY_CODE = "import requests\ndata = requests.get('http://example.com')"
SAFE_CODE = "a = 1\nb = a + 2\nresult = b * 10"


class _FakeExecutor:
    """Minimal stand-in for a smolagents PythonExecutor."""

    def __init__(self):
        self.calls: list[str] = []
        self.state: dict = {}

    def __call__(self, code_action: str, *args, **kwargs):
        self.calls.append(code_action)
        return ("ok", "", False)

    def send_tools(self, tools):  # delegated-attribute smoke target
        return ("tools", tools)


class _FakeAgent:
    """Minimal stand-in for a smolagents CodeAgent."""

    def __init__(self):
        self.python_executor = _FakeExecutor()
        self.final_answer_checks: list = []
        self.step_callbacks: list = []


class _FakeStep:
    def __init__(self, code_action=None, observations=None):
        self.code_action = code_action
        self.observations = observations


# -- GovernedPythonExecutor ------------------------------------------------


def test_executor_allows_safe_code():
    inner = _FakeExecutor()
    gov = SmolagentsGovernor()
    executor = gov.python_executor(inner)
    out = executor(SAFE_CODE)
    assert out == ("ok", "", False)
    assert inner.calls == [SAFE_CODE]


def test_executor_blocks_dangerous_code_before_running():
    inner = _FakeExecutor()
    gov = SmolagentsGovernor()  # strict by default
    executor = gov.python_executor(inner)
    with pytest.raises(ConstitutionalViolationError):
        executor(DANGEROUS_CODE)
    # Crucially, the inner executor was never invoked.
    assert inner.calls == []


def test_executor_non_strict_does_not_raise():
    inner = _FakeExecutor()
    gov = SmolagentsGovernor(strict=False)
    executor = gov.python_executor(inner)
    out = executor(DANGEROUS_CODE)
    assert out == ("ok", "", False)
    assert inner.calls == [DANGEROUS_CODE]


def test_executor_delegates_unknown_attributes():
    inner = _FakeExecutor()
    executor = GovernedPythonExecutor(inner, SmolagentsGovernor())
    assert executor.send_tools(["t"]) == ("tools", ["t"])
    assert executor.state is inner.state


def test_ast_only_code_blocks_when_analysis_on():
    inner = _FakeExecutor()
    executor = SmolagentsGovernor().python_executor(inner)
    with pytest.raises(ConstitutionalViolationError):
        executor(AST_ONLY_CODE)
    assert inner.calls == []


def test_executor_can_disable_ast_analysis():
    inner = _FakeExecutor()
    gov = SmolagentsGovernor(analyze_code=False)
    executor = gov.python_executor(inner)
    # With AST analysis off, the default constitution does not block this
    # otherwise-inert code, so it passes through to the inner executor.
    out = executor(AST_ONLY_CODE)
    assert out == ("ok", "", False)
    assert inner.calls == [AST_ONLY_CODE]


# -- final_answer_check ----------------------------------------------------


def test_final_answer_check_accepts_clean_answer():
    check = SmolagentsGovernor().final_answer_check()
    assert check("The total is 42.") is True


def test_final_answer_check_handles_non_string():
    check = SmolagentsGovernor().final_answer_check()
    assert check(42) is True


# -- step_callback ---------------------------------------------------------


def test_step_callback_records_audit_entries():
    gov = SmolagentsGovernor()
    callback = gov.step_callback()
    before = gov.engine.stats["total_validations"]
    callback(_FakeStep(code_action=SAFE_CODE, observations="done"))
    after = gov.engine.stats["total_validations"]
    assert after > before
    assert gov.audit_log.verify_chain()


def test_step_callback_is_non_blocking_on_violation():
    gov = SmolagentsGovernor()
    callback = gov.step_callback()
    # Must not raise even though the code is dangerous (audit-only).
    callback(_FakeStep(code_action=DANGEROUS_CODE))


def test_step_callback_two_arg_signature():
    gov = SmolagentsGovernor()
    callback = gov.step_callback()
    callback(_FakeStep(code_action=SAFE_CODE), object())  # agent positional arg


# -- wrap() ----------------------------------------------------------------


def test_wrap_attaches_all_hooks():
    agent = _FakeAgent()
    inner = agent.python_executor
    gov = SmolagentsGovernor()
    returned = gov.wrap(agent)

    assert returned is agent
    assert isinstance(agent.python_executor, GovernedPythonExecutor)
    assert len(agent.final_answer_checks) == 1
    assert len(agent.step_callbacks) == 1
    # Governed executor now blocks dangerous code before the original runs.
    with pytest.raises(ConstitutionalViolationError):
        agent.python_executor(DANGEROUS_CODE)
    assert inner.calls == []


def test_wrap_is_idempotent_on_executor():
    agent = _FakeAgent()
    gov = SmolagentsGovernor()
    gov.wrap(agent)
    first = agent.python_executor
    gov.wrap(agent)
    # Executor not double-wrapped; hooks appended each call (caller's choice).
    assert agent.python_executor is first


def test_wrap_initialises_none_hook_lists():
    class _Bare:
        def __init__(self):
            self.python_executor = _FakeExecutor()
            self.final_answer_checks = None
            self.step_callbacks = None

    agent = _Bare()
    SmolagentsGovernor().wrap(agent)
    assert isinstance(agent.final_answer_checks, list)
    assert isinstance(agent.step_callbacks, list)


# -- stats -----------------------------------------------------------------


def test_governor_exposes_stats():
    gov = SmolagentsGovernor(agent_id="demo")
    stats = gov.stats
    assert stats["agent_id"] == "demo"
    assert "total_validations" in stats
    assert stats["audit_chain_valid"] is True
