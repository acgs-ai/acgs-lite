"""Tests for the smolagents governance adapter (integrations/smolagents.py).

These use lightweight fakes for the smolagents executor/agent so they run
without ``smolagents`` installed — the blocking behaviour comes from ACGS-Lite's
own AST validator and engine, not from smolagents.
"""

from __future__ import annotations

import pytest

from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.integrations.smolagents import (
    GovernedPythonExecutor,
    SmolagentsGovernor,
)

pytestmark = pytest.mark.integration


def _const_with_rule(action: ViolationAction) -> Constitution:
    """A one-rule constitution that fires on the keyword 'forbiddenphrase'."""
    rule = Rule(
        id="TEST-BLOCK",
        text="Forbidden phrase is not allowed",
        severity=Severity.CRITICAL,
        category="safety",
        keywords=["forbiddenphrase"],
        workflow_action=action,
    )
    return Constitution(id="test-const", version="1.0.0", rules=[rule])


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


def test_executor_blocks_even_when_governor_non_strict():
    # H1: the pre-execution gate is a HARD gate. A strict=False governor must
    # NOT downgrade it to audit-only — dangerous code still never runs.
    inner = _FakeExecutor()
    gov = SmolagentsGovernor(strict=False)
    executor = gov.python_executor(inner)
    with pytest.raises(ConstitutionalViolationError):
        executor(DANGEROUS_CODE)
    assert inner.calls == []


def test_executor_blocks_deeply_nested_code_action():
    # H2 end-to-end: padding a dangerous action with deep nesting cannot defeat
    # the gate — the analyzer fails closed and the executor blocks.
    inner = _FakeExecutor()
    executor = SmolagentsGovernor().python_executor(inner)
    payload = "(" * 2000 + "os.system('id')" + ")" * 2000
    with pytest.raises(ConstitutionalViolationError):
        executor(payload)
    assert inner.calls == []


def test_executor_blocks_extreme_unary_nesting_memoryerror_band():
    # H2 MemoryError band end-to-end: deep unary nesting makes ast.parse raise
    # MemoryError (not RecursionError); the gate must still fail closed and the
    # inner executor must never run the smuggled __import__('os').system call.
    inner = _FakeExecutor()
    executor = SmolagentsGovernor().python_executor(inner)
    payload = "not " * 9000 + "__import__('os').system('id')"
    with pytest.raises(ConstitutionalViolationError):
        executor(payload)
    assert inner.calls == []


def test_medium_finding_is_non_blocking_through_executor():
    # T2: a MEDIUM (WARN) finding must pass through the strict executor — only
    # blocking severities stop execution.
    inner = _FakeExecutor()
    executor = SmolagentsGovernor().python_executor(inner)
    out = executor("value = getattr(obj, 'name')")
    assert out == ("ok", "", False)
    assert inner.calls == ["value = getattr(obj, 'name')"]


def test_executor_governs_alternate_execution_methods():
    # M6: run()/execute() are execution entrypoints too; they must be gated, not
    # blindly delegated through __getattr__.
    class _MultiExec:
        def __init__(self):
            self.calls: list = []
            self.state: dict = {}

        def __call__(self, code, *a, **k):
            self.calls.append(("call", code))
            return ("ok", "", False)

        def run(self, code, *a, **k):
            self.calls.append(("run", code))
            return "ran"

        def execute(self, code, *a, **k):
            self.calls.append(("execute", code))
            return "executed"

    inner = _MultiExec()
    executor = SmolagentsGovernor().python_executor(inner)
    assert executor.run(SAFE_CODE) == "ran"
    assert executor.execute(SAFE_CODE) == "executed"
    for entry in ("run", "execute"):
        with pytest.raises(ConstitutionalViolationError):
            getattr(executor, entry)(DANGEROUS_CODE)
    # Only the safe calls reached the inner executor.
    assert all(code == SAFE_CODE for _, code in inner.calls)


def test_executor_gates_run_code_raise_errors_bypass():
    # Adversarial F1: the REAL smolagents PythonExecutor delegates __call__ to
    # run_code_raise_errors. A name-based allowlist that omits it lets a caller
    # reach the inner executor ungoverned. Fail-closed arg-based gating blocks
    # ANY forwarded callable invoked with a code action.
    class _RealisticExec:
        def __init__(self):
            self.ran: list = []
            self.state: dict = {}

        def __call__(self, code):
            return self.run_code_raise_errors(code)

        def run_code_raise_errors(self, code, return_final_answer=False):
            self.ran.append(code)
            return ("out", "logs", False)

        def send_variables(self, variables):  # non-code call must pass through
            return ("vars", variables)

    inner = _RealisticExec()
    executor = SmolagentsGovernor().python_executor(inner)
    # The framework's real execution method is gated, not just __call__.
    with pytest.raises(ConstitutionalViolationError):
        executor.run_code_raise_errors(DANGEROUS_CODE)
    assert inner.ran == []
    # Safe code still runs through it.
    assert executor.run_code_raise_errors(SAFE_CODE) == ("out", "logs", False)
    assert inner.ran == [SAFE_CODE]
    # A non-code call (dict arg) is delegated unchanged, not gated.
    assert executor.send_variables({"x": 1}) == ("vars", {"x": 1})


def test_executor_blocks_non_string_code_action():
    # L5/L12 at the gate: a non-string code action cannot be analyzed, so the
    # gate blocks it fail-closed with a clean ConstitutionalViolationError rather
    # than crashing the engine on action[:500] before the analyzer runs.
    inner = _FakeExecutor()
    executor = SmolagentsGovernor().python_executor(inner)
    with pytest.raises(ConstitutionalViolationError):
        executor(12345)  # type: ignore[arg-type]
    assert inner.calls == []


def test_executor_decodes_and_governs_bytes_code_action():
    # Bytes are decoded at the gate so both string rules and the AST validator
    # see the source; dangerous bytes are blocked, safe bytes pass through.
    inner = _FakeExecutor()
    executor = SmolagentsGovernor().python_executor(inner)
    with pytest.raises(ConstitutionalViolationError):
        executor(DANGEROUS_CODE.encode())  # type: ignore[arg-type]
    assert inner.calls == []


def test_executor_gates_bytearray_and_memoryview_on_forwarded_path():
    # Adversarial (governance-branch-review #1): _extract_code_arg once accepted
    # only (str, bytes) while _gate decoded bytearray, so a bytearray code action
    # on a FORWARDED method (run_code_raise_errors) skipped the gate entirely and
    # ran ungoverned -- a fail-open bypass of the executor gate. Every bytes-like
    # carrier must be gated on the forwarded path exactly as on direct __call__.
    class _RealisticExec:
        def __init__(self):
            self.ran: list = []
            self.state: dict = {}

        def __call__(self, code):
            return self.run_code_raise_errors(code)

        def run_code_raise_errors(self, code, return_final_answer=False):
            self.ran.append(code)
            return ("out", "logs", False)

    dangerous = DANGEROUS_CODE.encode()
    for carrier in (bytearray(dangerous), memoryview(dangerous)):
        inner = _RealisticExec()
        executor = SmolagentsGovernor().python_executor(inner)
        # Forwarded execution method must gate the bytes-like action (the bypass).
        with pytest.raises(ConstitutionalViolationError):
            executor.run_code_raise_errors(carrier)
        assert inner.ran == []
        # Direct __call__ path gates it too (control).
        with pytest.raises(ConstitutionalViolationError):
            executor(carrier)
        assert inner.ran == []

    # Safe bytes-like code still reaches the inner executor through forwarding.
    inner = _RealisticExec()
    executor = SmolagentsGovernor().python_executor(inner)
    executor.run_code_raise_errors(bytearray(SAFE_CODE.encode()))
    assert len(inner.ran) == 1
    assert bytes(inner.ran[0]).decode() == SAFE_CODE


def test_executor_gates_code_shadowed_behind_benign_positional():
    # Adversarial (verify-governance-fixes / M6 residual): dangerous code passed
    # behind a benign leading positional must NOT run. Returning only the FIRST
    # code carrier let the benign string be validated (passing) while the trailing
    # code was forwarded to the inner executor ungoverned. The gate now validates
    # EVERY carrier, on both the forwarded path and __call__.
    class _SessionExec:
        def __init__(self):
            self.ran: list = []

        def __call__(self, *args, **kwargs):
            self.ran.append(args)
            return "called"

        def run(self, session_id, code, **kwargs):
            self.ran.append((session_id, code))
            return f"executed under {session_id}"

    danger = "import os\nos.system('id')"
    # Forwarded method with code at the 2nd positional.
    inner = _SessionExec()
    ex = SmolagentsGovernor().python_executor(inner)
    with pytest.raises(ConstitutionalViolationError):
        ex.run("session-9", danger)
    assert inner.ran == []
    # __call__ with a benign leading marker then dangerous code.
    inner2 = _SessionExec()
    ex2 = SmolagentsGovernor().python_executor(inner2)
    with pytest.raises(ConstitutionalViolationError):
        ex2("benign_marker", danger)
    assert inner2.ran == []


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


def test_stats_exposes_analyze_code_flag():
    # L7: the reduced-governance posture must be observable, not silent.
    assert SmolagentsGovernor().stats["analyze_code"] is True
    assert SmolagentsGovernor(analyze_code=False).stats["analyze_code"] is False


# -- final_answer_check rejection + never-raises (T1, M1, M5, L9) -----------


def test_final_answer_check_rejects_blocking_answer():
    # T1: the reject-and-retry contract — a blocking answer returns False.
    check = SmolagentsGovernor(
        constitution=_const_with_rule(ViolationAction.BLOCK)
    ).final_answer_check()
    assert check("the forbiddenphrase appears here") is False
    assert check("a totally clean answer") is True


def test_final_answer_check_never_raises_on_halt_rule():
    # M1: a HALT rule raises at the engine layer regardless of strict; the
    # non-blocking hook must swallow it and reject rather than crash the loop.
    check = SmolagentsGovernor(
        constitution=_const_with_rule(ViolationAction.HALT)
    ).final_answer_check()
    assert check("this contains forbiddenphrase") is False


def test_final_answer_check_never_raises_on_bad_str():
    # M5: an answer whose __str__ raises must not propagate out of the hook.
    class _Boom:
        def __str__(self):
            raise ValueError("boom")

    check = SmolagentsGovernor().final_answer_check()
    assert check(_Boom()) in (True, False)


def test_final_answer_check_rejects_unreadable_answer():
    # M5 (fail-closed): a non-empty answer whose __str__ and __repr__ both raise
    # cannot be proven safe, so it is rejected (False), not silently accepted.
    class _Unreadable:
        def __str__(self):
            raise ValueError("boom")

        def __repr__(self):
            raise ValueError("boom")

    check = SmolagentsGovernor().final_answer_check()
    assert check(_Unreadable()) is False
    # A genuinely empty answer still has nothing to govern -> accepted.
    assert check("") is True
    assert check(None) is True


def test_final_answer_check_serialises_structured_answer():
    # L9: structured content is matchable, not an opaque repr.
    check = SmolagentsGovernor(
        constitution=_const_with_rule(ViolationAction.BLOCK)
    ).final_answer_check()
    assert check({"plan": "use the forbiddenphrase"}) is False


def test_final_answer_check_matches_non_ascii_in_structured_answer():
    # Adversarial (verify-governance-fixes / M5-L9): a non-ASCII forbidden keyword
    # inside a structured answer must be matchable. With json.dumps' default
    # ensure_ascii=True it would serialise to "café" and slip past substring
    # matching; ensure_ascii=False exposes it at plain-string fidelity.
    rule = Rule(
        id="TEST-NONASCII",
        text="café is not allowed",
        severity=Severity.CRITICAL,
        category="safety",
        keywords=["café"],
        workflow_action=ViolationAction.BLOCK,
    )
    const = Constitution(id="nonascii-const", version="1.0.0", rules=[rule])
    check = SmolagentsGovernor(constitution=const).final_answer_check()
    # Plain string is caught (control)...
    assert check("go to the café now") is False
    # ...and so is the same content wrapped in a structured answer.
    assert check({"plan": "go to the café now"}) is False
    assert check(["meet at the café"]) is False
    # A clean structured answer is still accepted.
    assert check({"plan": "summarise the report"}) is True


def test_step_callback_never_raises_on_halt_rule():
    # M1: step callbacks are non-blocking even when a HALT rule matches.
    gov = SmolagentsGovernor(constitution=_const_with_rule(ViolationAction.HALT))
    callback = gov.step_callback()
    callback(_FakeStep(code_action="forbiddenphrase", observations="forbiddenphrase output"))


# -- wrap() robustness (M4, L8) --------------------------------------------


def test_wrap_coerces_tuple_hook_sequences():
    # M4: a tuple hook sequence must be coerced, not silently dropped.
    class _TupleAgent:
        def __init__(self):
            self.python_executor = _FakeExecutor()
            self.final_answer_checks = ()
            self.step_callbacks = ()

    agent = _TupleAgent()
    SmolagentsGovernor().wrap(agent)
    assert isinstance(agent.final_answer_checks, list)
    assert len(agent.final_answer_checks) == 1
    assert isinstance(agent.step_callbacks, list)
    assert len(agent.step_callbacks) == 1


def test_wrap_does_not_double_append_hooks():
    # L8: re-wrapping with the same governor is idempotent for hooks too.
    agent = _FakeAgent()
    gov = SmolagentsGovernor()
    gov.wrap(agent)
    gov.wrap(agent)
    assert len(agent.final_answer_checks) == 1
    assert len(agent.step_callbacks) == 1
