"""Payload-projection denials leave a deny entry in the audit trail.

A ``GovernancePayloadError`` is raised while projecting a governed value, before
the engine runs, so the engine records nothing for it. Every test goes through
``GovernedAgent.run``/``.arun``, a ``GovernedCallable``-decorated function or
``issue_grant`` and asserts a ``validation`` entry with ``valid=False`` and the
payload rule id exists.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any

import pytest

from acgs_lite import GovernedAgent, MACIRole
from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import DecisionReceipt, ExecutionBoundary
from acgs_lite.serialization import GovernancePayloadError

OVERSIZE = "GOVERNANCE-PAYLOAD-OVERSIZE"
UNEVALUABLE = "GOVERNANCE-PAYLOAD-UNEVALUABLE"
MODES = pytest.mark.parametrize("mode", ["run", "arun"])


def _denials(audit_log: AuditLog, rule_id: str) -> list[Any]:
    return [
        entry
        for entry in audit_log.entries
        if entry.type == "validation" and not entry.valid and rule_id in entry.violations
    ]


class _Agent:
    def __init__(self, output: Any = "ok") -> None:
        self.calls = 0
        self._output = output

    def run(self, input: str, **kwargs: Any) -> Any:
        self.calls += 1
        return self._output

    async def arun(self, input: str, **kwargs: Any) -> Any:
        return self.run(input, **kwargs)


def _invoke(mode: str, governed: GovernedAgent, input: str, **kwargs: Any) -> Any:
    if mode == "run":
        return governed.run(input, governance_action="execute", **kwargs)
    return asyncio.run(governed.arun(input, governance_action="execute", **kwargs))


def _agent(output: Any = "ok") -> tuple[_Agent, GovernedAgent]:
    stub = _Agent(output)
    governed = GovernedAgent(stub, constitution=Constitution.default(), maci_role=MACIRole.EXECUTOR)
    return stub, governed


@MODES
def test_agent_oversize_input_denial_is_audited(mode: str) -> None:
    stub, governed = _agent()
    with pytest.raises(GovernancePayloadError):
        _invoke(mode, governed, "a" * 10_001)
    assert stub.calls == 0
    (entry,) = _denials(governed.audit_log, OVERSIZE)
    assert entry.action == "governance_payload_denied:payload"
    assert entry.agent_id == governed.agent_id
    assert entry.metadata["rule_id"] == OVERSIZE
    assert governed.audit_log.verify_chain()


@MODES
def test_agent_unevaluable_kwargs_denial_is_audited(mode: str) -> None:
    stub, governed = _agent()
    with pytest.raises(GovernancePayloadError):
        _invoke(mode, governed, "hello", amount=Decimal("1"))
    assert stub.calls == 0
    (entry,) = _denials(governed.audit_log, UNEVALUABLE)
    assert entry.agent_id == f"{governed.agent_id}:kwargs"


@MODES
def test_agent_unevaluable_output_denial_is_audited(mode: str) -> None:
    stub, governed = _agent(output={"amount": Decimal("1")})
    with pytest.raises(GovernancePayloadError):
        _invoke(mode, governed, "hello")
    (entry,) = _denials(governed.audit_log, UNEVALUABLE)
    assert entry.agent_id == f"{governed.agent_id}:output"


@MODES
def test_agent_allowed_call_records_no_payload_denial(mode: str) -> None:
    _, governed = _agent()
    assert _invoke(mode, governed, "hello", note="fine") == "ok"
    assert not [e for e in governed.audit_log.entries if not e.valid]


def _receipt(method: str) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-compat",
        goal="compat call",
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


def _wrapped(guard: GovernedCallable, asynchronous: bool, calls: list[Any], output: Any) -> Any:
    def sync_f(value: Any) -> Any:
        calls.append(value)
        return output

    async def async_f(value: Any) -> Any:
        return sync_f(value)

    return guard(async_f if asynchronous else sync_f)


def _call(f: Any, asynchronous: bool, value: Any) -> Any:
    call = f(value, decision_receipt=_receipt(f.__name__))
    return asyncio.run(call) if asynchronous else call


@pytest.mark.parametrize("asynchronous", [False, True])
def test_callable_argument_denial_is_audited(asynchronous: bool) -> None:
    guard = GovernedCallable(Constitution.default())
    calls: list[Any] = []
    f = _wrapped(guard, asynchronous, calls, "ok")
    # Digestible by the binder (a non-JSON value is refused there first), but oversize.
    with pytest.raises(GovernancePayloadError):
        _call(f, asynchronous, {"text": "a" * 10_001})
    assert calls == []
    (entry,) = _denials(guard.audit_log, OVERSIZE)
    assert entry.action == "governance_payload_denied:arguments"
    assert entry.metadata["stage"] == "arguments"
    assert guard.audit_log.verify_chain()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_callable_output_denial_is_audited(asynchronous: bool) -> None:
    guard = GovernedCallable(Constitution.default())
    calls: list[Any] = []
    f = _wrapped(guard, asynchronous, calls, "x" * 10_001)
    with pytest.raises(GovernancePayloadError):
        _call(f, asynchronous, "hello")
    assert calls == ["hello"]
    (entry,) = _denials(guard.audit_log, OVERSIZE)
    assert entry.action == "governance_payload_denied:output"


def test_callable_issue_grant_denial_is_audited() -> None:
    guard = GovernedCallable(Constitution.default())
    calls: list[Any] = []
    f = _wrapped(guard, False, calls, "ok")
    with pytest.raises(GovernancePayloadError):
        f.issue_grant({"amount": Decimal("1")})
    assert calls == []
    (entry,) = _denials(guard.audit_log, UNEVALUABLE)
    assert entry.action == "governance_payload_denied:issue:arguments"
