"""Dispatcher-level cap on raw-leaf fan-out for governed values.

Each distinct non-empty text leaf and key of a governed value is validated on its
own, after the value's JSON payload. A value with more than ``_MAX_RAW_LEAVES``
distinct leaves denies with ``GOVERNANCE-PAYLOAD-UNEVALUABLE`` instead of fanning
out into one engine call (and one audit entry) per leaf. Every test goes through
``GovernedAgent.run``/``.arun`` or a ``GovernedCallable``-decorated function.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from acgs_lite import GovernedAgent, MACIRole
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import DecisionReceipt, ExecutionBoundary
from acgs_lite.serialization import _MAX_RAW_LEAVES, GovernancePayloadError

UNEVALUABLE = "GOVERNANCE-PAYLOAD-UNEVALUABLE"
MODES = pytest.mark.parametrize("mode", ["run", "arun"])


def _constitution() -> Constitution:
    return Constitution.from_rules(
        [
            Rule(
                id="NO-FORBIDDEN",
                text="Never mention the forbidden word",
                severity=Severity.CRITICAL,
                keywords=["forbidden"],
            )
        ]
    )


def _wide(count: int) -> dict[str, int]:
    """A dict whose only distinct text leaves are its ``count`` keys."""
    return {f"k{i:03d}": i for i in range(count)}


class _Agent:
    def __init__(self, output: Any) -> None:
        self.calls: list[str] = []
        self._output = output

    def run(self, input: str, **kwargs: Any) -> Any:
        self.calls.append(input)
        return self._output

    async def arun(self, input: str, **kwargs: Any) -> Any:
        return self.run(input, **kwargs)


def _spy(monkeypatch: pytest.MonkeyPatch, engine: Any) -> list[str]:
    seen: list[str] = []
    validate = engine.validate

    def spy(payload: str, *args: Any, **kwargs: Any) -> Any:
        seen.append(payload)
        return validate(payload, *args, **kwargs)

    monkeypatch.setattr(engine, "validate", spy)
    return seen


def _invoke(mode: str, governed: GovernedAgent, input: str, **kwargs: Any) -> Any:
    if mode == "run":
        return governed.run(input, governance_action="execute", **kwargs)
    return asyncio.run(governed.arun(input, governance_action="execute", **kwargs))


def _agent(output: Any) -> tuple[_Agent, GovernedAgent]:
    stub = _Agent(output)
    governed = GovernedAgent(stub, constitution=_constitution(), maci_role=MACIRole.EXECUTOR)
    return stub, governed


def test_cap_value() -> None:
    assert _MAX_RAW_LEAVES == 256


# --- GovernedAgent ---------------------------------------------------------------


@MODES
def test_agent_output_at_cap_is_evaluated_leaf_by_leaf(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = _wide(_MAX_RAW_LEAVES)
    stub, governed = _agent(output)
    seen = _spy(monkeypatch, governed.engine)
    assert _invoke(mode, governed, "hello") == output
    assert stub.calls == ["hello"]
    # Every key reached the engine as its own payload.
    assert set(output) <= set(seen)


@MODES
def test_agent_output_over_cap_denied(mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    stub, governed = _agent(_wide(_MAX_RAW_LEAVES + 1))
    seen = _spy(monkeypatch, governed.engine)
    with pytest.raises(GovernancePayloadError) as excinfo:
        _invoke(mode, governed, "hello")
    assert excinfo.value.rule_id == UNEVALUABLE
    assert str(_MAX_RAW_LEAVES) in str(excinfo.value)
    # Denied before any per-leaf validation of the output.
    assert not any(payload.startswith("k") for payload in seen)


@MODES
def test_agent_kwargs_over_cap_denied_before_run(mode: str) -> None:
    stub, governed = _agent("ok")
    with pytest.raises(GovernancePayloadError) as excinfo:
        _invoke(mode, governed, "hello", payload=_wide(_MAX_RAW_LEAVES + 1))
    assert excinfo.value.rule_id == UNEVALUABLE
    assert stub.calls == []


@MODES
def test_agent_benign_payloads_unaffected(mode: str) -> None:
    output = {"summary": "all good", "items": [{"name": "a"}, {"name": "b"}]}
    stub, governed = _agent(output)
    assert _invoke(mode, governed, "hello", payload={"note": "fine", "n": 3}) == output
    assert len(stub.calls) == 1


@MODES
def test_agent_leaf_under_cap_still_denied_by_rule(mode: str) -> None:
    # 254 keys + one more key + its text value = exactly the cap.
    wide: dict[str, Any] = _wide(_MAX_RAW_LEAVES - 2)
    wide["k999"] = "forbidden"
    stub, governed = _agent(wide)
    with pytest.raises(Exception) as excinfo:
        _invoke(mode, governed, "hello")
    assert getattr(excinfo.value, "rule_id", None) == "NO-FORBIDDEN"


# --- GovernedCallable ------------------------------------------------------------


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


@pytest.mark.parametrize("asynchronous", [False, True])
def test_callable_argument_at_cap_passes(
    asynchronous: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = GovernedCallable(_constitution())
    seen = _spy(monkeypatch, guard.engine)
    calls: list[int] = []

    def sync_f(data: dict[str, int]) -> str:
        calls.append(len(data))
        return "ok"

    async def async_f(data: dict[str, int]) -> str:
        return sync_f(data)

    f = guard(async_f if asynchronous else sync_f)
    data = _wide(_MAX_RAW_LEAVES)
    call = f(data, decision_receipt=_receipt(f.__name__))
    result = asyncio.run(call) if asynchronous else call
    assert result == "ok"
    assert calls == [_MAX_RAW_LEAVES]
    assert set(data) <= set(seen)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_callable_argument_over_cap_denied(asynchronous: bool) -> None:
    guard = GovernedCallable(_constitution())
    calls: list[int] = []

    def sync_f(data: dict[str, int]) -> str:
        calls.append(len(data))
        return "ok"

    async def async_f(data: dict[str, int]) -> str:
        return sync_f(data)

    f = guard(async_f if asynchronous else sync_f)
    with pytest.raises(GovernancePayloadError) as excinfo:
        call = f(_wide(_MAX_RAW_LEAVES + 1), decision_receipt=_receipt(f.__name__))
        if asynchronous:
            asyncio.run(call)
    assert excinfo.value.rule_id == UNEVALUABLE
    assert calls == []


def test_callable_output_over_cap_denied() -> None:
    guard = GovernedCallable(_constitution())

    @guard
    def f(text: str) -> dict[str, int]:
        return _wide(_MAX_RAW_LEAVES + 1)

    with pytest.raises(GovernancePayloadError) as excinfo:
        f("hello", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == UNEVALUABLE


def test_callable_benign_payload_unaffected() -> None:
    guard = GovernedCallable(_constitution())

    @guard
    def f(data: dict[str, Any]) -> dict[str, Any]:
        return {"echo": data}

    data = {"name": "alice", "tags": ["x", "y"], "n": 1}
    assert f(data, decision_receipt=_receipt("f")) == {"echo": data}
