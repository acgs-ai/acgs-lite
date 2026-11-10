"""An operator-pinned ``governance_action`` cannot be relabelled by the caller.

When the constructor's ``governance_context`` sets ``governance_action``, that
label is the one MACI checks, the engine's rule conditions see, and the CDP
record carries. A per-call ``governance_action`` that differs from it denies
before the wrapped agent runs (fail closed); an equal one is allowed. Without a
pinned label the per-call label behaves as before. Every test goes through
``GovernedAgent.run`` or ``.arun`` and asserts whether the agent ran.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from acgs_lite import GovernedAgent, MACIRole
from acgs_lite.cdp.store import InMemoryCDPBackend
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.errors import ConstitutionalViolationError, GovernanceError, MACIViolationError

MODES = pytest.mark.parametrize("mode", ["run", "arun"])
ROLES = pytest.mark.parametrize("role", [MACIRole.OBSERVER, MACIRole.EXECUTOR])
PINNED = {"governance_action": "execute"}


class StubAgent:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def run(self, input: str, **kwargs: Any) -> Any:
        self.calls.append((input, dict(kwargs)))
        return "done"


class AsyncStubAgent(StubAgent):
    async def arun(self, input: str, **kwargs: Any) -> Any:
        return self.run(input, **kwargs)


def _stub(mode: str) -> StubAgent:
    return StubAgent() if mode == "run" else AsyncStubAgent()


def _execute_only_rule() -> Rule:
    return Rule(
        id="X-1",
        text="executions need review",
        severity=Severity.CRITICAL,
        keywords=["delete"],
        condition={"governance_action": "execute"},
    )


def _governed(stub: StubAgent, role: MACIRole, **options: Any) -> GovernedAgent:
    return GovernedAgent(
        stub,
        constitution=Constitution.from_rules([_execute_only_rule()]),
        maci_role=role,
        **options,
    )


def _invoke(mode: str, governed: GovernedAgent, input: str, **kwargs: Any) -> Any:
    if mode == "run":
        return governed.run(input, **kwargs)
    return asyncio.run(governed.arun(input, **kwargs))


@MODES
@ROLES
@pytest.mark.parametrize("splat", [False, True], ids=["keyword", "splat"])
def test_conflicting_per_call_label_denies_before_agent_runs(
    mode: str, role: MACIRole, splat: bool
) -> None:
    stub = _stub(mode)
    governed = _governed(stub, role, governance_context=PINNED)

    with pytest.raises(GovernanceError) as exc_info:
        if splat:
            tool_args = {"governance_action": "read"}  # e.g. model-produced arguments
            _invoke(mode, governed, "delete customer 42", **tool_args)
        else:
            _invoke(mode, governed, "delete customer 42", governance_action="read")

    assert exc_info.value.rule_id == "MACI-ACTION"
    assert not isinstance(exc_info.value, ConstitutionalViolationError)
    assert stub.calls == []


@MODES
def test_conflicting_label_denies_with_maci_advisory(mode: str) -> None:
    # The pin also guards rule selection when MACI enforcement is off.
    stub = _stub(mode)
    governed = GovernedAgent(
        stub,
        constitution=Constitution.from_rules([_execute_only_rule()]),
        enforce_maci=False,
        governance_context=PINNED,
    )

    with pytest.raises(GovernanceError) as exc_info:
        _invoke(mode, governed, "delete customer 42", governance_action="read")
    assert exc_info.value.rule_id == "MACI-ACTION"
    assert stub.calls == []

    with pytest.raises(ConstitutionalViolationError) as violation:
        _invoke(mode, governed, "delete customer 42")
    assert violation.value.rule_id == "X-1"
    assert stub.calls == []


@pytest.mark.parametrize("pinned", ["", None, 1, ["execute"]])
def test_invalid_pinned_label_is_rejected_at_construction(pinned: Any) -> None:
    with pytest.raises(TypeError, match="governance_action"):
        _governed(StubAgent(), MACIRole.EXECUTOR, governance_context={"governance_action": pinned})


@MODES
def test_pinned_label_reaches_maci_without_per_call_label(mode: str) -> None:
    stub = _stub(mode)
    governed = _governed(stub, MACIRole.OBSERVER, governance_context=PINNED)

    with pytest.raises(MACIViolationError):
        _invoke(mode, governed, "summarise the report")

    assert stub.calls == []


@MODES
def test_pinned_label_selects_rules_without_per_call_label(mode: str) -> None:
    stub = _stub(mode)
    governed = _governed(stub, MACIRole.EXECUTOR, governance_context=PINNED)

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "delete customer 42")
    assert exc_info.value.rule_id == "X-1"
    assert stub.calls == []

    assert _invoke(mode, governed, "summarise the report") == "done"
    assert len(stub.calls) == 1


@MODES
def test_equal_per_call_label_is_allowed(mode: str) -> None:
    stub = _stub(mode)
    governed = _governed(stub, MACIRole.EXECUTOR, governance_context=PINNED)

    assert _invoke(mode, governed, "summarise the report", governance_action="execute") == "done"
    assert len(stub.calls) == 1

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "delete customer 42", governance_action="execute")
    assert exc_info.value.rule_id == "X-1"
    assert len(stub.calls) == 1


@MODES
def test_unpinned_per_call_label_is_unchanged(mode: str) -> None:
    # Without a pinned label the caller's label is asserted by the caller: an
    # OBSERVER may ``read``, and the execute-only rule does not apply.
    stub = _stub(mode)
    governed = _governed(stub, MACIRole.OBSERVER, governance_context={"tenant": "acme"})

    assert _invoke(mode, governed, "delete customer 42", governance_action="read") == "done"
    assert len(stub.calls) == 1

    with pytest.raises(MACIViolationError):
        _invoke(mode, governed, "summarise the report", governance_action="execute")
    assert len(stub.calls) == 1

    with pytest.raises(GovernanceError) as exc_info:
        _invoke(mode, governed, "summarise the report")
    assert exc_info.value.rule_id == "MACI-ACTION"
    assert len(stub.calls) == 1


@MODES
@pytest.mark.parametrize("per_call", [None, "execute"], ids=["no-label", "equal-label"])
def test_audit_and_cdp_carry_resolved_label(mode: str, per_call: str | None) -> None:
    # CDP records are only assembled under the canonical constitution (INV-004).
    stub = _stub(mode)
    backend = InMemoryCDPBackend()
    governed = GovernedAgent(
        stub,
        constitution=Constitution.default(),
        maci_role=MACIRole.EXECUTOR,
        governance_context=PINNED,
        cdp_backend=backend,
    )
    kwargs = {} if per_call is None else {"governance_action": per_call}

    assert _invoke(mode, governed, "summarise the report", **kwargs) == "done"

    maci_entries = [e for e in governed.audit_log.entries if e.type == "maci_check"]
    assert [(e.action, e.valid) for e in maci_entries] == [("execute", True)]
    records = backend.list()
    assert len(records) == 1
    assert records[0].action == "execute"
