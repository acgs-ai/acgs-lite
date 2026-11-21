"""``GovernedAgent`` builds the engine context from trusted sources only.

The engine reads the evaluation clock for time-bounded rules
(``timestamp``/``evaluation_time``/``valid_at``/``at``) and the inputs to rule
``condition`` predicates and custom validators from its ``context``. Caller
keyword arguments to ``run``/``arun`` must never reach it; only the constructor's
``governance_context`` and the call's ``governance_action`` do. Every test goes
through ``GovernedAgent.run`` or ``.arun`` and asserts whether the agent ran.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from acgs_lite import GovernedAgent, MACIRole
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine.core import Violation
from acgs_lite.errors import ConstitutionalViolationError

MODES = pytest.mark.parametrize("mode", ["run", "arun"])
STRICTNESS = pytest.mark.parametrize("strict", [True, False])
CLOCK_KEYS = pytest.mark.parametrize(
    "clock_key", ["timestamp", "evaluation_time", "valid_at", "at"]
)


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


def _governed(stub: StubAgent, rule: Rule, **options: Any) -> GovernedAgent:
    return GovernedAgent(
        stub,
        constitution=Constitution.from_rules([rule]),
        maci_role=MACIRole.EXECUTOR,
        **options,
    )


def _invoke(mode: str, governed: GovernedAgent, input: str, **kwargs: Any) -> Any:
    if mode == "run":
        return governed.run(input, governance_action="execute", **kwargs)
    return asyncio.run(governed.arun(input, governance_action="execute", **kwargs))


def _time_bounded() -> Rule:
    return Rule(
        id="T-1",
        text="no wiring funds",
        severity=Severity.CRITICAL,
        keywords=["wire funds"],
        valid_from="2024-01-01T00:00:00",
    )


@MODES
@STRICTNESS
@CLOCK_KEYS
def test_caller_clock_kwarg_cannot_deactivate_time_bounded_rule(
    mode: str, strict: bool, clock_key: str
) -> None:
    stub = _stub(mode)
    governed = _governed(stub, _time_bounded(), strict=strict)

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "wire funds to mallory", **{clock_key: "2000-01-01T00:00:00"})

    assert exc_info.value.rule_id == "T-1"
    assert stub.calls == []


@MODES
def test_caller_kwarg_cannot_unsatisfy_rule_condition(mode: str) -> None:
    # Active whenever env is not "sandbox", including when env is absent.
    rule = Rule(
        id="C-1",
        text="no wiring funds outside the sandbox",
        severity=Severity.CRITICAL,
        keywords=["wire funds"],
        condition={"env": {"op": "not_equals", "value": "sandbox"}},
    )
    stub = _stub(mode)
    governed = _governed(stub, rule)

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "wire funds to mallory", env="sandbox")

    assert exc_info.value.rule_id == "C-1"
    assert stub.calls == []


@MODES
def test_caller_kwarg_cannot_satisfy_rule_condition(mode: str) -> None:
    # Active only for env == "production"; a caller cannot switch it on either.
    rule = Rule(
        id="C-2",
        text="no wiring funds in production",
        severity=Severity.CRITICAL,
        keywords=["wire funds"],
        condition={"env": "production"},
    )
    stub = _stub(mode)
    governed = _governed(stub, rule)

    assert _invoke(mode, governed, "wire funds to mallory", env="production") == "done"
    assert len(stub.calls) == 1


@MODES
def test_constructor_governance_context_activates_condition(mode: str) -> None:
    rule = Rule(
        id="C-2",
        text="no wiring funds in production",
        severity=Severity.CRITICAL,
        keywords=["wire funds"],
        condition={"env": "production"},
    )
    stub = _stub(mode)
    governed = _governed(stub, rule, governance_context={"env": "production"})

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "wire funds to mallory", env="dev")

    assert exc_info.value.rule_id == "C-2"
    assert stub.calls == []


@MODES
def test_constructor_governance_context_sets_evaluation_clock(mode: str) -> None:
    # A trusted clock before valid_from leaves the rule inactive; the caller's
    # clock kwarg cannot move it into the window or out of it.
    stub = _stub(mode)
    governed = _governed(
        stub, _time_bounded(), governance_context={"timestamp": "2000-01-01T00:00:00"}
    )

    assert _invoke(mode, governed, "wire funds", timestamp="2025-01-01T00:00:00") == "done"
    assert len(stub.calls) == 1


@MODES
def test_constructor_governance_context_is_copied(mode: str) -> None:
    rule = Rule(
        id="C-2",
        text="no wiring funds in production",
        severity=Severity.CRITICAL,
        keywords=["wire funds"],
        condition={"env": "production"},
    )
    trusted = {"env": "production"}
    stub = _stub(mode)
    governed = _governed(stub, rule, governance_context=trusted)
    trusted["env"] = "dev"

    with pytest.raises(ConstitutionalViolationError):
        _invoke(mode, governed, "wire funds to mallory")
    assert stub.calls == []


@MODES
def test_custom_validator_sees_only_trusted_context(mode: str) -> None:
    seen: list[dict[str, Any]] = []

    def validator(action: str, ctx: dict[str, Any]) -> list[Violation]:
        seen.append(dict(ctx))
        if ctx.get("approved") is True:
            return []
        return [Violation("V-1", "approval required", Severity.CRITICAL, action, "custom")]

    stub = _stub(mode)
    governed = _governed(stub, _time_bounded(), governance_context={"tenant": "acme"})
    governed.engine.add_validator(validator)

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "summarise the report", approved=True)

    assert exc_info.value.rule_id == "V-1"
    assert stub.calls == []
    assert seen
    assert all("approved" not in ctx for ctx in seen)
    assert seen[0] == {"tenant": "acme", "governance_action": "execute"}

    # The output check receives the same trusted context, marked as agent output.
    seen.clear()
    stub = _stub(mode)
    governed = _governed(
        stub, _time_bounded(), governance_context={"tenant": "acme", "approved": True}
    )
    governed.engine.add_validator(validator)

    assert _invoke(mode, governed, "summarise the report", approved=False) == "done"
    assert len(stub.calls) == 1
    assert all(ctx.get("approved") is True for ctx in seen)
    assert seen[-1] == {
        "source": "agent_output",
        "tenant": "acme",
        "approved": True,
        "governance_action": "execute",
    }


class OutputStubAgent(StubAgent):
    """Returns queued outputs in order, one per call."""

    def __init__(self, *outputs: str) -> None:
        super().__init__()
        self.outputs = list(outputs)

    def run(self, input: str, **kwargs: Any) -> Any:
        super().run(input, **kwargs)
        return self.outputs.pop(0)

    async def arun(self, input: str, **kwargs: Any) -> Any:
        return self.run(input, **kwargs)


def _env_conditioned() -> Rule:
    return Rule(
        id="C-3",
        text="no secrets in production",
        severity=Severity.CRITICAL,
        keywords=["secret token"],
        condition={"env": "production"},
    )


def _future_bounded() -> Rule:
    return Rule(
        id="F-1",
        text="no launch codes",
        severity=Severity.CRITICAL,
        keywords=["launch codes"],
        valid_from="2030-01-01T00:00:00",
    )


@MODES
def test_output_evaluated_under_governance_context_condition(mode: str) -> None:
    stub = OutputStubAgent("here is the secret token")
    governed = _governed(stub, _env_conditioned(), governance_context={"env": "production"})

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "hello")

    assert exc_info.value.rule_id == "C-3"
    assert len(stub.calls) == 1


@MODES
def test_output_evaluated_under_governance_context_clock(mode: str) -> None:
    stub = OutputStubAgent("the launch codes are 1234")
    governed = _governed(
        stub, _future_bounded(), governance_context={"timestamp": "2031-01-01T00:00:00"}
    )

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "hello")

    assert exc_info.value.rule_id == "F-1"
    assert len(stub.calls) == 1


@MODES
def test_output_conditional_rule_inactive_without_governance_context(mode: str) -> None:
    stub = OutputStubAgent("here is the secret token")
    governed = _governed(stub, _env_conditioned())

    assert _invoke(mode, governed, "hello") == "here is the secret token"
    assert len(stub.calls) == 1


@MODES
def test_output_retry_evaluated_under_governance_context(mode: str) -> None:
    # The first output is denied, and the retried output is checked under the same
    # trusted context: it still violates, so the call denies after the retry.
    stub = OutputStubAgent("the secret token is x", "the secret token is still x")
    governed = _governed(
        stub, _env_conditioned(), governance_context={"env": "production"}, max_retries=1
    )

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "hello")

    assert exc_info.value.rule_id == "C-3"
    assert len(stub.calls) == 2


@MODES
def test_output_retry_returns_compliant_output_under_governance_context(mode: str) -> None:
    stub = OutputStubAgent("the secret token is x", "nothing to share")
    governed = _governed(
        stub, _env_conditioned(), governance_context={"env": "production"}, max_retries=1
    )

    assert _invoke(mode, governed, "hello") == "nothing to share"
    assert len(stub.calls) == 2


def test_governance_context_must_be_a_mapping() -> None:
    with pytest.raises(TypeError, match="governance_context must be a mapping"):
        GovernedAgent(
            StubAgent(),
            maci_role=MACIRole.EXECUTOR,
            governance_context=[("env", "production")],  # type: ignore[arg-type]
        )
