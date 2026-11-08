"""Dispatcher-level fail-closed payload enforcement for ``GovernedAgent``.

Every test goes through ``GovernedAgent.run`` or ``.arun`` and asserts whether the
wrapped agent ran. ``GovernedAgent`` enforces the same contract as
``GovernedCallable``: input, caller kwargs and output are projected with
``governance_payloads_for_enforcement`` (JSON-native only, never truncated) and any
engine result that is not ``valid is True`` denies, whatever ``strict`` is set to.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from acgs_lite import GovernedAgent, MACIRole
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.serialization import GovernancePayloadError

LIMIT = 10_000
OVERSIZE = "GOVERNANCE-PAYLOAD-OVERSIZE"
UNEVALUABLE = "GOVERNANCE-PAYLOAD-UNEVALUABLE"


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


class StubAgent:
    """Records every invocation; returns queued outputs, then the last one forever."""

    def __init__(self, *outputs: Any) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._outputs = list(outputs) or ["ok"]

    def _next(self, input: str, kwargs: dict[str, Any]) -> Any:
        self.calls.append((input, dict(kwargs)))
        if len(self._outputs) > 1:
            return self._outputs.pop(0)
        return self._outputs[0]

    def run(self, input: str, **kwargs: Any) -> Any:
        return self._next(input, kwargs)


class AsyncStubAgent(StubAgent):
    async def arun(self, input: str, **kwargs: Any) -> Any:
        return self._next(input, kwargs)


def _governed(stub: StubAgent, **options: Any) -> GovernedAgent:
    return GovernedAgent(
        stub,
        constitution=_constitution(),
        maci_role=MACIRole.EXECUTOR,
        **options,
    )


def _invoke(mode: str, governed: GovernedAgent, input: str, **kwargs: Any) -> Any:
    if mode == "run":
        return governed.run(input, governance_action="execute", **kwargs)
    return asyncio.run(governed.arun(input, governance_action="execute", **kwargs))


MODES = pytest.mark.parametrize("mode", ["run", "arun"])
STRICTNESS = pytest.mark.parametrize("strict", [True, False])


def _stub(mode: str, *outputs: Any) -> StubAgent:
    return StubAgent(*outputs) if mode == "run" else AsyncStubAgent(*outputs)


# --- kwargs -----------------------------------------------------------------


@MODES
@STRICTNESS
def test_kwarg_keyword_past_preview_truncation_is_denied(mode: str, strict: bool) -> None:
    # The preview serializer truncated at LIMIT, so this keyword was never evaluated.
    stub = _stub(mode)
    governed = _governed(stub, strict=strict)
    with pytest.raises(GovernancePayloadError) as exc_info:
        _invoke(mode, governed, "safe input", notes="a" * LIMIT + " forbidden")
    assert exc_info.value.rule_id == OVERSIZE
    assert stub.calls == []


@MODES
@STRICTNESS
def test_kwarg_keyword_within_limit_is_denied_by_rule(mode: str, strict: bool) -> None:
    stub = _stub(mode)
    governed = _governed(stub, strict=strict)
    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "safe input", notes={"deep": ["x" * 9_000, "forbidden"]})
    assert exc_info.value.rule_id == "NO-FORBIDDEN"
    assert stub.calls == []


@MODES
def test_non_json_kwarg_is_denied(mode: str) -> None:
    stub = _stub(mode)
    governed = _governed(stub)
    with pytest.raises(GovernancePayloadError) as exc_info:
        _invoke(mode, governed, "safe input", handle=object())
    assert exc_info.value.rule_id == UNEVALUABLE
    assert stub.calls == []


@MODES
def test_oversize_benign_kwarg_is_denied(mode: str) -> None:
    stub = _stub(mode)
    governed = _governed(stub)
    with pytest.raises(GovernancePayloadError) as exc_info:
        _invoke(mode, governed, "safe input", notes="a" * (LIMIT + 1))
    assert exc_info.value.rule_id == OVERSIZE
    assert stub.calls == []


@MODES
def test_oversize_input_is_denied(mode: str) -> None:
    stub = _stub(mode)
    governed = _governed(stub)
    with pytest.raises(GovernancePayloadError) as exc_info:
        _invoke(mode, governed, "a" * (LIMIT + 1))
    assert exc_info.value.rule_id == OVERSIZE
    assert stub.calls == []


# --- strict=False -----------------------------------------------------------


@MODES
def test_strict_false_violating_input_is_denied(mode: str) -> None:
    stub = _stub(mode)
    governed = _governed(stub, strict=False)
    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "say the forbidden word")
    assert exc_info.value.rule_id == "NO-FORBIDDEN"
    assert stub.calls == []
    assert governed.audit_log.query(valid=False)


# --- output -----------------------------------------------------------------


@MODES
@STRICTNESS
def test_violating_output_without_retries_is_denied(mode: str, strict: bool) -> None:
    stub = _stub(mode, "the forbidden answer")
    governed = _governed(stub, strict=strict, max_retries=0)
    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "safe input")
    assert exc_info.value.rule_id == "NO-FORBIDDEN"
    assert len(stub.calls) == 1


@MODES
@STRICTNESS
def test_violating_output_retries_then_denies_after_exhaustion(mode: str, strict: bool) -> None:
    stub = _stub(mode, "the forbidden answer")
    governed = _governed(stub, strict=strict, max_retries=2)
    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "safe input")
    assert exc_info.value.rule_id == "NO-FORBIDDEN"
    assert len(stub.calls) == 3
    assert stub.calls[1][0].startswith("[GOVERNANCE RETRY 1]")
    assert stub.calls[2][0].startswith("[GOVERNANCE RETRY 2]")
    retries = [e for e in governed.audit_log.entries if e.type == "output_retry"]
    assert len(retries) == 2


@MODES
@STRICTNESS
def test_violating_output_remediated_by_retry_is_returned(mode: str, strict: bool) -> None:
    stub = _stub(mode, "the forbidden answer", "a compliant answer")
    governed = _governed(stub, strict=strict, max_retries=1)
    assert _invoke(mode, governed, "safe input") == "a compliant answer"
    assert len(stub.calls) == 2


@MODES
def test_non_json_output_is_denied_without_retry(mode: str) -> None:
    stub = _stub(mode, object())
    governed = _governed(stub, max_retries=2)
    with pytest.raises(GovernancePayloadError) as exc_info:
        _invoke(mode, governed, "safe input")
    assert exc_info.value.rule_id == UNEVALUABLE
    assert len(stub.calls) == 1


@MODES
def test_oversize_output_is_denied(mode: str) -> None:
    stub = _stub(mode, "a" * LIMIT + " forbidden")
    governed = _governed(stub)
    with pytest.raises(GovernancePayloadError) as exc_info:
        _invoke(mode, governed, "safe input")
    assert exc_info.value.rule_id == OVERSIZE


@MODES
def test_validate_output_false_is_the_explicit_output_opt_out(mode: str) -> None:
    sentinel = object()
    stub = _stub(mode, sentinel)
    governed = _governed(stub, validate_output=False)
    assert _invoke(mode, governed, "safe input") is sentinel


# --- clean path -------------------------------------------------------------


@MODES
@STRICTNESS
def test_clean_input_kwargs_and_output_run_and_return(mode: str, strict: bool) -> None:
    output = {"answer": "fine", "items": [1, 2.5, True, None]}
    stub = _stub(mode, output)
    governed = _governed(stub, strict=strict)
    assert _invoke(mode, governed, "safe input", notes={"k": ["v"]}, count=3) == output
    assert stub.calls == [("safe input", {"notes": {"k": ["v"]}, "count": 3})]
