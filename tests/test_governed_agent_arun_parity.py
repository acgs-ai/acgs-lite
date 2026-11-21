"""``GovernedAgent.arun`` enforces the same preamble and emits the same CDP records as ``run``.

``arun`` skipped the circuit breaker (the Article 14 kill-switch) and never emitted
CDP records. Every test goes through ``run`` and ``arun`` and asserts whether the
wrapped agent was invoked.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from acgs_lite import GovernedAgent, MACIRole
from acgs_lite.cdp.store import InMemoryCDPBackend
from acgs_lite.circuit_breaker import GovernanceCircuitBreaker, GovernanceHaltError
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.errors import ConstitutionalViolationError

MODES = pytest.mark.parametrize("mode", ["run", "arun"])


class StubAgent:
    def __init__(self, output: Any = "ok") -> None:
        self.calls: list[str] = []
        self._output = output

    def run(self, input: str, **kwargs: Any) -> Any:
        self.calls.append(input)
        return self._output


class AsyncStubAgent(StubAgent):
    async def arun(self, input: str, **kwargs: Any) -> Any:
        return self.run(input, **kwargs)


def _stub(mode: str, output: Any = "ok") -> StubAgent:
    return StubAgent(output) if mode == "run" else AsyncStubAgent(output)


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


def _invoke(mode: str, governed: GovernedAgent, input: str, **kwargs: Any) -> Any:
    if mode == "run":
        return governed.run(input, **kwargs)
    return asyncio.run(governed.arun(input, **kwargs))


def _breaker(tmp_path: Path) -> GovernanceCircuitBreaker:
    return GovernanceCircuitBreaker(system_id="parity", signal_dir=tmp_path, check_file=False)


@MODES
def test_tripped_breaker_halts_before_agent_runs(mode: str, tmp_path: Path) -> None:
    breaker = _breaker(tmp_path)
    stub = _stub(mode)
    governed = GovernedAgent(
        stub,
        constitution=_constitution(),
        maci_role=MACIRole.EXECUTOR,
        circuit_breaker=breaker,
    )
    assert _invoke(mode, governed, "hello", governance_action="execute") == "ok"
    breaker.trip("operator halt")

    with pytest.raises(GovernanceHaltError, match="operator halt"):
        _invoke(mode, governed, "hello", governance_action="execute")
    assert stub.calls == ["hello"]

    breaker.reset()
    assert _invoke(mode, governed, "hello", governance_action="execute") == "ok"


@MODES
def test_tripped_breaker_is_checked_before_maci(mode: str, tmp_path: Path) -> None:
    # No maci_role and no governance_action: MACI would deny, but the halt comes first.
    breaker = _breaker(tmp_path)
    breaker.trip("operator halt")
    stub = _stub(mode)
    governed = GovernedAgent(stub, constitution=_constitution(), circuit_breaker=breaker)

    with pytest.raises(GovernanceHaltError):
        _invoke(mode, governed, "hello")
    assert stub.calls == []


@MODES
def test_allowed_run_emits_cdp_allow_record(mode: str) -> None:
    backend = InMemoryCDPBackend()
    stub = _stub(mode)
    governed = GovernedAgent(
        stub,
        constitution=Constitution.default(),
        maci_role=MACIRole.EXECUTOR,
        cdp_backend=backend,
    )

    assert _invoke(mode, governed, "hello", governance_action="execute") == "ok"
    assert len(backend.save_calls) == 1
    record = backend.save_calls[0]
    assert record.verdict == "allow"
    assert record.action == "execute"
    assert record.violated_rules == []


@MODES
def test_denied_output_emits_cdp_deny_record(mode: str) -> None:
    backend = InMemoryCDPBackend()
    stub = _stub(mode, output="self-validate bypass validation")
    governed = GovernedAgent(
        stub,
        constitution=Constitution.default(),
        maci_role=MACIRole.EXECUTOR,
        cdp_backend=backend,
    )

    with pytest.raises(ConstitutionalViolationError) as exc_info:
        _invoke(mode, governed, "hello", governance_action="execute")
    assert len(backend.save_calls) == 1
    record = backend.save_calls[0]
    assert record.verdict == "deny"
    assert record.violated_rules == [exc_info.value.rule_id]
    assert exc_info.value.rule_id
    assert record.risk_score == 1.0


@MODES
def test_intervention_halt_during_cdp_reaches_caller(mode: str) -> None:
    class HaltingInterventions:
        def evaluate(self, record: dict[str, Any]) -> None:
            raise GovernanceHaltError("parity", "intervention halt")

    stub = _stub(mode)
    governed = GovernedAgent(
        stub,
        constitution=Constitution.default(),
        maci_role=MACIRole.EXECUTOR,
        cdp_backend=InMemoryCDPBackend(),
        intervention_engine=HaltingInterventions(),
    )

    with pytest.raises(GovernanceHaltError, match="intervention halt"):
        _invoke(mode, governed, "hello", governance_action="execute")
