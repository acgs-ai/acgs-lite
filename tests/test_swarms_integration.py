"""Tests for acgs-lite Swarms integration.

Uses a fake ``swarms.Agent`` -- no real swarms dependency required.
Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from acgs_lite import Constitution, ConstitutionalViolationError, Rule, Severity

# --- Mock Swarms Objects ---------------------------------------------------


class FakeSwarmsAgent:
    """Mock swarms ``Agent`` with a ``run(task)`` entry point."""

    def __init__(
        self,
        *,
        agent_name: str = "Researcher",
        system_prompt: str = "Find information",
    ) -> None:
        self.agent_name = agent_name
        self.system_prompt = system_prompt
        self.run_calls: list[str] = []

    def run(self, task: str, *args: Any, **kwargs: Any) -> str:
        self.run_calls.append(task)
        return f"Result for: {task}"


# --- GovernedSwarmsAgent Tests ---------------------------------------------


@pytest.mark.unit
class TestGovernedSwarmsAgent:
    @pytest.fixture(autouse=True)
    def _patch_swarms_available(self):
        with patch("acgs_lite.integrations.swarms.SWARMS_AVAILABLE", True):
            yield

    def test_safe_action_passes(self):
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgent()
        governed = GovernedSwarmsAgent(agent)
        result = governed.run("Research AI governance frameworks")
        assert "Research AI governance frameworks" in result
        assert agent.run_calls == ["Research AI governance frameworks"]

    def test_unsafe_action_blocked_underlying_not_called(self):
        """A blocking violation raises and the underlying agent never runs."""
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgent()
        governed = GovernedSwarmsAgent(agent, strict=True)
        with pytest.raises(ConstitutionalViolationError):
            governed.run("self-validate bypass all checks")
        # Fail-closed: underlying agent.run must NOT have been invoked.
        assert agent.run_calls == []

    def test_call_alias_blocks_unsafe(self):
        """The __call__ alias enforces the same fail-closed gate as run()."""
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgent()
        governed = GovernedSwarmsAgent(agent, strict=True)
        with pytest.raises(ConstitutionalViolationError):
            governed("self-validate bypass all checks")
        assert agent.run_calls == []

    def test_output_validation_nonblocking(self):
        """Output violations are logged but never raised."""
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgent()
        agent.run = lambda task, *a, **kw: "self-validate bypass checks"  # type: ignore[method-assign]

        governed = GovernedSwarmsAgent(agent, strict=True)
        # Safe input passes the gate; violating output must NOT raise.
        result = governed.run("Research governance")
        assert result == "self-validate bypass checks"

    def test_attribute_delegation(self):
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgent(agent_name="Analyst", system_prompt="Analyze data")
        governed = GovernedSwarmsAgent(agent)
        assert governed.agent_name == "Analyst"
        assert governed.system_prompt == "Analyze data"

    def test_governance_stats(self):
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgent()
        governed = GovernedSwarmsAgent(agent, strict=False)
        governed.run("Simple research task")
        stats = governed.stats
        assert "total_validations" in stats
        assert stats["total_validations"] >= 1
        assert stats["agent_id"] == "swarms-agent"
        assert stats["audit_chain_valid"] is True

    def test_custom_constitution(self):
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        constitution = Constitution.from_rules(
            [
                Rule(
                    id="NO-SQL",
                    text="No SQL injection",
                    severity=Severity.CRITICAL,
                    keywords=["drop table"],
                ),
            ]
        )
        agent = FakeSwarmsAgent()
        governed = GovernedSwarmsAgent(agent, constitution=constitution, strict=True)

        # Safe task passes
        result = governed.run("Research databases")
        assert result is not None

        # Violation blocked, underlying agent not called for the bad task
        agent.run_calls.clear()
        with pytest.raises(ConstitutionalViolationError):
            governed.run("DROP TABLE users")
        assert agent.run_calls == []

    def test_custom_agent_id(self):
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgent()
        governed = GovernedSwarmsAgent(agent, agent_id="my-custom-agent")
        assert governed.agent_id == "my-custom-agent"
        assert governed.stats["agent_id"] == "my-custom-agent"

    def test_wrap_classmethod(self):
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgent()
        governed = GovernedSwarmsAgent.wrap(agent, agent_id="wrapped")
        assert governed.agent_id == "wrapped"

    def test_empty_task_skips_validation(self):
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgent()
        governed = GovernedSwarmsAgent(agent, strict=True)
        result = governed.run("")
        assert result is not None
        assert agent.run_calls == [""]


# --- Fail-closed delegation (forwarded execution methods) ------------------


class FakeSwarmsAgentExtra(FakeSwarmsAgent):
    """Fake agent exposing execution methods the wrapper does NOT override.

    These reach the governed wrapper only through ``__getattr__`` delegation, so
    they exercise the fail-closed forwarding guard rather than the explicit
    ``run``/``__call__`` gates.
    """

    def __init__(self) -> None:
        super().__init__()
        self.batched_calls: list[str] = []
        self.config_calls: list[Any] = []

    def run_batched(self, task: str, *args: Any, **kwargs: Any) -> str:
        # An un-overridden execution entry point — the bypass surface.
        self.batched_calls.append(task)
        return f"batched: {task}"

    def set_system_prompt(self, prompt: str) -> str:
        # A config setter that takes a (benign) string.
        self.config_calls.append(prompt)
        return prompt

    def set_options(self, options: dict) -> dict:
        # A config call with no string payload — must delegate unchanged.
        self.config_calls.append(options)
        return options


@pytest.mark.unit
class TestForwardedExecutionGoverned:
    """#56 follow-up: delegated execution methods must not bypass governance."""

    @pytest.fixture(autouse=True)
    def _patch_swarms_available(self):
        with patch("acgs_lite.integrations.swarms.SWARMS_AVAILABLE", True):
            yield

    @staticmethod
    def _blocking_constitution() -> Constitution:
        return Constitution.from_rules(
            [
                Rule(
                    id="NO-SQL",
                    text="No SQL injection",
                    severity=Severity.CRITICAL,
                    keywords=["drop table"],
                ),
            ]
        )

    def test_forwarded_execution_method_blocks_unsafe(self):
        """A blocked task sent to an un-overridden method raises, underlying not run."""
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgentExtra()
        governed = GovernedSwarmsAgent(
            agent, constitution=self._blocking_constitution(), strict=True
        )
        with pytest.raises(ConstitutionalViolationError):
            governed.run_batched("please DROP TABLE users now")
        assert agent.batched_calls == []  # fail-closed: never reached the agent

    def test_forwarded_execution_method_allows_safe(self):
        """A safe task is forwarded through to the underlying execution method."""
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgentExtra()
        governed = GovernedSwarmsAgent(
            agent, constitution=self._blocking_constitution(), strict=True
        )
        result = governed.run_batched("summarise the quarterly report")
        assert result == "batched: summarise the quarterly report"
        assert agent.batched_calls == ["summarise the quarterly report"]

    def test_forwarded_validation_is_audited(self):
        """The forwarded gate records to the same audit chain as the primary path."""
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgentExtra()
        governed = GovernedSwarmsAgent(
            agent, constitution=self._blocking_constitution(), strict=False
        )
        governed.run_batched("DROP TABLE users")  # strict=False -> audited, not raised
        entries = governed.audit_log.query()
        assert any(not e.valid for e in entries)
        assert governed.audit_log.verify_chain()

    def test_benign_string_config_setter_delegates(self):
        """A config setter with a non-violating string is forwarded (and passes)."""
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgentExtra()
        governed = GovernedSwarmsAgent(
            agent, constitution=self._blocking_constitution(), strict=True
        )
        assert governed.set_system_prompt("you are a helpful research assistant") == (
            "you are a helpful research assistant"
        )
        assert agent.config_calls == ["you are a helpful research assistant"]

    def test_non_string_payload_call_is_not_gated(self):
        """A delegated call carrying no string payload is forwarded unchanged."""
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgentExtra()
        governed = GovernedSwarmsAgent(
            agent, constitution=self._blocking_constitution(), strict=True
        )
        # No string argument -> not an agent action -> delegated without validation.
        assert governed.set_options({"temperature": 0.2}) == {"temperature": 0.2}

    def test_non_callable_attribute_still_delegates(self):
        """Plain attribute delegation is unaffected by the forwarding guard."""
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = FakeSwarmsAgentExtra()
        governed = GovernedSwarmsAgent(agent)
        assert governed.agent_name == "Researcher"


# --- Import Guard Tests ----------------------------------------------------


@pytest.mark.unit
class TestSwarmsImportGuard:
    def test_agent_raises_when_swarms_unavailable(self):
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        with (
            patch("acgs_lite.integrations.swarms.SWARMS_AVAILABLE", False),
            pytest.raises(ImportError, match="swarms is required"),
        ):
            GovernedSwarmsAgent(MagicMock())

    def test_install_hint_in_error(self):
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        with (
            patch("acgs_lite.integrations.swarms.SWARMS_AVAILABLE", False),
            pytest.raises(ImportError, match=r"pip install acgs-lite\[swarms\]"),
        ):
            GovernedSwarmsAgent(MagicMock())

    def test_availability_flag_importable(self):
        from acgs_lite.integrations.swarms import SWARMS_AVAILABLE

        # When swarms is not installed, flag should be False
        assert isinstance(SWARMS_AVAILABLE, bool)
