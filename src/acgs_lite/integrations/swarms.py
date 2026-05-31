"""ACGS-Lite Swarms Integration.

Wraps a `swarms <https://github.com/kyegomez/swarms>`_ ``Agent`` with
constitutional governance.  The task/prompt is validated *before* the
underlying agent executes, and the result is validated non-blockingly after.

Enforcement is fail-closed: when input validation raises
:class:`~acgs_lite.errors.ConstitutionalViolationError`, the wrapped ``run``
never calls the underlying agent.  Output validation mirrors the CrewAI adapter:
violations are logged, never raised.

Usage::

    from swarms import Agent
    from acgs_lite.integrations.swarms import GovernedSwarmsAgent

    agent = Agent(agent_name="Researcher", system_prompt="Find info")
    governed = GovernedSwarmsAgent(agent)

    result = governed.run("Summarise the quarterly report")

    # Attribute access delegates to the underlying agent
    print(governed.agent_name)  # "Researcher"

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import logging
from typing import Any

from acgs_lite.constitution import Constitution
from acgs_lite.integrations.base import GovernedBase

logger = logging.getLogger(__name__)

try:
    from swarms import Agent  # noqa: F401

    SWARMS_AVAILABLE = True
except ImportError:
    SWARMS_AVAILABLE = False
    Agent = object  # type: ignore[assignment,misc]


class GovernedSwarmsAgent(GovernedBase):
    """Swarms ``Agent`` wrapper with constitutional governance.

    Validates the task/prompt before the underlying agent runs it and
    validates the output non-blockingly after execution.

    Usage::

        from swarms import Agent
        from acgs_lite.integrations.swarms import GovernedSwarmsAgent

        agent = Agent(agent_name="Researcher", system_prompt="Find info")
        governed = GovernedSwarmsAgent(agent)

        # Attribute access delegates to the underlying agent
        print(governed.agent_name)  # "Researcher"
    """

    def __init__(
        self,
        agent: Any,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "swarms-agent",
        strict: bool = True,
    ) -> None:
        if not SWARMS_AVAILABLE:
            raise ImportError("swarms is required. Install with: pip install acgs-lite[swarms]")

        self._agent = agent
        self._init_governance(
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )

    @classmethod
    def wrap(
        cls,
        agent: Any,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "swarms-agent",
        strict: bool = True,
    ) -> GovernedSwarmsAgent:
        """Wrap a Swarms ``Agent`` with governance."""
        return cls(
            agent,
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to the underlying Swarms agent.

        Fail-closed: a task string passed to an execution method this wrapper
        does not override by name (``arun``, ``run_batched``, ``stream``, a
        future method) is validated before the underlying agent runs it, so
        delegation cannot become an ungoverned execution path.
        """
        if name == "_agent":
            raise AttributeError(name)
        return self._govern_forwarded_attr(name, getattr(self._agent, name))

    def _validate_input(self, text: str) -> None:
        """Validate input text against the constitution (raises on violation)."""
        if text:
            self.engine.validate(text, agent_id=self.agent_id)

    def _validate_output(self, text: str) -> None:
        """Validate output text without raising (log warnings only)."""
        self._validate_nonstrict(text, label="Swarms agent output")

    def run(self, task: str, *args: Any, **kwargs: Any) -> Any:
        """Run a task with governance validation.

        Validates *task* before execution (fail-closed: a blocking violation
        raises and the underlying agent is never called) and validates the
        result non-blockingly after execution.
        """
        # Fail-closed: this raises on a blocking violation, so the underlying
        # agent below is never reached for a disallowed task.
        self._validate_input(str(task))

        result = self._agent.run(task, *args, **kwargs)

        self._validate_output(str(result) if result is not None else "")
        return result

    def __call__(self, task: str, *args: Any, **kwargs: Any) -> Any:
        """Alias for :meth:`run` (swarms agents are also callable)."""
        return self.run(task, *args, **kwargs)

    @property
    def stats(self) -> dict[str, Any]:
        """Return governance statistics for this agent."""
        return self.governance_stats


__all__ = [
    "SWARMS_AVAILABLE",
    "GovernedSwarmsAgent",
]
