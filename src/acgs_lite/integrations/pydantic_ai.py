"""ACGS-Lite Pydantic AI Integration.

Wraps Pydantic AI's Agent and Model with constitutional governance.
Every prompt is validated before execution. Every response is validated
after (non-blocking).

Usage::

    from pydantic_ai import Agent
    from acgs_lite.integrations.pydantic_ai import GovernedPydanticAgent

    agent = Agent("openai:gpt-5.5")
    governed = GovernedPydanticAgent.wrap(agent)
    result = governed.run_sync("What is AI governance?")

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import logging
from typing import Any

from acgs_lite.constitution import Constitution
from acgs_lite.integrations.base import GovernedBase

logger = logging.getLogger(__name__)

try:
    from pydantic_ai import Agent as PydanticAgent  # noqa: F401

    PYDANTIC_AI_AVAILABLE = True
except ImportError:
    PYDANTIC_AI_AVAILABLE = False
    PydanticAgent = object  # type: ignore[assignment,misc]


class GovernedPydanticAgent(GovernedBase):
    """Pydantic AI Agent wrapper with constitutional governance.

    Wraps a ``pydantic_ai.Agent`` instance, validating prompts before
    execution and responses after (non-blocking).

    Usage::

        from pydantic_ai import Agent
        from acgs_lite.integrations.pydantic_ai import GovernedPydanticAgent

        agent = Agent("openai:gpt-5.5")
        governed = GovernedPydanticAgent(agent)
        result = governed.run_sync("What is AI governance?")

    With custom constitution::

        from acgs_lite import Constitution
        constitution = Constitution.from_yaml("rules.yaml")
        governed = GovernedPydanticAgent(agent, constitution=constitution)
    """

    def __init__(
        self,
        agent: Any,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "pydantic-ai-agent",
        strict: bool = True,
    ) -> None:
        if not PYDANTIC_AI_AVAILABLE:
            raise ImportError(
                "pydantic-ai is required. Install with: pip install acgs-lite[pydantic-ai]"
            )

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
        agent_id: str = "pydantic-ai-agent",
        strict: bool = True,
    ) -> GovernedPydanticAgent:
        """Wrap a Pydantic AI Agent with governance."""
        return cls(
            agent,
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )

    def _extract_text(self, data: Any) -> str:
        """Extract text from a Pydantic AI result's data attribute."""
        if isinstance(data, str):
            return data
        return str(data)

    def _validate_output(self, text: str) -> None:
        """Validate output without raising (just log warnings)."""
        self._validate_nonstrict(text, label="Pydantic AI output")

    def run_sync(self, prompt: str, **kwargs: Any) -> Any:
        """Run the agent synchronously with governance.

        Validates the prompt before execution. Validates the response
        text after execution (non-blocking).
        """
        if prompt:
            self.engine.validate(prompt, agent_id=self.agent_id)

        result = self._agent.run_sync(prompt, **kwargs)

        output_text = self._extract_text(result.data)
        self._validate_output(output_text)

        return result

    async def run(self, prompt: str, **kwargs: Any) -> Any:
        """Run the agent asynchronously with governance.

        Validates the prompt before execution. Validates the response
        text after execution (non-blocking).
        """
        if prompt:
            self.engine.validate(prompt, agent_id=self.agent_id)

        result = await self._agent.run(prompt, **kwargs)

        output_text = self._extract_text(result.data)
        self._validate_output(output_text)

        return result

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to the wrapped agent.

        Fail-closed: a prompt string passed to an un-overridden execution method
        is validated before the underlying agent runs it (see
        ``_govern_forwarded_attr``), so delegation is not an ungoverned path.
        """
        if name == "_agent":
            raise AttributeError(name)
        return self._govern_forwarded_attr(name, getattr(self._agent, name))

    @property
    def stats(self) -> dict[str, Any]:
        """Return governance statistics for this agent."""
        return self.governance_stats


class GovernedModel(GovernedBase):
    """Low-level Pydantic AI model wrapper with constitutional governance.

    Intercepts ``request()`` and ``arequest()`` to validate message
    content before sending and response text after receiving.

    Usage::

        from acgs_lite.integrations.pydantic_ai import GovernedModel

        governed = GovernedModel(model)
        response = governed.request(messages)
    """

    def __init__(
        self,
        model: Any,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "pydantic-ai-model",
        strict: bool = True,
    ) -> None:
        if not PYDANTIC_AI_AVAILABLE:
            raise ImportError(
                "pydantic-ai is required. Install with: pip install acgs-lite[pydantic-ai]"
            )

        self._model = model
        self._init_governance(
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )

    def _extract_messages_text(self, messages: Any) -> str:
        """Extract text content from a list of messages."""
        texts: list[str] = []
        if isinstance(messages, list):
            for msg in messages:
                if isinstance(msg, str):
                    texts.append(msg)
                elif hasattr(msg, "content"):
                    texts.append(str(msg.content))
                elif isinstance(msg, dict):
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        texts.append(content)
        elif isinstance(messages, str):
            texts.append(messages)
        return " ".join(texts)

    def _validate_output(self, text: str) -> None:
        """Validate output without raising (just log warnings)."""
        self._validate_nonstrict(text, label="Pydantic AI model output")

    def request(self, messages: Any, **kwargs: Any) -> Any:
        """Intercept a synchronous model request with governance."""
        text = self._extract_messages_text(messages)
        if text:
            self.engine.validate(text, agent_id=self.agent_id)

        response = self._model.request(messages, **kwargs)

        if hasattr(response, "content"):
            self._validate_output(str(response.content))
        elif isinstance(response, str):
            self._validate_output(response)

        return response

    async def arequest(self, messages: Any, **kwargs: Any) -> Any:
        """Intercept an asynchronous model request with governance."""
        text = self._extract_messages_text(messages)
        if text:
            self.engine.validate(text, agent_id=self.agent_id)

        response = await self._model.arequest(messages, **kwargs)

        if hasattr(response, "content"):
            self._validate_output(str(response.content))
        elif isinstance(response, str):
            self._validate_output(response)

        return response

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to the wrapped model.

        Fail-closed: a prompt string passed to an un-overridden execution method
        is validated before the underlying model runs it (see
        ``_govern_forwarded_attr``), so delegation is not an ungoverned path.
        """
        if name == "_model":
            raise AttributeError(name)
        return self._govern_forwarded_attr(name, getattr(self._model, name))

    @property
    def stats(self) -> dict[str, Any]:
        """Return governance statistics for this model."""
        return self.governance_stats
