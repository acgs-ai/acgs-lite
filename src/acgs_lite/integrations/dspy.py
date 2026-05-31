"""ACGS-Lite DSPy Integration.

Wraps DSPy Module and Predict with constitutional governance.
Every input is validated before execution. Every output is validated
non-blockingly after execution.

Usage::

    import dspy
    from acgs_lite.integrations.dspy import GovernedDSPyModule

    class MyModule(dspy.Module):
        def __init__(self):
            super().__init__()
            self.predict = dspy.Predict("question -> answer")

        def forward(self, question):
            return self.predict(question=question)

    module = MyModule()
    governed = GovernedDSPyModule(module)
    result = governed(question="What is AI governance?")

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import logging
from typing import Any

from acgs_lite.constitution import Constitution
from acgs_lite.integrations.base import GovernedBase

logger = logging.getLogger(__name__)

try:
    import dspy  # noqa: F401

    DSPY_AVAILABLE = True
except ImportError:
    DSPY_AVAILABLE = False
    dspy = None  # type: ignore[assignment]


class GovernedDSPyModule(GovernedBase):
    """DSPy Module wrapper with constitutional governance.

    Wraps any DSPy Module with governance validation on inputs
    and outputs.  Input kwargs are scanned for string values and
    validated before calling the underlying ``forward()`` method.
    Output text is validated non-blockingly (warnings only) after
    execution.

    Usage::

        from acgs_lite.integrations.dspy import GovernedDSPyModule

        governed = GovernedDSPyModule(my_module)
        result = governed(question="What is AI governance?")
    """

    def __init__(
        self,
        module: Any,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "dspy-agent",
        strict: bool = True,
    ) -> None:
        if not DSPY_AVAILABLE:
            raise ImportError("dspy is required. Install with: pip install acgs-lite[dspy]")

        self._module = module
        self._init_governance(
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )

    @classmethod
    def wrap(
        cls,
        module: Any,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "dspy-agent",
        strict: bool = True,
    ) -> GovernedDSPyModule:
        """Wrap a DSPy Module with governance."""
        return cls(
            module,
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )

    def _extract_input_text(
        self,
        kwargs: dict[str, Any],
    ) -> str:
        """Extract text from input kwargs."""
        parts: list[str] = []
        for value in kwargs.values():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        parts.append(item)
        return " ".join(parts)

    def _extract_output_text(self, result: Any) -> str:
        """Extract text from a DSPy output.

        Handles dspy.Prediction objects which store results as
        attributes, as well as plain strings and objects with
        string attributes.
        """
        if isinstance(result, str):
            return result

        # dspy.Prediction stores completions or named attributes
        if hasattr(result, "completions"):
            completions = result.completions
            if isinstance(completions, dict):
                completion_parts = [str(v) for v in completions.values() if v is not None]
                return " ".join(completion_parts)
            if isinstance(completions, list):
                return " ".join(str(c) for c in completions if c is not None)

        # Generic attribute scanning for Prediction-like objects
        if hasattr(result, "keys") and callable(result.keys):
            attribute_parts: list[str] = []
            for key in result.keys():  # noqa: SIM118
                val = getattr(result, key, None) if not isinstance(result, dict) else result[key]
                if isinstance(val, str):
                    attribute_parts.append(val)
            if attribute_parts:
                return " ".join(attribute_parts)

        # Fallback: check common output attributes
        for attr in (
            "answer",
            "output",
            "response",
            "text",
            "content",
        ):
            val = getattr(result, attr, None)
            if isinstance(val, str):
                return val

        return str(result) if result is not None else ""

    def _validate_output(self, result: Any) -> None:
        """Validate output text without raising."""
        text = self._extract_output_text(result)
        self._validate_nonstrict(text, label="DSPy output")

    def forward(self, **kwargs: Any) -> Any:
        """Execute the module's forward() with governance.

        Validates concatenated string kwargs before execution and
        validates the output non-blockingly after.
        """
        text = self._extract_input_text(kwargs)
        if text:
            self.engine.validate(text, agent_id=self.agent_id)

        result = self._module.forward(**kwargs)

        self._validate_output(result)
        return result

    def __call__(self, **kwargs: Any) -> Any:
        """Delegate to forward() -- DSPy modules are callable."""
        return self.forward(**kwargs)

    def __getattr__(self, name: str) -> Any:
        """Delegate to the underlying DSPy module.

        Fail-closed: a string passed to an un-overridden execution method is
        validated before the underlying module runs it (see
        ``_govern_forwarded_attr``), so delegation is not an ungoverned path.
        """
        if name == "_module":
            raise AttributeError(name)
        return self._govern_forwarded_attr(name, getattr(self._module, name))

    @property
    def stats(self) -> dict[str, Any]:
        """Return governance statistics for this module."""
        return self.governance_stats


class GovernedPredict(GovernedBase):
    """DSPy Predict wrapper with constitutional governance.

    Wraps a ``dspy.Predict`` instance (or any callable predictor)
    with input and output governance validation.

    Usage::

        from acgs_lite.integrations.dspy import GovernedPredict

        predictor = dspy.Predict("question -> answer")
        governed = GovernedPredict(predictor)
        result = governed(question="What is AI governance?")
    """

    def __init__(
        self,
        predict: Any,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "dspy-predict",
        strict: bool = True,
    ) -> None:
        if not DSPY_AVAILABLE:
            raise ImportError("dspy is required. Install with: pip install acgs-lite[dspy]")

        self._predict = predict
        self._init_governance(
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )

    @classmethod
    def wrap(
        cls,
        predict: Any,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "dspy-predict",
        strict: bool = True,
    ) -> GovernedPredict:
        """Wrap a DSPy Predict with governance."""
        return cls(
            predict,
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )

    def _extract_input_text(
        self,
        kwargs: dict[str, Any],
    ) -> str:
        """Extract text from input kwargs."""
        parts: list[str] = []
        for value in kwargs.values():
            if isinstance(value, str):
                parts.append(value)
        return " ".join(parts)

    def _extract_output_text(self, result: Any) -> str:
        """Extract text from a Prediction result."""
        if isinstance(result, str):
            return result

        if hasattr(result, "completions"):
            completions = result.completions
            if isinstance(completions, dict):
                completion_parts = [str(v) for v in completions.values() if v is not None]
                return " ".join(completion_parts)
            if isinstance(completions, list):
                return " ".join(str(c) for c in completions if c is not None)

        if hasattr(result, "keys") and callable(result.keys):
            attribute_parts: list[str] = []
            for key in result.keys():  # noqa: SIM118
                val = getattr(result, key, None) if not isinstance(result, dict) else result[key]
                if isinstance(val, str):
                    attribute_parts.append(val)
            if attribute_parts:
                return " ".join(attribute_parts)

        for attr in (
            "answer",
            "output",
            "response",
            "text",
            "content",
        ):
            val = getattr(result, attr, None)
            if isinstance(val, str):
                return val

        return str(result) if result is not None else ""

    def _validate_output(self, result: Any) -> None:
        """Validate output text without raising."""
        text = self._extract_output_text(result)
        self._validate_nonstrict(text, label="DSPy predict output")

    def __call__(self, **kwargs: Any) -> Any:
        """Call the predictor with governance validation."""
        text = self._extract_input_text(kwargs)
        if text:
            self.engine.validate(text, agent_id=self.agent_id)

        result = self._predict(**kwargs)

        self._validate_output(result)
        return result

    def __getattr__(self, name: str) -> Any:
        """Delegate to the underlying predictor.

        Fail-closed: a string passed to an un-overridden execution method is
        validated before the underlying predictor runs it (see
        ``_govern_forwarded_attr``), so delegation is not an ungoverned path.
        """
        if name == "_predict":
            raise AttributeError(name)
        return self._govern_forwarded_attr(name, getattr(self._predict, name))

    @property
    def stats(self) -> dict[str, Any]:
        """Return governance statistics for this predictor."""
        return self.governance_stats
