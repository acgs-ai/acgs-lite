"""ACGS-Lite integration for HuggingFace ``smolagents``.

``smolagents`` agents act by *writing Python code* and executing it, rather
than emitting JSON tool calls.  That makes the generated code itself the thing
worth governing — *before* it runs.  This adapter plugs constitutional
governance into the three stable smolagents extension points:

* **the executor** — :class:`GovernedPythonExecutor` wraps any smolagents
  ``PythonExecutor`` and validates each code action *before* delegating, so a
  blocked snippet raises and never executes.
* **final-answer checks** — a callable (``(answer, memory) -> bool``) that
  rejects a final answer violating the constitution, letting the agent retry.
* **step callbacks** — a callable invoked after each step that records the
  step's code/output to the tamper-evident audit log (non-blocking).

:class:`SmolagentsGovernor` owns one :class:`~acgs_lite.engine.GovernanceEngine`
(plus an :class:`~acgs_lite.audit.AuditLog`) and produces all three hooks, so a
single constitution governs the whole run.  Pre-execution code checks use the
AST-based :class:`~acgs_lite.engine.code_analysis.CodeActionValidator` in
addition to the constitution's string rules.

``smolagents`` is **not** imported at module load: the governor and executor
are duck-typed and work in tests without it installed.  Only
:func:`build_governed_code_agent` requires the package.

Usage::

    from smolagents import CodeAgent, InferenceClientModel
    from acgs_lite.integrations.smolagents import SmolagentsGovernor

    governor = SmolagentsGovernor()
    agent = CodeAgent(tools=[...], model=InferenceClientModel())
    governor.wrap(agent)          # in-place: executor + checks + audit
    agent.run("Summarise sales.csv")
    print(governor.stats)

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from acgs_lite.constitution import Constitution
from acgs_lite.engine.code_analysis import CodeActionValidator
from acgs_lite.engine.types import ValidationResult
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.integrations.base import GovernedBase

logger = logging.getLogger(__name__)

try:
    import smolagents  # noqa: F401

    SMOLAGENTS_AVAILABLE = True
except ImportError:
    SMOLAGENTS_AVAILABLE = False

# Context flag that routes a validate() call through the AST code validator.
_CODE_CONTEXT: dict[str, str] = {"action_type": "code"}


class GovernedPythonExecutor:
    """Constitutional wrapper around a smolagents ``PythonExecutor``.

    Intercepts the executor call to validate the code action first; in strict
    mode a blocking violation raises
    :class:`~acgs_lite.errors.ConstitutionalViolationError` and the code never
    runs.  All other attributes/methods (``send_tools``, ``send_variables``,
    ``state`` …) are delegated to the wrapped executor unchanged, so this works
    across smolagents versions regardless of the executor's return shape.
    """

    def __init__(self, inner: Any, governor: SmolagentsGovernor) -> None:
        self._inner = inner
        self._gov = governor

    def __call__(self, code_action: str, *args: Any, **kwargs: Any) -> Any:
        # Raises in strict mode if the code is blocked; records an audit entry.
        self._gov.validate_code(code_action)
        return self._inner(code_action, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        # Only reached for attributes not set on this wrapper.
        if name in ("_inner", "_gov"):
            raise AttributeError(name)
        return getattr(self._inner, name)


class SmolagentsGovernor(GovernedBase):
    """Constitutional governance for a smolagents agent run.

    Holds a single engine + audit log and emits the smolagents hooks that bind
    governance to a run.  Reusable across agents that should share one
    constitution and audit trail.
    """

    def __init__(
        self,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "smolagents-agent",
        strict: bool = True,
        analyze_code: bool = True,
        code_validator: CodeActionValidator | None = None,
    ) -> None:
        self._init_governance(
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )
        self.analyze_code = analyze_code
        self.code_validator = code_validator or CodeActionValidator()
        if analyze_code:
            # One decision covers constitution string rules + AST structural rules.
            self.engine.add_validator(self.code_validator.as_engine_validator())

    # -- core validation ----------------------------------------------------

    def validate_code(self, code: str, *, strict: bool | None = None) -> ValidationResult:
        """Validate a code action (constitution + AST rules) and audit it.

        In strict mode a blocking violation raises
        :class:`~acgs_lite.errors.ConstitutionalViolationError`.
        """
        return self.engine.validate(
            code,
            agent_id=f"{self.agent_id}:code",
            context=dict(_CODE_CONTEXT),
            strict=strict,
        )

    # -- smolagents hooks ---------------------------------------------------

    def python_executor(self, inner: Any) -> GovernedPythonExecutor:
        """Wrap a smolagents ``PythonExecutor`` with pre-execution governance."""
        return GovernedPythonExecutor(inner, self)

    def final_answer_check(self) -> Callable[..., bool]:
        """Return a smolagents ``final_answer_checks`` callable.

        Validates the final answer non-strictly; returns ``True`` to accept and
        ``False`` to reject (smolagents then continues the loop).  Never raises,
        so a violating answer triggers a retry rather than crashing the run.
        """

        def _check(final_answer: Any, memory: Any = None) -> bool:  # noqa: ARG001
            text = final_answer if isinstance(final_answer, str) else str(final_answer)
            result = self._validate_nonstrict(text, label="smolagents final answer")
            return result is None or result.valid

        return _check

    def step_callback(self) -> Callable[..., None]:
        """Return a smolagents ``step_callbacks`` callable.

        Records each step's code action and observation to the audit log
        (non-blocking).  Accepts the one- or two-argument smolagents callback
        signature.
        """

        def _callback(memory_step: Any, agent: Any = None) -> None:  # noqa: ARG001
            code = _first_str_attr(memory_step, ("code_action", "tool_call", "action"))
            if code:
                self._validate_nonstrict(code, label="smolagents step code")
            observation = _first_str_attr(
                memory_step, ("observations", "observation", "action_output")
            )
            if observation:
                self._validate_nonstrict(observation, label="smolagents step output")

        return _callback

    # -- convenience --------------------------------------------------------

    def wrap(self, agent: Any) -> Any:
        """Attach governance to an existing smolagents agent in place.

        Replaces ``agent.python_executor`` with a governed wrapper and appends
        the final-answer check and step callback.  Returns the same agent for
        chaining.  Idempotent guards avoid double-wrapping the executor.
        """
        inner = getattr(agent, "python_executor", None)
        if inner is not None and not isinstance(inner, GovernedPythonExecutor):
            agent.python_executor = self.python_executor(inner)

        _append_hook(agent, "final_answer_checks", self.final_answer_check())
        _append_hook(agent, "step_callbacks", self.step_callback())
        return agent

    @property
    def stats(self) -> dict[str, Any]:
        """Return governance statistics for this run."""
        return self.governance_stats


def _first_str_attr(obj: Any, names: tuple[str, ...]) -> str | None:
    """Return the first non-empty string attribute among *names*, else ``None``."""
    for name in names:
        value = getattr(obj, name, None)
        if isinstance(value, str) and value:
            return value
    return None


def _append_hook(agent: Any, attr: str, hook: Any) -> None:
    """Append *hook* to a smolagents list/None hook attribute.

    ``step_callbacks`` may be a list, ``None``, or a dict keyed by step type.
    For a dict we cannot infer the right key without importing smolagents
    types, so we skip it and log; lists and ``None`` are handled directly.
    """
    existing = getattr(agent, attr, None)
    if existing is None:
        setattr(agent, attr, [hook])
    elif isinstance(existing, list):
        existing.append(hook)
    else:
        logger.warning(
            "Cannot attach governance to agent.%s of type %s; "
            "pass the hook explicitly when constructing the agent.",
            attr,
            type(existing).__name__,
        )


def build_governed_code_agent(
    *,
    constitution: Constitution | None = None,
    agent_id: str = "smolagents-agent",
    strict: bool = True,
    analyze_code: bool = True,
    **code_agent_kwargs: Any,
) -> tuple[Any, SmolagentsGovernor]:
    """Construct a smolagents ``CodeAgent`` with governance attached.

    Requires ``smolagents`` (``pip install acgs-lite[smolagents]``).  Remaining
    keyword arguments are forwarded to ``CodeAgent`` (``tools``, ``model``, …).
    Returns ``(agent, governor)``.
    """
    if not SMOLAGENTS_AVAILABLE:
        raise ImportError("smolagents is required. Install with: pip install acgs-lite[smolagents]")
    from smolagents import CodeAgent  # noqa: PLC0415

    governor = SmolagentsGovernor(
        constitution=constitution,
        agent_id=agent_id,
        strict=strict,
        analyze_code=analyze_code,
    )
    agent = CodeAgent(**code_agent_kwargs)
    governor.wrap(agent)
    return agent, governor


__all__ = [
    "SMOLAGENTS_AVAILABLE",
    "ConstitutionalViolationError",
    "GovernedPythonExecutor",
    "SmolagentsGovernor",
    "build_governed_code_agent",
]
