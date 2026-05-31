"""ACGS-Lite integration for HuggingFace ``smolagents``.

``smolagents`` agents act by *writing Python code* and executing it, rather
than emitting JSON tool calls.  That makes the generated code itself the thing
worth governing — *before* it runs.  This adapter plugs constitutional
governance into the three stable smolagents extension points:

* **the executor** — :class:`GovernedPythonExecutor` wraps any smolagents
  ``PythonExecutor`` and validates each code action *before* delegating, so a
  blocked snippet raises and never executes.  This pre-execution gate is a hard
  gate: it blocks on any blocking violation **regardless** of the governor's
  ``strict`` flag (``strict`` governs the advisory output hooks below, not
  whether dangerous code is allowed to run).
* **final-answer checks** — a callable (``(answer, memory) -> bool``) that
  rejects a final answer violating the constitution, letting the agent retry.
* **step callbacks** — a callable invoked after each step that records the
  step's code/output to the tamper-evident audit log (non-blocking).

:class:`SmolagentsGovernor` owns one :class:`~acgs_lite.engine.GovernanceEngine`
(plus an :class:`~acgs_lite.audit.AuditLog`) and produces all three hooks, so a
single constitution governs the whole run.  Pre-execution code checks use the
AST-based :class:`~acgs_lite.engine.code_analysis.CodeActionValidator` in
addition to the constitution's string rules.

``smolagents`` is **not** imported at module load: availability is probed with
:func:`importlib.util.find_spec`, and the governor and executor are duck-typed
and work in tests without it installed.  Only :func:`build_governed_code_agent`
imports the package (lazily, at call time).

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

import importlib.util
import json
import logging
from collections.abc import Callable
from typing import Any

from acgs_lite.constitution import Constitution
from acgs_lite.engine.code_analysis import CodeActionValidator
from acgs_lite.engine.types import ValidationResult
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.integrations.base import GovernedBase

logger = logging.getLogger(__name__)

# L1/CK-001: probe availability without importing the optional SDK at load time.
SMOLAGENTS_AVAILABLE = importlib.util.find_spec("smolagents") is not None

# Context flag that routes a validate() call through the AST code validator.
_CODE_CONTEXT: dict[str, str] = {"action_type": "code"}

# Audit-identity labels appended to ``agent_id`` per seam, so one logical agent
# correlates across the executor and step/final-answer hooks (M8).
_LABEL_CODE = "code"  # code actions: executor gate AND step code
_LABEL_FINAL = "final"  # final-answer checks
_LABEL_OUTPUT = "output"  # step observations / tool output

# Keyword names through which a smolagents executor may receive a code action.
_CODE_KWARGS: tuple[str, ...] = ("code", "code_action", "source")

# Code-carrier types the gate must recognise. ``_gate`` decodes every bytes-like
# form (bytes/bytearray/memoryview); recognising fewer here than ``_gate`` accepts
# would let a forwarded call slip an unrecognised carrier past the gate ungoverned.
_CODE_CARRIER_TYPES: tuple[type, ...] = (str, bytes, bytearray, memoryview)


def _extract_code_arg(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> str | bytes | bytearray | memoryview | None:
    """Return the code action of an executor call, if the call carries one.

    A smolagents executor receives the code action as a positional argument (or,
    defensively, via a ``code``/``code_action``/``source`` keyword).  A call with
    no code-carrier argument is not code execution (``send_variables(dict)``,
    ``send_tools(list)``) and is delegated unchanged.

    Recognises every bytes-like carrier ``_gate`` can decode — str, bytes,
    bytearray, memoryview — so a forwarded call cannot smuggle one past the gate
    (a ``bytearray`` once returned ``None`` here while ``_gate`` happily decoded
    it, a fail-open bypass of the executor gate). Scans *all* positional args, not
    just the first, so a code action passed positionally behind a leading non-code
    argument is still gated.
    """
    for value in args:
        if isinstance(value, _CODE_CARRIER_TYPES):
            return value
    for key in _CODE_KWARGS:
        value = kwargs.get(key)
        if isinstance(value, _CODE_CARRIER_TYPES):
            return value
    return None


def _coerce_answer_text(value: Any) -> str:
    """Deterministically render *value* to text for governance matching.

    Strings pass through.  Mappings/sequences are JSON-serialised (sorted, with
    a ``str`` fallback) so their *content* is visible to substring/regex rules
    rather than an opaque ``repr`` (L9).  ``ensure_ascii=False`` keeps non-ASCII
    content readable at the same fidelity as a plain string — with the default
    ``ensure_ascii=True`` a forbidden non-ASCII keyword inside a structured answer
    (``{"plan": "go to the café now"}`` -> ``café``) would be escaped past
    substring matching and evade the check.  Any object whose ``__str__`` raises
    falls back to ``repr`` and finally to ``""`` so coercion never raises (M5).
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(value, default=str, sort_keys=True, ensure_ascii=False)
        except Exception:  # noqa: BLE001 - best-effort; fall through to str()
            pass
    try:
        return str(value)
    except Exception:  # noqa: BLE001
        try:
            return repr(value)
        except Exception:  # noqa: BLE001
            return ""


class GovernedPythonExecutor:
    """Constitutional wrapper around a smolagents ``PythonExecutor``.

    Intercepts the executor call to validate the code action first; a blocking
    violation raises :class:`~acgs_lite.errors.ConstitutionalViolationError` and
    the code never runs.  The gate is **independent of governor strictness** — a
    pre-execution code gate that could be downgraded to audit-only by a
    constructor flag would defeat the purpose (H1).

    Forwarding is fail-closed: any callable the wrapped executor exposes is
    gated when it is called with a code action (a str/bytes argument), so an
    execution entry point not known by name — the real smolagents
    ``run_code_raise_errors``, ``run_async``, or a future method — still
    validates before running.  Non-code attributes and calls (``send_tools``,
    ``send_variables(dict)``, ``state`` …) are delegated unchanged (M6).
    """

    def __init__(self, inner: Any, governor: SmolagentsGovernor) -> None:
        self._inner = inner
        self._gov = governor

    def _gate(self, code_action: Any) -> None:
        """Validate *code_action* and raise if it must not run.

        Forces a strict check so the gate blocks regardless of the governor's
        engine strictness, and re-raises defensively if any path were ever to
        return an invalid result instead of raising.

        Non-string actions are normalised here so the analyzer's fail-closed
        guarantee is realised at the live gate, not just in ``analyze()``: every
        bytes-like carrier (bytes/bytearray/memoryview) is decoded, and any other
        non-string type is blocked outright. Without this the engine would crash
        on ``action[:500]`` / ``action.lower()`` before the AST validator's
        ``CODE-UNANALYZABLE`` guard could run. The accepted bytes-like set must
        stay in sync with ``_extract_code_arg`` so the forwarded path and this
        gate never disagree on what counts as a code carrier.
        """
        if not isinstance(code_action, str):
            if isinstance(code_action, (bytes, bytearray, memoryview)):
                code_action = bytes(code_action).decode("utf-8", "replace")
            else:
                raise ConstitutionalViolationError(
                    "Code action blocked before execution: non-string code action of "
                    f"type {type(code_action).__name__} cannot be analyzed",
                    rule_id="CODE-UNANALYZABLE",
                    severity="high",
                )
        result = self._gov.validate_code(code_action, strict=True)
        if result is not None and not result.valid:  # defense in depth
            first = result.violations[0] if result.violations else None
            raise ConstitutionalViolationError(
                f"Code action blocked before execution: {first.rule_id if first else 'blocked'}",
                rule_id=first.rule_id if first else "CODE-BLOCKED",
                severity=first.severity.value if first else "high",
            )

    def __call__(self, code_action: str, *args: Any, **kwargs: Any) -> Any:
        # Raises if the code is blocked; records an audit entry either way.
        self._gate(code_action)
        return self._inner(code_action, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        # Only reached for attributes not set on this wrapper.
        if name in ("_inner", "_gov"):
            raise AttributeError(name)
        attr = getattr(self._inner, name)
        # Fail-closed forwarding: gate *any* callable the inner executor exposes
        # when it is invoked with a code action (a str/bytes argument), so an
        # execution entry point we don't know by name — the real smolagents
        # ``run_code_raise_errors``, ``run_async``, a future method — cannot run
        # code ungoverned.  Dunder lookups and non-code calls
        # (``send_variables(dict)``, ``state``) are delegated unchanged (M6).
        if callable(attr) and not name.startswith("__"):
            gate = self._gate

            def _governed(*args: Any, **kwargs: Any) -> Any:
                code = _extract_code_arg(args, kwargs)
                if code is not None:
                    gate(code)
                return attr(*args, **kwargs)

            return _governed
        return attr


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
        else:
            # L7: make the reduced-governance posture observable, not silent.
            logger.warning(
                "SmolagentsGovernor(analyze_code=False): AST code analysis is OFF; "
                "code actions are governed by constitution string rules only."
            )

    # -- core validation ----------------------------------------------------

    def validate_code(self, code: str, *, strict: bool | None = None) -> ValidationResult:
        """Validate a code action (constitution + AST rules) and audit it.

        A blocking violation raises
        :class:`~acgs_lite.errors.ConstitutionalViolationError`.  Callers that
        need an unconditional gate (the executor) pass ``strict=True``; the
        default ``None`` defers to the engine's instance strictness.
        """
        return self.engine.validate(
            code,
            agent_id=f"{self.agent_id}:{_LABEL_CODE}",
            context=dict(_CODE_CONTEXT),
            strict=strict,
        )

    # -- smolagents hooks ---------------------------------------------------

    def python_executor(self, inner: Any) -> GovernedPythonExecutor:
        """Wrap a smolagents ``PythonExecutor`` with pre-execution governance."""
        return GovernedPythonExecutor(inner, self)

    def final_answer_check(self) -> Callable[..., bool]:
        """Return a smolagents ``final_answer_checks`` callable.

        Returns ``True`` to accept the answer and ``False`` to reject it
        (smolagents then continues the loop).  **Never raises** (M1/M5): a HALT
        rule that the engine would raise on is suppressed by
        :meth:`_validate_nonstrict` and treated as a rejection here.  Any
        blocking violation also yields ``False`` so a violating answer is not
        silently accepted (L10).
        """

        def _check(final_answer: Any, memory: Any = None) -> bool:  # noqa: ARG001
            # A genuinely empty answer (None / "") has no content to govern.
            if final_answer is None or (isinstance(final_answer, str) and not final_answer):
                return True
            text = _coerce_answer_text(final_answer)
            if not text:
                # A non-empty answer we could not render to text (e.g. __str__
                # and __repr__ both raise) cannot be proven safe -> reject
                # (fail-closed) rather than silently accept it (M5).
                return False
            result = self._validate_nonstrict(text, label=_LABEL_FINAL)
            if result is None:
                # Suppressed HALT on non-empty content -> reject, do not crash.
                return False
            return result.valid

        _check._acgs_governor = id(self)  # type: ignore[attr-defined]
        return _check

    def step_callback(self) -> Callable[..., None]:
        """Return a smolagents ``step_callbacks`` callable.

        Records each step's code action and observation to the audit log
        (non-blocking).  Step *code* is validated under the code context so the
        AST validator fires on it (L11); observations are validated as text.
        Accepts the one- or two-argument smolagents callback signature.
        """

        def _callback(memory_step: Any, agent: Any = None) -> None:  # noqa: ARG001
            code = _first_str_attr(memory_step, ("code_action", "tool_call", "action"))
            if code:
                self._validate_nonstrict(code, label=_LABEL_CODE, context=dict(_CODE_CONTEXT))
            observation = _first_str_attr(
                memory_step, ("observations", "observation", "action_output")
            )
            if observation:
                self._validate_nonstrict(observation, label=_LABEL_OUTPUT)

        _callback._acgs_governor = id(self)  # type: ignore[attr-defined]
        return _callback

    # -- convenience --------------------------------------------------------

    def wrap(self, agent: Any) -> Any:
        """Attach governance to an existing smolagents agent in place.

        Replaces ``agent.python_executor`` with a governed wrapper and appends
        the final-answer check and step callback.  Returns the same agent for
        chaining.  Idempotent: re-wrapping the same agent with the same governor
        neither double-wraps the executor nor re-appends duplicate hooks (L8).
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
        return {**self.governance_stats, "analyze_code": self.analyze_code}


def _first_str_attr(obj: Any, names: tuple[str, ...]) -> str | None:
    """Return the first non-empty string attribute among *names*, else ``None``."""
    for name in names:
        value = getattr(obj, name, None)
        if isinstance(value, str) and value:
            return value
    return None


def _append_hook(agent: Any, attr: str, hook: Any) -> None:
    """Append *hook* to a smolagents list/None hook attribute, idempotently.

    ``step_callbacks`` may be a list, ``None``, a tuple, or a dict keyed by step
    type.  Lists and ``None`` are handled directly; a tuple (or other sequence)
    is coerced to a list so governance is actually attached rather than silently
    dropped (M4).  A dict cannot be keyed without importing smolagents types, so
    we skip it and log.  Hooks tagged with the same governor id are not appended
    twice (L8).
    """
    existing = getattr(agent, attr, None)
    if existing is None:
        setattr(agent, attr, [hook])
        return
    if isinstance(existing, list):
        seq = existing
    elif isinstance(existing, tuple):
        seq = list(existing)
        setattr(agent, attr, seq)
    else:
        logger.warning(
            "Cannot attach governance to agent.%s of type %s; "
            "pass the hook explicitly when constructing the agent.",
            attr,
            type(existing).__name__,
        )
        return
    marker = getattr(hook, "_acgs_governor", None)
    if marker is not None and any(getattr(h, "_acgs_governor", None) == marker for h in seq):
        return  # already governed by this governor; do not double-append
    seq.append(hook)


def build_governed_code_agent(
    *,
    constitution: Constitution | None = None,
    agent_id: str = "smolagents-agent",
    strict: bool = True,
    analyze_code: bool = True,
    code_validator: CodeActionValidator | None = None,
    **code_agent_kwargs: Any,
) -> tuple[Any, SmolagentsGovernor]:
    """Construct a smolagents ``CodeAgent`` with governance attached.

    Requires ``smolagents`` (``pip install acgs-lite[smolagents]``).  Pass
    *code_validator* to tune the AST allowlist (authorized/critical imports,
    dangerous calls) — without it the governor's default analyzer is used (L6).
    Remaining keyword arguments are forwarded to ``CodeAgent`` (``tools``,
    ``model``, …).  Returns ``(agent, governor)``.
    """
    if not SMOLAGENTS_AVAILABLE:
        raise ImportError("smolagents is required. Install with: pip install acgs-lite[smolagents]")
    from smolagents import CodeAgent  # noqa: PLC0415

    governor = SmolagentsGovernor(
        constitution=constitution,
        agent_id=agent_id,
        strict=strict,
        analyze_code=analyze_code,
        code_validator=code_validator,
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
