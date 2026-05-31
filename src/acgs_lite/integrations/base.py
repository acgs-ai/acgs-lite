"""GovernedBase mixin — shared governance setup for integration wrappers.

Eliminates ~200 lines of duplicated init, stats, and non-strict validation
boilerplate across CrewAI, DSPy, Haystack, Pydantic AI, and other governed
wrapper classes.

No framework-specific imports live here.  Only ``acgs_lite.constitution``,
``acgs_lite.engine``, and ``acgs_lite.audit`` are used.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import logging
from typing import Any

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.engine import GovernanceEngine
from acgs_lite.engine.types import ValidationResult
from acgs_lite.errors import ConstitutionalViolationError

logger = logging.getLogger(__name__)

# Keyword names under which agent/task execution entry points commonly receive
# the prompt to run. Mirrors smolagents' positional-first code extraction, but
# for natural-language task strings rather than code actions.
_FORWARD_PROMPT_KWARGS = (
    "task",
    "prompt",
    "query",
    "message",
    "messages",
    "input",
    "text",
    "description",
    "instruction",
    "goal",
)


def _coerce_prompt(value: Any) -> str | None:
    """Return *value* as text if it is a task/prompt carrier, else ``None``.

    Recognises ``str`` and every bytes-like form (bytes/bytearray/memoryview),
    decoding the latter so a task smuggled as bytes cannot slip past the
    forwarded gate ungoverned. Non-text payloads (dicts, numbers, tools) are not
    agent actions and return ``None``.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", "replace")
    return None


def _extract_forwarded_prompts(args: tuple[Any, ...], kwargs: dict[str, Any]) -> list[str]:
    """Return *every* task/prompt carried by a forwarded execution call.

    Agent execution entry points take the task as a positional argument (or via a
    ``task``/``prompt``/``query``/… keyword). A call carrying no text payload is
    configuration, not an agent action (``set_temperature(0.5)``,
    ``add_tool(tool)``, ``run(data={...})``), and is forwarded unchanged so the
    fail-closed gate governs execution without blocking benign setup.

    Returns *all* text carriers, not just the first, and decodes bytes-like
    carriers: a task passed behind a leading non-text/benign argument
    (``run(session_id, task)``) or smuggled as bytes must still be validated —
    otherwise the leading argument is validated, passes, and the trailing task is
    forwarded to the underlying agent ungoverned (a fail-open bypass).
    """
    prompts: list[str] = []
    for value in args:
        text = _coerce_prompt(value)
        if text is not None:
            prompts.append(text)
    for key in _FORWARD_PROMPT_KWARGS:
        text = _coerce_prompt(kwargs.get(key))
        if text is not None:
            prompts.append(text)
    return prompts


class GovernedBase:
    """Mixin providing common governance plumbing for integration wrappers.

    Subclasses call :meth:`_init_governance` in their ``__init__`` to set up
    the standard ``constitution``, ``audit_log``, ``engine``, and ``agent_id``
    attributes.  They can then use :attr:`governance_stats` and
    :meth:`_validate_nonstrict` to avoid repeating the same patterns.
    """

    # These are set by _init_governance; declared here for type checkers.
    constitution: Constitution
    audit_log: AuditLog
    engine: GovernanceEngine
    agent_id: str

    def _init_governance(
        self,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "governed",
        strict: bool = True,
    ) -> None:
        """Initialise the governance attributes shared by every wrapper.

        Parameters
        ----------
        constitution:
            Constitution to validate against.  Defaults to
            ``Constitution.default()``.
        agent_id:
            Identifier for this governed entity in audit entries.
        strict:
            Whether to raise on violation (``True``) or just warn
            (``False``).
        """
        self.constitution = constitution or Constitution.default()
        self.audit_log = AuditLog()
        self.engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict,
        )
        self.agent_id = agent_id

    @property
    def governance_stats(self) -> dict[str, Any]:
        """Return the standard governance statistics dict."""
        return {
            **self.engine.stats,
            "agent_id": self.agent_id,
            "audit_chain_valid": self.audit_log.verify_chain(),
        }

    def _validate_forwarded(self, text: str) -> None:
        """Validate a forwarded execution call's task/prompt.

        Honors the adapter's strictness exactly like the primary governed path
        (``run``/``kickoff``/…): a blocking violation under strict raises
        :class:`ConstitutionalViolationError`; under ``strict=False`` it is
        audit-only. This keeps un-overridden execution methods at parity with the
        methods the wrapper governs explicitly.
        """
        self.engine.validate(text, agent_id=self.agent_id)

    def _govern_forwarded_attr(self, name: str, inner: Any) -> Any:
        """Fail-closed forwarding for a delegated wrapper attribute.

        Wrapper adapters delegate unknown attributes to the wrapped object via
        ``__getattr__``. Without a guard, an execution entry point the wrapper
        does not override by name (``arun``, ``akickoff``, ``stream``,
        ``run_batched``, or a future method) would run the agent on an
        *ungoverned* task — a fail-open bypass of the governance the wrapper
        exists to enforce.

        This returns *inner* unchanged unless it is a non-dunder **callable**, in
        which case it is wrapped so a task/prompt string passed to it is validated
        (see :meth:`_validate_forwarded`) before the underlying call runs. Calls
        carrying no string payload (config setters, dict/list inputs) and dunder
        lookups are forwarded unchanged.

        Adapters call this from ``__getattr__`` after resolving the attribute, and
        must guard their inner-object attribute name to avoid recursion, e.g.::

            def __getattr__(self, name):
                if name == "_agent":
                    raise AttributeError(name)
                return self._govern_forwarded_attr(name, getattr(self._agent, name))
        """
        if not callable(inner) or name.startswith("__"):
            return inner
        validate = self._validate_forwarded

        def _governed(*args: Any, **kwargs: Any) -> Any:
            # Gate EVERY task carrier (not just the first): a benign leading
            # argument must not shadow a dangerous task in a later argument.
            for prompt in _extract_forwarded_prompts(args, kwargs):
                if prompt:
                    validate(prompt)
            return inner(*args, **kwargs)

        return _governed

    def _validate_nonstrict(
        self,
        text: str,
        *,
        label: str = "output",
        context: dict[str, Any] | None = None,
    ) -> ValidationResult | None:
        """Validate *text* non-strictly and log warnings on violation.

        Returns the :class:`ValidationResult` when validation ran, or
        ``None`` when *text* was empty/falsy and validation was skipped, or when
        the engine raised on an absolute-HALT rule (see below).

        Non-blocking contract: this helper must **never** raise.  ``strict=False``
        suppresses ordinary blocking violations, but the engine still raises
        :class:`ConstitutionalViolationError` for ``HALT`` rules regardless of
        strictness (HALT is absolute at the engine layer).  Integration hooks
        that document themselves as non-blocking rely on this method swallowing
        that exception — so we catch it, log, and return ``None`` rather than let
        a HALT rule tear down a caller's loop.

        *context* is forwarded to :meth:`GovernanceEngine.validate` so callers can
        opt produced content into context-gated validators (e.g. pass
        ``{"action_type": "code"}`` to run the AST code validator on step code).
        """
        if not text:
            return None
        try:
            result = self.engine.validate(
                text,
                agent_id=f"{self.agent_id}:{label}",
                context=context,
                strict=False,
            )
        except ConstitutionalViolationError as exc:
            logger.warning(
                "%s governance HALT (suppressed; non-blocking hook): rule=%s",
                label,
                exc.rule_id,
            )
            return None
        if not result.valid:
            logger.warning(
                "%s governance violations: %s",
                label,
                [v.rule_id for v in result.violations],
            )
        return result
