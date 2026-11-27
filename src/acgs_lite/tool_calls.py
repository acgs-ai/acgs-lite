# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""
Framework-neutral evaluation of a single tool call against an ACGS constitution.

This module turns one tool call into a text representation, validates that text with
``GovernanceEngine.validate``, and maps the result to one of three verdicts
(``ALLOW``, ``DENY``, ``REVIEW``) that framework adapters translate into native decisions.

The evaluation never raises: any error is converted into a ``DENY`` verdict.

Usage::

    from acgs_lite.tool_calls import ToolCallGovernor, Verdict

    governor = ToolCallGovernor(constitution, agent_id="my-agent")
    decision = governor.evaluate("send_email", {"to": "a@example.com"})
    if decision.verdict is not Verdict.ALLOW:
        ...  # refuse the call, or ask a human when the verdict is REVIEW
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from acgs_lite.constitution import Constitution, Rule
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.engine import GovernanceEngine, ValidationResult
from acgs_lite.errors import ConstitutionalViolationError

__all__ = [
    "MAX_ARGUMENT_DEPTH",
    "GovernanceDecision",
    "ToolCallFormatter",
    "ToolCallGovernor",
    "Verdict",
    "format_tool_call",
]

logger = logging.getLogger(__name__)

ToolCallFormatter = Callable[[str, Any], str]
"""Signature of a function that renders ``(tool_name, arguments)`` as the text ACGS validates."""

MAX_ARGUMENT_DEPTH = 32
"""Nesting depth above which a tool call is rejected instead of being partially rendered."""

_REVIEW_ACTIONS = frozenset({ViolationAction.REQUIRE_HUMAN_REVIEW, ViolationAction.ESCALATE})

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SEPARATORS = re.compile(r"[\s_\-./:\[\]]+")
# Matches the same strings as the adapters' original pattern
# ``^[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+|[A-Z][a-z0-9]+)+$``, whose repeated
# alternation backtracked exponentially. Here the two branches cannot overlap.
_IDENTIFIER_VALUE = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:(?:[_-][A-Za-z0-9]+)+|[A-Z][a-z0-9]+)$")
_MAX_IDENTIFIER_VALUE_LENGTH = 64


class Verdict(str, Enum):  # noqa: UP042  # StrEnum needs Python 3.11, and changes str() output
    """Outcome of evaluating one tool call."""

    ALLOW = "allow"
    """No blocking rule matched. Warnings may still have been recorded."""

    DENY = "deny"
    """A blocking rule matched, or governance could not be evaluated."""

    REVIEW = "review"
    """Only review/escalation rules matched. A human must approve the call."""


@dataclass(frozen=True)
class GovernanceDecision:
    """
    Result of evaluating one tool call.

    :param verdict: The verdict the adapter maps to a native framework decision.
    :param tool_name: Name of the evaluated tool.
    :param reason: Human-readable explanation. It names matched rules but never includes argument values.
        For ``DENY`` it starts with ``Blocked by`` followed by the blocking rules only.
    :param rule_ids: IDs of the blocking or review rules that matched, in match order.
    :param warning_rule_ids: IDs of non-blocking (warn) rules that matched.
    :param error: Set when the verdict is ``DENY`` because evaluation itself failed.
    """

    verdict: Verdict
    tool_name: str
    reason: str
    rule_ids: tuple[str, ...] = ()
    warning_rule_ids: tuple[str, ...] = ()
    error: str | None = None


def _humanize(identifier: str) -> str:
    """Split an identifier such as ``skip_audit`` or ``disableLogging`` into lower-case words."""
    spaced = _CAMEL_BOUNDARY.sub(" ", identifier)
    return " ".join(_SEPARATORS.sub(" ", spaced).split()).lower()


def _render_scalar(value: Any) -> str:
    """Render a leaf value on a single line."""
    if isinstance(value, str):
        return " ".join(value.split())
    if value is None or isinstance(value, bool | int | float):
        return json.dumps(value)
    return " ".join(str(value).split())


def _flatten(value: Any, path: str, depth: int) -> Iterator[tuple[str, Any]]:
    """Yield ``(dotted_path, leaf_value)`` pairs for nested mappings and sequences."""
    if depth > MAX_ARGUMENT_DEPTH:
        msg = f"Tool call arguments are nested deeper than {MAX_ARGUMENT_DEPTH} levels."
        raise ValueError(msg)
    if isinstance(value, Mapping):
        if not value:
            yield path, "{}"
            return
        for key in sorted(value, key=str):
            child = f"{path}.{key}" if path else str(key)
            yield from _flatten(value[key], child, depth + 1)
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if not value:
            yield path, "[]"
            return
        for index, item in enumerate(value):
            yield from _flatten(item, f"{path}[{index}]", depth + 1)
    else:
        yield path, value


def format_tool_call(tool_name: str, arguments: Any) -> str:
    r"""
    Render a tool call as the text that ACGS keyword and pattern rules are matched against.

    The output has one ``path: value`` line per argument leaf, so argument names and values are
    both visible to rules, and multi-line values are collapsed onto one line. Identifiers
    (the tool name, argument names and single-token string values) that contain separators or
    camelCase are repeated in a trailing ``normalized:`` line as plain words, so that a rule
    keyword such as ``skip audit`` also matches a tool named ``skip_audit``.

    Example::

        >>> print(format_tool_call("send_email", {"to": "a@example.com", "body": "Hi\nthere"}))
        tool: send_email
        arguments:
        body: Hi there
        to: a@example.com
        normalized: send email

    :param tool_name: Name of the tool the model wants to call.
    :param arguments: The tool arguments, usually a mapping. Other values are rendered as ``input``.
    :returns: The text passed to ``GovernanceEngine.validate``.
    :raises ValueError: If the arguments are nested deeper than ``MAX_ARGUMENT_DEPTH``.
    """
    lines = [f"tool: {tool_name}", "arguments:"]
    identifiers = [tool_name]
    leaves = list(_flatten(arguments, "" if isinstance(arguments, Mapping) else "input", 0))
    if isinstance(arguments, Mapping) and not arguments:
        leaves = []
    if not leaves:
        lines.append("(none)")
    for path, leaf in leaves:
        rendered = _render_scalar(leaf)
        lines.append(f"{path}: {rendered}")
        identifiers.append(path)
        if (
            isinstance(leaf, str)
            and len(rendered) <= _MAX_IDENTIFIER_VALUE_LENGTH
            and _IDENTIFIER_VALUE.match(rendered)
        ):
            identifiers.append(rendered)
    normalized: list[str] = []
    for identifier in identifiers:
        words = _humanize(identifier)
        if words and words != identifier.lower() and words not in normalized:
            normalized.append(words)
    if normalized:
        lines.append("normalized: " + " | ".join(normalized))
    return "\n".join(lines)


class ToolCallGovernor:
    """
    Evaluate tool calls against an ACGS constitution and return a ``GovernanceDecision``.

    Verdict mapping, applied to the blocking violations of the validation result:

    - no violations: ``ALLOW`` (matched warn-only rules are reported in ``warning_rule_ids``);
    - every violation comes from a rule whose workflow action is ``require_human_review`` or
      ``escalate_to_senior``: ``REVIEW``;
    - anything else (``block``, ``block_and_notify``, ``halt_and_alert``, a rule ID that is not in
      the constitution, an unknown action, or an invalid result without violations): ``DENY``.

    A blocking rule is never downgraded to ``REVIEW`` because a review rule matched as well. In
    that case the reason names only the blocking rules after ``Blocked by`` and lists the matched
    review rules separately; ``rule_ids`` still contains every matched rule in match order.
    Any exception raised while formatting or validating also yields ``DENY``.
    """

    def __init__(
        self,
        constitution: Constitution | None = None,
        *,
        agent_id: str,
        tool_call_formatter: ToolCallFormatter | None = None,
    ) -> None:
        """
        Create a governor.

        :param constitution: The constitution to enforce. Defaults to ``Constitution.default()``.
        :param agent_id: Agent identifier passed to ``GovernanceEngine.validate``.
        :param tool_call_formatter: Optional replacement for ``format_tool_call``.
        """
        self.constitution = constitution if constitution is not None else Constitution.default()
        self.agent_id = agent_id
        self.tool_call_formatter = tool_call_formatter
        self._engine = GovernanceEngine(self.constitution, strict=False)
        self._rules: dict[str, Rule] = {rule.id: rule for rule in self.constitution.rules}

    def evaluate(self, tool_name: str, arguments: Any) -> GovernanceDecision:
        """
        Evaluate one tool call. Never raises.

        :param tool_name: Name of the tool the model wants to call.
        :param arguments: The tool arguments.
        :returns: The governance decision.
        """
        try:
            formatter = self.tool_call_formatter or format_tool_call
            action = formatter(tool_name, arguments)
            if not isinstance(action, str) or not action.strip():
                msg = "The tool call formatter must return a non-empty string."
                raise TypeError(msg)
            result = self._engine.validate(action, agent_id=self.agent_id, strict=False)
            decision = self._decide(tool_name, result)
        except ConstitutionalViolationError as error:
            rule_id = error.rule_id or "unknown"
            decision = GovernanceDecision(
                verdict=Verdict.DENY,
                tool_name=tool_name,
                reason=f"ACGS rule {rule_id} halted the call.",
                rule_ids=(rule_id,),
            )
        except Exception as error:
            logger.warning(
                "ACGS governance failed for tool '%s'; denying the call (fail-closed).",
                tool_name,
                exc_info=True,
            )
            decision = GovernanceDecision(
                verdict=Verdict.DENY,
                tool_name=tool_name,
                reason="ACGS governance could not evaluate this tool call, so it was denied.",
                error=f"{type(error).__name__}: {error}",
            )
        self._log(decision)
        return decision

    def _workflow_action(self, rule_id: str) -> ViolationAction | None:
        rule = self._rules.get(rule_id)
        if rule is None:
            return None
        if rule.workflow_action is not None:
            return rule.workflow_action
        return (
            ViolationAction.BLOCK if rule.severity.blocks() else ViolationAction.WARN
        )  # pragma: no cover

    def _decide(self, tool_name: str, result: ValidationResult) -> GovernanceDecision:
        warnings = tuple(dict.fromkeys(w.rule_id for w in result.warnings))
        rule_ids = tuple(dict.fromkeys(v.rule_id for v in result.violations))
        if not rule_ids:
            if result.valid:
                return GovernanceDecision(
                    verdict=Verdict.ALLOW,
                    tool_name=tool_name,
                    reason="No blocking ACGS rule matched.",
                    warning_rule_ids=warnings,
                )
            return GovernanceDecision(
                verdict=Verdict.DENY,
                tool_name=tool_name,
                reason="ACGS reported the call as invalid without naming a rule.",
                warning_rule_ids=warnings,
            )
        review_ids = tuple(
            rule_id for rule_id in rule_ids if self._workflow_action(rule_id) in _REVIEW_ACTIONS
        )
        blocking_ids = tuple(rule_id for rule_id in rule_ids if rule_id not in review_ids)
        if not blocking_ids:
            return GovernanceDecision(
                verdict=Verdict.REVIEW,
                tool_name=tool_name,
                reason=f"Human review required by {self._describe(review_ids)}.",
                rule_ids=rule_ids,
                warning_rule_ids=warnings,
            )
        reason = f"Blocked by {self._describe(blocking_ids)}."
        if review_ids:
            reason += f" Review rules that also matched: {self._describe(review_ids)}."
        return GovernanceDecision(
            verdict=Verdict.DENY,
            tool_name=tool_name,
            reason=reason,
            rule_ids=rule_ids,
            warning_rule_ids=warnings,
        )

    def _describe(self, rule_ids: Sequence[str]) -> str:
        """Join ``ACGS rule <id> (<text>)`` descriptions for ``rule_ids``; unknown IDs have no text."""
        parts = []
        for rule_id in rule_ids:
            rule = self._rules.get(rule_id)
            parts.append(
                f"ACGS rule {rule_id}" if rule is None else f"ACGS rule {rule_id} ({rule.text})"
            )
        return "; ".join(parts)

    @staticmethod
    def _log(decision: GovernanceDecision) -> None:
        if decision.verdict is Verdict.ALLOW:
            logger.debug("ACGS allowed tool '%s'.", decision.tool_name)
        elif decision.verdict is Verdict.REVIEW:
            logger.info(
                "ACGS requires review for tool '%s': %s", decision.tool_name, decision.rule_ids
            )
        else:
            logger.info(
                "ACGS denied tool '%s': %s", decision.tool_name, decision.rule_ids or decision.error
            )
