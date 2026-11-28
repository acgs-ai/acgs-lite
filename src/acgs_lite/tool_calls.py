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
from acgs_lite.engine.core import normalize_for_matching
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
# Matches identifier-style string tokens of any length in linear time. Leading separators and
# the mandatory alphanumeric core are disjoint, so the pattern never backtracks; emails
# containing ``@`` are naturally excluded.
_IDENTIFIER_VALUE = re.compile(r"^[_\-./:\[\]]*[A-Za-z0-9][A-Za-z0-9_\-./:\[\]]*$")
# Control characters (Unicode category Cc) other than tab, newline and carriage return.
_HIDDEN_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
# Hidden controls that ``str.split()`` does not treat as whitespace.
_NON_SPACE_CONTROLS = re.compile(r"[\x00-\x08\x0e-\x1b\x7f-\x84\x86-\x9f]")
# Hidden controls that ``str.split()`` treats as whitespace.
_SPACE_CONTROLS = re.compile(r"[\x0b\x0c\x1c-\x1f\x85]")


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


def _extra_hidden_readings(value: Any, rendered: str) -> list[str]:
    """
    Return alternate single-line readings of ``value`` when hidden controls alter it.

    ``_render_scalar`` collapses whitespace with ``str.split``, which also treats control
    characters such as vertical tab, form feed and the ``\\x1c``-``\\x1f`` separators as
    whitespace. The engine does not: it drops them before matching. Collapsing first therefore
    turns ``del<VT>ete`` into ``del ete`` and hides keywords. Values containing more than one
    whitespace control character are rejected fail-closed because each control could be either a
    word boundary or intra-word padding; otherwise alternate readings with controls dropped or
    turned into spaces are returned when they differ from what the engine sees in ``rendered``.
    """
    if value is None or isinstance(value, bool | int | float):
        return []
    text = value if isinstance(value, str) else str(value)
    if len(_SPACE_CONTROLS.findall(text)) > 1:
        msg = "A tool call contains more than one whitespace control character."
        raise ValueError(msg)
    engine_rendered = normalize_for_matching(rendered)
    candidates: list[str] = [normalize_for_matching(text)]
    if _HIDDEN_CONTROLS.search(text):
        candidates.extend(
            (
                normalize_for_matching(_NON_SPACE_CONTROLS.sub(" ", _SPACE_CONTROLS.sub("", text))),
                _HIDDEN_CONTROLS.sub(" ", text),
            )
        )
    readings: list[str] = []
    for candidate in candidates:
        reading = " ".join(candidate.split())
        if (
            reading != rendered
            and normalize_for_matching(reading) != engine_rendered
            and reading not in readings
        ):
            readings.append(reading)
    return readings


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
    both visible to rules, and multi-line values are collapsed onto one line. A tool name, argument
    key or argument value that contains hidden control characters is also rendered with them
    dropped and as spaces, so that they can neither split a word nor join two; values, names or
    keys with more than one whitespace control character raise ``ValueError``. Identifiers (the
    tool name, argument names, and identifier-style string tokens of any length, checked after
    hidden-character and NFKC normalization) that contain separators or camelCase are repeated in
    a trailing ``normalized:`` line as plain words, so that a rule keyword such as ``skip audit``
    also matches ``skip_audit``, ``skip__audit``, ``_skip_audit``, ``skip.audit``, or padded
    and obfuscated variants.

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
    :raises ValueError: If the arguments are nested deeper than ``MAX_ARGUMENT_DEPTH`` or the tool
        name, an argument key or a leaf value contains more than one whitespace control character.
    """
    rendered_tool = _render_scalar(tool_name)
    extra_tools = _extra_hidden_readings(tool_name, rendered_tool)
    tool_readings = (rendered_tool, *extra_tools)
    lines = [*(f"tool: {reading}" for reading in tool_readings), "arguments:"]
    identifiers = list(tool_readings)
    value_tokens: list[str] = []
    leaves = list(_flatten(arguments, "" if isinstance(arguments, Mapping) else "input", 0))
    if isinstance(arguments, Mapping) and not arguments:
        leaves = []
    if not leaves:
        lines.append("(none)")
    for path, leaf in leaves:
        rendered_path = _render_scalar(path)
        extra_paths = _extra_hidden_readings(path, rendered_path)
        path_readings = (rendered_path, *extra_paths)

        rendered_leaf = _render_scalar(leaf)
        extra_leaves = _extra_hidden_readings(leaf, rendered_leaf)
        leaf_readings = (rendered_leaf, *extra_leaves)

        for path_reading in path_readings:
            for leaf_reading in leaf_readings:
                lines.append(f"{path_reading}: {leaf_reading}")
        identifiers.extend(path_readings)
        if isinstance(leaf, str):
            id_candidates = (
                *leaf_readings,
                " ".join(normalize_for_matching(leaf).split()),
                " ".join(normalize_for_matching(rendered_leaf).split()),
            )
            for candidate in dict.fromkeys(id_candidates):
                for raw_token in candidate.split():
                    clean_token = normalize_for_matching(raw_token)
                    if clean_token and _IDENTIFIER_VALUE.match(clean_token):
                        value_tokens.append(clean_token)
    normalized: list[str] = []
    seen_normalized: set[str] = set()
    for identifier in identifiers:
        clean_identifier = normalize_for_matching(identifier)
        words = _humanize(clean_identifier)
        if words and words != clean_identifier.lower() and words not in seen_normalized:
            seen_normalized.add(words)
            normalized.append(words)
    for token in value_tokens:
        words = _humanize(token)
        if (
            words
            and words != token.lower()
            and (" " in words or "_" in token)
            and words not in seen_normalized
        ):
            seen_normalized.add(words)
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
        context: Mapping[str, Any] | None = None,
    ) -> None:
        """
        Create a governor.

        :param constitution: The constitution to enforce. Defaults to ``Constitution.default()``.
        :param agent_id: Agent identifier passed to ``GovernanceEngine.validate``.
        :param tool_call_formatter: Optional replacement for ``format_tool_call``.
        :param context: Optional trusted governance context forwarded to conditional rules.
            Never populate this from model-supplied tool arguments.
        :raises TypeError: If ``context`` is provided and is not a mapping.
        """
        if context is not None and not isinstance(context, Mapping):
            msg = "Governance context must be a mapping."
            raise TypeError(msg)
        self.constitution = constitution if constitution is not None else Constitution.default()
        self.agent_id = agent_id
        self.tool_call_formatter = tool_call_formatter
        self.context: dict[str, Any] = dict(context) if context is not None else {}
        self._engine = GovernanceEngine(self.constitution, strict=False)
        self._rules: dict[str, Rule] = {rule.id: rule for rule in self.constitution.rules}

    def evaluate(
        self,
        tool_name: str,
        arguments: Any,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> GovernanceDecision:
        """
        Evaluate one tool call. Never raises.

        :param tool_name: Name of the tool the model wants to call.
        :param arguments: The tool arguments.
        :param context: Optional per-call trusted governance context merged over the
            governor's default ``context``.
        :returns: The governance decision.
        """
        try:
            eval_context: dict[str, Any] | None
            if context is None:
                eval_context = dict(self.context) if self.context else None
            else:
                if not isinstance(context, Mapping):
                    msg = "Governance context must be a mapping."
                    raise TypeError(msg)
                eval_context = {**self.context, **context}
            formatter = self.tool_call_formatter or format_tool_call
            action = formatter(tool_name, arguments)
            if not isinstance(action, str) or not action.strip():
                msg = "The tool call formatter must return a non-empty string."
                raise TypeError(msg)
            result = self._engine.validate(
                action,
                agent_id=self.agent_id,
                context=eval_context,
                strict=False,
            )
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
