"""Run an acgs-lite GovernanceEngine as a gove-zone Policy.

The engine's keyword/regex constitution evaluates a deterministic
free-text projection of the structured ToolCall. Kernel-level argument
binding still comes from ``argument_hash`` over the structured args, so
the free-text projection is a policy input, not the integrity anchor.
"""

from __future__ import annotations

from typing import Any, Protocol

from gove_zone.decision import Decision, DecisionRecord, canonical_json, sha256_json
from gove_zone.policy import Policy, new_event_id
from gove_zone.tool import ToolCall


class ValidatorLike(Protocol):
    """The slice of GovernanceEngine this adapter needs (duck-typed)."""

    def validate(self, action: str, *, agent_id: str = ..., **kwargs: Any) -> Any: ...


class ConstitutionPolicy(Policy):
    def __init__(self, engine: ValidatorLike, *, version: str) -> None:
        if not version:
            raise ValueError("version must be a non-empty stable constitution identifier")
        self._engine = engine
        self._version = f"acgs-lite-constitution/{version}"

    @property
    def version(self) -> str:
        return self._version

    @staticmethod
    def _action_text(call: ToolCall) -> str:
        return f"{call.name} {canonical_json(dict(call.args))} {call.goal}".strip()

    def _record(self, call: ToolCall, *, argument_hash: str, **overrides: Any) -> DecisionRecord:
        base: dict[str, Any] = {
            "tool": call.name,
            "argument_hash": argument_hash,
            "policy_version": self.version,
            "event_id": new_event_id(),
            "goal": call.goal,
            "actor": call.actor,
            "path": call.path,
        }
        base.update(overrides)
        return DecisionRecord(**base)

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        try:
            argument_hash = sha256_json(dict(call.args))
        except Exception as exc:  # fail closed — unserializable args
            return self._record(
                call,
                argument_hash="unserializable-args",
                decision=Decision.DENY,
                reason=f"argument-serialization-error:{type(exc).__name__}",
            )
        try:
            result = self._engine.validate(
                self._action_text(call), agent_id=call.actor or "anonymous"
            )
        except Exception as exc:  # fail closed — incl. strict-mode
            # ConstitutionalViolationError (engine/core.py CK-002 raises
            # instead of returning valid=False in strict mode).
            return self._record(
                call,
                argument_hash=argument_hash,
                decision=Decision.DENY,
                reason=f"constitution-engine-error:{type(exc).__name__}",
            )
        if getattr(result, "valid", False):
            return self._record(
                call,
                argument_hash=argument_hash,
                decision=Decision.ALLOW,
                reason="constitution: no violations",
            )
        violations = list(getattr(result, "violations", []) or [])
        rule_ids = tuple(str(v.rule_id) for v in violations)
        first_text = str(violations[0].rule_text) if violations else "unspecified violation"
        return self._record(
            call,
            argument_hash=argument_hash,
            decision=Decision.DENY,
            matched_rules=rule_ids,
            reason=f"constitution violation: {first_text}",
        )
