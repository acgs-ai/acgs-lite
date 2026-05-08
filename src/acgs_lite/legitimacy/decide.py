"""Canonical legitimacy decision taxonomy and migration helpers."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

DecisionState = Literal[
    "ALLOW",
    "ALLOW_WITH_CONTROLS",
    "TRANSFORM_REQUIRED",
    "REPLAN_REQUIRED",
    "STRUCTURED_REVIEW_REQUIRED",
    "DENY_OPERATION_WITH_ALTERNATIVE",
    "DENY_GOAL",
    "HARD_DENY",
]

CANONICAL_DECISION_STATES: frozenset[str] = frozenset(
    (
        "ALLOW",
        "ALLOW_WITH_CONTROLS",
        "TRANSFORM_REQUIRED",
        "REPLAN_REQUIRED",
        "STRUCTURED_REVIEW_REQUIRED",
        "DENY_OPERATION_WITH_ALTERNATIVE",
        "DENY_GOAL",
        "HARD_DENY",
    )
)

_LEGACY_STATE_MAP: dict[str, str] = {
    "allow": "ALLOW",
    "audit_only": "ALLOW_WITH_CONTROLS",
    "conditional": "ALLOW_WITH_CONTROLS",
    "require_review": "STRUCTURED_REVIEW_REQUIRED",
    "review": "STRUCTURED_REVIEW_REQUIRED",
    "escalate": "STRUCTURED_REVIEW_REQUIRED",
    "deny": "DENY_GOAL",
    "block": "DENY_GOAL",
    "blocked": "DENY_GOAL",
    "reject": "DENY_GOAL",
    "rejected": "DENY_GOAL",
    "kill_switch": "HARD_DENY",
    "circuit_breaker": "HARD_DENY",
    "hard_deny": "HARD_DENY",
}


def canonicalize_decision_state(
    state: Any,
    *,
    critical: bool = False,
    kill_switch: bool = False,
) -> DecisionState:
    """Return an uppercase canonical decision state or raise on unknown input."""
    raw = str(state.value) if isinstance(state, Enum) else str(state)
    normalized = raw.strip()
    if normalized in CANONICAL_DECISION_STATES:
        return normalized  # type: ignore[return-value]

    mapped = _LEGACY_STATE_MAP.get(normalized.lower())
    if mapped is None:
        raise ValueError(f"Unknown decision state: {raw!r}")
    if kill_switch:
        return "HARD_DENY"
    if critical and mapped == "DENY_GOAL":
        return "DENY_GOAL"
    return mapped  # type: ignore[return-value]


def is_allow_state(state: Any) -> bool:
    """True only for the canonical unconditional allow state."""
    try:
        return canonicalize_decision_state(state) == "ALLOW"
    except ValueError:
        return False


__all__ = [
    "CANONICAL_DECISION_STATES",
    "DecisionState",
    "canonicalize_decision_state",
    "is_allow_state",
]
