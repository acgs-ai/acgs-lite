"""Map acgs-lite's 8-state decision taxonomy onto gove-zone's 4 kernel verdicts.

Lossless in combination with DecisionRecord.reason: adapters prefix the
original state as ``acgs-lite:<STATE>:`` so replay/audit can recover it.
"""

from __future__ import annotations

from gove_zone.decision import Decision

REASON_PREFIX = "acgs-lite:"

_STATE_TO_DECISION: dict[str, Decision] = {
    "ALLOW": Decision.ALLOW,
    "ALLOW_WITH_CONTROLS": Decision.ALLOW,
    "TRANSFORM_REQUIRED": Decision.TRANSFORM,
    "STRUCTURED_REVIEW_REQUIRED": Decision.ESCALATE,
    "REPLAN_REQUIRED": Decision.DENY,
    "DENY_OPERATION_WITH_ALTERNATIVE": Decision.DENY,
    "DENY_GOAL": Decision.DENY,
    "HARD_DENY": Decision.DENY,
}


def decision_state_to_gove(state: str) -> Decision:
    """Return the kernel verdict for an acgs-lite DecisionState.

    Raises ValueError for unknown states so callers fail closed rather
    than silently allowing.
    """
    try:
        return _STATE_TO_DECISION[state]
    except KeyError:
        raise ValueError(f"unknown DecisionState: {state!r}") from None
