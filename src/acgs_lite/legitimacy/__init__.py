"""Fail-closed legitimacy contracts for governed execution."""

from acgs_lite.legitimacy.decide import (
    CANONICAL_DECISION_STATES,
    DecisionState,
    canonicalize_decision_state,
    is_allow_state,
)
from acgs_lite.legitimacy.invariants import (
    ActualCall,
    LegitimacyInvariantError,
    call_matches,
    normalize_actual_call,
    route_ambiguous_decision,
    validate_receipt_for_execution,
)
from acgs_lite.legitimacy.receipt import (
    BASELINE_CONSTRAINT_MARKER,
    DecisionReceipt,
    ExecutionBoundary,
    to_receipt_dict,
)

__all__ = [
    "BASELINE_CONSTRAINT_MARKER",
    "CANONICAL_DECISION_STATES",
    "ActualCall",
    "DecisionReceipt",
    "DecisionState",
    "ExecutionBoundary",
    "LegitimacyInvariantError",
    "call_matches",
    "canonicalize_decision_state",
    "is_allow_state",
    "normalize_actual_call",
    "route_ambiguous_decision",
    "to_receipt_dict",
    "validate_receipt_for_execution",
]
