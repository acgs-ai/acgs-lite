"""Stable fail-closed legitimacy contracts for governed execution.

The public names exported here form the Runtime Legitimacy Kernel surface:
canonical decision taxonomy helpers, immutable decision receipts, execution
boundary normalization, and receipt verification before side effects.
"""

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
from acgs_lite.legitimacy.replay_verify import (
    DecisionEvaluator,
    ReplayInputs,
    ReplayVerification,
    replay_and_verify,
)
from acgs_lite.legitimacy.signing import (
    Ed25519ReceiptSigner,
    ReceiptSigner,
    ReceiptSigningUnavailable,
    SignedReceipt,
    sign_receipt,
    verify_signature,
)

__all__ = [
    "BASELINE_CONSTRAINT_MARKER",
    "CANONICAL_DECISION_STATES",
    "ActualCall",
    "DecisionEvaluator",
    "DecisionReceipt",
    "DecisionState",
    "Ed25519ReceiptSigner",
    "ExecutionBoundary",
    "LegitimacyInvariantError",
    "ReceiptSigner",
    "ReceiptSigningUnavailable",
    "ReplayInputs",
    "ReplayVerification",
    "SignedReceipt",
    "call_matches",
    "canonicalize_decision_state",
    "is_allow_state",
    "normalize_actual_call",
    "replay_and_verify",
    "route_ambiguous_decision",
    "sign_receipt",
    "to_receipt_dict",
    "validate_receipt_for_execution",
    "verify_signature",
]
