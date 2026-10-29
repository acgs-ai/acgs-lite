"""Stable fail-closed legitimacy contracts for governed execution.

The public names exported here form the Runtime Legitimacy Kernel surface:
canonical decision taxonomy helpers, immutable decision receipts, execution
boundary normalization, and receipt verification before side effects.
"""

from acgs_lite.legitimacy.authorization import (
    AsyncGrantResolver,
    AuthorizationProfile,
    ExecutionAuthority,
    ExecutionGrant,
    GrantResolver,
    TrustedExecutionContext,
)
from acgs_lite.legitimacy.decide import (
    CANONICAL_DECISION_STATES,
    DecisionState,
    canonicalize_decision_state,
    is_allow_state,
)
from acgs_lite.legitimacy.effects import (
    EffectBudget,
    EffectOutcome,
    EffectProvider,
    EffectRecord,
    EffectRequest,
    EffectState,
    EffectStore,
    ProviderResult,
)
from acgs_lite.legitimacy.identity import (
    local_grant_identity,
    policy_identity,
    receipt_identity,
    signed_envelope_identity,
)
from acgs_lite.legitimacy.invariants import (
    ActualCall,
    LegitimacyInvariantError,
    call_matches,
    normalize_actual_call,
    route_ambiguous_decision,
    validate_receipt_for_execution,
)
from acgs_lite.legitimacy.invocation import (
    ArgumentNotDigestible,
    InvocationBinding,
    PolicyBinding,
    bind_invocation,
    bind_policy,
    canonical_argument_digest,
    trusted_method_id,
)
from acgs_lite.legitimacy.ledger import (
    AttemptStatus,
    ExecutionAttemptRecord,
    InProcessGrantLedger,
)
from acgs_lite.legitimacy.outcome import (
    OUTCOME_RECEIPT_SCHEMA,
    OutcomeReceipt,
    SignedOutcomeReceipt,
    outcome_from_record,
    sign_outcome,
)
from acgs_lite.legitimacy.provider_contract import (
    PROVIDER_CONTRACT_SCHEMA,
    ContractedEffectStore,
    ProviderContract,
    ProviderContractClass,
    ProviderContractRegistry,
    ProviderNotDispatchable,
)
from acgs_lite.legitimacy.receipt import (
    BASELINE_CONSTRAINT_MARKER,
    RECEIPT_HASH_DOMAIN_V2,
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
    sign_execution_authorization,
    sign_receipt,
    verify_signature,
)

__all__ = [
    "BASELINE_CONSTRAINT_MARKER",
    "CANONICAL_DECISION_STATES",
    "OUTCOME_RECEIPT_SCHEMA",
    "PROVIDER_CONTRACT_SCHEMA",
    "RECEIPT_HASH_DOMAIN_V2",
    "ActualCall",
    "ArgumentNotDigestible",
    "AsyncGrantResolver",
    "AttemptStatus",
    "AuthorizationProfile",
    "ContractedEffectStore",
    "DecisionEvaluator",
    "DecisionReceipt",
    "DecisionState",
    "Ed25519ReceiptSigner",
    "EffectBudget",
    "EffectOutcome",
    "EffectProvider",
    "EffectRecord",
    "EffectRequest",
    "EffectState",
    "EffectStore",
    "ExecutionAttemptRecord",
    "ExecutionAuthority",
    "ExecutionBoundary",
    "ExecutionGrant",
    "GrantResolver",
    "InProcessGrantLedger",
    "InvocationBinding",
    "LegitimacyInvariantError",
    "OutcomeReceipt",
    "PolicyBinding",
    "ProviderContract",
    "ProviderContractClass",
    "ProviderContractRegistry",
    "ProviderNotDispatchable",
    "ProviderResult",
    "ReceiptSigner",
    "ReceiptSigningUnavailable",
    "ReplayInputs",
    "ReplayVerification",
    "SignedOutcomeReceipt",
    "SignedReceipt",
    "TrustedExecutionContext",
    "bind_invocation",
    "bind_policy",
    "call_matches",
    "canonical_argument_digest",
    "canonicalize_decision_state",
    "is_allow_state",
    "local_grant_identity",
    "normalize_actual_call",
    "outcome_from_record",
    "policy_identity",
    "receipt_identity",
    "replay_and_verify",
    "route_ambiguous_decision",
    "sign_execution_authorization",
    "sign_outcome",
    "sign_receipt",
    "signed_envelope_identity",
    "to_receipt_dict",
    "trusted_method_id",
    "validate_receipt_for_execution",
    "verify_signature",
]
