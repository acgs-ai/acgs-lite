"""Control plane for self-improving agents.

Phase 1: immutable core. Phase 2: signed, hash-chained receipts for every
decision and promotion, backed by independently validated external runs
(:mod:`.evidence`, :mod:`.receipts`, :mod:`.receipt_ledger`,
:mod:`.receipt_verify`, :mod:`.promotion`). Phase 3: separation of duties
and harness-enforced limits -- signed single-use approvals bound to an action
hash with requester/author/sibling exclusion (:mod:`.approvals`,
:mod:`.action_hash`), harness-issued short-TTL credentials
(:mod:`.credentials`), an independent kill switch (:mod:`.killswitch`),
resource budgets (:mod:`.budgets`), automatic autonomy demotion
(:mod:`.autonomy`) and a human-only change class (:mod:`.change_class`)
whose file writes go only through :class:`CoreChangeWriter`
(:mod:`.core_write`). Phase 4: oversight telemetry -- override rate,
approval latency, verifier precision/recall and post-merge rework, segmented
agent vs human (:mod:`.telemetry`, :mod:`.telemetry_api`) -- feeding the
error budget, plus a per-trigger circuit breaker (:mod:`.breaker`). Phase 5:
tiers computed from irreversibility and blast radius (:mod:`.tier_policy`),
machine-readable runbooks gating T1 (:mod:`.runbook`), explicit roles
(:mod:`.roles`), single writer per change (:mod:`.change_ownership`), a
deterministic evaluator outside mutation scope (:mod:`.evaluator`), an
independent artifact-anchored verifier (:mod:`.verifier`), the incident
mutation lock (:mod:`.incident`) and one wiring constructor
(:mod:`.facade`); :mod:`.demo_loop` is the self-improvement demo.

Mutating agents must never be able to write to the things that judge them.
The immutable core is protected twice, by independent code paths:

* the policy engine (:class:`PolicyDecisionPoint` with non-overridable
  :data:`CONSTITUTION_INVARIANTS`, enforced at the
  :class:`GovernedToolDispatcher` chokepoint); and
* repository permissions (:class:`RepositoryPermissions`, a generated
  CODEOWNERS file and the ``immutable-core-guard`` CI workflow).

Import from ``acgs_lite.control_plane``; nothing here is re-exported from the
top-level ``acgs_lite`` package.
"""

from __future__ import annotations

from acgs_lite.control_plane.action_hash import action_hash
from acgs_lite.control_plane.approvals import (
    DEFAULT_QUORUM_POLICIES,
    ApprovalAuthority,
    ApprovalGate,
    ApprovalRegistrationRejected,
    QuorumPolicy,
    QuorumResult,
    SignedApproval,
)
from acgs_lite.control_plane.autonomy import (
    AutonomyController,
    AutonomyLevel,
    AutonomyRestoreRejected,
    ErrorBudget,
    FailureKind,
)
from acgs_lite.control_plane.breaker import (
    BreakerPolicy,
    BreakerResetRejected,
    BreakerState,
    BreakerStatus,
    TriggerCircuitBreaker,
)
from acgs_lite.control_plane.budgets import (
    BudgetChargeRefused,
    BudgetExhausted,
    BudgetLedger,
    BudgetLimits,
    BudgetState,
)
from acgs_lite.control_plane.change_class import ChangeClass, classify_change
from acgs_lite.control_plane.change_ownership import ChangeOwnershipRegistry, OwnershipDenied
from acgs_lite.control_plane.context import (
    READ_ONLY_ACTIONS,
    WRITE_VERBS,
    DecisionContext,
    DecisionRequest,
    is_write_action,
)
from acgs_lite.control_plane.core_write import CoreChangeWriter, CoreWriteRejected
from acgs_lite.control_plane.credentials import (
    CredentialInvalid,
    CredentialIssuanceRefused,
    CredentialIssuer,
    ScopedCredential,
)
from acgs_lite.control_plane.dispatcher import GovernedToolDispatcher, ToolDenied, ToolResult
from acgs_lite.control_plane.evaluator import (
    DeterministicEvaluator,
    EvaluationResult,
    EvaluatorService,
)
from acgs_lite.control_plane.evidence import (
    DEFAULT_EVIDENCE_POLICY,
    CompositeRunVerifier,
    EvidencePolicy,
    EvidenceSource,
    ExternalRunRef,
    ExternalRunVerifier,
    GitHubActionsRunVerifier,
    RunRegistrationRejected,
    RunValidation,
    TrustedRunRegistry,
)
from acgs_lite.control_plane.facade import (
    ControlPlane,
    ControlPlaneConfig,
    ControlPlaneConfigError,
    build_control_plane,
)
from acgs_lite.control_plane.iam import (
    IAMGrantRejected,
    RepositoryPermissions,
    WriteGrant,
    render_codeowners,
)
from acgs_lite.control_plane.immutable_core import (
    DEFAULT_IMMUTABLE_CORE,
    CoreCategory,
    ImmutableCoreError,
    ImmutableCoreRegistry,
    normalize_path,
)
from acgs_lite.control_plane.incident import IncidentLockError, IncidentMutationLock
from acgs_lite.control_plane.invariants import CONSTITUTION_INVARIANTS
from acgs_lite.control_plane.killswitch import KillSwitch, KillSwitchOperationRejected
from acgs_lite.control_plane.pdp import (
    Decision,
    PolicyDecisionPoint,
    PolicyEffect,
    PolicyParseError,
    PolicySet,
    PolicyStatement,
)
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.promotion import PromotionGate, PromotionRejected
from acgs_lite.control_plane.receipt_ledger import (
    DEFAULT_RECEIPT_STORE_PATH,
    InMemoryReceiptStore,
    JSONLReceiptStore,
    ReceiptCapabilityError,
    ReceiptConflict,
    ReceiptEmissionError,
    ReceiptLedger,
    ReceiptStore,
    ReceiptStoreCorrupted,
)
from acgs_lite.control_plane.receipt_verify import (
    ReceiptVerification,
    verify_chain,
    verify_receipt,
)
from acgs_lite.control_plane.receipts import (
    GENESIS_RECEIPT_HASH,
    ApproverRef,
    ControlPlaneReceipt,
    ReceiptKind,
    SignedControlPlaneReceipt,
)
from acgs_lite.control_plane.roles import Role, RoleAssignments, RoleConflict
from acgs_lite.control_plane.runbook import (
    Runbook,
    RunbookDenied,
    RunbookRegistry,
    RunbookRejected,
    runbook_hash,
    runbook_json_schema,
)
from acgs_lite.control_plane.telemetry import (
    AgentTelemetryRejected,
    InMemoryTelemetryStore,
    JSONLTelemetryStore,
    OversightEvent,
    OversightMetrics,
    TelemetryAutonomyBridge,
    TelemetryRecorder,
    TelemetryStore,
)
from acgs_lite.control_plane.tier_policy import (
    ActionProfile,
    PostHocReviewItem,
    ReviewQueue,
    classify_tier,
)
from acgs_lite.control_plane.tiers import ActionTier
from acgs_lite.control_plane.verifier import (
    IndependentVerifier,
    ReplayVerifier,
    VerifierPolicy,
    VerifierRejected,
    VerifierVerdict,
)

__all__ = [
    "ActionProfile",
    "ActionTier",
    "AgentTelemetryRejected",
    "ApprovalAuthority",
    "ApprovalGate",
    "ApprovalRegistrationRejected",
    "ApproverRef",
    "AutonomyController",
    "AutonomyLevel",
    "AutonomyRestoreRejected",
    "BreakerPolicy",
    "BreakerResetRejected",
    "BreakerState",
    "BreakerStatus",
    "BudgetChargeRefused",
    "BudgetExhausted",
    "BudgetLedger",
    "BudgetLimits",
    "BudgetState",
    "CONSTITUTION_INVARIANTS",
    "ChangeClass",
    "ChangeOwnershipRegistry",
    "CompositeRunVerifier",
    "ControlPlane",
    "ControlPlaneConfig",
    "ControlPlaneConfigError",
    "ControlPlaneReceipt",
    "CoreCategory",
    "CoreChangeWriter",
    "CoreWriteRejected",
    "CredentialInvalid",
    "CredentialIssuanceRefused",
    "CredentialIssuer",
    "DEFAULT_EVIDENCE_POLICY",
    "DEFAULT_IMMUTABLE_CORE",
    "DEFAULT_QUORUM_POLICIES",
    "DEFAULT_RECEIPT_STORE_PATH",
    "Decision",
    "DecisionContext",
    "DecisionRequest",
    "DeterministicEvaluator",
    "ErrorBudget",
    "EvaluationResult",
    "EvaluatorService",
    "EvidencePolicy",
    "EvidenceSource",
    "ExternalRunRef",
    "ExternalRunVerifier",
    "FailureKind",
    "GENESIS_RECEIPT_HASH",
    "GitHubActionsRunVerifier",
    "GovernedToolDispatcher",
    "IAMGrantRejected",
    "ImmutableCoreError",
    "ImmutableCoreRegistry",
    "InMemoryReceiptStore",
    "InMemoryTelemetryStore",
    "IncidentLockError",
    "IncidentMutationLock",
    "IndependentVerifier",
    "JSONLReceiptStore",
    "JSONLTelemetryStore",
    "KillSwitch",
    "KillSwitchOperationRejected",
    "OversightEvent",
    "OversightMetrics",
    "OwnershipDenied",
    "PolicyDecisionPoint",
    "PolicyEffect",
    "PolicyParseError",
    "PolicySet",
    "PolicyStatement",
    "PostHocReviewItem",
    "Principal",
    "PrincipalKind",
    "PromotionGate",
    "PromotionRejected",
    "QuorumPolicy",
    "QuorumResult",
    "READ_ONLY_ACTIONS",
    "ReceiptCapabilityError",
    "ReceiptConflict",
    "ReceiptEmissionError",
    "ReceiptKind",
    "ReceiptLedger",
    "ReceiptStore",
    "ReceiptStoreCorrupted",
    "ReceiptVerification",
    "ReplayVerifier",
    "RepositoryPermissions",
    "ReviewQueue",
    "Role",
    "RoleAssignments",
    "RoleConflict",
    "RunRegistrationRejected",
    "RunValidation",
    "Runbook",
    "RunbookDenied",
    "RunbookRegistry",
    "RunbookRejected",
    "ScopedCredential",
    "SignedApproval",
    "SignedControlPlaneReceipt",
    "TelemetryAutonomyBridge",
    "TelemetryRecorder",
    "TelemetryStore",
    "ToolDenied",
    "ToolResult",
    "TriggerCircuitBreaker",
    "TrustedRunRegistry",
    "VerifierPolicy",
    "VerifierRejected",
    "VerifierVerdict",
    "WRITE_VERBS",
    "WriteGrant",
    "action_hash",
    "build_control_plane",
    "classify_change",
    "classify_tier",
    "is_write_action",
    "normalize_path",
    "render_codeowners",
    "runbook_hash",
    "runbook_json_schema",
    "verify_chain",
    "verify_receipt",
]
