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

from importlib import import_module
from typing import TYPE_CHECKING, Any

from acgs_lite.control_plane.action_hash import action_hash

if TYPE_CHECKING:
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
    from acgs_lite.control_plane.identity import (
        ADMIN_SCOPE,
        AdminAttestationFailed,
        AdminAttestor,
        HumanAuthenticationFailed,
        HumanAuthenticator,
        HumanChallenge,
        IdentityDirectoryError,
        IdentityEntry,
        IdentityProvider,
        StaticIdentityDirectory,
        VerifiedHumanSession,
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
    from acgs_lite.control_plane.service import (
        ControlPlaneService,
        ControlPlaneServiceError,
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

# Keep independent receipt verification importable without the issuer.
_LAZY_EXPORTS = {
    "action_hash": "acgs_lite.control_plane.action_hash",
    "DEFAULT_QUORUM_POLICIES": "acgs_lite.control_plane.approvals",
    "ApprovalAuthority": "acgs_lite.control_plane.approvals",
    "ApprovalGate": "acgs_lite.control_plane.approvals",
    "ApprovalRegistrationRejected": "acgs_lite.control_plane.approvals",
    "QuorumPolicy": "acgs_lite.control_plane.approvals",
    "QuorumResult": "acgs_lite.control_plane.approvals",
    "SignedApproval": "acgs_lite.control_plane.approvals",
    "AutonomyController": "acgs_lite.control_plane.autonomy",
    "AutonomyLevel": "acgs_lite.control_plane.autonomy",
    "AutonomyRestoreRejected": "acgs_lite.control_plane.autonomy",
    "ErrorBudget": "acgs_lite.control_plane.autonomy",
    "FailureKind": "acgs_lite.control_plane.autonomy",
    "BreakerPolicy": "acgs_lite.control_plane.breaker",
    "BreakerResetRejected": "acgs_lite.control_plane.breaker",
    "BreakerState": "acgs_lite.control_plane.breaker",
    "BreakerStatus": "acgs_lite.control_plane.breaker",
    "TriggerCircuitBreaker": "acgs_lite.control_plane.breaker",
    "BudgetChargeRefused": "acgs_lite.control_plane.budgets",
    "BudgetExhausted": "acgs_lite.control_plane.budgets",
    "BudgetLedger": "acgs_lite.control_plane.budgets",
    "BudgetLimits": "acgs_lite.control_plane.budgets",
    "BudgetState": "acgs_lite.control_plane.budgets",
    "ChangeClass": "acgs_lite.control_plane.change_class",
    "classify_change": "acgs_lite.control_plane.change_class",
    "ChangeOwnershipRegistry": "acgs_lite.control_plane.change_ownership",
    "OwnershipDenied": "acgs_lite.control_plane.change_ownership",
    "READ_ONLY_ACTIONS": "acgs_lite.control_plane.context",
    "WRITE_VERBS": "acgs_lite.control_plane.context",
    "DecisionContext": "acgs_lite.control_plane.context",
    "DecisionRequest": "acgs_lite.control_plane.context",
    "is_write_action": "acgs_lite.control_plane.context",
    "CoreChangeWriter": "acgs_lite.control_plane.core_write",
    "CoreWriteRejected": "acgs_lite.control_plane.core_write",
    "CredentialInvalid": "acgs_lite.control_plane.credentials",
    "CredentialIssuanceRefused": "acgs_lite.control_plane.credentials",
    "CredentialIssuer": "acgs_lite.control_plane.credentials",
    "ScopedCredential": "acgs_lite.control_plane.credentials",
    "GovernedToolDispatcher": "acgs_lite.control_plane.dispatcher",
    "ToolDenied": "acgs_lite.control_plane.dispatcher",
    "ToolResult": "acgs_lite.control_plane.dispatcher",
    "DeterministicEvaluator": "acgs_lite.control_plane.evaluator",
    "EvaluationResult": "acgs_lite.control_plane.evaluator",
    "EvaluatorService": "acgs_lite.control_plane.evaluator",
    "DEFAULT_EVIDENCE_POLICY": "acgs_lite.control_plane.evidence",
    "CompositeRunVerifier": "acgs_lite.control_plane.evidence",
    "EvidencePolicy": "acgs_lite.control_plane.evidence",
    "EvidenceSource": "acgs_lite.control_plane.evidence",
    "ExternalRunRef": "acgs_lite.control_plane.evidence",
    "ExternalRunVerifier": "acgs_lite.control_plane.evidence",
    "GitHubActionsRunVerifier": "acgs_lite.control_plane.evidence",
    "RunRegistrationRejected": "acgs_lite.control_plane.evidence",
    "RunValidation": "acgs_lite.control_plane.evidence",
    "TrustedRunRegistry": "acgs_lite.control_plane.evidence",
    "ControlPlane": "acgs_lite.control_plane.facade",
    "ControlPlaneConfig": "acgs_lite.control_plane.facade",
    "ControlPlaneConfigError": "acgs_lite.control_plane.facade",
    "build_control_plane": "acgs_lite.control_plane.facade",
    "IAMGrantRejected": "acgs_lite.control_plane.iam",
    "RepositoryPermissions": "acgs_lite.control_plane.iam",
    "WriteGrant": "acgs_lite.control_plane.iam",
    "render_codeowners": "acgs_lite.control_plane.iam",
    "ADMIN_SCOPE": "acgs_lite.control_plane.identity",
    "AdminAttestationFailed": "acgs_lite.control_plane.identity",
    "AdminAttestor": "acgs_lite.control_plane.identity",
    "HumanAuthenticationFailed": "acgs_lite.control_plane.identity",
    "HumanAuthenticator": "acgs_lite.control_plane.identity",
    "HumanChallenge": "acgs_lite.control_plane.identity",
    "IdentityDirectoryError": "acgs_lite.control_plane.identity",
    "IdentityEntry": "acgs_lite.control_plane.identity",
    "IdentityProvider": "acgs_lite.control_plane.identity",
    "StaticIdentityDirectory": "acgs_lite.control_plane.identity",
    "VerifiedHumanSession": "acgs_lite.control_plane.identity",
    "DEFAULT_IMMUTABLE_CORE": "acgs_lite.control_plane.immutable_core",
    "CoreCategory": "acgs_lite.control_plane.immutable_core",
    "ImmutableCoreError": "acgs_lite.control_plane.immutable_core",
    "ImmutableCoreRegistry": "acgs_lite.control_plane.immutable_core",
    "normalize_path": "acgs_lite.control_plane.immutable_core",
    "IncidentLockError": "acgs_lite.control_plane.incident",
    "IncidentMutationLock": "acgs_lite.control_plane.incident",
    "CONSTITUTION_INVARIANTS": "acgs_lite.control_plane.invariants",
    "KillSwitch": "acgs_lite.control_plane.killswitch",
    "KillSwitchOperationRejected": "acgs_lite.control_plane.killswitch",
    "Decision": "acgs_lite.control_plane.pdp",
    "PolicyDecisionPoint": "acgs_lite.control_plane.pdp",
    "PolicyEffect": "acgs_lite.control_plane.pdp",
    "PolicyParseError": "acgs_lite.control_plane.pdp",
    "PolicySet": "acgs_lite.control_plane.pdp",
    "PolicyStatement": "acgs_lite.control_plane.pdp",
    "Principal": "acgs_lite.control_plane.principal",
    "PrincipalKind": "acgs_lite.control_plane.principal",
    "PromotionGate": "acgs_lite.control_plane.promotion",
    "PromotionRejected": "acgs_lite.control_plane.promotion",
    "DEFAULT_RECEIPT_STORE_PATH": "acgs_lite.control_plane.receipt_ledger",
    "InMemoryReceiptStore": "acgs_lite.control_plane.receipt_ledger",
    "JSONLReceiptStore": "acgs_lite.control_plane.receipt_ledger",
    "ReceiptCapabilityError": "acgs_lite.control_plane.receipt_ledger",
    "ReceiptConflict": "acgs_lite.control_plane.receipt_ledger",
    "ReceiptEmissionError": "acgs_lite.control_plane.receipt_ledger",
    "ReceiptLedger": "acgs_lite.control_plane.receipt_ledger",
    "ReceiptStore": "acgs_lite.control_plane.receipt_ledger",
    "ReceiptStoreCorrupted": "acgs_lite.control_plane.receipt_ledger",
    "ReceiptVerification": "acgs_lite.control_plane.receipt_verify",
    "verify_chain": "acgs_lite.control_plane.receipt_verify",
    "verify_receipt": "acgs_lite.control_plane.receipt_verify",
    "GENESIS_RECEIPT_HASH": "acgs_lite.control_plane.receipts",
    "ApproverRef": "acgs_lite.control_plane.receipts",
    "ControlPlaneReceipt": "acgs_lite.control_plane.receipts",
    "ReceiptKind": "acgs_lite.control_plane.receipts",
    "SignedControlPlaneReceipt": "acgs_lite.control_plane.receipts",
    "Role": "acgs_lite.control_plane.roles",
    "RoleAssignments": "acgs_lite.control_plane.roles",
    "RoleConflict": "acgs_lite.control_plane.roles",
    "Runbook": "acgs_lite.control_plane.runbook",
    "RunbookDenied": "acgs_lite.control_plane.runbook",
    "RunbookRegistry": "acgs_lite.control_plane.runbook",
    "RunbookRejected": "acgs_lite.control_plane.runbook",
    "runbook_hash": "acgs_lite.control_plane.runbook",
    "runbook_json_schema": "acgs_lite.control_plane.runbook",
    "ControlPlaneService": "acgs_lite.control_plane.service",
    "ControlPlaneServiceError": "acgs_lite.control_plane.service",
    "AgentTelemetryRejected": "acgs_lite.control_plane.telemetry",
    "InMemoryTelemetryStore": "acgs_lite.control_plane.telemetry",
    "JSONLTelemetryStore": "acgs_lite.control_plane.telemetry",
    "OversightEvent": "acgs_lite.control_plane.telemetry",
    "OversightMetrics": "acgs_lite.control_plane.telemetry",
    "TelemetryAutonomyBridge": "acgs_lite.control_plane.telemetry",
    "TelemetryRecorder": "acgs_lite.control_plane.telemetry",
    "TelemetryStore": "acgs_lite.control_plane.telemetry",
    "ActionProfile": "acgs_lite.control_plane.tier_policy",
    "PostHocReviewItem": "acgs_lite.control_plane.tier_policy",
    "ReviewQueue": "acgs_lite.control_plane.tier_policy",
    "classify_tier": "acgs_lite.control_plane.tier_policy",
    "ActionTier": "acgs_lite.control_plane.tiers",
    "IndependentVerifier": "acgs_lite.control_plane.verifier",
    "ReplayVerifier": "acgs_lite.control_plane.verifier",
    "VerifierPolicy": "acgs_lite.control_plane.verifier",
    "VerifierRejected": "acgs_lite.control_plane.verifier",
    "VerifierVerdict": "acgs_lite.control_plane.verifier",
}


def __getattr__(name: str) -> Any:
    module = _LAZY_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


__all__ = [
    "ActionProfile",
    "ActionTier",
    "ADMIN_SCOPE",
    "AdminAttestationFailed",
    "AdminAttestor",
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
    "ControlPlaneService",
    "ControlPlaneServiceError",
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
    "HumanAuthenticationFailed",
    "HumanAuthenticator",
    "HumanChallenge",
    "IAMGrantRejected",
    "IdentityDirectoryError",
    "IdentityEntry",
    "IdentityProvider",
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
    "StaticIdentityDirectory",
    "TelemetryAutonomyBridge",
    "TelemetryRecorder",
    "TelemetryStore",
    "ToolDenied",
    "ToolResult",
    "TriggerCircuitBreaker",
    "TrustedRunRegistry",
    "VerifiedHumanSession",
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
