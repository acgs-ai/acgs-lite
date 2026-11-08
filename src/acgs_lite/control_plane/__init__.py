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
error budget, plus a per-trigger circuit breaker (:mod:`.breaker`).

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

if TYPE_CHECKING:
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
    from acgs_lite.control_plane.tiers import ActionTier

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
    "IAMGrantRejected": "acgs_lite.control_plane.iam",
    "RepositoryPermissions": "acgs_lite.control_plane.iam",
    "WriteGrant": "acgs_lite.control_plane.iam",
    "render_codeowners": "acgs_lite.control_plane.iam",
    "DEFAULT_IMMUTABLE_CORE": "acgs_lite.control_plane.immutable_core",
    "CoreCategory": "acgs_lite.control_plane.immutable_core",
    "ImmutableCoreError": "acgs_lite.control_plane.immutable_core",
    "ImmutableCoreRegistry": "acgs_lite.control_plane.immutable_core",
    "normalize_path": "acgs_lite.control_plane.immutable_core",
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
    "AgentTelemetryRejected": "acgs_lite.control_plane.telemetry",
    "InMemoryTelemetryStore": "acgs_lite.control_plane.telemetry",
    "JSONLTelemetryStore": "acgs_lite.control_plane.telemetry",
    "OversightEvent": "acgs_lite.control_plane.telemetry",
    "OversightMetrics": "acgs_lite.control_plane.telemetry",
    "TelemetryAutonomyBridge": "acgs_lite.control_plane.telemetry",
    "TelemetryRecorder": "acgs_lite.control_plane.telemetry",
    "TelemetryStore": "acgs_lite.control_plane.telemetry",
    "ActionTier": "acgs_lite.control_plane.tiers",
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
    "CONSTITUTION_INVARIANTS",
    "DEFAULT_EVIDENCE_POLICY",
    "DEFAULT_IMMUTABLE_CORE",
    "DEFAULT_QUORUM_POLICIES",
    "DEFAULT_RECEIPT_STORE_PATH",
    "GENESIS_RECEIPT_HASH",
    "READ_ONLY_ACTIONS",
    "WRITE_VERBS",
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
    "ChangeClass",
    "CompositeRunVerifier",
    "ControlPlaneReceipt",
    "CoreChangeWriter",
    "CoreWriteRejected",
    "CoreCategory",
    "CredentialInvalid",
    "CredentialIssuanceRefused",
    "CredentialIssuer",
    "Decision",
    "DecisionContext",
    "DecisionRequest",
    "ErrorBudget",
    "EvidencePolicy",
    "EvidenceSource",
    "ExternalRunRef",
    "ExternalRunVerifier",
    "FailureKind",
    "GitHubActionsRunVerifier",
    "GovernedToolDispatcher",
    "IAMGrantRejected",
    "ImmutableCoreError",
    "ImmutableCoreRegistry",
    "InMemoryReceiptStore",
    "InMemoryTelemetryStore",
    "JSONLReceiptStore",
    "JSONLTelemetryStore",
    "KillSwitch",
    "KillSwitchOperationRejected",
    "OversightEvent",
    "OversightMetrics",
    "PolicyDecisionPoint",
    "PolicyEffect",
    "PolicyParseError",
    "PolicySet",
    "PolicyStatement",
    "Principal",
    "PrincipalKind",
    "PromotionGate",
    "PromotionRejected",
    "QuorumPolicy",
    "QuorumResult",
    "ReceiptCapabilityError",
    "ReceiptConflict",
    "ReceiptEmissionError",
    "ReceiptKind",
    "ReceiptLedger",
    "ReceiptStore",
    "ReceiptStoreCorrupted",
    "ReceiptVerification",
    "RepositoryPermissions",
    "RunRegistrationRejected",
    "RunValidation",
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
    "WriteGrant",
    "action_hash",
    "classify_change",
    "is_write_action",
    "normalize_path",
    "render_codeowners",
    "verify_chain",
    "verify_receipt",
]
