"""Control plane for self-improving agents.

Phase 1: immutable core. Phase 2: signed, hash-chained receipts for every
decision and promotion, backed by independently validated external runs
(:mod:`.evidence`, :mod:`.receipts`, :mod:`.receipt_ledger`,
:mod:`.receipt_verify`, :mod:`.promotion`).

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

from acgs_lite.control_plane.context import (
    READ_ONLY_ACTIONS,
    WRITE_VERBS,
    DecisionContext,
    DecisionRequest,
    is_write_action,
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
from acgs_lite.control_plane.tiers import ActionTier

__all__ = [
    "CONSTITUTION_INVARIANTS",
    "DEFAULT_EVIDENCE_POLICY",
    "DEFAULT_IMMUTABLE_CORE",
    "DEFAULT_RECEIPT_STORE_PATH",
    "GENESIS_RECEIPT_HASH",
    "READ_ONLY_ACTIONS",
    "WRITE_VERBS",
    "ActionTier",
    "ApproverRef",
    "CompositeRunVerifier",
    "ControlPlaneReceipt",
    "CoreCategory",
    "Decision",
    "DecisionContext",
    "DecisionRequest",
    "EvidencePolicy",
    "EvidenceSource",
    "ExternalRunRef",
    "ExternalRunVerifier",
    "GitHubActionsRunVerifier",
    "GovernedToolDispatcher",
    "IAMGrantRejected",
    "ImmutableCoreError",
    "ImmutableCoreRegistry",
    "InMemoryReceiptStore",
    "JSONLReceiptStore",
    "PolicyDecisionPoint",
    "PolicyEffect",
    "PolicyParseError",
    "PolicySet",
    "PolicyStatement",
    "Principal",
    "PrincipalKind",
    "PromotionGate",
    "PromotionRejected",
    "ReceiptEmissionError",
    "ReceiptCapabilityError",
    "ReceiptConflict",
    "ReceiptKind",
    "ReceiptLedger",
    "ReceiptStore",
    "ReceiptStoreCorrupted",
    "ReceiptVerification",
    "RepositoryPermissions",
    "RunRegistrationRejected",
    "RunValidation",
    "SignedControlPlaneReceipt",
    "ToolDenied",
    "ToolResult",
    "TrustedRunRegistry",
    "WriteGrant",
    "is_write_action",
    "normalize_path",
    "render_codeowners",
    "verify_chain",
    "verify_receipt",
]
