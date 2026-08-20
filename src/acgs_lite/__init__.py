"""ACGS: Constitutional AI Governance for Any Agent.

Copyright (C) 2024-2026 ACGS Contributors
Licensed under Apache-2.0. See LICENSE for details.
Commercial license available at https://acgs.ai for proprietary use.

Constitutional Hash: 608508a9bd224290

Usage::

    from acgs_lite import Constitution, GovernedAgent, MACIRole

    constitution = Constitution.from_yaml("rules.yaml")
    agent = GovernedAgent(
        my_agent,
        constitution=constitution,
        maci_role=MACIRole.EXECUTOR,
    )
    result = agent.run("process this request", governance_action="execute")
"""

from acgs_lite._meta import CONSTITUTIONAL_HASH, VERSION
from acgs_lite.audit import (
    AuditBackend,
    AuditEntry,
    AuditLog,
    InMemoryAuditBackend,
    JSONLAuditBackend,
)
from acgs_lite.circuit_breaker import GovernanceCircuitBreaker, GovernanceHaltError
from acgs_lite.constitution import (
    AcknowledgedTension,
    ActivationRecord,
    AuditPolicy,
    BundleStatus,
    CaseConfig,
    CaseManager,
    CaseRecord,
    Constitution,
    ConstitutionBuilder,
    ConstitutionBundle,
    GovernanceMemoryPrecedentHit,
    GovernanceMemoryReport,
    GovernanceMemoryRetriever,
    GovernanceMemorySummary,
    InMemoryLifecycleAuditSink,
    LifecycleAuditSink,
    LifecycleEvidenceRecord,
    Rule,
    RuleSnapshot,
    RuleSynthesisProvider,
    SelectionPolicy,
    SelectionResult,
    Severity,
    SpotCheckAuditor,
    SpotCheckResult,
    StatusTransition,
    TrustAdjustment,
    TrustConfig,
    TrustScoreManager,
    ValidatorPool,
    ValidatorSelector,
)
from acgs_lite.constitution.claim_lifecycle import (
    CaseState,
    TransitionRecord,
)
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.constitution.spot_check import (
    CompletedCase,
    ValidatorAssessment,
    ValidatorProfile,
)
from acgs_lite.constitution.trust_score import (
    TrustEvent,
    TrustTier,
)
from acgs_lite.engine import BatchValidationResult, GovernanceEngine, ValidationResult
from acgs_lite.errors import (
    ConstitutionalViolationError,
    GovernanceError,
    MACIViolationError,
    PolicyDeniedError,
)
from acgs_lite.events import EventBus, GovernanceEvent, get_event_bus
from acgs_lite.fail_closed import fail_closed as fail_closed
from acgs_lite.formal.exemption import (
    ExemptionError,
    VerificationExemption,
    verification_exempt,
)
from acgs_lite.governed import GovernedAgent, GovernedCallable
from acgs_lite.legitimacy.authorization import (
    AsyncGrantResolver,
    AuthorizationProfile,
    ExecutionGrant,
    GrantResolver,
)
from acgs_lite.licensing import LicenseInfo, LicenseManager, Tier
from acgs_lite.maci import MACIEnforcer, MACIRole
from acgs_lite.production import (
    ProductionProfile,
    ProductionProfileError,
    ProductionProfileValidation,
    validate_production_profile,
)
from acgs_lite.z3_verify import VerificationStatus, blocks_execution

# ── Optional dependency tracking ────────────────────────────────────────────
# Populated when optional extras are not installed. __getattr__ below uses
# this to raise ImportError with a helpful install hint instead of crashing
# the entire `import acgs_lite` at startup.
_MISSING_OPTIONAL: dict[str, str] = {}
_LAZY_EXPORTS: dict[str, tuple[str, str, str]] = {
    "NullVerificationGate": (
        "acgs_lite.formal.smt_gate",
        "NullVerificationGate",
        "pip install z3-solver",
    ),
    "VerificationResult": (
        "acgs_lite.formal.smt_gate",
        "VerificationResult",
        "pip install z3-solver",
    ),
    "Z3VerificationGate": (
        "acgs_lite.formal.smt_gate",
        "Z3VerificationGate",
        "pip install z3-solver",
    ),
    "BundleStore": (
        "acgs_lite.constitution.bundle_store",
        "BundleStore",
        "pip install acgs-lite",
    ),
    "InMemoryBundleStore": (
        "acgs_lite.constitution.bundle_store",
        "InMemoryBundleStore",
        "pip install acgs-lite",
    ),
    "PostgresBundleStore": (
        "acgs_lite.constitution.postgres_bundle_store",
        "PostgresBundleStore",
        "pip install acgs-lite[postgres]",
    ),
    "SQLiteBundleStore": (
        "acgs_lite.constitution.sqlite_bundle_store",
        "SQLiteBundleStore",
        "pip install acgs-lite",
    ),
    "ConcurrentLifecycleError": (
        "acgs_lite.constitution.lifecycle_service",
        "ConcurrentLifecycleError",
        "pip install acgs-lite",
    ),
    "ConstitutionLifecycle": (
        "acgs_lite.constitution.lifecycle_service",
        "ConstitutionLifecycle",
        "pip install acgs-lite",
    ),
    "LifecycleError": (
        "acgs_lite.constitution.lifecycle_service",
        "LifecycleError",
        "pip install acgs-lite",
    ),
    "LifecycleEvidenceError": (
        "acgs_lite.constitution.lifecycle_service",
        "LifecycleEvidenceError",
        "pip install acgs-lite",
    ),
    "Z3_AVAILABLE": ("acgs_lite.z3_verify", "Z3_AVAILABLE", "pip install z3-solver"),
    "Z3_RISK_THRESHOLD": (
        "acgs_lite.z3_verify",
        "Z3_RISK_THRESHOLD",
        "pip install z3-solver",
    ),
    "Z3ConstraintVerifier": (
        "acgs_lite.z3_verify",
        "Z3ConstraintVerifier",
        "pip install z3-solver",
    ),
    "Z3VerifyResult": ("acgs_lite.z3_verify", "Z3VerifyResult", "pip install z3-solver"),
}

try:
    from acgs_lite.lean_verify import (
        LEAN_AVAILABLE,
        MISTRAL_AVAILABLE,
        LeanstralVerifier,
        LeanVerifyResult,
        ProofCertificate,
    )
except ImportError:
    for _s in (
        "LEAN_AVAILABLE",
        "MISTRAL_AVAILABLE",
        "LeanstralVerifier",
        "LeanVerifyResult",
        "ProofCertificate",
    ):
        _MISSING_OPTIONAL[_s] = "pip install acgs-lite[lean]"

_openshell_syms = (
    "ActionContext",
    "ActionEnvelope",
    "ActionPayloadSummary",
    "ActionRequirements",
    "ActionType",
    "ActorRef",
    "ActorRole",
    "ApprovalReviewRequest",
    "ApprovalReviewResponse",
    "ApprovalSubmission",
    "AuditEvent",
    "AuditEventType",
    "ComplianceResult",
    "ComplianceStatus",
    "DecisionType",
    "ExecutionOutcome",
    "ExternalRef",
    "GovernanceDecision",
    "GovernanceStateBackend",
    "GovernanceStateChecksumError",
    "GovernanceStateError",
    "GovernanceStateMigrationError",
    "GovernanceStateObservabilityHook",
    "GovernanceStateVersionError",
    "InMemoryGovernanceStateBackend",
    "JsonFileGovernanceStateBackend",
    "OperationType",
    "OutcomeStatus",
    "RedisGovernanceStateBackend",
    "ResourceRef",
    "RiskLevel",
    "SQLiteGovernanceStateBackend",
    "create_openshell_governance_app",
    "create_openshell_governance_router",
)
for _s in _openshell_syms:
    _LAZY_EXPORTS[_s] = (
        "acgs_lite.openshell",
        _s,
        "pip install acgs-lite",
    )
from acgs_lite.agents import (
    AgentCapabilityProfile,
    AgentRegistry,
    AgentSelection,
    GovernedAgentSelector,
    NoEligibleAgentError,
    SelectionDeniedError,
    get_agent_registry,
    reset_agent_registry,
)
from acgs_lite.policygen import (
    AdaptivePolicyGenerator,
    DomainRiskLevel,
    GeneratedPolicy,
    PolicyRequirement,
    PolicyResearcher,
    PreContext,
    PreContextBuilder,
    ResearchReport,
)
from acgs_lite.provenance import ProvenanceNode, ProvenanceRecord
from acgs_lite.scoring import ConstitutionalImpactScorer, RuleBasedScorer, score_impact
from acgs_lite.trajectory import (
    CumulativeValueRule,
    FrequencyThresholdRule,
    InMemoryTrajectoryStore,
    SensitiveToolSequenceRule,
    TrajectoryMonitor,
    TrajectorySession,
    TrajectoryViolation,
)

__version__ = VERSION


def set_license(key: str) -> LicenseInfo:
    """Activate a license key for this process.

    Args:
        key: License key in ACGS-{TIER}-{data} format.

    Returns:
        LicenseInfo with tier and expiry details.

    Example::

        import acgs_lite
        acgs_lite.set_license("ACGS-PRO-...")
    """
    return LicenseManager().set_license(key)


__constitutional_hash__ = CONSTITUTIONAL_HASH

__all__ = [
    # Governed agent discovery (registry + selector)
    "AgentCapabilityProfile",
    "AgentRegistry",
    "AgentSelection",
    "GovernedAgentSelector",
    "NoEligibleAgentError",
    "SelectionDeniedError",
    "get_agent_registry",
    "reset_agent_registry",
    # Adaptive policy generation (precontext -> research -> YAML)
    "AdaptivePolicyGenerator",
    "DomainRiskLevel",
    "GeneratedPolicy",
    "PolicyRequirement",
    "PolicyResearcher",
    "PreContext",
    "PreContextBuilder",
    "ResearchReport",
    # Core
    "Constitution",
    "ConstitutionBuilder",
    "ConstitutionBundle",
    "Rule",
    "RuleSynthesisProvider",
    "AcknowledgedTension",
    "ActivationRecord",
    "GovernanceMemoryPrecedentHit",
    "GovernanceMemoryReport",
    "GovernanceMemoryRetriever",
    "GovernanceMemorySummary",
    "BundleStatus",
    "BundleStore",
    "InMemoryBundleStore",
    "RuleSnapshot",
    "Severity",
    "StatusTransition",
    "ViolationAction",
    # Spot-check audit / governance lifecycle (Week-3)
    "AuditPolicy",
    "CaseConfig",
    "CaseManager",
    "CaseRecord",
    "CaseState",
    "CompletedCase",
    "ConcurrentLifecycleError",
    "ConstitutionLifecycle",
    "InMemoryLifecycleAuditSink",
    "LifecycleAuditSink",
    "LifecycleError",
    "LifecycleEvidenceError",
    "LifecycleEvidenceRecord",
    "SelectionPolicy",
    "SelectionResult",
    "SpotCheckAuditor",
    "SpotCheckResult",
    "TransitionRecord",
    "TrustAdjustment",
    "TrustConfig",
    "TrustEvent",
    "TrustScoreManager",
    "TrustTier",
    "ValidatorAssessment",
    "ValidatorProfile",
    "ValidatorPool",
    "ValidatorSelector",
    # Engine
    "GovernanceEngine",
    "ValidationResult",
    "BatchValidationResult",
    # Wrappers
    "GovernedAgent",
    "GovernedCallable",
    "AuthorizationProfile",
    "ExecutionGrant",
    "GrantResolver",
    "AsyncGrantResolver",
    "VerificationResult",
    "Z3VerificationGate",
    "NullVerificationGate",
    "ProvenanceRecord",
    "ProvenanceNode",
    "EventBus",
    "GovernanceEvent",
    "get_event_bus",
    # Audit
    "AuditLog",
    "AuditEntry",
    "AuditBackend",
    "InMemoryAuditBackend",
    "JSONLAuditBackend",
    # Circuit breaker (Article 14 kill-switch)
    "GovernanceCircuitBreaker",
    "GovernanceHaltError",
    # MACI
    "MACIRole",
    "MACIEnforcer",
    # Production profile validation
    "ProductionProfile",
    "ProductionProfileError",
    "ProductionProfileValidation",
    "validate_production_profile",
    # Scoring
    "ConstitutionalImpactScorer",
    "RuleBasedScorer",
    "score_impact",
    # Runtime trajectory monitoring
    "TrajectoryMonitor",
    "TrajectorySession",
    "TrajectoryViolation",
    "InMemoryTrajectoryStore",
    "FrequencyThresholdRule",
    "CumulativeValueRule",
    "SensitiveToolSequenceRule",
    # Z3 formal verification
    "Z3ConstraintVerifier",
    "Z3VerifyResult",
    "Z3_AVAILABLE",
    "Z3_RISK_THRESHOLD",
    "VerificationStatus",
    "blocks_execution",
    "verification_exempt",
    "VerificationExemption",
    "ExemptionError",
    # Leanstral formal verification (Lean 4 proof certificates)
    "LeanstralVerifier",
    "LeanVerifyResult",
    "ProofCertificate",
    "MISTRAL_AVAILABLE",
    "LEAN_AVAILABLE",
    # OpenShell governance integration
    "ActionContext",
    "ActionEnvelope",
    "ActionPayloadSummary",
    "ActionRequirements",
    "ActionType",
    "ActorRef",
    "ActorRole",
    "ApprovalReviewRequest",
    "ApprovalReviewResponse",
    "ApprovalSubmission",
    "AuditEvent",
    "AuditEventType",
    "ComplianceResult",
    "ComplianceStatus",
    "DecisionType",
    "ExecutionOutcome",
    "ExternalRef",
    "GovernanceStateChecksumError",
    "GovernanceDecision",
    "GovernanceStateBackend",
    "GovernanceStateError",
    "GovernanceStateMigrationError",
    "GovernanceStateObservabilityHook",
    "GovernanceStateVersionError",
    "InMemoryGovernanceStateBackend",
    "JsonFileGovernanceStateBackend",
    "OperationType",
    "OutcomeStatus",
    "RedisGovernanceStateBackend",
    "ResourceRef",
    "RiskLevel",
    "SQLiteGovernanceStateBackend",
    "create_openshell_governance_app",
    "create_openshell_governance_router",
    # Errors
    "ConstitutionalViolationError",
    "GovernanceError",
    "MACIViolationError",
    "PolicyDeniedError",
    # Licensing
    "set_license",
    "LicenseInfo",
    "LicenseManager",
    "Tier",
    # Bundle stores
    "PostgresBundleStore",
    "SQLiteBundleStore",
    # API stability metadata
    "API_STABILITY",
    "stability",
]


# ── API stability layers ────────────────────────────────────────────────
# Public-API stability classification. Useful for downstream tooling that
# needs to know which exports are safe to depend on across minor versions.
#
# Layers:
#   "stable"       — semver-protected. Breaking changes only on major bumps.
#   "beta"         — feature-complete, but signature/behavior may shift in
#                    minor releases. Lifecycle, governance memory, spot-check.
#   "experimental" — may change or be removed without a deprecation cycle.
#                    Verification gates, formal-verification adapters, OpenShell.
#
# Anything not present in this map should be treated as "experimental" by
# downstream consumers until explicitly classified here.

_STABILITY_STABLE: frozenset[str] = frozenset(
    {
        # Constitutional model
        "Constitution",
        "ConstitutionBuilder",
        "Rule",
        "RuleSnapshot",
        "Severity",
        "ViolationAction",
        "AcknowledgedTension",
        # Engine surface
        "GovernanceEngine",
        "ValidationResult",
        "BatchValidationResult",
        # Governed wrappers
        "GovernedAgent",
        "GovernedCallable",
        # Audit
        "AuditLog",
        "AuditEntry",
        "AuditBackend",
        "InMemoryAuditBackend",
        "JSONLAuditBackend",
        # MACI separation of powers
        "MACIRole",
        "MACIEnforcer",
        # Errors
        "ConstitutionalViolationError",
        "GovernanceError",
        "MACIViolationError",
        "PolicyDeniedError",
        # Circuit breaker (Article 14 kill-switch)
        "GovernanceCircuitBreaker",
        "GovernanceHaltError",
        # Production readiness gates (fail-closed startup validation)
        "ProductionProfile",
        "ProductionProfileError",
        "ProductionProfileValidation",
        "validate_production_profile",
        # Trajectory monitoring (core rule types are stable)
        "TrajectoryMonitor",
        "TrajectorySession",
        "TrajectoryViolation",
        "InMemoryTrajectoryStore",
        "FrequencyThresholdRule",
        "CumulativeValueRule",
        "SensitiveToolSequenceRule",
        # Constants / metadata
        "CONSTITUTIONAL_HASH",
        "VERSION",
    }
)

_STABILITY_BETA: frozenset[str] = frozenset(
    {
        # Bundle lifecycle (week-3 spot-check / lifecycle)
        "ConstitutionBundle",
        "BundleStatus",
        "BundleStore",
        "InMemoryBundleStore",
        "PostgresBundleStore",
        "SQLiteBundleStore",
        "ActivationRecord",
        "ConstitutionLifecycle",
        "ConcurrentLifecycleError",
        "LifecycleError",
        "LifecycleEvidenceError",
        "LifecycleEvidenceRecord",
        "LifecycleAuditSink",
        "InMemoryLifecycleAuditSink",
        "TransitionRecord",
        "StatusTransition",
        # Spot-check + trust scoring
        "AuditPolicy",
        "CaseConfig",
        "CaseManager",
        "CaseRecord",
        "CaseState",
        "CompletedCase",
        "SelectionPolicy",
        "SelectionResult",
        "SpotCheckAuditor",
        "SpotCheckResult",
        "TrustAdjustment",
        "TrustConfig",
        "TrustEvent",
        "TrustScoreManager",
        "TrustTier",
        "ValidatorAssessment",
        "ValidatorProfile",
        "ValidatorPool",
        "ValidatorSelector",
        # Governance memory
        "GovernanceMemoryPrecedentHit",
        "GovernanceMemoryReport",
        "GovernanceMemoryRetriever",
        "GovernanceMemorySummary",
        # Provenance + event bus
        "ProvenanceRecord",
        "ProvenanceNode",
        "EventBus",
        "GovernanceEvent",
        "get_event_bus",
        # Scoring
        "ConstitutionalImpactScorer",
        "RuleBasedScorer",
        "score_impact",
        # Licensing
        "set_license",
        "LicenseInfo",
        "LicenseManager",
        "Tier",
        # Governed agent discovery (registry + selector)
        "AgentCapabilityProfile",
        "AgentRegistry",
        "AgentSelection",
        "GovernedAgentSelector",
        "NoEligibleAgentError",
        "SelectionDeniedError",
        "get_agent_registry",
        "reset_agent_registry",
        # Adaptive policy generation
        "AdaptivePolicyGenerator",
        "DomainRiskLevel",
        "GeneratedPolicy",
        "PolicyRequirement",
        "PolicyResearcher",
        "PreContext",
        "PreContextBuilder",
        "ResearchReport",
        # Execution authorization (in-process grants; production profile is opt-in)
        "AuthorizationProfile",
        "ExecutionGrant",
        "GrantResolver",
        "AsyncGrantResolver",
    }
)

_STABILITY_EXPERIMENTAL: frozenset[str] = frozenset(
    {
        # Verification gates
        "VerificationResult",
        "Z3VerificationGate",
        "NullVerificationGate",
        # Z3 formal verification
        "Z3ConstraintVerifier",
        "Z3VerifyResult",
        "Z3_AVAILABLE",
        "Z3_RISK_THRESHOLD",
        "VerificationStatus",
        "blocks_execution",
        "verification_exempt",
        "VerificationExemption",
        "ExemptionError",
        # Leanstral / Lean 4 proof certificates
        "LeanstralVerifier",
        "LeanVerifyResult",
        "ProofCertificate",
        "MISTRAL_AVAILABLE",
        "LEAN_AVAILABLE",
        # OpenShell governance integration (entire surface)
        "ActionContext",
        "ActionEnvelope",
        "ActionPayloadSummary",
        "ActionRequirements",
        "ActionType",
        "ActorRef",
        "ActorRole",
        "ApprovalReviewRequest",
        "ApprovalReviewResponse",
        "ApprovalSubmission",
        "AuditEvent",
        "AuditEventType",
        "ComplianceResult",
        "ComplianceStatus",
        "DecisionType",
        "ExecutionOutcome",
        "ExternalRef",
        "GovernanceStateChecksumError",
        "GovernanceDecision",
        "GovernanceStateBackend",
        "GovernanceStateError",
        "GovernanceStateMigrationError",
        "GovernanceStateObservabilityHook",
        "GovernanceStateVersionError",
        "InMemoryGovernanceStateBackend",
        "JsonFileGovernanceStateBackend",
        "OperationType",
        "OutcomeStatus",
        "RedisGovernanceStateBackend",
        "ResourceRef",
        "RiskLevel",
        "SQLiteGovernanceStateBackend",
        "create_openshell_governance_app",
        "create_openshell_governance_router",
        # RuleSynthesisProvider (still maturing)
        "RuleSynthesisProvider",
    }
)

API_STABILITY: dict[str, str] = {
    **{name: "stable" for name in _STABILITY_STABLE},
    **{name: "beta" for name in _STABILITY_BETA},
    **{name: "experimental" for name in _STABILITY_EXPERIMENTAL},
}


def stability(name: str) -> str:
    """Return the stability layer for a public export.

    :param name: A symbol name from ``acgs_lite.__all__``.
    :returns: ``"stable"``, ``"beta"``, or ``"experimental"``. Unclassified
        symbols default to ``"experimental"`` so downstream callers err on
        the side of caution.
    """
    return API_STABILITY.get(name, "experimental")


def __getattr__(name: str) -> object:
    if name in _LAZY_EXPORTS:
        module_name, attr_name, install_hint = _LAZY_EXPORTS[name]
        try:
            from importlib import import_module

            value = getattr(import_module(module_name), attr_name)
        except ImportError as exc:
            raise ImportError(
                f"acgs_lite.{name!r} requires optional dependencies. Install with: {install_hint}"
            ) from exc
        globals()[name] = value
        return value
    if name in _MISSING_OPTIONAL:
        raise ImportError(
            f"acgs_lite.{name!r} requires optional dependencies. "
            f"Install with: {_MISSING_OPTIONAL[name]}"
        )
    raise AttributeError(f"module 'acgs_lite' has no attribute {name!r}")


# Filter __all__ so `from acgs_lite import *` only advertises symbols that are
# actually resolvable in this installation. Optional symbols missing from the
# install stay accessible via explicit import (with a helpful ImportError hint
# from __getattr__), but are not emitted by star-import.
__all__ = [n for n in __all__ if n not in _MISSING_OPTIONAL]
