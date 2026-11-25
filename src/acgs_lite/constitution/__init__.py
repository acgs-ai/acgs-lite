"""ACGS-Lite Constitution package — governance rule definitions and analysis.

Eagerly loads hot-path-critical types (Constitution, Rule, Severity, etc.).
All other symbols are lazy-loaded via ``_LAZY_REGISTRY`` on first access.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from .analytics import (
    _KW_NEGATIVE_RE,
    _NEGATIVE_VERBS_LIST,
    _NEGATIVE_VERBS_RE,
    _POSITIVE_VERBS_SET,
    classify_action_intent,
    governance_decision_report,
    score_context_risk,
)
from .core import AcknowledgedTension, Constitution, Rule, RuleSynthesisProvider, Severity

if TYPE_CHECKING:
    from .abac import (
        CLASS_CONFIDENTIAL as CLASS_CONFIDENTIAL,
    )
    from .abac import (
        CLASS_INTERNAL as CLASS_INTERNAL,
    )
    from .abac import (
        CLASS_PHI as CLASS_PHI,
    )
    from .abac import (
        CLASS_PII as CLASS_PII,
    )
    from .abac import (
        CLASS_PUBLIC as CLASS_PUBLIC,
    )
    from .abac import (
        CLASS_SECRET as CLASS_SECRET,
    )
    from .abac import (
        CLASS_TOP_SECRET as CLASS_TOP_SECRET,
    )
    from .abac import (
        REGION_APAC as REGION_APAC,
    )
    from .abac import (
        REGION_EU as REGION_EU,
    )
    from .abac import (
        REGION_GLOBAL as REGION_GLOBAL,
    )
    from .abac import (
        REGION_UK as REGION_UK,
    )
    from .abac import (
        REGION_US as REGION_US,
    )
    from .abac import (
        RISK_CRITICAL as RISK_CRITICAL,
    )
    from .abac import (
        RISK_HIGH as RISK_HIGH,
    )
    from .abac import (
        RISK_LOW as RISK_LOW,
    )
    from .abac import (
        RISK_MEDIUM as RISK_MEDIUM,
    )
    from .abac import (
        TIER_AUTONOMOUS as TIER_AUTONOMOUS,
    )
    from .abac import (
        TIER_PRIVILEGED as TIER_PRIVILEGED,
    )
    from .abac import (
        TIER_RESTRICTED as TIER_RESTRICTED,
    )
    from .abac import (
        TIER_STANDARD as TIER_STANDARD,
    )
    from .abac import (
        EvaluationContext as EvaluationContext,
    )
    from .autonomy_ratio import (
        ActionCommitment as ActionCommitment,
    )
    from .autonomy_ratio import (
        CommitmentRatioState as CommitmentRatioState,
    )
    from .autonomy_ratio import (
        CommitmentRatioTracker as CommitmentRatioTracker,
    )
    from .autonomy_ratio import (
        classify_action as classify_action,
    )
    from .boundaries import (
        BoundaryViolation as BoundaryViolation,
    )
    from .boundaries import (
        PolicyBoundary as PolicyBoundary,
    )
    from .boundaries import (
        PolicyBoundarySet as PolicyBoundarySet,
    )
    from .deduplication import (
        DuplicationReport as DuplicationReport,
    )
    from .deduplication import (
        ExactDuplicateGroup as ExactDuplicateGroup,
    )
    from .deduplication import (
        NearDuplicatePair as NearDuplicatePair,
    )
    from .deduplication import (
        SubsetRedundancy as SubsetRedundancy,
    )
    from .deduplication import (
        deduplicate as deduplicate,
    )
    from .deduplication import (
        find_duplicates as find_duplicates,
    )
    from .intent_alignment import (
        ActionAlignmentRecord as ActionAlignmentRecord,
    )
    from .intent_alignment import (
        IntentAlignmentState as IntentAlignmentState,
    )
    from .intent_alignment import (
        IntentAlignmentTracker as IntentAlignmentTracker,
    )
    from .intent_alignment import (
        IntentProfile as IntentProfile,
    )
    from .interpolation import (
        context_coverage as context_coverage,
    )
    from .interpolation import (
        extract_placeholders as extract_placeholders,
    )
    from .interpolation import (
        render_constitution as render_constitution,
    )
    from .interpolation import (
        render_rule as render_rule,
    )
    from .interpolation import (
        render_text as render_text,
    )
    from .interpolation import (
        validate_context_schema as validate_context_schema,
    )
    from .memoization import (
        CacheStats as CacheStats,
    )
    from .memoization import (
        MemoizedConstitution as MemoizedConstitution,
    )
    from .metrics import (
        AuditEntry as AuditEntry,
    )
    from .metrics import (
        AuditLedger as AuditLedger,
    )
    from .metrics import (
        GovernanceCostModel as GovernanceCostModel,
    )
    from .metrics import (
        GovernanceEvent as GovernanceEvent,
    )
    from .metrics import (
        GovernanceForecaster as GovernanceForecaster,
    )
    from .metrics import (
        GovernanceMetrics as GovernanceMetrics,
    )
    from .metrics import (
        GovernanceSession as GovernanceSession,
    )
    from .metrics import (
        GovernanceSLO as GovernanceSLO,
    )
    from .metrics import (
        RuleEffectiveness as RuleEffectiveness,
    )
    from .metrics import (
        create_governance_event as create_governance_event,
    )
    from .obligation_engine import (
        ObligationEngine as ObligationEngine,
    )
    from .obligation_engine import (
        ObligationRecord as ObligationRecord,
    )
    from .obligation_engine import (
        ObligationSpec as ObligationSpec,
    )
    from .obligation_engine import (
        ObligationStatus as ObligationStatus,
    )
    from .routing import GovernanceRouter as GovernanceRouter
    from .snapshot import (
        ConstitutionSnapshot as ConstitutionSnapshot,
    )
    from .snapshot import (
        capture_snapshot as capture_snapshot,
    )
    from .templates import ConstitutionBuilder as ConstitutionBuilder
    from .versioning import (
        ChangelogEntry as ChangelogEntry,
    )
    from .versioning import (
        GovernanceChangelog as GovernanceChangelog,
    )
    from .versioning import (
        RuleSnapshot as RuleSnapshot,
    )
    from .weighted_policy import (
        RulePenalty as RulePenalty,
    )
    from .weighted_policy import (
        WeightedConstitution as WeightedConstitution,
    )
    from .weighted_policy import (
        WeightedEvaluationResult as WeightedEvaluationResult,
    )

# ── Declarative lazy-load registry ────────────────────────────────────────────
# Maps symbol_name → (module_name, domain).
# __getattr__ imports the module on first access.
# To add a new symbol: add ONE line to this dict. That's it.
#
# Domains organise 80 modules into 5 virtual sub-packages:
#   core        — Foundation types, rule definitions, builders, ABAC
#   lifecycle   — Policy versioning, amendments, migration, rollout, export
#   enforcement — Runtime enforcement, access control, trust, delegation
#   monitoring  — Metrics, behavioral tracking, observability, anomaly detection
#   analysis    — Quality analysis, simulation, compliance, reporting

_LAZY_REGISTRY: dict[str, tuple[str, str]] = {
    # ── core (lazy builders, ABAC, rendering, memoization) ────────────────
    "EvaluationContext": ("abac", "core"),
    "TIER_RESTRICTED": ("abac", "core"),
    "TIER_STANDARD": ("abac", "core"),
    "TIER_PRIVILEGED": ("abac", "core"),
    "TIER_AUTONOMOUS": ("abac", "core"),
    "CLASS_PUBLIC": ("abac", "core"),
    "CLASS_INTERNAL": ("abac", "core"),
    "CLASS_CONFIDENTIAL": ("abac", "core"),
    "CLASS_PII": ("abac", "core"),
    "CLASS_PHI": ("abac", "core"),
    "CLASS_SECRET": ("abac", "core"),
    "CLASS_TOP_SECRET": ("abac", "core"),
    "REGION_EU": ("abac", "core"),
    "REGION_US": ("abac", "core"),
    "REGION_UK": ("abac", "core"),
    "REGION_APAC": ("abac", "core"),
    "REGION_GLOBAL": ("abac", "core"),
    "RISK_LOW": ("abac", "core"),
    "RISK_MEDIUM": ("abac", "core"),
    "RISK_HIGH": ("abac", "core"),
    "RISK_CRITICAL": ("abac", "core"),
    "ConstitutionBuilder": ("templates", "core"),
    "ConstitutionSnapshot": ("snapshot", "core"),
    "capture_snapshot": ("snapshot", "core"),
    "render_text": ("interpolation", "core"),
    "render_rule": ("interpolation", "core"),
    "render_constitution": ("interpolation", "core"),
    "extract_placeholders": ("interpolation", "core"),
    "context_coverage": ("interpolation", "core"),
    "validate_context_schema": ("interpolation", "core"),
    "MemoizedConstitution": ("memoization", "core"),
    "CacheStats": ("memoization", "core"),
    "WeightedConstitution": ("weighted_policy", "core"),
    "WeightedEvaluationResult": ("weighted_policy", "core"),
    "RulePenalty": ("weighted_policy", "core"),
    "BoundaryViolation": ("boundaries", "enforcement"),
    "PolicyBoundary": ("boundaries", "enforcement"),
    "PolicyBoundarySet": ("boundaries", "enforcement"),
    "GovernanceRouter": ("routing", "enforcement"),
    "ObligationEngine": ("obligation_engine", "enforcement"),
    "ObligationSpec": ("obligation_engine", "enforcement"),
    "ObligationRecord": ("obligation_engine", "enforcement"),
    "ObligationStatus": ("obligation_engine", "enforcement"),
    "RuleSnapshot": ("versioning", "lifecycle"),
    "ChangelogEntry": ("versioning", "lifecycle"),
    "GovernanceChangelog": ("versioning", "lifecycle"),
    "CommitmentRatioTracker": ("autonomy_ratio", "monitoring"),
    "CommitmentRatioState": ("autonomy_ratio", "monitoring"),
    "ActionCommitment": ("autonomy_ratio", "monitoring"),
    "classify_action": ("autonomy_ratio", "monitoring"),
    "IntentAlignmentTracker": ("intent_alignment", "monitoring"),
    "IntentProfile": ("intent_alignment", "monitoring"),
    "ActionAlignmentRecord": ("intent_alignment", "monitoring"),
    "IntentAlignmentState": ("intent_alignment", "monitoring"),
    "GovernanceEvent": ("metrics", "monitoring"),
    "create_governance_event": ("metrics", "monitoring"),
    "GovernanceMetrics": ("metrics", "monitoring"),
    "GovernanceSLO": ("metrics", "monitoring"),
    "GovernanceCostModel": ("metrics", "monitoring"),
    "GovernanceForecaster": ("metrics", "monitoring"),
    "GovernanceSession": ("metrics", "monitoring"),
    "RuleEffectiveness": ("metrics", "monitoring"),
    "AuditEntry": ("metrics", "monitoring"),
    "AuditLedger": ("metrics", "monitoring"),
    "find_duplicates": ("deduplication", "analysis"),
    "deduplicate": ("deduplication", "analysis"),
    "DuplicationReport": ("deduplication", "analysis"),
    "ExactDuplicateGroup": ("deduplication", "analysis"),
    "SubsetRedundancy": ("deduplication", "analysis"),
    "NearDuplicatePair": ("deduplication", "analysis"),
    # ── editor ─────────────────────────────────────────────────────────
    "RuleDraft": ("editor", "lifecycle"),
    "ConstitutionDiff": ("editor", "lifecycle"),
    "ConstitutionVersion": ("editor", "lifecycle"),
    "ConstitutionEditor": ("editor", "lifecycle"),
    "ConstitutionVersionControl": ("editor", "lifecycle"),
    "merge_constitutions": ("editor", "lifecycle"),
    # ── lifecycle ─────────────────────────────────────────────────────────
    "Amendment": ("amendments", "lifecycle"),
    "AmendmentProtocol": ("amendments", "lifecycle"),
    "AmendmentStatus": ("amendments", "lifecycle"),
    "AmendmentType": ("amendments", "lifecycle"),
    "Vote": ("amendments", "lifecycle"),
    "DecisionFlip": ("rollout", "lifecycle"),
    "RolloutStage": ("rollout", "lifecycle"),
    "RolloutStageMetrics": ("rollout", "lifecycle"),
    "PolicyRolloutPipeline": ("rollout", "lifecycle"),
    "BundleStatus": ("bundle", "lifecycle"),
    "ConstitutionBundle": ("bundle", "lifecycle"),
    "StatusTransition": ("bundle", "lifecycle"),
    "VALID_TRANSITIONS": ("bundle", "lifecycle"),
    "ActivationRecord": ("activation", "lifecycle"),
    "BundleStore": ("bundle_store", "lifecycle"),
    "InMemoryBundleStore": ("bundle_store", "lifecycle"),
    "SQLiteBundleStore": ("sqlite_bundle_store", "lifecycle"),
    "PolicyWaiver": ("waivers", "lifecycle"),
    "WaiverRegistry": ("waivers", "lifecycle"),
    "WaiverStatus": ("waivers", "lifecycle"),
    "PolicyVersionMigrator": ("migration", "lifecycle"),
    "MigrationPlan": ("migration", "lifecycle"),
    "MigrationResult": ("migration", "lifecycle"),
    "MigrationStatus": ("migration", "lifecycle"),
    "RuleMigrationStep": ("migration", "lifecycle"),
    "RuleAction": ("migration", "lifecycle"),
    "PolicyLifecycleOrchestrator": ("policy_lifecycle", "lifecycle"),
    "ManagedPolicy": ("policy_lifecycle", "lifecycle"),
    "PolicyState": ("policy_lifecycle", "lifecycle"),
    "LifecycleGate": ("policy_lifecycle", "lifecycle"),
    "GateType": ("policy_lifecycle", "lifecycle"),
    "TransitionResult": ("policy_lifecycle", "lifecycle"),
    "RolloutPlan": ("policy_lifecycle", "lifecycle"),
    "TransitionRecord": ("policy_lifecycle", "lifecycle"),
    "OrchestratorTransitionResult": ("policy_lifecycle", "lifecycle"),
    "GateEvaluation": ("policy_lifecycle", "lifecycle"),
    "PolicyExporter": ("policy_export", "lifecycle"),
    "GovernanceFeatureFlag": ("feature_flag", "lifecycle"),
    "FlagManager": ("feature_flag", "lifecycle"),
    "FlagStatus": ("feature_flag", "lifecycle"),
    "FlagChangeEvent": ("feature_flag", "lifecycle"),
    "ChangeRequestManager": ("change_request", "lifecycle"),
    "ChangeRequest": ("change_request", "lifecycle"),
    "ChangeRequestStatus": ("change_request", "lifecycle"),
    "ChangeType": ("change_request", "lifecycle"),
    "ChangeRequestEvent": ("change_request", "lifecycle"),
    "TagRegistry": ("tags", "lifecycle"),
    "TagStats": ("tags", "lifecycle"),
    "RuleTemplate": ("rule_template", "lifecycle"),
    "RuleTemplateRegistry": ("rule_template", "lifecycle"),
    "InstantiationRecord": ("rule_template", "lifecycle"),
    "GovernanceAttestation": ("attestation", "lifecycle"),
    "AttestationRegistry": ("attestation", "lifecycle"),
    "LifecycleEvidenceRecord": ("evidence", "lifecycle"),
    "LifecycleAuditReceipt": ("evidence", "lifecycle"),
    "LifecycleAuditSink": ("evidence", "lifecycle"),
    "LifecycleAuditSinkError": ("evidence", "lifecycle"),
    "InMemoryLifecycleAuditSink": ("evidence", "lifecycle"),
    "ConstitutionLifecycle": ("lifecycle_service", "lifecycle"),
    "LifecycleError": ("lifecycle_service", "lifecycle"),
    "ConcurrentLifecycleError": ("lifecycle_service", "lifecycle"),
    "LifecycleEvidenceError": ("lifecycle_service", "lifecycle"),
    "SelfEvolutionConfig": ("self_evolution", "lifecycle"),
    "SelfEvolutionEngine": ("self_evolution", "lifecycle"),
    "SelfEvolutionReport": ("self_evolution", "lifecycle"),
    "EvolutionCandidate": ("self_evolution", "lifecycle"),
    "EvolutionEvidence": ("self_evolution", "lifecycle"),
    "CandidateGateResult": ("self_evolution", "lifecycle"),
    "EvolutionGateReport": ("self_evolution", "lifecycle"),
    # ── enforcement ───────────────────────────────────────────────────────
    "PolicyDecisionPoint": ("enforcement", "enforcement"),
    "PolicyEnforcementPoint": ("enforcement", "enforcement"),
    "PolicyDecision": ("enforcement", "enforcement"),
    "EnforcementResult": ("enforcement", "enforcement"),
    "EnforcementPolicy": ("enforcement", "enforcement"),
    "EnforcementAction": ("enforcement", "enforcement"),
    "DecisionOutcome": ("enforcement", "enforcement"),
    "PEPNetwork": ("enforcement", "enforcement"),
    "GraduatedEnforcer": ("graduated_enforcement", "enforcement"),
    "EnforcementLevel": ("graduated_enforcement", "enforcement"),
    "EscalationPolicy": ("graduated_enforcement", "enforcement"),
    "ViolationRecord": ("graduated_enforcement", "enforcement"),
    "EscalationEvent": ("graduated_enforcement", "enforcement"),
    "GovernanceEmergencyOverride": ("emergency", "enforcement"),
    "EmergencyOverride": ("emergency", "enforcement"),
    "OverridePolicy": ("emergency", "enforcement"),
    "OverrideScope": ("emergency", "enforcement"),
    "OverrideStatus": ("emergency", "enforcement"),
    "GovernanceCircuitBreaker": ("circuit_breaker", "enforcement"),
    "CircuitBreakerPolicy": ("circuit_breaker", "enforcement"),
    "CircuitState": ("circuit_breaker", "enforcement"),
    "CircuitEvent": ("circuit_breaker", "enforcement"),
    "FallbackPolicy": ("circuit_breaker", "enforcement"),
    "GovernanceRateLimiter": ("ratelimit", "enforcement"),
    "RateLimitPolicy": ("ratelimit", "enforcement"),
    "RateLimitResult": ("ratelimit", "enforcement"),
    "RateLimitAction": ("ratelimit", "enforcement"),
    "AutonomySphere": ("guardian", "enforcement"),
    "GuardianGate": ("guardian", "enforcement"),
    "QuarantinedAction": ("quarantine", "enforcement"),
    "GovernanceQuarantine": ("quarantine", "enforcement"),
    "QuarantineStatus": ("quarantine", "enforcement"),
    "TimeoutPolicy": ("quarantine", "enforcement"),
    "GovernanceEscrow": ("escrow", "enforcement"),
    "EscrowedAction": ("escrow", "enforcement"),
    "EscrowPolicy": ("escrow", "enforcement"),
    "EscrowApproval": ("escrow", "enforcement"),
    "EscrowStatus": ("escrow", "enforcement"),
    "TimeoutAction": ("escrow", "enforcement"),
    "PolicySandbox": ("sandbox", "enforcement"),
    "SandboxReport": ("sandbox", "enforcement"),
    "SandboxOutcome": ("sandbox", "enforcement"),
    "GovernanceAccessControl": ("access_control", "enforcement"),
    "AccessPolicy": ("access_control", "enforcement"),
    "AccessRole": ("access_control", "enforcement"),
    "AccessCondition": ("access_control", "enforcement"),
    "AccessCheckResult": ("access_control", "enforcement"),
    "AccessDecision": ("access_control", "enforcement"),
    "Permission": ("access_control", "enforcement"),
    "ConsentManager": ("consent", "enforcement"),
    "ConsentRecord": ("consent", "enforcement"),
    "ConsentStatus": ("consent", "enforcement"),
    "LawfulBasis": ("consent", "enforcement"),
    "DataSubjectRight": ("consent", "enforcement"),
    "RightsRequest": ("consent", "enforcement"),
    "ContractTerm": ("contracts", "enforcement"),
    "GovernanceContract": ("contracts", "enforcement"),
    "ContractRegistry": ("contracts", "enforcement"),
    "ContractStatus": ("contracts", "enforcement"),
    "BreachRecord": ("contracts", "enforcement"),
    "BreachSeverity": ("contracts", "enforcement"),
    "DisputeResolution": ("contracts", "enforcement"),
    "VerifiableDelegationToken": ("delegation_token", "enforcement"),
    "DelegationTokenAuthority": ("delegation_token", "enforcement"),
    "DelegationScope": ("delegation_token", "enforcement"),
    "VerificationResult": ("delegation_token", "enforcement"),
    "TokenStatus": ("delegation_token", "enforcement"),
    "InterAgentGovernanceProtocol": ("interagent_protocol", "enforcement"),
    "DelegationLink": ("interagent_protocol", "enforcement"),
    "DelegationChain": ("interagent_protocol", "enforcement"),
    "DelegationResult": ("interagent_protocol", "enforcement"),
    "AuthorizationResult": ("interagent_protocol", "enforcement"),
    "TrustScoreManager": ("trust_score", "enforcement"),
    "TrustConfig": ("trust_score", "enforcement"),
    "TrustEvent": ("trust_score", "enforcement"),
    "TrustTier": ("trust_score", "enforcement"),
    "PolicyBallot": ("voting", "enforcement"),
    "CondorcetVoting": ("voting", "enforcement"),
    "BallotStatus": ("voting", "enforcement"),
    "QuorumManager": ("quorum", "enforcement"),
    "GateState": ("quorum", "enforcement"),
    "GateStatus": ("quorum", "enforcement"),
    "VoteRecord": ("quorum", "enforcement"),
    "SpotCheckAuditor": ("spot_check", "enforcement"),
    "AuditPolicy": ("spot_check", "enforcement"),
    "SpotCheckResult": ("spot_check", "enforcement"),
    "TrustAdjustment": ("spot_check", "enforcement"),
    "ValidatorProfile": ("spot_check", "enforcement"),
    "CaseManager": ("claim_lifecycle", "enforcement"),
    "CaseConfig": ("claim_lifecycle", "enforcement"),
    "CaseRecord": ("claim_lifecycle", "enforcement"),
    "CaseState": ("claim_lifecycle", "enforcement"),
    "ValidatorPool": ("validator_selection", "enforcement"),
    "ValidatorSelector": ("validator_selection", "enforcement"),
    "SelectionPolicy": ("validator_selection", "enforcement"),
    "SelectionResult": ("validator_selection", "enforcement"),
    "SelectionProof": ("validator_selection", "enforcement"),
    "ValidatorInfo": ("validator_selection", "enforcement"),
    # ── monitoring ────────────────────────────────────────────────────────
    "NearMissRecord": ("nearmiss", "monitoring"),
    "NearMissTracker": ("nearmiss", "monitoring"),
    "DriftSignal": ("drift", "monitoring"),
    "GovernanceDriftDetector": ("drift", "monitoring"),
    "GovernanceAnomalyDetector": ("anomaly", "monitoring"),
    "AnomalySignal": ("anomaly", "monitoring"),
    "GovernanceObservabilityExporter": ("observability_exporter", "monitoring"),
    "MetricPoint": ("observability_exporter", "monitoring"),
    "HistogramMetric": ("observability_exporter", "monitoring"),
    "HistogramBucket": ("observability_exporter", "monitoring"),
    "DecisionTrace": ("observability_exporter", "monitoring"),
    "SLAManager": ("sla", "monitoring"),
    "SLATarget": ("sla", "monitoring"),
    "SLAMetricType": ("sla", "monitoring"),
    "SLAObservation": ("sla", "monitoring"),
    "SLABreach": ("sla", "monitoring"),
    "CostBudgetManager": ("cost_budget", "monitoring"),
    "CostBudget": ("cost_budget", "monitoring"),
    "UsageRecord": ("cost_budget", "monitoring"),
    "RecordStatus": ("cost_budget", "monitoring"),
    "ResetPeriod": ("cost_budget", "monitoring"),
    "BudgetBreach": ("cost_budget", "monitoring"),
    "IncidentManager": ("incident", "monitoring"),
    "Incident": ("incident", "monitoring"),
    "IncidentSeverity": ("incident", "monitoring"),
    "IncidentPhase": ("incident", "monitoring"),
    "TimelineEntry": ("incident", "monitoring"),
    "GovernanceNotificationBus": ("notification", "monitoring"),
    "GovernanceNotification": ("notification", "monitoring"),
    "Subscriber": ("notification", "monitoring"),
    "DeliveryRecord": ("notification", "monitoring"),
    "NotificationPriority": ("notification", "monitoring"),
    "DeliveryStatus": ("notification", "monitoring"),
    "GovernanceMetadataStore": ("metadata_store", "monitoring"),
    "MetadataEntry": ("metadata_store", "monitoring"),
    "MetadataDiff": ("metadata_store", "monitoring"),
    "MetadataScope": ("metadata_store", "monitoring"),
    "CausalChainTracker": ("causal_chain", "monitoring"),
    "ChainPattern": ("causal_chain", "monitoring"),
    "ChainStep": ("causal_chain", "monitoring"),
    "ChainMatch": ("causal_chain", "monitoring"),
    "ChainAlert": ("causal_chain", "monitoring"),
    "ChainCheckResult": ("causal_chain", "monitoring"),
    "builtin_patterns": ("causal_chain", "monitoring"),
    "SessionContractTracker": ("session_contract", "monitoring"),
    "BehaviorContract": ("session_contract", "monitoring"),
    "ContractDivergence": ("session_contract", "monitoring"),
    "ContractCheckResult": ("session_contract", "monitoring"),
    "SessionReport": ("session_contract", "monitoring"),
    "DivergenceType": ("session_contract", "monitoring"),
    "Obligation": ("obligations", "monitoring"),
    "ObligationSet": ("obligations", "monitoring"),
    "ObligationPredictor": ("obligation_prediction", "monitoring"),
    "ObligationState": ("obligation_prediction", "monitoring"),
    "BreachPrediction": ("obligation_prediction", "monitoring"),
    "PortfolioRisk": ("obligation_prediction", "monitoring"),
    # ── analysis ──────────────────────────────────────────────────────────
    "GovernanceTestCase": ("testing", "analysis"),
    "TestCaseFailure": ("testing", "analysis"),
    "TestSuiteResult": ("testing", "analysis"),
    "BehavioralConsistencyCase": ("testing", "analysis"),
    "BehavioralConsistencyFinding": ("testing", "analysis"),
    "BehavioralConsistencyReport": ("testing", "analysis"),
    "BehavioralConsistencyAuditor": ("testing", "analysis"),
    "GovernanceTestSuite": ("testing", "analysis"),
    "GovernanceEngineFn": ("test_suite", "analysis"),
    "AssertionResult": ("test_suite", "analysis"),
    "TestReport": ("test_suite", "analysis"),
    "TestOutcome": ("test_suite", "analysis"),
    "RuleMetrics": ("rule_metrics", "analysis"),
    "ScenarioOutcomeMetrics": ("rule_metrics", "analysis"),
    "EvalReport": ("rule_metrics", "analysis"),
    "compute_eval_report": ("rule_metrics", "analysis"),
    "SimulationResult": ("simulation", "analysis"),
    "SimulationReport": ("simulation", "analysis"),
    "simulate_constitution_change": ("simulation", "analysis"),
    "DecisionDelta": ("counterfactual", "analysis"),
    "CounterfactualReport": ("counterfactual", "analysis"),
    "CounterfactualGovernance": ("counterfactual", "analysis"),
    "GovernancePolicySimulator": ("policy_simulator", "analysis"),
    "ActionDelta": ("policy_simulator", "analysis"),
    "CandidateReport": ("policy_simulator", "analysis"),
    "SimulationComparisonReport": ("policy_simulator", "analysis"),
    "GovernancePolicyFuzzer": ("policy_fuzzer", "analysis"),
    "FuzzCase": ("policy_fuzzer", "analysis"),
    "FuzzReport": ("policy_fuzzer", "analysis"),
    "RuleCoverage": ("policy_fuzzer", "analysis"),
    "PolicyLinter": ("policy_linter", "analysis"),
    "LintReport": ("policy_linter", "analysis"),
    "LintIssue": ("policy_linter", "analysis"),
    "LintSeverity": ("policy_linter", "analysis"),
    "LintCode": ("policy_linter", "analysis"),
    "RuleCoverageResult": ("subsumption", "analysis"),
    "SubsumptionReport": ("subsumption", "analysis"),
    "CrossConstitutionCompliance": ("subsumption", "analysis"),
    "RuleProvenanceGraph": ("provenance", "analysis"),
    "ProvenanceEdge": ("provenance", "analysis"),
    "ProvenanceRelation": ("provenance", "analysis"),
    "RuleNode": ("provenance", "analysis"),
    "GovernanceReplay": ("replay", "analysis"),
    "ReplayReport": ("replay", "analysis"),
    "ReplayedDecision": ("replay", "analysis"),
    "HistoricalDecision": ("replay", "analysis"),
    "ComplianceCertificate": ("certificate", "analysis"),
    "CertificateAuthority": ("certificate", "analysis"),
    "CertificateStatus": ("certificate", "analysis"),
    "ComplianceMapper": ("compliance_mapping", "analysis"),
    "RegulatoryFramework": ("compliance_mapping", "analysis"),
    "ControlMapping": ("compliance_mapping", "analysis"),
    "CoverageGap": ("compliance_mapping", "analysis"),
    "RegulatoryHorizonScanner": ("regulatory_scanner", "analysis"),
    "RegulatoryRequirement": ("regulatory_scanner", "analysis"),
    "RegulatoryFrameworkVersion": ("regulatory_scanner", "analysis"),
    "RuleMappingEntry": ("regulatory_scanner", "analysis"),
    "CoverageGapItem": ("regulatory_scanner", "analysis"),
    "RemediationTicket": ("regulatory_scanner", "analysis"),
    "ScanReport": ("regulatory_scanner", "analysis"),
    "DataClassifier": ("data_classification", "analysis"),
    "SensitivityLevel": ("data_classification", "analysis"),
    "HandlingRequirement": ("data_classification", "analysis"),
    "ClassificationPolicy": ("data_classification", "analysis"),
    "ClassificationResult": ("data_classification", "analysis"),
    "ClassificationAuditEntry": ("data_classification", "analysis"),
    "RetentionManager": ("retention", "analysis"),
    "RetentionPolicy": ("retention", "analysis"),
    "RetentionCategory": ("retention", "analysis"),
    "RetentionStatus": ("retention", "analysis"),
    "RetainedArtifact": ("retention", "analysis"),
    "PurgeRecord": ("retention", "analysis"),
    "GovernanceDecisionExplainer": ("decision_explainer", "analysis"),
    "DecisionExplanation": ("decision_explainer", "analysis"),
    "RuleSummary": ("decision_explainer", "analysis"),
    "ExplanationDetail": ("decision_explainer", "analysis"),
    "ExplanationFormat": ("decision_explainer", "analysis"),
    "RefusalReasoningEngine": ("refusal_reasoning", "analysis"),
    "RefusalDecision": ("refusal_reasoning", "analysis"),
    "RefusalReason": ("refusal_reasoning", "analysis"),
    "RefusalSuggestion": ("refusal_reasoning", "analysis"),
    "SemanticRuleSearch": ("semantic_search", "analysis"),
    "GovernanceMemoryPrecedentHit": ("governance_memory", "analysis"),
    "GovernanceMemorySummary": ("governance_memory", "analysis"),
    "GovernanceMemoryReport": ("governance_memory", "analysis"),
    "GovernanceMemoryRetriever": ("governance_memory", "analysis"),
}

# Submodules that were historically accessible as attributes on acgs_lite.constitution
# immediately after import; resolved lazily on first attribute access and cached in globals().
_LAZY_SUBMODULES: frozenset[str] = frozenset(
    {
        "abac",
        "activation",
        "autonomy_ratio",
        "boundaries",
        "bundle",
        "claim_lifecycle",
        "comparison",
        "conflict_resolution",
        "coverage_analysis",
        "deduplication",
        "dependency_analysis",
        "diffing",
        "editor",
        "evidence",
        "experience_library",
        "filtering",
        "governance_memory",
        "intent_alignment",
        "interpolation",
        "lifecycle",
        "memoization",
        "merging",
        "metrics",
        "obligation_engine",
        "permission_ceiling",
        "provenance",
        "refusal_reasoning",
        "regulatory",
        "rendering",
        "reporting",
        "routing",
        "semantic_search",
        "serialization",
        "similarity",
        "snapshot",
        "spot_check",
        "templates",
        "trust_score",
        "validator_selection",
        "versioning",
        "weighted_policy",
        "workflow_analytics",
    }
)

# Module cache to avoid repeated importlib calls
_MODULE_CACHE: dict[str, Any] = {}


def __getattr__(name: str) -> object:
    entry = _LAZY_REGISTRY.get(name)
    if entry is not None:
        module_name = entry[0]
        mod = _MODULE_CACHE.get(module_name)
        if mod is None:
            mod = importlib.import_module(f".{module_name}", __name__)
            _MODULE_CACHE[module_name] = mod
        value = getattr(mod, name)
        globals()[name] = value
        return value
    if name in _LAZY_SUBMODULES:
        mod = _MODULE_CACHE.get(name)
        if mod is None:
            mod = importlib.import_module(f".{name}", __name__)
            _MODULE_CACHE[name] = mod
        globals()[name] = mod
        return mod
    raise AttributeError(name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__) | _LAZY_SUBMODULES)


def modules_by_domain(domain: str | None = None) -> dict[str, list[str]]:
    """Return module names grouped by domain. Pass domain='lifecycle' etc. to filter."""
    grouped: dict[str, set[str]] = {}
    for _sym, (mod, dom) in _LAZY_REGISTRY.items():
        if domain and dom != domain:
            continue
        grouped.setdefault(dom, set()).add(mod)
    return {d: sorted(mods) for d, mods in sorted(grouped.items())}


__all__ = [
    # eagerly loaded — core types
    "Severity",
    "Rule",
    "RuleSynthesisProvider",
    "AcknowledgedTension",
    "Constitution",
    "classify_action_intent",
    "score_context_risk",
    "governance_decision_report",
    "_NEGATIVE_VERBS_LIST",
    "_NEGATIVE_VERBS_RE",
    "_POSITIVE_VERBS_SET",
    "_KW_NEGATIVE_RE",
    # lazy-loaded — all registry symbols
    *_LAZY_REGISTRY.keys(),
]
