"""End-to-end tests for ACGS-Lite constitutional governance.

Tests critical user journeys through the full governance stack:
1. Constitution loading + GovernedAgent + validation + audit trail
2. MACI separation of powers enforcement
3. Constitutional hash integrity across all paths
4. Engine backend fallback (Rust unavailable -> Python)
5. EU AI Act risk classification end-to-end
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine import GovernanceEngine, ValidationResult
from acgs_lite.errors import ConstitutionalViolationError, MACIViolationError
from acgs_lite.eu_ai_act.risk_classification import (
    RiskClassifier,
    RiskLevel,
    SystemDescription,
)
from acgs_lite.governed import GovernedAgent
from acgs_lite.maci import (
    MACIEnforcer,
    MACIRole,
    recommend_escalation,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

EXAMPLE_CONSTITUTION_PATH = (
    Path(__file__).resolve().parent.parent / "examples" / "constitution.yaml"
)

MINIMAL_CONSTITUTION_YAML = """\
name: e2e-test-governance
version: "2.0.0"
description: Minimal constitution for E2E testing

rules:
  - id: E2E-001
    text: Agents must not expose PII
    severity: critical
    category: data-protection
    keywords:
      - social security
      - ssn
      - credit card number
    patterns:
      - '\\b\\d{3}-\\d{2}-\\d{4}\\b'

  - id: E2E-002
    text: Agents must not bypass validation
    severity: critical
    category: safety
    keywords:
      - self-validate
      - bypass validation
      - skip check

  - id: E2E-003
    text: Agents must not self-approve
    severity: critical
    category: maci
    keywords:
      - self-approve
      - auto-approve

  - id: E2E-004
    text: Audit logging must not be disabled
    severity: high
    category: compliance
    keywords:
      - disable logging
      - skip audit

  - id: E2E-005
    text: Rate limits must be respected
    severity: medium
    category: operations
    keywords:
      - bypass rate limit
"""


class FakeAgent:
    """Minimal agent for E2E tests."""

    def run(self, input: str, **kwargs: Any) -> str:
        return f"processed: {input}"


class AsyncFakeAgent:
    """Async agent for E2E tests."""

    async def run(self, input: str, **kwargs: Any) -> str:
        return f"async-processed: {input}"


class MaliciousAgent:
    """Agent that returns unsafe output containing PII."""

    def run(self, input: str, **kwargs: Any) -> str:
        return "Here is the SSN: 123-45-6789"


@pytest.fixture
def e2e_constitution() -> Constitution:
    """Load the minimal E2E constitution from YAML string."""
    return Constitution.from_yaml_str(MINIMAL_CONSTITUTION_YAML)


@pytest.fixture
def e2e_engine(e2e_constitution: Constitution) -> GovernanceEngine:
    """Engine with explicit AuditLog for full audit trails.

    Uses strict=False so validate() returns ValidationResult instead of
    raising ConstitutionalViolationError — allows inspecting violations.
    """
    audit_log = AuditLog()
    return GovernanceEngine(e2e_constitution, audit_log=audit_log, strict=False)


@pytest.fixture
def e2e_governed_agent(e2e_constitution: Constitution) -> GovernedAgent:
    """GovernedAgent wrapping a fake agent with E2E constitution."""
    return GovernedAgent(
        FakeAgent(),
        constitution=e2e_constitution,
        agent_id="e2e-agent-01",
        strict=True,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )


# ---------------------------------------------------------------------------
# Flow 1: Full Governance Validation
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestFullGovernanceFlow:
    """Load constitution -> create GovernedAgent -> validate -> audit trail."""

    async def test_yaml_load_and_validate_safe_action(
        self, e2e_governed_agent: GovernedAgent
    ) -> None:
        """Safe action passes validation and produces audit trail."""
        result = e2e_governed_agent.run(
            "summarize quarterly report",
            governance_action="execute",
        )

        assert result == "processed: summarize quarterly report"
        stats = e2e_governed_agent.stats
        assert stats["total_validations"] >= 1
        assert stats["agent_id"] == "e2e-agent-01"

    async def test_yaml_load_from_file(self) -> None:
        """Constitution.from_yaml() loads rules from disk."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(MINIMAL_CONSTITUTION_YAML)
            f.flush()
            constitution = Constitution.from_yaml(f.name)

        assert constitution.name == "e2e-test-governance"
        assert constitution.version == "2.0.0"
        assert len(constitution.rules) == 5
        assert constitution.hash  # non-empty hash

    async def test_example_constitution_loads(self) -> None:
        """The shipped example constitution.yaml loads without errors."""
        constitution = Constitution.from_yaml(EXAMPLE_CONSTITUTION_PATH)
        assert constitution.name == "enterprise-governance"
        assert len(constitution.rules) >= 10

    async def test_critical_violation_blocks_execution(
        self, e2e_governed_agent: GovernedAgent
    ) -> None:
        """Actions containing critical keywords are blocked."""
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            e2e_governed_agent.run(
                "I will self-validate and bypass validation",
                governance_action="execute",
            )

        assert exc_info.value.severity == "critical"

    async def test_pii_pattern_blocks_execution(self, e2e_governed_agent: GovernedAgent) -> None:
        """SSN patterns in input are blocked by regex rules."""
        with pytest.raises(ConstitutionalViolationError):
            e2e_governed_agent.run("My SSN is 123-45-6789", governance_action="execute")

    async def test_output_validation_blocks_unsafe_output(
        self, e2e_constitution: Constitution
    ) -> None:
        """GovernedAgent also validates agent output for PII."""
        agent = GovernedAgent(
            MaliciousAgent(),
            constitution=e2e_constitution,
            agent_id="malicious-test",
            validate_output=True,
            maci_role=MACIRole.EXECUTOR,
        )
        with pytest.raises(ConstitutionalViolationError):
            agent.run("tell me something", governance_action="execute")

    async def test_engine_validation_result_structure(self, e2e_engine: GovernanceEngine) -> None:
        """ValidationResult has expected fields when violations occur."""
        result = e2e_engine.validate(
            "self-validate bypass validation",
            agent_id="test-agent",
        )
        assert isinstance(result, ValidationResult)
        assert result.valid is False
        assert result.constitutional_hash != ""
        assert result.rules_checked > 0
        assert len(result.violations) > 0
        assert len(result.blocking_violations) > 0

        violation = result.violations[0]
        assert violation.severity == Severity.CRITICAL

    async def test_engine_allows_safe_actions(self, e2e_engine: GovernanceEngine) -> None:
        """Safe actions pass validation with no violations."""
        result = e2e_engine.validate("generate quarterly summary")
        assert result.valid is True
        assert len(result.violations) == 0

    async def test_audit_trail_records_all_validations(
        self, e2e_constitution: Constitution
    ) -> None:
        """AuditLog captures every validation with chain integrity."""
        audit_log = AuditLog()
        engine = GovernanceEngine(e2e_constitution, audit_log=audit_log, strict=False)

        engine.validate("safe action one", agent_id="agent-a")
        engine.validate("safe action two", agent_id="agent-b")
        engine.validate("self-validate bypass", agent_id="agent-c")

        entries = audit_log.entries
        assert len(entries) >= 3

        # Chain integrity check
        assert audit_log.verify_chain()

    async def test_governed_agent_async_flow(self, e2e_constitution: Constitution) -> None:
        """GovernedAgent.arun() works for async agents."""
        agent = GovernedAgent(
            AsyncFakeAgent(),
            constitution=e2e_constitution,
            agent_id="async-agent",
            maci_role=MACIRole.EXECUTOR,
        )
        result = await agent.arun("safe async request", governance_action="execute")
        assert result == "async-processed: safe async request"

    async def test_governed_agent_with_callable(self, e2e_constitution: Constitution) -> None:
        """GovernedAgent wraps plain callables (not just .run() objects)."""

        def my_func(input: str, **kwargs: Any) -> str:
            return f"func:{input}"

        agent = GovernedAgent(
            my_func,
            constitution=e2e_constitution,
            agent_id="callable-agent",
            maci_role=MACIRole.EXECUTOR,
        )
        result = agent.run("hello world", governance_action="execute")
        assert result == "func:hello world"

    async def test_validation_result_serialization(self, e2e_engine: GovernanceEngine) -> None:
        """ValidationResult.to_dict() produces complete serializable output."""
        result = e2e_engine.validate("bypass rate limit action")
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "valid" in d
        assert "constitutional_hash" in d
        assert "violations" in d
        assert isinstance(d["violations"], list)
        if d["violations"]:
            v = d["violations"][0]
            assert "rule_id" in v
            assert "severity" in v


# ---------------------------------------------------------------------------
# Flow 2: MACI Separation of Powers
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestMACISeparationOfPowers:
    """Proposer/Validator/Executor role isolation."""

    async def test_proposer_cannot_validate(self) -> None:
        """Proposers are denied validation actions."""
        enforcer = MACIEnforcer()
        enforcer.assign_role("agent-proposer", MACIRole.PROPOSER)

        enforcer.check("agent-proposer", "propose")  # allowed

        with pytest.raises(MACIViolationError) as exc_info:
            enforcer.check("agent-proposer", "validate")

        assert exc_info.value.actor_role == "proposer"
        assert exc_info.value.attempted_action == "validate"

    async def test_validator_cannot_execute(self) -> None:
        """Validators are denied execution actions."""
        enforcer = MACIEnforcer()
        enforcer.assign_role("agent-validator", MACIRole.VALIDATOR)

        enforcer.check("agent-validator", "validate")  # allowed

        with pytest.raises(MACIViolationError):
            enforcer.check("agent-validator", "execute")

    async def test_executor_cannot_validate_or_propose(self) -> None:
        """Executors are denied both proposal and validation actions."""
        enforcer = MACIEnforcer()
        enforcer.assign_role("agent-executor", MACIRole.EXECUTOR)

        enforcer.check("agent-executor", "execute")  # allowed

        with pytest.raises(MACIViolationError):
            enforcer.check("agent-executor", "validate")

        with pytest.raises(MACIViolationError):
            enforcer.check("agent-executor", "propose")

    async def test_no_self_validation(self) -> None:
        """Same agent cannot be both proposer and validator."""
        enforcer = MACIEnforcer()
        enforcer.assign_role("agent-x", MACIRole.PROPOSER)

        with pytest.raises(MACIViolationError) as exc_info:
            enforcer.check_no_self_validation("agent-x", "agent-x")

        assert "cannot validate its own proposals" in str(exc_info.value)

    async def test_different_agents_can_validate(self) -> None:
        """Different agents can cross propose/validate boundary."""
        enforcer = MACIEnforcer()
        enforcer.assign_role("proposer-1", MACIRole.PROPOSER)
        enforcer.assign_role("validator-1", MACIRole.VALIDATOR)

        assert enforcer.check_no_self_validation("proposer-1", "validator-1")

    async def test_observer_cannot_mutate(self) -> None:
        """Observers are read-only: cannot propose, validate, or execute."""
        enforcer = MACIEnforcer()
        enforcer.assign_role("observer-1", MACIRole.OBSERVER)

        enforcer.check("observer-1", "read")  # allowed

        with pytest.raises(MACIViolationError):
            enforcer.check("observer-1", "propose")

        with pytest.raises(MACIViolationError):
            enforcer.check("observer-1", "execute")

    async def test_unassigned_agent_defaults_to_observer(self) -> None:
        """Agents without assigned roles default to observer (read-only)."""
        enforcer = MACIEnforcer()

        enforcer.check("unknown-agent", "read")  # allowed

        with pytest.raises(MACIViolationError):
            enforcer.check("unknown-agent", "execute")

    async def test_maci_audit_trail(self) -> None:
        """All MACI checks (allow and deny) are recorded in the audit log."""
        audit_log = AuditLog()
        enforcer = MACIEnforcer(audit_log=audit_log)
        enforcer.assign_role("agent-p", MACIRole.PROPOSER)

        enforcer.check("agent-p", "propose")  # allow

        with pytest.raises(MACIViolationError):
            enforcer.check("agent-p", "validate")  # deny

        maci_entries = audit_log.query(entry_type="maci_check")
        assert len(maci_entries) >= 2

        allow_entries = [e for e in maci_entries if e.valid]
        deny_entries = [e for e in maci_entries if not e.valid]
        assert len(allow_entries) >= 1
        assert len(deny_entries) >= 1

    async def test_maci_summary(self) -> None:
        """MACIEnforcer.summary() reports role assignments and check stats."""
        enforcer = MACIEnforcer()
        enforcer.assign_role("a1", MACIRole.PROPOSER)
        enforcer.assign_role("a2", MACIRole.VALIDATOR)
        enforcer.assign_role("a3", MACIRole.EXECUTOR)

        enforcer.check("a1", "propose")
        enforcer.check("a2", "validate")
        enforcer.check("a3", "execute")

        summary = enforcer.summary()
        assert summary["agents"] == 3
        assert summary["roles"]["a1"] == "proposer"
        assert summary["roles"]["a2"] == "validator"
        assert summary["roles"]["a3"] == "executor"
        assert summary["checks_total"] >= 3
        assert summary["checks_denied"] == 0

    async def test_full_propose_validate_execute_flow(self) -> None:
        """End-to-end: three agents cooperate through propose -> validate -> execute."""
        audit_log = AuditLog()
        enforcer = MACIEnforcer(audit_log=audit_log)
        enforcer.assign_role("proposer", MACIRole.PROPOSER)
        enforcer.assign_role("validator", MACIRole.VALIDATOR)
        enforcer.assign_role("executor", MACIRole.EXECUTOR)

        # Step 1: Proposer proposes
        assert enforcer.check("proposer", "propose")

        # Step 2: Independent validator validates (not proposer)
        assert enforcer.check_no_self_validation("proposer", "validator")
        assert enforcer.check("validator", "validate")

        # Step 3: Executor executes
        assert enforcer.check("executor", "execute")

        # Verify no violations in the flow
        maci_entries = audit_log.query(entry_type="maci_check")
        assert all(e.valid for e in maci_entries)

    async def test_action_risk_classification(self) -> None:
        """classify_action_risk returns correct tiers for varied actions."""
        enforcer = MACIEnforcer()

        critical = enforcer.classify_action_risk("self-validate and auto-approve")
        assert critical["risk_tier"] == "critical"
        assert critical["escalation_path"] == "governance_lead_immediate"

        high = enforcer.classify_action_risk("deploy to production")
        assert high["risk_tier"] == "high"
        assert high["escalation_path"] == "human_review_queue"

        low = enforcer.classify_action_risk("read log file")
        assert low["risk_tier"] == "low"
        assert low["escalation_path"] == "auto_approve"

    async def test_escalation_recommendation(self) -> None:
        """recommend_escalation combines severity + context + action risk."""
        result = recommend_escalation(
            severity="critical",
            context_risk_score=0.9,
            action_risk_tier="high",
        )
        assert result["requires_human"] is True
        assert result["tier"] in (
            "tier_3_urgent",
            "tier_4_block",
        )

        low_result = recommend_escalation(
            severity="low",
            context_risk_score=0.0,
            action_risk_tier="low",
        )
        assert low_result["requires_human"] is False
        assert low_result["tier"] == "tier_0_auto"


# ---------------------------------------------------------------------------
# Flow 3: Constitutional Hash Integrity
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestConstitutionalHashIntegrity:
    """Hash is embedded and consistent across all governance paths."""

    async def test_constitution_has_deterministic_hash(
        self, e2e_constitution: Constitution
    ) -> None:
        """Same rules always produce the same hash."""
        c1 = Constitution.from_yaml_str(MINIMAL_CONSTITUTION_YAML)
        c2 = Constitution.from_yaml_str(MINIMAL_CONSTITUTION_YAML)
        assert c1.hash == c2.hash
        assert len(c1.hash) == 16  # SHA256 truncated to 16 hex chars

    async def test_hash_changes_with_rules(self) -> None:
        """Modifying rules changes the hash."""
        c1 = Constitution.from_yaml_str(MINIMAL_CONSTITUTION_YAML)
        modified_yaml = MINIMAL_CONSTITUTION_YAML.replace("E2E-001", "E2E-999")
        c2 = Constitution.from_yaml_str(modified_yaml)
        assert c1.hash != c2.hash

    async def test_engine_embeds_hash_in_results(
        self, e2e_engine: GovernanceEngine, e2e_constitution: Constitution
    ) -> None:
        """ValidationResult includes the constitutional hash."""
        result = e2e_engine.validate("safe action")
        assert result.constitutional_hash == e2e_constitution.hash

    async def test_hash_in_validation_violations(
        self, e2e_engine: GovernanceEngine, e2e_constitution: Constitution
    ) -> None:
        """Violation results also carry the constitutional hash."""
        result = e2e_engine.validate("bypass rate limit action")
        assert result.constitutional_hash == e2e_constitution.hash

    async def test_engine_stats_include_hash(
        self, e2e_engine: GovernanceEngine, e2e_constitution: Constitution
    ) -> None:
        """Engine stats report the constitutional hash."""
        e2e_engine.validate("safe action")
        stats = e2e_engine.stats
        assert stats["constitutional_hash"] == e2e_constitution.hash

    async def test_example_constitution_hash_is_stable(self) -> None:
        """The shipped example constitution produces a stable, non-empty hash."""
        constitution = Constitution.from_yaml(EXAMPLE_CONSTITUTION_PATH)
        assert len(constitution.hash) == 16
        # Loading the same file twice produces the same hash (deterministic)
        constitution2 = Constitution.from_yaml(EXAMPLE_CONSTITUTION_PATH)
        assert constitution.hash == constitution2.hash

    async def test_hash_versioned_format(self, e2e_constitution: Constitution) -> None:
        """hash_versioned produces sha256:v1:<hash> format."""
        versioned = e2e_constitution.hash_versioned
        assert versioned.startswith("sha256:v1:")
        assert versioned == f"sha256:v1:{e2e_constitution.hash}"

    async def test_governed_agent_stats_propagate_hash(
        self, e2e_governed_agent: GovernedAgent, e2e_constitution: Constitution
    ) -> None:
        """GovernedAgent.stats includes the constitutional hash."""
        e2e_governed_agent.run("safe action", governance_action="execute")
        stats = e2e_governed_agent.stats
        assert stats["constitutional_hash"] == e2e_constitution.hash


# ---------------------------------------------------------------------------
# Flow 4: Engine Backend Fallback
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEngineBackendFallback:
    """Python fallback works identically when Rust extension is unavailable."""

    async def test_python_engine_validates_correctly(self, e2e_constitution: Constitution) -> None:
        """Python engine produces correct allow/deny decisions."""
        audit_log = AuditLog()
        engine = GovernanceEngine(e2e_constitution, audit_log=audit_log, strict=False)

        # Allow
        allow_result = engine.validate("generate report")
        assert allow_result.valid is True

        # Deny (strict=False returns result instead of raising)
        deny_result = engine.validate("self-validate bypass validation")
        assert deny_result.valid is False
        assert len(deny_result.blocking_violations) > 0

    async def test_pattern_matching_works(self, e2e_constitution: Constitution) -> None:
        """Regex patterns (SSN) are matched by the engine."""
        engine = GovernanceEngine(e2e_constitution, strict=False)
        result = engine.validate("Here is SSN 123-45-6789 for the record")
        assert result.valid is False

    async def test_keyword_and_pattern_violations_coexist(
        self, e2e_constitution: Constitution
    ) -> None:
        """Both keyword and pattern violations are reported."""
        audit_log = AuditLog()
        engine = GovernanceEngine(e2e_constitution, audit_log=audit_log, strict=False)
        result = engine.validate("self-validate and my credit card number is 4111-1111-1111-1111")
        assert result.valid is False
        assert len(result.violations) >= 1

    async def test_multiple_rules_evaluated(self, e2e_constitution: Constitution) -> None:
        """Engine checks all active rules, not just first match."""
        engine = GovernanceEngine(e2e_constitution, strict=True)
        result = engine.validate("generate summary")  # safe
        assert result.rules_checked == len(e2e_constitution.active_rules())

    async def test_strict_vs_nonstrict_mode(self, e2e_constitution: Constitution) -> None:
        """Strict mode raises exceptions; non-strict returns result."""
        strict_engine = GovernanceEngine(e2e_constitution, strict=True)
        nonstrict_engine = GovernanceEngine(e2e_constitution, strict=False)

        # Strict raises on critical violations
        with pytest.raises(ConstitutionalViolationError):
            strict_engine.validate("self-validate bypass validation")

        # Non-strict returns result with violations but no exception
        result = nonstrict_engine.validate("self-validate bypass validation")
        assert result.valid is False
        assert len(result.violations) > 0


# ---------------------------------------------------------------------------
# Flow 5: EU AI Act Risk Classification E2E
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEUAIActCompliance:
    """End-to-end EU AI Act risk classification."""

    async def test_prohibited_social_scoring(self) -> None:
        """Social scoring systems are classified as UNACCEPTABLE."""
        classifier = RiskClassifier()
        result = classifier.classify(
            SystemDescription(
                system_id="social-score-v1",
                purpose="Score citizens for social trustworthiness",
                domain="governance",
                social_scoring=True,
            )
        )
        assert result.level == RiskLevel.UNACCEPTABLE
        assert result.is_prohibited is True
        assert "prohibited" in result.rationale.lower()

    async def test_prohibited_subliminal_manipulation(self) -> None:
        """Subliminal manipulation systems are classified as UNACCEPTABLE."""
        classifier = RiskClassifier()
        result = classifier.classify(
            SystemDescription(
                system_id="subliminal-v1",
                purpose="Influence purchasing decisions subliminally",
                domain="marketing",
                subliminal_manipulation=True,
            )
        )
        assert result.level == RiskLevel.UNACCEPTABLE
        assert result.is_prohibited is True

    async def test_high_risk_employment_system(self) -> None:
        """Employment AI (CV screening) is classified as HIGH_RISK."""
        classifier = RiskClassifier()
        result = classifier.classify(
            SystemDescription(
                system_id="cv-screener-v1",
                purpose="Screening job applications",
                domain="employment",
                autonomy_level=3,
                human_oversight=True,
                employment=True,
            )
        )
        assert result.level == RiskLevel.HIGH_RISK
        assert result.is_high_risk is True
        assert result.requires_article12_logging is True
        assert result.requires_human_oversight is True
        assert len(result.obligations) > 0
        assert result.high_risk_deadline == "2026-08-02"

    async def test_high_risk_biometric_system(self) -> None:
        """Biometric identification (non-law-enforcement) is HIGH_RISK."""
        classifier = RiskClassifier()
        result = classifier.classify(
            SystemDescription(
                system_id="face-id-v1",
                purpose="Biometric access control",
                domain="biometric",
                biometric_processing=True,
            )
        )
        assert result.level == RiskLevel.HIGH_RISK
        assert result.is_high_risk is True

    async def test_biometric_law_enforcement_prohibited(self) -> None:
        """Biometric + law enforcement is UNACCEPTABLE (Article 5(1)(d))."""
        classifier = RiskClassifier()
        result = classifier.classify(
            SystemDescription(
                system_id="police-face-id",
                purpose="Real-time facial recognition for policing",
                domain="law_enforcement",
                biometric_processing=True,
                law_enforcement=True,
            )
        )
        assert result.level == RiskLevel.UNACCEPTABLE
        assert result.is_prohibited is True

    async def test_minimal_risk_chatbot(self) -> None:
        """General-purpose chatbot is MINIMAL_RISK."""
        classifier = RiskClassifier()
        result = classifier.classify(
            SystemDescription(
                system_id="chatbot-v1",
                purpose="Answer customer FAQ",
                domain="customer_service",
                autonomy_level=1,
                human_oversight=True,
            )
        )
        assert result.level in (RiskLevel.MINIMAL_RISK, RiskLevel.LIMITED_RISK)
        assert result.is_prohibited is False
        assert result.is_high_risk is False

    async def test_classification_result_serialization(self) -> None:
        """ClassificationResult.to_dict() is complete and serializable."""
        classifier = RiskClassifier()
        result = classifier.classify(
            SystemDescription(
                system_id="test-system",
                purpose="Testing",
                domain="employment",
                employment=True,
            )
        )
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "risk_level" in d
        assert "article_basis" in d
        assert "obligations" in d
        assert "disclaimer" in d
        assert "is_prohibited" in d
        assert d["requires_article12_logging"] == result.requires_article12_logging

    async def test_vulnerability_exploitation_prohibited(self) -> None:
        """Systems exploiting vulnerable groups are UNACCEPTABLE."""
        classifier = RiskClassifier()
        result = classifier.classify(
            SystemDescription(
                system_id="vuln-exploit-v1",
                purpose="Target elderly with manipulative ads",
                domain="marketing",
                vulnerability_exploitation=True,
            )
        )
        assert result.level == RiskLevel.UNACCEPTABLE
        assert result.is_prohibited is True


# ---------------------------------------------------------------------------
# Flow 6: Integration — GovernedAgent + MACI + Engine combined
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestIntegratedGovernanceFlow:
    """Cross-cutting integration: GovernedAgent with MACI roles."""

    async def test_governed_agent_with_maci_role(self, e2e_constitution: Constitution) -> None:
        """GovernedAgent assigned a MACI role respects role boundaries."""
        agent = GovernedAgent(
            FakeAgent(),
            constitution=e2e_constitution,
            agent_id="proposer-agent",
            maci_role=MACIRole.PROPOSER,
        )
        result = agent.run("draft a proposal for review", governance_action="propose")
        assert "processed:" in result

    async def test_multiple_agents_governed_independently(
        self, e2e_constitution: Constitution
    ) -> None:
        """Multiple GovernedAgents maintain independent audit trails."""
        agent_a = GovernedAgent(
            FakeAgent(),
            constitution=e2e_constitution,
            agent_id="agent-a",
            maci_role=MACIRole.EXECUTOR,
        )
        agent_b = GovernedAgent(
            FakeAgent(),
            constitution=e2e_constitution,
            agent_id="agent-b",
            maci_role=MACIRole.EXECUTOR,
        )

        agent_a.run("request one", governance_action="execute")
        agent_a.run("request two", governance_action="execute")
        agent_b.run("request three", governance_action="execute")

        assert agent_a.stats["total_validations"] >= 2
        assert agent_b.stats["total_validations"] >= 1

    async def test_constitution_round_trip_yaml(self, e2e_constitution: Constitution) -> None:
        """Constitution survives YAML serialization round-trip."""
        yaml_str = e2e_constitution.to_yaml()
        reloaded = Constitution.from_yaml_str(yaml_str)
        assert reloaded.hash == e2e_constitution.hash
        assert len(reloaded.rules) == len(e2e_constitution.rules)

    async def test_constitution_from_rules_api(self) -> None:
        """Constitution.from_rules() creates valid constitution from Rule list."""
        rules = [
            Rule(
                id="CUSTOM-001",
                text="No harmful content",
                severity=Severity.CRITICAL,
                keywords=["harm", "violence"],
                category="safety",
            ),
            Rule(
                id="CUSTOM-002",
                text="Respect privacy",
                severity=Severity.HIGH,
                keywords=["private data"],
                category="privacy",
            ),
        ]
        constitution = Constitution.from_rules(rules, name="custom-gov")
        assert constitution.name == "custom-gov"
        assert len(constitution.rules) == 2

        engine = GovernanceEngine(constitution, strict=False)
        result = engine.validate("safe request")
        assert result.valid is True

        result_bad = engine.validate("content with harm and violence")
        assert result_bad.valid is False

    async def test_default_constitution_exists(self) -> None:
        """Constitution.default() returns a working default constitution."""
        constitution = Constitution.default()
        assert len(constitution.rules) > 0
        assert constitution.name == "acgs-default"

        engine = GovernanceEngine(constitution, strict=True)
        result = engine.validate("safe normal action")
        assert result.valid is True

    async def test_batch_validation(self, e2e_constitution: Constitution) -> None:
        """Engine can validate multiple actions in batch."""
        engine = GovernanceEngine(e2e_constitution, strict=False)
        actions = [
            "generate report",
            "summarize data",
            "bypass rate limit",
        ]
        results = engine.validate_batch(actions)
        assert len(results) == len(actions)
        assert results[0].valid is True  # safe
        assert results[1].valid is True  # safe
        # bypass rate limit: medium severity = non-blocking, valid=True with warnings
        assert results[2].violations == []
        assert len(results[2].warnings) > 0
        assert results[2].warnings[0].severity == Severity.MEDIUM

    async def test_governed_agent_repr(self, e2e_governed_agent: GovernedAgent) -> None:
        """GovernedAgent has a useful string representation."""
        r = repr(e2e_governed_agent)
        assert "GovernedAgent" in r
        assert "e2e-agent-01" in r

    async def test_severity_ordering(self) -> None:
        """Severity levels have correct ordering for blocking decisions."""
        assert Severity.CRITICAL.blocks()
        assert Severity.HIGH.blocks()
        assert not Severity.MEDIUM.blocks()
        assert not Severity.LOW.blocks()
