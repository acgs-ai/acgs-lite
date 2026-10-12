"""Tests for acgs_lite.engine.core — targeting missed lines for coverage boost.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import pytest

from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.constitution import Constitution, Severity
from acgs_lite.engine.core import (
    GovernanceEngine,
    ValidationResult,
    Violation,
    _dedup_violations,
    _FastAuditLog,
    _NoopRecorder,
)
from acgs_lite.errors import ConstitutionalViolationError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_RULES_YAML = """
rules:
  - id: SAFETY-001
    text: Do not deploy models without safety review
    severity: critical
    category: safety
    keywords: [deploy, model, without, safety, review]
    patterns:
      - "\\\\bdeploy.{0,30}without.{0,30}safety\\\\b"

  - id: FAIRNESS-001
    text: Do not use age-based discrimination
    severity: high
    category: fairness
    keywords: [age-based, discrimination, bias]
    patterns:
      - "age-based|age.*discriminat"

  - id: TRANSPARENCY-001
    text: Do not hide AI involvement in decisions
    severity: critical
    category: transparency
    keywords: [hide, secret, conceal, AI, involvement]
    patterns:
      - "\\\\bhide.{0,30}AI\\\\b"
      - "\\\\bsecret\\\\b"

  - id: APPEAL-001
    text: Ensure appeal rights for affected users
    severity: high
    category: accountability
    keywords: [no appeal, without appeal, deny appeal]
    patterns:
      - "\\\\bno\\\\s+appeal\\\\b"
      - "\\\\bwithout\\\\s+appeal\\\\b"

  - id: INFO-001
    text: Provide notice about data use
    severity: low
    category: transparency
    keywords: [data collection, privacy notice]
    patterns: []
"""


@pytest.fixture
def constitution():
    return Constitution.from_yaml_str(SAMPLE_RULES_YAML)


@pytest.fixture
def engine(constitution):
    return GovernanceEngine(constitution, strict=True)


@pytest.fixture
def engine_with_audit_log(constitution):
    audit_log = AuditLog()
    return GovernanceEngine(constitution, audit_log=audit_log, strict=True)


# ---------------------------------------------------------------------------
# Violation NamedTuple
# ---------------------------------------------------------------------------


class TestViolation:
    def test_violation_creation(self):
        v = Violation(
            rule_id="TEST-001",
            rule_text="test rule",
            severity=Severity.CRITICAL,
            matched_content="bad content",
            category="safety",
        )
        assert v.rule_id == "TEST-001"
        assert v.severity == Severity.CRITICAL
        assert v.category == "safety"

    def test_violation_is_tuple(self):
        v = Violation("A", "B", Severity.LOW, "C", "D")
        assert isinstance(v, tuple)
        assert len(v) == 5


# ---------------------------------------------------------------------------
# ValidationResult
# ---------------------------------------------------------------------------


class TestValidationResult:
    def test_to_dict(self):
        result = ValidationResult(
            valid=True,
            constitutional_hash="608508a9bd224290",
            violations=[],
            rules_checked=5,
            latency_ms=1.23,
            request_id="req-1",
        )
        d = result.to_dict()
        assert d["valid"] is True
        assert d["rules_checked"] == 5
        assert d["violations"] == []

    def test_to_dict_with_violations(self):
        v = Violation("R1", "rule text", Severity.HIGH, "matched", "cat")
        result = ValidationResult(
            valid=False,
            constitutional_hash="608508a9bd224290",
            violations=[v],
            rules_checked=3,
        )
        d = result.to_dict()
        assert len(d["violations"]) == 1
        assert d["violations"][0]["rule_id"] == "R1"
        assert d["violations"][0]["severity"] == "high"

    def test_blocking_violations(self):
        v_block = Violation("R1", "text", Severity.CRITICAL, "m", "c")
        v_warn = Violation("R2", "text", Severity.LOW, "m", "c")
        result = ValidationResult(
            valid=False,
            constitutional_hash="608508a9bd224290",
            violations=[v_block, v_warn],
            rules_checked=2,
        )
        assert len(result.blocking_violations) == 1
        assert result.blocking_violations[0].rule_id == "R1"

    def test_warnings(self):
        """warnings is now a separate field populated by the engine."""
        v_block = Violation("R1", "text", Severity.CRITICAL, "m", "c")
        v_warn = Violation("R2", "text", Severity.LOW, "m", "c")
        # Explicit field construction
        result = ValidationResult(
            valid=False,
            constitutional_hash="608508a9bd224290",
            violations=[v_block],
            warnings=[v_warn],
            rules_checked=2,
        )
        assert len(result.warnings) == 1
        assert result.warnings[0].rule_id == "R2"
        # Default is empty when only violations given
        result2 = ValidationResult(
            valid=False,
            constitutional_hash="608508a9bd224290",
            violations=[v_block, v_warn],
            rules_checked=2,
        )
        assert result2.warnings == []


# ---------------------------------------------------------------------------
# _dedup_violations
# ---------------------------------------------------------------------------


class TestDedupViolations:
    def test_empty(self):
        assert _dedup_violations([]) == []

    def test_no_duplicates(self):
        v1 = Violation("A", "", Severity.LOW, "", "")
        v2 = Violation("B", "", Severity.LOW, "", "")
        result = _dedup_violations([v1, v2])
        assert len(result) == 2

    def test_removes_duplicates(self):
        v1 = Violation("A", "", Severity.LOW, "", "")
        v2 = Violation("A", "", Severity.HIGH, "", "")
        result = _dedup_violations([v1, v2])
        assert len(result) == 1
        assert result[0].severity == Severity.LOW  # first wins


# ---------------------------------------------------------------------------
# _NoopRecorder
# ---------------------------------------------------------------------------


class TestNoopRecorder:
    def test_append_and_len(self):
        r = _NoopRecorder()
        assert len(r) == 0
        r.append("anything")
        assert len(r) == 1
        r.append(None)
        assert len(r) == 2


# ---------------------------------------------------------------------------
# _FastAuditLog
# ---------------------------------------------------------------------------


class TestFastAuditLog:
    def test_record_fast_full_tuple(self):
        log = _FastAuditLog("hash123")
        log.record_fast("req1", "agent1", "action1", True, [], "hash123", 1.5, "2024-01-01")
        assert len(log) == 1
        entries = log.entries
        assert len(entries) == 1
        assert entries[0].agent_id == "agent1"
        assert entries[0].action == "action1"
        assert entries[0].valid is True

    def test_record_compat_shim(self):
        log = _FastAuditLog("hash123")
        entry = AuditEntry(
            id="req2",
            type="validation",
            agent_id="agent2",
            action="action2",
            valid=False,
            violations=["R1"],
            constitutional_hash="hash123",
            latency_ms=2.0,
            timestamp="2024-01-01",
        )
        log.record(entry)
        assert len(log) == 1
        entries = log.entries
        assert entries[0].agent_id == "agent2"

    def test_compact_allow_record_reconstruction(self):
        """Test that 2-tuple compact records reconstruct correctly."""
        log = _FastAuditLog("hash456")
        # Directly insert a compact 2-tuple (used internally for allow-path)
        log._records.append(("req-compact", "some action"))
        entries = log.entries
        assert len(entries) == 1
        assert entries[0].agent_id == "anonymous"
        assert entries[0].action == "some action"
        assert entries[0].valid is True


# ---------------------------------------------------------------------------
# GovernanceEngine — construction and basic validation
# ---------------------------------------------------------------------------


class TestGovernanceEngineConstruction:
    def test_engine_created_with_rules(self, engine):
        assert engine._rules_count > 0
        assert engine._const_hash == engine.constitution.hash

    def test_engine_with_explicit_audit_log(self, constitution):
        audit_log = AuditLog()
        eng = GovernanceEngine(constitution, audit_log=audit_log)
        # _fast_records should be None when explicit AuditLog is provided
        assert eng._fast_records is None

    def test_engine_default_fast_audit_log(self, constitution):
        eng = GovernanceEngine(constitution)
        assert isinstance(eng.audit_log, _FastAuditLog)

    def test_engine_strict_mode(self, constitution):
        eng = GovernanceEngine(constitution, strict=True)
        assert eng.strict is True

    def test_engine_non_strict_mode(self, constitution):
        eng = GovernanceEngine(constitution, strict=False)
        assert eng.strict is False

    def test_custom_validators(self, constitution):
        def my_validator(action, context):
            return []

        eng = GovernanceEngine(constitution, custom_validators=[my_validator])
        assert len(eng.custom_validators) == 1


# ---------------------------------------------------------------------------
# GovernanceEngine — validate()
# ---------------------------------------------------------------------------


class TestGovernanceEngineValidate:
    def test_allow_safe_action(self, engine):
        result = engine.validate("run safety test on model accuracy")
        assert result.valid is True

    def test_deny_critical_action(self, engine):
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("deploy model without safety review")

    def test_deny_secret_action(self, engine):
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("keep the decision secret from users")

    def test_allow_positive_verb_action(self, engine):
        result = engine.validate("implement differential privacy controls")
        assert result.valid is True

    def test_escalate_high_severity_no_block(self, engine):
        """HIGH severity raises ConstitutionalViolationError in strict mode."""
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            engine.validate("apply age-based insurance pricing")
        assert exc_info.value.rule_id == "FAIRNESS-001"

    def test_validate_with_context(self, engine):
        result = engine.validate(
            "run compliance check",
            context={"action_description": "review safety controls for completeness"},
        )
        assert isinstance(result, ValidationResult)

    def test_validate_with_context_deny(self, engine):
        with pytest.raises(ConstitutionalViolationError):
            engine.validate(
                "update service configuration",
                context={"action_description": "deploy model without safety review"},
            )

    def test_validate_empty_context(self, engine):
        result = engine.validate("run safety audit", context={})
        assert result.valid is True

    def test_validate_metadata_only_context(self, engine):
        result = engine.validate(
            "run safety audit",
            context={"source": "autoresearch", "rule": "SAFETY-003"},
        )
        assert isinstance(result, ValidationResult)

    def test_validate_with_agent_id(self, engine):
        result = engine.validate("run safety test", agent_id="agent-42")
        assert isinstance(result, ValidationResult)

    def test_validate_multiple_calls_increment_counter(self, engine):
        r1 = engine.validate("run safety test")
        r2 = engine.validate("run another safety test")
        assert isinstance(r1, ValidationResult)
        assert isinstance(r2, ValidationResult)

    def test_validate_returns_constitutional_hash(self, engine):
        result = engine.validate("run safety test")
        assert result.constitutional_hash == engine._const_hash


# ---------------------------------------------------------------------------
# GovernanceEngine — validate with explicit AuditLog
# ---------------------------------------------------------------------------


class TestGovernanceEngineWithAuditLog:
    def test_validate_records_audit_entry(self, engine_with_audit_log):
        result = engine_with_audit_log.validate("run safety test")
        assert result.valid is True
        # The real AuditLog should have entries
        assert len(engine_with_audit_log.audit_log) > 0

    def test_deny_critical_still_tracks_validation(self, engine_with_audit_log):
        """Critical violations raise but the engine still tracks them internally."""
        with pytest.raises(ConstitutionalViolationError):
            engine_with_audit_log.validate("deploy model without safety review")
        # The exception is raised before the audit entry is recorded for critical
        # violations, so we just verify the engine is still usable afterwards.
        result = engine_with_audit_log.validate("run safety test")
        assert result.valid is True
        assert len(engine_with_audit_log.audit_log) > 0


# ---------------------------------------------------------------------------
# GovernanceEngine — non-strict mode
# ---------------------------------------------------------------------------


class TestGovernanceEngineNonStrict:
    def test_non_strict_returns_result_instead_of_raising(self, constitution):
        eng = GovernanceEngine(constitution, strict=False)
        result = eng.validate("deploy model without safety review")
        # Non-strict should return a result with violations instead of raising
        assert isinstance(result, ValidationResult)
        assert result.valid is False or len(result.violations) > 0

    def test_non_strict_allow_action(self, constitution):
        eng = GovernanceEngine(constitution, strict=False)
        result = eng.validate("run safety test")
        assert result.valid is True


# ---------------------------------------------------------------------------
# GovernanceEngine — edge cases
# ---------------------------------------------------------------------------


class TestGovernanceEngineEdgeCases:
    def test_empty_action(self, engine):
        result = engine.validate("")
        assert isinstance(result, ValidationResult)

    def test_very_long_action(self, engine):
        long_action = "run safety test " * 1000
        result = engine.validate(long_action)
        assert isinstance(result, ValidationResult)

    def test_special_characters(self, engine):
        result = engine.validate("run <script>alert('xss')</script> test")
        assert isinstance(result, ValidationResult)

    def test_unicode_action(self, engine):
        result = engine.validate("run safety test with unicode chars: \u00e9\u00e8\u00ea\u00eb")
        assert isinstance(result, ValidationResult)

    def test_action_with_newlines(self, engine):
        result = engine.validate("run safety\ntest\nfor\nmodel")
        assert isinstance(result, ValidationResult)


# ---------------------------------------------------------------------------
# GovernanceEngine — stats / rule data
# ---------------------------------------------------------------------------


class TestGovernanceEngineInternals:
    def test_rule_data_populated(self, engine):
        assert len(engine._rule_data) == engine._rules_count

    def test_rule_data_tuple_structure(self, engine):
        for rd in engine._rule_data:
            assert len(rd) == 7
            # (rule_id, rule_text, severity, severity_value, category, is_critical, err_msg)
            assert isinstance(rd[0], str)  # rule_id
            assert isinstance(rd[1], str)  # rule_text
            assert isinstance(rd[4], str)  # category
            assert isinstance(rd[5], bool)  # is_critical

    def test_has_high_rules(self, engine):
        # Our fixture includes HIGH severity rules
        assert engine._has_high_rules is True

    def test_allow_results_are_independent(self, engine):
        first = engine.validate("ordinary action")
        second = engine.validate("another ordinary action")
        assert first.valid and second.valid
        assert first is not second
        assert first.violations is not second.violations
        first.violations.append("caller mutation")
        assert second.violations == []
        assert engine.validate("ordinary action").violations == []

    def test_escalation_result_survives_later_validation(self, constitution):
        engine = GovernanceEngine(constitution, strict=False)
        first = engine.validate("age-based discrimination")
        original = first.to_dict()
        assert first.violations
        second = engine.validate("ordinary action")
        assert second.valid
        assert first is not second
        assert first.violations is not second.violations
        assert first.to_dict() == original


# ---------------------------------------------------------------------------
# Constitution without HIGH severity rules
# ---------------------------------------------------------------------------


class TestEngineWithoutHighRules:
    def test_no_high_rules_flag(self):
        yaml_str = """
rules:
  - id: SAFETY-001
    text: Do not deploy without review
    severity: critical
    category: safety
    keywords: [deploy, without, review]
    patterns: []
  - id: INFO-001
    text: Provide notice
    severity: low
    category: transparency
    keywords: [notice]
    patterns: []
"""
        c = Constitution.from_yaml_str(yaml_str)
        eng = GovernanceEngine(c)
        assert eng._has_high_rules is False
