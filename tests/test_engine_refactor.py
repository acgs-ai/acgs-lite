"""Tests for engine module APIs added during refactor/engine cleanup.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import pytest

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution, Severity
from acgs_lite.engine.batch import BatchValidationResult
from acgs_lite.engine.core import (
    GovernanceEngine,
    ValidationResult,
    Violation,
    _dedup_violations,
    _FastAuditLog,
    _NoopRecorder,
)
from acgs_lite.engine.enforcement import NotificationEvent

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_YAML = """
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
    keywords: [age, discrimination, bias]
    patterns:
      - "\\\\bage.{0,20}discriminat"

  - id: TRANSPARENCY-001
    text: Do not hide AI involvement in decisions
    severity: critical
    category: transparency
    keywords: [hide, secret, conceal, AI, involvement]
    patterns:
      - "\\\\bhide.{0,30}AI\\\\b"

  - id: WARN-001
    text: Be cautious with automated decisions
    severity: low
    category: governance
    keywords: [automated, decisions]
"""


@pytest.fixture
def constitution() -> Constitution:
    return Constitution.from_yaml_str(SAMPLE_YAML)


@pytest.fixture
def engine(constitution: Constitution) -> GovernanceEngine:
    return GovernanceEngine(constitution, strict=False)


@pytest.fixture
def strict_engine(constitution: Constitution) -> GovernanceEngine:
    return GovernanceEngine(constitution, strict=True)


# ---------------------------------------------------------------------------
# _dedup_violations
# ---------------------------------------------------------------------------


class TestDedupViolations:
    def test_empty_list(self) -> None:
        assert _dedup_violations([]) == []

    def test_single_item(self) -> None:
        v = Violation("R1", "text", Severity.LOW, "match", "cat")
        assert _dedup_violations([v]) == [v]

    def test_removes_duplicates(self) -> None:
        # Dedup is keyed on (rule_id, matched_content): an exact duplicate is
        # removed, but distinct findings that share a rule_id (different
        # matched_content) are both preserved so the audit keeps every distinct
        # finding (#4 — e.g. two CODE-DANGEROUS-CALLs at different sites).
        v1 = Violation("R1", "text1", Severity.LOW, "m1", "cat")
        v2 = Violation("R1", "text2", Severity.HIGH, "m2", "cat")  # same rule, diff content
        v3 = Violation("R2", "text3", Severity.CRITICAL, "m3", "cat")
        v4 = Violation("R1", "text1 again", Severity.LOW, "m1", "cat")  # exact (R1, m1) dup
        result = _dedup_violations([v1, v2, v3, v4])
        assert len(result) == 3
        assert [v.rule_id for v in result] == ["R1", "R1", "R2"]
        assert [v.matched_content for v in result] == ["m1", "m2", "m3"]


# ---------------------------------------------------------------------------
# _NoopRecorder
# ---------------------------------------------------------------------------


class TestNoopRecorder:
    def test_append_increments_count(self) -> None:
        rec = _NoopRecorder()
        assert len(rec) == 0
        rec.append("anything")
        rec.append(None)
        assert len(rec) == 2


# ---------------------------------------------------------------------------
# _FastAuditLog
# ---------------------------------------------------------------------------


class TestFastAuditLog:
    def test_record_and_entries(self) -> None:
        log = _FastAuditLog("hash123")
        log.record_fast(
            "req1", "agent1", "action1", True, [], "hash123", 1.0, "2025-01-01T00:00:00Z"
        )
        assert len(log) == 1
        entries = log.entries
        assert len(entries) == 1
        assert entries[0].agent_id == "agent1"
        assert entries[0].valid is True

    def test_compact_allow_record(self) -> None:
        log = _FastAuditLog("hash123")
        log._records.append(("req1", "run test"))
        entries = log.entries
        assert len(entries) == 1
        assert entries[0].action == "run test"
        assert entries[0].agent_id == "anonymous"


# ---------------------------------------------------------------------------
# ValidationResult
# ---------------------------------------------------------------------------


class TestValidationResult:
    def test_blocking_violations_property(self) -> None:
        v_block = Violation("R1", "text", Severity.CRITICAL, "m", "cat")
        v_warn = Violation("R2", "text", Severity.LOW, "m", "cat")
        result = ValidationResult(
            valid=False,
            constitutional_hash="hash",
            violations=[v_block, v_warn],
        )
        assert len(result.blocking_violations) == 1
        assert result.blocking_violations[0].rule_id == "R1"

    def test_warnings_field(self) -> None:
        """warnings is now a separate field for WARN-action violations."""
        v_block = Violation("R1", "text", Severity.CRITICAL, "m", "cat")
        v_warn = Violation("R2", "text", Severity.LOW, "m", "cat")
        # Construct with explicit warnings field (engine populates it)
        result = ValidationResult(
            valid=False,
            constitutional_hash="hash",
            violations=[v_block],
            warnings=[v_warn],
        )
        assert len(result.warnings) == 1
        assert result.warnings[0].rule_id == "R2"
        # Default is empty (violations and warnings are separate)
        result2 = ValidationResult(
            valid=False,
            constitutional_hash="hash",
            violations=[v_block, v_warn],
        )
        assert result2.warnings == []

    def test_to_dict(self) -> None:
        result = ValidationResult(
            valid=True,
            constitutional_hash="hash",
            violations=[],
            rules_checked=5,
            request_id="req1",
            action="test action",
            agent_id="agent1",
        )
        d = result.to_dict()
        assert d["valid"] is True
        assert d["rules_checked"] == 5
        assert d["action"] == "test action"

    def test_to_dict_includes_notifications(self) -> None:
        result = ValidationResult(
            valid=False,
            constitutional_hash="hash",
            violations=[],
            notifications=[
                NotificationEvent(
                    rule_id="R1",
                    rule_text="notify",
                    severity="high",
                    category="security",
                    action="send secret",
                    matched_content="send secret",
                )
            ],
        )
        d = result.to_dict()
        assert d["notifications"][0]["rule_id"] == "R1"


# ---------------------------------------------------------------------------
# BatchValidationResult
# ---------------------------------------------------------------------------


class TestBatchValidationResult:
    def test_to_dict(self, engine: GovernanceEngine) -> None:
        r1 = engine.validate("run safety test")
        r2 = engine.validate("run safety test")
        batch = BatchValidationResult(
            results=(r1, r2),
            total=2,
            allowed=2,
            denied=0,
            escalated=0,
            compliance_rate=1.0,
            critical_rule_ids=(),
            summary="PASS: all 2 actions compliant",
        )
        d = batch.to_dict()
        assert d["total"] == 2
        assert d["compliance_rate"] == 1.0
        assert len(d["results"]) == 2


# ---------------------------------------------------------------------------
# GovernanceEngine.validate_batch
# ---------------------------------------------------------------------------


class TestValidateBatch:
    def test_batch_returns_list(self, strict_engine: GovernanceEngine) -> None:
        results = strict_engine.validate_batch(["run safety test", "implement audit"])
        assert isinstance(results, list)
        assert len(results) == 2
        assert all(isinstance(r, ValidationResult) for r in results)

    def test_batch_does_not_raise_in_strict(self, strict_engine: GovernanceEngine) -> None:
        """Even strict engines should not raise during validate_batch."""
        results = strict_engine.validate_batch(["deploy model without safety review"])
        assert len(results) == 1
        # strict was temporarily disabled, so result has violations but no exception
        assert not results[0].valid or len(results[0].violations) > 0


# ---------------------------------------------------------------------------
# GovernanceEngine.validate_batch_report
# ---------------------------------------------------------------------------


class TestValidateBatchReport:
    def test_all_compliant(self, engine: GovernanceEngine) -> None:
        report = engine.validate_batch_report(["run safety test", "implement audit"])
        assert isinstance(report, BatchValidationResult)
        assert report.denied == 0
        assert "PASS" in report.summary

    def test_mixed_results(self, strict_engine: GovernanceEngine) -> None:
        report = strict_engine.validate_batch_report(
            [
                "run safety test",
                "deploy model without safety review",
            ]
        )
        assert report.total == 2
        assert report.denied >= 1
        assert "FAIL" in report.summary
        assert len(report.critical_rule_ids) >= 1

    def test_context_tuples(self, engine: GovernanceEngine) -> None:
        report = engine.validate_batch_report(
            [
                ("run safety test", {"source": "test"}),
            ]
        )
        assert report.total == 1


# ---------------------------------------------------------------------------
# GovernanceEngine.stats
# ---------------------------------------------------------------------------


class TestEngineStats:
    def test_stats_with_noop_recorder(self, engine: GovernanceEngine) -> None:
        engine.validate("run safety test")
        s = engine.stats
        assert "total_validations" in s
        assert "compliance_rate" in s
        assert "rules_count" in s
        assert s["rules_count"] == len(engine.constitution.rules)

    def test_stats_with_audit_log(self, constitution: Constitution) -> None:
        audit = AuditLog()
        eng = GovernanceEngine(constitution, audit_log=audit, strict=False)
        eng.validate("run safety test")
        s = eng.stats
        assert s["total_validations"] >= 1


# ---------------------------------------------------------------------------
# GovernanceEngine.add_validator
# ---------------------------------------------------------------------------


class TestAddValidator:
    def test_custom_validator_called(self, engine: GovernanceEngine) -> None:
        calls: list[str] = []

        def my_validator(action: str, ctx: dict) -> list:
            calls.append(action)
            return []

        engine.add_validator(my_validator)
        engine.validate("run safety test")
        assert len(calls) >= 1
