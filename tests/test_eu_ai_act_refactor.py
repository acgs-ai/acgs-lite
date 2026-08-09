"""Tests for the eu_ai_act module — covers exported APIs without license gating.

These tests import the underlying implementations directly to avoid
license-tier checks, which are tested separately.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from acgs_lite.eu_ai_act.article12 import Article12Logger, Article12Record, _hash_content
from acgs_lite.eu_ai_act.compliance_checklist import (
    ChecklistItem,
    ChecklistStatus,
    ComplianceChecklist,
)
from acgs_lite.eu_ai_act.human_oversight import (
    DEFAULT_OVERSIGHT_THRESHOLD,
    HumanOversightGateway,
    OversightDecision,
    OversightOutcome,
)
from acgs_lite.eu_ai_act.risk_classification import (
    ClassificationResult,
    RiskClassifier,
    RiskLevel,
    SystemDescription,
)
from acgs_lite.eu_ai_act.transparency import TransparencyDisclosure

# ---------------------------------------------------------------------------
# Risk Classification (Article 6 + Annex III)
# ---------------------------------------------------------------------------


class TestRiskClassifier:
    def test_minimal_risk_default(self) -> None:
        classifier = RiskClassifier()
        desc = SystemDescription(system_id="s1", purpose="weather chatbot", domain="weather")
        result = classifier.classify(desc)
        assert result.level == RiskLevel.MINIMAL_RISK
        assert not result.is_high_risk
        assert not result.is_prohibited
        assert result.obligations == []

    def test_high_risk_employment(self) -> None:
        classifier = RiskClassifier()
        desc = SystemDescription(
            system_id="s2", purpose="hiring", domain="employment", employment=True
        )
        result = classifier.classify(desc)
        assert result.level == RiskLevel.HIGH_RISK
        assert result.is_high_risk
        assert result.requires_article12_logging
        assert result.requires_human_oversight
        assert len(result.obligations) > 0

    def test_high_risk_by_domain(self) -> None:
        classifier = RiskClassifier()
        desc = SystemDescription(system_id="s3", purpose="diagnosis", domain="healthcare")
        result = classifier.classify(desc)
        assert result.level == RiskLevel.HIGH_RISK

    def test_unacceptable_social_scoring(self) -> None:
        classifier = RiskClassifier()
        desc = SystemDescription(
            system_id="s4", purpose="scoring", domain="gov", social_scoring=True
        )
        result = classifier.classify(desc)
        assert result.level == RiskLevel.UNACCEPTABLE
        assert result.is_prohibited

    def test_unacceptable_subliminal(self) -> None:
        classifier = RiskClassifier()
        desc = SystemDescription(
            system_id="s5", purpose="ads", domain="marketing", subliminal_manipulation=True
        )
        result = classifier.classify(desc)
        assert result.is_prohibited

    def test_unacceptable_vulnerability_exploitation(self) -> None:
        classifier = RiskClassifier()
        desc = SystemDescription(
            system_id="s6", purpose="targeting", domain="ads", vulnerability_exploitation=True
        )
        result = classifier.classify(desc)
        assert result.is_prohibited

    def test_unacceptable_biometric_law_enforcement(self) -> None:
        classifier = RiskClassifier()
        desc = SystemDescription(
            system_id="s7",
            purpose="id",
            domain="police",
            biometric_processing=True,
            law_enforcement=True,
        )
        result = classifier.classify(desc)
        assert result.is_prohibited

    def test_limited_risk_chatbot(self) -> None:
        classifier = RiskClassifier()
        desc = SystemDescription(system_id="s8", purpose="chat", domain="chatbot")
        result = classifier.classify(desc)
        assert result.level == RiskLevel.LIMITED_RISK

    def test_classify_many(self) -> None:
        classifier = RiskClassifier()
        descs = [
            SystemDescription(system_id="a", purpose="p", domain="weather"),
            SystemDescription(system_id="b", purpose="p", domain="employment", employment=True),
        ]
        results = classifier.classify_many(descs)
        assert len(results) == 2
        assert results[0].level == RiskLevel.MINIMAL_RISK
        assert results[1].level == RiskLevel.HIGH_RISK

    def test_classification_result_to_dict(self) -> None:
        result = ClassificationResult(
            level=RiskLevel.MINIMAL_RISK,
            article_basis="Recital 69",
            obligations=[],
            rationale="test",
        )
        d = result.to_dict()
        assert d["risk_level"] == "minimal_risk"
        assert "disclaimer" in d


# ---------------------------------------------------------------------------
# Article 12 — Record-Keeping
# ---------------------------------------------------------------------------


class TestArticle12Logger:
    def test_log_call_success(self) -> None:
        logger = Article12Logger(system_id="test-sys")
        result = logger.log_call("op1", call=lambda: "hello", input_text="prompt")
        assert result == "hello"
        assert logger.record_count == 1
        assert logger.verify_chain()

    def test_log_call_failure(self) -> None:
        logger = Article12Logger(system_id="test-sys")

        def failing() -> str:
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            logger.log_call("op2", call=failing)
        assert logger.record_count == 1
        assert logger.records[0].outcome == "failure"

    def test_chain_integrity(self) -> None:
        logger = Article12Logger(system_id="test-sys")
        logger.log_call("a", call=lambda: 1)
        logger.log_call("b", call=lambda: 2)
        logger.log_call("c", call=lambda: 3)
        assert logger.verify_chain()
        assert logger.record_count == 3

    def test_record_operation_context_manager(self) -> None:
        logger = Article12Logger(system_id="test-sys")
        with logger.record_operation("manual_op", input_text="input") as ctx:
            ctx.set_output("output")
        assert logger.record_count == 1
        assert logger.records[0].outcome == "success"

    def test_export_jsonl(self) -> None:
        logger = Article12Logger(system_id="test-sys")
        logger.log_call("op", call=lambda: "ok")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            logger.export_jsonl(path)
            lines = path.read_text().strip().split("\n")
            assert len(lines) == 1
            record = json.loads(lines[0])
            assert record["system_id"] == "test-sys"

    def test_export_dict(self) -> None:
        logger = Article12Logger(system_id="test-sys")
        logger.log_call("op", call=lambda: "ok")
        d = logger.export_dict()
        assert d["chain_valid"] is True
        assert d["record_count"] == 1

    def test_compliance_summary_empty(self) -> None:
        logger = Article12Logger(system_id="test-sys")
        summary = logger.compliance_summary()
        assert summary["compliant"] is True
        assert summary["record_count"] == 0

    def test_compliance_summary_with_records(self) -> None:
        logger = Article12Logger(system_id="test-sys")
        logger.log_call("op", call=lambda: "ok")
        summary = logger.compliance_summary()
        assert summary["record_count"] == 1
        assert summary["chain_valid"] is True

    def test_article12_record_hash_deterministic(self) -> None:
        r = Article12Record(
            record_id="r1",
            system_id="s1",
            operation="op",
            timestamp="2025-01-01T00:00:00",
            outcome="success",
        )
        assert r.record_hash == r.record_hash  # deterministic

    def test_hash_content(self) -> None:
        h = _hash_content("test input")
        assert len(h) == 16
        assert h == _hash_content("test input")

    def test_max_records_trim(self) -> None:
        logger = Article12Logger(system_id="test-sys", max_records=3)
        for i in range(5):
            logger.log_call(f"op{i}", call=lambda value=i: value)
        assert logger.record_count == 3

    def test_repr(self) -> None:
        logger = Article12Logger(system_id="test-sys")
        r = repr(logger)
        assert "test-sys" in r
        assert "records=0" in r


# ---------------------------------------------------------------------------
# Article 13 — Transparency
# ---------------------------------------------------------------------------


class TestTransparencyDisclosure:
    def _valid_disclosure(self) -> TransparencyDisclosure:
        return TransparencyDisclosure(
            system_id="s1",
            system_name="Test System",
            provider="Acme",
            intended_purpose="Testing",
            capabilities=["Cap1"],
            limitations=["Lim1"],
            human_oversight_measures=["Measure1"],
            contact_email="test@example.com",
        )

    def test_valid_disclosure(self) -> None:
        d = self._valid_disclosure()
        assert d.is_valid()
        assert d.validate() == []

    def test_invalid_disclosure_missing_fields(self) -> None:
        d = TransparencyDisclosure()
        assert not d.is_valid()
        missing = d.validate()
        assert "system_id" in missing

    def test_to_system_card(self) -> None:
        d = self._valid_disclosure()
        card = d.to_system_card()
        assert card["system_id"] == "s1"
        assert card["validation_status"] == "compliant"
        assert "disclaimer" in card

    def test_render_text(self) -> None:
        d = self._valid_disclosure()
        text = d.render_text()
        assert "Test System" in text
        assert "Article 13" in text

    def test_render_markdown(self) -> None:
        d = self._valid_disclosure()
        md = d.render_markdown()
        assert "# EU AI Act" in md
        assert "Test System" in md

    def test_repr(self) -> None:
        d = self._valid_disclosure()
        r = repr(d)
        assert "s1" in r
        assert "valid=True" in r


# ---------------------------------------------------------------------------
# Article 14 — Human Oversight
# ---------------------------------------------------------------------------


class TestHumanOversightGateway:
    def test_auto_approve_low_impact(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        decision = gw.submit("op", "output", impact_score=0.1)
        assert decision.outcome == OversightOutcome.AUTO_APPROVED
        assert not decision.requires_human_review

    def test_pending_high_impact(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        decision = gw.submit("op", "output", impact_score=0.9)
        assert decision.outcome == OversightOutcome.PENDING
        assert decision.requires_human_review

    def test_approve_decision(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        decision = gw.submit("op", "output", impact_score=0.9)
        approved = gw.approve(decision.decision_id, reviewer_id="r1", notes="ok")
        assert approved.outcome == OversightOutcome.APPROVED
        assert approved.reviewer_id == "r1"

    def test_reject_decision(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        decision = gw.submit("op", "output", impact_score=0.9)
        rejected = gw.reject(decision.decision_id, reviewer_id="r1", notes="bad")
        assert rejected.outcome == OversightOutcome.REJECTED

    def test_escalate_decision(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        decision = gw.submit("op", "output", impact_score=0.9)
        escalated = gw.escalate(decision.decision_id, reason="SLA breach")
        assert escalated.outcome == OversightOutcome.ESCALATED

    def test_approve_nonexistent_raises(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        with pytest.raises(KeyError):
            gw.approve("nonexistent", reviewer_id="r1")

    def test_approve_non_pending_raises(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        decision = gw.submit("op", "output", impact_score=0.1)
        with pytest.raises(ValueError):
            gw.approve(decision.decision_id, reviewer_id="r1")

    def test_invalid_threshold(self) -> None:
        with pytest.raises(ValueError, match="oversight_threshold"):
            HumanOversightGateway(system_id="s1", oversight_threshold=1.5)

    def test_pending_decisions(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        gw.submit("op1", "out1", impact_score=0.9)
        gw.submit("op2", "out2", impact_score=0.1)
        assert len(gw.pending_decisions()) == 1

    def test_compliance_summary_empty(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        summary = gw.compliance_summary()
        assert summary["compliant"] is True
        assert summary["total_decisions"] == 0

    def test_compliance_summary_with_decisions(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        d = gw.submit("op", "out", impact_score=0.9)
        gw.approve(d.decision_id, reviewer_id="r1")
        summary = gw.compliance_summary()
        assert summary["compliant"] is True
        assert summary["reviewed"] == 1

    def test_export_decisions(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        gw.submit("op", "out", impact_score=0.5)
        exported = gw.export_decisions()
        assert len(exported) == 1
        assert "decision_id" in exported[0]

    def test_get_decision(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        d = gw.submit("op", "out", impact_score=0.5)
        assert gw.get_decision(d.decision_id) is not None
        assert gw.get_decision("nonexistent") is None

    def test_notification_callback(self) -> None:
        notified: list[OversightDecision] = []
        gw = HumanOversightGateway(system_id="s1", on_review_required=notified.append)
        gw.submit("op", "out", impact_score=0.9)
        assert len(notified) == 1

    def test_notification_callback_failure_is_suppressed(self) -> None:
        def fail(_: OversightDecision) -> None:
            raise RuntimeError("boom")

        gw = HumanOversightGateway(system_id="s1", on_review_required=fail)
        decision = gw.submit("op", "out", impact_score=0.9)
        assert decision.outcome == OversightOutcome.PENDING
        assert gw.get_decision(decision.decision_id) is decision

    def test_approval_callback_failure_is_suppressed(self) -> None:
        def fail(_: OversightDecision) -> None:
            raise RuntimeError("boom")

        gw = HumanOversightGateway(system_id="s1", on_approved=fail)
        decision = gw.submit("op", "out", impact_score=0.9)
        approved = gw.approve(decision.decision_id, reviewer_id="r1")
        assert approved.outcome == OversightOutcome.APPROVED

    def test_oversight_decision_to_dict(self) -> None:
        gw = HumanOversightGateway(system_id="s1")
        d = gw.submit("op", "out", impact_score=0.5)
        dd = d.to_dict()
        assert dd["system_id"] == "s1"
        assert "outcome" in dd

    def test_default_threshold(self) -> None:
        assert DEFAULT_OVERSIGHT_THRESHOLD == 0.8


# ---------------------------------------------------------------------------
# Compliance Checklist
# ---------------------------------------------------------------------------


class TestComplianceChecklist:
    def test_high_risk_items_populated(self) -> None:
        cl = ComplianceChecklist(system_id="s1")
        assert len(cl.items) > 0
        assert any(i.article_ref == "Article 12" for i in cl.items)

    def test_limited_risk_items(self) -> None:
        cl = ComplianceChecklist(system_id="s1", risk_level="limited_risk")
        assert len(cl.items) > 0
        assert any("Article 50(" in i.article_ref for i in cl.items)

    def test_minimal_risk_empty(self) -> None:
        cl = ComplianceChecklist(system_id="s1", risk_level="minimal_risk")
        assert len(cl.items) == 0
        assert cl.is_gate_clear

    def test_mark_complete(self) -> None:
        cl = ComplianceChecklist(system_id="s1")
        assert cl.mark_complete("Article 12", evidence="Logger attached")
        item = cl.get_item("Article 12")
        assert item is not None
        assert item.status == ChecklistStatus.COMPLIANT

    def test_mark_partial(self) -> None:
        cl = ComplianceChecklist(system_id="s1")
        assert cl.mark_partial("Article 12", evidence="Partial")
        item = cl.get_item("Article 12")
        assert item is not None
        assert item.status == ChecklistStatus.PARTIAL

    def test_mark_not_applicable(self) -> None:
        cl = ComplianceChecklist(system_id="s1")
        assert cl.mark_not_applicable("Article 12", reason="N/A")

    def test_mark_nonexistent_returns_false(self) -> None:
        cl = ComplianceChecklist(system_id="s1")
        assert not cl.mark_complete("Article 999")

    def test_auto_populate(self) -> None:
        cl = ComplianceChecklist(system_id="s1")
        cl.auto_populate_acgs_lite()
        assert cl.compliance_score > 0.0
        item = cl.get_item("Article 12")
        assert item is not None
        assert item.status == ChecklistStatus.COMPLIANT

    def test_gate_not_clear_initially(self) -> None:
        cl = ComplianceChecklist(system_id="s1")
        assert not cl.is_gate_clear
        assert len(cl.blocking_gaps) > 0

    def test_generate_report(self) -> None:
        cl = ComplianceChecklist(system_id="s1")
        report = cl.generate_report()
        assert report["system_id"] == "s1"
        assert "items" in report
        assert "compliance_score" in report

    def test_checklist_item_to_dict(self) -> None:
        item = ChecklistItem(article_ref="Article 12", requirement="Record-keeping")
        d = item.to_dict()
        assert d["article_ref"] == "Article 12"
        assert d["status"] == "pending"

    def test_repr(self) -> None:
        cl = ComplianceChecklist(system_id="s1")
        r = repr(cl)
        assert "s1" in r


# ---------------------------------------------------------------------------
# Module __init__ exports
# ---------------------------------------------------------------------------


class TestModuleExports:
    def test_risk_level_enum(self) -> None:
        assert RiskLevel.HIGH_RISK.value == "high_risk"
        assert RiskLevel.UNACCEPTABLE.value == "unacceptable"

    def test_checklist_status_enum(self) -> None:
        assert ChecklistStatus.PENDING.value == "pending"
        assert ChecklistStatus.COMPLIANT.value == "compliant"

    def test_oversight_outcome_enum(self) -> None:
        assert OversightOutcome.APPROVED.value == "approved"
        assert OversightOutcome.PENDING.value == "pending"

    def test_system_description_frozen(self) -> None:
        desc = SystemDescription(system_id="s1", purpose="p", domain="d")
        with pytest.raises(AttributeError):
            desc.system_id = "changed"  # type: ignore[misc]

    def test_article12_record_frozen(self) -> None:
        r = Article12Record(
            record_id="r1",
            system_id="s1",
            operation="op",
            timestamp="t",
            outcome="success",
        )
        with pytest.raises(AttributeError):
            r.outcome = "failure"  # type: ignore[misc]
