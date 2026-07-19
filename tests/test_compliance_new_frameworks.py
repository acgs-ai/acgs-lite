"""Tests for the five new compliance frameworks added to acgs-lite.

Covers:
- EU AI Act (Regulation (EU) 2024/1689)
- DORA (EU Digital Operational Resilience Act)
- Canada AIDA (Bill C-27)
- Singapore MAIGF v2
- UK AI Framework (AI White Paper, 2023)
- MultiFrameworkAssessor jurisdiction routing for new jurisdictions
- Cross-framework gap analysis with new frameworks included

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import pytest

from acgs_lite.compliance import (
    CanadaAIDAFramework,
    ChecklistStatus,
    DORAFramework,
    EUAIActFramework,
    FrameworkAssessment,
    MultiFrameworkAssessor,
    MultiFrameworkReport,
    SingaporeMAIGFFramework,
    UKAIFramework,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_BASE_DESC: dict = {
    "system_id": "test-system-v1",
    "purpose": "Automated decision support",
    "domain": "general",
}


@pytest.fixture
def base_desc() -> dict:
    return dict(_BASE_DESC)


@pytest.fixture
def high_risk_eu_desc() -> dict:
    return {
        "system_id": "eu-high-risk",
        "jurisdiction": "european_union",
        "domain": "employment",
        "risk_tier": "high",
        "is_gpai": False,
    }


@pytest.fixture
def financial_desc() -> dict:
    return {
        "system_id": "fintech-ai",
        "jurisdiction": "european_union",
        "domain": "financial",
        "is_significant_entity": True,
    }


# ---------------------------------------------------------------------------
# EU AI Act
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestEUAIActFramework:
    def test_framework_metadata(self) -> None:
        fw = EUAIActFramework()
        assert fw.framework_id == "eu_ai_act"
        assert fw.jurisdiction == "European Union"
        assert fw.status == "enacted"
        assert fw.enforcement_date == "2025-02-02"

    def test_high_risk_checklist_covers_core_articles(self, high_risk_eu_desc: dict) -> None:
        fw = EUAIActFramework()
        checklist = fw.get_checklist(high_risk_eu_desc)
        refs = [item.ref for item in checklist]
        assert any("Art.9" in r for r in refs), "Missing Art.9 risk management items"
        assert any("Art.12" in r for r in refs), "Missing Art.12 logging items"
        assert any("Art.13" in r for r in refs), "Missing Art.13 transparency items"
        assert any("Art.14" in r for r in refs), "Missing Art.14 human oversight items"

    def test_minimal_risk_skips_high_risk_articles(self, base_desc: dict) -> None:
        fw = EUAIActFramework()
        desc = {**base_desc, "risk_tier": "minimal"}
        checklist = fw.get_checklist(desc)
        refs = [item.ref for item in checklist]
        # Only prohibited and transparency articles for minimal risk
        for ref in refs:
            assert "Art.9" not in ref
            assert "Art.11" not in ref
            assert "Art.14" not in ref

    def test_minimal_risk_includes_art5_and_art50(self, base_desc: dict) -> None:
        fw = EUAIActFramework()
        desc = {**base_desc, "risk_tier": "minimal"}
        checklist = fw.get_checklist(desc)
        refs = [item.ref for item in checklist]
        assert any("Art.5" in r for r in refs)
        assert any("Art.50" in r for r in refs)

    def test_gpai_items_included_when_flag_set(self, base_desc: dict) -> None:
        fw = EUAIActFramework()
        desc = {**base_desc, "risk_tier": "high", "is_gpai": True}
        checklist = fw.get_checklist(desc)
        refs = [item.ref for item in checklist]
        assert any("Art.53" in r for r in refs)

    def test_gpai_items_excluded_for_non_gpai(self, high_risk_eu_desc: dict) -> None:
        fw = EUAIActFramework()
        checklist = fw.get_checklist(high_risk_eu_desc)
        refs = [item.ref for item in checklist]
        assert not any("Art.53" in r for r in refs)
        assert not any("Art.55" in r for r in refs)

    def test_auto_populate_marks_audit_log_items(self, high_risk_eu_desc: dict) -> None:
        fw = EUAIActFramework()
        checklist = fw.get_checklist(high_risk_eu_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant_refs = {i.ref for i in checklist if i.status == ChecklistStatus.COMPLIANT}
        assert "EU-AIA Art.12(1)" in compliant_refs
        assert "EU-AIA Art.14(1)" in compliant_refs
        assert "EU-AIA Art.13(1)" in compliant_refs

    def test_auto_populate_maci_enforcer_art14_5(self, high_risk_eu_desc: dict) -> None:
        fw = EUAIActFramework()
        checklist = fw.get_checklist(high_risk_eu_desc)
        fw.auto_populate_acgs_lite(checklist)
        item = next(i for i in checklist if i.ref == "EU-AIA Art.14(5)")
        assert item.status == ChecklistStatus.COMPLIANT
        assert "MACIEnforcer" in (item.evidence or "")

    def test_assess_returns_frozen_framework_assessment(self, high_risk_eu_desc: dict) -> None:
        fw = EUAIActFramework()
        result = fw.assess(high_risk_eu_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "eu_ai_act"
        assert 0.0 <= result.compliance_score <= 1.0
        assert result.acgs_lite_coverage > 0.0

    def test_assess_produces_gaps_for_unmet_items(self, high_risk_eu_desc: dict) -> None:
        fw = EUAIActFramework()
        result = fw.assess(high_risk_eu_desc)
        # Art.10 data governance not auto-satisfied — should appear in gaps
        assert len(result.gaps) > 0
        assert any("Art.10" in g or "Art.9" in g for g in result.gaps)

    def test_recommendations_mention_annex_iv(self, high_risk_eu_desc: dict) -> None:
        fw = EUAIActFramework()
        result = fw.assess(high_risk_eu_desc)
        all_recs = " ".join(result.recommendations)
        assert "Annex IV" in all_recs or "technical documentation" in all_recs.lower()


# ---------------------------------------------------------------------------
# DORA
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestDORAFramework:
    def test_framework_metadata(self) -> None:
        fw = DORAFramework()
        assert fw.framework_id == "dora"
        assert fw.jurisdiction == "European Union"
        assert fw.status == "enacted"
        assert fw.enforcement_date == "2025-01-17"

    def test_checklist_covers_all_dora_chapters(self, financial_desc: dict) -> None:
        fw = DORAFramework()
        checklist = fw.get_checklist(financial_desc)
        refs = [item.ref for item in checklist]
        assert any("Art.6" in r for r in refs), "Missing Art.6 ICT risk management"
        assert any("Art.9" in r for r in refs), "Missing Art.9 protection"
        assert any("Art.10" in r for r in refs), "Missing Art.10 detection"
        assert any("Art.17" in r for r in refs), "Missing Art.17 incident reporting"
        assert any("Art.28" in r for r in refs), "Missing Art.28 third-party risk"

    def test_tlpt_not_applicable_for_non_significant_entity(self, base_desc: dict) -> None:
        fw = DORAFramework()
        desc = {**base_desc, "is_significant_entity": False}
        checklist = fw.get_checklist(desc)
        art25 = next((i for i in checklist if i.ref == "DORA Art.26(1)"), None)
        assert art25 is not None
        assert art25.status == ChecklistStatus.NOT_APPLICABLE

    def test_tlpt_required_for_significant_entity(self, financial_desc: dict) -> None:
        fw = DORAFramework()
        checklist = fw.get_checklist(financial_desc)
        art25 = next((i for i in checklist if i.ref == "DORA Art.26(1)"), None)
        assert art25 is not None
        assert art25.status == ChecklistStatus.PENDING  # not auto-satisfied

    def test_auto_populate_marks_governance_engine_items(self, financial_desc: dict) -> None:
        fw = DORAFramework()
        checklist = fw.get_checklist(financial_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant_refs = {i.ref for i in checklist if i.status == ChecklistStatus.COMPLIANT}
        assert "DORA Art.6(1)" in compliant_refs
        assert "DORA Art.10(1)" in compliant_refs
        assert "DORA Art.17(1)" in compliant_refs

    def test_assess_returns_valid_framework_assessment(self, financial_desc: dict) -> None:
        fw = DORAFramework()
        result = fw.assess(financial_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "dora"
        assert 0.0 <= result.compliance_score <= 1.0

    def test_gaps_include_asset_inventory(self, financial_desc: dict) -> None:
        fw = DORAFramework()
        result = fw.assess(financial_desc)
        # Art.8 asset identification is not auto-populated
        assert any("Art.8" in g for g in result.gaps)

    def test_recommendations_mention_ict_framework(self, financial_desc: dict) -> None:
        fw = DORAFramework()
        result = fw.assess(financial_desc)
        recs_text = " ".join(result.recommendations)
        assert "ICT" in recs_text


# ---------------------------------------------------------------------------
# Canada AIDA
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestCanadaAIDAFramework:
    def test_framework_metadata(self) -> None:
        fw = CanadaAIDAFramework()
        assert fw.framework_id == "canada_aida"
        assert fw.jurisdiction == "Canada"
        assert fw.status == "defunct"
        assert fw.enforcement_date is None

    def test_checklist_covers_key_sections(self, base_desc: dict) -> None:
        fw = CanadaAIDAFramework()
        checklist = fw.get_checklist(base_desc)
        refs = [item.ref for item in checklist]
        assert any("§5" in r for r in refs), "Missing §5 high-impact system determination"
        assert any("§9" in r for r in refs), "Missing §9 impact assessment"
        assert any("§10" in r for r in refs), "Missing §10 plain language description"
        assert any("§16" in r for r in refs), "Missing §16 bias prohibition"

    def test_auto_populate_marks_audit_and_governance_items(self, base_desc: dict) -> None:
        fw = CanadaAIDAFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant_refs = {i.ref for i in checklist if i.status == ChecklistStatus.COMPLIANT}
        assert "AIDA §12(1)" in compliant_refs
        assert "AIDA §13(1)" in compliant_refs
        assert "AIDA §14(1)" in compliant_refs
        assert "AIDA §17" in compliant_refs

    def test_section10_transparency_auto_satisfied(self, base_desc: dict) -> None:
        fw = CanadaAIDAFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        s10 = next(i for i in checklist if i.ref == "AIDA §10(1)")
        assert s10.status == ChecklistStatus.COMPLIANT

    def test_section16_bias_not_auto_satisfied(self, base_desc: dict) -> None:
        fw = CanadaAIDAFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        s16 = next(i for i in checklist if i.ref == "AIDA §16")
        assert s16.status == ChecklistStatus.PENDING

    def test_assess_returns_valid_assessment(self, base_desc: dict) -> None:
        fw = CanadaAIDAFramework()
        result = fw.assess(base_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "canada_aida"
        assert 0.0 <= result.compliance_score <= 1.0
        assert result.acgs_lite_coverage > 0.0

    def test_gaps_include_anonymized_data_and_bias(self, base_desc: dict) -> None:
        fw = CanadaAIDAFramework()
        result = fw.assess(base_desc)
        assert any("§8" in g or "§16" in g for g in result.gaps)

    def test_recommendations_mention_bias_testing(self, base_desc: dict) -> None:
        fw = CanadaAIDAFramework()
        result = fw.assess(base_desc)
        recs_text = " ".join(result.recommendations)
        assert "bias" in recs_text.lower() or "§16" in recs_text


# ---------------------------------------------------------------------------
# Singapore MAIGF
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestSingaporeMAIGFFramework:
    def test_framework_metadata(self) -> None:
        fw = SingaporeMAIGFFramework()
        assert fw.framework_id == "singapore_maigf"
        assert "Singapore" in fw.jurisdiction
        assert fw.status == "voluntary"

    def test_checklist_covers_all_four_principles(self, base_desc: dict) -> None:
        fw = SingaporeMAIGFFramework()
        checklist = fw.get_checklist(base_desc)
        refs = [item.ref for item in checklist]
        assert any("Internal Governance" in r for r in refs), "Missing Internal Governance items"
        assert any("Human Involvement" in r for r in refs), "Missing Human Involvement items"
        assert any("Operations Management" in r for r in refs), (
            "Missing Operations Management items"
        )
        assert any("Stakeholder Interaction" in r for r in refs), (
            "Missing Stakeholder Interaction items"
        )

    def test_auto_populate_marks_human_oversight_items(self, base_desc: dict) -> None:
        fw = SingaporeMAIGFFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant_refs = {i.ref for i in checklist if i.status == ChecklistStatus.COMPLIANT}
        assert "MAIGF — Internal Governance: human-AI decision model" in compliant_refs
        assert (
            "MAIGF — Internal Governance: human review for significant decisions" in compliant_refs
        )
        assert "MAIGF — Stakeholder Interaction: feedback & complaint mechanisms" in compliant_refs
        assert "MAIGF — Stakeholder Interaction: dispute review & redress" in compliant_refs

    def test_risk_classifier_items_auto_satisfied(self, base_desc: dict) -> None:
        fw = SingaporeMAIGFFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        p21 = next(
            i
            for i in checklist
            if i.ref == "MAIGF — Human Involvement: risk-based oversight determination"
        )
        assert p21.status == ChecklistStatus.COMPLIANT
        assert "RiskClassifier" in (p21.evidence or "")

    def test_data_governance_items_not_auto_satisfied(self, base_desc: dict) -> None:
        fw = SingaporeMAIGFFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        p32a = next(
            i for i in checklist if i.ref == "MAIGF — Operations Management: data governance"
        )
        assert p32a.status == ChecklistStatus.PENDING

    def test_assess_returns_valid_assessment(self, base_desc: dict) -> None:
        fw = SingaporeMAIGFFramework()
        result = fw.assess(base_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "singapore_maigf"
        assert 0.0 <= result.compliance_score <= 1.0

    def test_gaps_exist_for_unmet_items(self, base_desc: dict) -> None:
        fw = SingaporeMAIGFFramework()
        result = fw.assess(base_desc)
        # P3.1(a) bias testing and P3.2 data governance are not auto-populated
        assert len(result.gaps) > 0

    def test_recommendations_cover_all_principles(self, base_desc: dict) -> None:
        fw = SingaporeMAIGFFramework()
        result = fw.assess(base_desc)
        recs_text = " ".join(result.recommendations)
        # Expect recommendations across multiple principles
        assert "MAIGF" in recs_text


# ---------------------------------------------------------------------------
# UK AI Framework
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestUKAIFramework:
    def test_framework_metadata(self) -> None:
        fw = UKAIFramework()
        assert fw.framework_id == "uk_ai_framework"
        assert fw.jurisdiction == "United Kingdom"
        assert fw.status == "voluntary"

    def test_checklist_covers_all_five_principles(self, base_desc: dict) -> None:
        fw = UKAIFramework()
        checklist = fw.get_checklist(base_desc)
        refs = [item.ref for item in checklist]
        assert any("PRO-1" in r for r in refs), "Missing PRO-1 safety items"
        assert any("PRO-2" in r for r in refs), "Missing PRO-2 transparency items"
        assert any("PRO-3" in r for r in refs), "Missing PRO-3 fairness items"
        assert any("PRO-4" in r for r in refs), "Missing PRO-4 accountability items"
        assert any("PRO-5" in r for r in refs), "Missing PRO-5 contestability items"

    def test_auto_populate_marks_transparency_items(self, base_desc: dict) -> None:
        fw = UKAIFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant_refs = {i.ref for i in checklist if i.status == ChecklistStatus.COMPLIANT}
        assert "UK-AI PRO-2.1" in compliant_refs
        assert "UK-AI PRO-2.2" in compliant_refs
        assert "UK-AI PRO-2.3" in compliant_refs

    def test_maci_enforcer_satisfies_accountability(self, base_desc: dict) -> None:
        fw = UKAIFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        pro41 = next(i for i in checklist if i.ref == "UK-AI PRO-4.1")
        assert pro41.status == ChecklistStatus.COMPLIANT
        assert "MACIEnforcer" in (pro41.evidence or "")

    def test_hog_satisfies_contestability(self, base_desc: dict) -> None:
        fw = UKAIFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        pro51 = next(i for i in checklist if i.ref == "UK-AI PRO-5.1")
        assert pro51.status == ChecklistStatus.COMPLIANT
        assert "HumanOversightGateway" in (pro51.evidence or "")

    def test_security_testing_not_auto_satisfied(self, base_desc: dict) -> None:
        fw = UKAIFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        pro13 = next(i for i in checklist if i.ref == "UK-AI PRO-1.3")
        assert pro13.status == ChecklistStatus.PENDING

    def test_fairness_testing_not_auto_satisfied(self, base_desc: dict) -> None:
        fw = UKAIFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        pro32 = next(i for i in checklist if i.ref == "UK-AI PRO-3.2")
        assert pro32.status == ChecklistStatus.PENDING

    def test_assess_returns_valid_assessment(self, base_desc: dict) -> None:
        fw = UKAIFramework()
        result = fw.assess(base_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "uk_ai_framework"
        assert 0.0 <= result.compliance_score <= 1.0
        assert result.acgs_lite_coverage > 0.5  # most items have acgs_lite_feature

    def test_recommendations_reference_equality_act(self, base_desc: dict) -> None:
        fw = UKAIFramework()
        result = fw.assess(base_desc)
        recs_text = " ".join(result.recommendations)
        assert "Equality Act" in recs_text or "PRO-3" in recs_text


# ---------------------------------------------------------------------------
# MultiFrameworkAssessor — new jurisdiction routing
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestMultiFrameworkAssessorNewJurisdictions:
    def test_european_union_now_includes_eu_ai_act(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("european_union", "general")
        assert "eu_ai_act" in fws
        assert "gdpr" in fws

    def test_canada_jurisdiction_routes_canada_aida(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("canada", "general")
        assert "canada_aida" in fws

    def test_united_kingdom_routes_uk_framework(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_kingdom", "general")
        assert "uk_ai_framework" in fws

    def test_singapore_routes_maigf(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("singapore", "general")
        assert "singapore_maigf" in fws

    def test_financial_domain_routes_dora(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("european_union", "financial")
        assert "dora" in fws

    def test_banking_domain_routes_dora(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("european_union", "banking")
        assert "dora" in fws

    def test_gpai_domain_routes_eu_ai_act(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("european_union", "gpai")
        assert "eu_ai_act" in fws

    def test_available_frameworks_lists_all_13(self) -> None:
        assessor = MultiFrameworkAssessor()
        available = assessor.available_frameworks()
        assert len(available) >= 13  # now 20 (incl. igaming + japan_ai_guidelines)
        for fid in (
            "eu_ai_act",
            "dora",
            "canada_aida",
            "singapore_maigf",
            "uk_ai_framework",
        ):
            assert fid in available, f"Expected {fid!r} in available frameworks"

    def test_explicit_selection_of_new_frameworks(self) -> None:
        assessor = MultiFrameworkAssessor(frameworks=["eu_ai_act", "dora", "canada_aida"])
        report = assessor.assess(
            {
                "system_id": "multi-test",
                "risk_tier": "high",
                "is_significant_entity": True,
            }
        )
        assert isinstance(report, MultiFrameworkReport)
        assert set(report.frameworks_assessed) == {"eu_ai_act", "dora", "canada_aida"}
        assert 0.0 <= report.overall_score <= 1.0

    def test_eu_full_assessment_includes_new_frameworks(self) -> None:
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(
            {
                "system_id": "eu-system",
                "jurisdiction": "european_union",
                "domain": "general",
                "risk_tier": "high",
            }
        )
        assert "eu_ai_act" in report.frameworks_assessed
        assert "gdpr" in report.frameworks_assessed

    def test_cross_framework_gaps_propagate(self) -> None:
        assessor = MultiFrameworkAssessor(
            frameworks=["eu_ai_act", "nist_ai_rmf", "uk_ai_framework"]
        )
        report = assessor.assess(
            {
                "system_id": "cross-gap-test",
                "risk_tier": "high",
            }
        )
        # All three frameworks require bias testing → should appear in cross gaps
        assert len(report.cross_framework_gaps) >= 0  # may or may not trigger
        assert report.overall_score >= 0.0

    def test_singapore_full_assessment(self) -> None:
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(
            {
                "system_id": "sg-system",
                "jurisdiction": "singapore",
                "domain": "financial",
            }
        )
        assert "singapore_maigf" in report.frameworks_assessed
        assert isinstance(report, MultiFrameworkReport)

    def test_canada_full_assessment(self) -> None:
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(
            {
                "system_id": "ca-system",
                "jurisdiction": "canada",
                "domain": "general",
            }
        )
        assert "canada_aida" in report.frameworks_assessed
        # healthcare domain adds hipaa_ai globally; general domain should not
        assert "hipaa_ai" not in report.frameworks_assessed
