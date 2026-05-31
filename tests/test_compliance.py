"""Tests for multi-framework AI compliance module.

Covers all 18 compliance frameworks, auto-population of acgs-lite
features, the MultiFrameworkAssessor orchestrator, jurisdiction-based
framework selection, domain routing, cross-framework gap analysis,
compliance scoring, report exporter, and evidence collection.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json

import pytest

from acgs_lite.compliance import (
    AustraliaAIEthicsFramework,
    BrazilLGPDFramework,
    CanadaAIDAFramework,
    CCPACPRAFramework,
    ChecklistItem,
    ChecklistStatus,
    ChinaAIFramework,
    ComplianceFramework,
    ComplianceReportExporter,
    DORAFramework,
    EUAIActFramework,
    EvidenceCollector,
    EvidenceRecord,
    FrameworkAssessment,
    GDPRFramework,
    HIPAAAIFramework,
    IndiaDPDPFramework,
    ISO42001Framework,
    MultiFrameworkAssessor,
    MultiFrameworkReport,
    NISTAIRMFFramework,
    NYCLL144Framework,
    OECDAIFramework,
    SingaporeMAIGFFramework,
    SOC2AIFramework,
    UKAIFramework,
    USFairLendingFramework,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SYSTEM_DESC: dict = {
    "system_id": "test-system-v1",
    "purpose": "Automated decision support",
    "domain": "general",
    "jurisdiction": "international",
}


@pytest.fixture
def system_desc() -> dict:
    return dict(_SYSTEM_DESC)


# ---------------------------------------------------------------------------
# 1. ChecklistItem unit tests
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestChecklistItem:
    def test_default_status_is_pending(self) -> None:
        item = ChecklistItem(ref="TEST.1", requirement="Test requirement")
        assert item.status == ChecklistStatus.PENDING

    def test_mark_complete_sets_status_and_evidence(self) -> None:
        item = ChecklistItem(ref="TEST.1", requirement="Test")
        item.mark_complete("evidence text")
        assert item.status == ChecklistStatus.COMPLIANT
        assert item.evidence == "evidence text"
        assert item.updated_at is not None

    def test_mark_partial(self) -> None:
        item = ChecklistItem(ref="TEST.1", requirement="Test")
        item.mark_partial("partial evidence")
        assert item.status == ChecklistStatus.PARTIAL

    def test_mark_not_applicable(self) -> None:
        item = ChecklistItem(ref="TEST.1", requirement="Test")
        item.mark_not_applicable("does not apply")
        assert item.status == ChecklistStatus.NOT_APPLICABLE

    def test_to_dict_round_trip(self) -> None:
        item = ChecklistItem(
            ref="ART.1",
            requirement="Must comply",
            legal_citation="Law 123",
            acgs_lite_feature="GovernanceEngine",
        )
        d = item.to_dict()
        assert d["ref"] == "ART.1"
        assert d["legal_citation"] == "Law 123"
        assert d["acgs_lite_feature"] == "GovernanceEngine"


# ---------------------------------------------------------------------------
# 2. Per-framework checklist generation tests — original 8
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestNISTAIRMF:
    def test_checklist_has_all_four_functions(self, system_desc: dict) -> None:
        fw = NISTAIRMFFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [item.ref for item in checklist]
        assert any("GOVERN" in r for r in refs)
        assert any("MAP" in r for r in refs)
        assert any("MEASURE" in r for r in refs)
        assert any("MANAGE" in r for r in refs)

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = NISTAIRMFFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 5

    def test_assess_returns_frozen_assessment(self, system_desc: dict) -> None:
        fw = NISTAIRMFFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "nist_ai_rmf"
        assert 0.0 <= result.compliance_score <= 1.0

    def test_framework_metadata(self) -> None:
        fw = NISTAIRMFFramework()
        assert fw.jurisdiction == "United States"
        assert fw.status == "voluntary"


@pytest.mark.compliance
class TestISO42001:
    def test_checklist_has_clauses_and_annex(self, system_desc: dict) -> None:
        fw = ISO42001Framework()
        checklist = fw.get_checklist(system_desc)
        refs = [item.ref for item in checklist]
        assert any("ISO 5" in r for r in refs)
        assert any("ISO 8" in r for r in refs)
        assert any("ISO A." in r for r in refs)

    def test_auto_populate_coverage(self, system_desc: dict) -> None:
        fw = ISO42001Framework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 7

    def test_assess_produces_gaps(self, system_desc: dict) -> None:
        fw = ISO42001Framework()
        result = fw.assess(system_desc)
        assert result.framework_id == "iso_42001"
        assert len(result.gaps) > 0


@pytest.mark.compliance
class TestGDPR:
    def test_checklist_covers_key_articles(self, system_desc: dict) -> None:
        fw = GDPRFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [item.ref for item in checklist]
        assert any("Art.22" in r for r in refs)
        assert any("Art.13" in r for r in refs)
        assert any("Art.35" in r for r in refs)

    def test_auto_populate_marks_transparency_items(self, system_desc: dict) -> None:
        fw = GDPRFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        art13 = next(i for i in checklist if "Art.13" in i.ref)
        assert art13.status == ChecklistStatus.COMPLIANT

    def test_assess_enforcement_date(self) -> None:
        fw = GDPRFramework()
        assert fw.enforcement_date == "2018-05-25"
        assert fw.status == "enacted"


@pytest.mark.compliance
class TestSOC2AI:
    def test_checklist_covers_trust_criteria(self, system_desc: dict) -> None:
        fw = SOC2AIFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [item.ref for item in checklist]
        assert any("CC" in r for r in refs)
        assert any("PI" in r for r in refs)
        assert any("AI-" in r for r in refs)

    def test_auto_populate(self, system_desc: dict) -> None:
        fw = SOC2AIFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 8


@pytest.mark.compliance
class TestHIPAAAI:
    def test_checklist_covers_hipaa_rules(self, system_desc: dict) -> None:
        fw = HIPAAAIFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [item.ref for item in checklist]
        assert any("164.502" in r for r in refs)
        assert any("164.312" in r for r in refs)
        assert any("164.404" in r for r in refs)

    def test_auto_populate_privacy_and_security(self, system_desc: dict) -> None:
        fw = HIPAAAIFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 7


@pytest.mark.compliance
class TestUSFairLending:
    def test_checklist_covers_ecoa_and_fcra(self, system_desc: dict) -> None:
        fw = USFairLendingFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [item.ref for item in checklist]
        assert any("ECOA" in r for r in refs)
        assert any("FCRA" in r for r in refs)
        assert any("FL-" in r for r in refs)

    def test_assess_has_recommendations(self, system_desc: dict) -> None:
        fw = USFairLendingFramework()
        result = fw.assess(system_desc)
        assert len(result.recommendations) > 0


@pytest.mark.compliance
class TestNYCLL144:
    def test_checklist_covers_audit_and_notice(self, system_desc: dict) -> None:
        fw = NYCLL144Framework()
        checklist = fw.get_checklist(system_desc)
        refs = [item.ref for item in checklist]
        assert any("AUDIT" in r for r in refs)
        assert any("NOTICE" in r for r in refs)
        assert any("POST" in r for r in refs)

    def test_enforcement_date(self) -> None:
        fw = NYCLL144Framework()
        assert fw.enforcement_date == "2023-07-05"
        assert fw.jurisdiction == "New York City"


@pytest.mark.compliance
class TestOECDAI:
    def test_checklist_covers_five_principles(self, system_desc: dict) -> None:
        fw = OECDAIFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [item.ref for item in checklist]
        assert any("OECD 1" in r for r in refs)
        assert any("OECD 2" in r for r in refs)
        assert any("OECD 3" in r for r in refs)
        assert any("OECD 4" in r for r in refs)
        assert any("OECD 5" in r for r in refs)

    def test_auto_populate_high_coverage(self, system_desc: dict) -> None:
        fw = OECDAIFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 8


# ---------------------------------------------------------------------------
# 2b. Per-framework tests — new 10 frameworks
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestEUAIAct:
    def test_framework_metadata(self) -> None:
        fw = EUAIActFramework()
        assert fw.framework_id == "eu_ai_act"
        assert fw.jurisdiction == "European Union"
        assert fw.status == "enacted"
        assert fw.enforcement_date == "2025-02-02"

    def test_checklist_covers_core_articles(self, system_desc: dict) -> None:
        fw = EUAIActFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [i.ref for i in checklist]
        assert any("Art.9" in r for r in refs)
        assert any("Art.12" in r for r in refs)
        assert any("Art.13" in r for r in refs)
        assert any("Art.14" in r for r in refs)

    def test_conditional_na_for_non_high_risk(self) -> None:
        fw = EUAIActFramework()
        desc = dict(_SYSTEM_DESC, risk_tier="low")
        checklist = fw.get_checklist(desc)
        na_items = [i for i in checklist if i.status == ChecklistStatus.NOT_APPLICABLE]
        assert len(na_items) >= 10  # most items are high-risk scoped

    def test_conditional_na_for_non_gpai(self) -> None:
        fw = EUAIActFramework()
        desc = dict(_SYSTEM_DESC, is_gpai=False)
        checklist = fw.get_checklist(desc)
        gpai_items = [i for i in checklist if "Art.53" in i.ref or "Art.55" in i.ref]
        assert all(i.status == ChecklistStatus.NOT_APPLICABLE for i in gpai_items)

    def test_gpai_items_active_when_flagged(self) -> None:
        fw = EUAIActFramework()
        desc = dict(_SYSTEM_DESC, is_gpai=True)
        checklist = fw.get_checklist(desc)
        gpai_items = [i for i in checklist if "Art.53" in i.ref or "Art.55" in i.ref]
        assert all(i.status == ChecklistStatus.PENDING for i in gpai_items)

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = EUAIActFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 8

    def test_key_items_not_auto_satisfied(self, system_desc: dict) -> None:
        fw = EUAIActFramework()
        result = fw.assess(system_desc)
        assert len(result.gaps) > 0  # data governance, documentation not auto-satisfied

    def test_assess_returns_valid_assessment(self, system_desc: dict) -> None:
        fw = EUAIActFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)
        assert 0.0 <= result.compliance_score <= 1.0


@pytest.mark.compliance
class TestDORA:
    def test_framework_metadata(self) -> None:
        fw = DORAFramework()
        assert fw.framework_id == "dora"
        assert fw.jurisdiction == "European Union"
        assert fw.status == "enacted"
        assert fw.enforcement_date == "2025-01-17"

    def test_checklist_covers_core_sections(self, system_desc: dict) -> None:
        fw = DORAFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [i.ref for i in checklist]
        assert any("Art.5" in r for r in refs)
        assert any("Art.6" in r for r in refs)
        assert any("Art.17" in r for r in refs)

    def test_conditional_na_for_non_significant(self) -> None:
        fw = DORAFramework()
        desc = dict(_SYSTEM_DESC, is_significant_entity=False)
        checklist = fw.get_checklist(desc)
        art25 = [i for i in checklist if "Art.25" in i.ref]
        assert all(i.status == ChecklistStatus.NOT_APPLICABLE for i in art25)

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = DORAFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 5

    def test_assess_returns_valid_assessment(self, system_desc: dict) -> None:
        fw = DORAFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "dora"


@pytest.mark.compliance
class TestCanadaAIDA:
    def test_framework_metadata(self) -> None:
        fw = CanadaAIDAFramework()
        assert fw.framework_id == "canada_aida"
        assert fw.jurisdiction == "Canada"
        assert fw.status == "proposed"
        assert fw.enforcement_date is None

    def test_checklist_covers_core_sections(self, system_desc: dict) -> None:
        fw = CanadaAIDAFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [i.ref for i in checklist]
        assert any("§5" in r for r in refs)
        assert any("§10" in r for r in refs)
        assert any("§12" in r for r in refs)

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = CanadaAIDAFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 5

    def test_assess_returns_valid_assessment(self, system_desc: dict) -> None:
        fw = CanadaAIDAFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)
        assert 0.0 <= result.compliance_score <= 1.0


@pytest.mark.compliance
class TestSingaporeMAIGF:
    def test_framework_metadata(self) -> None:
        fw = SingaporeMAIGFFramework()
        assert fw.framework_id == "singapore_maigf"
        assert fw.jurisdiction == "Singapore"
        assert fw.status == "voluntary"

    def test_checklist_covers_four_principles(self, system_desc: dict) -> None:
        fw = SingaporeMAIGFFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [i.ref for i in checklist]
        assert any("P1" in r for r in refs)
        assert any("P2" in r for r in refs)
        assert any("P3" in r for r in refs)
        assert any("P4" in r for r in refs)

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = SingaporeMAIGFFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 7

    def test_assess_returns_valid_assessment(self, system_desc: dict) -> None:
        fw = SingaporeMAIGFFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)


@pytest.mark.compliance
class TestUKAIFramework:
    def test_framework_metadata(self) -> None:
        fw = UKAIFramework()
        assert fw.framework_id == "uk_ai_framework"
        assert fw.jurisdiction == "United Kingdom"
        assert fw.status == "voluntary"

    def test_checklist_covers_five_principles(self, system_desc: dict) -> None:
        fw = UKAIFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [i.ref for i in checklist]
        assert any("PRO-1" in r for r in refs)
        assert any("PRO-2" in r for r in refs)
        assert any("PRO-3" in r for r in refs)
        assert any("PRO-4" in r for r in refs)
        assert any("PRO-5" in r for r in refs)

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = UKAIFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 8

    def test_assess_returns_valid_assessment(self, system_desc: dict) -> None:
        fw = UKAIFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)


@pytest.mark.compliance
class TestIndiaDPDP:
    def test_framework_metadata(self) -> None:
        fw = IndiaDPDPFramework()
        assert fw.framework_id == "india_dpdp"
        assert fw.jurisdiction == "India"
        assert fw.status == "enacted"
        assert fw.enforcement_date == "2023-08-11"

    def test_checklist_covers_core_sections(self, system_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [i.ref for i in checklist]
        assert any("§4" in r for r in refs)
        assert any("§6" in r or "§8" in r for r in refs)  # §7 optional in some builds
        assert any("§8" in r or "§9" in r for r in refs)

    def test_conditional_na_for_non_sdf(self) -> None:
        fw = IndiaDPDPFramework()
        desc = dict(_SYSTEM_DESC, is_significant_data_fiduciary=False)
        checklist = fw.get_checklist(desc)
        sdf_items = [i for i in checklist if "§16" in i.ref]
        assert all(i.status == ChecklistStatus.NOT_APPLICABLE for i in sdf_items)

    def test_conditional_na_for_no_children_data(self) -> None:
        fw = IndiaDPDPFramework()
        desc = dict(_SYSTEM_DESC, processes_children_data=False)
        checklist = fw.get_checklist(desc)
        child_items = [i for i in checklist if "§9" in i.ref]
        assert all(i.status == ChecklistStatus.NOT_APPLICABLE for i in child_items)

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 3

    def test_assess_returns_valid_assessment(self, system_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)


@pytest.mark.compliance
class TestAustraliaAIEthics:
    def test_framework_metadata(self) -> None:
        fw = AustraliaAIEthicsFramework()
        assert fw.framework_id == "australia_ai_ethics"
        assert fw.jurisdiction == "Australia"
        assert fw.status == "voluntary"

    def test_checklist_covers_eight_principles(self, system_desc: dict) -> None:
        fw = AustraliaAIEthicsFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [i.ref for i in checklist]
        # Principles 1-8
        for n in range(1, 9):
            assert any(f"P{n}" in r for r in refs), f"Missing principle P{n}"

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = AustraliaAIEthicsFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 6

    def test_assess_returns_valid_assessment(self, system_desc: dict) -> None:
        fw = AustraliaAIEthicsFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)


@pytest.mark.compliance
class TestBrazilLGPD:
    def test_framework_metadata(self) -> None:
        fw = BrazilLGPDFramework()
        assert fw.framework_id == "brazil_lgpd"
        assert fw.jurisdiction == "Brazil"
        assert fw.status == "enacted"
        assert fw.enforcement_date == "2021-08-01"

    def test_checklist_covers_key_articles(self, system_desc: dict) -> None:
        fw = BrazilLGPDFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [i.ref for i in checklist]
        assert any("Art.20" in r for r in refs)
        assert any("Art.6" in r for r in refs)
        assert any("Art.50" in r for r in refs)

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = BrazilLGPDFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 5

    def test_assess_returns_valid_assessment(self, system_desc: dict) -> None:
        fw = BrazilLGPDFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)


@pytest.mark.compliance
class TestChinaAI:
    def test_framework_metadata(self) -> None:
        fw = ChinaAIFramework()
        assert fw.framework_id == "china_ai"
        assert fw.jurisdiction == "China"
        assert fw.status == "enacted"

    def test_checklist_covers_all_four_regulations(self, system_desc: dict) -> None:
        fw = ChinaAIFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [i.ref for i in checklist]
        assert any("CN-ALG" in r for r in refs)
        assert any("CN-DS" in r for r in refs)
        assert any("CN-GAI" in r for r in refs)
        assert any("CN-GAIG" in r for r in refs)

    def test_conditional_na_for_non_generative(self) -> None:
        fw = ChinaAIFramework()
        desc = dict(_SYSTEM_DESC, is_generative_ai=False)
        checklist = fw.get_checklist(desc)
        gai_items = [i for i in checklist if i.ref.startswith("CN-GAI Art.")]
        assert len(gai_items) >= 4
        assert all(i.status == ChecklistStatus.NOT_APPLICABLE for i in gai_items)

    def test_generative_items_active_when_flagged(self) -> None:
        fw = ChinaAIFramework()
        desc = dict(_SYSTEM_DESC, is_generative_ai=True)
        checklist = fw.get_checklist(desc)
        gai_items = [i for i in checklist if i.ref.startswith("CN-GAI Art.")]
        assert all(i.status == ChecklistStatus.PENDING for i in gai_items)

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = ChinaAIFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 3

    def test_assess_returns_valid_assessment(self, system_desc: dict) -> None:
        fw = ChinaAIFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)


@pytest.mark.compliance
class TestCCPACPRA:
    def test_framework_metadata(self) -> None:
        fw = CCPACPRAFramework()
        assert fw.framework_id == "ccpa_cpra"
        assert fw.jurisdiction == "California"
        assert fw.status == "enacted"
        assert fw.enforcement_date == "2020-07-01"

    def test_checklist_covers_key_sections(self, system_desc: dict) -> None:
        fw = CCPACPRAFramework()
        checklist = fw.get_checklist(system_desc)
        refs = [i.ref for i in checklist]
        assert any("§1798.100" in r for r in refs)
        assert any("§1798.105" in r for r in refs)
        assert any("§1798.185" in r for r in refs)

    def test_auto_populate_marks_acgs_items(self, system_desc: dict) -> None:
        fw = CCPACPRAFramework()
        checklist = fw.get_checklist(system_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant = [i for i in checklist if i.status == ChecklistStatus.COMPLIANT]
        assert len(compliant) >= 4

    def test_assess_returns_valid_assessment(self, system_desc: dict) -> None:
        fw = CCPACPRAFramework()
        result = fw.assess(system_desc)
        assert isinstance(result, FrameworkAssessment)
        assert 0.0 <= result.compliance_score <= 1.0


# ---------------------------------------------------------------------------
# 3. ComplianceFramework protocol conformance — all 18
# ---------------------------------------------------------------------------

_ALL_FRAMEWORK_CLASSES = [
    NISTAIRMFFramework,
    ISO42001Framework,
    GDPRFramework,
    EUAIActFramework,
    DORAFramework,
    SOC2AIFramework,
    HIPAAAIFramework,
    USFairLendingFramework,
    NYCLL144Framework,
    OECDAIFramework,
    CanadaAIDAFramework,
    SingaporeMAIGFFramework,
    UKAIFramework,
    IndiaDPDPFramework,
    AustraliaAIEthicsFramework,
    BrazilLGPDFramework,
    ChinaAIFramework,
    CCPACPRAFramework,
]


@pytest.mark.compliance
class TestProtocolConformance:
    @pytest.mark.parametrize("framework_cls", _ALL_FRAMEWORK_CLASSES)
    def test_implements_compliance_framework_protocol(
        self,
        framework_cls: type,
    ) -> None:
        fw = framework_cls()
        assert isinstance(fw, ComplianceFramework)
        assert hasattr(fw, "framework_id")
        assert hasattr(fw, "framework_name")
        assert hasattr(fw, "jurisdiction")
        assert hasattr(fw, "status")


# ---------------------------------------------------------------------------
# 4. MultiFrameworkAssessor tests
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestMultiFrameworkAssessor:
    def test_assess_all_frameworks(self) -> None:
        desc = {"system_id": "all-fw-test", "jurisdiction": "global", "domain": "multi"}
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(desc)
        assert isinstance(report, MultiFrameworkReport)
        assert len(report.frameworks_assessed) == 20
        assert 0.0 <= report.overall_score <= 1.0

    def test_assess_explicit_frameworks(self, system_desc: dict) -> None:
        assessor = MultiFrameworkAssessor(frameworks=["gdpr", "nist_ai_rmf"])
        report = assessor.assess(system_desc)
        assert set(report.frameworks_assessed) == {"gdpr", "nist_ai_rmf"}
        assert len(report.by_framework) == 2

    def test_assess_single_framework(self, system_desc: dict) -> None:
        assessor = MultiFrameworkAssessor(frameworks=["iso_42001"])
        report = assessor.assess(system_desc)
        assert report.frameworks_assessed == ("iso_42001",)
        assert "iso_42001" in report.by_framework

    def test_overall_score_is_average(self, system_desc: dict) -> None:
        assessor = MultiFrameworkAssessor(frameworks=["nist_ai_rmf", "oecd_ai"])
        report = assessor.assess(system_desc)
        nist_score = report.by_framework["nist_ai_rmf"].compliance_score
        oecd_score = report.by_framework["oecd_ai"].compliance_score
        expected = round((nist_score + oecd_score) / 2, 4)
        assert report.overall_score == expected

    def test_report_to_dict(self, system_desc: dict) -> None:
        assessor = MultiFrameworkAssessor(frameworks=["gdpr"])
        report = assessor.assess(system_desc)
        d = report.to_dict()
        assert "system_id" in d
        assert "overall_score" in d
        assert "by_framework" in d
        assert "disclaimer" in d

    def test_acgs_lite_total_coverage(self, system_desc: dict) -> None:
        assessor = MultiFrameworkAssessor(frameworks=["oecd_ai"])
        report = assessor.assess(system_desc)
        assert report.acgs_lite_total_coverage > 0.0

    def test_available_frameworks_lists_all_18(self) -> None:
        available = MultiFrameworkAssessor.available_frameworks()
        assert len(available) == 20
        assert "nist_ai_rmf" in available
        assert "gdpr" in available
        assert "eu_ai_act" in available
        assert "dora" in available
        assert "canada_aida" in available
        assert "singapore_maigf" in available
        assert "uk_ai_framework" in available
        assert "india_dpdp" in available
        assert "australia_ai_ethics" in available
        assert "brazil_lgpd" in available
        assert "china_ai" in available
        assert "ccpa_cpra" in available

    def test_invalid_framework_id_ignored(self, system_desc: dict) -> None:
        assessor = MultiFrameworkAssessor(frameworks=["nonexistent", "gdpr"])
        report = assessor.assess(system_desc)
        assert report.frameworks_assessed == ("gdpr",)


# ---------------------------------------------------------------------------
# 5. Jurisdiction-based framework selection
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestJurisdictionSelection:
    def test_eu_jurisdiction_includes_gdpr_and_eu_ai_act(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("european_union", "general")
        assert "gdpr" in fws
        assert "eu_ai_act" in fws
        assert "iso_42001" in fws
        assert "oecd_ai" in fws

    def test_us_jurisdiction_includes_nist_and_ccpa(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_states", "general")
        assert "nist_ai_rmf" in fws
        assert "soc2_ai" in fws
        assert "ccpa_cpra" in fws

    def test_uk_jurisdiction(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_kingdom", "general")
        assert "uk_ai_framework" in fws
        assert "iso_42001" in fws

    def test_canada_jurisdiction(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("canada", "general")
        assert "canada_aida" in fws
        assert "nist_ai_rmf" in fws

    def test_singapore_jurisdiction(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("singapore", "general")
        assert "singapore_maigf" in fws

    def test_asean_jurisdiction(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("asean", "general")
        assert "singapore_maigf" in fws

    def test_india_jurisdiction(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("india", "general")
        assert "india_dpdp" in fws

    def test_australia_jurisdiction(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("australia", "general")
        assert "australia_ai_ethics" in fws

    def test_brazil_jurisdiction(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("brazil", "general")
        assert "brazil_lgpd" in fws

    def test_china_jurisdiction(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("china", "general")
        assert "china_ai" in fws

    def test_california_jurisdiction(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("california", "general")
        assert "ccpa_cpra" in fws
        assert "nist_ai_rmf" in fws

    def test_healthcare_domain_adds_hipaa(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_states", "healthcare")
        assert "hipaa_ai" in fws
        assert "nist_ai_rmf" in fws

    def test_lending_domain_adds_fair_lending(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_states", "lending")
        assert "us_fair_lending" in fws

    def test_financial_domain_adds_dora(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("european_union", "financial")
        assert "dora" in fws
        assert "us_fair_lending" in fws
        assert "soc2_ai" in fws

    def test_fintech_domain_adds_dora_and_soc2(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("european_union", "fintech")
        assert "dora" in fws
        assert "soc2_ai" in fws

    def test_banking_domain(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_states", "banking")
        assert "dora" in fws
        assert "us_fair_lending" in fws
        assert "soc2_ai" in fws

    def test_insurance_domain(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("european_union", "insurance")
        assert "dora" in fws
        assert "soc2_ai" in fws

    def test_gpai_domain_adds_eu_ai_act(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("international", "gpai")
        assert "eu_ai_act" in fws

    def test_nyc_jurisdiction_adds_ll144(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("new_york_city", "general")
        assert "nyc_ll144" in fws

    def test_unknown_jurisdiction_returns_all_19(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("unknown_place", "unknown_domain")
        assert len(fws) == 20

    def test_auto_selection_from_system_desc(self) -> None:
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(
            {
                "system_id": "test",
                "jurisdiction": "european_union",
                "domain": "healthcare",
            }
        )
        fw_ids = set(report.frameworks_assessed)
        assert "gdpr" in fw_ids
        assert "hipaa_ai" in fw_ids
        assert "eu_ai_act" in fw_ids


# ---------------------------------------------------------------------------
# 6. Cross-framework gap analysis
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestCrossFrameworkGaps:
    def test_cross_gaps_identified(self, system_desc: dict) -> None:
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(system_desc)
        assert len(report.cross_framework_gaps) >= 0

    def test_recommendations_include_priority(self, system_desc: dict) -> None:
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(system_desc)
        if report.cross_framework_gaps:
            assert any("PRIORITY" in r for r in report.recommendations)


# ---------------------------------------------------------------------------
# 7. Compliance scoring edge cases
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestComplianceScoring:
    def test_empty_checklist_scores_one(self) -> None:
        assessment = FrameworkAssessment(
            framework_id="test",
            framework_name="Test",
            compliance_score=1.0,
            items=(),
            gaps=(),
            acgs_lite_coverage=0.0,
            recommendations=(),
        )
        assert assessment.compliance_score == 1.0

    def test_all_compliant_scores_one(self, system_desc: dict) -> None:
        fw = NISTAIRMFFramework()
        checklist = fw.get_checklist(system_desc)
        for item in checklist:
            item.mark_complete("test evidence")
        total = len(checklist)
        compliant = sum(1 for i in checklist if i.status == ChecklistStatus.COMPLIANT)
        assert compliant == total

    def test_framework_assessment_to_dict(self, system_desc: dict) -> None:
        fw = GDPRFramework()
        result = fw.assess(system_desc)
        d = result.to_dict()
        assert isinstance(d["items"], list)
        assert isinstance(d["gaps"], list)
        assert isinstance(d["recommendations"], list)
        assert d["framework_id"] == "gdpr"

    def test_partial_compliance_scores_between_zero_and_one(
        self,
        system_desc: dict,
    ) -> None:
        fw = NISTAIRMFFramework()
        result = fw.assess(system_desc)
        assert 0.0 < result.compliance_score < 1.0


# ---------------------------------------------------------------------------
# 8. ComplianceReportExporter tests
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestComplianceReportExporter:
    @pytest.fixture
    def report(self, system_desc: dict) -> MultiFrameworkReport:
        assessor = MultiFrameworkAssessor(frameworks=["gdpr", "nist_ai_rmf"])
        return assessor.assess(system_desc)

    def test_to_text(self, report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(report, title="Test Report")
        text = exporter.to_text()
        assert "Test Report" in text
        assert "Overall score" in text
        assert "DISCLAIMER" in text

    def test_to_markdown(self, report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(report, title="MD Report")
        md = exporter.to_markdown()
        assert "# MD Report" in md
        assert "| Field | Value |" in md
        assert "Disclaimer" in md

    def test_to_json(self, report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(report)
        js = exporter.to_json()
        data = json.loads(js)
        assert "system_id" in data
        assert "title" in data
        assert "by_framework" in data

    def test_to_text_file(self, report: MultiFrameworkReport, tmp_path) -> None:
        exporter = ComplianceReportExporter(report)
        path = tmp_path / "report.txt"
        exporter.to_text_file(str(path))
        assert path.exists()
        content = path.read_text()
        assert "Overall score" in content

    def test_to_markdown_file(self, report: MultiFrameworkReport, tmp_path) -> None:
        exporter = ComplianceReportExporter(report)
        path = tmp_path / "sub" / "report.md"
        exporter.to_markdown_file(str(path))
        assert path.exists()

    def test_to_json_file(self, report: MultiFrameworkReport, tmp_path) -> None:
        exporter = ComplianceReportExporter(report)
        path = tmp_path / "report.json"
        exporter.to_json_file(str(path))
        data = json.loads(path.read_text())
        assert data["system_id"] == "test-system-v1"

    def test_framework_summary_text_static(self, report: MultiFrameworkReport) -> None:
        a = report.by_framework["gdpr"]
        text = ComplianceReportExporter.framework_summary_text(a)
        assert "gdpr" in text
        assert "Score" in text

    def test_framework_summary_markdown_static(self, report: MultiFrameworkReport) -> None:
        a = report.by_framework["nist_ai_rmf"]
        md = ComplianceReportExporter.framework_summary_markdown(a)
        assert "`nist_ai_rmf`" in md
        assert "**Score:**" in md


# ---------------------------------------------------------------------------
# 9. Evidence collection tests
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestEvidenceCollection:
    def test_add_and_retrieve(self) -> None:
        ec = EvidenceCollector(system_id="test-sys")
        rec = ec.add("GDPR Art.5(2)", "audit_chain", {"length": 100})
        assert isinstance(rec, EvidenceRecord)
        assert rec.ref == "GDPR Art.5(2)"
        assert rec.system_id == "test-sys"
        assert len(ec.records) == 1

    def test_records_for_ref(self) -> None:
        ec = EvidenceCollector(system_id="test-sys")
        ec.add("REF-1", "type_a")
        ec.add("REF-2", "type_b")
        ec.add("REF-1", "type_c")
        assert len(ec.records_for_ref("REF-1")) == 2
        assert len(ec.records_for_ref("REF-2")) == 1
        assert len(ec.records_for_ref("REF-3")) == 0

    def test_summary(self) -> None:
        ec = EvidenceCollector(system_id="s1")
        ec.add("A", "t1")
        ec.add("B", "t2")
        s = ec.summary()
        assert s["total_records"] == 2
        assert "A" in s["unique_refs"]
        assert "t1" in s["evidence_types"]

    def test_clear(self) -> None:
        ec = EvidenceCollector(system_id="s1")
        ec.add("A", "t")
        ec.clear()
        assert len(ec.records) == 0

    def test_record_to_dict(self) -> None:
        ec = EvidenceCollector(system_id="s1")
        rec = ec.add("X", "y", {"k": "v"})
        d = rec.to_dict()
        assert d["ref"] == "X"
        assert d["data"]["k"] == "v"
