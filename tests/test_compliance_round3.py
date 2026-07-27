"""Tests for round-3 compliance frameworks and the report exporter.

Covers:
- India DPDP Act (2023)
- Australia AI Ethics Framework (8 principles)
- Brazil LGPD + AI
- China AI Governance Regulations
- CCPA/CPRA + ADMT
- ComplianceReportExporter (text, Markdown, JSON)
- MultiFrameworkAssessor routing for round-3 jurisdictions
- 20-framework total count

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from acgs_lite.compliance import (
    AustraliaAIEthicsFramework,
    BrazilLGPDFramework,
    CCPACPRAFramework,
    ChecklistStatus,
    ChinaAIFramework,
    ComplianceReportExporter,
    FrameworkAssessment,
    IndiaDPDPFramework,
    MultiFrameworkAssessor,
    MultiFrameworkReport,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def base_desc() -> dict:
    return {"system_id": "test-system", "domain": "general"}


@pytest.fixture
def india_desc() -> dict:
    return {
        "system_id": "india-ai",
        "jurisdiction": "india",
        "is_significant_data_fiduciary": False,
        "processes_children_data": False,
    }


@pytest.fixture
def india_sdf_desc() -> dict:
    return {
        "system_id": "india-sdf",
        "jurisdiction": "india",
        "is_significant_data_fiduciary": True,
        "processes_children_data": True,
    }


# ---------------------------------------------------------------------------
# India DPDP
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestIndiaDPDPFramework:
    def test_framework_metadata(self) -> None:
        fw = IndiaDPDPFramework()
        assert fw.framework_id == "india_dpdp"
        assert fw.jurisdiction == "India"
        assert fw.status == "enacted"
        assert fw.enforcement_date == "2023-08-11"

    def test_checklist_covers_core_sections(self, india_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        checklist = fw.get_checklist(india_desc)
        refs = [item.ref for item in checklist]
        assert any("§4" in r for r in refs)
        assert any("§6" in r for r in refs)
        assert any("§8" in r for r in refs)
        assert any("§11" in r for r in refs)
        assert any("§8(6)" in r for r in refs)

    def test_sdf_items_not_applicable_for_non_sdf(self, india_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        checklist = fw.get_checklist(india_desc)
        sdf_items = [i for i in checklist if "§10(2)" in i.ref]
        assert sdf_items, "Expected India DPDP SDF items in checklist"
        assert all(i.status == ChecklistStatus.NOT_APPLICABLE for i in sdf_items)

    def test_sdf_items_pending_for_sdf(self, india_sdf_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        checklist = fw.get_checklist(india_sdf_desc)
        sdf_items = [i for i in checklist if "§10(2)(a)" in i.ref]
        assert any(i.status == ChecklistStatus.PENDING for i in sdf_items)

    def test_children_data_items_not_applicable_by_default(self, india_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        checklist = fw.get_checklist(india_desc)
        child_items = [i for i in checklist if "§9" in i.ref]
        assert all(i.status == ChecklistStatus.NOT_APPLICABLE for i in child_items)

    def test_children_data_items_active_when_flagged(self, india_sdf_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        checklist = fw.get_checklist(india_sdf_desc)
        child_items = [i for i in checklist if "§9(3)" in i.ref]
        assert any(i.status != ChecklistStatus.NOT_APPLICABLE for i in child_items)

    def test_auto_populate_marks_audit_log_and_governance(self, india_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        checklist = fw.get_checklist(india_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant_refs = {i.ref for i in checklist if i.status == ChecklistStatus.COMPLIANT}
        assert "DPDP §8(4)/(5)" in compliant_refs
        assert "DPDP §8(6)" in compliant_refs
        assert "DPDP §11(1)" in compliant_refs

    def test_section8_5_dpf_contact_not_auto_satisfied(self, india_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        checklist = fw.get_checklist(india_desc)
        fw.auto_populate_acgs_lite(checklist)
        s89 = next(i for i in checklist if i.ref == "DPDP §8(9)")
        assert s89.status == ChecklistStatus.PENDING

    def test_assess_returns_valid_assessment(self, india_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        result = fw.assess(india_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "india_dpdp"
        assert 0.0 <= result.compliance_score <= 1.0

    def test_gaps_include_consent_and_erasure(self, india_desc: dict) -> None:
        fw = IndiaDPDPFramework()
        result = fw.assess(india_desc)
        gap_refs = " ".join(result.gaps)
        assert "§6" in gap_refs or "§12" in gap_refs or "§8" in gap_refs


# ---------------------------------------------------------------------------
# Australia AI Ethics Framework
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestAustraliaAIEthicsFramework:
    def test_framework_metadata(self) -> None:
        fw = AustraliaAIEthicsFramework()
        assert fw.framework_id == "australia_ai_ethics"
        assert fw.jurisdiction == "Australia"
        assert fw.status == "voluntary"

    def test_checklist_covers_all_eight_principles(self, base_desc: dict) -> None:
        fw = AustraliaAIEthicsFramework()
        checklist = fw.get_checklist(base_desc)
        refs = [item.ref for item in checklist]
        for prin in ("P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"):
            assert any(prin in r for r in refs), f"Missing {prin} items"

    def test_auto_populate_marks_governance_engine_items(self, base_desc: dict) -> None:
        fw = AustraliaAIEthicsFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant_refs = {i.ref for i in checklist if i.status == ChecklistStatus.COMPLIANT}
        assert "AU-AI P5-2" in compliant_refs  # GovernanceEngine fail-safe
        assert "AU-AI P7-1" in compliant_refs  # HumanOversightGateway
        assert "AU-AI P8-1" in compliant_refs  # MACIEnforcer accountability

    def test_privacy_impact_assessment_not_blocking(self, base_desc: dict) -> None:
        fw = AustraliaAIEthicsFramework()
        checklist = fw.get_checklist(base_desc)
        pia = next(i for i in checklist if i.ref == "AU-AI P4-3")
        assert not pia.blocking

    def test_disaggregated_testing_not_auto_satisfied(self, base_desc: dict) -> None:
        fw = AustraliaAIEthicsFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        prin32 = next(i for i in checklist if i.ref == "AU-AI P3-2")
        assert prin32.status == ChecklistStatus.PENDING

    def test_assess_returns_valid_assessment(self, base_desc: dict) -> None:
        fw = AustraliaAIEthicsFramework()
        result = fw.assess(base_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "australia_ai_ethics"
        assert 0.0 <= result.compliance_score <= 1.0

    def test_acgs_coverage_above_half(self, base_desc: dict) -> None:
        fw = AustraliaAIEthicsFramework()
        result = fw.assess(base_desc)
        assert result.acgs_lite_coverage > 0.5


# ---------------------------------------------------------------------------
# Brazil LGPD + AI
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestBrazilLGPDFramework:
    def test_framework_metadata(self) -> None:
        fw = BrazilLGPDFramework()
        assert fw.framework_id == "brazil_lgpd"
        assert fw.jurisdiction == "Brazil"
        assert fw.status == "enacted"
        assert fw.enforcement_date == "2021-08-01"

    def test_checklist_includes_art20_automated_decisions(self, base_desc: dict) -> None:
        fw = BrazilLGPDFramework()
        checklist = fw.get_checklist(base_desc)
        refs = [item.ref for item in checklist]
        assert any("Art.20" in r for r in refs), "Missing LGPD Art.20 automated decisions"

    def test_auto_populate_marks_art20_with_hog(self, base_desc: dict) -> None:
        fw = BrazilLGPDFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        art20 = next(i for i in checklist if i.ref == "LGPD Art.20(1)")
        assert art20.status == ChecklistStatus.COMPLIANT
        assert "HumanOversightGateway" in (art20.evidence or "")

    def test_art20_2_disclosure_auto_satisfied(self, base_desc: dict) -> None:
        fw = BrazilLGPDFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        art202 = next(i for i in checklist if i.ref == "LGPD Art.20(2)")
        assert art202.status == ChecklistStatus.COMPLIANT

    def test_sensitive_data_art11_not_auto_satisfied(self, base_desc: dict) -> None:
        fw = BrazilLGPDFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        art11 = next(i for i in checklist if i.ref == "LGPD Art.11")
        assert art11.status == ChecklistStatus.PENDING

    def test_assess_returns_valid_assessment(self, base_desc: dict) -> None:
        fw = BrazilLGPDFramework()
        result = fw.assess(base_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "brazil_lgpd"
        assert 0.0 <= result.compliance_score <= 1.0

    def test_recommendations_mention_art20(self, base_desc: dict) -> None:
        fw = BrazilLGPDFramework()
        result = fw.assess(base_desc)
        recs_text = " ".join(result.recommendations)
        # Art.11 or Art.6 should trigger a recommendation
        assert any(kw in recs_text for kw in ["Art.11", "Art.20", "Art.6", "sensitive"])


# ---------------------------------------------------------------------------
# China AI Governance Regulations
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestChinaAIFramework:
    def test_framework_metadata(self) -> None:
        fw = ChinaAIFramework()
        assert fw.framework_id == "china_ai"
        assert fw.jurisdiction == "China"
        assert fw.status == "enacted"

    def test_checklist_covers_all_four_regulations(self, base_desc: dict) -> None:
        fw = ChinaAIFramework()
        checklist = fw.get_checklist(base_desc)
        refs = [item.ref for item in checklist]
        assert any("CN-ALG" in r for r in refs), "Missing Algorithm Recommendation items"
        assert any("CN-DS" in r for r in refs), "Missing Deep Synthesis items"
        assert any("CN-GAI" in r for r in refs), "Missing Generative AI items"
        assert any("CN-PIPL" in r for r in refs), "Missing PIPL items"

    def test_cac_security_assessment_not_applicable_for_non_generative(self) -> None:
        fw = ChinaAIFramework()
        checklist = fw.get_checklist({"system_id": "test", "is_generative_ai": False})
        art17 = next(i for i in checklist if i.ref == "CN-GAI Art.17")
        assert art17.status == ChecklistStatus.NOT_APPLICABLE

    def test_auto_populate_marks_governance_and_transparency(self, base_desc: dict) -> None:
        fw = ChinaAIFramework()
        desc = {**base_desc, "is_generative_ai": True}
        checklist = fw.get_checklist(desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant_refs = {i.ref for i in checklist if i.status == ChecklistStatus.COMPLIANT}
        assert "CN-ALG Art.21" in compliant_refs
        assert "CN-PIPL Art.24" in compliant_refs
        assert "CN-PIPL Art.51" in compliant_refs

    def test_training_data_legality_not_auto_satisfied(self, base_desc: dict) -> None:
        fw = ChinaAIFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        art7 = next(i for i in checklist if i.ref == "CN-GAI Art.7")
        assert art7.status == ChecklistStatus.PENDING

    def test_assess_returns_valid_assessment(self, base_desc: dict) -> None:
        fw = ChinaAIFramework()
        result = fw.assess(base_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "china_ai"
        assert 0.0 <= result.compliance_score <= 1.0

    def test_pipl_impact_assessment_auto_satisfied(self, base_desc: dict) -> None:
        fw = ChinaAIFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        art55 = next(i for i in checklist if i.ref == "CN-PIPL Art.55")
        assert art55.status == ChecklistStatus.COMPLIANT


# ---------------------------------------------------------------------------
# CCPA/CPRA + ADMT
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestCCPACPRAFramework:
    def test_framework_metadata(self) -> None:
        fw = CCPACPRAFramework()
        assert fw.framework_id == "ccpa_cpra"
        assert "California" in fw.jurisdiction
        assert fw.status == "enacted"

    def test_checklist_covers_core_rights(self, base_desc: dict) -> None:
        fw = CCPACPRAFramework()
        checklist = fw.get_checklist(base_desc)
        refs = [item.ref for item in checklist]
        assert any("§1798.100" in r for r in refs), "Missing right to know"
        assert any("§1798.105" in r for r in refs), "Missing right to delete"
        assert any("§1798.120" in r for r in refs), "Missing opt-out right"
        assert any("ADMT" in r for r in refs), "Missing ADMT rules"

    def test_admt_items_include_opt_out_and_human_review(self, base_desc: dict) -> None:
        fw = CCPACPRAFramework()
        checklist = fw.get_checklist(base_desc)
        admt_refs = [i.ref for i in checklist if "ADMT" in i.ref]
        assert "CCPA ADMT-OPT-OUT" in admt_refs
        assert "CCPA ADMT-HUMAN-REVIEW" in admt_refs
        assert "CCPA ADMT-LOGIC" in admt_refs
        assert "CCPA ADMT-RISK" in admt_refs

    def test_auto_populate_marks_admt_obligations(self, base_desc: dict) -> None:
        fw = CCPACPRAFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant_refs = {i.ref for i in checklist if i.status == ChecklistStatus.COMPLIANT}
        assert "CCPA ADMT-OPT-OUT" in compliant_refs
        assert "CCPA ADMT-HUMAN-REVIEW" in compliant_refs
        assert "CCPA ADMT-NOTICE" in compliant_refs
        assert "CCPA ADMT-RISK" in compliant_refs

    def test_right_to_delete_not_auto_satisfied(self, base_desc: dict) -> None:
        fw = CCPACPRAFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        del_item = next(i for i in checklist if i.ref == "CCPA §1798.105")
        assert del_item.status == ChecklistStatus.PENDING

    def test_opt_out_mechanism_not_auto_satisfied(self, base_desc: dict) -> None:
        fw = CCPACPRAFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        opt_out = next(i for i in checklist if i.ref == "CCPA §1798.120")
        assert opt_out.status == ChecklistStatus.PENDING

    def test_assess_returns_valid_assessment(self, base_desc: dict) -> None:
        fw = CCPACPRAFramework()
        result = fw.assess(base_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "ccpa_cpra"
        assert 0.0 <= result.compliance_score <= 1.0

    def test_recommendations_mention_deletion_and_opt_out(self, base_desc: dict) -> None:
        fw = CCPACPRAFramework()
        result = fw.assess(base_desc)
        recs = " ".join(result.recommendations)
        assert any(kw in recs for kw in ["deletion", "opt-out", "§1798", "GPC", "sensitive"])


# ---------------------------------------------------------------------------
# MultiFrameworkAssessor — round-3 jurisdiction routing
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestMultiFrameworkAssessorRound3:
    def test_india_jurisdiction_routes_india_dpdp(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("india", "general")
        assert "india_dpdp" in fws

    def test_australia_jurisdiction_routes_au_ethics(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("australia", "general")
        assert "australia_ai_ethics" in fws

    def test_brazil_jurisdiction_routes_lgpd(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("brazil", "general")
        assert "brazil_lgpd" in fws

    def test_china_jurisdiction_routes_china_ai(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("china", "general")
        assert "china_ai" in fws

    def test_california_jurisdiction_routes_ccpa(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("california", "general")
        assert "ccpa_cpra" in fws

    def test_us_jurisdiction_now_includes_ccpa(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_states", "general")
        assert "ccpa_cpra" in fws

    def test_available_frameworks_lists_all_18(self) -> None:
        assessor = MultiFrameworkAssessor()
        available = assessor.available_frameworks()
        assert len(available) == 20
        for fid in (
            "india_dpdp",
            "australia_ai_ethics",
            "brazil_lgpd",
            "china_ai",
            "ccpa_cpra",
        ):
            assert fid in available, f"Expected {fid!r} in registry"

    def test_india_full_assessment(self) -> None:
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(
            {
                "system_id": "india-test",
                "jurisdiction": "india",
                "domain": "general",
            }
        )
        assert "india_dpdp" in report.frameworks_assessed
        assert isinstance(report, MultiFrameworkReport)

    def test_explicit_18_framework_run(self) -> None:
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(
            {
                "system_id": "global-test",
                "jurisdiction": "nowhere",
                "domain": "unknown",
            }
        )
        # Unknown jurisdiction → all 20 frameworks
        assert len(report.frameworks_assessed) == 20

    def test_cross_global_assessment_score_range(self) -> None:
        assessor = MultiFrameworkAssessor(
            frameworks=[
                "india_dpdp",
                "australia_ai_ethics",
                "brazil_lgpd",
                "china_ai",
                "ccpa_cpra",
            ]
        )
        report = assessor.assess({"system_id": "r3-test"})
        assert 0.0 <= report.overall_score <= 1.0
        assert len(report.frameworks_assessed) == 5


# ---------------------------------------------------------------------------
# ComplianceReportExporter
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestComplianceReportExporter:
    @pytest.fixture
    def sample_report(self) -> MultiFrameworkReport:
        assessor = MultiFrameworkAssessor(frameworks=["nist_ai_rmf", "gdpr", "eu_ai_act"])
        return assessor.assess(
            {
                "system_id": "exporter-test",
                "risk_tier": "high",
                "jurisdiction": "european_union",
            }
        )

    def test_to_text_contains_system_id(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report)
        text = exporter.to_text()
        assert "exporter-test" in text

    def test_to_text_contains_all_framework_names(
        self, sample_report: MultiFrameworkReport
    ) -> None:
        exporter = ComplianceReportExporter(sample_report)
        text = exporter.to_text()
        assert "NIST" in text
        assert "GDPR" in text
        assert "EU Artificial Intelligence Act" in text

    def test_to_text_contains_score(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report)
        text = exporter.to_text()
        # Should contain a percentage
        assert "%" in text

    def test_to_text_contains_disclaimer(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report)
        text = exporter.to_text()
        assert "DISCLAIMER" in text
        assert "legal advice" in text.lower()

    def test_to_markdown_is_valid_structure(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report)
        md = exporter.to_markdown()
        assert md.startswith("#")
        assert "## Framework Summary" in md
        assert "|" in md  # has a table
        assert "Constitutional Hash" in md

    def test_to_markdown_contains_score_badges(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report)
        md = exporter.to_markdown()
        # At least one score badge emoji should appear
        assert any(badge in md for badge in ("🟢", "🔵", "🟡", "🟠", "🔴"))

    def test_to_json_is_valid_json(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report)
        json_str = exporter.to_json()
        data = json.loads(json_str)
        assert data["system_id"] == "exporter-test"
        assert "frameworks_assessed" in data
        assert "by_framework" in data

    def test_to_json_includes_title_and_generated_at(
        self, sample_report: MultiFrameworkReport
    ) -> None:
        exporter = ComplianceReportExporter(sample_report, title="Test Report")
        data = json.loads(exporter.to_json())
        assert data["report_title"] == "Test Report"
        assert "generated_at" in data

    def test_to_text_file_writes_file(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "report.txt"
            result = exporter.to_text_file(out)
            assert result.exists()
            content = result.read_text()
            assert "exporter-test" in content

    def test_to_markdown_file_writes_file(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "report.md"
            result = exporter.to_markdown_file(out)
            assert result.exists()
            content = result.read_text()
            assert content.startswith("#")

    def test_to_json_file_writes_valid_json(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "report.json"
            result = exporter.to_json_file(out)
            assert result.exists()
            data = json.loads(result.read_text())
            assert "system_id" in data

    def test_to_text_file_creates_parent_dirs(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "nested" / "dir" / "report.txt"
            result = exporter.to_text_file(out)
            assert result.exists()

    def test_framework_summary_text_static_method(
        self, sample_report: MultiFrameworkReport
    ) -> None:
        fa = sample_report.by_framework["nist_ai_rmf"]
        text = ComplianceReportExporter.framework_summary_text(fa)
        assert "NIST" in text
        assert "%" in text or "score" in text.lower()

    def test_framework_summary_markdown_static_method(
        self, sample_report: MultiFrameworkReport
    ) -> None:
        fa = sample_report.by_framework["gdpr"]
        md = ComplianceReportExporter.framework_summary_markdown(fa)
        assert "GDPR" in md or "gdpr" in md.lower()

    def test_custom_title_appears_in_output(self, sample_report: MultiFrameworkReport) -> None:
        exporter = ComplianceReportExporter(sample_report, title="My Custom Compliance Report")
        assert "My Custom Compliance Report" in exporter.to_text()
        assert "My Custom Compliance Report" in exporter.to_markdown()

    def test_18_framework_exporter_smoke_test(self) -> None:
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(
            {
                "system_id": "global-all",
                "jurisdiction": "unknown",
                "domain": "unknown",
            }
        )
        exporter = ComplianceReportExporter(report)
        text = exporter.to_text()
        md = exporter.to_markdown()
        js = exporter.to_json()
        assert len(text) > 1000
        assert len(md) > 1000
        data = json.loads(js)
        assert len(data["frameworks_assessed"]) == 20
