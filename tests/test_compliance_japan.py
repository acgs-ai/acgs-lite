"""Smoke tests for the Japan AI Guidelines for Business compliance framework.

Covers:
- Framework metadata and registry registration
- Checklist coverage of the ten common guiding principles
- acgs-lite auto-population of mapped controls
- assess() producing a valid FrameworkAssessment with a sane score
- MultiFrameworkAssessor jurisdiction routing for "japan"
- CLI-style dashed framework ID ("japan-ai-guidelines") resolving correctly

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import pytest

from acgs_lite.compliance import (
    ChecklistStatus,
    FrameworkAssessment,
    JapanAIGuidelinesFramework,
    MultiFrameworkAssessor,
    MultiFrameworkReport,
)
from acgs_lite.compliance.multi_framework import _FRAMEWORK_REGISTRY

_BASE_DESC: dict = {
    "system_id": "test-jp-system",
    "purpose": "Automated decision support",
    "domain": "general",
}


@pytest.fixture
def base_desc() -> dict:
    return dict(_BASE_DESC)


@pytest.mark.unit
class TestJapanAIGuidelinesFramework:
    def test_registered_in_registry(self) -> None:
        assert "japan_ai_guidelines" in _FRAMEWORK_REGISTRY
        assert _FRAMEWORK_REGISTRY["japan_ai_guidelines"] is JapanAIGuidelinesFramework

    def test_framework_metadata(self) -> None:
        fw = JapanAIGuidelinesFramework()
        assert fw.framework_id == "japan_ai_guidelines"
        assert fw.jurisdiction == "Japan"
        assert fw.status == "voluntary"
        assert fw.enforcement_date is None

    def test_checklist_covers_core_principles(self, base_desc: dict) -> None:
        fw = JapanAIGuidelinesFramework()
        checklist = fw.get_checklist(base_desc)
        refs = [item.ref for item in checklist]
        # Human-centric, safety, fairness, privacy, transparency, accountability
        assert any("JP1" in r for r in refs), "Missing JP1 human-centric items"
        assert any("JP2" in r for r in refs), "Missing JP2 safety items"
        assert any("JP3" in r for r in refs), "Missing JP3 fairness items"
        assert any("JP4" in r for r in refs), "Missing JP4 privacy items"
        assert any("JP6" in r for r in refs), "Missing JP6 transparency items"
        assert any("JP7" in r for r in refs), "Missing JP7 accountability items"

    def test_auto_populate_marks_mapped_controls(self, base_desc: dict) -> None:
        fw = JapanAIGuidelinesFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        compliant_refs = {i.ref for i in checklist if i.status == ChecklistStatus.COMPLIANT}
        assert "JP-AI JP1.2" in compliant_refs
        assert "JP-AI JP6.1" in compliant_refs
        assert "JP-AI JP7.1" in compliant_refs

    def test_accountability_uses_maci_enforcer(self, base_desc: dict) -> None:
        fw = JapanAIGuidelinesFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        item = next(i for i in checklist if i.ref == "JP-AI JP7.1")
        assert item.status == ChecklistStatus.COMPLIANT
        assert "MACIEnforcer" in (item.evidence or "")

    def test_fairness_and_privacy_not_auto_satisfied(self, base_desc: dict) -> None:
        fw = JapanAIGuidelinesFramework()
        checklist = fw.get_checklist(base_desc)
        fw.auto_populate_acgs_lite(checklist)
        jp31 = next(i for i in checklist if i.ref == "JP-AI JP3.1")
        jp41 = next(i for i in checklist if i.ref == "JP-AI JP4.1")
        assert jp31.status == ChecklistStatus.PENDING
        assert jp41.status == ChecklistStatus.PENDING

    def test_assess_returns_valid_assessment(self, base_desc: dict) -> None:
        fw = JapanAIGuidelinesFramework()
        result = fw.assess(base_desc)
        assert isinstance(result, FrameworkAssessment)
        assert result.framework_id == "japan_ai_guidelines"
        assert result.framework_name == "Japan AI Guidelines for Business (METI/MIC)"
        assert 0.0 <= result.compliance_score <= 1.0
        assert result.acgs_lite_coverage > 0.0
        # acgs-lite maps a meaningful share of controls but does not fully cover
        assert result.compliance_score < 1.0

    def test_assess_has_mapped_controls_in_items(self, base_desc: dict) -> None:
        fw = JapanAIGuidelinesFramework()
        result = fw.assess(base_desc)
        mapped = [i for i in result.items if i["acgs_lite_feature"] is not None]
        assert len(mapped) >= 5
        assert any(i["status"] == "compliant" for i in result.items)

    def test_assess_produces_gaps_and_recommendations(self, base_desc: dict) -> None:
        fw = JapanAIGuidelinesFramework()
        result = fw.assess(base_desc)
        assert len(result.gaps) > 0
        assert any("JP3" in g or "JP4" in g for g in result.gaps)
        recs_text = " ".join(result.recommendations)
        assert "Japan AI Guidelines" in recs_text


@pytest.mark.unit
class TestJapanRouting:
    def test_japan_jurisdiction_routes_framework(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("japan", "general")
        assert "japan_ai_guidelines" in fws

    def test_available_frameworks_includes_japan(self) -> None:
        available = MultiFrameworkAssessor.available_frameworks()
        assert "japan_ai_guidelines" in available
        assert available["japan_ai_guidelines"] == "Japan AI Guidelines for Business (METI/MIC)"

    def test_explicit_underscore_selection(self) -> None:
        assessor = MultiFrameworkAssessor(frameworks=["japan_ai_guidelines"])
        report = assessor.assess({"system_id": "jp-explicit"})
        assert isinstance(report, MultiFrameworkReport)
        assert report.frameworks_assessed == ("japan_ai_guidelines",)

    def test_cli_dashed_framework_id_resolves(self) -> None:
        # The 'acgs assess --framework japan-ai-guidelines' surface passes the
        # dashed ID through verbatim; the assessor must normalize it.
        assessor = MultiFrameworkAssessor(frameworks=["japan-ai-guidelines"])
        report = assessor.assess({"system_id": "jp-dashed"})
        assert report.frameworks_assessed == ("japan_ai_guidelines",)

    def test_full_japan_assessment(self) -> None:
        assessor = MultiFrameworkAssessor()
        report = assessor.assess(
            {
                "system_id": "jp-system",
                "jurisdiction": "japan",
                "domain": "general",
            }
        )
        assert "japan_ai_guidelines" in report.frameworks_assessed
        assert 0.0 <= report.overall_score <= 1.0
