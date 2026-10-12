"""Supplementary tests for compliance module -- gap coverage.

Covers APIs and edge cases not exercised by test_compliance.py:
- ChecklistItem.to_dict after status transitions
- ChecklistStatus enum values
- FrameworkAssessment.to_dict field types
- MultiFrameworkReport.to_dict disclaimer field
- MultiFrameworkAssessor with employment/hiring domains
- Cross-framework gap theme detection
- _compute_overall_score / _compute_acgs_coverage with empty input
"""

from __future__ import annotations

import pytest

from acgs_lite.compliance.base import (
    ChecklistItem,
    ChecklistStatus,
    ComplianceFramework,
    FrameworkAssessment,
    MultiFrameworkReport,
)
from acgs_lite.compliance.multi_framework import (
    MultiFrameworkAssessor,
    _compute_acgs_coverage,
    _compute_overall_score,
    _identify_cross_framework_gaps,
)

# ---------------------------------------------------------------------------
# ChecklistItem edge cases
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestChecklistItemEdgeCases:
    def test_to_dict_includes_updated_at_after_mark_complete(self) -> None:
        item = ChecklistItem(ref="T.1", requirement="req")
        item.mark_complete("done")
        d = item.to_dict()
        assert d["status"] == "compliant"
        assert d["updated_at"] is not None
        assert "T" in d["updated_at"]  # ISO format contains 'T'

    def test_to_dict_after_mark_partial(self) -> None:
        item = ChecklistItem(ref="T.2", requirement="req")
        item.mark_partial("partial")
        d = item.to_dict()
        assert d["status"] == "partial"
        assert d["evidence"] == "partial"

    def test_to_dict_after_mark_not_applicable(self) -> None:
        item = ChecklistItem(ref="T.3", requirement="req")
        item.mark_not_applicable("n/a reason")
        d = item.to_dict()
        assert d["status"] == "not_applicable"
        assert d["evidence"] == "n/a reason"

    def test_mark_complete_without_evidence(self) -> None:
        item = ChecklistItem(ref="T.4", requirement="req")
        item.mark_complete()
        assert item.status == ChecklistStatus.COMPLIANT
        assert item.evidence is None

    def test_default_blocking_is_true(self) -> None:
        item = ChecklistItem(ref="T.5", requirement="req")
        assert item.blocking is True
        assert item.to_dict()["blocking"] is True

    def test_non_blocking_item(self) -> None:
        item = ChecklistItem(ref="T.6", requirement="req", blocking=False)
        assert item.to_dict()["blocking"] is False


# ---------------------------------------------------------------------------
# ChecklistStatus enum
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestChecklistStatusEnum:
    def test_all_status_values(self) -> None:
        expected = {"pending", "compliant", "partial", "non_compliant", "not_applicable"}
        actual = {s.value for s in ChecklistStatus}
        assert actual == expected

    def test_str_enum_comparison(self) -> None:
        assert ChecklistStatus.PENDING == "pending"
        assert ChecklistStatus.COMPLIANT == "compliant"


# ---------------------------------------------------------------------------
# FrameworkAssessment serialization
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestFrameworkAssessmentSerialization:
    def test_to_dict_lists_not_tuples(self) -> None:
        fa = FrameworkAssessment(
            framework_id="test",
            framework_name="Test",
            compliance_score=0.5,
            items=({"ref": "X.1"},),
            gaps=("gap1",),
            acgs_lite_coverage=0.25,
            recommendations=("rec1",),
            assessed_at="2025-01-01T00:00:00",
        )
        d = fa.to_dict()
        assert isinstance(d["items"], list)
        assert isinstance(d["gaps"], list)
        assert isinstance(d["recommendations"], list)
        assert d["assessed_at"] == "2025-01-01T00:00:00"

    def test_frozen_assessment_is_immutable(self) -> None:
        fa = FrameworkAssessment(
            framework_id="test",
            framework_name="Test",
            compliance_score=1.0,
            items=(),
            gaps=(),
            acgs_lite_coverage=0.0,
            recommendations=(),
        )
        with pytest.raises(AttributeError):
            fa.compliance_score = 0.5  # type: ignore[misc]


# ---------------------------------------------------------------------------
# MultiFrameworkReport serialization
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestMultiFrameworkReportSerialization:
    def test_to_dict_has_disclaimer(self) -> None:
        report = MultiFrameworkReport(
            system_id="sys",
            frameworks_assessed=("gdpr",),
            overall_score=0.8,
        )
        d = report.to_dict()
        assert "disclaimer" in d
        assert "Not legal advice" in d["disclaimer"]

    def test_to_dict_converts_tuples_to_lists(self) -> None:
        report = MultiFrameworkReport(
            system_id="sys",
            frameworks_assessed=("a", "b"),
            overall_score=0.5,
            cross_framework_gaps=("gap1",),
            recommendations=("rec1",),
        )
        d = report.to_dict()
        assert isinstance(d["frameworks_assessed"], list)
        assert isinstance(d["cross_framework_gaps"], list)
        assert isinstance(d["recommendations"], list)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestProtocolRuntimeCheck:
    def test_non_conformant_object_fails_isinstance(self) -> None:
        class NotAFramework:
            pass

        assert not isinstance(NotAFramework(), ComplianceFramework)


# ---------------------------------------------------------------------------
# Private scoring helpers
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestScoringHelpers:
    def test_compute_overall_score_empty(self) -> None:
        assert _compute_overall_score({}) == 0.0

    def test_compute_acgs_coverage_empty(self) -> None:
        assert _compute_acgs_coverage({}) == 0.0

    def test_identify_cross_framework_gaps_empty(self) -> None:
        assert _identify_cross_framework_gaps({}) == ()

    def test_identify_cross_framework_gaps_with_bias_theme(self) -> None:
        fa = FrameworkAssessment(
            framework_id="test",
            framework_name="Test",
            compliance_score=0.5,
            items=(),
            gaps=("Conduct bias testing across demographic groups",),
            acgs_lite_coverage=0.0,
            recommendations=(),
        )
        result = _identify_cross_framework_gaps({"test": fa})
        # Should detect "bias_testing" theme
        assert any("bias" in g.lower() or "fairness" in g.lower() for g in result)


# ---------------------------------------------------------------------------
# Domain-based framework selection
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestDomainSelection:
    def test_employment_domain_adds_ll144(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_states", "employment")
        assert "nyc_ll144" in fws

    def test_hiring_domain_adds_ll144(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_states", "hiring")
        assert "nyc_ll144" in fws

    def test_credit_domain_adds_fair_lending(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_states", "credit")
        assert "us_fair_lending" in fws

    def test_financial_domain_adds_soc2_and_fair_lending(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("international", "financial")
        assert "us_fair_lending" in fws
        assert "soc2_ai" in fws

    def test_medical_domain_adds_hipaa(self) -> None:
        assessor = MultiFrameworkAssessor()
        fws = assessor.applicable_frameworks("united_states", "medical")
        assert "hipaa_ai" in fws


# ---------------------------------------------------------------------------
# MultiFrameworkAssessor caching
# ---------------------------------------------------------------------------


@pytest.mark.compliance
class TestAssessorCaching:
    def test_get_instance_returns_same_object(self) -> None:
        assessor = MultiFrameworkAssessor(frameworks=["gdpr"])
        desc = {"system_id": "test"}
        assessor.assess(desc)
        # Access private cache to verify singleton behavior
        assert "gdpr" in assessor._instances
        first = assessor._instances["gdpr"]
        assessor.assess(desc)
        assert assessor._instances["gdpr"] is first
