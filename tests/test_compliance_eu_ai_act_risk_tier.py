"""Tests for EU AI Act risk-tier auto-detection (infer_risk_tier).

Covers:
- Explicit risk_tier override (highest priority)
- High-risk domain inference (Annex III mapping)
- Limited-risk domain inference (Art. 50 transparency)
- Conservative default (no domain → "high")
- Integration: checklist length varies by inferred tier
- Integration: assess() passes inferred tier through correctly

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import pytest

from acgs_lite.compliance.eu_ai_act import EUAIActFramework, infer_risk_tier


class TestInferRiskTier:
    """Unit tests for infer_risk_tier()."""

    # ----- explicit override -----

    def test_explicit_high(self):
        assert infer_risk_tier({"risk_tier": "high"}) == "high"

    def test_explicit_minimal(self):
        assert infer_risk_tier({"risk_tier": "minimal"}) == "minimal"

    def test_explicit_limited(self):
        assert infer_risk_tier({"risk_tier": "limited"}) == "limited"

    def test_explicit_unacceptable(self):
        assert infer_risk_tier({"risk_tier": "unacceptable"}) == "unacceptable"

    def test_explicit_overrides_domain(self):
        """Explicit risk_tier wins even when domain would infer differently."""
        assert infer_risk_tier({"risk_tier": "minimal", "domain": "healthcare"}) == "minimal"
        assert infer_risk_tier({"risk_tier": "high", "domain": "chatbot"}) == "high"

    def test_explicit_is_case_insensitive(self):
        assert infer_risk_tier({"risk_tier": "HIGH"}) == "high"
        assert infer_risk_tier({"risk_tier": "MINIMAL"}) == "minimal"

    # ----- high-risk Annex III domains -----

    @pytest.mark.parametrize(
        "domain",
        [
            # Annex III point 3 — Education
            "education",
            "vocational_training",
            "exam",
            "admissions",
            # Annex III point 4 — Employment / HR
            "employment",
            "hiring",
            "hr",
            "human_resources",
            "recruitment",
            "performance_evaluation",
            # Annex III point 5 — Essential services
            "credit",
            "credit_scoring",
            "lending",
            "insurance",
            # Healthcare
            "healthcare",
            "medical",
            "clinical",
            "diagnostic",
            "hospital",
            # Annex III point 1 — Biometrics
            "biometrics",
            "facial_recognition",
            # Annex III point 2 — Critical infrastructure
            "critical_infrastructure",
            "energy",
            "transport",
            # Annex III point 6 — Law enforcement
            "law_enforcement",
            "police",
            # Annex III point 7 — Migration
            "migration",
            "border_control",
            # Annex III point 8 — Justice
            "justice",
            "legal",
            "judicial",
        ],
    )
    def test_high_risk_domains(self, domain: str):
        tier = infer_risk_tier({"domain": domain})
        assert tier == "high", f"Expected 'high' for domain={domain!r}, got {tier!r}"

    # ----- limited-risk domains -----

    @pytest.mark.parametrize(
        "domain",
        [
            "chatbot",
            "customer_service",
            "virtual_assistant",
            "content_generation",
            "creative",
            "entertainment",
            "recommendation",
            "search",
        ],
    )
    def test_limited_risk_domains(self, domain: str):
        tier = infer_risk_tier({"domain": domain})
        assert tier == "limited", f"Expected 'limited' for domain={domain!r}, got {tier!r}"

    # ----- conservative default -----

    def test_no_domain_defaults_to_high(self):
        assert infer_risk_tier({}) == "high"

    def test_empty_domain_defaults_to_high(self):
        assert infer_risk_tier({"domain": ""}) == "high"

    def test_unknown_domain_defaults_to_high(self):
        """Unknown domain should fall through to the conservative default."""
        assert infer_risk_tier({"domain": "manufacturing_quality_control"}) == "high"

    def test_general_domain_defaults_to_high(self):
        assert infer_risk_tier({"domain": "general"}) == "high"


class TestEUAIActChecklistByTier:
    """Integration tests: checklist length and content varies by tier."""

    def _checklist_refs(self, system_description: dict) -> set[str]:
        fw = EUAIActFramework()
        items = fw.get_checklist(system_description)
        # Only include items that are applicable (not NOT_APPLICABLE)
        from acgs_lite.compliance.base import ChecklistStatus

        return {item.ref for item in items if item.status != ChecklistStatus.NOT_APPLICABLE}

    def test_high_risk_includes_arts_9_through_26(self):
        refs = self._checklist_refs({"risk_tier": "high"})
        high_risk_arts = [
            "EU-AIA Art.9(1)",
            "EU-AIA Art.10(2)",
            "EU-AIA Art.11(1)",
            "EU-AIA Art.12(1)",
            "EU-AIA Art.13(1)",
            "EU-AIA Art.14(1)",
            "EU-AIA Art.15(1)",
            "EU-AIA Art.26(1)",
        ]
        for ref in high_risk_arts:
            assert ref in refs, f"{ref} missing from high-risk checklist"

    def test_minimal_risk_only_arts_5_and_50(self):
        refs = self._checklist_refs({"risk_tier": "minimal"})
        # Only Art.5 and Art.50 should be present
        assert all(
            ref.startswith("EU-AIA Art.5") or ref.startswith("EU-AIA Art.50") for ref in refs
        ), (
            f"Unexpected refs in minimal checklist: {refs - {'EU-AIA Art.5(1)', 'EU-AIA Art.5(2)', 'EU-AIA Art.50(1)', 'EU-AIA Art.50(2)'}}"
        )

    def test_limited_risk_same_as_minimal_no_high_risk_arts(self):
        refs = self._checklist_refs({"risk_tier": "limited"})
        high_risk_refs = {
            "EU-AIA Art.9(1)",
            "EU-AIA Art.10(2)",
            "EU-AIA Art.11(1)",
            "EU-AIA Art.12(1)",
            "EU-AIA Art.14(1)",
            "EU-AIA Art.15(1)",
        }
        assert not refs.intersection(high_risk_refs), (
            f"High-risk articles leaked into limited checklist: {refs & high_risk_refs}"
        )

    def test_high_risk_checklist_larger_than_limited(self):
        high_refs = self._checklist_refs({"risk_tier": "high"})
        limited_refs = self._checklist_refs({"risk_tier": "limited"})
        assert len(high_refs) > len(limited_refs)

    def test_gpai_adds_arts_53_and_55(self):
        refs_no_gpai = self._checklist_refs({"risk_tier": "high", "is_gpai": False})
        refs_gpai = self._checklist_refs({"risk_tier": "high", "is_gpai": True})
        assert "EU-AIA Art.53(1)" not in refs_no_gpai
        assert "EU-AIA Art.55(1)" not in refs_no_gpai
        assert "EU-AIA Art.53(1)" in refs_gpai
        assert "EU-AIA Art.55(1)" in refs_gpai

    # ----- auto-inferred from domain -----

    def test_hiring_domain_infers_high_tier_full_checklist(self):
        refs = self._checklist_refs({"domain": "hiring"})
        assert "EU-AIA Art.9(1)" in refs
        assert "EU-AIA Art.14(1)" in refs

    def test_chatbot_domain_infers_limited_tier_small_checklist(self):
        refs = self._checklist_refs({"domain": "chatbot"})
        assert "EU-AIA Art.50(1)" in refs
        assert "EU-AIA Art.9(1)" not in refs

    def test_healthcare_domain_infers_high_tier(self):
        refs = self._checklist_refs({"domain": "healthcare"})
        assert "EU-AIA Art.9(1)" in refs
        assert "EU-AIA Art.14(1)" in refs


class TestEUAIActAssessWithTierInference:
    """Integration tests: assess() plumbs inferred tier through correctly."""

    def test_assess_high_domain_produces_larger_gap_list(self):
        fw = EUAIActFramework()
        high = fw.assess({"system_id": "s", "domain": "hiring"})
        limited = fw.assess({"system_id": "s", "domain": "chatbot"})
        # High-risk assessment covers more articles → more gaps (before auto-pop)
        assert len(high.items) > len(limited.items)

    def test_assess_returns_valid_framework_assessment(self):
        fw = EUAIActFramework()
        a = fw.assess({"system_id": "test", "domain": "education"})
        assert a.framework_id == "eu_ai_act"
        assert 0.0 <= a.compliance_score <= 1.0
        assert isinstance(a.items, tuple)
        assert isinstance(a.gaps, tuple)

    def test_limited_domain_has_fewer_items_than_high_domain(self):
        """Limited-tier checklist is smaller than high-risk; score comparison
        is not meaningful because acgs-lite covers more high-risk articles
        proportionally (score may be higher for high tier)."""
        fw = EUAIActFramework()
        limited = fw.assess({"system_id": "s", "domain": "chatbot"})
        high = fw.assess({"system_id": "s", "domain": "education"})
        assert len(limited.items) < len(high.items)

    def test_infer_risk_tier_exported_from_compliance_init(self):
        from acgs_lite.compliance import infer_risk_tier as exported_fn

        assert callable(exported_fn)
        assert exported_fn({"domain": "healthcare"}) == "high"
