"""Tests for the API_STABILITY classification map (api-stability-layers)."""

from __future__ import annotations

import acgs_lite


class TestApiStability:
    def test_classification_layers_are_well_formed(self) -> None:
        for name, layer in acgs_lite.API_STABILITY.items():
            assert layer in {"stable", "beta", "experimental"}, (name, layer)

    def test_no_overlap_between_layers(self) -> None:
        from acgs_lite import (
            _STABILITY_BETA,
            _STABILITY_EXPERIMENTAL,
            _STABILITY_STABLE,
        )

        assert _STABILITY_STABLE.isdisjoint(_STABILITY_BETA)
        assert _STABILITY_STABLE.isdisjoint(_STABILITY_EXPERIMENTAL)
        assert _STABILITY_BETA.isdisjoint(_STABILITY_EXPERIMENTAL)

    def test_core_surface_marked_stable(self) -> None:
        for name in (
            "Constitution",
            "Rule",
            "Severity",
            "GovernanceEngine",
            "GovernedAgent",
            "AuditLog",
            "MACIRole",
            "ConstitutionalViolationError",
            "PolicyDeniedError",
            "GovernanceCircuitBreaker",
        ):
            assert acgs_lite.stability(name) == "stable", name

    def test_lifecycle_surface_marked_beta(self) -> None:
        for name in (
            "ConstitutionLifecycle",
            "ConstitutionBundle",
            "TrustScoreManager",
            "SpotCheckAuditor",
        ):
            assert acgs_lite.stability(name) == "beta", name

    def test_formal_verification_marked_experimental(self) -> None:
        for name in (
            "Z3ConstraintVerifier",
            "LeanstralVerifier",
            "create_openshell_governance_app",
        ):
            assert acgs_lite.stability(name) == "experimental", name

    def test_unclassified_defaults_to_experimental(self) -> None:
        assert acgs_lite.stability("DoesNotExist__Symbol") == "experimental"

    def test_every_public_export_is_classified(self) -> None:
        unclassified = [
            name
            for name in acgs_lite.__all__
            if name not in acgs_lite.API_STABILITY and name not in {"API_STABILITY", "stability"}
        ]
        assert unclassified == [], (
            f"These public exports lack a stability classification: {unclassified}"
        )

    def test_api_stability_and_helper_are_exported(self) -> None:
        assert "API_STABILITY" in acgs_lite.__all__
        assert "stability" in acgs_lite.__all__
        assert isinstance(acgs_lite.API_STABILITY, dict)
        assert callable(acgs_lite.stability)
