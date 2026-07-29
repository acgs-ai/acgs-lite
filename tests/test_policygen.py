"""Tests for adaptive policy generation (policygen subpackage).

Covers the pre-context builder, the researcher's knowledge base + dedupe, and the
adaptive generator — including the invariant that every generated policy YAML
round-trips through Constitution.from_yaml_str.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import acgs_lite
from acgs_lite.constitution.core import Severity
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.engine import GovernanceEngine
from acgs_lite.policygen import (
    AdaptivePolicyGenerator,
    DomainRiskLevel,
    PolicyRequirement,
    PolicyResearcher,
    PreContext,
    PreContextBuilder,
    ResearchReport,
)

# -- PreContextBuilder ------------------------------------------------------------


class TestPreContextBuilder:
    def test_empty_domain_rejected(self) -> None:
        with pytest.raises(ValueError):
            PreContextBuilder("   ")

    def test_infer_detects_risk_areas_and_frameworks(self) -> None:
        pc = (
            PreContextBuilder(
                "Support Bot",
                description="Handles PII and credentials; GDPR and SOC2 scope.",
            )
            .infer()
            .build()
        )
        assert "pii" in pc.risk_areas
        assert "secrets" in pc.risk_areas
        assert "gdpr" in pc.frameworks
        assert "soc2" in pc.frameworks

    def test_infer_detects_plural_secret_aliases(self) -> None:
        pc = (
            PreContextBuilder(
                "Support Bot",
                description="Handles API keys and access tokens for users.",
            )
            .infer()
            .build()
        )
        assert "secrets" in pc.risk_areas

    def test_infer_matches_aliases_as_words_not_substrings(self) -> None:
        pc = (
            PreContextBuilder(
                "Authoring Assistant",
                description="Creates executive summaries without touching auth or exec features.",
            )
            .infer()
            .build()
        )
        assert "authentication" in pc.risk_areas
        assert "code-execution" in pc.risk_areas

        pc = (
            PreContextBuilder(
                "Authoring Assistant",
                description="Creates executive summaries for documentation.",
            )
            .infer()
            .build()
        )
        assert "authentication" not in pc.risk_areas
        assert "code-execution" not in pc.risk_areas

    def test_alias_normalization_and_dedupe(self) -> None:
        pc = (
            PreContextBuilder("X")
            .add_risk_area("privacy", "pii", "personal data")  # all map to "pii"
            .add_framework("EU AI Act", "ai act")  # both map to "eu-ai-act"
            .build()
        )
        assert pc.risk_areas == ("pii",)
        assert pc.frameworks == ("eu-ai-act",)

    def test_high_risk_domain_classification(self) -> None:
        pc = PreContextBuilder("Clinical healthcare triage").infer().build()
        assert pc.risk_level is DomainRiskLevel.HIGH

    def test_high_risk_domain_classification_uses_word_boundaries(self) -> None:
        pc = PreContextBuilder("Medicality notes").infer().build()
        assert pc.risk_level is DomainRiskLevel.MINIMAL

    def test_two_high_impact_areas_is_high_risk(self) -> None:
        pc = PreContextBuilder("Ops Bot").add_risk_area("pii", "secrets").infer().build()
        assert pc.risk_level is DomainRiskLevel.HIGH

    def test_high_impact_aliases_are_normalized_before_classification(self) -> None:
        pc = PreContextBuilder("Ops Bot").add_risk_area("payment", "personal data").infer().build()
        assert pc.risk_level is DomainRiskLevel.HIGH
        assert pc.risk_areas == ("financial", "pii")

    def test_transparency_only_is_limited(self) -> None:
        pc = PreContextBuilder("Notes Bot").add_risk_area("transparency").infer().build()
        assert pc.risk_level is DomainRiskLevel.LIMITED

    def test_no_signals_is_minimal(self) -> None:
        pc = PreContextBuilder("Hello Bot").infer().build()
        assert pc.risk_level is DomainRiskLevel.MINIMAL

    def test_explicit_risk_level_overrides_inference(self) -> None:
        pc = (
            PreContextBuilder("Clinical healthcare")
            .with_risk_level(DomainRiskLevel.UNACCEPTABLE)
            .infer()
            .build()
        )
        assert pc.risk_level is DomainRiskLevel.UNACCEPTABLE

    def test_is_production(self) -> None:
        assert PreContextBuilder("X", environment="prod").build().is_production()
        assert not PreContextBuilder("X", environment="staging").build().is_production()


class TestPreContextFromDict:
    def test_round_trip_fully_populated(self) -> None:
        pc = (
            PreContextBuilder("ACME Health", environment="production")
            .with_objectives("Ship safely")
            .add_risk_area("pii", "secrets")
            .add_framework("hipaa")
            .add_custom_requirement("Never fabricate diagnoses.")
            .with_seed_keywords("triage", "diagnosis")
            .with_risk_level(DomainRiskLevel.HIGH)
            .metadata(owner="team-x")
            .build()
        )
        restored = PreContext.from_dict(pc.to_dict())
        assert restored == pc
        assert restored.to_dict() == pc.to_dict()

    def test_round_trip_defaults_only(self) -> None:
        pc = PreContext(domain="X")
        restored = PreContext.from_dict(pc.to_dict())
        assert restored == pc
        assert restored.to_dict() == pc.to_dict()

    def test_sequence_fields_restored_as_tuples(self) -> None:
        restored = PreContext.from_dict(
            {"domain": "X", "objectives": ["a", "b"], "risk_areas": ["pii"]}
        )
        assert restored.objectives == ("a", "b")
        assert restored.risk_areas == ("pii",)

    def test_missing_optional_keys_use_dataclass_defaults(self) -> None:
        restored = PreContext.from_dict({"domain": "X"})
        assert restored == PreContext(domain="X")

    def test_missing_required_domain_raises(self) -> None:
        with pytest.raises(ValueError, match="domain"):
            PreContext.from_dict({"description": "no domain here"})

    def test_unknown_key_raises(self) -> None:
        with pytest.raises(ValueError, match="bogus_key"):
            PreContext.from_dict({"domain": "X", "bogus_key": 1})

    def test_bad_risk_level_raises_with_valid_values_listed(self) -> None:
        with pytest.raises(ValueError, match="not-a-real-level") as exc_info:
            PreContext.from_dict({"domain": "X", "risk_level": "not-a-real-level"})
        message = str(exc_info.value)
        for level in DomainRiskLevel.__members__.values():
            assert level.value in message

    @pytest.mark.parametrize(
        "field",
        ["objectives", "risk_areas", "frameworks", "custom_requirements", "seed_keywords"],
    )
    def test_scalar_string_for_sequence_field_raises(self, field: str) -> None:
        with pytest.raises(ValueError, match=field):
            PreContext.from_dict({"domain": "X", field: "pii"})

    @pytest.mark.parametrize(
        "field",
        ["objectives", "risk_areas", "frameworks", "custom_requirements", "seed_keywords"],
    )
    def test_non_sequence_for_sequence_field_raises(self, field: str) -> None:
        with pytest.raises(ValueError, match=field):
            PreContext.from_dict({"domain": "X", field: 123})

    def test_non_mapping_metadata_raises(self) -> None:
        with pytest.raises(ValueError, match="metadata"):
            PreContext.from_dict({"domain": "X", "metadata": ["not", "a", "mapping"]})


# -- PolicyResearcher -------------------------------------------------------------


class TestPolicyResearcher:
    def test_risk_area_yields_requirement(self) -> None:
        pc = PreContextBuilder("X").add_risk_area("pii").build()
        report = PolicyResearcher().research(pc)
        assert len(report.requirements) == 1
        req = report.requirements[0]
        assert req.severity is Severity.CRITICAL
        assert req.patterns  # PII has regex patterns
        assert req.source == "risk-area:pii"

    def test_framework_yields_multiple_requirements(self) -> None:
        pc = PreContextBuilder("X").add_framework("gdpr").build()
        report = PolicyResearcher().research(pc)
        assert len(report.requirements) == 2
        assert all(r.source == "framework:gdpr" for r in report.requirements)

    def test_custom_requirement_synthesized_offline(self) -> None:
        pc = (
            PreContextBuilder("X")
            .add_custom_requirement("Agents must never fabricate clinical diagnoses.")
            .build()
        )
        report = PolicyResearcher().research(pc)
        assert len(report.requirements) == 1
        assert report.requirements[0].source == "custom"
        # heuristic infers CRITICAL from "must never"
        assert report.requirements[0].severity is Severity.CRITICAL

    def test_unknown_area_recorded_as_gap(self) -> None:
        pc = PreContext(domain="X", risk_areas=("nonsense-area",))
        report = PolicyResearcher().research(pc)
        assert report.requirements == ()
        assert any("nonsense-area" in g for g in report.gaps)

    def test_gap_compose_with_unknown_and_known_areas(self) -> None:
        pc = PreContext(domain="X", risk_areas=("pii", "nonsense-area"))
        report = PolicyResearcher().research(pc)
        # Should have exactly one requirement from PII
        pii_reqs = [r for r in report.requirements if r.source == "risk-area:pii"]
        assert len(pii_reqs) == 1
        # Should have a gap starting with "risk-area:nonsense-area" (stable prefix only)
        assert any(g.startswith("risk-area:nonsense-area") for g in report.gaps)

    def test_dedupe_merges_identical_text(self) -> None:
        # Same canonical area added twice (alias dedupe happens at build, so inject
        # a raw PreContext with a duplicate to exercise the researcher's own dedupe).
        pc = PreContext(domain="X", risk_areas=("pii", "pii"))
        report = PolicyResearcher().research(pc)
        assert len(report.requirements) == 1
        assert report.requirements[0].source == "risk-area:pii"

    def test_dedupe_preserves_unique_sources(self) -> None:
        req = PolicyResearcher._dedupe(
            [
                PolicyRequirement(
                    text="Agents must keep auditable records.",
                    severity=Severity.MEDIUM,
                    category="audit",
                    source="risk-area:pii",
                ),
                PolicyRequirement(
                    text="Agents must keep auditable records.",
                    severity=Severity.HIGH,
                    category="audit",
                    source="framework:gdpr",
                ),
            ]
        )[0]
        assert req.severity is Severity.HIGH
        assert req.source == "risk-area:pii, framework:gdpr"
        assert req.sources == ("risk-area:pii", "framework:gdpr")

        report = ResearchReport(domain="X", requirements=(req,))
        serialized = report.to_dict()["requirements"][0]
        assert serialized["source"] == "risk-area:pii, framework:gdpr"
        assert serialized["sources"] == ["risk-area:pii", "framework:gdpr"]

    def test_policy_requirement_positional_prod_only_abi_is_preserved(self) -> None:
        req = PolicyRequirement(
            "Agents must not mutate production.",
            Severity.CRITICAL,
            "operations",
            (),
            (),
            (),
            None,
            "legacy:source",
            True,
        )

        assert req.prod_only is True
        assert req.sources == ("legacy:source",)

    def test_policy_requirement_normalizes_explicit_sources(self) -> None:
        req = PolicyRequirement(
            text="Agents must keep auditable records.",
            severity=Severity.MEDIUM,
            category="audit",
            source="ignored-when-sources-present",
            sources=(" risk-area:pii ", "", "risk-area:pii", "framework:gdpr"),
        )

        assert req.provenance_sources() == ("risk-area:pii", "framework:gdpr")
        assert req.source == "risk-area:pii, framework:gdpr"

    def test_optional_llm_provider_is_used_for_custom(self) -> None:
        class StubProvider:
            def generate_rule(self, description: str, *, rule_id: str) -> dict[str, object]:
                return {"severity": "low", "keywords": ["stubbed"]}

        pc = PreContextBuilder("X").add_custom_requirement("Do the thing.").build()
        report = PolicyResearcher(llm_provider=StubProvider()).research(pc)
        req = report.requirements[0]
        assert req.severity is Severity.LOW
        assert "stubbed" in req.keywords


# -- AdaptivePolicyGenerator ------------------------------------------------------


def _high_risk_prod() -> PreContext:
    return (
        PreContextBuilder("ACME Health", environment="production")
        .add_risk_area("pii", "secrets")
        .add_framework("hipaa")
        .infer()
        .build()
    )


class TestAdaptiveGenerator:
    def test_generates_valid_roundtripping_yaml(self) -> None:
        policy = AdaptivePolicyGenerator().generate(_high_risk_prod())
        reloaded = acgs_lite.Constitution.from_yaml_str(policy.yaml)
        assert reloaded.hash == policy.constitution.hash
        assert len(reloaded.rules) == len(policy.constitution.rules) >= 1

    def test_high_risk_promotes_high_to_critical(self) -> None:
        # production-deploy is HIGH in the KB; HIGH-risk domain promotes it to CRITICAL.
        pc = (
            PreContextBuilder("Clinical healthcare", environment="production")
            .add_risk_area("production-deploy")
            .infer()
            .build()
        )
        assert pc.risk_level is DomainRiskLevel.HIGH
        policy = AdaptivePolicyGenerator().generate(pc)
        assert all(r.severity is Severity.CRITICAL for r in policy.constitution.rules)

    def test_unacceptable_escalates_every_rule(self) -> None:
        pc = (
            PreContextBuilder("X", environment="production")
            .add_risk_area("transparency")  # MEDIUM in KB
            .with_risk_level(DomainRiskLevel.UNACCEPTABLE)
            .build()
        )
        policy = AdaptivePolicyGenerator().generate(pc)
        # MEDIUM escalates one step -> HIGH
        assert policy.constitution.rules[0].severity is Severity.HIGH

    def test_production_only_rule_gets_env_condition(self) -> None:
        pc = (
            PreContextBuilder("X", environment="production")
            .add_risk_area("data-deletion")  # prod_only in KB
            .build()
        )
        policy = AdaptivePolicyGenerator().generate(pc)
        rule = policy.constitution.rules[0]
        assert rule.condition == {
            "env": {"op": "in", "value": ["production", "prod", "live"], "missing": "match"}
        }

    def test_production_only_rule_is_conditioned_outside_production(self) -> None:
        pc = (
            PreContextBuilder("X", environment="staging")
            .add_risk_area("data-deletion")  # prod_only in KB
            .build()
        )
        policy = AdaptivePolicyGenerator().generate(pc)
        rule = policy.constitution.rules[0]
        assert rule.condition == {
            "env": {"op": "in", "value": ["production", "prod", "live"], "missing": "match"}
        }
        assert rule.condition_matches({"env": "production"})
        assert rule.condition_matches({"env": "prod"})
        assert rule.condition_matches({"env": "live"})
        assert rule.condition_matches({"env": "PROD"})
        assert rule.condition_matches({"env": " prod "})
        assert rule.condition_matches({"environment": "prod"})
        assert rule.condition_matches({"environment": "Production"})
        assert not rule.condition_matches({"env": "staging"})
        assert not rule.condition_matches({"environment": "staging"})
        assert rule.condition_matches({})
        assert rule.workflow_action is ViolationAction.BLOCK_AND_NOTIFY

    def test_production_only_rule_matches_environment_context_in_engine(self) -> None:
        pc = (
            PreContextBuilder("X", environment="staging")
            .add_risk_area("data-deletion")  # prod_only in KB
            .build()
        )
        policy = AdaptivePolicyGenerator().generate(pc)

        result = GovernanceEngine(policy.constitution).validate(
            "delete from users",
            context={"environment": "prod"},
            strict=False,
        )

        assert not result.valid
        assert result.violations
        result = GovernanceEngine(policy.constitution).validate(
            "delete from users",
            context={"environment": "Production"},
            strict=False,
        )
        assert not result.valid
        assert result.violations

    def test_production_only_rule_fails_closed_when_environment_missing(self) -> None:
        pc = (
            PreContextBuilder("X", environment="staging")
            .add_risk_area("data-deletion")  # prod_only in KB
            .build()
        )
        policy = AdaptivePolicyGenerator().generate(pc)

        result = GovernanceEngine(policy.constitution).validate(
            "delete from users",
            context={},
            strict=False,
        )

        assert not result.valid
        assert result.violations

    def test_production_critical_uses_block_and_notify(self) -> None:
        pc = PreContextBuilder("X", environment="production").add_risk_area("pii").build()
        policy = AdaptivePolicyGenerator().generate(pc)
        assert policy.constitution.rules[0].workflow_action is ViolationAction.BLOCK_AND_NOTIFY

    def test_permission_ceiling_scales_with_risk(self) -> None:
        gen = AdaptivePolicyGenerator()
        high = gen.generate(_high_risk_prod())
        assert high.constitution.permission_ceiling == "strict"
        low = gen.generate(
            PreContextBuilder("Notes Bot").add_risk_area("transparency").infer().build()
        )
        assert low.constitution.permission_ceiling == "standard"

    def test_rule_ids_unique_and_prefixed(self) -> None:
        policy = AdaptivePolicyGenerator().generate(_high_risk_prod())
        ids = [r.id for r in policy.constitution.rules]
        assert len(ids) == len(set(ids))
        assert all(r.id.startswith("ACME-") for r in policy.constitution.rules)

    def test_provenance_recorded_per_rule(self) -> None:
        policy = AdaptivePolicyGenerator().generate(_high_risk_prod())
        assert all(r.provenance for r in policy.constitution.rules)

    def test_comma_separated_provenance_is_recorded_as_multiple_entries(self) -> None:
        class StubResearcher(PolicyResearcher):
            def research(self, precontext: PreContext) -> ResearchReport:
                return ResearchReport(
                    domain=precontext.domain,
                    requirements=(
                        PolicyRequirement(
                            text="Agents must keep auditable records.",
                            severity=Severity.MEDIUM,
                            category="audit",
                            source="risk-area:pii, framework:gdpr",
                            sources=("risk-area:pii", "framework:gdpr"),
                        ),
                    ),
                )

        pc = PreContextBuilder("X").build()
        policy = AdaptivePolicyGenerator(researcher=StubResearcher()).generate(pc)
        assert policy.constitution.rules[0].provenance == ["risk-area:pii", "framework:gdpr"]

    def test_summary_counts(self) -> None:
        policy = AdaptivePolicyGenerator().generate(_high_risk_prod())
        assert policy.summary["rule_count"] == len(policy.constitution.rules)
        assert sum(policy.summary["by_severity"].values()) == policy.summary["rule_count"]

    def test_write_yaml_to_disk(self, tmp_path: Path) -> None:
        out = tmp_path / "policy.yaml"
        path = AdaptivePolicyGenerator().write_yaml(_high_risk_prod(), out)
        assert path == out
        # The written file loads as a constitution.
        loaded = acgs_lite.Constitution.from_yaml(str(out))
        assert len(loaded.rules) >= 1
        # Provenance round-trip: ensure loaded rules have same provenance as original
        policy = AdaptivePolicyGenerator().generate(_high_risk_prod())
        assert {r.id: list(r.provenance) for r in loaded.rules} == {
            r.id: list(r.provenance) for r in policy.constitution.rules
        }


# -- public API -------------------------------------------------------------------


class TestPublicAPI:
    def test_top_level_imports(self) -> None:
        for name in (
            "AdaptivePolicyGenerator",
            "PreContextBuilder",
            "PreContext",
            "PolicyResearcher",
            "GeneratedPolicy",
            "DomainRiskLevel",
            "ResearchReport",
            "PolicyRequirement",
        ):
            assert hasattr(acgs_lite, name), name

    def test_stability_is_beta(self) -> None:
        assert acgs_lite.stability("AdaptivePolicyGenerator") == "beta"
        assert acgs_lite.stability("PreContextBuilder") == "beta"
