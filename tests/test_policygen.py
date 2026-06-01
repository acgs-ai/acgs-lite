"""Tests for adaptive policy generation (policygen subpackage).

Covers the pre-context builder, the researcher's knowledge base + dedupe, and the
adaptive generator — including the invariant that every generated policy YAML
round-trips through Constitution.from_yaml_str.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acgs_lite import Constitution
from acgs_lite.constitution.core import Severity
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.policygen import (
    AdaptivePolicyGenerator,
    DomainRiskLevel,
    PolicyResearcher,
    PreContext,
    PreContextBuilder,
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

    def test_two_high_impact_areas_is_high_risk(self) -> None:
        pc = PreContextBuilder("Ops Bot").add_risk_area("pii", "secrets").infer().build()
        assert pc.risk_level is DomainRiskLevel.HIGH

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

    def test_dedupe_merges_identical_text(self) -> None:
        # Same canonical area added twice (alias dedupe happens at build, so inject
        # a raw PreContext with a duplicate to exercise the researcher's own dedupe).
        pc = PreContext(domain="X", risk_areas=("pii", "pii"))
        report = PolicyResearcher().research(pc)
        assert len(report.requirements) == 1

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
        reloaded = Constitution.from_yaml_str(policy.yaml)
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
        assert rule.condition == {"env": "production"}

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

    def test_summary_counts(self) -> None:
        policy = AdaptivePolicyGenerator().generate(_high_risk_prod())
        assert policy.summary["rule_count"] == len(policy.constitution.rules)
        assert sum(policy.summary["by_severity"].values()) == policy.summary["rule_count"]

    def test_write_yaml_to_disk(self, tmp_path: Path) -> None:
        out = tmp_path / "policy.yaml"
        path = AdaptivePolicyGenerator().write_yaml(_high_risk_prod(), out)
        assert path == out
        # The written file loads as a constitution.
        loaded = Constitution.from_yaml(str(out))
        assert len(loaded.rules) >= 1


# -- public API -------------------------------------------------------------------


class TestPublicAPI:
    def test_top_level_imports(self) -> None:
        import acgs_lite

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
        from acgs_lite import stability

        assert stability("AdaptivePolicyGenerator") == "beta"
        assert stability("PreContextBuilder") == "beta"
