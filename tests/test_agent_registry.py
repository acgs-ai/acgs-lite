"""Tests for the agent capability profile schema and registry (U1, U2, U4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acgs_lite.agents import (
    AgentCapabilityProfile,
    AgentRegistry,
    get_agent_registry,
    reset_agent_registry,
)


def _make_profile(agent_id: str = "rev", **overrides: object) -> AgentCapabilityProfile:
    """Fixture helper: build a profile with sensible governance-flavored defaults."""
    defaults: dict[str, object] = {
        "name": "Reviewer",
        "description": "reviews governance changes",
        "capabilities": ("review", "governance", "audit"),
        "domains": ("governance",),
        "skills": ("branch-review",),
    }
    defaults.update(overrides)
    return AgentCapabilityProfile(agent_id=agent_id, **defaults)  # type: ignore[arg-type]


# -- U1: AgentCapabilityProfile ---------------------------------------------------


class TestProfile:
    def test_round_trip_to_from_dict(self) -> None:
        profile = _make_profile(tags=("ci",), metadata={"team": "gov"})
        assert AgentCapabilityProfile.from_dict(profile.to_dict()) == profile

    def test_from_dict_coerces_lists_to_tuples(self) -> None:
        profile = AgentCapabilityProfile.from_dict(
            {"agent_id": "x", "name": "X", "capabilities": ["a", "b"]}
        )
        assert profile.capabilities == ("a", "b")
        assert profile.domains == ()  # missing optional -> default

    def test_from_dict_rejects_empty_agent_id(self) -> None:
        with pytest.raises(ValueError):
            AgentCapabilityProfile.from_dict({"agent_id": "  ", "name": "X"})

    def test_from_dict_rejects_empty_name(self) -> None:
        with pytest.raises(ValueError):
            AgentCapabilityProfile.from_dict({"agent_id": "x", "name": ""})

    def test_inactive_profile_round_trips(self) -> None:
        profile = _make_profile(is_active=False)
        assert profile.is_active is False
        assert AgentCapabilityProfile.from_dict(profile.to_dict()).is_active is False

    def test_match_score_zero_when_no_overlap(self) -> None:
        assert _make_profile().match_score("write some css for the landing page") == 0.0

    def test_domain_agnostic_profile_handles_any_domain(self) -> None:
        profile = _make_profile(domains=())
        assert profile.handles_domain("anything") is True


# -- U2: AgentRegistry ------------------------------------------------------------


class TestRegistry:
    def test_register_get_list(self) -> None:
        reg = AgentRegistry(profiles=[])
        reg.register(_make_profile("a"))
        reg.register(_make_profile("b"))
        assert reg.get("a") is not None
        assert reg.get("missing") is None
        assert [p.agent_id for p in reg.list_profiles()] == ["a", "b"]

    def test_register_replaces_same_agent_id(self) -> None:
        reg = AgentRegistry(profiles=[])
        reg.register(_make_profile("a", name="First"))
        reg.register(_make_profile("a", name="Second"))
        assert len(reg) == 1
        assert reg.get("a").name == "Second"  # type: ignore[union-attr]

    def test_active_only_filter(self) -> None:
        reg = AgentRegistry(profiles=[])
        reg.register(_make_profile("a"))
        reg.register(_make_profile("b", is_active=False))
        assert [p.agent_id for p in reg.list_profiles(active_only=True)] == ["a"]
        assert [p.agent_id for p in reg.list_profiles(active_only=False)] == ["a", "b"]

    def test_candidates_ranked_best_first(self) -> None:
        reg = AgentRegistry(profiles=[])
        reg.register(_make_profile("gov", capabilities=("review", "governance", "audit")))
        reg.register(
            _make_profile(
                "fe",
                name="Frontend",
                description="builds css",
                capabilities=("css", "react"),
                domains=("frontend",),
                skills=(),
            )
        )
        ranked = reg.candidates_for("review a branch for governance regressions")
        assert ranked[0][0].agent_id == "gov"
        assert all(score > 0 for _profile, score in ranked)

    def test_candidates_deterministic_tie_break_by_agent_id(self) -> None:
        reg = AgentRegistry(profiles=[])
        # Two identical-capability agents -> equal score, ordered by agent_id.
        reg.register(_make_profile("zeta", skills=()))
        reg.register(_make_profile("alpha", skills=()))
        ranked = reg.candidates_for("review governance audit")
        assert [p.agent_id for p, _ in ranked] == ["alpha", "zeta"]

    def test_empty_registry_returns_no_candidates(self) -> None:
        assert AgentRegistry(profiles=[]).candidates_for("anything") == []

    def test_match_score_empty_task_is_zero(self) -> None:
        profile = _make_profile()
        assert profile.match_score("") == 0.0
        assert profile.match_score("   ") == 0.0

    def test_clear_empties_registry(self) -> None:
        reg = AgentRegistry(profiles=[])
        reg.register(_make_profile("a"))
        reg.clear()
        assert len(reg) == 0

    def test_to_manifest_round_trips(self, tmp_path: Path) -> None:
        reg = AgentRegistry(profiles=[])
        reg.register(_make_profile("a"))
        reg.register(_make_profile("b", is_active=False))
        manifest = tmp_path / "out.json"
        manifest.write_text(json.dumps(reg.to_manifest()), encoding="utf-8")
        restored = AgentRegistry.from_manifest(manifest)
        assert {p.agent_id for p in restored.list_profiles(active_only=False)} == {"a", "b"}

    def test_metadata_deep_copy_isolates_nested_state(self) -> None:
        nested = {"env": ["ci", "pr"]}
        profile = AgentCapabilityProfile.from_dict(
            {"agent_id": "x", "name": "X", "metadata": {"cfg": nested}}
        )
        nested["env"].append("mutated")  # mutate the source after construction
        assert profile.metadata["cfg"]["env"] == ["ci", "pr"]  # profile is isolated

    def test_from_manifest_loads_profiles(self, tmp_path: Path) -> None:
        manifest = tmp_path / "index.json"
        manifest.write_text(
            json.dumps([_make_profile("a").to_dict(), _make_profile("b").to_dict()]),
            encoding="utf-8",
        )
        reg = AgentRegistry.from_manifest(manifest)
        assert {p.agent_id for p in reg.list_profiles()} == {"a", "b"}

    def test_from_manifest_rejects_non_list(self, tmp_path: Path) -> None:
        manifest = tmp_path / "bad.json"
        manifest.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
        with pytest.raises(ValueError):
            AgentRegistry.from_manifest(manifest)

    def test_from_manifest_rejects_malformed_entry(self, tmp_path: Path) -> None:
        manifest = tmp_path / "bad.json"
        manifest.write_text(json.dumps([{"name": "no id"}]), encoding="utf-8")
        with pytest.raises((ValueError, KeyError)):
            AgentRegistry.from_manifest(manifest)


class TestSingleton:
    def test_singleton_is_stable_and_resettable(self) -> None:
        reg = get_agent_registry()
        assert get_agent_registry() is reg
        reg.register(_make_profile("temp"))
        assert reg.get("temp") is not None
        reset_agent_registry()
        assert get_agent_registry().get("temp") is None

    def test_bundled_manifest_load_does_not_error(self) -> None:
        # The bundled manifest may be empty; loading/reset must never raise.
        reset_agent_registry()
        assert isinstance(get_agent_registry().list_profiles(active_only=False), list)


# -- U4: public API surface -------------------------------------------------------


class TestPublicAPI:
    def test_top_level_imports(self) -> None:
        import acgs_lite

        for name in (
            "AgentCapabilityProfile",
            "AgentRegistry",
            "GovernedAgentSelector",
            "AgentSelection",
            "SelectionDeniedError",
            "NoEligibleAgentError",
            "get_agent_registry",
            "reset_agent_registry",
        ):
            assert hasattr(acgs_lite, name), name

    def test_stability_is_beta(self) -> None:
        from acgs_lite import stability

        for name in ("GovernedAgentSelector", "AgentRegistry", "AgentCapabilityProfile"):
            assert stability(name) == "beta", name
