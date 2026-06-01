# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""In-memory registry of agent capability profiles.

Mirrors :class:`~acgs_lite.provider_capabilities.CapabilityRegistry`: a process-local
registry seeded from a bundled JSON manifest, with a singleton accessor and a reset
hook for tests. Lookups are thread-safe for reads; the registry is the *discovery*
half of agent routing -- the governed :class:`~acgs_lite.agents.selector.GovernedAgentSelector`
is the *decision* half.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from acgs_lite.agents.capability import AgentCapabilityProfile


def _manifest_path() -> Path:
    return Path(__file__).with_name("agent_capabilities_manifest.json")


def _load_profiles(path: Path) -> list[AgentCapabilityProfile]:
    """Load and parse a JSON array of profile dicts from ``path``."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("agent capability manifest must be a JSON list")
    profiles: list[AgentCapabilityProfile] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each agent manifest entry must be an object")
        profiles.append(AgentCapabilityProfile.from_dict(item))
    return profiles


def load_agent_manifest() -> list[AgentCapabilityProfile]:
    """Load the bundled agent capability manifest, tolerating its absence.

    The bundled manifest is intentionally allowed to be missing or empty: a fresh
    deployment populates the registry via :meth:`AgentRegistry.register` or
    :meth:`AgentRegistry.from_manifest`, e.g. from the repo's ``agent-index.json``.
    """
    path = _manifest_path()
    if not path.exists():
        return []
    return _load_profiles(path)


def get_agent_manifest_path() -> Path:
    """Return the bundled manifest path."""
    return _manifest_path()


class AgentRegistry:
    """In-memory registry of :class:`AgentCapabilityProfile` records."""

    def __init__(self, profiles: list[AgentCapabilityProfile] | None = None) -> None:
        self._lock = threading.RLock()
        self._profiles: dict[str, AgentCapabilityProfile] = {}
        if profiles is None:
            self.reset()
        else:
            for profile in profiles:
                self.register(profile)

    def register(self, profile: AgentCapabilityProfile) -> None:
        """Register a profile, replacing any existing one with the same agent_id."""
        with self._lock:
            self._profiles[profile.agent_id] = profile

    def get(self, agent_id: str) -> AgentCapabilityProfile | None:
        """Return the profile for ``agent_id`` or ``None``."""
        with self._lock:
            return self._profiles.get(agent_id)

    def list_profiles(self, *, active_only: bool = True) -> list[AgentCapabilityProfile]:
        """Return registered profiles, sorted by agent_id for determinism."""
        with self._lock:
            profiles = list(self._profiles.values())
        if active_only:
            profiles = [p for p in profiles if p.is_active]
        return sorted(profiles, key=lambda p: p.agent_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._profiles)

    @staticmethod
    def rank_profiles(
        profiles: list[AgentCapabilityProfile],
        task: str,
        *,
        domain: str | None = None,
    ) -> list[tuple[AgentCapabilityProfile, float]]:
        """Rank an explicit profile list against ``task``, best-first.

        Shared ranking core used by both :meth:`candidates_for` (registry-backed)
        and the selector's caller-supplied-candidates path, so the scoring and
        ordering rules live in exactly one place. Only positive-score profiles are
        returned; ordering is deterministic (descending score, ties broken by
        ``agent_id``). Active-only filtering is the caller's responsibility.
        """
        scored: list[tuple[AgentCapabilityProfile, float]] = []
        for profile in profiles:
            if domain is not None and not profile.handles_domain(domain):
                continue
            score = profile.match_score(task, domain=domain)
            if score > 0.0:
                scored.append((profile, score))
        scored.sort(key=lambda pair: (-pair[1], pair[0].agent_id))
        return scored

    def candidates_for(
        self,
        task: str,
        *,
        domain: str | None = None,
        active_only: bool = True,
    ) -> list[tuple[AgentCapabilityProfile, float]]:
        """Return registered profiles matching ``task``, ranked best-first.

        Only profiles with a positive match score are returned -- when nothing
        matches, the result is ``[]`` and the governed selector fails closed rather
        than picking an unsuitable agent.
        """
        return self.rank_profiles(
            self.list_profiles(active_only=active_only), task, domain=domain
        )

    def clear(self) -> None:
        """Remove all registered profiles."""
        with self._lock:
            self._profiles.clear()

    def reset(self) -> None:
        """Reset the registry to the bundled manifest contents."""
        with self._lock:
            self._profiles = {p.agent_id: p for p in load_agent_manifest()}

    @classmethod
    def from_manifest(cls, path: str | Path) -> AgentRegistry:
        """Build a registry from a JSON manifest at ``path``.

        This is how the repo's ``agent-index.json`` is loaded into the same
        runtime schema the library uses, keeping the two discovery layers in lockstep.
        """
        profiles = _load_profiles(Path(path))
        registry = cls(profiles=[])
        for profile in profiles:
            registry.register(profile)
        return registry

    def to_manifest(self) -> list[dict[str, Any]]:
        """Serialize all registered profiles to manifest shape."""
        return [p.to_dict() for p in self.list_profiles(active_only=False)]


_REGISTRY = AgentRegistry()


def get_agent_registry() -> AgentRegistry:
    """Return the process-local agent registry."""
    return _REGISTRY


def reset_agent_registry() -> None:
    """Reset the process-local agent registry to the bundled manifest."""
    _REGISTRY.reset()


__all__ = [
    "AgentRegistry",
    "get_agent_manifest_path",
    "get_agent_registry",
    "load_agent_manifest",
    "reset_agent_registry",
]
