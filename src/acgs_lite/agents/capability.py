# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Agent capability profiles.

A :class:`AgentCapabilityProfile` is a declarative, framework-neutral description
of *an agent* (or skill) that an orchestrator might delegate a task to. It is the
shared schema for both layers of agent discovery: the runtime
:class:`~acgs_lite.agents.registry.AgentRegistry` consumes these profiles, and the
repo's machine-readable ``agent-index.json`` (repo root) is authored in the exact
same shape so the two layers cannot drift.

The profile carries no executable behavior -- selection returns a decision and a
receipt, it does not run the agent. Profiles are frozen value objects, mirroring
:class:`~acgs_lite.provider_capabilities.ProviderCapabilityProfile`.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

_TERM_SPLIT = re.compile(r"[^a-z0-9]+")


def _coerce_str_tuple(value: Any) -> tuple[str, ...]:
    """Coerce a manifest value into a tuple of non-empty strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        # A bare string is treated as a single entry, not split into characters.
        return (value,) if value else ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if str(item))
    raise ValueError(f"expected a list of strings, got {type(value).__name__}")


def _tokenize(*sources: str) -> frozenset[str]:
    """Lowercase, split, and dedupe free text into search terms."""
    tokens: set[str] = set()
    for source in sources:
        for token in _TERM_SPLIT.split(source.lower()):
            if token:
                tokens.add(token)
    return frozenset(tokens)


@dataclass(slots=True, frozen=True)
class AgentCapabilityProfile:
    """Declarative capability profile for a delegable agent or skill."""

    agent_id: str
    name: str
    description: str = ""
    capabilities: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    skills: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    support_level: str = "community"
    stability: str = "beta"
    is_active: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.agent_id or not self.agent_id.strip():
            raise ValueError("AgentCapabilityProfile requires a non-empty agent_id")
        if not self.name or not self.name.strip():
            raise ValueError("AgentCapabilityProfile requires a non-empty name")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentCapabilityProfile:
        """Build a profile from agent-index / manifest data.

        List-valued fields are coerced to tuples; missing optional fields fall back
        to defaults. An empty ``agent_id`` or ``name`` raises ``ValueError`` so a
        malformed index entry fails loudly rather than producing a silent ghost
        profile that can never be selected.
        """
        if not isinstance(data, Mapping):
            raise ValueError(f"profile entry must be a mapping, got {type(data).__name__}")
        metadata_raw = data.get("metadata", {})
        if not isinstance(metadata_raw, Mapping):
            raise ValueError("profile 'metadata' must be a mapping")
        return cls(
            agent_id=str(data["agent_id"]),
            name=str(data["name"]),
            description=str(data.get("description", "")),
            capabilities=_coerce_str_tuple(data.get("capabilities")),
            domains=_coerce_str_tuple(data.get("domains")),
            skills=_coerce_str_tuple(data.get("skills")),
            tags=_coerce_str_tuple(data.get("tags")),
            support_level=str(data.get("support_level", "community")),
            stability=str(data.get("stability", "beta")),
            is_active=bool(data.get("is_active", True)),
            # Deep-copy so a frozen profile never shares nested mutable state with
            # the source dict (the round-trip stays lossless and truly isolated).
            metadata=copy.deepcopy(dict(metadata_raw)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the profile into agent-index / manifest shape."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "description": self.description,
            "capabilities": list(self.capabilities),
            "domains": list(self.domains),
            "skills": list(self.skills),
            "tags": list(self.tags),
            "support_level": self.support_level,
            "stability": self.stability,
            "is_active": self.is_active,
            "metadata": copy.deepcopy(dict(self.metadata)),
        }

    def handles_domain(self, domain: str) -> bool:
        """Return True when ``domain`` matches one of the profile's domains.

        An empty ``domains`` tuple means the agent is domain-agnostic and handles
        any domain.
        """
        if not self.domains:
            return True
        target = domain.strip().lower()
        return any(target == d.strip().lower() for d in self.domains)

    def match_score(self, task: str, *, domain: str | None = None) -> float:
        """Score this profile against a task description.

        Deterministic, dependency-free lexical overlap: structured terms
        (capabilities, skills, domains, tags) are weighted above prose terms
        (name, description), with a bonus when an explicit ``domain`` matches.
        Returns ``0.0`` when nothing overlaps. The scoring is pure-Python by design
        (the "keep Python fallbacks" rule); a semantic ranker is a future extra.
        """
        task_terms = _tokenize(task)
        if not task_terms:
            return 0.0
        strong = _tokenize(*self.capabilities, *self.skills, *self.domains, *self.tags)
        weak = _tokenize(self.name, self.description)
        score = 2.0 * len(task_terms & strong) + 1.0 * len(task_terms & weak)
        if domain is not None and self.domains and self.handles_domain(domain):
            score += 3.0
        return score


__all__ = ["AgentCapabilityProfile"]
