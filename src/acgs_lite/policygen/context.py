# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Pre-context assembly for adaptive policy generation.

A :class:`PreContext` is the structured "research brief" that drives adaptive
policy (constitution) generation: which governance *domain* is being governed,
its risk areas, the regulatory frameworks in scope, the deployment environment,
and any free-text custom requirements. :class:`PreContextBuilder` assembles one
*robustly* -- normalizing vocabulary, de-duplicating, and enriching the brief
deterministically by scanning the domain description for known risk signals and
framework references and classifying the domain's overall risk level.

This is deliberately dependency-free and deterministic (no LLM, no network) so
the pre-context is reproducible; the optional LLM enrichment lives downstream in
the researcher, behind a lazy import.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DomainRiskLevel(str, Enum):
    """Coarse risk level for a governance domain.

    Mirrors the spirit of the EU AI Act tiers without coupling to that module, so
    the generator can scale strictness adaptively.
    """

    MINIMAL = "minimal"
    LIMITED = "limited"
    HIGH = "high"
    UNACCEPTABLE = "unacceptable"

    def rank(self) -> int:
        return _RISK_RANK[self]


_RISK_RANK: dict[DomainRiskLevel, int] = {
    DomainRiskLevel.MINIMAL: 0,
    DomainRiskLevel.LIMITED: 1,
    DomainRiskLevel.HIGH: 2,
    DomainRiskLevel.UNACCEPTABLE: 3,
}
PRODUCTION_ENV_VALUES = ("production", "prod", "live")

# Canonical risk-area vocabulary. Aliases map free-form terms onto a stable key so
# the researcher's knowledge base can be addressed deterministically.
_RISK_AREA_ALIASES: dict[str, str] = {
    "pii": "pii",
    "personal data": "pii",
    "personally identifiable information": "pii",
    "privacy": "pii",
    "secret": "secrets",
    "secrets": "secrets",
    "credential": "secrets",
    "credentials": "secrets",
    "api key": "secrets",
    "api keys": "secrets",
    "access token": "secrets",
    "access tokens": "secrets",
    "token": "secrets",
    "tokens": "secrets",
    "code execution": "code-execution",
    "code-execution": "code-execution",
    "exec": "code-execution",
    "shell": "code-execution",
    "financial": "financial",
    "payment": "financial",
    "payments": "financial",
    "money": "financial",
    "billing": "financial",
    "data deletion": "data-deletion",
    "data-deletion": "data-deletion",
    "delete": "data-deletion",
    "destruction": "data-deletion",
    "drop table": "data-deletion",
    "production deploy": "production-deploy",
    "production-deploy": "production-deploy",
    "deploy": "production-deploy",
    "deployment": "production-deploy",
    "release": "production-deploy",
    "network": "network-egress",
    "network-egress": "network-egress",
    "egress": "network-egress",
    "exfiltration": "network-egress",
    "authentication": "authentication",
    "auth": "authentication",
    "authorization": "authentication",
    "access control": "authentication",
    "transparency": "transparency",
    "disclosure": "transparency",
    "explainability": "transparency",
    "human oversight": "human-oversight",
    "human-oversight": "human-oversight",
    "human review": "human-oversight",
    "oversight": "human-oversight",
}

# Framework name aliases -> canonical framework key understood by the researcher.
_FRAMEWORK_ALIASES: dict[str, str] = {
    "eu ai act": "eu-ai-act",
    "eu-ai-act": "eu-ai-act",
    "ai act": "eu-ai-act",
    "gdpr": "gdpr",
    "soc2": "soc2",
    "soc 2": "soc2",
    "hipaa": "hipaa",
}

# Domains that are inherently high-risk (subset mirroring EU AI Act Annex III spirit).
_HIGH_RISK_DOMAINS: frozenset[str] = frozenset(
    {
        "healthcare",
        "medical",
        "credit",
        "lending",
        "finance",
        "employment",
        "hiring",
        "education",
        "law enforcement",
        "justice",
        "biometric",
        "critical infrastructure",
    }
)


def _normalize_terms(values: tuple[str, ...], aliases: Mapping[str, str]) -> tuple[str, ...]:
    """Map free-form values onto canonical keys, preserving order and de-duping."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = aliases.get(value.strip().lower(), value.strip().lower())
        if key and key not in seen:
            out.append(key)
            seen.add(key)
    return tuple(out)


def _contains_alias(haystack: str, alias: str) -> bool:
    """Return whether ``alias`` appears as a complete token/phrase in ``haystack``."""
    return re.search(rf"\b{re.escape(alias)}\b", haystack) is not None


@dataclass(slots=True, frozen=True)
class PreContext:
    """The assembled, normalized research brief for policy generation."""

    domain: str
    description: str = ""
    objectives: tuple[str, ...] = ()
    risk_areas: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    environment: str = "production"
    risk_level: DomainRiskLevel = DomainRiskLevel.LIMITED
    custom_requirements: tuple[str, ...] = ()
    seed_keywords: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def is_production(self) -> bool:
        return self.environment.strip().lower() in PRODUCTION_ENV_VALUES

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "description": self.description,
            "objectives": list(self.objectives),
            "risk_areas": list(self.risk_areas),
            "frameworks": list(self.frameworks),
            "environment": self.environment,
            "risk_level": self.risk_level.value,
            "custom_requirements": list(self.custom_requirements),
            "seed_keywords": list(self.seed_keywords),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PreContext:
        """Inverse of :meth:`to_dict`.

        Deterministic and strict (fail-closed, as befits a governance artifact):
        unknown top-level keys raise ``ValueError`` naming them, a missing
        ``domain`` raises ``ValueError``, and an unrecognized ``risk_level``
        raises ``ValueError`` listing the valid values. Sequence fields are
        restored as tuples to match the dataclass field types; keys absent from
        ``data`` fall back to the dataclass defaults.
        """
        known_keys = {
            "domain",
            "description",
            "objectives",
            "risk_areas",
            "frameworks",
            "environment",
            "risk_level",
            "custom_requirements",
            "seed_keywords",
            "metadata",
        }
        unknown_keys = set(data.keys()) - known_keys
        if unknown_keys:
            raise ValueError(f"Unknown PreContext key(s): {', '.join(sorted(unknown_keys))}")
        if "domain" not in data:
            raise ValueError("Missing required PreContext key: 'domain'")

        kwargs: dict[str, Any] = {"domain": data["domain"]}
        if "description" in data:
            kwargs["description"] = data["description"]
        if "objectives" in data:
            kwargs["objectives"] = tuple(data["objectives"])
        if "risk_areas" in data:
            kwargs["risk_areas"] = tuple(data["risk_areas"])
        if "frameworks" in data:
            kwargs["frameworks"] = tuple(data["frameworks"])
        if "environment" in data:
            kwargs["environment"] = data["environment"]
        if "risk_level" in data:
            raw_risk_level = data["risk_level"]
            try:
                kwargs["risk_level"] = DomainRiskLevel(raw_risk_level)
            except ValueError as exc:
                valid_values = ", ".join(level.value for level in DomainRiskLevel)
                raise ValueError(
                    f"Invalid risk_level {raw_risk_level!r}; valid values: {valid_values}"
                ) from exc
        if "custom_requirements" in data:
            kwargs["custom_requirements"] = tuple(data["custom_requirements"])
        if "seed_keywords" in data:
            kwargs["seed_keywords"] = tuple(data["seed_keywords"])
        if "metadata" in data:
            kwargs["metadata"] = dict(data["metadata"])

        return cls(**kwargs)


class PreContextBuilder:
    """Robustly assemble a :class:`PreContext`, with deterministic enrichment.

    The builder normalizes risk-area and framework vocabulary, de-duplicates, and
    -- when :meth:`infer` is called -- scans the domain description for known risk
    signals and framework references and classifies the domain's risk level. None
    of this requires a network call or an LLM.
    """

    def __init__(
        self, domain: str, *, description: str = "", environment: str = "production"
    ) -> None:
        if not domain or not domain.strip():
            raise ValueError("PreContextBuilder requires a non-empty domain")
        self._domain = domain.strip()
        self._description = description.strip()
        self._environment = environment.strip() or "production"
        self._objectives: list[str] = []
        self._risk_areas: list[str] = []
        self._frameworks: list[str] = []
        self._custom: list[str] = []
        self._seed_keywords: list[str] = []
        self._risk_level: DomainRiskLevel | None = None
        self._metadata: dict[str, Any] = {}

    def with_objectives(self, *objectives: str) -> PreContextBuilder:
        self._objectives.extend(o.strip() for o in objectives if o.strip())
        return self

    def add_risk_area(self, *areas: str) -> PreContextBuilder:
        self._risk_areas.extend(areas)
        return self

    def add_framework(self, *frameworks: str) -> PreContextBuilder:
        self._frameworks.extend(frameworks)
        return self

    def add_custom_requirement(self, *requirements: str) -> PreContextBuilder:
        self._custom.extend(r.strip() for r in requirements if r.strip())
        return self

    def with_seed_keywords(self, *keywords: str) -> PreContextBuilder:
        self._seed_keywords.extend(k.strip() for k in keywords if k.strip())
        return self

    def with_risk_level(self, level: DomainRiskLevel | str) -> PreContextBuilder:
        self._risk_level = DomainRiskLevel(level) if isinstance(level, str) else level
        return self

    def metadata(self, **kwargs: Any) -> PreContextBuilder:
        self._metadata.update(kwargs)
        return self

    def infer(self) -> PreContextBuilder:
        """Enrich the brief from the domain + description, deterministically.

        Detects risk areas and frameworks mentioned in free text and, unless an
        explicit risk level was set, classifies the domain. Safe to call more than
        once; detection is additive and de-duplicated at build time.
        """
        haystack = f"{self._domain} {self._description}".lower()
        for alias, canonical in _RISK_AREA_ALIASES.items():
            if _contains_alias(haystack, alias) and canonical not in self._risk_areas:
                self._risk_areas.append(canonical)
        for alias, canonical in _FRAMEWORK_ALIASES.items():
            if _contains_alias(haystack, alias) and canonical not in self._frameworks:
                self._frameworks.append(canonical)
        if self._risk_level is None:
            self._risk_level = self._classify_risk(haystack)
        return self

    def _classify_risk(self, haystack: str) -> DomainRiskLevel:
        if any(_contains_alias(haystack, domain) for domain in _HIGH_RISK_DOMAINS):
            return DomainRiskLevel.HIGH
        # Several high-impact risk areas present -> treat as high risk.
        high_impact = {"pii", "secrets", "code-execution", "financial", "data-deletion"}
        normalized_risk_areas = _normalize_terms(tuple(self._risk_areas), _RISK_AREA_ALIASES)
        if len(high_impact.intersection(normalized_risk_areas)) >= 2:
            return DomainRiskLevel.HIGH
        if self._risk_areas or self._frameworks:
            return DomainRiskLevel.LIMITED
        return DomainRiskLevel.MINIMAL

    def build(self) -> PreContext:
        return PreContext(
            domain=self._domain,
            description=self._description,
            objectives=tuple(dict.fromkeys(self._objectives)),
            risk_areas=_normalize_terms(tuple(self._risk_areas), _RISK_AREA_ALIASES),
            frameworks=_normalize_terms(tuple(self._frameworks), _FRAMEWORK_ALIASES),
            environment=self._environment,
            risk_level=self._risk_level or DomainRiskLevel.LIMITED,
            custom_requirements=tuple(dict.fromkeys(self._custom)),
            seed_keywords=tuple(dict.fromkeys(self._seed_keywords)),
            metadata=dict(self._metadata),
        )


__all__ = ["DomainRiskLevel", "PRODUCTION_ENV_VALUES", "PreContext", "PreContextBuilder"]
