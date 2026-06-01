# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Automated policy research.

The :class:`PolicyResearcher` turns a :class:`~acgs_lite.policygen.context.PreContext`
into a set of concrete :class:`PolicyRequirement` records, drawing on a curated,
deterministic knowledge base that maps governance *risk areas* and *regulatory
frameworks* onto well-formed requirement specs (text, severity, keywords, regex
patterns, provenance). Free-text custom requirements are synthesized through the
existing :meth:`acgs_lite.constitution.Rule.from_description` heuristic, with an
optional pluggable ``RuleSynthesisProvider`` for LLM-backed enrichment.

The baseline is fully offline and reproducible (no network, no LLM). The optional
LLM provider follows the repo's lazy-integration convention -- it is injected by
the caller, never imported here.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from acgs_lite.constitution import Rule, Severity
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.policygen.context import PreContext

if TYPE_CHECKING:
    from acgs_lite.constitution.rule import RuleSynthesisProvider

_WS = re.compile(r"\s+")


@dataclass(slots=True, frozen=True)
class PolicyRequirement:
    """A single researched policy requirement, ready to become a rule."""

    text: str
    severity: Severity
    category: str
    keywords: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    workflow_action: ViolationAction | None = None
    source: str = ""
    prod_only: bool = False

    def fingerprint(self) -> str:
        """Normalized text key used to de-duplicate requirements."""
        return _WS.sub(" ", self.text.strip().lower())


@dataclass(slots=True, frozen=True)
class ResearchReport:
    """The output of :meth:`PolicyResearcher.research`."""

    domain: str
    requirements: tuple[PolicyRequirement, ...]
    sources: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "requirements": [
                {
                    "text": r.text,
                    "severity": r.severity.value,
                    "category": r.category,
                    "keywords": list(r.keywords),
                    "patterns": list(r.patterns),
                    "tags": list(r.tags),
                    "source": r.source,
                    "prod_only": r.prod_only,
                }
                for r in self.requirements
            ],
            "sources": list(self.sources),
            "gaps": list(self.gaps),
        }


# --- Knowledge base ---------------------------------------------------------------
# Each entry is a partial spec; PolicyRequirement is constructed in research().

_RISK_AREA_KB: dict[str, dict[str, Any]] = {
    "pii": {
        "text": "Agents must not expose, log, or transmit personally identifiable information (PII).",
        "severity": Severity.CRITICAL,
        "category": "data-protection",
        "keywords": ["ssn", "social security", "credit card number", "date of birth", "passport"],
        "patterns": [r"\b\d{3}-\d{2}-\d{4}\b", r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"],
        "tags": ["privacy"],
    },
    "secrets": {
        "text": "Agents must not read, log, or transmit secrets, credentials, API keys, or private keys.",
        "severity": Severity.CRITICAL,
        "category": "security",
        "keywords": ["api key", "secret key", "password", "private key", "access token"],
        "patterns": [r"(?i)\bapi[_-]?key\b", r"(?i)\bsecret[_-]?key\b"],
        "tags": ["security"],
    },
    "code-execution": {
        "text": "Agents must not execute arbitrary or unsandboxed code or shell commands.",
        "severity": Severity.CRITICAL,
        "category": "code-execution",
        "keywords": ["exec", "eval", "subprocess", "os.system", "shell"],
        "tags": ["safety"],
    },
    "financial": {
        "text": "Agents must not initiate financial transactions or move funds without authorization.",
        "severity": Severity.CRITICAL,
        "category": "financial",
        "keywords": ["transfer funds", "wire transfer", "payment", "refund", "charge card"],
        "tags": ["financial"],
        "prod_only": True,
    },
    "data-deletion": {
        "text": "Agents must not delete, drop, or truncate data or schema without explicit approval.",
        "severity": Severity.CRITICAL,
        "category": "data-integrity",
        "keywords": ["delete from", "drop table", "truncate", "rm -rf", "destroy"],
        "tags": ["data-integrity"],
        "prod_only": True,
    },
    "production-deploy": {
        "text": "Agents must not deploy to production or mutate live infrastructure without approval.",
        "severity": Severity.HIGH,
        "category": "operations",
        "keywords": ["deploy production", "kubectl apply", "terraform apply", "force push"],
        "tags": ["operations"],
        "workflow_action": ViolationAction.REQUIRE_HUMAN_REVIEW,
        "prod_only": True,
    },
    "network-egress": {
        "text": "Agents must not exfiltrate data to untrusted external endpoints.",
        "severity": Severity.HIGH,
        "category": "security",
        "keywords": ["upload to", "exfiltrate", "external endpoint", "outbound webhook"],
        "tags": ["security"],
    },
    "authentication": {
        "text": "Agents must not bypass authentication or escalate privileges.",
        "severity": Severity.CRITICAL,
        "category": "security",
        "keywords": ["bypass auth", "escalate privilege", "sudo", "admin override"],
        "tags": ["security"],
    },
    "transparency": {
        "text": "Agents must disclose automated decision-making and provide explanations on request.",
        "severity": Severity.MEDIUM,
        "category": "transparency",
        "keywords": ["automated decision", "disclose", "explanation"],
        "tags": ["transparency"],
    },
    "human-oversight": {
        "text": "High-impact agent actions must route to human review before execution.",
        "severity": Severity.HIGH,
        "category": "oversight",
        "keywords": ["human review", "approval required", "oversight"],
        "tags": ["oversight"],
        "workflow_action": ViolationAction.REQUIRE_HUMAN_REVIEW,
    },
}

_FRAMEWORK_KB: dict[str, tuple[dict[str, Any], ...]] = {
    "eu-ai-act": (
        {
            "text": "High-risk AI systems must operate under a documented risk-management system (EU AI Act Art.9).",
            "severity": Severity.HIGH,
            "category": "compliance",
            "keywords": ["risk management", "high-risk"],
            "tags": ["eu-ai-act"],
        },
        {
            "text": "High-risk AI systems must ensure effective human oversight (EU AI Act Art.14).",
            "severity": Severity.HIGH,
            "category": "oversight",
            "keywords": ["human oversight"],
            "tags": ["eu-ai-act"],
            "workflow_action": ViolationAction.REQUIRE_HUMAN_REVIEW,
        },
        {
            "text": "Maintain automatic logs ensuring traceability of system operation (EU AI Act Art.12).",
            "severity": Severity.MEDIUM,
            "category": "transparency",
            "keywords": ["logging", "traceability"],
            "tags": ["eu-ai-act"],
        },
    ),
    "gdpr": (
        {
            "text": "Process personal data only with a lawful basis and explicit consent (GDPR Art.6).",
            "severity": Severity.HIGH,
            "category": "data-protection",
            "keywords": ["lawful basis", "consent", "personal data"],
            "tags": ["gdpr"],
        },
        {
            "text": "Honor data-subject rights including access and erasure (GDPR Art.15-17).",
            "severity": Severity.HIGH,
            "category": "data-protection",
            "keywords": ["right to access", "erasure", "data subject"],
            "tags": ["gdpr"],
        },
    ),
    "soc2": (
        {
            "text": "Restrict and log privileged access to production systems (SOC2 CC6).",
            "severity": Severity.HIGH,
            "category": "security",
            "keywords": ["privileged access", "access logging"],
            "tags": ["soc2"],
        },
        {
            "text": "Production changes must follow a documented change-management process (SOC2 CC8).",
            "severity": Severity.HIGH,
            "category": "operations",
            "keywords": ["change management", "deploy"],
            "tags": ["soc2"],
            "prod_only": True,
        },
    ),
    "hipaa": (
        {
            "text": "Protected health information (PHI) must be encrypted and access-audited (HIPAA Security Rule).",
            "severity": Severity.CRITICAL,
            "category": "data-protection",
            "keywords": ["phi", "health information", "encrypt"],
            "tags": ["hipaa"],
        },
        {
            "text": "Disclosures of PHI require minimum-necessary justification (HIPAA Privacy Rule).",
            "severity": Severity.HIGH,
            "category": "data-protection",
            "keywords": ["phi disclosure", "minimum necessary"],
            "tags": ["hipaa"],
        },
    ),
}


def _spec_to_requirement(spec: Mapping[str, Any], *, source: str) -> PolicyRequirement:
    return PolicyRequirement(
        text=str(spec["text"]),
        severity=spec.get("severity", Severity.HIGH),
        category=str(spec.get("category", "general")),
        keywords=tuple(spec.get("keywords", ())),
        patterns=tuple(spec.get("patterns", ())),
        tags=tuple(spec.get("tags", ())),
        workflow_action=spec.get("workflow_action"),
        source=source,
        prod_only=bool(spec.get("prod_only", False)),
    )


class PolicyResearcher:
    """Derive concrete policy requirements from a pre-context.

    Deterministic by default. Pass an optional ``llm_provider`` (any object
    satisfying :class:`~acgs_lite.constitution.rule.RuleSynthesisProvider`) to
    enrich free-text custom requirements; the baseline never needs it.
    """

    def __init__(self, *, llm_provider: RuleSynthesisProvider | None = None) -> None:
        self._llm_provider = llm_provider

    def research(self, precontext: PreContext) -> ResearchReport:
        requirements: list[PolicyRequirement] = []
        sources: list[str] = []
        gaps: list[str] = []

        for area in precontext.risk_areas:
            spec = _RISK_AREA_KB.get(area)
            if spec is None:
                gaps.append(f"risk-area:{area} (no knowledge-base entry)")
                continue
            requirements.append(_spec_to_requirement(spec, source=f"risk-area:{area}"))
            sources.append(f"risk-area:{area}")

        for framework in precontext.frameworks:
            specs = _FRAMEWORK_KB.get(framework)
            if specs is None:
                gaps.append(f"framework:{framework} (no knowledge-base entry)")
                continue
            for spec in specs:
                requirements.append(_spec_to_requirement(spec, source=f"framework:{framework}"))
            sources.append(f"framework:{framework}")

        for custom in precontext.custom_requirements:
            requirements.append(self._synthesize_custom(custom))
            sources.append("custom")

        deduped = self._dedupe(requirements)
        return ResearchReport(
            domain=precontext.domain,
            requirements=tuple(deduped),
            sources=tuple(dict.fromkeys(sources)),
            gaps=tuple(gaps),
        )

    def _synthesize_custom(self, description: str) -> PolicyRequirement:
        # Reuse the existing offline heuristic (or the injected LLM provider) to
        # infer severity/category/keywords from free text.
        rule = Rule.from_description(description, llm_provider=self._llm_provider)
        return PolicyRequirement(
            text=rule.text,
            severity=rule.severity,
            category=rule.category,
            keywords=tuple(rule.keywords),
            patterns=tuple(rule.patterns),
            tags=("custom",),
            source="custom",
        )

    @staticmethod
    def _dedupe(requirements: list[PolicyRequirement]) -> list[PolicyRequirement]:
        """Merge requirements with identical normalized text.

        On collision: keep the highest severity, union keywords/patterns/tags, and
        OR the prod_only flag so the strictest reading wins.
        """
        by_fp: dict[str, PolicyRequirement] = {}
        order: list[str] = []
        for req in requirements:
            fp = req.fingerprint()
            existing = by_fp.get(fp)
            if existing is None:
                by_fp[fp] = req
                order.append(fp)
                continue
            severity = max(existing.severity, req.severity, key=_severity_rank)
            by_fp[fp] = PolicyRequirement(
                text=existing.text,
                severity=severity,
                category=existing.category,
                keywords=tuple(dict.fromkeys((*existing.keywords, *req.keywords))),
                patterns=tuple(dict.fromkeys((*existing.patterns, *req.patterns))),
                tags=tuple(dict.fromkeys((*existing.tags, *req.tags))),
                workflow_action=existing.workflow_action or req.workflow_action,
                source=existing.source,
                prod_only=existing.prod_only or req.prod_only,
            )
        return [by_fp[fp] for fp in order]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def _severity_rank(severity: Severity) -> int:
    return _SEVERITY_RANK[severity]


__all__ = ["PolicyRequirement", "PolicyResearcher", "ResearchReport"]
