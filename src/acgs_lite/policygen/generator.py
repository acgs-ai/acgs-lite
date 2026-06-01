# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Adaptive policy (constitution) generation.

:class:`AdaptivePolicyGenerator` turns a researched set of requirements into a
valid acgs-lite constitution YAML, *adapting* the output to the pre-context:

- **Severity** escalates with the domain risk level (a HIGH-risk domain promotes
  HIGH rules to CRITICAL; an UNACCEPTABLE domain escalates everything one step).
- **Enforcement action** hardens in production (blocking CRITICAL rules become
  ``block_and_notify``).
- **Activation conditions** gate production-only requirements on ``env=production``.
- **Permission ceiling** tightens with risk (``permissive`` -> ``standard`` ->
  ``strict``).

The generated constitution is assembled with the existing ``ConstitutionBuilder``,
serialized with ``Constitution.to_yaml()``, and verified to round-trip through
``Constitution.from_yaml_str`` before it is returned -- a generated policy that
cannot be parsed back is a generation failure, not a silent artifact.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acgs_lite.constitution import Constitution, Severity
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.constitution.templates import ConstitutionBuilder
from acgs_lite.policygen.context import DomainRiskLevel, PreContext
from acgs_lite.policygen.research import PolicyRequirement, PolicyResearcher, ResearchReport

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)

_CEILING_BY_RISK: dict[DomainRiskLevel, str] = {
    DomainRiskLevel.MINIMAL: "permissive",
    DomainRiskLevel.LIMITED: "standard",
    DomainRiskLevel.HIGH: "strict",
    DomainRiskLevel.UNACCEPTABLE: "strict",
}

_PRIORITY_BY_SEVERITY: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 0,
}


def _escalate(severity: Severity, steps: int) -> Severity:
    idx = min(len(_SEVERITY_ORDER) - 1, _SEVERITY_ORDER.index(severity) + steps)
    return _SEVERITY_ORDER[idx]


def _domain_prefix(domain: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9]+", domain)
    return tokens[0][:6].upper() if tokens else "POL"


def _category_code(category: str) -> str:
    letters = re.sub(r"[^a-zA-Z]", "", category).upper()
    return letters[:3] or "GEN"


@dataclass(slots=True, frozen=True)
class GeneratedPolicy:
    """The result of adaptive policy generation."""

    constitution: Constitution
    yaml: str
    report: ResearchReport
    rationale: tuple[str, ...] = ()
    summary: dict[str, Any] = field(default_factory=dict)

    def write(self, path: str | Path) -> Path:
        """Write the generated YAML to ``path`` and return the resolved path."""
        target = Path(path)
        target.write_text(self.yaml, encoding="utf-8")
        return target


class AdaptivePolicyGenerator:
    """Generate an adaptive constitution YAML from a pre-context."""

    def __init__(self, *, researcher: PolicyResearcher | None = None) -> None:
        self._researcher = researcher or PolicyResearcher()

    def generate(self, precontext: PreContext) -> GeneratedPolicy:
        """Research, adapt, build, serialize, and verify a policy for ``precontext``."""
        report = self._researcher.research(precontext)
        is_prod = precontext.is_production()
        prefix = _domain_prefix(precontext.domain)

        builder = ConstitutionBuilder(
            name=f"{prefix.lower()}-governance",
            version="1.0.0",
            description=(
                precontext.description
                or f"Adaptively generated governance policy for {precontext.domain}."
            ),
        )
        rationale: list[str] = []
        for counter, req in enumerate(report.requirements, start=1):
            severity = self._adapt_severity(req.severity, precontext.risk_level)
            workflow = self._adapt_workflow(req, severity, is_prod=is_prod)
            rule_id = f"{prefix}-{_category_code(req.category)}-{counter:03d}"
            condition = {"env": "production"} if (req.prod_only and is_prod) else {}
            tags = tuple(dict.fromkeys((*req.tags, *((precontext.domain.lower(),)))))
            builder.add_rule(
                rule_id,
                req.text,
                severity=severity,
                keywords=list(req.keywords),
                patterns=list(req.patterns),
                category=req.category,
                workflow_action=workflow,
                tags=list(tags),
                priority=_PRIORITY_BY_SEVERITY[severity],
                condition=condition,
                provenance=[req.source] if req.source else [],
            )
            rationale.append(
                f"{rule_id}: {req.source or 'custom'} -> {severity.value}"
                + (" (prod-gated)" if condition else "")
            )

        constitution = self._finalize(builder, precontext)
        yaml_text = constitution.to_yaml()
        # Fail-closed on the artifact: a policy that cannot be parsed back is invalid.
        reparsed = Constitution.from_yaml_str(yaml_text)
        if reparsed.hash != constitution.hash:
            raise ValueError(
                f"generated policy YAML did not round-trip: {constitution.hash} != {reparsed.hash}"
            )

        return GeneratedPolicy(
            constitution=constitution,
            yaml=yaml_text,
            report=report,
            rationale=tuple(rationale),
            summary=self._summary(constitution, precontext),
        )

    def generate_yaml(self, precontext: PreContext) -> str:
        """Convenience: return only the YAML string."""
        return self.generate(precontext).yaml

    def write_yaml(self, precontext: PreContext, path: str | Path) -> Path:
        """Automate end-to-end: generate and write the YAML to ``path``."""
        return self.generate(precontext).write(path)

    # -- adaptivity ------------------------------------------------------------------

    def _adapt_severity(self, severity: Severity, risk_level: DomainRiskLevel) -> Severity:
        if risk_level is DomainRiskLevel.UNACCEPTABLE:
            return _escalate(severity, 1)
        if risk_level is DomainRiskLevel.HIGH and severity is Severity.HIGH:
            return Severity.CRITICAL
        return severity

    def _adapt_workflow(
        self, req: PolicyRequirement, severity: Severity, *, is_prod: bool
    ) -> ViolationAction:
        if req.workflow_action is not None:
            return req.workflow_action
        if severity.blocks():
            if is_prod and severity is Severity.CRITICAL:
                return ViolationAction.BLOCK_AND_NOTIFY
            return ViolationAction.BLOCK
        return ViolationAction.WARN

    def _finalize(self, builder: ConstitutionBuilder, precontext: PreContext) -> Constitution:
        base = builder.metadata(
            generated_by="acgs_lite.policygen.AdaptivePolicyGenerator",
            domain=precontext.domain,
            risk_level=precontext.risk_level.value,
            environment=precontext.environment,
            frameworks=list(precontext.frameworks),
        ).build()
        ceiling = _CEILING_BY_RISK[precontext.risk_level]
        if ceiling == "standard":
            return base
        # ConstitutionBuilder.build() does not set permission_ceiling; reconstruct
        # with the adaptive ceiling while preserving the assembled rules + metadata.
        return Constitution(
            name=base.name,
            version=base.version,
            description=base.description,
            rules=list(base.rules),
            metadata=dict(base.metadata),
            permission_ceiling=ceiling,
        )

    def _summary(self, constitution: Constitution, precontext: PreContext) -> dict[str, Any]:
        by_severity: dict[str, int] = {}
        for rule in constitution.rules:
            by_severity[rule.severity.value] = by_severity.get(rule.severity.value, 0) + 1
        return {
            "domain": precontext.domain,
            "rule_count": len(constitution.rules),
            "by_severity": by_severity,
            "permission_ceiling": constitution.permission_ceiling,
            "risk_level": precontext.risk_level.value,
            "environment": precontext.environment,
            "frameworks": list(precontext.frameworks),
            "constitutional_hash": constitution.hash,
        }


__all__ = ["AdaptivePolicyGenerator", "GeneratedPolicy"]
