"""UK AI Regulatory Principles Framework compliance module.

Implements the five cross-sector AI regulatory principles published in the
UK Government's AI Regulation White Paper (March 2023, CP 815) and carried
forward in the AI Opportunities Action Plan (January 2025). These principles
are operationalised by UK sector regulators (FCA, ICO, CMA, MHRA, Ofcom).

Principles covered:
- PRO-1: Safety, security and robustness
- PRO-2: Appropriate transparency and explainability
- PRO-3: Fairness
- PRO-4: Accountability and governance
- PRO-5: Contestability and redress

For each principle the module captures:
(a) the core obligation
(b) evidence/documentation obligations
(c) sector-specific extensions where significant

Key sector instruments cross-referenced:
- FCA/PRA AI Discussion Paper (DP5/22) — financial services
- ICO AI Auditing Framework — data protection
- MHRA Guidance on Software and AI as Medical Devices — healthcare AI
- Equality Act 2010 — protected characteristic fairness requirements

Reference: UK AI Regulatory Framework — AI White Paper (CP 815, 2023)
           UK AI Opportunities Action Plan (DSIT, January 2025)
Status:    Voluntary framework; mandatory compliance derives from sector
           regulators applying these principles through existing powers.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from acgs_lite.compliance.base import (
    ChecklistItem,
    ChecklistStatus,
    FrameworkAssessment,
)

# ---------------------------------------------------------------------------
# Checklist: (ref, requirement, legal_citation, acgs_lite_feature, blocking)
# ---------------------------------------------------------------------------
_UK_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # PRO-1 — Safety, security and robustness
    (
        "UK-AI PRO-1.1",
        "Identify and assess safety-related risks from the AI system throughout "
        "its lifecycle, including novel failure modes, adversarial attacks, and "
        "cascading harms.",
        "UK AI White Paper (CP 815, 2023), Principle 1 — Safety",
        "RiskClassifier — automated risk level classification and obligation mapping",
        True,
    ),
    (
        "UK-AI PRO-1.2",
        "Implement technical and organisational measures to ensure the AI system "
        "operates safely within defined boundaries, including fail-safe mechanisms "
        "and human override capability.",
        "UK AI White Paper (CP 815, 2023), Principle 1 — Safety",
        "GovernanceEngine — severity-based blocking with halt and override controls",
        True,
    ),
    (
        "UK-AI PRO-1.3",
        "Conduct security testing of the AI system against known attack vectors "
        "(adversarial inputs, data poisoning, model extraction, prompt injection) "
        "and remediate identified vulnerabilities.",
        "UK AI White Paper (CP 815, 2023), Principle 1 — Security",
        None,
        True,
    ),
    (
        "UK-AI PRO-1.4",
        "Ensure the AI system is robust to reasonably foreseeable misuse and "
        "distribution shift; test and document performance degradation at "
        "operational boundaries.",
        "UK AI White Paper (CP 815, 2023), Principle 1 — Robustness",
        "GovernanceEngine — anomaly detection flags out-of-distribution behaviour",
        True,
    ),
    # PRO-2 — Appropriate transparency and explainability
    (
        "UK-AI PRO-2.1",
        "Provide clear, accurate, and accessible information about what the AI "
        "system does, its intended use, known limitations, and the role of AI "
        "in any decision that affects an individual.",
        "UK AI White Paper (CP 815, 2023), Principle 2 — Transparency",
        "TransparencyDisclosure — system card with capabilities, limitations, and purpose",
        True,
    ),
    (
        "UK-AI PRO-2.2",
        "Where the AI system produces decisions or recommendations that affect "
        "individuals, provide meaningful explanations that those individuals "
        "can understand and act upon.",
        "UK AI White Paper (CP 815, 2023), Principle 2 — Explainability",
        "TransparencyDisclosure — decision-level explanation fields in system card",
        True,
    ),
    (
        "UK-AI PRO-2.3",
        "Ensure that AI system transparency obligations comply with applicable "
        "UK data protection law (UK GDPR Art.22; DPA 2018 Schedule 2 para.6) "
        "regarding automated decision-making.",
        "UK AI White Paper + UK GDPR Article 22 / DPA 2018",
        "HumanOversightGateway — ensures human review for automated high-impact decisions",
        True,
    ),
    (
        "UK-AI PRO-2.4",
        "Publish or make available technical documentation (model cards, system "
        "cards, or equivalent) proportionate to the risk and impact of the AI "
        "system.",
        "UK AI White Paper (CP 815, 2023), Principle 2",
        "TransparencyDisclosure — standardised machine-readable system card",
        False,
    ),
    # PRO-3 — Fairness
    (
        "UK-AI PRO-3.1",
        "Identify and assess risks of unfair outcomes or discrimination against "
        "protected groups under the Equality Act 2010 arising from the AI "
        "system's design or use.",
        "UK AI White Paper (CP 815, 2023), Principle 3 — Fairness; Equality Act 2010",
        "RiskClassifier — protected characteristic risk flags",
        True,
    ),
    (
        "UK-AI PRO-3.2",
        "Conduct disaggregated performance testing across demographic sub-groups "
        "relevant to the AI system's use case and document the results.",
        "UK AI White Paper (CP 815, 2023), Principle 3 — Fairness",
        None,
        True,
    ),
    (
        "UK-AI PRO-3.3",
        "Implement technical and procedural controls to detect, monitor, and "
        "mitigate unfair bias and disparate impact in AI system outputs.",
        "UK AI White Paper (CP 815, 2023), Principle 3 — Fairness",
        "GovernanceEngine — constitutional fairness rules block discriminatory outputs",
        True,
    ),
    # PRO-4 — Accountability and governance
    (
        "UK-AI PRO-4.1",
        "Designate a responsible person or function accountable for the AI "
        "system throughout its lifecycle, with documented authority and "
        "escalation pathways.",
        "UK AI White Paper (CP 815, 2023), Principle 4 — Accountability",
        "MACIEnforcer — role separation with designated accountability per action class",
        True,
    ),
    (
        "UK-AI PRO-4.2",
        "Maintain governance documentation covering the AI system's purpose, "
        "risks, controls, testing results, and any material changes throughout "
        "its lifecycle.",
        "UK AI White Paper (CP 815, 2023), Principle 4 — Governance",
        "AuditLog — lifecycle audit chain with tamper-evident governance records",
        True,
    ),
    (
        "UK-AI PRO-4.3",
        "Establish a process to review and update AI governance measures in "
        "response to incidents, regulatory changes, or significant model changes.",
        "UK AI White Paper (CP 815, 2023), Principle 4 — Governance",
        "GovernanceEngine — continuous lifecycle validation triggers review on changes",
        True,
    ),
    (
        "UK-AI PRO-4.4",
        "Comply with sector-specific regulatory obligations (FCA AI DP5/22, "
        "ICO AI auditing framework, MHRA SaMD guidance) as applicable to the "
        "deployment context.",
        "UK AI White Paper (CP 815, 2023), Principle 4; Sector regulators",
        None,
        False,  # blocking depends on sector
    ),
    # PRO-5 — Contestability and redress
    (
        "UK-AI PRO-5.1",
        "Provide individuals with the ability to contest AI-assisted decisions "
        "that significantly affect them, with a genuine and accessible process "
        "for review.",
        "UK AI White Paper (CP 815, 2023), Principle 5 — Contestability",
        "HumanOversightGateway — contestation pathway with human review capability",
        True,
    ),
    (
        "UK-AI PRO-5.2",
        "Ensure contestation processes are accessible, clearly communicated, "
        "and resolve disputes within a reasonable timeframe with documented "
        "outcomes.",
        "UK AI White Paper (CP 815, 2023), Principle 5 — Redress",
        "HumanOversightGateway — documented review flow with outcome recording",
        True,
    ),
    (
        "UK-AI PRO-5.3",
        "Where an AI decision is found to be erroneous or unfair following "
        "contestation, implement remediation and update controls to prevent "
        "recurrence.",
        "UK AI White Paper (CP 815, 2023), Principle 5 — Redress",
        "GovernanceEngine — policy update workflow with constitutional amendment",
        True,
    ),
    (
        "UK-AI PRO-5.4",
        "Log all contestation requests, their outcomes, and any system "
        "changes made in response, to demonstrate responsiveness to "
        "redress obligations.",
        "UK AI White Paper (CP 815, 2023), Principle 5",
        "AuditLog — contestation records with outcome and remediation fields",
        True,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "UK-AI PRO-1.1": (
        "acgs-lite RiskClassifier — automated lifecycle risk classification "
        "and obligation mapping covers safety risk identification"
    ),
    "UK-AI PRO-1.2": (
        "acgs-lite GovernanceEngine — severity-based blocking with halt "
        "and override controls implements safety and fail-safe mechanisms"
    ),
    "UK-AI PRO-1.4": (
        "acgs-lite GovernanceEngine — anomaly detection flags out-of-distribution "
        "behaviour and robustness boundary violations"
    ),
    "UK-AI PRO-2.1": (
        "acgs-lite TransparencyDisclosure — system card documents capabilities, "
        "limitations, intended purpose, and AI involvement notice"
    ),
    "UK-AI PRO-2.2": (
        "acgs-lite TransparencyDisclosure — decision-level explanation fields "
        "provide meaningful, actionable information to affected individuals"
    ),
    "UK-AI PRO-2.3": (
        "acgs-lite HumanOversightGateway — ensures human review for automated "
        "high-impact decisions, supporting UK GDPR Art.22 safeguards"
    ),
    "UK-AI PRO-2.4": (
        "acgs-lite TransparencyDisclosure — standardised machine-readable "
        "system card constitutes required technical documentation"
    ),
    "UK-AI PRO-3.1": (
        "acgs-lite RiskClassifier — protected characteristic risk flags "
        "identify potential Equality Act 2010 exposure"
    ),
    "UK-AI PRO-3.3": (
        "acgs-lite GovernanceEngine — constitutional fairness rules block "
        "discriminatory outputs and monitor for disparate impact"
    ),
    "UK-AI PRO-4.1": (
        "acgs-lite MACIEnforcer — role separation with designated accountability "
        "per action class and documented escalation paths"
    ),
    "UK-AI PRO-4.2": (
        "acgs-lite AuditLog — lifecycle audit chain with tamper-evident "
        "governance records covering purpose, risks, and changes"
    ),
    "UK-AI PRO-4.3": (
        "acgs-lite GovernanceEngine — continuous lifecycle validation triggers "
        "governance review on incidents or configuration changes"
    ),
    "UK-AI PRO-5.1": (
        "acgs-lite HumanOversightGateway — contestation pathway with genuine "
        "human review capability for affected individuals"
    ),
    "UK-AI PRO-5.2": (
        "acgs-lite HumanOversightGateway — documented review flow with "
        "outcome recording supports accessible redress process"
    ),
    "UK-AI PRO-5.3": (
        "acgs-lite GovernanceEngine — policy update workflow with constitutional "
        "amendment mechanism addresses remediation and recurrence prevention"
    ),
    "UK-AI PRO-5.4": (
        "acgs-lite AuditLog — contestation records with outcome and "
        "remediation fields logged tamper-evidently"
    ),
}


class UKAIFramework:
    """UK AI Regulatory Principles Framework compliance assessor.

    Covers all five UK cross-sector AI principles (safety, transparency,
    fairness, accountability, contestability) as set out in the AI White
    Paper (2023) and UK AI Opportunities Action Plan (2025).

    Status: Voluntary framework; sector regulators (FCA, ICO, CMA, MHRA,
    Ofcom) operationalise these principles through sector-specific powers.

    Usage::

        from acgs_lite.compliance.uk_ai_framework import UKAIFramework

        framework = UKAIFramework()
        assessment = framework.assess({
            "system_id": "my-system",
            "jurisdiction": "united_kingdom",
        })
    """

    framework_id: str = "uk_ai_framework"
    framework_name: str = "UK AI Regulatory Principles Framework (AI White Paper, 2023)"
    jurisdiction: str = "United Kingdom"
    status: str = "voluntary"
    enforcement_date: str | None = None

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate UK AI Framework checklist items."""
        return [
            ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            for ref, req, citation, feature, blocking in _UK_ITEMS
        ]

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full UK AI Framework compliance assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(
    fw: UKAIFramework,
    checklist: list[ChecklistItem],
) -> FrameworkAssessment:
    total = len(checklist)
    compliant = sum(
        1
        for item in checklist
        if item.status in (ChecklistStatus.COMPLIANT, ChecklistStatus.NOT_APPLICABLE)
    )
    acgs_covered = sum(1 for item in checklist if item.acgs_lite_feature is not None)
    gaps = tuple(
        f"{item.ref}: {item.requirement[:120]}"
        for item in checklist
        if item.status not in (ChecklistStatus.COMPLIANT, ChecklistStatus.NOT_APPLICABLE)
        and item.blocking
    )
    recommendations = _generate_recommendations(checklist)
    return FrameworkAssessment(
        framework_id=fw.framework_id,
        framework_name=fw.framework_name,
        compliance_score=round(compliant / total, 4) if total else 1.0,
        items=tuple(item.to_dict() for item in checklist),
        gaps=gaps,
        acgs_lite_coverage=round(acgs_covered / total, 4) if total else 0.0,
        recommendations=recommendations,
        assessed_at=datetime.now(timezone.utc).isoformat(),
    )


def _generate_recommendations(checklist: list[ChecklistItem]) -> tuple[str, ...]:
    recs: list[str] = []
    for item in checklist:
        if item.status == ChecklistStatus.PENDING and item.blocking:
            if "PRO-1" in item.ref:
                recs.append(
                    f"{item.ref}: Address safety and security obligations. "
                    f"FCA/PRA, MHRA, and ICO expect PRO-1 evidence in AI audits."
                )
            elif "PRO-2" in item.ref:
                recs.append(
                    f"{item.ref}: Produce transparency documentation and "
                    f"explainability measures proportionate to decision impact."
                )
            elif "PRO-3" in item.ref:
                recs.append(
                    f"{item.ref}: Conduct disaggregated bias testing and "
                    f"implement Equality Act 2010 compliant fairness controls."
                )
            elif "PRO-4" in item.ref:
                recs.append(
                    f"{item.ref}: Establish accountability structure and "
                    f"maintain governance documentation for regulator review."
                )
            elif "PRO-5" in item.ref:
                recs.append(
                    f"{item.ref}: Implement accessible contestation and "
                    f"redress mechanisms; log all challenge outcomes."
                )
    return tuple(recs)
