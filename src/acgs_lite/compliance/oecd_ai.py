"""OECD AI Principles compliance module.

Implements the five OECD AI Principles and five policy recommendations
adopted by the OECD Council in May 2019. The principles serve as the
international baseline for responsible AI and have been endorsed by
46 countries including all G7 and G20 members.

Reference: OECD Recommendation on Artificial Intelligence (OECD/LEGAL/0449)
Adopted: May 22, 2019 (updated May 2024)
Endorsed by 46 countries + the European Union.

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

_OECD_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # Principle 1: Inclusive growth, sustainable development, and well-being
    (
        "OECD 1.1",
        "AI systems should benefit people and the planet by driving inclusive "
        "growth, sustainable development, and well-being. Stakeholders should "
        "proactively engage in responsible stewardship of trustworthy AI.",
        "OECD/LEGAL/0449, Principle 1.1",
        None,
        False,
    ),
    (
        "OECD 1.2",
        "Consider the broader societal impacts of AI systems including effects "
        "on employment, inequality, and access to essential services.",
        "OECD/LEGAL/0449, Principle 1.1",
        None,
        False,
    ),
    # Principle 2: Human-centred values and fairness
    (
        "OECD 2.1",
        "AI systems should respect the rule of law, human rights, democratic "
        "values, and diversity. They should include appropriate safeguards "
        "to ensure a fair and just society.",
        "OECD/LEGAL/0449, Principle 1.2(a)",
        "Constitution — governance rules encode human rights safeguards",
        True,
    ),
    (
        "OECD 2.2",
        "AI actors should respect and promote fairness and non-discrimination "
        "throughout the AI system lifecycle.",
        "OECD/LEGAL/0449, Principle 1.2(a)",
        "GovernanceEngine — anti-discrimination rules in constitution",
        True,
    ),
    (
        "OECD 2.3",
        "AI actors should implement mechanisms for human determination to "
        "ensure outcomes respect human autonomy and dignity.",
        "OECD/LEGAL/0449, Principle 1.2(b)",
        "HumanOversightGateway — human-in-the-loop decision gates",
        True,
    ),
    # Principle 3: Transparency and explainability
    (
        "OECD 3.1",
        "AI actors should commit to transparency and responsible disclosure "
        "regarding AI systems. Provide meaningful information appropriate to "
        "the context to foster general understanding of AI systems.",
        "OECD/LEGAL/0449, Principle 1.3(i)",
        "TransparencyDisclosure — system cards with capabilities and limits",
        True,
    ),
    (
        "OECD 3.2",
        "Enable people affected by an AI system to understand the outcome "
        "and to challenge it. Provide explanations that are timely and "
        "accessible.",
        "OECD/LEGAL/0449, Principle 1.3(ii)",
        "HumanOversightGateway — contestation mechanism with audit trail",
        True,
    ),
    (
        "OECD 3.3",
        "Provide information about the factors, logic, and techniques that "
        "led to the AI system's output, at a level appropriate to the "
        "context and consistent with the state of art.",
        "OECD/LEGAL/0449, Principle 1.3(iii)",
        "AuditLog — per-decision audit trail with decision factors",
        True,
    ),
    # Principle 4: Robustness, security, and safety
    (
        "OECD 4.1",
        "AI systems should be robust, secure, and safe throughout their "
        "lifecycle. They should not pose unreasonable safety risks and should "
        "continuously manage and mitigate risks.",
        "OECD/LEGAL/0449, Principle 1.4(a)",
        "GovernanceEngine — continuous validation against constitutional rules",
        True,
    ),
    (
        "OECD 4.2",
        "Ensure traceability of AI system decisions and enable analysis of "
        "outcomes. Apply risk management processes that address risks related "
        "to AI systems.",
        "OECD/LEGAL/0449, Principle 1.4(b)",
        "AuditLog + RiskClassifier — decision traceability and risk management",
        True,
    ),
    # Principle 5: Accountability
    (
        "OECD 5.1",
        "AI actors should be accountable for the proper functioning of AI "
        "systems and for the respect of the above principles. Mechanisms "
        "should ensure accountability consistent with their roles.",
        "OECD/LEGAL/0449, Principle 1.5",
        "MACIEnforcer — role-based accountability with separation of duties",
        True,
    ),
    (
        "OECD 5.2",
        "AI actors should provide comprehensive records to enable audit "
        "and accountability assessment, including records of AI system design, "
        "development, deployment, and operational decisions.",
        "OECD/LEGAL/0449, Principle 1.5",
        "AuditLog — tamper-evident cryptographic audit chain",
        True,
    ),
    # Policy Recommendations
    (
        "OECD PR.1",
        "Invest in AI research and development that fosters innovation in "
        "trustworthy AI, prioritizing challenging technical issues related to "
        "AI trustworthiness.",
        "OECD/LEGAL/0449, Policy Recommendation 2.1",
        None,
        False,
    ),
    (
        "OECD PR.2",
        "Foster a digital ecosystem for trustworthy AI including data "
        "infrastructure, technology access, and appropriate mechanisms for "
        "data sharing while protecting privacy.",
        "OECD/LEGAL/0449, Policy Recommendation 2.2",
        None,
        False,
    ),
    (
        "OECD PR.3",
        "Ensure a policy environment that opens the way to deployment of "
        "trustworthy AI systems, reviewing and adapting regulatory frameworks "
        "as needed.",
        "OECD/LEGAL/0449, Policy Recommendation 2.3",
        None,
        False,
    ),
]

_ACGS_LITE_MAP: dict[str, str] = {
    "OECD 2.1": (
        "acgs-lite Constitution — governance rules encode human rights "
        "and democratic values as enforceable constraints"
    ),
    "OECD 2.2": (
        "acgs-lite GovernanceEngine — fairness and non-discrimination "
        "rules enforced across the AI system lifecycle"
    ),
    "OECD 2.3": (
        "acgs-lite HumanOversightGateway — configurable HITL gates "
        "ensuring human determination in high-impact decisions"
    ),
    "OECD 3.1": (
        "acgs-lite TransparencyDisclosure — generates system cards "
        "with capabilities, limitations, and intended use documentation"
    ),
    "OECD 3.2": (
        "acgs-lite HumanOversightGateway — contestation mechanism "
        "with human review and full audit trail"
    ),
    "OECD 3.3": (
        "acgs-lite AuditLog — per-decision audit trail documenting "
        "decision factors and governance logic"
    ),
    "OECD 4.1": (
        "acgs-lite GovernanceEngine — continuous validation of every "
        "agent action against constitutional safety rules"
    ),
    "OECD 4.2": (
        "acgs-lite AuditLog + RiskClassifier — decision traceability "
        "via audit chain plus risk management via classification"
    ),
    "OECD 5.1": (
        "acgs-lite MACIEnforcer — role-based accountability with "
        "separation of duties (proposer/validator/executor)"
    ),
    "OECD 5.2": (
        "acgs-lite AuditLog — tamper-evident SHA-256 chained audit "
        "trail for comprehensive accountability records"
    ),
}


class OECDAIFramework:
    """OECD AI Principles compliance assessor.

    Covers the five OECD AI Principles (inclusive growth, human-centred
    values, transparency, robustness, accountability) and five policy
    recommendations. Serves as the international baseline for responsible
    AI, endorsed by 46 countries.

    Status: Adopted May 2019 (voluntary but widely referenced in
    national legislation including the EU AI Act and US EO 14110).

    Usage::

        from acgs_lite.compliance.oecd_ai import OECDAIFramework

        framework = OECDAIFramework()
        assessment = framework.assess({"system_id": "my-system"})
    """

    framework_id: str = "oecd_ai"
    framework_name: str = "OECD AI Principles (OECD/LEGAL/0449)"
    jurisdiction: str = "International (46 countries)"
    status: str = "voluntary"
    enforcement_date: str | None = None

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate OECD AI Principles checklist items."""
        return [
            ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            for ref, req, citation, feature, blocking in _OECD_ITEMS
        ]

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full OECD AI Principles assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)

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

        recs: list[str] = []
        for item in checklist:
            if item.status == ChecklistStatus.PENDING and item.blocking:
                recs.append(
                    f"{item.ref}: Align with OECD principle. Referenced by "
                    f"46+ national AI strategies and regulations."
                )

        return FrameworkAssessment(
            framework_id=self.framework_id,
            framework_name=self.framework_name,
            compliance_score=round(compliant / total, 4) if total else 1.0,
            items=tuple(item.to_dict() for item in checklist),
            gaps=gaps,
            acgs_lite_coverage=round(acgs_covered / total, 4) if total else 0.0,
            recommendations=tuple(recs),
            assessed_at=datetime.now(timezone.utc).isoformat(),
        )
