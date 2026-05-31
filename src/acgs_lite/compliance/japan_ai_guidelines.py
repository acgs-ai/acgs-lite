"""Japan AI Guidelines for Business compliance module.

Implements the common guiding principles of Japan's "AI Guidelines for
Business" (AI事業者ガイドライン), jointly published by the Ministry of
Economy, Trade and Industry (METI) and the Ministry of Internal Affairs and
Communications (MIC). The Guidelines consolidate Japan's earlier "Social
Principles of Human-Centric AI", "AI R&D Guidelines", and "AI Utilization
Guidelines" into a single soft-law framework for AI developers, providers,
and business users.

Ten common guiding principles covered:
- JP1  Human-centric — respect human dignity, autonomy, and rights
- JP2  Safety — avoid harm to life, body, property, and the environment
- JP3  Fairness — prevent unfair bias and discrimination
- JP4  Privacy protection — respect and protect personal data and privacy
- JP5  Security — ensure confidentiality, integrity, and availability
- JP6  Transparency — provide appropriate information to stakeholders
- JP7  Accountability — fulfil accountability to stakeholders
- JP8  Education / literacy — promote AI literacy and education
- JP9  Fair competition — maintain a fair and open competitive environment
- JP10 Innovation — promote innovation while managing risk

These principles are voluntary soft law in Japan, but are referenced by
Japanese regulators, the Hiroshima AI Process / G7 Code of Conduct, and the
OECD AI Principles, and are widely adopted as a baseline by Japanese
enterprises deploying AI.

Reference: METI / MIC — "AI Guidelines for Business" Version 1.0 (April 2024),
common guiding principles, Part 2.

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
_JP_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # JP1 — Human-centric
    (
        "JP-AI JP1.1",
        "Ensure AI systems respect human dignity and individual autonomy, and "
        "do not unduly manipulate human decision-making or infringe "
        "fundamental human rights.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 1 (Human-centric)",
        "Constitution — human-centric constraints encoded as enforceable rules",
        True,
    ),
    (
        "JP-AI JP1.2",
        "Provide meaningful human oversight for AI-assisted decisions that "
        "significantly affect individuals, so that humans retain ultimate "
        "control over consequential outcomes.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 1 (Human-centric)",
        "HumanOversightGateway — human-in-the-loop control over consequential actions",
        True,
    ),
    # JP2 — Safety
    (
        "JP-AI JP2.1",
        "Take measures so that AI systems do not harm the life, body, or "
        "property of stakeholders, nor the environment, throughout the AI "
        "lifecycle.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 2 (Safety)",
        "GovernanceEngine — pre-action validation blocks unsafe or harmful actions",
        True,
    ),
    (
        "JP-AI JP2.2",
        "Establish the ability to suspend, roll back, or stop AI operation "
        "where safety risks emerge that cannot be adequately controlled.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 2 (Safety)",
        "GovernanceEngine — halt capability and severity-based action blocking",
        True,
    ),
    # JP3 — Fairness
    (
        "JP-AI JP3.1",
        "Take measures to prevent unfair bias and discrimination against "
        "individuals or groups in AI inputs, models, and outputs, considering "
        "protected attributes where relevant.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 3 (Fairness)",
        None,
        True,
    ),
    (
        "JP-AI JP3.2",
        "Document and review the criteria used by AI systems for consequential "
        "decisions so that unfair or unjustified discriminatory effects can be "
        "identified and corrected.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 3 (Fairness)",
        "AuditLog — decision-criteria records support fairness review and correction",
        True,
    ),
    # JP4 — Privacy protection
    (
        "JP-AI JP4.1",
        "Respect and protect the privacy of stakeholders and handle personal "
        "data lawfully and appropriately, consistent with Japan's Act on the "
        "Protection of Personal Information (APPI).",
        "METI/MIC AI Guidelines for Business v1.0, Principle 4 (Privacy protection)",
        None,
        True,
    ),
    # JP5 — Security
    (
        "JP-AI JP5.1",
        "Ensure the confidentiality, integrity, and availability of AI systems "
        "and their data, and implement measures against unauthorised access, "
        "tampering, and adversarial attacks.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 5 (Security)",
        "AuditLog — tamper-evident audit chain protects record integrity",
        True,
    ),
    # JP6 — Transparency
    (
        "JP-AI JP6.1",
        "Provide stakeholders with appropriate information about the AI system, "
        "including notice that AI is in use and a plain-language description of "
        "its purpose and intended use.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 6 (Transparency)",
        "TransparencyDisclosure — AI-use notice and plain-language system card",
        True,
    ),
    (
        "JP-AI JP6.2",
        "Provide explanations of AI outputs and the main factors influencing "
        "them at a level of detail appropriate to the impact on stakeholders.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 6 (Transparency)",
        "TransparencyDisclosure — system card with decision factors and logic",
        True,
    ),
    # JP7 — Accountability
    (
        "JP-AI JP7.1",
        "Establish clear roles and responsibilities across AI developers, "
        "providers, and business users, with a designated accountable person "
        "and defined escalation paths.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 7 (Accountability)",
        "MACIEnforcer — proposer/validator/executor role separation with accountability",
        True,
    ),
    (
        "JP-AI JP7.2",
        "Maintain records that document the design, operation, and governance "
        "of the AI system sufficient to demonstrate accountability to "
        "stakeholders and regulators.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 7 (Accountability)",
        "AuditLog — lifecycle audit chain with tamper-evident records",
        True,
    ),
    (
        "JP-AI JP7.3",
        "Establish accessible mechanisms for stakeholders to raise concerns, "
        "provide feedback, and seek redress for AI-related harms, with human "
        "review of disputed outcomes.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 7 (Accountability)",
        "HumanOversightGateway — contestation pathway with human review and override",
        True,
    ),
    # JP8 — Education / literacy
    (
        "JP-AI JP8.1",
        "Promote AI literacy and provide education and training so that "
        "personnel involved with the AI system understand its capabilities, "
        "limitations, and governance obligations.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 8 (Education/literacy)",
        None,
        False,
    ),
    # JP9 — Fair competition
    (
        "JP-AI JP9.1",
        "Use AI in a manner that maintains a fair and open competitive "
        "environment and does not engage in anti-competitive practices or "
        "abuse of market power through AI.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 9 (Fair competition)",
        None,
        False,
    ),
    # JP10 — Innovation
    (
        "JP-AI JP10.1",
        "Promote innovation and the beneficial use of AI while applying "
        "risk-proportionate governance so that risk management does not "
        "unnecessarily impede responsible innovation.",
        "METI/MIC AI Guidelines for Business v1.0, Principle 10 (Innovation)",
        "RiskClassifier — risk-proportionate governance scales controls to assessed risk",
        False,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "JP-AI JP1.1": (
        "acgs-lite Constitution — human-centric constraints encoded as "
        "version-controlled, enforceable governance rules"
    ),
    "JP-AI JP1.2": (
        "acgs-lite HumanOversightGateway — human-in-the-loop control retains "
        "human authority over consequential AI-assisted decisions"
    ),
    "JP-AI JP2.1": (
        "acgs-lite GovernanceEngine — pre-action constitutional validation "
        "blocks unsafe or harmful actions across the lifecycle"
    ),
    "JP-AI JP2.2": (
        "acgs-lite GovernanceEngine — halt capability and severity-based "
        "action blocking enable suspension when safety risks emerge"
    ),
    "JP-AI JP3.2": (
        "acgs-lite AuditLog — decision-criteria records support review and "
        "correction of unfair or discriminatory effects"
    ),
    "JP-AI JP5.1": (
        "acgs-lite AuditLog — tamper-evident audit chain protects the "
        "integrity of governance and decision records"
    ),
    "JP-AI JP6.1": (
        "acgs-lite TransparencyDisclosure — AI-use notice and plain-language "
        "system card inform stakeholders of purpose and intended use"
    ),
    "JP-AI JP6.2": (
        "acgs-lite TransparencyDisclosure — system card includes decision "
        "factors and logic at impact-appropriate specificity"
    ),
    "JP-AI JP7.1": (
        "acgs-lite MACIEnforcer — enforces proposer/validator/executor role "
        "separation with clear accountability and escalation paths"
    ),
    "JP-AI JP7.2": (
        "acgs-lite AuditLog — lifecycle audit chain with tamper-evident "
        "records demonstrates accountability to stakeholders"
    ),
    "JP-AI JP7.3": (
        "acgs-lite HumanOversightGateway — contestation pathway with human "
        "review and override enables redress for disputed outcomes"
    ),
    "JP-AI JP10.1": (
        "acgs-lite RiskClassifier — risk-proportionate governance scales "
        "controls to assessed risk, supporting responsible innovation"
    ),
}


class JapanAIGuidelinesFramework:
    """Japan AI Guidelines for Business (METI/MIC) compliance assessor.

    Covers the ten common guiding principles of Japan's "AI Guidelines for
    Business": human-centric, safety, fairness, privacy protection, security,
    transparency, accountability, education/literacy, fair competition, and
    innovation.

    Status: Voluntary soft-law framework; referenced by Japanese regulators,
    the Hiroshima AI Process / G7 Code of Conduct, and OECD AI Principles.

    Usage::

        from acgs_lite.compliance.japan_ai_guidelines import (
            JapanAIGuidelinesFramework,
        )

        framework = JapanAIGuidelinesFramework()
        assessment = framework.assess({
            "system_id": "my-system",
            "jurisdiction": "japan",
        })
    """

    framework_id: str = "japan_ai_guidelines"
    framework_name: str = "Japan AI Guidelines for Business (METI/MIC)"
    jurisdiction: str = "Japan"
    status: str = "voluntary"
    enforcement_date: str | None = None

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate Japan AI Guidelines checklist items."""
        return [
            ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            for ref, req, citation, feature, blocking in _JP_ITEMS
        ]

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full Japan AI Guidelines compliance assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(
    fw: JapanAIGuidelinesFramework,
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
            if "JP3" in item.ref:
                recs.append(
                    f"{item.ref}: Conduct bias and fairness testing and document "
                    f"decision criteria per Japan AI Guidelines Principle 3 (Fairness)."
                )
            elif "JP4" in item.ref:
                recs.append(
                    f"{item.ref}: Implement privacy controls aligned with Japan's "
                    f"APPI per Japan AI Guidelines Principle 4 (Privacy protection)."
                )
            elif "JP2" in item.ref:
                recs.append(
                    f"{item.ref}: Implement safety measures and suspension controls "
                    f"per Japan AI Guidelines Principle 2 (Safety)."
                )
            else:
                recs.append(
                    f"{item.ref}: Address this requirement per the Japan AI "
                    f"Guidelines for Business common guiding principles."
                )
    return tuple(recs)
