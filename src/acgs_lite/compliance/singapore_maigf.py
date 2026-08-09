"""Singapore Model AI Governance Framework v2 (MAIGF) compliance module.

Implements the four principles and twelve practices of Singapore's Model AI
Governance Framework, Second Edition (2020), published by the Personal Data
Protection Commission (PDPC) and Infocomm Media Development Authority (IMDA).

Principles and practices covered:
- Internal Governance Structures and Measures
  - Roles, responsibilities, and accountability for AI governance
  - The human-AI decision-making model (fully automated / human-in-the-loop /
    human-on-the-loop)
  - Human review for decisions that significantly affect individuals
- Human Involvement in AI-Augmented Decision-Making
  - Risk-based determination of the appropriate degree of human involvement
  - Risk-level classification (probability × impact)
  - Oversight requirements commensurate with risk level
- Operations Management
  - Model testing, fairness, and reproducibility
  - Data governance and lifecycle management
  - Vendor / third-party risk management
  - Incident and anomaly response procedures
- Stakeholder Interaction and Communication
  - Disclosure of AI involvement to customers and users
  - Transparency of decision factors
  - Feedback, complaint, and redress mechanisms

The MAIGF is a voluntary framework but is referenced in MAS (Monetary
Authority of Singapore) guidance, Singapore courts, and ASEAN AI governance
frameworks.

NOTE ON REFERENCES: the PDPC's Second Edition document could not be quickly
verified for its exact internal clause-numbering scheme (e.g. whether
individual practices are labelled "1.1(a)"-style). To avoid citing invented
sub-clause numbers, item refs below use a descriptive
"MAIGF — <Principle>: <topic>" form instead of numbered citations. The four
top-level principle names themselves are well-corroborated across independent
public summaries of the framework.

Reference: Personal Data Protection Commission Singapore — Model AI
Governance Framework, Second Edition (2020).

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
_MAIGF_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # Principle — Internal Governance
    (
        "MAIGF — Internal Governance: roles & accountability",
        "Establish clear roles and responsibilities for AI governance, "
        "including a designated senior accountable person (AI owner or "
        "equivalent) and defined escalation paths.",
        "PDPC MAIGF v2 — Internal Governance Structures and Measures",
        "MACIEnforcer — role separation (proposer/validator/executor) with accountability",
        True,
    ),
    (
        "MAIGF — Internal Governance: documented AI policies",
        "Document AI governance policies covering model selection, testing, "
        "deployment, monitoring, and decommissioning, with board/senior "
        "management sign-off.",
        "PDPC MAIGF v2 — Internal Governance Structures and Measures",
        "Constitution — board-approved governance policies as version-controlled code",
        True,
    ),
    (
        "MAIGF — Internal Governance: staff training",
        "Conduct staff training on AI ethics, data governance, and the "
        "organisation's AI governance policies.",
        "PDPC MAIGF v2 — Internal Governance Structures and Measures",
        None,
        False,
    ),
    (
        "MAIGF — Internal Governance: human-AI decision model",
        "Define and document how AI systems interact with human decision-makers: "
        "fully automated, human-in-the-loop (advisory), or human-on-the-loop "
        "(override-only) models.",
        "PDPC MAIGF v2 — Internal Governance Structures and Measures",
        "HumanOversightGateway — configurable HITL/human-on-the-loop with documented modes",
        True,
    ),
    (
        "MAIGF — Internal Governance: human review for significant decisions",
        "For decisions that significantly affect individuals, ensure that a "
        "human with appropriate authority reviews AI output before action is "
        "taken or within a defined correction window.",
        "PDPC MAIGF v2 — Internal Governance Structures and Measures",
        "HumanOversightGateway — mandatory human review gate for high-impact actions",
        True,
    ),
    # Principle — Human Involvement in AI-Augmented Decision-Making
    (
        "MAIGF — Human Involvement: risk-based oversight determination",
        "Determine the appropriate degree of human involvement based on "
        "quantitative risk assessment: consider probability of error, impact "
        "on individuals, reversibility, and recourse available.",
        "PDPC MAIGF v2 — Human Involvement in AI-Augmented Decision-Making",
        "RiskClassifier — probability × impact scoring determines required oversight level",
        True,
    ),
    (
        "MAIGF — Human Involvement: risk-level classification",
        "Classify the AI decision scenario into a risk level (high / medium / "
        "low) based on the product of decision error probability and impact "
        "severity on individuals.",
        "PDPC MAIGF v2 — Human Involvement in AI-Augmented Decision-Making",
        "RiskClassifier — automated risk tier classification with configurable thresholds",
        True,
    ),
    (
        "MAIGF — Human Involvement: oversight commensurate with risk",
        "Apply minimum human oversight requirements commensurate with risk "
        "level: high-risk decisions require human approval; medium-risk "
        "require human review within defined window.",
        "PDPC MAIGF v2 — Human Involvement in AI-Augmented Decision-Making",
        "GovernanceEngine — severity-based escalation with configurable approval gates",
        True,
    ),
    # Principle — Operations Management
    (
        "MAIGF — Operations Management: model testing & fairness",
        "Test AI models for performance, accuracy, and fairness before "
        "deployment, including testing across demographic sub-groups where "
        "relevant.",
        "PDPC MAIGF v2 — Operations Management",
        None,
        True,
    ),
    (
        "MAIGF — Operations Management: version control & rollback",
        "Implement version control for AI models and training data to enable "
        "reproducibility and rollback to known-good states.",
        "PDPC MAIGF v2 — Operations Management",
        "AuditLog — versioned audit chain supports model lineage and rollback",
        True,
    ),
    (
        "MAIGF — Operations Management: ongoing performance monitoring",
        "Monitor AI model performance on an ongoing basis in production, "
        "including detecting drift, degradation, and changes in input data "
        "distributions.",
        "PDPC MAIGF v2 — Operations Management",
        "GovernanceEngine — continuous monitoring detects performance anomalies",
        True,
    ),
    (
        "MAIGF — Operations Management: data governance",
        "Establish data governance practices covering data collection consent "
        "or legal basis, data quality, data lineage, and documentation of "
        "training data sources.",
        "PDPC MAIGF v2 — Operations Management",
        None,
        True,
    ),
    (
        "MAIGF — Operations Management: data lifecycle management",
        "Implement data lifecycle management including secure deletion of "
        "training data when no longer needed and appropriate controls for "
        "personal data used in AI.",
        "PDPC MAIGF v2 — Operations Management",
        None,
        True,
    ),
    (
        "MAIGF — Operations Management: vendor/third-party risk",
        "Assess and manage risks from AI vendors and third-party models "
        "used in the system, including review of vendor governance practices "
        "and data handling.",
        "PDPC MAIGF v2 — Operations Management",
        None,
        True,
    ),
    (
        "MAIGF — Operations Management: incident response procedures",
        "Establish documented procedures for detecting, responding to, and "
        "recovering from AI system incidents, anomalies, and errors, with "
        "defined escalation paths.",
        "PDPC MAIGF v2 — Operations Management",
        "GovernanceEngine — incident escalation with anomaly detection and audit trail",
        True,
    ),
    # Principle — Stakeholder Interaction and Communication
    (
        "MAIGF — Stakeholder Interaction: AI involvement disclosure",
        "Inform customers and users that an AI system is involved in "
        "decisions that affect them, in plain language and in advance.",
        "PDPC MAIGF v2 — Stakeholder Interaction and Communication",
        "TransparencyDisclosure — AI system identification and plain-language notice",
        True,
    ),
    (
        "MAIGF — Stakeholder Interaction: decision-factor transparency",
        "Provide customers with meaningful information about the factors "
        "the AI system considers and how these influence the outcome, "
        "at the level of specificity appropriate to the risk.",
        "PDPC MAIGF v2 — Stakeholder Interaction and Communication",
        "TransparencyDisclosure — system card with decision factors and logic",
        True,
    ),
    (
        "MAIGF — Stakeholder Interaction: feedback & complaint mechanisms",
        "Establish accessible feedback and complaint mechanisms for "
        "customers affected by AI decisions, with defined response "
        "and resolution timeframes.",
        "PDPC MAIGF v2 — Stakeholder Interaction and Communication",
        "HumanOversightGateway — contestation pathway with human review",
        True,
    ),
    (
        "MAIGF — Stakeholder Interaction: dispute review & redress",
        "For decisions disputed by customers, ensure human review is "
        "available with authority to overturn AI-assisted decisions "
        "and correct any harm caused.",
        "PDPC MAIGF v2 — Stakeholder Interaction and Communication",
        "HumanOversightGateway — override controls with authority delegation",
        True,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "MAIGF — Internal Governance: roles & accountability": (
        "acgs-lite MACIEnforcer — enforces proposer/validator/executor role "
        "separation with clear accountability and escalation paths"
    ),
    "MAIGF — Internal Governance: documented AI policies": (
        "acgs-lite Constitution — version-controlled governance policies "
        "with hash integrity and audit trail"
    ),
    "MAIGF — Internal Governance: human-AI decision model": (
        "acgs-lite HumanOversightGateway — configurable HITL and human-on-the-loop "
        "modes with documented decision flow"
    ),
    "MAIGF — Internal Governance: human review for significant decisions": (
        "acgs-lite HumanOversightGateway — mandatory human review gate for "
        "high-impact actions with authority delegation"
    ),
    "MAIGF — Human Involvement: risk-based oversight determination": (
        "acgs-lite RiskClassifier — probability × impact scoring used to "
        "determine required oversight level"
    ),
    "MAIGF — Human Involvement: risk-level classification": (
        "acgs-lite RiskClassifier — automated risk tier classification with "
        "configurable probability × impact thresholds"
    ),
    "MAIGF — Human Involvement: oversight commensurate with risk": (
        "acgs-lite GovernanceEngine — severity-based escalation with "
        "configurable human approval gates by risk level"
    ),
    "MAIGF — Operations Management: version control & rollback": (
        "acgs-lite AuditLog — versioned audit chain with model lineage "
        "records supports reproducibility and rollback"
    ),
    "MAIGF — Operations Management: ongoing performance monitoring": (
        "acgs-lite GovernanceEngine — continuous monitoring detects "
        "performance anomalies and drift in production"
    ),
    "MAIGF — Operations Management: incident response procedures": (
        "acgs-lite GovernanceEngine — incident escalation with anomaly "
        "detection, halt controls, and full audit trail"
    ),
    "MAIGF — Stakeholder Interaction: AI involvement disclosure": (
        "acgs-lite TransparencyDisclosure — AI system identification with "
        "plain-language notice in system card"
    ),
    "MAIGF — Stakeholder Interaction: decision-factor transparency": (
        "acgs-lite TransparencyDisclosure — system card includes decision "
        "factors and logic explanation at appropriate specificity"
    ),
    "MAIGF — Stakeholder Interaction: feedback & complaint mechanisms": (
        "acgs-lite HumanOversightGateway — contestation pathway and "
        "human review channel with defined response flow"
    ),
    "MAIGF — Stakeholder Interaction: dispute review & redress": (
        "acgs-lite HumanOversightGateway — override controls with authority "
        "delegation enable overturn of disputed AI decisions"
    ),
}


class SingaporeMAIGFFramework:
    """Singapore Model AI Governance Framework v2 (MAIGF) compliance assessor.

    Covers internal governance, risk-proportionate human oversight,
    operations management, and stakeholder communication across all
    four MAIGF principles (P1-P4).

    Status: Voluntary framework; referenced in MAS guidance and ASEAN
    regional AI governance network.

    Usage::

        from acgs_lite.compliance.singapore_maigf import SingaporeMAIGFFramework

        framework = SingaporeMAIGFFramework()
        assessment = framework.assess({
            "system_id": "my-system",
            "jurisdiction": "singapore",
        })
    """

    framework_id: str = "singapore_maigf"
    framework_name: str = "Singapore Model AI Governance Framework v2 (MAIGF)"
    jurisdiction: str = "Singapore"
    status: str = "voluntary"
    enforcement_date: str | None = None

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate Singapore MAIGF checklist items."""
        return [
            ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            for ref, req, citation, feature, blocking in _MAIGF_ITEMS
        ]

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full Singapore MAIGF compliance assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(
    fw: SingaporeMAIGFFramework,
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
            if "Internal Governance" in item.ref:
                recs.append(
                    f"{item.ref}: Establish internal governance structures "
                    f"and document AI policies per MAIGF Internal Governance principle."
                )
            elif "Human Involvement" in item.ref:
                recs.append(
                    f"{item.ref}: Conduct risk classification and define "
                    f"human oversight requirements per MAIGF Human Involvement principle."
                )
            elif "Operations Management" in item.ref:
                recs.append(
                    f"{item.ref}: Implement operational controls including "
                    f"testing, data governance, and incident response per "
                    f"MAIGF Operations Management principle."
                )
            elif "Stakeholder Interaction" in item.ref:
                recs.append(
                    f"{item.ref}: Establish stakeholder communication and "
                    f"feedback mechanisms per MAIGF Stakeholder Interaction principle."
                )
    return tuple(recs)
