"""Brazil Lei Geral de Proteção de Dados (LGPD) + AI compliance module.

Implements AI-relevant obligations from Brazil's Lei Geral de Proteção de
Dados Pessoais (LGPD, Law No. 13,709/2018) and the ANPD (National Data
Protection Authority) guidance on automated decision-making and AI systems.

Sections covered:
- Article 5:  Definitions (including automated data processing)
- Article 7:  Legal bases for personal data processing
- Article 11: Legal bases for sensitive personal data processing
- Article 17: Rights of data subjects
- Article 18: Rights to confirmation, access, and correction
- Article 20: Review of automated decisions — the AI transparency article
- Article 37: Records of data processing activities (controller obligations)
- Article 46: Security measures
- Article 48: Incident communication to ANPD and data subjects

Article 20 is the most AI-critical: it gives data subjects the right to
request a review of decisions taken solely by automated means, including
profiling, credit scoring, hiring, and similar decisions.

Reference: Lei No. 13,709, de 14 de agosto de 2018 (LGPD)
           ANPD Resolution CD/ANPD No. 2/2022 (DPIA guidance)
Enforcement: Since September 18, 2020 (administrative sanctions from August 1, 2021)

Penalties: Up to 2% of revenue in Brazil (last year) per infraction,
capped at BRL 50 million per infraction.

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
_LGPD_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # Article 7 — Legal bases for processing
    (
        "LGPD Art.7",
        "Identify and document the lawful basis for processing personal data "
        "used in the AI system (consent, legitimate interest, contract, legal "
        "obligation, etc.).",
        "LGPD, Article 7 (Law No. 13,709/2018)",
        "GovernanceEngine — constitutional rules enforce legal-basis checks before processing",
        True,
    ),
    # Article 11 — Sensitive personal data
    (
        "LGPD Art.11",
        "Ensure that sensitive personal data (racial origin, religion, health, "
        "biometric, etc.) used in the AI system has an explicit legal basis "
        "such as specific consent or ANPD authorisation.",
        "LGPD, Article 11 (Law No. 13,709/2018)",
        None,
        True,
    ),
    # Article 18 — Rights of data subjects
    (
        "LGPD Art.18(I-II)",
        "Provide data subjects with confirmation of whether personal data is "
        "being processed by the AI system, and access to that data.",
        "LGPD, Article 18(I-II)",
        "AuditLog — queryable per-subject processing record",
        True,
    ),
    (
        "LGPD Art.18(III-IV)",
        "Provide mechanisms for data subjects to request correction of "
        "incomplete, inaccurate, or outdated data processed by the AI system.",
        "LGPD, Article 18(III-IV)",
        None,
        True,
    ),
    (
        "LGPD Art.18(VII)",
        "Provide data subjects with information about the legal basis and "
        "legitimate interests relied upon for data processing.",
        "LGPD, Article 18(VII)",
        "TransparencyDisclosure — legal basis disclosed in system card",
        True,
    ),
    # Article 20 — Automated decision review (key AI article)
    (
        "LGPD Art.20(1)",
        "Provide data subjects with the right to request a review of decisions "
        "made solely by automated processing, including AI/ML systems, that "
        "affect their interests (profiling, credit, hiring, health, etc.).",
        "LGPD, Article 20, §1 (Law No. 13,709/2018)",
        "HumanOversightGateway — human review pathway for contested automated decisions",
        True,
    ),
    (
        "LGPD Art.20(2)",
        "Upon request for automated decision review, disclose the criteria "
        "and procedures used for the automated decision, subject to "
        "trade-secret protections.",
        "LGPD, Article 20, §2 (Law No. 13,709/2018)",
        "TransparencyDisclosure — decision criteria and logic fields in system card",
        True,
    ),
    # Article 37 — Records of processing
    (
        "LGPD Art.37",
        "Maintain records of personal data processing activities, including "
        "AI-driven processing, as required by the ANPD.",
        "LGPD, Article 37 (Law No. 13,709/2018)",
        "AuditLog — tamper-evident processing records with full lifecycle coverage",
        True,
    ),
    # Article 44 / 46 — Security
    (
        "LGPD Art.46",
        "Implement technical and administrative security measures to protect "
        "personal data from unauthorised access, accidental or unlawful "
        "destruction, loss, alteration, or disclosure.",
        "LGPD, Article 46 (Law No. 13,709/2018)",
        "GovernanceEngine — circuit breakers and access controls protect personal data",
        True,
    ),
    # Article 48 — Breach notification
    (
        "LGPD Art.48",
        "In the event of a security incident that may pose risk or harm to "
        "data subjects, communicate this to the ANPD and affected data "
        "subjects within a reasonable period.",
        "LGPD, Article 48 (Law No. 13,709/2018)",
        "AuditLog — security incident detection and immutable record for notification",
        True,
    ),
    # ANPD DPIA guidance — for high-risk AI processing
    (
        "LGPD DPIA",
        "Conduct a Data Protection Impact Assessment (DPIA / RIPD) for AI "
        "processing activities that pose high risk to data subjects, as "
        "required by ANPD Resolution CD/ANPD No. 2/2022.",
        "ANPD Resolution CD/ANPD No. 2/2022",
        "RiskClassifier — risk tier assessment scopes DPIA obligations",
        True,
    ),
    # Data minimisation
    (
        "LGPD Art.6(III)",
        "Apply the data minimisation principle: process only the personal data "
        "strictly necessary to achieve the AI system's legitimate purpose.",
        "LGPD, Article 6(III) — Data Minimisation Principle",
        None,
        True,
    ),
    # Article 50 — Good practices and governance (added from 6a0bfe78)
    (
        "LGPD Art.50(1)",
        "Controllers and processors may formulate rules of good practice "
        "and governance that establish conditions of organization, "
        "complaint handling, and applicable rules.",
        "LGPD Article 50(1)",
        "GovernanceEngine — governance rules as documented best practices",
        True,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "LGPD Art.7": (
        "acgs-lite GovernanceEngine — constitutional rules enforce legal-basis "
        "checks before any personal data processing action"
    ),
    "LGPD Art.18(I-II)": (
        "acgs-lite AuditLog — queryable per-subject processing records support "
        "rights to confirmation and access"
    ),
    "LGPD Art.18(VII)": (
        "acgs-lite TransparencyDisclosure — legal basis and purposes disclosed in system card"
    ),
    "LGPD Art.20(1)": (
        "acgs-lite HumanOversightGateway — human review pathway enables "
        "contestation of automated decisions"
    ),
    "LGPD Art.20(2)": (
        "acgs-lite TransparencyDisclosure — decision criteria and logic fields "
        "provide the required disclosure on review"
    ),
    "LGPD Art.37": (
        "acgs-lite AuditLog — tamper-evident processing records with full "
        "lifecycle coverage support LGPD record-keeping"
    ),
    "LGPD Art.46": (
        "acgs-lite GovernanceEngine — circuit breakers and access controls "
        "protect personal data from unauthorised access"
    ),
    "LGPD Art.48": (
        "acgs-lite AuditLog — security incident detection and immutable record "
        "supports ANPD notification obligations"
    ),
    "LGPD DPIA": (
        "acgs-lite RiskClassifier — risk tier assessment scopes DPIA obligations "
        "per ANPD Resolution No. 2/2022"
    ),
    "LGPD Art.50(1)": (
        "acgs-lite GovernanceEngine — governance rules formalized as "
        "documented good-practice policies with audit trail"
    ),
}


class BrazilLGPDFramework:
    """Brazil LGPD + AI compliance assessor.

    Covers all AI-relevant LGPD obligations: legal bases for processing,
    data subject rights, the automated decision review right (Art. 20),
    processing records, security, breach notification, and DPIA requirements.

    Status: Enacted; administrative sanctions applicable since August 2021.

    Penalties: Up to 2% of prior-year Brazil revenue per infraction,
    capped at BRL 50 million per infraction.

    Usage::

        from acgs_lite.compliance.brazil_lgpd import BrazilLGPDFramework

        framework = BrazilLGPDFramework()
        assessment = framework.assess({
            "system_id": "my-system",
            "jurisdiction": "brazil",
        })
    """

    framework_id: str = "brazil_lgpd"
    framework_name: str = "Brazil Lei Geral de Proteção de Dados (LGPD) + AI"
    jurisdiction: str = "Brazil"
    status: str = "enacted"
    enforcement_date: str | None = "2021-08-01"

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate Brazil LGPD AI checklist items."""
        return [
            ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            for ref, req, citation, feature, blocking in _LGPD_ITEMS
        ]

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full Brazil LGPD compliance assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(
    fw: BrazilLGPDFramework, checklist: list[ChecklistItem]
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
    recs: list[str] = []
    for item in checklist:
        if item.status == ChecklistStatus.PENDING and item.blocking:
            if "Art.20" in item.ref:
                recs.append(
                    f"{item.ref}: Implement automated decision review mechanism. "
                    f"LGPD Art.20 gives data subjects the right to request human review."
                )
            elif "Art.11" in item.ref:
                recs.append(
                    f"{item.ref}: Ensure explicit consent or ANPD authorisation "
                    f"for any sensitive personal data used in the AI system."
                )
            elif "Art.6(III)" in item.ref:
                recs.append(
                    f"{item.ref}: Apply data minimisation — review and remove "
                    f"personal data not strictly necessary for the AI purpose."
                )
    return FrameworkAssessment(
        framework_id=fw.framework_id,
        framework_name=fw.framework_name,
        compliance_score=round(compliant / total, 4) if total else 1.0,
        items=tuple(item.to_dict() for item in checklist),
        gaps=gaps,
        acgs_lite_coverage=round(acgs_covered / total, 4) if total else 0.0,
        recommendations=tuple(recs),
        assessed_at=datetime.now(timezone.utc).isoformat(),
    )
