"""California Consumer Privacy Act (CCPA) + CPRA AI compliance module.

Implements AI-relevant obligations from the California Consumer Privacy Act
(CCPA, Cal. Civ. Code §§ 1798.100–1798.199.100) as amended by the California
Privacy Rights Act (CPRA, Prop. 24, 2020), and relevant California Privacy
Protection Agency (CPPA) rulemaking on automated decision-making technology
(ADMT).

Sections covered:
- § 1798.100: Right to know about personal information collected
- § 1798.105: Right to delete
- § 1798.110: Right to know categories of information used
- § 1798.120: Right to opt out of sale/sharing
- § 1798.121: Right to limit use of sensitive personal information
- § 1798.135: Methods for submitting opt-out requests
- § 1798.150: Private right of action for data breaches
- § 1798.185: CPPA rulemaking — ADMT rules (automated decision-making)

CPPA ADMT rules (finalized — OAL approved 2025-09-23, effective 2026-01-01;
ADMT-specific compliance duties phase in from 2027-01-01):
- Right to opt out of automated decision-making
- Right to access information about ADMT logic
- Right to human review of ADMT decisions with significant effect
- Risk assessment obligations for high-risk ADMT

Scope: Applies to for-profit businesses above thresholds that collect
personal information about California residents.

Reference: Cal. Civ. Code §§ 1798.100-1798.199 (CCPA/CPRA)
           CPPA Automated Decision-Making Technology Regulations, finalized 2025
Enforcement: Since July 1, 2020 (CCPA); July 1, 2023 (CPRA amendments)
ADMT rules: Finalized (OAL approved 2025-09-23); effective 2026-01-01;
            ADMT-specific compliance duties phase in from 2027-01-01

Penalties: Up to USD 2,500 per unintentional violation; USD 7,500 per
intentional violation or violation involving minor data.

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
_CCPA_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # § 1798.100 — Right to know
    (
        "CCPA §1798.100",
        "Provide California consumers with the right to know what personal "
        "information the business (or AI system) has collected about them, "
        "the sources, purposes, and third parties shared with.",
        "Cal. Civ. Code § 1798.100 (CCPA/CPRA)",
        "AuditLog — queryable per-subject processing record",
        True,
    ),
    # § 1798.105 — Right to delete
    (
        "CCPA §1798.105",
        "Honour consumer requests to delete personal information collected "
        "by the AI system, subject to statutory exceptions.",
        "Cal. Civ. Code § 1798.105 (CCPA/CPRA)",
        None,
        True,
    ),
    # § 1798.110 — Right to know categories
    (
        "CCPA §1798.110",
        "Disclose the specific categories and pieces of personal information "
        "collected and used by the AI system, and the categories of third "
        "parties with whom such information is shared.",
        "Cal. Civ. Code § 1798.110 (CCPA/CPRA)",
        "TransparencyDisclosure — data categories and sharing disclosed in system card",
        True,
    ),
    # § 1798.120 — Right to opt out of sale/sharing
    (
        "CCPA §1798.120",
        "Provide a 'Do Not Sell or Share My Personal Information' mechanism "
        "and honour opt-out requests within 15 business days.",
        "Cal. Civ. Code § 1798.120 (CCPA/CPRA)",
        None,
        True,
    ),
    # § 1798.121 — Sensitive personal information
    (
        "CCPA §1798.121",
        "Provide consumers with the right to limit the use of sensitive "
        "personal information (racial origin, religion, health, finances, "
        "precise geolocation, etc.) to purposes strictly necessary to "
        "provide the requested service.",
        "Cal. Civ. Code § 1798.121 (CPRA)",
        None,
        True,
    ),
    # § 1798.135 — Opt-out methods
    (
        "CCPA §1798.135",
        "Implement an opt-out preference signal processing mechanism "
        "(e.g. Global Privacy Control), clearly visible and accessible "
        "opt-out links, and document how opt-out requests are honoured.",
        "Cal. Civ. Code § 1798.135 (CPRA)",
        None,
        True,
    ),
    # § 1798.185 / CPPA ADMT Rules — Automated decision-making
    (
        "CCPA §1798.185",
        "Comply with CPPA rulemaking on automated decision-making technology (ADMT) "
        "including opt-out rights, notice requirements, and human review pathways.",
        "Cal. Civ. Code §1798.185 (CPPA ADMT Regulations, 2024)",
        "HumanOversightGateway — opt-out and human review pathway for significant decisions",
        True,
    ),
    (
        "CCPA ADMT-OPT-OUT",
        "Provide consumers with the right to opt out of automated "
        "decision-making technology (ADMT) used for significant decisions "
        "including profiling for work, credit, healthcare, education, "
        "insurance, or housing.",
        "CPPA Draft ADMT Regulations (2024), § 1798.185(a)(21)",
        "HumanOversightGateway — opt-out and human review pathway for significant decisions",
        True,
    ),
    (
        "CCPA ADMT-NOTICE",
        "Provide consumers with a plain-language notice at or before the "
        "point of using ADMT that describes: what ADMT is used for, "
        "what data is used, how to opt out, and how to request human review.",
        "CPPA Draft ADMT Regulations (2024), § 1798.185(a)(21)",
        "TransparencyDisclosure — ADMT notice fields in system card",
        True,
    ),
    (
        "CCPA ADMT-LOGIC",
        "Upon consumer request, disclose the logic used by the ADMT system "
        "to the extent it would not reveal trade secrets.",
        "CPPA Draft ADMT Regulations (2024)",
        "TransparencyDisclosure — decision logic explanation fields",
        True,
    ),
    (
        "CCPA ADMT-HUMAN-REVIEW",
        "Provide consumers a meaningful right to request human review of "
        "consequential decisions made by ADMT; ensure the human reviewer "
        "has authority to override the automated decision.",
        "CPPA Draft ADMT Regulations (2024)",
        "HumanOversightGateway — human review with override authority",
        True,
    ),
    (
        "CCPA ADMT-RISK",
        "Conduct a risk assessment before deploying ADMT for significant "
        "decisions; document risks to consumers, safeguards, and whether "
        "benefits outweigh risks.",
        "CPPA Draft ADMT Regulations (2024), Risk Assessment provisions",
        "RiskClassifier — risk tier assessment and documentation for ADMT deployment",
        True,
    ),
    # Privacy by design / security
    (
        "CCPA §1798.150",
        "Implement reasonable security measures to protect personal information "
        "collected by the AI system; failure to do so exposes the business "
        "to a private right of action.",
        "Cal. Civ. Code § 1798.150 (CCPA)",
        "GovernanceEngine — circuit breakers and security controls for personal data protection",
        True,
    ),
    # Data minimisation (CPRA addition)
    (
        "CCPA §1798.100(a)(3)",
        "Collect only the personal information that is reasonably necessary "
        "and proportionate to the purpose for which the AI system processes "
        "it (data minimisation, CPRA addition).",
        "Cal. Civ. Code § 1798.100(a)(3) (CPRA)",
        None,
        True,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "CCPA §1798.100": (
        "acgs-lite AuditLog — queryable per-subject processing record "
        "satisfies right-to-know obligations"
    ),
    "CCPA §1798.110": (
        "acgs-lite TransparencyDisclosure — data categories and third-party "
        "sharing disclosed in system card"
    ),
    "CCPA ADMT-OPT-OUT": (
        "acgs-lite HumanOversightGateway — opt-out and human review pathway "
        "for significant ADMT decisions"
    ),
    "CCPA ADMT-NOTICE": (
        "acgs-lite TransparencyDisclosure — ADMT notice fields included "
        "in system card with opt-out instructions"
    ),
    "CCPA ADMT-LOGIC": (
        "acgs-lite TransparencyDisclosure — decision logic explanation fields "
        "satisfy ADMT logic disclosure obligation"
    ),
    "CCPA ADMT-HUMAN-REVIEW": (
        "acgs-lite HumanOversightGateway — human review with override "
        "authority for consequential automated decisions"
    ),
    "CCPA ADMT-RISK": (
        "acgs-lite RiskClassifier — risk tier assessment and documentation "
        "for ADMT deployment risk assessment"
    ),
    "CCPA §1798.150": (
        "acgs-lite GovernanceEngine — circuit breakers and security controls "
        "provide reasonable security for personal data"
    ),
}


class CCPACPRAFramework:
    """California CCPA/CPRA + AI (ADMT) compliance assessor.

    Covers CCPA/CPRA consumer rights (know, delete, opt-out, sensitive data
    limits), automated decision-making technology (ADMT) obligations from
    CPPA draft rules (2024), risk assessment, and security requirements.

    Status: CCPA/CPRA enacted and enforced. ADMT rules: finalized (OAL approved
    2025-09-23), effective 2026-01-01, with ADMT-specific compliance duties
    phasing in from 2027-01-01.

    Penalties: USD 2,500–7,500 per violation; private right of action for
    security breaches.

    Usage::

        from acgs_lite.compliance.ccpa_cpra import CCPACPRAFramework

        framework = CCPACPRAFramework()
        assessment = framework.assess({
            "system_id": "my-system",
            "jurisdiction": "california",
        })
    """

    framework_id: str = "ccpa_cpra"
    framework_name: str = "California Consumer Privacy Act / CPRA + ADMT Rules (CCPA/CPRA)"
    jurisdiction: str = "California"
    status: str = "enacted"  # Core CCPA/CPRA enacted; ADMT rules finalized 2025-09-23
    enforcement_date: str | None = "2020-07-01"

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate CCPA/CPRA checklist items."""
        return [
            ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            for ref, req, citation, feature, blocking in _CCPA_ITEMS
        ]

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full CCPA/CPRA compliance assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(fw: CCPACPRAFramework, checklist: list[ChecklistItem]) -> FrameworkAssessment:
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
            if "§1798.105" in item.ref:
                recs.append(
                    f"{item.ref}: Implement consumer deletion request workflow "
                    f"with 45-day response window per CCPA §1798.105."
                )
            elif "§1798.120" in item.ref or "§1798.135" in item.ref:
                recs.append(
                    f"{item.ref}: Implement 'Do Not Sell or Share' link and "
                    f"Global Privacy Control (GPC) signal processing."
                )
            elif "§1798.121" in item.ref:
                recs.append(
                    f"{item.ref}: Implement sensitive personal information "
                    f"limitation mechanism per CPRA §1798.121."
                )
            elif "§1798.100(a)(3)" in item.ref:
                recs.append(
                    f"{item.ref}: Audit AI system's data collection against "
                    f"CPRA data minimisation principle."
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
