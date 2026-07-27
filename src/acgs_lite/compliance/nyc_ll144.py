"""NYC Local Law 144 (2021) compliance module.

Implements requirements for Automated Employment Decision Tools (AEDTs)
used in New York City:
- Annual bias audit by independent auditor
- Public posting of audit results summary
- 10 business day advance notice to candidates
- Impact ratio calculations for race/ethnicity and sex categories

Reference: NYC Local Law 144 of 2021; NYC DCWP Rules (Title 6, Ch. 5)
Effective Jan 1, 2023; DCWP enforcement since July 5, 2023.
Penalties: up to $500 first violation, $500-$1,500 subsequent.

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

_NYC_LL144_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # Bias Audit Requirements
    (
        "LL144-AUDIT.1",
        "Conduct a bias audit of the AEDT within one year prior to use. "
        "The audit must be conducted by an independent auditor who is not "
        "involved in the use or development of the AEDT.",
        "NYC LL144 Section 20-871(a); DCWP Rules Section 5-301",
        None,
        True,
    ),
    (
        "LL144-AUDIT.2",
        "The bias audit must calculate impact ratios for each category "
        "(selection rate or scoring rate) comparing each race/ethnicity "
        "and sex category to the most selected category.",
        "NYC LL144 Section 20-871(b); DCWP Rules Section 5-301(b)",
        None,
        True,
    ),
    (
        "LL144-AUDIT.3",
        "If historical data is insufficient for bias audit, use test data "
        "that meets demographic representation requirements. Document the "
        "data source and any limitations.",
        "DCWP Rules Section 5-301(c)",
        None,
        False,
    ),
    (
        "LL144-AUDIT.4",
        "Retain bias audit results for a minimum period as required. The "
        "audit must cover the AEDT as deployed, not just the model in "
        "development.",
        "DCWP Rules Section 5-301(d)",
        "AuditLog — audit trail retention with tamper-evident chain",
        True,
    ),
    # Public Posting Requirements
    (
        "LL144-POST.1",
        "Make a summary of the most recent bias audit publicly available "
        "on the employer's or employment agency's website before using "
        "the AEDT.",
        "NYC LL144 Section 20-871(b)(1)",
        None,
        True,
    ),
    (
        "LL144-POST.2",
        "The published summary must include: source and explanation of data, "
        "number of individuals assessed, selection/scoring rates by category, "
        "and impact ratios for each category.",
        "NYC LL144 Section 20-871(b)(2); DCWP Rules Section 5-302",
        None,
        True,
    ),
    (
        "LL144-POST.3",
        "The published summary must include the date of the most recent "
        "bias audit and the distribution date of the AEDT.",
        "DCWP Rules Section 5-302(c)",
        None,
        True,
    ),
    # Candidate Notice Requirements
    (
        "LL144-NOTICE.1",
        "Provide candidates or employees with notice at least 10 business "
        "days before the AEDT is used, including notification that an AEDT "
        "will be used in the assessment.",
        "NYC LL144 Section 20-871(b)(3); DCWP Rules Section 5-303",
        "TransparencyDisclosure — system card provides AEDT disclosure",
        True,
    ),
    (
        "LL144-NOTICE.2",
        "The notice must describe the job qualifications and characteristics "
        "that the AEDT will assess and state the data sources used.",
        "DCWP Rules Section 5-303(b)",
        "TransparencyDisclosure — capabilities and data source documentation",
        True,
    ),
    (
        "LL144-NOTICE.3",
        "Provide information about how to request an alternative selection "
        "process or a reasonable accommodation under applicable law.",
        "DCWP Rules Section 5-303(c)",
        "HumanOversightGateway — alternative human review pathway",
        True,
    ),
    # Governance and Documentation
    (
        "LL144-GOV.1",
        "Maintain documentation of AEDT governance including model purpose, "
        "training data characteristics, performance metrics, and known "
        "limitations for auditor review.",
        "NYC LL144 Section 20-871(a); DCWP Rules Section 5-301",
        "Constitution + AuditLog — governance documentation with audit trail",
        True,
    ),
    (
        "LL144-GOV.2",
        "Implement ongoing monitoring of AEDT performance and bias metrics "
        "between annual audits to detect drift or emerging disparities.",
        "DCWP Rules; Best practice per EEOC AI guidance",
        "GovernanceMetrics — real-time governance performance monitoring",
        False,
    ),
]

_ACGS_LITE_MAP: dict[str, str] = {
    "LL144-AUDIT.4": (
        "acgs-lite AuditLog — tamper-evident audit trail retains "
        "audit documentation with cryptographic chain integrity"
    ),
    "LL144-NOTICE.1": (
        "acgs-lite TransparencyDisclosure — generates AEDT disclosure "
        "notices meeting the 10-day advance notice requirement"
    ),
    "LL144-NOTICE.2": (
        "acgs-lite TransparencyDisclosure — documents assessed "
        "qualifications, characteristics, and data sources"
    ),
    "LL144-NOTICE.3": (
        "acgs-lite HumanOversightGateway — provides alternative "
        "human review pathway for candidates requesting accommodation"
    ),
    "LL144-GOV.1": (
        "acgs-lite Constitution + AuditLog — governance policy "
        "documentation with tamper-evident audit trail"
    ),
    "LL144-GOV.2": (
        "acgs-lite GovernanceMetrics — ongoing monitoring of "
        "governance decisions and performance metrics"
    ),
}


class NYCLL144Framework:
    """NYC Local Law 144 (AEDT) compliance assessor.

    Covers requirements for Automated Employment Decision Tools used
    in New York City: bias audits, public posting, candidate notice,
    and ongoing governance. Applies to employers and employment agencies
    using AEDTs for hiring or promotion decisions in NYC.

    Penalties: up to $500 first violation, $500-$1,500 subsequent.
    Each use of a non-compliant AEDT on a candidate is a separate violation.

    Status: Enacted. Effective Jan 1, 2023; DCWP enforcement since July 5, 2023.

    Usage::

        from acgs_lite.compliance.nyc_ll144 import NYCLL144Framework

        framework = NYCLL144Framework()
        assessment = framework.assess({
            "system_id": "resume-screener",
            "domain": "employment",
            "jurisdiction": "new_york_city",
        })
    """

    framework_id: str = "nyc_ll144"
    framework_name: str = "NYC Local Law 144 — Automated Employment Decision Tools"
    jurisdiction: str = "New York City"
    status: str = "enacted"
    enforcement_date: str | None = "2023-07-05"

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate NYC LL144 checklist items."""
        return [
            ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            for ref, req, citation, feature, blocking in _NYC_LL144_ITEMS
        ]

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full NYC LL144 assessment."""
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
                    f"{item.ref}: Address before using AEDT in NYC. "
                    f"Each non-compliant use is a separate violation."
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
