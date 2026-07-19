"""India Digital Personal Data Protection Act (DPDP Act) compliance module.

Implements AI-relevant obligations from the Digital Personal Data Protection
Act, 2023 (Act 22 of 2023), India's first comprehensive data protection law.

Sections covered:
- Section 4:  Lawfulness of personal data processing
- Section 6:  Consent requirements
- Section 8:  Obligations of Data Fiduciary (controller)
- Section 9:  Processing of children's data
- Section 11: Right to access and information
- Section 12: Right to correction and erasure
- Section 16: Additional obligations of Significant Data Fiduciary (SDF)
- Section 17: Obligations of Data Processor
- Section 19: Establishment and powers of Data Protection Board
- Section 25: Intimation of personal data breach

Significant Data Fiduciary (SDF) obligations (Section 16) include:
- Data Protection Impact Assessment (DPIA)
- Auditing AI systems
- Algorithmic accountability

Reference: Digital Personal Data Protection Act, 2023 (India)
           No. 22 of 2023, Ministry of Electronics and Information Technology
Enacted: August 11, 2023 (Presidential assent)
Rules: DPDP Rules 2025 notified 2025-11-13; phased commencement — most
       procedural provisions in force from 2025-11-14, main compliance
       duty provisions from 2027-05-13

Penalties: Up to INR 250 crore per instance (≈ USD 30 million) for
significant data fiduciary violations.

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
_DPDP_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # Section 4 — Lawfulness of processing
    (
        "DPDP §4",
        "Process personal data only for a lawful purpose for which an "
        "individual has consented, or for certain legitimate uses specified "
        "in the Act. AI inference on personal data must have a legal basis.",
        "India DPDP Act 2023, Section 4",
        "GovernanceEngine — constitutional rules enforce lawful-purpose checks",
        True,
    ),
    # Section 6 — Consent
    (
        "DPDP §6(1)",
        "Personal data may be processed only upon the consent of the Data "
        "Principal, which must be free, specific, informed, unconditional, "
        "and unambiguous.",
        "India DPDP Act 2023, Section 6(1)",
        None,
        True,
    ),
    (
        "DPDP §6(4)",
        "Provide the Data Principal with a clear notice before seeking "
        "consent, specifying personal data to be processed, purpose, and "
        "the manner in which consent may be withdrawn.",
        "India DPDP Act 2023, Section 6(4)",
        "TransparencyDisclosure — notice and consent information in system card",
        True,
    ),
    # Section 8 — Data Fiduciary obligations
    (
        "DPDP §8(1)",
        "Ensure the accuracy, completeness, and consistency of personal data "
        "used in the AI system before and during processing.",
        "India DPDP Act 2023, Section 8(1)",
        None,
        True,
    ),
    (
        "DPDP §8(3)",
        "Implement appropriate technical and organisational measures to ensure "
        "observance of data processing obligations and prevent unauthorised "
        "access, use, alteration, or deletion of personal data.",
        "India DPDP Act 2023, Section 8(3)",
        "GovernanceEngine — circuit breakers and access controls prevent unauthorised processing",
        True,
    ),
    (
        "DPDP §8(5)",
        "Publish the contact details of a Data Protection Officer (or "
        "authorised person) to address grievances raised by Data Principals.",
        "India DPDP Act 2023, Section 8(5)",
        None,
        True,
    ),
    (
        "DPDP §8(6)",
        "Erase personal data when the purpose for which it was collected has "
        "been met or when consent is withdrawn, unless retention is required "
        "by applicable law.",
        "India DPDP Act 2023, Section 8(6)",
        None,
        True,
    ),
    # Section 9 — Children's data
    (
        "DPDP §9(1)",
        "Before processing personal data of a child, obtain verifiable parental "
        "consent. Do not process personal data in a manner that is detrimental "
        "to the well-being of a child.",
        "India DPDP Act 2023, Section 9(1)",
        "GovernanceEngine — age-related processing restrictions",
        False,  # only relevant for systems processing children's data
    ),
    (
        "DPDP §9(3)",
        "Do not undertake tracking or behavioural monitoring of children, or "
        "targeted advertising directed at children.",
        "India DPDP Act 2023, Section 9(3)",
        "GovernanceEngine — constitutional rules block prohibited profiling categories",
        False,
    ),
    # Section 11 — Right to information
    (
        "DPDP §11(1)",
        "Upon request, inform the Data Principal of the personal data being "
        "processed, the processing activities, and the identities of all "
        "Data Processors and recipients.",
        "India DPDP Act 2023, Section 11(1)",
        "AuditLog — queryable per-subject processing record",
        True,
    ),
    # Section 12 — Right to correction and erasure
    (
        "DPDP §12",
        "Correct inaccurate or misleading personal data, complete incomplete "
        "data, update data, or erase data that is no longer necessary for the "
        "purpose of processing, upon request from the Data Principal.",
        "India DPDP Act 2023, Section 12",
        None,
        True,
    ),
    # Section 16 — Significant Data Fiduciary (SDF) obligations
    (
        "DPDP §16(1)(a)",
        "Significant Data Fiduciaries must appoint a Data Protection Officer "
        "based in India who is accountable to the Board of the entity.",
        "India DPDP Act 2023, Section 16(1)(a)",
        None,
        False,  # Only for SDFs
    ),
    (
        "DPDP §16(1)(b)",
        "Significant Data Fiduciaries must appoint an independent data auditor "
        "to evaluate compliance with the Act and rules.",
        "India DPDP Act 2023, Section 16(1)(b)",
        "AuditLog — tamper-evident audit chain supports independent audit",
        False,
    ),
    (
        "DPDP §16(1)(c)",
        "Significant Data Fiduciaries must conduct a Data Protection Impact "
        "Assessment (DPIA) for high-risk AI processing activities.",
        "India DPDP Act 2023, Section 16(1)(c)",
        "RiskClassifier — risk tier assessment scopes DPIA obligations",
        False,
    ),
    (
        "DPDP §16(2)",
        "Significant Data Fiduciaries must implement additional safeguards "
        "including algorithmic accountability measures ensuring AI outputs "
        "do not pose systemic risk.",
        "India DPDP Act 2023, Section 16(2)",
        "GovernanceEngine — constitutional rule set provides algorithmic accountability",
        False,
    ),
    # Section 25 — Data breach notification
    (
        "DPDP §25(1)",
        "In the event of a personal data breach, notify each affected Data "
        "Principal and the Data Protection Board in such form and manner as "
        "prescribed.",
        "India DPDP Act 2023, Section 25(1)",
        "AuditLog — breach event detection and immutable record for notification",
        True,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "DPDP §4": (
        "acgs-lite GovernanceEngine — constitutional rules enforce lawful-purpose "
        "checks before any personal data processing action"
    ),
    "DPDP §6(4)": (
        "acgs-lite TransparencyDisclosure — notice and consent information "
        "fields in system card satisfy prior notice obligation"
    ),
    "DPDP §8(3)": (
        "acgs-lite GovernanceEngine — circuit breakers and access controls "
        "prevent unauthorised access, use, or alteration of personal data"
    ),
    "DPDP §9(1)": (
        "acgs-lite GovernanceEngine — constitutional rules can enforce "
        "age-related processing restrictions for children's data"
    ),
    "DPDP §9(3)": (
        "acgs-lite GovernanceEngine — constitutional rules block prohibited "
        "profiling and behavioural tracking categories"
    ),
    "DPDP §11(1)": (
        "acgs-lite AuditLog — queryable per-subject processing record "
        "satisfies right to access information obligation"
    ),
    "DPDP §16(1)(b)": (
        "acgs-lite AuditLog — tamper-evident audit chain with hash integrity "
        "supports independent auditor review"
    ),
    "DPDP §16(1)(c)": (
        "acgs-lite RiskClassifier — risk tier assessment scopes DPIA "
        "obligations for Significant Data Fiduciaries"
    ),
    "DPDP §16(2)": (
        "acgs-lite GovernanceEngine — constitutional rule set provides "
        "algorithmic accountability with full audit trail"
    ),
    "DPDP §25(1)": (
        "acgs-lite AuditLog — breach event detection and immutable record "
        "supports notification obligations"
    ),
}


class IndiaDPDPFramework:
    """India Digital Personal Data Protection Act (DPDP Act 2023) compliance assessor.

    Covers lawfulness, consent, Data Fiduciary obligations, children's data,
    rights of Data Principals, Significant Data Fiduciary additional obligations,
    and breach notification.

    Status: Enacted August 2023; DPDP Rules 2025 notified 2025-11-13 with phased
    commencement (most procedural provisions from 2025-11-14; main compliance
    duty provisions from 2027-05-13).

    Penalties: Up to INR 250 crore (≈ USD 30 million) per instance.

    Usage::

        from acgs_lite.compliance.india_dpdp import IndiaDPDPFramework

        framework = IndiaDPDPFramework()
        assessment = framework.assess({
            "system_id": "my-system",
            "jurisdiction": "india",
            "is_significant_data_fiduciary": False,
        })
    """

    framework_id: str = "india_dpdp"
    framework_name: str = "India Digital Personal Data Protection Act (DPDP Act 2023)"
    jurisdiction: str = "India"
    status: str = "enacted"
    enforcement_date: str | None = "2023-08-11"

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate India DPDP checklist items.

        SDF-specific obligations are N/A unless is_significant_data_fiduciary=True.
        Child-data obligations are N/A unless processes_children_data=True.
        """
        is_sdf = system_description.get("is_significant_data_fiduciary", False)
        processes_children = system_description.get("processes_children_data", False)

        _sdf_refs = {"DPDP §16(1)(a)", "DPDP §16(1)(b)", "DPDP §16(1)(c)", "DPDP §16(2)"}
        _child_refs = {"DPDP §9(1)", "DPDP §9(3)"}

        items: list[ChecklistItem] = []
        for ref, req, citation, feature, blocking in _DPDP_ITEMS:
            item = ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            if ref in _sdf_refs and not is_sdf:
                item.mark_not_applicable("Not a Significant Data Fiduciary.")
            elif ref in _child_refs and not processes_children:
                item.mark_not_applicable("System does not process children's data.")
            items.append(item)
        return items

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP and item.status != ChecklistStatus.NOT_APPLICABLE:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full India DPDP compliance assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(
    fw: IndiaDPDPFramework, checklist: list[ChecklistItem]
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
            if "§6" in item.ref:
                recs.append(
                    f"{item.ref}: Implement consent mechanism with required notice "
                    f"per DPDP Act Section 6. Consent must be free, specific, informed."
                )
            elif "§8" in item.ref:
                recs.append(
                    f"{item.ref}: Implement Data Fiduciary obligations including "
                    f"data accuracy, security measures, and DPO contact publication."
                )
            elif "§12" in item.ref:
                recs.append(
                    f"{item.ref}: Implement correction/erasure workflow for "
                    f"Data Principal rights requests."
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
