"""HIPAA + AI compliance module for healthcare AI systems.

Implements HIPAA provisions relevant to AI systems processing
Protected Health Information (PHI) or electronic PHI (ePHI):
- Privacy Rule: PHI protection in AI inputs/outputs
- Security Rule: Technical safeguards for AI processing ePHI
- Breach Notification Rule: AI-involved incident requirements

Reference: Health Insurance Portability and Accountability Act (1996),
HITECH Act (2009), 45 CFR Parts 160, 162, 164.
Penalty exposure is tiered, culpability-dependent, and annually
inflation-adjusted under 45 CFR 160.404 / 45 CFR 102.3; verify current
HHS/OCR amounts with legal review.

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

_HIPAA_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # Privacy Rule
    (
        "HIPAA 164.502(a)",
        "Ensure AI system uses or discloses PHI only as permitted by the "
        "Privacy Rule. Implement minimum necessary standard — AI system "
        "must access only the minimum PHI required for its purpose.",
        "45 CFR 164.502(a) — Uses and Disclosures",
        "GovernanceEngine — constitutional rules enforce data access boundaries",
        True,
    ),
    (
        "HIPAA 164.502(b)",
        "Apply the minimum necessary standard: AI systems must request, use, "
        "and disclose only the minimum amount of PHI needed to accomplish "
        "the intended purpose.",
        "45 CFR 164.502(b) — Minimum Necessary",
        "MACIEnforcer — scope-limited role enforcement restricts data access",
        True,
    ),
    (
        "HIPAA 164.520",
        "Provide notice of privacy practices describing how AI systems use "
        "PHI, including automated processing and profiling activities.",
        "45 CFR 164.520 — Notice of Privacy Practices",
        "TransparencyDisclosure — system card documenting PHI processing",
        True,
    ),
    (
        "HIPAA 164.524",
        "Provide individuals with access to their PHI processed by AI "
        "systems, including the right to inspect and obtain copies.",
        "45 CFR 164.524 — Access of Individuals to PHI",
        "AuditLog — queryable per-subject audit trail",
        True,
    ),
    (
        "HIPAA 164.526",
        "Allow individuals to request amendments to their PHI if the AI "
        "system maintains PHI in a designated record set.",
        "45 CFR 164.526 — Amendment of PHI",
        None,
        True,
    ),
    (
        "HIPAA 164.528",
        "Maintain an accounting of disclosures of PHI made by the AI system "
        "for up to six years from the date of disclosure.",
        "45 CFR 164.528 — Accounting of Disclosures",
        "AuditLog — tamper-evident disclosure logging with retention",
        True,
    ),
    # Security Rule — Technical Safeguards
    (
        "HIPAA 164.312(a)",
        "Implement technical policies and procedures for electronic "
        "information systems that maintain ePHI to allow access only to "
        "authorized persons or software programs.",
        "45 CFR 164.312(a) — Access Control",
        "GovernanceEngine — constitutional rule-based access control",
        True,
    ),
    (
        "HIPAA 164.312(b)",
        "Implement hardware, software, and/or procedural mechanisms that "
        "record and examine activity in AI systems that contain or use ePHI.",
        "45 CFR 164.312(b) — Audit Controls",
        "AuditLog — SHA-256 chained audit trail with chain verification",
        True,
    ),
    (
        "HIPAA 164.312(c)",
        "Implement policies and procedures to protect ePHI processed by AI "
        "systems from improper alteration or destruction.",
        "45 CFR 164.312(c) — Integrity",
        "AuditLog — tamper-evident cryptographic hash chaining",
        True,
    ),
    (
        "HIPAA 164.312(d)",
        "Implement procedures to verify the identity of persons or entities "
        "seeking access to ePHI through the AI system.",
        "45 CFR 164.312(d) — Person or Entity Authentication",
        None,
        True,
    ),
    (
        "HIPAA 164.312(e)",
        "Implement technical security measures to guard against unauthorized "
        "access to ePHI transmitted over electronic communications networks "
        "to or from the AI system.",
        "45 CFR 164.312(e) — Transmission Security",
        None,
        True,
    ),
    # Breach Notification Rule
    (
        "HIPAA 164.404",
        "Notify affected individuals without unreasonable delay (no later "
        "than 60 calendar days) following discovery of a breach of unsecured "
        "PHI involving the AI system.",
        "45 CFR 164.404 — Notification to Individuals",
        None,
        True,
    ),
    (
        "HIPAA 164.408",
        "Notify the Secretary of HHS of breaches of unsecured PHI involving "
        "AI systems. Breaches affecting 500+ individuals require notification "
        "contemporaneously with individual notice (without unreasonable "
        "delay, no later than 60 days).",
        "45 CFR 164.408 — Notification to the Secretary",
        None,
        True,
    ),
    # AI-specific considerations
    (
        "HIPAA-AI.1",
        "Implement PHI detection and redaction controls in AI system inputs "
        "and outputs to prevent inadvertent PHI exposure in model responses.",
        "HIPAA Privacy Rule + HHS AI Guidance",
        "Constitution — PHI detection rules in governance framework",
        True,
    ),
    (
        "HIPAA-AI.2",
        "Ensure AI model training data containing PHI is de-identified per "
        "Safe Harbor (164.514(b)) or Expert Determination (164.514(a)) methods.",
        "45 CFR 164.514 — De-identification",
        None,
        True,
    ),
]

_ACGS_LITE_MAP: dict[str, str] = {
    "HIPAA 164.502(a)": (
        "acgs-lite GovernanceEngine — constitutional rules restrict AI "
        "actions to authorized PHI access patterns"
    ),
    "HIPAA 164.502(b)": (
        "acgs-lite MACIEnforcer — role-scoped access ensures minimum "
        "necessary PHI access per separation of duties"
    ),
    "HIPAA 164.520": (
        "acgs-lite TransparencyDisclosure — system card documenting "
        "PHI processing purposes and AI system capabilities"
    ),
    "HIPAA 164.524": (
        "acgs-lite AuditLog — queryable audit trail supporting "
        "per-subject PHI access request fulfillment"
    ),
    "HIPAA 164.528": (
        "acgs-lite AuditLog — tamper-evident logging of all PHI "
        "disclosures with configurable retention"
    ),
    "HIPAA 164.312(a)": (
        "acgs-lite GovernanceEngine — constitutional rules as access "
        "control policies for ePHI-processing AI systems"
    ),
    "HIPAA 164.312(b)": (
        "acgs-lite AuditLog — hardware-independent audit controls "
        "with SHA-256 cryptographic chain verification"
    ),
    "HIPAA 164.312(c)": (
        "acgs-lite AuditLog — tamper-evident cryptographic hash chaining ensures ePHI integrity"
    ),
    "HIPAA-AI.1": (
        "acgs-lite Constitution — PHI detection keywords and patterns "
        "in governance rules flag potential PHI exposure"
    ),
}


class HIPAAAIFramework:
    """HIPAA + AI compliance assessor for healthcare AI systems.

    Covers the Privacy Rule (PHI protection), Security Rule (technical
    safeguards), and Breach Notification Rule as applied to AI systems
    that process Protected Health Information.

    HIPAA civil monetary penalties are tiered, culpability-dependent,
    and annually inflation-adjusted under 45 CFR 160.404 / 45 CFR 102.3.
    Verify current HHS/OCR amounts with legal review. Criminal penalties
    are possible for knowing violations.

    Status: Enacted (1996, HITECH 2009). Enforced by HHS OCR.

    Usage::

        from acgs_lite.compliance.hipaa_ai import HIPAAAIFramework

        framework = HIPAAAIFramework()
        assessment = framework.assess({
            "system_id": "clinical-decision-support",
            "domain": "healthcare",
            "processes_phi": True,
        })
    """

    framework_id: str = "hipaa_ai"
    framework_name: str = "HIPAA + AI Healthcare Compliance"
    jurisdiction: str = "United States"
    status: str = "enacted"
    enforcement_date: str | None = "1996-08-21"

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate HIPAA + AI checklist items."""
        return [
            ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            for ref, req, citation, feature, blocking in _HIPAA_ITEMS
        ]

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full HIPAA + AI assessment."""
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
                    f"{item.ref}: Address for HIPAA compliance. Civil monetary "
                    f"penalty exposure is tiered, culpability-dependent, and "
                    f"annually inflation-adjusted under 45 CFR 160.404 / 45 CFR 102.3; "
                    f"verify current HHS/OCR amounts with legal review."
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
