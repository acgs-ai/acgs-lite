"""Canada Artificial Intelligence and Data Act (AIDA) compliance module.

Implements key obligations from Part 3 of Bill C-27 (the Artificial
Intelligence and Data Act), Canada's proposed federal AI legislation.

Covered obligations:
- Section 5:  Definition and identification of high-impact AI systems
- Section 8:  Anonymized data use and disclosure obligations
- Section 9:  Impact assessments for high-impact AI systems
- Section 10: Plain-language public descriptions
- Section 11: Risk mitigation measures
- Section 12: Monitoring obligations
- Section 13: Record-keeping obligations
- Section 14: Anomalous outcome detection and correction
- Section 16: General prohibition on harmful bias
- Section 17: Prohibition on misleading outputs
- Section 25: Cross-referencing with CPPA (personal information protection)

Note: AIDA is a Bill, not yet enacted law as of the document date. However,
it signals Canada's regulatory direction, and Canadian AI practitioners are
encouraged to adopt conformant practices proactively.

Reference: Bill C-27 — Digital Charter Implementation Act, 2022, Part 3
(AIDA) as amended in Committee (2023-2024)

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
_AIDA_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # Section 5 — High-impact AI system identification
    (
        "AIDA §5(1)",
        "Determine whether the AI system meets the threshold for a "
        "'high-impact AI system' based on the categories prescribed by "
        "regulation (employment, essential services, law enforcement, etc.).",
        "Bill C-27, AIDA Section 5(1)",
        "RiskClassifier — automated risk level classification for impact determination",
        True,
    ),
    (
        "AIDA §5(2)",
        "Document the determination of high-impact status and keep records "
        "that justify the classification decision.",
        "Bill C-27, AIDA Section 5(2)",
        "AuditLog — tamper-evident classification record with rationale",
        True,
    ),
    # Section 8 — Anonymized data
    (
        "AIDA §8(1)",
        "If the AI system is trained on anonymized data, implement measures "
        "to minimise the risk of re-identification of individuals from "
        "training data or AI outputs.",
        "Bill C-27, AIDA Section 8(1)",
        None,
        True,
    ),
    (
        "AIDA §8(2)",
        "On request from the AI and Data Commissioner, provide a description "
        "of the measures taken to anonymize personal information used.",
        "Bill C-27, AIDA Section 8(2)",
        "AuditLog — queryable data governance records support commissioner requests",
        False,
    ),
    # Section 9 — Impact assessments
    (
        "AIDA §9(1)",
        "Assess impacts of the high-impact AI system on individuals, groups, "
        "and society before deployment, including risks of bias, harm, and "
        "infringement of rights.",
        "Bill C-27, AIDA Section 9(1)",
        "RiskClassifier — impact assessment with obligation mapping across risk tiers",
        True,
    ),
    (
        "AIDA §9(2)",
        "Update the impact assessment when there are material changes to the "
        "high-impact AI system or its operating context.",
        "Bill C-27, AIDA Section 9(2)",
        "GovernanceEngine — continuous lifecycle monitoring triggers reassessment",
        True,
    ),
    # Section 10 — Plain language description
    (
        "AIDA §10(1)",
        "Make publicly available a plain language description of the "
        "high-impact AI system, its intended use, and the types of decisions "
        "or recommendations it makes.",
        "Bill C-27, AIDA Section 10(1)",
        "TransparencyDisclosure — public system card with plain language summary",
        True,
    ),
    (
        "AIDA §10(2)",
        "Keep the public description current and update it following material "
        "changes to the system.",
        "Bill C-27, AIDA Section 10(2)",
        "TransparencyDisclosure — versioned system card with change history",
        True,
    ),
    # Section 11 — Mitigation measures
    (
        "AIDA §11(1)",
        "Implement measures to identify, assess, and mitigate risks of harm "
        "and biased output before deployment of a high-impact AI system.",
        "Bill C-27, AIDA Section 11(1)",
        "GovernanceEngine — pre-deployment constitutional validation and blocking",
        True,
    ),
    (
        "AIDA §11(2)",
        "Implement measures to mitigate risks in real time during deployment, "
        "including the ability to suspend operation if risks cannot be "
        "adequately controlled.",
        "Bill C-27, AIDA Section 11(2)",
        "GovernanceEngine — severity-based action blocking with halt capability",
        True,
    ),
    # Section 12 — Monitoring
    (
        "AIDA §12(1)",
        "Monitor the AI system for the emergence of risks and biased output "
        "once deployed; update mitigation measures as new risks are identified.",
        "Bill C-27, AIDA Section 12(1)",
        "GovernanceEngine — continuous post-deployment monitoring and validation",
        True,
    ),
    (
        "AIDA §12(2)",
        "Retain monitoring records for a period prescribed by regulation "
        "(expected 10 years for high-impact systems).",
        "Bill C-27, AIDA Section 12(2)",
        "AuditLog — configurable log retention with immutable records",
        True,
    ),
    # Section 13 — Record-keeping
    (
        "AIDA §13(1)",
        "Maintain records of the design, development, testing, and deployment "
        "of the high-impact AI system sufficient to demonstrate compliance "
        "with AIDA obligations.",
        "Bill C-27, AIDA Section 13(1)",
        "AuditLog — lifecycle audit chain with tamper-evident records",
        True,
    ),
    (
        "AIDA §13(2)",
        "Provide records to the AI and Data Commissioner on request within "
        "the time period specified.",
        "Bill C-27, AIDA Section 13(2)",
        "AuditLog — queryable, exportable audit log for regulatory disclosure",
        True,
    ),
    # Section 14 — Anomalous outcomes
    (
        "AIDA §14(1)",
        "Put in place processes to detect anomalous outputs and outcomes "
        "from the high-impact AI system that could harm individuals.",
        "Bill C-27, AIDA Section 14(1)",
        "GovernanceEngine — anomaly detection flags unexpected or high-risk outputs",
        True,
    ),
    (
        "AIDA §14(2)",
        "Where an anomalous harmful output is detected, take immediate "
        "corrective action including possible suspension of the system, "
        "and notify the Commissioner.",
        "Bill C-27, AIDA Section 14(2)",
        "GovernanceEngine — halt capability and escalation for confirmed harms",
        True,
    ),
    # Section 16 — Bias prohibition
    (
        "AIDA §16",
        "It is prohibited to make, use, or offer for use a high-impact AI "
        "system that results in serious harm or generates biased output "
        "that causes significant adverse impact on a protected group.",
        "Bill C-27, AIDA Section 16",
        None,
        True,
    ),
    # Section 17 — Prohibition on fraudulent outputs
    (
        "AIDA §17",
        "It is prohibited to use a high-impact AI system to generate content "
        "for the purpose of deceiving individuals in a way that could harm them.",
        "Bill C-27, AIDA Section 17",
        "GovernanceEngine — constitutional rules prohibit deceptive action classes",
        True,
    ),
    # Section 25 — Cross-reference with personal information protection
    (
        "AIDA §25",
        "Ensure that use of personal information in the AI system complies "
        "with the Consumer Privacy Protection Act (CPPA) and that AI-specific "
        "transparency provisions do not conflict with CPPA obligations.",
        "Bill C-27, AIDA Section 25",
        None,
        True,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "AIDA §5(1)": (
        "acgs-lite RiskClassifier — automated risk level classification "
        "determines high-impact system status against prescribed categories"
    ),
    "AIDA §5(2)": (
        "acgs-lite AuditLog — tamper-evident classification record with "
        "rationale provides required documentation of high-impact determination"
    ),
    "AIDA §8(2)": (
        "acgs-lite AuditLog — queryable data governance records support "
        "commissioner requests for anonymization descriptions"
    ),
    "AIDA §9(1)": (
        "acgs-lite RiskClassifier — impact assessment with obligation mapping "
        "across risk tiers supports pre-deployment impact assessment"
    ),
    "AIDA §9(2)": (
        "acgs-lite GovernanceEngine — continuous lifecycle monitoring triggers "
        "reassessment on material changes to system or context"
    ),
    "AIDA §10(1)": (
        "acgs-lite TransparencyDisclosure — public system card with plain "
        "language summary of system purpose and decision types"
    ),
    "AIDA §10(2)": (
        "acgs-lite TransparencyDisclosure — versioned system card with "
        "change history kept current after material changes"
    ),
    "AIDA §11(1)": (
        "acgs-lite GovernanceEngine — pre-deployment constitutional validation "
        "and blocking addresses risk identification and mitigation"
    ),
    "AIDA §11(2)": (
        "acgs-lite GovernanceEngine — severity-based action blocking with "
        "halt capability for real-time risk mitigation during deployment"
    ),
    "AIDA §12(1)": (
        "acgs-lite GovernanceEngine — continuous post-deployment monitoring "
        "and validation detects emerging risks and biased outputs"
    ),
    "AIDA §12(2)": (
        "acgs-lite AuditLog — configurable log retention with immutable "
        "records supports monitoring record retention obligations"
    ),
    "AIDA §13(1)": (
        "acgs-lite AuditLog — lifecycle audit chain with tamper-evident "
        "records demonstrates compliance with AIDA record-keeping"
    ),
    "AIDA §13(2)": (
        "acgs-lite AuditLog — queryable, exportable audit log supports "
        "records disclosure to AI and Data Commissioner"
    ),
    "AIDA §14(1)": (
        "acgs-lite GovernanceEngine — anomaly detection flags unexpected "
        "or high-risk outputs for review"
    ),
    "AIDA §14(2)": (
        "acgs-lite GovernanceEngine — halt capability and escalation pipeline "
        "enables corrective action on confirmed harmful outputs"
    ),
    "AIDA §17": (
        "acgs-lite GovernanceEngine — constitutional rules explicitly prohibit "
        "deceptive action classes at the governance layer"
    ),
}


class CanadaAIDAFramework:
    """Canada Artificial Intelligence and Data Act (AIDA) compliance assessor.

    Covers all major obligations for high-impact AI systems under AIDA:
    impact assessment, plain-language disclosure, risk mitigation, monitoring,
    record-keeping, and prohibitions on harmful bias and deception.

    Status: Defunct. Bill C-27 (which contained AIDA) died on the Order Paper at
    prorogation in January 2025 and was not reintroduced as drafted; Canada has no
    federal AI-specific statute in force as of 2026, though a successor framework
    is expected.

    Penalties (proposed):
    - Administrative penalties up to CAD 10 million or 3% of global revenues
    - Offences: up to CAD 25 million or 5% of global revenues

    Usage::

        from acgs_lite.compliance.canada_aida import CanadaAIDAFramework

        framework = CanadaAIDAFramework()
        assessment = framework.assess({
            "system_id": "my-ai-system",
            "jurisdiction": "canada",
        })
    """

    framework_id: str = "canada_aida"
    framework_name: str = "Canada Artificial Intelligence and Data Act (AIDA / Bill C-27)"
    jurisdiction: str = "Canada"
    status: str = "defunct"
    enforcement_date: str | None = None  # Not yet enacted

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate Canada AIDA checklist items."""
        return [
            ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            for ref, req, citation, feature, blocking in _AIDA_ITEMS
        ]

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full Canada AIDA compliance assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(
    fw: CanadaAIDAFramework,
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
            if "§5" in item.ref or "§9" in item.ref:
                recs.append(
                    f"{item.ref}: Conduct and document high-impact determination "
                    f"and impact assessment per AIDA Sections 5 and 9."
                )
            elif "§10" in item.ref:
                recs.append(
                    f"{item.ref}: Publish plain language system description "
                    f"on a publicly accessible website."
                )
            elif "§11" in item.ref or "§12" in item.ref:
                recs.append(
                    f"{item.ref}: Implement risk mitigation and monitoring "
                    f"procedures with documented processes and controls."
                )
            elif "§13" in item.ref:
                recs.append(
                    f"{item.ref}: Establish record-keeping system to demonstrate "
                    f"compliance; records must be available to Commissioner."
                )
            elif "§16" in item.ref:
                recs.append(
                    f"{item.ref}: Conduct bias testing and implement fairness "
                    f"measures. AIDA §16 imposes criminal-level prohibition."
                )
    return tuple(recs)
