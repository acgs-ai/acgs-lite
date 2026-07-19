"""Australia AI Ethics Framework compliance module.

Implements the eight principles of Australia's voluntary AI Ethics Framework,
published by the Department of Industry, Innovation and Science (now
Department of Industry, Science and Resources) in 2019, and cross-referenced
with the Responsible AI Framework published by the Digital Transformation
Agency (2023).

The eight principles:
- PRIN-1: Human, societal and environmental wellbeing
- PRIN-2: Human-centred values
- PRIN-3: Fairness
- PRIN-4: Privacy protection and security
- PRIN-5: Reliability and safety
- PRIN-6: Transparency and explainability
- PRIN-7: Contestability
- PRIN-8: Accountability

Cross-referenced instruments:
- Australia's National AI Strategy (2021)
- Responsible AI Framework (Digital Transformation Agency, 2023)
- Privacy Act 1988 (AI-relevant provisions, 2024 reform)
- Anti-Discrimination Act obligations (Federal + State)

Reference: Australia's AI Ethics Framework — Department of Industry,
Innovation and Science (2019)
Responsible AI Framework — Digital Transformation Agency (2023)

Status: Voluntary; referenced in government procurement and APS AI guidance.

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
_AU_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # PRIN-1 — Human, societal and environmental wellbeing
    (
        "AU-AI P1-1",
        "Assess AI system impacts on individuals, communities, society, and "
        "the environment throughout the system lifecycle, including unintended "
        "or adverse consequences.",
        "Australia AI Ethics Framework, Principle 1 — Wellbeing",
        "RiskClassifier — impact assessment across individual, group, and societal risk tiers",
        True,
    ),
    (
        "AU-AI P1-2",
        "Give priority to human and societal wellbeing above commercial or "
        "operational objectives when conflicts arise in AI system design or use.",
        "Australia AI Ethics Framework, Principle 1 — Wellbeing",
        "GovernanceEngine — constitutional rules enforce wellbeing constraints on actions",
        True,
    ),
    # PRIN-2 — Human-centred values
    (
        "AU-AI P2-1",
        "Design, develop, and deploy AI systems that respect and uphold "
        "universal human rights, democratic institutions, and the diversity "
        "of individuals and communities.",
        "Australia AI Ethics Framework, Principle 2 — Human Values",
        "Constitution — governance policies embed human rights constraints",
        True,
    ),
    (
        "AU-AI P2-2",
        "Ensure AI systems do not use data or design choices that produce "
        "outcomes that are discriminatory, harmful, or undermine human dignity.",
        "Australia AI Ethics Framework, Principle 2 — Human Values",
        "GovernanceEngine — constitutional rules block discriminatory action classes",
        True,
    ),
    # PRIN-3 — Fairness
    (
        "AU-AI P3-1",
        "Identify and assess risks of unfair bias and disparate impact on "
        "protected groups under Australian anti-discrimination law throughout "
        "the AI system lifecycle.",
        "Australia AI Ethics Framework, Principle 3 — Fairness; "
        "Racial Discrimination Act 1975; Sex Discrimination Act 1984",
        "RiskClassifier — protected attribute risk flags",
        True,
    ),
    (
        "AU-AI P3-2",
        "Conduct disaggregated performance and outcome testing across "
        "demographic groups relevant to the deployment context.",
        "Australia AI Ethics Framework, Principle 3 — Fairness",
        None,
        True,
    ),
    (
        "AU-AI P3-3",
        "Implement technical and procedural controls to detect and correct "
        "unfair bias in training data, model outputs, and downstream decisions.",
        "Australia AI Ethics Framework, Principle 3 — Fairness",
        "GovernanceEngine — fairness rules monitor and block biased output patterns",
        True,
    ),
    # PRIN-4 — Privacy protection and security
    (
        "AU-AI P4-1",
        "Protect personal information processed by the AI system in accordance "
        "with the Privacy Act 1988, Australian Privacy Principles, and data "
        "minimisation best practices.",
        "Australia AI Ethics Framework, Principle 4 — Privacy; Privacy Act 1988 (Cth)",
        None,
        True,
    ),
    (
        "AU-AI P4-2",
        "Implement security measures to protect AI system data, models, and "
        "infrastructure from unauthorised access, tampering, and adversarial "
        "attacks.",
        "Australia AI Ethics Framework, Principle 4 — Security",
        "GovernanceEngine — circuit breakers protect against adversarial inputs",
        True,
    ),
    (
        "AU-AI P4-3",
        "Conduct privacy impact assessment (PIA) before deploying AI systems "
        "that process personal information or may affect individual privacy.",
        "Australia AI Ethics Framework, Principle 4 — Privacy; "
        "APP 1 (Office of the Australian Information Commissioner)",
        "RiskClassifier — risk tier assessment scopes privacy impact assessment",
        False,
    ),
    # PRIN-5 — Reliability and safety
    (
        "AU-AI P5-1",
        "Test AI systems extensively to ensure they perform reliably within "
        "their intended operational scope and handle edge cases, adversarial "
        "inputs, and distributional shift safely.",
        "Australia AI Ethics Framework, Principle 5 — Reliability and Safety",
        "GovernanceEngine — anomaly detection on unexpected or out-of-scope behaviour",
        True,
    ),
    (
        "AU-AI P5-2",
        "Implement fail-safe mechanisms that default to safe states when the "
        "AI system is uncertain, out of distribution, or encounters anomalies.",
        "Australia AI Ethics Framework, Principle 5 — Safety",
        "GovernanceEngine — severity-based blocking defaults to safe halt state",
        True,
    ),
    (
        "AU-AI P5-3",
        "Establish operational boundaries and monitor AI system behaviour in "
        "production; take corrective action promptly when boundaries are exceeded.",
        "Australia AI Ethics Framework, Principle 5 — Reliability",
        "GovernanceEngine — continuous monitoring with configurable alert thresholds",
        True,
    ),
    # PRIN-6 — Transparency and explainability
    (
        "AU-AI P6-1",
        "Ensure that those affected by AI decisions are made aware that AI "
        "is involved and are given information about the AI system's purpose, "
        "design, and how decisions are made.",
        "Australia AI Ethics Framework, Principle 6 — Transparency",
        "TransparencyDisclosure — AI system identification and purpose in system card",
        True,
    ),
    (
        "AU-AI P6-2",
        "Provide explanations of AI-assisted decisions at a level of detail "
        "appropriate to the decision's impact on the affected person.",
        "Australia AI Ethics Framework, Principle 6 — Explainability",
        "TransparencyDisclosure — decision-level explanation fields in system card",
        True,
    ),
    (
        "AU-AI P6-3",
        "Publish or make available documentation about AI system design, "
        "training data, validation methods, and limitations proportionate "
        "to the risk and public interest.",
        "Australia AI Ethics Framework, Principle 6 — Transparency",
        "TransparencyDisclosure — standardised system card with technical documentation",
        False,
    ),
    # PRIN-7 — Contestability
    (
        "AU-AI P7-1",
        "Enable those affected by AI-assisted decisions to contest outcomes "
        "through a genuine, accessible, and timely review process.",
        "Australia AI Ethics Framework, Principle 7 — Contestability",
        "HumanOversightGateway — contestation pathway with human review",
        True,
    ),
    (
        "AU-AI P7-2",
        "Provide clear information about how to challenge AI-assisted decisions "
        "and ensure the review process has genuine authority to change outcomes.",
        "Australia AI Ethics Framework, Principle 7 — Contestability",
        "HumanOversightGateway — documented review flow with override authority",
        True,
    ),
    # PRIN-8 — Accountability
    (
        "AU-AI P8-1",
        "Establish clear lines of accountability for AI system decisions, "
        "including designated responsible persons and documented governance "
        "structures.",
        "Australia AI Ethics Framework, Principle 8 — Accountability",
        "MACIEnforcer — role separation with designated accountability per action class",
        True,
    ),
    (
        "AU-AI P8-2",
        "Maintain audit trails and governance documentation sufficient to "
        "demonstrate compliance with AI ethics obligations and accountability "
        "to affected parties and regulators.",
        "Australia AI Ethics Framework, Principle 8 — Accountability",
        "AuditLog — tamper-evident lifecycle audit chain for accountability demonstration",
        True,
    ),
    (
        "AU-AI P8-3",
        "Review and improve AI governance practices regularly based on "
        "operational experience, incidents, and feedback from affected persons.",
        "Australia AI Ethics Framework, Principle 8 — Accountability",
        "GovernanceEngine — continuous lifecycle monitoring triggers governance review",
        False,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "AU-AI P1-1": (
        "acgs-lite RiskClassifier — impact assessment across individual, "
        "group, and societal risk tiers"
    ),
    "AU-AI P1-2": (
        "acgs-lite GovernanceEngine — constitutional rules enforce wellbeing "
        "constraints on agent actions"
    ),
    "AU-AI P2-1": (
        "acgs-lite Constitution — governance policies embed human rights "
        "constraints as version-controlled constitutional rules"
    ),
    "AU-AI P2-2": (
        "acgs-lite GovernanceEngine — constitutional rules block discriminatory "
        "action classes at the governance layer"
    ),
    "AU-AI P3-1": (
        "acgs-lite RiskClassifier — protected attribute risk flags identify "
        "potential anti-discrimination law exposure"
    ),
    "AU-AI P3-3": (
        "acgs-lite GovernanceEngine — fairness rules monitor and block biased "
        "output patterns in real time"
    ),
    "AU-AI P4-2": (
        "acgs-lite GovernanceEngine — circuit breakers protect AI system "
        "data and models from adversarial attacks"
    ),
    "AU-AI P4-3": (
        "acgs-lite RiskClassifier — risk tier assessment scopes privacy "
        "impact assessment obligations"
    ),
    "AU-AI P5-1": (
        "acgs-lite GovernanceEngine — anomaly detection on unexpected or out-of-scope behaviour"
    ),
    "AU-AI P5-2": (
        "acgs-lite GovernanceEngine — severity-based blocking defaults to "
        "safe halt state when uncertain or anomalous"
    ),
    "AU-AI P5-3": (
        "acgs-lite GovernanceEngine — continuous monitoring with configurable "
        "alert thresholds and corrective action triggers"
    ),
    "AU-AI P6-1": (
        "acgs-lite TransparencyDisclosure — AI system identification and "
        "purpose included in system card"
    ),
    "AU-AI P6-2": (
        "acgs-lite TransparencyDisclosure — decision-level explanation fields "
        "provide contextually appropriate information"
    ),
    "AU-AI P6-3": (
        "acgs-lite TransparencyDisclosure — standardised system card constitutes "
        "technical documentation for public disclosure"
    ),
    "AU-AI P7-1": (
        "acgs-lite HumanOversightGateway — contestation pathway with genuine "
        "human review capability"
    ),
    "AU-AI P7-2": (
        "acgs-lite HumanOversightGateway — documented review flow with "
        "override authority for affected individuals"
    ),
    "AU-AI P8-1": (
        "acgs-lite MACIEnforcer — role separation with designated accountability "
        "and escalation paths"
    ),
    "AU-AI P8-2": (
        "acgs-lite AuditLog — tamper-evident lifecycle audit chain provides "
        "accountability demonstration for regulators"
    ),
    "AU-AI P8-3": (
        "acgs-lite GovernanceEngine — continuous lifecycle monitoring triggers "
        "governance review on incidents or changes"
    ),
}


class AustraliaAIEthicsFramework:
    """Australia AI Ethics Framework (8 Principles) compliance assessor.

    Covers all eight Australian AI ethics principles: wellbeing, human values,
    fairness, privacy and security, reliability and safety, transparency,
    contestability, and accountability.

    Cross-references Privacy Act 1988, Australian Privacy Principles,
    and anti-discrimination legislation.

    Status: Voluntary; referenced in government AI procurement policy and
    Australian Public Service (APS) AI guidance.

    Usage::

        from acgs_lite.compliance.australia_ai_ethics import AustraliaAIEthicsFramework

        framework = AustraliaAIEthicsFramework()
        assessment = framework.assess({
            "system_id": "my-system",
            "jurisdiction": "australia",
        })
    """

    framework_id: str = "australia_ai_ethics"
    framework_name: str = "Australia AI Ethics Framework (8 Principles)"
    jurisdiction: str = "Australia"
    status: str = "voluntary"
    enforcement_date: str | None = None

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate Australia AI Ethics Framework checklist items."""
        return [
            ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            for ref, req, citation, feature, blocking in _AU_ITEMS
        ]

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full Australia AI Ethics Framework assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(
    fw: AustraliaAIEthicsFramework, checklist: list[ChecklistItem]
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
            if "PRIN-3" in item.ref:
                recs.append(
                    f"{item.ref}: Conduct disaggregated bias testing per "
                    f"Australian AI Ethics Framework Principle 3 (Fairness)."
                )
            elif "PRIN-4" in item.ref:
                recs.append(
                    f"{item.ref}: Ensure Privacy Act 1988 compliance and "
                    f"conduct privacy impact assessment."
                )
            elif "PRIN-5" in item.ref:
                recs.append(
                    f"{item.ref}: Implement reliability and safety testing "
                    f"including fail-safe mechanisms."
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
