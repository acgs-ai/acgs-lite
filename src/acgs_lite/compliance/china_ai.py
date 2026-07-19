"""China AI Governance Regulations compliance module.

Implements obligations from China's four major AI-specific regulations,
enforced by the Cyberspace Administration of China (CAC) and Ministry of
Industry and Information Technology (MIIT):

Reg-1: Provisions on the Administration of Algorithmic Recommendations
       (算法推荐服务管理规定) — Effective March 1, 2022
Reg-2: Provisions on the Administration of Deep Synthesis Internet
       Information Services (深度合成管理规定) — Effective January 10, 2023
Reg-3: Interim Measures for the Management of Generative Artificial
       Intelligence Services (生成式人工智能服务管理暂行办法) — Effective August 15, 2023
Reg-4: Personal Information Protection Law (PIPL) AI-relevant articles
       (个人信息保护法) — Effective November 1, 2021

Key obligations:
- Algorithm transparency labelling (Reg-1, Art.16; Reg-2, Art.17)
- Prohibitions on illegal content generation (Reg-3, Art.4)
- Training data legality and quality (Reg-3, Art.7)
- Deep-synthesis / AI-generated content labelling (Reg-2, Art.17)
- Automated decision-making transparency (PIPL Art.24)
- Opt-out from algorithmic recommendations (Reg-1, Art.17)
- Security assessment for generative AI (Reg-3, Art.17)
- Report mechanism for illegal content (Reg-3, Art.14)

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
_CHINA_AI_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # Reg-1: Algorithm Recommendation Provisions (2022)
    (
        "CN-ALG Art.4",
        "Algorithmic recommendation service providers shall not use algorithms "
        "to engage in unfair competition, disrupt market order, or discriminate "
        "based on user characteristics.",
        "Algorithm Recommendation Provisions, Article 4 (2022)",
        "GovernanceEngine — constitutional rules block discriminatory and anti-competitive actions",
        True,
    ),
    (
        "CN-ALG Art.7",
        "Establish algorithm security management systems, conduct periodic "
        "security assessments, and maintain records of algorithm training data "
        "sources and update history.",
        "Algorithm Recommendation Provisions, Article 7 (2022)",
        "AuditLog — tamper-evident algorithm update and training record",
        True,
    ),
    (
        "CN-ALG Art.14",
        "Do not use algorithm recommendations to push information that is "
        "false, harmful, illegal, or contrary to socialist core values.",
        "Algorithm Recommendation Provisions, Article 14 (2022)",
        "GovernanceEngine — constitutional content filtering rules",
        True,
    ),
    (
        "CN-ALG Art.16",
        "Label content generated or distributed by algorithmic recommendation "
        "systems to ensure users are aware of the algorithmic involvement.",
        "Algorithm Recommendation Provisions, Article 16 (2022)",
        "TransparencyDisclosure — algorithmic labelling in system card",
        True,
    ),
    (
        "CN-ALG Art.17",
        "Provide users with options to turn off algorithmic recommendations "
        "or adjust recommendation preferences; do not target illegal "
        "personalisation at minors.",
        "Algorithm Recommendation Provisions, Article 17 (2022)",
        None,
        True,
    ),
    # Reg-2: Deep Synthesis Provisions (2023)
    (
        "CN-DS Art.14",
        "Providers of deep synthesis services shall not generate content that "
        "undermines national security, disrupts social order, or infringes "
        "third-party rights.",
        "Deep Synthesis Provisions, Article 14 (2023)",
        "GovernanceEngine — constitutional rules block prohibited content generation classes",
        True,
    ),
    (
        "CN-DS Art.17",
        "Label AI-generated or AI-edited images, audio, video, and text "
        "content with prominent AI-generated content markers to prevent "
        "public deception.",
        "Deep Synthesis Provisions, Article 17 (2023)",
        "TransparencyDisclosure — AI-generated content labelling fields",
        True,
    ),
    (
        "CN-DS Art.18",
        "Implement content security management systems for deep synthesis "
        "services, including data security and personal information protection "
        "measures.",
        "Deep Synthesis Provisions, Article 18 (2023)",
        "GovernanceEngine — security controls and anomaly detection",
        True,
    ),
    # Reg-3: Generative AI Measures (2023)
    (
        "CN-GAI Art.4",
        "Generative AI service providers must not generate content that "
        "incites subversion of state power, undermines national unity, "
        "or contains false information.",
        "Generative AI Interim Measures, Article 4 (2023)",
        "GovernanceEngine — constitutional content prohibition rules",
        True,
    ),
    (
        "CN-GAI Art.7",
        "Use legitimately sourced training data; respect intellectual property "
        "rights; do not use personal data without a lawful basis; take measures "
        "to improve training data quality and truthfulness.",
        "Generative AI Interim Measures, Article 7 (2023)",
        None,
        True,
    ),
    (
        "CN-GAI Art.9",
        "Inform users clearly that they are interacting with a generative AI "
        "system. Do not impersonate humans or disguise the AI nature of the "
        "service.",
        "Generative AI Interim Measures, Article 9 (2023)",
        "TransparencyDisclosure — AI system identification in user-facing notices",
        True,
    ),
    (
        "CN-GAI Art.14",
        "Establish complaint and report mechanisms for users to flag "
        "illegal or non-compliant content; process complaints promptly "
        "and preserve records.",
        "Generative AI Interim Measures, Article 14 (2023)",
        "HumanOversightGateway — complaint and report pathway with audit trail",
        True,
    ),
    (
        "CN-GAI Art.17",
        "Generative AI services with significant public impact or more than "
        "one million users must file a security assessment with the CAC "
        "before public release.",
        "Generative AI Interim Measures, Article 17 (2023)",
        None,
        False,  # depends on scale/impact threshold
    ),
    # PIPL AI-relevant articles (2021)
    (
        "CN-PIPL Art.24",
        "When using personal information for automated decision-making, "
        "ensure transparency of decision rules; do not apply unreasonably "
        "different treatment to individuals in transactions; provide "
        "opt-out and human review for decisions with significant impact.",
        "Personal Information Protection Law, Article 24 (2021)",
        "HumanOversightGateway — human review pathway for impactful automated decisions",
        True,
    ),
    (
        "CN-PIPL Art.24(2)",
        "For automated decisions with significant impact on personal rights "
        "or interests, provide individuals with the ability to request "
        "explanation and human review.",
        "Personal Information Protection Law, Article 24(2) (2021)",
        "TransparencyDisclosure — decision explanation fields and review pathway",
        True,
    ),
    (
        "CN-PIPL Art.51",
        "Personal information processors (controllers) must implement "
        "internal management systems, data classification, technical "
        "security measures, and conduct regular compliance audits for "
        "AI processing of personal information.",
        "Personal Information Protection Law, Article 51 (2021)",
        "AuditLog — compliance audit records with tamper-evident integrity",
        True,
    ),
    (
        "CN-PIPL Art.55",
        "Conduct personal information protection impact assessment (PIPIA) "
        "prior to processing personal information for automated decisions, "
        "and retain assessment records for at least three years.",
        "Personal Information Protection Law, Article 55 (2021)",
        "RiskClassifier — impact assessment scopes PIPIA obligations",
        True,
    ),
    # Global AI Governance Initiative (CN-GAIG)
    (
        "CN-GAIG P1",
        "AI technology shall be human-centred and intelligent for good, "
        "developed in a way that is safe, reliable, controllable, and fair.",
        "Global AI Governance Initiative, Principle 1",
        "GovernanceEngine — constitutional safety and fairness constraints",
        False,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "CN-ALG Art.4": (
        "acgs-lite GovernanceEngine — constitutional rules block discriminatory "
        "and anti-competitive action classes"
    ),
    "CN-ALG Art.7": (
        "acgs-lite AuditLog — tamper-evident algorithm update and training "
        "data records with update history"
    ),
    "CN-ALG Art.14": (
        "acgs-lite GovernanceEngine — constitutional content filtering rules "
        "block false and harmful content"
    ),
    "CN-ALG Art.16": (
        "acgs-lite TransparencyDisclosure — algorithmic involvement labelling fields in system card"
    ),
    "CN-DS Art.14": (
        "acgs-lite GovernanceEngine — constitutional rules block prohibited "
        "content generation classes"
    ),
    "CN-DS Art.17": (
        "acgs-lite TransparencyDisclosure — AI-generated content labelling fields in system card"
    ),
    "CN-DS Art.18": (
        "acgs-lite GovernanceEngine — security controls and anomaly detection "
        "for deep synthesis services"
    ),
    "CN-GAI Art.4": (
        "acgs-lite GovernanceEngine — constitutional content prohibition rules "
        "block illegal generative content"
    ),
    "CN-GAI Art.9": (
        "acgs-lite TransparencyDisclosure — AI system identification in user-facing notices"
    ),
    "CN-GAI Art.14": (
        "acgs-lite HumanOversightGateway — complaint and report pathway "
        "with audit trail and escalation"
    ),
    "CN-PIPL Art.24": (
        "acgs-lite HumanOversightGateway — human review pathway for impactful "
        "automated decisions supports PIPL opt-out and review obligations"
    ),
    "CN-PIPL Art.24(2)": (
        "acgs-lite TransparencyDisclosure — decision explanation fields and "
        "HumanOversightGateway review pathway"
    ),
    "CN-PIPL Art.51": (
        "acgs-lite AuditLog — compliance audit records with tamper-evident "
        "integrity for regulatory review"
    ),
    "CN-PIPL Art.55": (
        "acgs-lite RiskClassifier — impact assessment scopes PIPIA obligations per PIPL Article 55"
    ),
    "CN-GAIG P1": (
        "acgs-lite GovernanceEngine — constitutional rules for safety, "
        "reliability, controllability, and fairness"
    ),
}


class ChinaAIFramework:
    """China AI Governance Regulations compliance assessor.

    Covers Algorithm Recommendation Provisions (2022), Deep Synthesis
    Provisions (2023), Generative AI Interim Measures (2023), and
    PIPL AI-relevant articles (2021).

    Status: All four instruments enacted and enforced by CAC.

    Penalties: PIPL — up to CNY 50 million or 5% of prior-year revenue;
    Generative AI Measures: no standalone fines; penalties under CSL/DSL/PIPL,
    else warnings, orders to correct, or service suspension (Art 21).

    Usage::

        from acgs_lite.compliance.china_ai import ChinaAIFramework

        framework = ChinaAIFramework()
        assessment = framework.assess({
            "system_id": "my-system",
            "jurisdiction": "china",
        })
    """

    framework_id: str = "china_ai"
    framework_name: str = "China AI Governance Regulations (Algorithmic Recommendations + Deep Synthesis + GenAI + PIPL)"
    jurisdiction: str = "China"
    status: str = "enacted"
    enforcement_date: str | None = "2022-03-01"  # First regulation effective date

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate China AI regulations checklist items."""
        is_generative = system_description.get("is_generative_ai", True)
        items: list[ChecklistItem] = []
        for ref, req, citation, feature, blocking in _CHINA_AI_ITEMS:
            item = ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            # All CN-GAI articles only apply to generative AI services
            _generative_refs = {r for r, *_ in _CHINA_AI_ITEMS if r.startswith("CN-GAI")}
            if ref in _generative_refs and not is_generative:
                item.mark_not_applicable("Not a generative AI service.")
            items.append(item)
        return items

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP and item.status != ChecklistStatus.NOT_APPLICABLE:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full China AI regulations compliance assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(fw: ChinaAIFramework, checklist: list[ChecklistItem]) -> FrameworkAssessment:
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
            if "CN-GAI Art.7" in item.ref:
                recs.append(
                    f"{item.ref}: Review training data sources for IP compliance "
                    f"and legality under Generative AI Interim Measures Art.7."
                )
            elif "CN-ALG Art.17" in item.ref:
                recs.append(
                    f"{item.ref}: Implement user opt-out controls for algorithmic "
                    f"recommendations per Algorithm Recommendation Provisions Art.17."
                )
            elif "CN-PIPL Art.55" in item.ref:
                recs.append(
                    f"{item.ref}: Conduct Personal Information Protection Impact "
                    f"Assessment and retain records for 3 years (PIPL Art.55)."
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
