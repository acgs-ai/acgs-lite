"""EU Digital Operational Resilience Act (DORA) compliance module.

Implements key ICT risk management obligations for financial entities
operating AI-driven systems under DORA:

- Article 6:  ICT risk management framework
- Article 8:  Identification of ICT assets and third-party dependencies
- Article 9:  Protection and prevention
- Article 10: Detection of anomalous activities
- Article 11: Response and recovery
- Article 12: Backup policies and recovery procedures
- Article 17: ICT incident management process
- Article 18: Classification of ICT-related incidents
- Article 19: Reporting of major ICT-related incidents
- Article 26: Advanced testing (threat-led penetration testing)
- Article 28: Third-party ICT risk management
- Article 30: Contract requirements with ICT third-party service providers

Scope: Credit institutions, payment institutions, e-money institutions,
investment firms, insurance/re-insurance undertakings, crypto-asset service
providers, and other financial entities operating in the EU.

Reference: Regulation (EU) 2022/2554 — Digital Operational Resilience Act
Applicable from: 17 January 2025

Penalties for financial entities are set by member states (Arts 50-52);
critical ICT third-party providers face periodic penalty payments up to 1%
of average daily worldwide turnover (Art 35(8)).

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
_DORA_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # Article 6 — ICT risk management framework
    # Article 5 — ICT governance (added for test compatibility)
    (
        "DORA Art.5(1)",
        "Financial entities shall have in place an internal governance and "
        "control framework that ensures effective and prudent management of "
        "all ICT risks.",
        "DORA Article 5(1)",
        "GovernanceEngine — automated governance control framework",
        True,
    ),
    (
        "DORA Art.6(1)",
        "Have in place an internal governance and control framework ensuring "
        "an effective and prudent management of ICT risk, including for "
        "AI-driven decision systems.",
        "Regulation (EU) 2022/2554, Article 6(1)",
        "GovernanceEngine — constitutional governance framework for ICT risk control",
        True,
    ),
    (
        "DORA Art.6(4)",
        "Establish, implement, and maintain an ICT risk management framework "
        "as part of the overall risk management system; review and update it "
        "after each major ICT disruption.",
        "Regulation (EU) 2022/2554, Article 6(4)",
        "Constitution — version-controlled governance policy with hash integrity",
        True,
    ),
    (
        "DORA Art.6(8)",
        "Perform thorough ICT risk assessments following major changes in "
        "network/infrastructure, operational processes, or AI system scope.",
        "Regulation (EU) 2022/2554, Article 6(8)",
        "RiskClassifier — automated risk classification on system configuration changes",
        True,
    ),
    # Article 8 — Identification
    (
        "DORA Art.8(1)",
        "Identify, classify, and document all ICT assets — hardware, software, "
        "data assets, and AI models — including their criticality and "
        "interdependencies.",
        "Regulation (EU) 2022/2554, Article 8(1)",
        None,
        True,
    ),
    (
        "DORA Art.8(4)",
        "Map all information assets and ICT assets supporting critical and "
        "important functions; maintain this map continuously.",
        "Regulation (EU) 2022/2554, Article 8(4)",
        None,
        True,
    ),
    # Article 9 — Protection and prevention
    (
        "DORA Art.9(2)",
        "Establish, document, and implement ICT security policies, procedures, "
        "and tools to protect ICT systems from cyberattacks, including AI "
        "model tampering and adversarial inputs.",
        "Regulation (EU) 2022/2554, Article 9(2)",
        "GovernanceEngine — circuit breakers protect against malicious inputs",
        True,
    ),
    (
        "DORA Art.9(4)(b)",
        "Implement dedicated and up-to-date antivirus, anti-malware, intrusion "
        "detection, and data-loss prevention solutions.",
        "Regulation (EU) 2022/2554, Article 9(4)(b)",
        None,
        True,
    ),
    (
        "DORA Art.9(4)(c)",
        "Implement patch management and source code review procedures; apply "
        "security patches within a defined time frame based on criticality.",
        "Regulation (EU) 2022/2554, Article 9(4)(c)",
        None,
        True,
    ),
    # Article 10 — Detection
    (
        "DORA Art.10(1)",
        "Implement mechanisms to promptly detect anomalous activities, "
        "ICT-related incidents, and potential single points of failure, "
        "including in AI inference pipelines.",
        "Regulation (EU) 2022/2554, Article 10(1)",
        "GovernanceEngine — anomaly detection on agent behaviour and outputs",
        True,
    ),
    (
        "DORA Art.10(2)",
        "Enable multi-layered controls with defined alert thresholds, "
        "response criteria, and processes for prompt escalation.",
        "Regulation (EU) 2022/2554, Article 10(2)",
        "GovernanceEngine — severity-based escalation tiers with configurable thresholds",
        True,
    ),
    # Article 11 — Response and recovery
    (
        "DORA Art.11(1)",
        "Have in place a comprehensive ICT business continuity policy with "
        "documented crisis communication procedures, business impact analysis, "
        "and crisis management plans.",
        "Regulation (EU) 2022/2554, Article 11(1)",
        None,
        True,
    ),
    (
        "DORA Art.11(2)",
        "Implement ICT continuity plans that include measures to maintain or "
        "restore critical functions during major ICT incidents, including "
        "AI system outages.",
        "Regulation (EU) 2022/2554, Article 11(2)",
        None,
        True,
    ),
    (
        "DORA Art.11(6)",
        "Test ICT continuity plans at least annually; adjust them based on "
        "test outcomes and changing threat landscapes.",
        "Regulation (EU) 2022/2554, Article 11(6)",
        None,
        False,
    ),
    # Article 12 — Backup policies
    (
        "DORA Art.12(1)",
        "Establish backup policies specifying scope and frequency of backups "
        "aligned with recovery time (RTO) and recovery point objectives (RPO).",
        "Regulation (EU) 2022/2554, Article 12(1)",
        None,
        True,
    ),
    (
        "DORA Art.12(3)",
        "Test backup and restoration procedures at least annually; document "
        "results. Backups of AI model artefacts shall be included.",
        "Regulation (EU) 2022/2554, Article 12(3)",
        None,
        False,
    ),
    # Article 17 — ICT-related incident reporting
    (
        "DORA Art.17(1)",
        "Establish and implement an ICT-related incident management process "
        "for the detection, management, and notification of incidents.",
        "Regulation (EU) 2022/2554, Article 17(1)",
        "AuditLog — tamper-evident event log supports incident investigation",
        True,
    ),
    (
        "DORA Art.19",
        "Report major ICT-related incidents to the competent authority and "
        "notify affected clients without undue delay.",
        "Regulation (EU) 2022/2554, Article 19",
        None,
        True,
    ),
    # Article 18 — Classification of incidents
    (
        "DORA Art.18(1)",
        "Classify ICT-related incidents and determine their impact using "
        "criteria including number of clients affected, data loss, "
        "criticality of services disrupted, and economic impact.",
        "Regulation (EU) 2022/2554, Article 18(1)",
        "RiskClassifier — incident severity classification with impact dimensions",
        True,
    ),
    # Article 26 — Advanced testing (TLPT)
    (
        "DORA Art.26(1)",
        "Significant financial entities shall conduct threat-led penetration "
        "testing (TLPT) at least every three years, covering live production "
        "systems including AI workloads.",
        "Regulation (EU) 2022/2554, Article 26(1)",
        None,
        False,  # only for significant entities
    ),
    # Article 28 — Third-party ICT risk management
    (
        "DORA Art.28(2)",
        "Adopt and regularly review a strategy on ICT third-party risk, "
        "including a policy for use of ICT services supporting critical "
        "functions (e.g. cloud-hosted AI inference).",
        "Regulation (EU) 2022/2554, Article 28(2)",
        None,
        True,
    ),
    (
        "DORA Art.28(4)",
        "Maintain an up-to-date register of all contractual arrangements with "
        "ICT third-party service providers, distinguishing critical and "
        "non-critical providers.",
        "Regulation (EU) 2022/2554, Article 28(4)",
        None,
        True,
    ),
    # Article 30 — Contract provisions
    (
        "DORA Art.30(2)",
        "Contracts with ICT third-party providers must include provisions on "
        "service description, locations of data processing, sub-contracting "
        "arrangements, and exit strategies.",
        "Regulation (EU) 2022/2554, Article 30(2)",
        None,
        True,
    ),
    (
        "DORA Art.30(3)",
        "Include full service level descriptions with quantitative and "
        "qualitative performance targets (uptime, RTO/RPO), audit rights, "
        "and termination rights for the regulator.",
        "Regulation (EU) 2022/2554, Article 30(3)",
        None,
        False,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "DORA Art.5(1)": (
        "acgs-lite GovernanceEngine — automated governance and ICT risk "
        "management control framework with constitutional enforcement"
    ),
    "DORA Art.6(1)": (
        "acgs-lite GovernanceEngine — provides constitutional governance "
        "framework implementing prudent ICT risk management and oversight"
    ),
    "DORA Art.6(4)": (
        "acgs-lite Constitution — version-controlled governance policy with "
        "hash integrity ensures auditable, up-to-date risk framework"
    ),
    "DORA Art.6(8)": (
        "acgs-lite RiskClassifier — automated risk re-classification triggered "
        "on configuration changes supports the post-change assessment obligation"
    ),
    "DORA Art.9(2)": (
        "acgs-lite GovernanceEngine — circuit breakers and input validation "
        "protect against adversarial inputs and ICT security threats"
    ),
    "DORA Art.10(1)": (
        "acgs-lite GovernanceEngine — real-time anomaly detection on agent "
        "behaviour, outputs, and inference pipeline events"
    ),
    "DORA Art.10(2)": (
        "acgs-lite GovernanceEngine — severity-based escalation tiers with "
        "configurable thresholds enable multi-layered alert controls"
    ),
    "DORA Art.17(1)": (
        "acgs-lite AuditLog — tamper-evident JSONL event log provides "
        "structured incident history for investigation and notification"
    ),
    "DORA Art.18(1)": (
        "acgs-lite RiskClassifier — incident severity classification with "
        "impact scoring across data loss, service, and economic dimensions"
    ),
}


class DORAFramework:
    """EU Digital Operational Resilience Act (DORA) compliance assessor.

    Covers ICT risk management framework, identification, protection,
    detection, response, incident reporting, and third-party risk
    management obligations relevant to AI-driven financial services.

    Status: Enacted; applicable from 17 January 2025.

    Penalties for financial entities are set by member states (Arts 50-52);
    critical ICT third-party providers face periodic penalty payments up to
    1% of average daily worldwide turnover (Art 35(8)).

    Usage::

        from acgs_lite.compliance.dora import DORAFramework

        framework = DORAFramework()
        assessment = framework.assess({
            "system_id": "my-fintech-ai",
            "is_significant_entity": True,
        })
    """

    framework_id: str = "dora"
    framework_name: str = "EU Digital Operational Resilience Act (DORA)"
    jurisdiction: str = "European Union"
    status: str = "enacted"
    enforcement_date: str | None = "2025-01-17"

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate DORA checklist items.

        TLPT obligation (Art. 26(1)) is only required for significant entities.
        """
        is_significant = system_description.get("is_significant_entity", True)
        items: list[ChecklistItem] = []
        for ref, req, citation, feature, blocking in _DORA_ITEMS:
            item = ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            # TLPT only required for significant entities
            if ref == "DORA Art.26(1)" and not is_significant:
                item.mark_not_applicable("Not a significant entity; TLPT not required.")
            items.append(item)
        return items

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP and item.status != ChecklistStatus.NOT_APPLICABLE:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full DORA compliance assessment."""
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(
    fw: DORAFramework,
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
            if "Art.6" in item.ref or "Art.8" in item.ref:
                recs.append(
                    f"{item.ref}: Establish documented ICT risk management "
                    f"framework and asset inventory per DORA Chapter II."
                )
            elif "Art.9" in item.ref:
                recs.append(
                    f"{item.ref}: Implement ICT security policies with patch "
                    f"management and adversarial input protection."
                )
            elif "Art.11" in item.ref or "Art.12" in item.ref:
                recs.append(
                    f"{item.ref}: Document and test business continuity and "
                    f"backup/recovery procedures including AI workloads."
                )
            elif "Art.17" in item.ref or "Art.18" in item.ref:
                recs.append(
                    f"{item.ref}: Implement incident classification and "
                    f"regulatory reporting procedures per DORA Chapter III."
                )
            elif "Art.28" in item.ref or "Art.30" in item.ref:
                recs.append(
                    f"{item.ref}: Register ICT third parties and update "
                    f"contracts to include DORA-mandated provisions."
                )
    return tuple(recs)
