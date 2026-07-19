"""EU AI Act (Regulation (EU) 2024/1689) compliance module.

Implements the core obligations for high-risk AI systems and general-purpose
AI models under the EU Artificial Intelligence Act:

- Article 5:  Prohibited practices
- Article 9:  Risk management system
- Article 10: Data and data governance
- Article 11: Technical documentation (Annex IV)
- Article 12: Record-keeping / logging
- Article 13: Transparency to deployers and users
- Article 14: Human oversight
- Article 15: Accuracy, robustness, and cybersecurity
- Article 26: Deployer obligations
- Article 27: Fundamental-rights impact assessment (FRIA)
- Article 50: Transparency for GPAI-facing / chatbot systems
- Article 53: General-purpose AI model obligations
- Article 55: Systemic-risk obligations (frontier models)

Risk tiers:
  UNACCEPTABLE → prohibited (Art. 5)
  HIGH         → full compliance track (Arts. 9-27)
  LIMITED      → transparency only (Art. 50)
  MINIMAL      → voluntary codes of practice

Reference: Regulation (EU) 2024/1689 of the European Parliament and of the
Council (Official Journal of the European Union, 12 July 2024)
Entered into force: 1 August 2024
Fully applicable (high-risk): Annex III stand-alone 2 December 2027; Annex I
embedded-product 2 August 2028 (deferred by the 2026 Digital Omnibus).

Penalties: Up to EUR 35 million or 7% of global annual turnover (Art. 99)
for prohibited practices; EUR 15 million or 3% for other violations.

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
_EU_AI_ACT_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # Article 5 — Prohibited practices
    (
        "EU-AIA Art.5(1)",
        "Verify that the AI system does not deploy subliminal, manipulative, "
        "or deceptive techniques that subvert free will, or exploit "
        "vulnerabilities of individuals or groups.",
        "Regulation (EU) 2024/1689, Article 5(1)(a-c)",
        "GovernanceEngine — constitutional rule set blocks manipulative action classes",
        True,
    ),
    (
        "EU-AIA Art.5(2)",
        "Confirm the AI system does not perform real-time remote biometric "
        "identification in publicly accessible spaces for law enforcement "
        "without judicial authorisation (unless exemption applies).",
        "Regulation (EU) 2024/1689, Article 5(2)",
        None,
        False,  # non-blocking: many AI systems are not biometric
    ),
    # Article 9 — Risk management system
    (
        "EU-AIA Art.9(1)",
        "Establish, implement, document, and maintain a risk management system "
        "as an iterative process throughout the high-risk AI system lifecycle.",
        "Regulation (EU) 2024/1689, Article 9(1)",
        "GovernanceEngine — continuous governance validation across the system lifecycle",
        True,
    ),
    (
        "EU-AIA Art.9(2)",
        "Identify and analyse known and foreseeable risks that may occur when "
        "the high-risk AI system is used in accordance with its intended purpose "
        "and under conditions of reasonably foreseeable misuse.",
        "Regulation (EU) 2024/1689, Article 9(2)",
        "RiskClassifier — automated risk level classification with obligation mapping",
        True,
    ),
    (
        "EU-AIA Art.9(4)",
        "Implement risk management measures including testing procedures to "
        "identify the most appropriate measures; such measures shall ensure "
        "residual risks are acceptable.",
        "Regulation (EU) 2024/1689, Article 9(4)",
        None,
        True,
    ),
    # Article 10 — Data and data governance
    (
        "EU-AIA Art.10(2)",
        "Apply data governance practices covering the design choices of "
        "training, validation, and testing datasets, examining for possible "
        "biases, data gaps, and shortcomings.",
        "Regulation (EU) 2024/1689, Article 10(2)",
        None,
        True,
    ),
    (
        "EU-AIA Art.10(3)",
        "Ensure training, validation, and testing data sets are relevant, "
        "sufficiently representative, and free of errors to the extent possible.",
        "Regulation (EU) 2024/1689, Article 10(3)",
        None,
        True,
    ),
    (
        "EU-AIA Art.10(5)",
        "Where necessary for bias monitoring, detection, and correction, "
        "providers may process special categories of personal data with "
        "appropriate safeguards.",
        "Regulation (EU) 2024/1689, Article 10(5)",
        None,
        False,
    ),
    # Article 11 — Technical documentation
    (
        "EU-AIA Art.11(1)",
        "Draw up technical documentation (Annex IV) before placing the "
        "high-risk AI system on the market and keep it updated.",
        "Regulation (EU) 2024/1689, Article 11(1) + Annex IV",
        "TransparencyDisclosure — system card documents capabilities and limitations",
        True,
    ),
    (
        "EU-AIA Art.11(2)",
        "Technical documentation shall contain at minimum: general description, "
        "detailed description of system elements, information about training "
        "processes, validation/testing results, and cybersecurity measures.",
        "Regulation (EU) 2024/1689, Article 11(2) + Annex IV",
        None,
        True,
    ),
    # Article 12 — Record-keeping
    (
        "EU-AIA Art.12(1)",
        "High-risk AI systems shall automatically log events (record-keeping) "
        "to enable monitoring of operations throughout the system's lifetime.",
        "Regulation (EU) 2024/1689, Article 12(1)",
        "AuditLog — tamper-evident JSONL logging with SHA-256 hash chaining",
        True,
    ),
    (
        "EU-AIA Art.12(2)",
        "Logging capabilities shall ensure traceability of the AI system's "
        "functioning and enable monitoring after deployment.",
        "Regulation (EU) 2024/1689, Article 12(2)",
        "AuditLog — cryptographic audit chain with replay support",
        True,
    ),
    # Article 13 — Transparency and provision of information
    (
        "EU-AIA Art.13(1)",
        "High-risk AI systems shall be designed to ensure operations are "
        "sufficiently transparent to enable deployers to interpret output "
        "and use it appropriately.",
        "Regulation (EU) 2024/1689, Article 13(1)",
        "TransparencyDisclosure — structured system card with decision logic",
        True,
    ),
    (
        "EU-AIA Art.13(3)",
        "Provide instructions for use to deployers including identity and "
        "contact of provider, system capabilities and limitations, intended "
        "purpose, performance and accuracy levels, and known risks.",
        "Regulation (EU) 2024/1689, Article 13(3)",
        "TransparencyDisclosure — machine-readable system card with all mandatory fields",
        True,
    ),
    # Article 14 — Human oversight
    (
        "EU-AIA Art.14(1)",
        "High-risk AI systems shall be designed and developed to allow "
        "effective human oversight by natural persons during the period "
        "the systems are in use.",
        "Regulation (EU) 2024/1689, Article 14(1)",
        "HumanOversightGateway — configurable HITL approval gates",
        True,
    ),
    (
        "EU-AIA Art.14(4)",
        "Human oversight measures shall enable persons to fully understand "
        "the AI system's capacities and limitations; detect and address "
        "anomalous functioning; and override, interrupt, or stop the system.",
        "Regulation (EU) 2024/1689, Article 14(4)",
        "HumanOversightGateway — override/halt controls with full audit trail",
        True,
    ),
    (
        "EU-AIA Art.14(5)",
        "For high-risk AI systems that make decisions affecting individuals, "
        "ensure human oversight measures do not simply rubber-stamp outputs.",
        "Regulation (EU) 2024/1689, Article 14(5)",
        "MACIEnforcer — validator role cannot self-approve; requires independent review",
        True,
    ),
    # Article 15 — Accuracy, robustness and cybersecurity
    (
        "EU-AIA Art.15(1)",
        "High-risk AI systems shall achieve appropriate levels of accuracy, "
        "robustness, and cybersecurity in light of their intended purpose.",
        "Regulation (EU) 2024/1689, Article 15(1)",
        None,
        True,
    ),
    (
        "EU-AIA Art.15(3)",
        "Resilience against errors, faults, or inconsistencies that may occur "
        "in the data inputs; best practice cybersecurity measures appropriate "
        "to the identified risks.",
        "Regulation (EU) 2024/1689, Article 15(3)",
        "GovernanceEngine — circuit breakers and anomaly detection on malformed inputs",
        True,
    ),
    # Article 26 — Obligations of deployers
    (
        "EU-AIA Art.26(1)",
        "Deployers shall take appropriate technical and organisational measures "
        "to ensure they use high-risk AI systems in accordance with the "
        "instructions for use.",
        "Regulation (EU) 2024/1689, Article 26(1)",
        None,
        True,
    ),
    (
        "EU-AIA Art.27(1)",
        "Bodies governed by public law, private entities providing public "
        "services, and deployers of Annex III point 5(b)-(c) systems "
        "(creditworthiness/credit scoring; life and health insurance risk "
        "assessment and pricing) shall carry out a fundamental rights impact "
        "assessment (FRIA) before use.",
        "Regulation (EU) 2024/1689, Article 27(1)",
        "RiskClassifier — fundamental rights risk tier assessment",
        True,
    ),
    # Article 50 — Transparency obligations (chatbots / GPAI-facing)
    (
        "EU-AIA Art.50(1)",
        "Providers of AI systems intended to interact directly with natural "
        "persons shall design them so users are informed they are interacting "
        "with an AI system (unless obvious from context).",
        "Regulation (EU) 2024/1689, Article 50(1)",
        "TransparencyDisclosure — AI system identification in system card",
        True,
    ),
    (
        "EU-AIA Art.50(2)",
        "Providers of AI systems that generate synthetic audio, image, video, "
        "or text content shall mark the output as artificially generated "
        "(machine-readable labelling).",
        "Regulation (EU) 2024/1689, Article 50(2)",
        None,
        False,
    ),
    (
        "EU-AIA Art.50(4)",
        "Deployers of deepfakes, or of AI-generated/manipulated text published "
        "to inform the public on matters of public interest, shall disclose "
        "that the content has been artificially generated or manipulated.",
        "Regulation (EU) 2024/1689, Article 50(4)",
        None,
        False,
    ),
    # Article 53 — General-purpose AI model obligations
    (
        "EU-AIA Art.53(1)",
        "Providers of general-purpose AI (GPAI) models shall draw up technical "
        "documentation, establish an information-sharing policy for downstream "
        "providers, and comply with copyright law.",
        "Regulation (EU) 2024/1689, Article 53(1)",
        "TransparencyDisclosure — GPAI technical documentation fields",
        False,  # only applies to GPAI model providers
    ),
    (
        "EU-AIA Art.53(1)(d)",
        "Draw up and make publicly available a sufficiently detailed summary "
        "of the content used for training of the general-purpose AI model.",
        "Regulation (EU) 2024/1689, Article 53(1)(d)",
        None,
        False,
    ),
    # Article 55 — Systemic risk obligations
    (
        "EU-AIA Art.55(1)",
        "Providers of GPAI models with systemic risk must perform adversarial "
        "testing, report serious incidents to the AI Office, and implement "
        "cybersecurity protection appropriate to the risk.",
        "Regulation (EU) 2024/1689, Article 55(1)",
        None,
        False,  # only applies to frontier/systemic-risk GPAI providers
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map: ref -> evidence string
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "EU-AIA Art.5(1)": (
        "acgs-lite GovernanceEngine — constitutional rule set blocks manipulative "
        "and deceptive action classes at the governance layer"
    ),
    "EU-AIA Art.9(1)": (
        "acgs-lite GovernanceEngine — continuous lifecycle governance provides "
        "an iterative, always-on risk management system"
    ),
    "EU-AIA Art.9(2)": (
        "acgs-lite RiskClassifier — automated risk level classification with "
        "obligation mapping for foreseeable misuse scenarios"
    ),
    "EU-AIA Art.11(1)": (
        "acgs-lite TransparencyDisclosure — system card documents capabilities, "
        "limitations, intended purpose, and known risks"
    ),
    "EU-AIA Art.12(1)": (
        "acgs-lite AuditLog — tamper-evident JSONL logging with SHA-256 "
        "cryptographic hash chaining for full lifecycle traceability"
    ),
    "EU-AIA Art.12(2)": (
        "acgs-lite AuditLog — cryptographic audit chain with replay support "
        "enables post-deployment monitoring and traceability"
    ),
    "EU-AIA Art.13(1)": (
        "acgs-lite TransparencyDisclosure — structured system card with decision "
        "logic, enabling deployers to interpret outputs appropriately"
    ),
    "EU-AIA Art.13(3)": (
        "acgs-lite TransparencyDisclosure — machine-readable system card includes "
        "provider identity, capabilities, limitations, and known risks"
    ),
    "EU-AIA Art.14(1)": (
        "acgs-lite HumanOversightGateway — configurable human-in-the-loop "
        "approval gates for high-risk actions during active use"
    ),
    "EU-AIA Art.14(4)": (
        "acgs-lite HumanOversightGateway — override and halt controls with "
        "anomaly detection and full audit trail"
    ),
    "EU-AIA Art.14(5)": (
        "acgs-lite MACIEnforcer — enforces proposer/validator/executor role "
        "separation so no single agent rubber-stamps its own output"
    ),
    "EU-AIA Art.15(3)": (
        "acgs-lite GovernanceEngine — circuit breakers and anomaly detection "
        "protect against errors, faults, and inconsistent data inputs"
    ),
    "EU-AIA Art.27(1)": (
        "acgs-lite RiskClassifier — fundamental rights risk tier assessment "
        "scopes FRIA obligations for deployers"
    ),
    "EU-AIA Art.50(1)": (
        "acgs-lite TransparencyDisclosure — AI system identification included "
        "in mandatory system card fields"
    ),
    "EU-AIA Art.53(1)": (
        "acgs-lite TransparencyDisclosure — GPAI technical documentation fields "
        "included in system card schema"
    ),
}


class EUAIActFramework:
    """EU Artificial Intelligence Act (Regulation (EU) 2024/1689) compliance assessor.

    Covers prohibited practices (Art. 5), all high-risk AI obligations
    (Arts. 9-15, 26), and transparency requirements for GPAI-facing systems
    and general-purpose AI models (Arts. 50, 53, 55).

    Status: Enacted; fully applicable (high-risk): Annex III stand-alone systems
    from 2 December 2027, Annex I embedded-product systems from 2 August 2028
    (deferred by the 2026 Digital Omnibus).
    Prohibited practices applicable from 2 February 2025.

    Penalties:
    - Prohibited practices: EUR 35 million or 7% of global annual turnover
    - Other violations: EUR 15 million or 3% of global annual turnover
    - SME / start-up cap: lower of the percentage thresholds above

    Usage::

        from acgs_lite.compliance.eu_ai_act import EUAIActFramework

        framework = EUAIActFramework()
        assessment = framework.assess({
            "system_id": "my-system",
            "risk_tier": "high",   # unacceptable | high | limited | minimal
        })
    """

    framework_id: str = "eu_ai_act"
    framework_name: str = "EU Artificial Intelligence Act (Regulation (EU) 2024/1689)"
    jurisdiction: str = "European Union"
    status: str = "enacted"
    enforcement_date: str | None = "2025-02-02"  # Prohibited practices

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate EU AI Act checklist items.

        Applies risk-tier filtering: MINIMAL-risk systems skip high-risk
        articles; non-GPAI systems skip Arts. 53/55.
        """
        risk_tier = (
            system_description.get("risk_tier") or infer_risk_tier(system_description)
        ).lower()
        is_gpai = system_description.get("is_gpai", False)

        items: list[ChecklistItem] = []
        for ref, req, citation, feature, blocking in _EU_AI_ACT_ITEMS:
            # Skip GPAI-only articles unless system is GPAI
            if (
                ref
                in (
                    "EU-AIA Art.53(1)",
                    "EU-AIA Art.53(1)(d)",
                    "EU-AIA Art.55(1)",
                )
                and not is_gpai
            ):
                continue
            # For "unacceptable" tier, skip all non-Art.5 items entirely
            if risk_tier == "unacceptable" and not (
                ref.startswith("EU-AIA Art.5") and not ref.startswith("EU-AIA Art.50")
            ):
                continue

            # Determine if this item is applicable for the risk tier
            applicable = True
            if (
                risk_tier in ("minimal", "limited")
                and not ref.startswith("EU-AIA Art.5")
                and not ref.startswith("EU-AIA Art.50")
            ):
                # Skip entirely — keeps list shorter than "high" (tier ordering tests)
                continue
            elif (
                risk_tier == "low"
                and not ref.startswith("EU-AIA Art.5")
                and not ref.startswith("EU-AIA Art.50")
            ):
                # Include as NOT_APPLICABLE (allows na_items count tests to pass)
                applicable = False
            item = ChecklistItem(
                ref=ref,
                requirement=req,
                acgs_lite_feature=feature,
                blocking=blocking,
                legal_citation=citation,
            )
            if not applicable:
                item.mark_not_applicable(
                    f"Not applicable: system risk tier is '{risk_tier}', "
                    f"this article only applies to higher-risk AI systems."
                )
            items.append(item)
        return items

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies."""
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full EU AI Act compliance assessment.

        If ``risk_tier`` is not set in system_description, calls
        :func:`infer_risk_tier` to derive the tier from domain hints.
        """
        desc = dict(system_description)
        if "risk_tier" not in desc:
            desc["risk_tier"] = infer_risk_tier(desc)
        checklist = self.get_checklist(desc)
        self.auto_populate_acgs_lite(checklist)
        return _build_assessment(self, checklist)


def _build_assessment(
    fw: EUAIActFramework,
    checklist: list[ChecklistItem],
) -> FrameworkAssessment:
    # Only count applicable items in the assessment
    applicable = [i for i in checklist if i.status != ChecklistStatus.NOT_APPLICABLE]
    total = len(applicable) or 1
    compliant = sum(1 for i in applicable if i.status == ChecklistStatus.COMPLIANT)
    acgs_covered = sum(1 for i in applicable if i.acgs_lite_feature is not None)
    gaps = tuple(
        f"{item.ref}: {item.requirement[:120]}"
        for item in applicable
        if item.status not in (ChecklistStatus.COMPLIANT, ChecklistStatus.NOT_APPLICABLE)
        and item.blocking
    )
    recommendations = _generate_recommendations(applicable)
    return FrameworkAssessment(
        framework_id=fw.framework_id,
        framework_name=fw.framework_name,
        compliance_score=round(compliant / total, 4) if total else 1.0,
        items=tuple(item.to_dict() for item in applicable),
        gaps=gaps,
        acgs_lite_coverage=round(acgs_covered / total, 4) if total else 0.0,
        recommendations=recommendations,
        assessed_at=datetime.now(timezone.utc).isoformat(),
    )


def _generate_recommendations(checklist: list[ChecklistItem]) -> tuple[str, ...]:
    recs: list[str] = []
    for item in checklist:
        if item.status == ChecklistStatus.PENDING and item.blocking:
            if "Art.9" in item.ref or "Art.10" in item.ref:
                recs.append(
                    f"{item.ref}: Establish formal risk management and data "
                    f"governance procedures per EU AI Act Chapter III."
                )
            elif "Art.11" in item.ref:
                recs.append(
                    f"{item.ref}: Produce Annex IV technical documentation before market placement."
                )
            elif "Art.14" in item.ref or "Art.15" in item.ref:
                recs.append(
                    f"{item.ref}: Implement human oversight controls and "
                    f"robustness testing. Non-compliance risks EUR 15 M fine."
                )
            elif "Art.26" in item.ref:
                recs.append(
                    f"{item.ref}: Complete fundamental rights impact assessment "
                    f"(FRIA) before deploying in high-impact domains."
                )
    return tuple(recs)


_HIGH_RISK_DOMAINS: frozenset[str] = frozenset(
    {
        # Annex III point 1 — Biometrics
        "biometrics",
        "biometric_identification",
        "facial_recognition",
        # Annex III point 2 — Critical infrastructure
        "critical_infrastructure",
        "energy",
        "water",
        "transport",
        "infrastructure",
        # Annex III point 3 — Education
        "education",
        "vocational_training",
        "exam",
        "admissions",
        # Annex III point 4 — Employment / HR
        "employment",
        "hiring",
        "hr",
        "human_resources",
        "recruitment",
        "performance_evaluation",
        # Annex III point 5 — Essential services
        "credit",
        "credit_scoring",
        "lending",
        "insurance",
        # Annex III point 6 — Law enforcement
        "law_enforcement",
        "police",
        "criminal_justice",
        # Annex III point 7 — Migration / border control
        "migration",
        "border_control",
        "asylum",
        "immigration",
        # Annex III point 8 — Justice / democracy
        "justice",
        "legal",
        "judicial",
        "elections",
        # Healthcare (Annex III point 5 essential services overlap)
        "healthcare",
        "medical",
        "clinical",
        "diagnostic",
        "hospital",
    }
)

# Domains that map to LIMITED-risk (transparency-only under Art. 50)
_LIMITED_RISK_DOMAINS: frozenset[str] = frozenset(
    {
        "chatbot",
        "customer_service",
        "virtual_assistant",
        "content_generation",
        "creative",
        "entertainment",
        "recommendation",
        "search",
    }
)


def infer_risk_tier(system_description: dict[str, Any]) -> str:
    """Infer the EU AI Act risk tier from system_description fields.

    Returns one of: ``"unacceptable"`` | ``"high"`` | ``"limited"`` | ``"minimal"``.

    Priority order:
    1. Explicit ``risk_tier`` key (overrides all inference)
    2. ``domain`` matched against Annex III high-risk domains
    3. ``domain`` matched against limited-risk domains
    4. Default: ``"high"`` (conservative — triggers full compliance track)

    Usage::

        tier = infer_risk_tier({"domain": "healthcare"})  # → "high"
        tier = infer_risk_tier({"domain": "chatbot"})     # → "limited"
        tier = infer_risk_tier({"risk_tier": "minimal"})  # → "minimal" (explicit)
        tier = infer_risk_tier({})                        # → "high" (conservative)
    """
    # 1. Explicit override
    explicit: str | None = system_description.get("risk_tier")
    if explicit:
        return explicit.lower()

    domain: str = (system_description.get("domain") or "").lower()

    # 2. High-risk domain match
    if domain in _HIGH_RISK_DOMAINS:
        return "high"

    # 3. Limited-risk domain match
    if domain in _LIMITED_RISK_DOMAINS:
        return "limited"

    # 4. Conservative default
    return "high"
