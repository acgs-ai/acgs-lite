"""EU AI Act Risk Classification — Article 6 and Annex III.

Classifies AI systems into one of four risk tiers:

- UNACCEPTABLE — Prohibited practices (Article 5). Must not be deployed.
- HIGH_RISK    — Regulated use cases (Article 6 + Annex III). Full obligations apply.
- LIMITED_RISK — Transparency obligations only (Article 50).
- MINIMAL_RISK — No mandatory obligations (most AI systems).

Main high-risk deadlines, per the 2026 Digital Omnibus (Council final approval
2026-06-29): Annex III stand-alone high-risk systems must comply by
December 2, 2027; Annex I embedded-product high-risk systems by August 2, 2028.

Constitutional Hash: 608508a9bd224290

Usage::

    from acgs_lite.eu_ai_act import RiskClassifier, SystemDescription

    classifier = RiskClassifier()
    result = classifier.classify(SystemDescription(
        system_id="cv-screener-v1",
        purpose="Screening job applications",
        domain="employment",
        autonomy_level=3,
        human_oversight=True,
        employment=True,
    ))
    print(result.level)          # RiskLevel.HIGH_RISK
    print(result.obligations)    # ["Article 9: Risk management...", ...]
    print(result.is_high_risk)   # True
"""

from __future__ import annotations

from dataclasses import dataclass

from acgs_lite._compat import StrEnum

_DISCLAIMER = (
    "Indicative assessment only. Not legal advice. "
    "Consult qualified legal counsel for binding EU AI Act compliance opinions."
)

# Annex III high-risk domain keywords
_HIGH_RISK_DOMAINS: frozenset[str] = frozenset(
    {
        "biometric",
        "critical_infrastructure",
        "education",
        "employment",
        "essential_services",
        "law_enforcement",
        "migration",
        "border_control",
        "justice",
        "democracy",
        "governance",
        "credit_scoring",
        "insurance",
        "healthcare",
        "medical",
    }
)

# Article 50 limited-risk domains
_LIMITED_RISK_DOMAINS: frozenset[str] = frozenset(
    {
        "chatbot",
        "emotion_recognition",
        "deepfake",
        "content_generation",
        "synthetic_media",
    }
)

# Full obligations for high-risk systems
_HIGH_RISK_OBLIGATIONS: list[str] = [
    "Article 9 — Risk management system: continuous identification and evaluation of risks",
    "Article 10 — Data governance: training data quality, representativeness, bias testing",
    "Article 11 — Technical documentation: detailed Annex IV documentation before deployment",
    "Article 12 — Record-keeping: automatic tamper-evident logging, 10-year retention",
    "Article 13 — Transparency: clear instructions for use, capabilities and limitations",
    "Article 14 — Human oversight: design enabling effective human intervention and override",
    "Article 15 — Accuracy, robustness, cybersecurity: declared accuracy levels and testing",
    "Article 16 — Obligations of providers: conformity assessment, CE marking, registration",
    "Article 43 — Conformity assessment: self-assessment or third-party audit",
]


class RiskLevel(StrEnum):
    """EU AI Act risk classification levels per Article 6."""

    UNACCEPTABLE = "unacceptable"
    HIGH_RISK = "high_risk"
    LIMITED_RISK = "limited_risk"
    MINIMAL_RISK = "minimal_risk"


@dataclass(frozen=True)
class SystemDescription:
    """Description of an AI system for EU AI Act risk classification.

    Attributes:
        system_id: Unique identifier for the system.
        purpose: Human-readable description of what the system does.
        domain: Primary application domain (e.g. "employment", "healthcare").
        autonomy_level: Degree of autonomous decision-making, 0 (none) to 5 (full).
        human_oversight: Whether the system operates under meaningful human oversight.
        biometric_processing: Processes biometric data for identification.
        critical_infrastructure: Used in critical infrastructure management.
        law_enforcement: Used for law enforcement purposes.
        education: Used in education or vocational training contexts.
        employment: Used for hiring, promotion, or worker management.
        social_scoring: Evaluates or scores people for social trustworthiness.
        subliminal_manipulation: Uses subliminal techniques to distort behaviour.
        vulnerability_exploitation: Exploits vulnerabilities of specific groups.
    """

    system_id: str
    purpose: str
    domain: str
    autonomy_level: int = 0  # 0-5
    human_oversight: bool = True
    biometric_processing: bool = False
    critical_infrastructure: bool = False
    law_enforcement: bool = False
    education: bool = False
    employment: bool = False
    social_scoring: bool = False
    subliminal_manipulation: bool = False
    vulnerability_exploitation: bool = False


@dataclass(frozen=True)
class ClassificationResult:
    """Result of an EU AI Act Article 6 risk classification.

    Attributes:
        level: Risk level (UNACCEPTABLE / HIGH_RISK / LIMITED_RISK / MINIMAL_RISK).
        article_basis: Legal basis for the classification.
        obligations: List of compliance obligations that apply.
        rationale: Human-readable explanation of the classification.
        high_risk_deadline: Compliance deadline if applicable.
        disclaimer: Legal disclaimer (always present).
    """

    level: RiskLevel
    article_basis: str
    obligations: list[str]
    rationale: str
    high_risk_deadline: str = (
        "2027-12-02"  # Annex III stand-alone high-risk; deferred by 2026 Digital Omnibus
    )
    disclaimer: str = _DISCLAIMER

    @property
    def is_prohibited(self) -> bool:
        """True if the system is classified as an unacceptable (prohibited) practice."""
        return self.level == RiskLevel.UNACCEPTABLE

    @property
    def is_high_risk(self) -> bool:
        """True if the system is classified as high-risk under Annex III."""
        return self.level == RiskLevel.HIGH_RISK

    @property
    def requires_article12_logging(self) -> bool:
        """True if automatic record-keeping (Article 12) is mandatory."""
        return self.level == RiskLevel.HIGH_RISK

    @property
    def requires_human_oversight(self) -> bool:
        """True if Article 14 human oversight is mandatory."""
        return self.level == RiskLevel.HIGH_RISK

    def to_dict(self) -> dict[str, object]:
        """Serialize the classification result to a dictionary."""
        return {
            "risk_level": self.level.value,
            "article_basis": self.article_basis,
            "obligations": self.obligations,
            "rationale": self.rationale,
            "high_risk_deadline": self.high_risk_deadline,
            "requires_article12_logging": self.requires_article12_logging,
            "requires_human_oversight": self.requires_human_oversight,
            "is_prohibited": self.is_prohibited,
            "disclaimer": self.disclaimer,
        }


class RiskClassifier:
    """Classify AI systems under the EU AI Act.

    Implements the Article 5 (prohibited) → Article 6 + Annex III (high-risk)
    → Article 50 (limited-risk) → minimal-risk decision tree.

    Usage::

        classifier = RiskClassifier()
        result = classifier.classify(description)

        if result.is_prohibited:
            raise ValueError("System must not be deployed in the EU")

        if result.is_high_risk:
            logger = Article12Logger(system_id=description.system_id)
            # ... mandatory Article 12 logging
    """

    def __init__(self) -> None:
        pass

    def classify(self, description: SystemDescription) -> ClassificationResult:
        """Classify an AI system's EU AI Act risk level.

        Args:
            description: System description with purpose, domain, and capability flags.

        Returns:
            ClassificationResult with risk level, obligations, and rationale.
        """
        # Stage 1: UNACCEPTABLE — Article 5 prohibited practices
        if description.social_scoring:
            return self._unacceptable(
                "Social scoring by public authorities is prohibited",
                "Article 5(1)(c)",
            )
        if description.subliminal_manipulation:
            return self._unacceptable(
                "Subliminal techniques to materially distort behaviour are prohibited",
                "Article 5(1)(a)",
            )
        if description.vulnerability_exploitation:
            return self._unacceptable(
                "Exploitation of vulnerabilities of specific groups is prohibited",
                "Article 5(1)(b)",
            )
        if description.biometric_processing and description.law_enforcement:
            return self._unacceptable(
                "Real-time remote biometric identification for law enforcement is prohibited",
                "Article 5(1)(d)",
            )

        # Stage 2: HIGH_RISK — Article 6 and Annex III
        high_risk_reasons: list[str] = []
        if description.biometric_processing:
            high_risk_reasons.append(
                "biometric identification or categorisation (Annex III, point 1)"
            )
        if description.critical_infrastructure:
            high_risk_reasons.append(
                "safety component of critical infrastructure (Annex III, point 2)"
            )
        if description.education:
            high_risk_reasons.append("education and vocational training (Annex III, point 3)")
        if description.employment:
            high_risk_reasons.append(
                "employment, worker management, and access to self-employment (Annex III, point 4)"
            )
        if description.law_enforcement:
            high_risk_reasons.append("law enforcement (Annex III, point 6)")

        domain_normalised = description.domain.lower().replace(" ", "_").replace("-", "_")
        if domain_normalised in _HIGH_RISK_DOMAINS:
            high_risk_reasons.append(
                f"domain '{description.domain}' matches an Annex III high-risk category"
            )

        if high_risk_reasons:
            return ClassificationResult(
                level=RiskLevel.HIGH_RISK,
                article_basis="Article 6, Annex III",
                obligations=_HIGH_RISK_OBLIGATIONS,
                rationale="; ".join(high_risk_reasons),
            )

        # Stage 3: LIMITED_RISK — Article 50 transparency obligations
        if domain_normalised in _LIMITED_RISK_DOMAINS:
            return ClassificationResult(
                level=RiskLevel.LIMITED_RISK,
                article_basis="Article 50",
                obligations=[
                    "Article 50(1) — Inform users they are interacting with an AI system",
                    "Article 50(3) — Disclose emotion recognition or biometric categorisation",
                    "Article 50(4) — Label AI-generated or manipulated content (deepfakes)",
                ],
                rationale=(
                    f"Domain '{description.domain}' triggers Article 50 transparency obligations"
                ),
            )

        # Stage 4: MINIMAL_RISK — no mandatory obligations
        return ClassificationResult(
            level=RiskLevel.MINIMAL_RISK,
            article_basis="Recital 69",
            obligations=[],
            rationale=(
                "System does not fall under prohibited practices, Annex III high-risk categories, "
                "or Article 50 limited-risk transparency obligations. "
                "Voluntary codes of conduct are encouraged."
            ),
        )

    @staticmethod
    def _unacceptable(reason: str, article: str) -> ClassificationResult:
        return ClassificationResult(
            level=RiskLevel.UNACCEPTABLE,
            article_basis=article,
            obligations=[
                "PROHIBITED: System must not be placed on the market or put into service in the EU"
            ],
            rationale=reason,
        )

    def classify_many(self, descriptions: list[SystemDescription]) -> list[ClassificationResult]:
        """Classify multiple systems in one call."""
        return [self.classify(d) for d in descriptions]
