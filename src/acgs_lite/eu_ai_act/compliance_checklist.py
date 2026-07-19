"""EU AI Act Programmatic Compliance Checklist.

Generates a structured, machine-readable compliance checklist for high-risk
AI systems. Each item maps to a specific EU AI Act article obligation with
status tracking and evidence references.

Designed for:
- Self-assessment before regulatory submission
- CI/CD compliance gates (fail build if checklist incomplete)
- Generating conformity assessment documentation

Constitutional Hash: 608508a9bd224290

Usage::

    from acgs_lite.eu_ai_act import ComplianceChecklist, ChecklistStatus

    checklist = ComplianceChecklist(system_id="cv-screener-v1")

    # Mark items complete with evidence
    checklist.mark_complete(
        "Article 12",
        evidence="Article12Logger attached, 10-year JSONL retention",
    )
    checklist.mark_complete(
        "Article 14",
        evidence="HumanOversightGateway with 2-of-3 approval",
    )

    # Check compliance gate
    if not checklist.is_gate_clear:
        print(checklist.blocking_gaps)  # ["Article 9: Risk management system not documented"]

    # Export for conformity assessment documentation
    report = checklist.generate_report()
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from acgs_lite._compat import StrEnum


class ChecklistStatus(StrEnum):
    """Status of a single checklist item."""

    PENDING = "pending"
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ChecklistItem:
    """A single EU AI Act compliance checklist item.

    Attributes:
        article_ref: Article reference (e.g. "Article 12").
        requirement: Full requirement description.
        status: Current compliance status.
        evidence: Description of evidence or implementation.
        acgs_lite_feature: Which acgs-lite feature satisfies this requirement.
        blocking: If True, a non-compliant status blocks the compliance gate.
        updated_at: ISO timestamp of last status update.
    """

    article_ref: str
    requirement: str
    status: ChecklistStatus = ChecklistStatus.PENDING
    evidence: str | None = None
    acgs_lite_feature: str | None = None
    blocking: bool = True
    updated_at: str | None = None

    def mark_complete(self, evidence: str | None = None) -> None:
        """Mark this item as compliant with optional evidence."""
        self.status = ChecklistStatus.COMPLIANT
        self.evidence = evidence
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_partial(self, evidence: str | None = None) -> None:
        """Mark this item as partially compliant with optional evidence."""
        self.status = ChecklistStatus.PARTIAL
        self.evidence = evidence
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_not_applicable(self, reason: str | None = None) -> None:
        """Mark this item as not applicable with optional reason."""
        self.status = ChecklistStatus.NOT_APPLICABLE
        self.evidence = reason
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the checklist item to a dictionary."""
        return {
            "article_ref": self.article_ref,
            "requirement": self.requirement,
            "status": self.status.value,
            "evidence": self.evidence,
            "acgs_lite_feature": self.acgs_lite_feature,
            "blocking": self.blocking,
            "updated_at": self.updated_at,
        }


# Canonical Article 9–16 checklist for high-risk systems
_HIGH_RISK_ITEMS: list[tuple[str, str, str | None, bool]] = [
    # (article_ref, requirement, acgs_lite_feature, blocking)
    (
        "Article 9",
        "Risk management system: establish, document, and implement a continuous risk "
        "management process covering identification, analysis, estimation, evaluation, "
        "and treatment of reasonably foreseeable risks throughout the AI lifecycle.",
        "RiskClassifier — classifies system risk level and generates obligation list",
        True,
    ),
    (
        "Article 10",
        "Data governance: training, validation, and testing datasets must meet quality "
        "criteria for relevance, representativeness, freedom from errors, and completeness. "
        "Data lineage and bias examination must be documented.",
        None,
        True,
    ),
    (
        "Article 11",
        "Technical documentation: draw up and maintain Annex IV technical documentation "
        "before placing the system on the market. Must cover system description, design "
        "choices, training methodology, validation results, and risk management.",
        None,
        True,
    ),
    (
        "Article 12",
        "Record-keeping: automatically log events throughout the AI system lifecycle "
        "with tamper-evident trails. Logs must allow post-hoc reconstruction of "
        "decisions. Minimum retention: 10 years.",
        "Article12Logger — automatic tamper-evident JSONL logging with SHA-256 chaining",
        True,
    ),
    (
        "Article 13",
        "Transparency and information to deployers: provide clear instructions for use "
        "including capabilities, limitations, intended purpose, human oversight measures, "
        "and foreseeable misuse. System must be interpretable by deployers.",
        "TransparencyDisclosure — generates Article 13 compliant system cards",
        True,
    ),
    (
        "Article 14",
        "Human oversight: design and deploy with measures enabling natural persons to "
        "effectively oversee the system, understand outputs, intervene, override, or "
        "halt the system when necessary.",
        "HumanOversightGateway — configurable HITL approval gates with audit trail",
        True,
    ),
    (
        "Article 15",
        "Accuracy, robustness, and cybersecurity: achieve declared accuracy levels; "
        "maintain performance under errors, faults, and inconsistencies; protect "
        "against adversarial attacks; ensure confidentiality of inputs/outputs.",
        None,
        False,
    ),
    (
        "Article 16",
        "Provider obligations: register the system in the EU database before deployment; "
        "affix CE marking (via notified body or self-assessment); appoint EU representative "
        "if provider is outside the EU.",
        None,
        False,
    ),
    (
        "Article 43",
        "Conformity assessment: carry out self-assessment (most Annex III systems) "
        "or third-party audit (biometric and law enforcement systems) before deployment.",
        "ComplianceChecklist — generates conformity assessment documentation",
        True,
    ),
]

_LIMITED_RISK_ITEMS: list[tuple[str, str, str | None, bool]] = [
    (
        "Article 50(1)",
        "Transparency obligation: inform natural persons that they are interacting "
        "with an AI system, unless this is obvious from context.",
        "TransparencyDisclosure — ai_system_disclosure text field",
        True,
    ),
    (
        "Article 50(3)",
        "Emotion/biometric disclosure: inform persons when they are subject to "
        "emotion recognition or biometric categorisation systems.",
        None,
        True,
    ),
    (
        "Article 50(4)",
        "Deepfake labelling: label AI-generated or manipulated images, audio, or "
        "video content so that it is disclosed as artificially generated.",
        None,
        True,
    ),
]


class ComplianceChecklist:
    """Programmatic EU AI Act compliance checklist for a single AI system.

    Generates a structured checklist of Article obligations based on risk level,
    tracks evidence for each item, and exposes a compliance gate check.

    Usage::

        checklist = ComplianceChecklist(system_id="cv-screener-v1")

        # Auto-populate with acgs-lite evidence
        checklist.auto_populate_acgs_lite()

        # Mark remaining items
        checklist.mark_complete("Article 10", evidence="Bias testing report v2.1")
        checklist.mark_complete("Article 11", evidence="Annex IV docs at docs/annex-iv.md")

        # Check gate
        if checklist.is_gate_clear:
            print("Ready for conformity assessment")
        else:
            print(checklist.blocking_gaps)
    """

    def __init__(
        self,
        system_id: str,
        *,
        risk_level: str = "high_risk",
    ) -> None:
        self.system_id = system_id
        self.risk_level = risk_level
        self._items: list[ChecklistItem] = self._build_items(risk_level)
        self.created_at = datetime.now(timezone.utc).isoformat()

    def _build_items(self, risk_level: str) -> list[ChecklistItem]:
        if risk_level == "high_risk":
            return [
                ChecklistItem(
                    article_ref=ref,
                    requirement=req,
                    acgs_lite_feature=feature,
                    blocking=blocking,
                )
                for ref, req, feature, blocking in _HIGH_RISK_ITEMS
            ]
        if risk_level == "limited_risk":
            return [
                ChecklistItem(
                    article_ref=ref,
                    requirement=req,
                    acgs_lite_feature=feature,
                    blocking=blocking,
                )
                for ref, req, feature, blocking in _LIMITED_RISK_ITEMS
            ]
        return []

    @property
    def items(self) -> list[ChecklistItem]:
        """Return a copy of all checklist items."""
        return list(self._items)

    def get_item(self, article_ref: str) -> ChecklistItem | None:
        """Retrieve a specific checklist item by article reference."""
        for item in self._items:
            if item.article_ref.lower() == article_ref.lower():
                return item
        return None

    def mark_complete(self, article_ref: str, *, evidence: str | None = None) -> bool:
        """Mark an article item as compliant.

        Args:
            article_ref: Article reference (e.g. "Article 12").
            evidence: Description of how compliance is achieved.

        Returns:
            True if the item was found and updated, False otherwise.
        """
        item = self.get_item(article_ref)
        if item is None:
            return False
        item.mark_complete(evidence)
        return True

    def mark_partial(self, article_ref: str, *, evidence: str | None = None) -> bool:
        """Mark an article item as partially compliant."""
        item = self.get_item(article_ref)
        if item is None:
            return False
        item.mark_partial(evidence)
        return True

    def mark_not_applicable(self, article_ref: str, *, reason: str | None = None) -> bool:
        """Mark an article item as not applicable."""
        item = self.get_item(article_ref)
        if item is None:
            return False
        item.mark_not_applicable(reason)
        return True

    def auto_populate_acgs_lite(self) -> None:
        """Mark items covered by acgs-lite technical measures as compliant.

        Call this after attaching Article12Logger, TransparencyDisclosure,
        and HumanOversightGateway to auto-populate their evidence.
        """
        acgs_articles = {
            "Article 9": (
                "acgs-lite RiskClassifier — risk level classification and obligation mapping"
            ),
            "Article 12": ("acgs-lite Article12Logger — automatic tamper-evident JSONL logging"),
            "Article 13": ("acgs-lite TransparencyDisclosure — Article 13 system card generation"),
            "Article 14": ("acgs-lite HumanOversightGateway — configurable HITL approval gates"),
            "Article 43": ("acgs-lite ComplianceChecklist — conformity assessment documentation"),
        }
        for article_ref, evidence in acgs_articles.items():
            self.mark_complete(article_ref, evidence=evidence)

    @property
    def is_gate_clear(self) -> bool:
        """True if all blocking items are compliant or not-applicable."""
        return all(
            item.status in (ChecklistStatus.COMPLIANT, ChecklistStatus.NOT_APPLICABLE)
            for item in self._items
            if item.blocking
        )

    @property
    def blocking_gaps(self) -> list[str]:
        """List of blocking items that are not yet compliant."""
        return [
            f"{item.article_ref}: {item.requirement[:100]}..."
            for item in self._items
            if item.blocking
            and item.status not in (ChecklistStatus.COMPLIANT, ChecklistStatus.NOT_APPLICABLE)
        ]

    @property
    def compliance_score(self) -> float:
        """Fraction of items that are compliant or not-applicable (0.0–1.0)."""
        if not self._items:
            return 1.0
        done = sum(
            1
            for item in self._items
            if item.status in (ChecklistStatus.COMPLIANT, ChecklistStatus.NOT_APPLICABLE)
        )
        return round(done / len(self._items), 4)

    def generate_report(self) -> dict[str, Any]:
        """Generate a structured compliance report for Annex IV documentation."""
        return {
            "system_id": self.system_id,
            "risk_level": self.risk_level,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "created_at": self.created_at,
            "compliance_score": self.compliance_score,
            "gate_clear": self.is_gate_clear,
            "blocking_gaps": self.blocking_gaps,
            "items": [item.to_dict() for item in self._items],
            # Annex III stand-alone high-risk; deferred by 2026 Digital Omnibus (Council approval 2026-06-29)
            "high_risk_deadline": "2027-12-02",
            "disclaimer": (
                "Indicative self-assessment only. Not legal advice. "
                "Consult qualified legal counsel for binding EU AI Act compliance opinions."
            ),
        }

    def __repr__(self) -> str:
        return (
            f"ComplianceChecklist(system_id={self.system_id!r}, "
            f"risk_level={self.risk_level!r}, "
            f"score={self.compliance_score:.0%}, "
            f"gate_clear={self.is_gate_clear})"
        )
