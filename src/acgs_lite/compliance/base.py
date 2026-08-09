"""Base protocol and data structures for multi-framework compliance.

Defines the ComplianceFramework protocol that every regulatory framework
module must implement, along with shared data types (ChecklistItem,
FrameworkAssessment) used across all frameworks.

Constitutional Hash: 608508a9bd224290

Usage::

    from acgs_lite.compliance.base import ComplianceFramework, FrameworkAssessment

    class MyFramework:
        # Implement ComplianceFramework protocol
        ...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

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
    """A single compliance checklist item applicable across any framework.

    Attributes:
        ref: Regulatory reference (e.g. "NIST MAP 1.1", "ISO A.4.2").
        requirement: Full requirement description.
        status: Current compliance status.
        evidence: Description of evidence or implementation.
        acgs_lite_feature: Which acgs-lite feature satisfies this requirement.
        blocking: If True, a non-compliant status blocks the compliance gate.
        legal_citation: Formal legal citation (statute, article, section).
        updated_at: ISO timestamp of last status update.

    """

    ref: str
    requirement: str
    status: ChecklistStatus = ChecklistStatus.PENDING
    evidence: str | None = None
    acgs_lite_feature: str | None = None
    blocking: bool = True
    legal_citation: str = ""
    updated_at: str | None = None

    def mark_complete(self, evidence: str | None = None) -> None:
        """Set status to COMPLIANT and record evidence."""
        self.status = ChecklistStatus.COMPLIANT
        self.evidence = evidence
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_partial(self, evidence: str | None = None) -> None:
        """Set status to PARTIAL and record evidence."""
        self.status = ChecklistStatus.PARTIAL
        self.evidence = evidence
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_not_applicable(self, reason: str | None = None) -> None:
        """Set status to NOT_APPLICABLE and record the reason."""
        self.status = ChecklistStatus.NOT_APPLICABLE
        self.evidence = reason
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Serialize this checklist item to a plain dictionary."""
        return {
            "ref": self.ref,
            "requirement": self.requirement,
            "status": self.status.value,
            "evidence": self.evidence,
            "acgs_lite_feature": self.acgs_lite_feature,
            "blocking": self.blocking,
            "legal_citation": self.legal_citation,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class FrameworkAssessment:
    """Immutable result of assessing a system against one compliance framework.

    Attributes:
        framework_id: Machine identifier (e.g. "nist_ai_rmf").
        framework_name: Human-readable name.
        compliance_score: Fraction of items compliant (0.0-1.0).
        items: All checklist items with their statuses.
        gaps: List of non-compliant item descriptions.
        acgs_lite_coverage: Fraction of items auto-satisfied by acgs-lite.
        recommendations: Actionable steps to close gaps.
        assessed_at: ISO timestamp of assessment.

    """

    framework_id: str
    framework_name: str
    compliance_score: float
    items: tuple[dict[str, Any], ...]
    gaps: tuple[str, ...]
    acgs_lite_coverage: float
    recommendations: tuple[str, ...]
    assessed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize this assessment to a plain dictionary."""
        return {
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "compliance_score": self.compliance_score,
            "items": list(self.items),
            "gaps": list(self.gaps),
            "acgs_lite_coverage": self.acgs_lite_coverage,
            "recommendations": list(self.recommendations),
            "assessed_at": self.assessed_at,
        }


@dataclass(frozen=True)
class MultiFrameworkReport:
    """Immutable unified report across all assessed compliance frameworks.

    Attributes:
        system_id: Identifier of the assessed system.
        frameworks_assessed: List of framework IDs that were evaluated.
        overall_score: Weighted average compliance across frameworks.
        by_framework: Per-framework assessment results.
        cross_framework_gaps: Requirements missing across multiple frameworks.
        acgs_lite_total_coverage: Average acgs-lite coverage across frameworks.
        recommendations: Prioritized list of actions to close gaps.
        assessed_at: ISO timestamp of the multi-framework assessment.

    """

    system_id: str
    frameworks_assessed: tuple[str, ...]
    overall_score: float
    by_framework: dict[str, FrameworkAssessment] = field(default_factory=dict)
    cross_framework_gaps: tuple[str, ...] = ()
    acgs_lite_total_coverage: float = 0.0
    recommendations: tuple[str, ...] = ()
    assessed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize this multi-framework report to a plain dictionary."""
        return {
            "system_id": self.system_id,
            "frameworks_assessed": list(self.frameworks_assessed),
            "overall_score": self.overall_score,
            "by_framework": {k: v.to_dict() for k, v in self.by_framework.items()},
            "cross_framework_gaps": list(self.cross_framework_gaps),
            "acgs_lite_total_coverage": self.acgs_lite_total_coverage,
            "recommendations": list(self.recommendations),
            "assessed_at": self.assessed_at,
            "disclaimer": (
                "Indicative self-assessment only. Not legal advice. "
                "Consult qualified legal counsel for binding compliance opinions."
            ),
        }


@runtime_checkable
class ComplianceFramework(Protocol):
    """Protocol that every regulatory compliance framework module must implement.

    Each framework provides:
    - A checklist of regulatory requirements specific to that framework
    - Auto-population of items that acgs-lite satisfies out of the box
    - A full assessment producing an immutable FrameworkAssessment
    """

    framework_id: str
    framework_name: str
    jurisdiction: str
    status: str  # "enacted" | "proposed" | "voluntary" | "defunct"
    enforcement_date: str | None

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate a checklist of requirements for the given system.

        Args:
            system_description: Dict with keys like 'system_id', 'purpose',
                'domain', 'processes_pii', 'autonomy_level', etc.

        Returns:
            List of ChecklistItem instances.

        """
        ...

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark checklist items that acgs-lite directly satisfies.

        Mutates items in place by calling mark_complete() with evidence
        referencing the specific acgs-lite feature.

        Args:
            checklist: List of ChecklistItem instances to populate.

        """
        ...

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run a full compliance assessment for the given system.

        Generates the checklist, auto-populates acgs-lite features,
        computes scores, identifies gaps, and returns an immutable
        FrameworkAssessment.

        Args:
            system_description: Dict describing the AI system.

        Returns:
            Frozen FrameworkAssessment dataclass.

        """
        ...
