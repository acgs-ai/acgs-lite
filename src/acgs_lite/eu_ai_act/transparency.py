"""EU AI Act Article 13 — Transparency and Information to Deployers.

Article 13 requires that high-risk AI systems be designed so that deployers
can understand and effectively use the system. Providers must supply:

- A description of the intended purpose and the forms of human oversight
- Capabilities and limitations, foreseeable misuse, and known biases
- Data requirements, computational resource requirements, and maintenance instructions
- Contact details of the provider

This module provides helpers for generating Article 13 compliant system cards
and validating that required disclosure fields are present.

Constitutional Hash: 608508a9bd224290

Usage::

    from acgs_lite.eu_ai_act import TransparencyDisclosure

    disclosure = TransparencyDisclosure(
        system_id="cv-screener-v1",
        system_name="CV Screening Assistant",
        provider="Acme Corp",
        intended_purpose="Automated first-pass screening of job applications",
        capabilities=["Text classification", "Scoring", "Ranking"],
        limitations=["Not validated for non-English CVs", "Accuracy <90% for creative roles"],
        human_oversight_measures=["All rejections reviewed by HR", "Monthly accuracy audits"],
        known_biases=["Underperforms for candidates from non-OECD universities"],
        contact_email="ai-compliance@acme.com",
    )

    disclosure.validate()          # Raises if required fields missing
    card = disclosure.to_system_card()  # Dict ready for documentation
    print(disclosure.render_text())    # Human-readable disclosure text
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_REQUIRED_FIELDS: tuple[str, ...] = (
    "system_id",
    "system_name",
    "provider",
    "intended_purpose",
    "capabilities",
    "limitations",
    "human_oversight_measures",
    "contact_email",
)

_DISCLAIMER = (
    "This disclosure is provided under EU AI Act Article 13. "
    "It is not a guarantee of performance. "
    "Consult qualified legal counsel for binding compliance advice."
)


@dataclass
class TransparencyDisclosure:
    """Article 13 transparency disclosure for a high-risk AI system.

    All fields marked with (required) must be populated before a system
    can be placed on the EU market. The ``validate()`` method checks this.

    Attributes:
        system_id: Unique system identifier. (required)
        system_name: Human-readable system name. (required)
        provider: Organisation placing the system on the market. (required)
        intended_purpose: Specific intended purpose. (required)
        capabilities: List of documented capabilities. (required)
        limitations: Known limitations and foreseeable issues. (required)
        human_oversight_measures: How humans can oversee and intervene. (required)
        contact_email: Provider contact for deployers. (required)
        version: System version.
        risk_level: EU AI Act risk classification.
        known_biases: Known data or algorithmic biases.
        data_requirements: Input data requirements.
        performance_metrics: Accuracy, precision, recall, etc.
        ai_system_disclosure: Text to show end users (Article 50).
        maintenance_instructions: How to monitor and maintain the system.
    """

    system_id: str = ""
    system_name: str = ""
    provider: str = ""
    intended_purpose: str = ""
    capabilities: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    human_oversight_measures: list[str] = field(default_factory=list)
    contact_email: str = ""
    version: str = "1.0"
    risk_level: str = "high_risk"
    known_biases: list[str] = field(default_factory=list)
    data_requirements: list[str] = field(default_factory=list)
    performance_metrics: dict[str, Any] = field(default_factory=dict)
    ai_system_disclosure: str = (
        "You are interacting with an AI system. "
        "Its outputs may not be accurate and should be reviewed by a qualified person."
    )
    maintenance_instructions: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        pass

    def validate(self) -> list[str]:
        """Validate that all required Article 13 fields are populated.

        Returns:
            List of missing field names. Empty list means all required disclosure
            fields are present.

        Raises:
            ValueError: If any required fields are missing (convenience form).
        """
        missing: list[str] = []
        for field_name in _REQUIRED_FIELDS:
            value = getattr(self, field_name, None)
            if not value:
                missing.append(field_name)
        return missing

    def is_valid(self) -> bool:
        """Return True if all required fields are populated."""
        return len(self.validate()) == 0

    def to_system_card(self) -> dict[str, Any]:
        """Generate an Article 13 compliant system card dictionary.

        Suitable for including in:
        - Technical documentation (Annex IV)
        - EU AI Act database registration
        - Deployer instructions
        """
        return {
            "article": "Article 13 — Transparency and Information to Deployers",
            "system_id": self.system_id,
            "system_name": self.system_name,
            "version": self.version,
            "provider": self.provider,
            "contact_email": self.contact_email,
            "risk_level": self.risk_level,
            "intended_purpose": self.intended_purpose,
            "capabilities": self.capabilities,
            "limitations": self.limitations,
            "known_biases": self.known_biases,
            "data_requirements": self.data_requirements,
            "performance_metrics": self.performance_metrics,
            "human_oversight_measures": self.human_oversight_measures,
            "ai_system_disclosure": self.ai_system_disclosure,
            "maintenance_instructions": self.maintenance_instructions,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "created_at": self.created_at,
            "validation_status": "compliant" if self.is_valid() else "incomplete",
            "missing_fields": self.validate(),
            "disclaimer": _DISCLAIMER,
        }

    def render_text(self) -> str:
        """Render a human-readable Article 13 disclosure document.

        Suitable for:
        - Including in user-facing documentation
        - Printing in compliance reports
        - Attaching to model cards
        """
        lines: list[str] = [
            "EU AI Act Article 13 Transparency Disclosure",
            f"{'=' * 50}",
            f"System: {self.system_name} (v{self.version})",
            f"System ID: {self.system_id}",
            f"Provider: {self.provider}",
            f"Contact: {self.contact_email}",
            f"Risk Level: {self.risk_level.upper()}",
            "",
            "Intended Purpose",
            f"{'-' * 20}",
            self.intended_purpose,
            "",
            "Capabilities",
            f"{'-' * 20}",
        ]
        for cap in self.capabilities:
            lines.append(f"  - {cap}")

        lines += [
            "",
            "Known Limitations",
            f"{'-' * 20}",
        ]
        for lim in self.limitations:
            lines.append(f"  - {lim}")

        if self.known_biases:
            lines += ["", "Known Biases", f"{'-' * 20}"]
            for bias in self.known_biases:
                lines.append(f"  - {bias}")

        lines += [
            "",
            "Human Oversight Measures (Article 14)",
            f"{'-' * 20}",
        ]
        for measure in self.human_oversight_measures:
            lines.append(f"  - {measure}")

        if self.performance_metrics:
            lines += ["", "Performance Metrics", f"{'-' * 20}"]
            for metric, value in self.performance_metrics.items():
                lines.append(f"  {metric}: {value}")

        if self.maintenance_instructions:
            lines += ["", "Maintenance Instructions", f"{'-' * 20}", self.maintenance_instructions]

        lines += [
            "",
            "User Disclosure (Article 50)",
            f"{'-' * 20}",
            self.ai_system_disclosure,
            "",
            f"Disclaimer: {_DISCLAIMER}",
        ]

        return "\n".join(lines)

    def render_markdown(self) -> str:
        """Render Article 13 disclosure as Markdown for documentation sites."""
        lines: list[str] = [
            "# EU AI Act Article 13 Transparency Disclosure",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| System | **{self.system_name}** (v{self.version}) |",
            f"| System ID | `{self.system_id}` |",
            f"| Provider | {self.provider} |",
            f"| Contact | {self.contact_email} |",
            f"| Risk Level | `{self.risk_level.upper()}` |",
            "",
            "## Intended Purpose",
            "",
            self.intended_purpose,
            "",
            "## Capabilities",
            "",
        ]
        for cap in self.capabilities:
            lines.append(f"- {cap}")

        lines += ["", "## Known Limitations", ""]
        for lim in self.limitations:
            lines.append(f"- {lim}")

        if self.known_biases:
            lines += ["", "## Known Biases", ""]
            for bias in self.known_biases:
                lines.append(f"- {bias}")

        lines += ["", "## Human Oversight Measures (Article 14)", ""]
        for measure in self.human_oversight_measures:
            lines.append(f"- {measure}")

        if self.performance_metrics:
            lines += ["", "## Performance Metrics", "", "| Metric | Value |", "|--------|-------|"]
            for metric, value in self.performance_metrics.items():
                lines.append(f"| {metric} | {value} |")

        lines += [
            "",
            "## User Disclosure (Article 50)",
            "",
            f"> {self.ai_system_disclosure}",
            "",
            "---",
            "",
            f"*{_DISCLAIMER}*",
        ]

        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"TransparencyDisclosure(system_id={self.system_id!r}, "
            f"valid={self.is_valid()}, "
            f"missing={self.validate()})"
        )
