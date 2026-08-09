"""Live evidence collection for compliance frameworks.

Gathers runtime and filesystem signals that substantiate compliance claims.
Collectors are lightweight — no network calls, no external services — and
produce :class:`EvidenceItem` records that map directly to article references
across all 20 supported frameworks.

Three built-in collectors:

* :class:`ACGSLiteImportCollector` — checks which acgs-lite components are
  importable in the current runtime environment.
* :class:`FileSystemCollector` — scans the working directory for compliance
  artefacts (rules files, privacy notices, risk registers, system cards, etc.).
* :class:`EnvironmentVarCollector` — reads environment variables that signal
  compliance configuration.

Usage::

    from acgs_lite.compliance.evidence import collect_evidence

    bundle = collect_evidence({"system_id": "my-ai", "domain": "healthcare"})

    # Items covering EU AI Act Article 12
    eu_items = bundle.for_ref("EU-AIA Art.12(1)")

    # All evidence for GDPR
    gdpr_items = bundle.for_framework("gdpr")

    # How many items per framework?
    print(bundle.summary())

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class EvidenceItem:
    """A single collected evidence artefact.

    Attributes:
        framework_id:  Framework this evidence applies to, or ``"*"`` for all.
        article_refs:  Article / requirement references satisfied by this item.
        source:        Machine-readable source tag
                       (e.g. ``"import:acgs_lite.AuditLog"``,
                       ``"file:rules.yaml"``, ``"env:ACGS_AUDIT_ENABLED"``).
        description:   Human-readable description of what was found.
        confidence:    Evidence strength, 0.0 (weak) – 1.0 (definitive).
    """

    framework_id: str
    article_refs: tuple[str, ...]
    source: str
    description: str
    confidence: float


@dataclass
class EvidenceBundle:
    """Aggregated evidence from all collectors.

    Attributes:
        system_id:     Identifier of the assessed system.
        collected_at:  ISO-8601 UTC timestamp.
        items:         All collected :class:`EvidenceItem` records.
    """

    system_id: str
    collected_at: str
    items: tuple[EvidenceItem, ...] = field(default_factory=tuple)

    def for_framework(self, fw_id: str) -> list[EvidenceItem]:
        """Return items that apply to *fw_id* or to all frameworks (``"*"``)."""
        return [i for i in self.items if i.framework_id in (fw_id, "*")]

    def for_ref(self, ref: str) -> list[EvidenceItem]:
        """Return items that reference *ref* in their ``article_refs``."""
        return [i for i in self.items if ref in i.article_refs]

    def summary(self) -> dict[str, int]:
        """Return a mapping of ``framework_id → item count``."""
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.framework_id] = counts.get(item.framework_id, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (JSON-safe)."""
        return {
            "system_id": self.system_id,
            "collected_at": self.collected_at,
            "item_count": len(self.items),
            "items": [
                {
                    "framework_id": i.framework_id,
                    "article_refs": list(i.article_refs),
                    "source": i.source,
                    "description": i.description,
                    "confidence": i.confidence,
                }
                for i in self.items
            ],
        }


@runtime_checkable
class EvidenceCollector(Protocol):
    """Protocol for pluggable evidence collectors."""

    def collect(self, system_description: dict[str, Any]) -> list[EvidenceItem]:
        """Collect evidence items for *system_description*."""
        ...


# ---------------------------------------------------------------------------
# acgs-lite component → article reference mapping
# ---------------------------------------------------------------------------

# Each entry: (import_path, description, [(framework_id, article_ref), ...], confidence)
_COMPONENT_EVIDENCE: list[tuple[str, str, list[tuple[str, str]], float]] = [
    (
        "acgs_lite.audit.AuditLog",
        "acgs-lite AuditLog — tamper-evident JSONL log with SHA-256 hash chaining",
        [
            ("eu_ai_act", "EU-AIA Art.12(1)"),
            ("eu_ai_act", "EU-AIA Art.12(2)"),
            ("gdpr", "GDPR Art.5(2)"),
            ("gdpr", "GDPR Art.30(1)"),
            ("dora", "DORA Art.8(6)"),
            ("dora", "DORA Art.17(1)"),
            ("india_dpdp", "DPDP Art.11(3)"),
            ("brazil_lgpd", "LGPD Art.37"),
            ("china_ai", "CN-ARS Art.11"),
            ("canada_aida", "AIDA §11(3)"),
            ("australia_ai_ethics", "AU-P3.2"),
            ("singapore_maigf", "MAIGF — Human Involvement: risk-based oversight determination"),
            ("uk_ai_framework", "UK ACC-1"),
            ("nist_ai_rmf", "NIST MEASURE 1.3"),
            ("soc2_ai", "SOC2 CC7.2"),
            ("ccpa_cpra", "CCPA §1798.110"),
            ("iso_42001", "ISO 42001 §9.1"),
        ],
        0.90,
    ),
    (
        "acgs_lite.engine.GovernanceEngine",
        "acgs-lite GovernanceEngine — constitutional rule validation across agent lifecycle",
        [
            ("nist_ai_rmf", "NIST GOVERN 1.1"),
            ("nist_ai_rmf", "NIST GOVERN 1.2"),
            ("iso_42001", "ISO 42001 §4.1"),
            ("iso_42001", "ISO 42001 §6.1.1"),
            ("eu_ai_act", "EU-AIA Art.9(1)"),
            ("eu_ai_act", "EU-AIA Art.5(1)"),
            ("eu_ai_act", "EU-AIA Art.15(3)"),
            ("dora", "DORA Art.6(1)"),
            ("australia_ai_ethics", "AU-P1.1"),
            ("singapore_maigf", "MAIGF — Internal Governance: documented AI policies"),
            ("uk_ai_framework", "UK SAF-1"),
            ("canada_aida", "AIDA §5(1)"),
            ("india_dpdp", "DPDP Art.8(1)"),
            ("china_ai", "CN-GAI Art.14(1)"),
            ("ccpa_cpra", "CCPA §1798.185(a)(16)"),
        ],
        0.85,
    ),
    (
        "acgs_lite.constitution.Constitution",
        "acgs-lite Constitution — declarative governance policy with rule versioning",
        [
            ("nist_ai_rmf", "NIST GOVERN 1.3"),
            ("iso_42001", "ISO 42001 §5.2"),
            ("eu_ai_act", "EU-AIA Art.9(4)"),
            ("canada_aida", "AIDA §5(2)"),
            ("australia_ai_ethics", "AU-P6.1"),
            ("singapore_maigf", "MAIGF — Internal Governance: documented AI policies"),
            ("uk_ai_framework", "UK SAF-3"),
        ],
        0.80,
    ),
    (
        "acgs_lite.governed.GovernedAgent",
        "acgs-lite GovernedAgent — agent wrapper enforcing constitutional governance",
        [
            ("nist_ai_rmf", "NIST GOVERN 1.2"),
            ("eu_ai_act", "EU-AIA Art.9(1)"),
            ("eu_ai_act", "EU-AIA Art.14(1)"),
            ("iso_42001", "ISO 42001 §8.1"),
            (
                "singapore_maigf",
                "MAIGF — Internal Governance: human review for significant decisions",
            ),
            ("uk_ai_framework", "UK SAF-2"),
            ("australia_ai_ethics", "AU-P8.1"),
        ],
        0.80,
    ),
    (
        "acgs_lite.maci.MACIEnforcer",
        "acgs-lite MACIEnforcer — role separation: proposer / validator / executor",
        [
            ("eu_ai_act", "EU-AIA Art.14(5)"),
            ("uk_ai_framework", "UK ACC-3"),
            ("singapore_maigf", "MAIGF — Internal Governance: roles & accountability"),
            ("nist_ai_rmf", "NIST GOVERN 2.1"),
            ("iso_42001", "ISO 42001 §5.3"),
            ("australia_ai_ethics", "AU-P4.2"),
            ("canada_aida", "AIDA §8(2)"),
        ],
        0.85,
    ),
    (
        "acgs_lite.report.RiskClassifier",
        "acgs-lite RiskClassifier — automated risk-level classification and tier mapping",
        [
            ("nist_ai_rmf", "NIST MAP 1.2"),
            ("eu_ai_act", "EU-AIA Art.9(2)"),
            ("eu_ai_act", "EU-AIA Art.27(1)"),
            ("dora", "DORA Art.8(3)"),
            ("iso_42001", "ISO 42001 §6.1.2"),
            ("singapore_maigf", "MAIGF — Internal Governance: human-AI decision model"),
            ("australia_ai_ethics", "AU-P7.1"),
            ("uk_ai_framework", "UK SAF-2"),
            ("india_dpdp", "DPDP §10(2)(c)"),
            ("china_ai", "CN-GAI Art.9(1)"),
        ],
        0.80,
    ),
    (
        "acgs_lite.report.TransparencyDisclosure",
        "acgs-lite TransparencyDisclosure — structured system card with mandatory fields",
        [
            ("eu_ai_act", "EU-AIA Art.13(1)"),
            ("eu_ai_act", "EU-AIA Art.13(3)"),
            ("eu_ai_act", "EU-AIA Art.50(1)"),
            ("eu_ai_act", "EU-AIA Art.11(1)"),
            ("uk_ai_framework", "UK TRA-1"),
            ("uk_ai_framework", "UK TRA-2"),
            ("singapore_maigf", "MAIGF — Stakeholder Interaction: AI involvement disclosure"),
            ("canada_aida", "AIDA §10(1)"),
            ("australia_ai_ethics", "AU-P5.1"),
            ("ccpa_cpra", "CCPA §1798.100(a)"),
            ("brazil_lgpd", "LGPD Art.9"),
            ("india_dpdp", "DPDP Art.5(1)"),
            ("nist_ai_rmf", "NIST GOVERN 4.1"),
            ("iso_42001", "ISO 42001 §7.4"),
        ],
        0.85,
    ),
    (
        "acgs_lite.report.HumanOversightGateway",
        "acgs-lite HumanOversightGateway — configurable HITL approval gates with audit trail",
        [
            ("eu_ai_act", "EU-AIA Art.14(1)"),
            ("eu_ai_act", "EU-AIA Art.14(4)"),
            ("gdpr", "GDPR Art.22(3)"),
            ("ccpa_cpra", "CPRA §1798.185(a)(16)"),
            ("uk_ai_framework", "UK ACC-2"),
            (
                "singapore_maigf",
                "MAIGF — Internal Governance: human review for significant decisions",
            ),
            ("australia_ai_ethics", "AU-P4.1"),
            ("canada_aida", "AIDA §8(1)"),
            ("brazil_lgpd", "LGPD Art.20(1)"),
            ("india_dpdp", "DPDP Art.14(1)"),
            ("nist_ai_rmf", "NIST MANAGE 1.2"),
            ("iso_42001", "ISO 42001 §8.4"),
            ("dora", "DORA Art.5(4)"),
        ],
        0.88,
    ),
]


# ---------------------------------------------------------------------------
# Filesystem artefact → article reference mapping
# ---------------------------------------------------------------------------

# Each entry: (glob_pattern, description, [(framework_id, ref), ...], confidence)
_FILE_EVIDENCE: list[tuple[str, str, list[tuple[str, str]], float]] = [
    (
        "rules.yaml",
        "ACGS governance rules file — constitutionalised policy",
        [
            ("nist_ai_rmf", "NIST GOVERN 1.2"),
            ("nist_ai_rmf", "NIST GOVERN 1.3"),
            ("iso_42001", "ISO 42001 §6.2"),
            ("eu_ai_act", "EU-AIA Art.9(1)"),
            ("australia_ai_ethics", "AU-P6.1"),
        ],
        0.70,
    ),
    (
        "governance.yaml",
        "Governance configuration file",
        [
            ("nist_ai_rmf", "NIST GOVERN 1.2"),
            ("iso_42001", "ISO 42001 §6.2"),
            ("eu_ai_act", "EU-AIA Art.9(1)"),
        ],
        0.65,
    ),
    (
        "privacy-policy.md",
        "Privacy policy document (Markdown)",
        [
            ("gdpr", "GDPR Art.13(1)"),
            ("gdpr", "GDPR Art.14(1)"),
            ("ccpa_cpra", "CCPA §1798.100(b)"),
            ("india_dpdp", "DPDP Art.5(2)"),
            ("brazil_lgpd", "LGPD Art.9"),
            ("china_ai", "CN-PIPL Art.17"),
            ("australia_ai_ethics", "AU-P5.2"),
        ],
        0.70,
    ),
    (
        "privacy-policy.html",
        "Privacy policy document (HTML)",
        [
            ("gdpr", "GDPR Art.13(1)"),
            ("ccpa_cpra", "CCPA §1798.100(b)"),
            ("india_dpdp", "DPDP Art.5(2)"),
            ("brazil_lgpd", "LGPD Art.9"),
        ],
        0.70,
    ),
    (
        "privacy_notice.*",
        "Privacy notice artefact",
        [
            ("gdpr", "GDPR Art.13(1)"),
            ("india_dpdp", "DPDP Art.5(1)"),
            ("brazil_lgpd", "LGPD Art.9"),
            ("china_ai", "CN-PIPL Art.17"),
        ],
        0.65,
    ),
    (
        "data-processing-agreement.*",
        "Data Processing Agreement (controller ↔ processor)",
        [
            ("gdpr", "GDPR Art.28(3)"),
            ("india_dpdp", "DPDP Art.8(2)"),
            ("brazil_lgpd", "LGPD Art.39"),
            ("uk_ai_framework", "UK TRA-3"),
        ],
        0.75,
    ),
    (
        "dpa.*",
        "Data Processing Agreement",
        [
            ("gdpr", "GDPR Art.28(3)"),
            ("india_dpdp", "DPDP Art.8(2)"),
        ],
        0.65,
    ),
    (
        "risk-register.*",
        "Risk register document",
        [
            ("eu_ai_act", "EU-AIA Art.9(2)"),
            ("dora", "DORA Art.6(1)"),
            ("iso_42001", "ISO 42001 §6.1.2"),
            ("nist_ai_rmf", "NIST MAP 1.5"),
            ("australia_ai_ethics", "AU-P7.1"),
            ("singapore_maigf", "MAIGF — Internal Governance: human-AI decision model"),
        ],
        0.75,
    ),
    (
        "risk_assessment.*",
        "Risk assessment document",
        [
            ("eu_ai_act", "EU-AIA Art.9(2)"),
            ("dora", "DORA Art.6(1)"),
            ("iso_42001", "ISO 42001 §6.1.2"),
            ("nist_ai_rmf", "NIST MAP 1.5"),
        ],
        0.70,
    ),
    (
        "impact-assessment.*",
        "Impact assessment (DPIA / FRIA)",
        [
            ("gdpr", "GDPR Art.35(1)"),
            ("eu_ai_act", "EU-AIA Art.27(1)"),
            ("india_dpdp", "DPDP §10(2)(c)"),
            ("brazil_lgpd", "LGPD Art.38"),
        ],
        0.75,
    ),
    (
        "pia.*",
        "Privacy Impact Assessment",
        [
            ("gdpr", "GDPR Art.35(1)"),
            ("india_dpdp", "DPDP §10(2)(c)"),
            ("canada_aida", "AIDA §11(1)"),
        ],
        0.70,
    ),
    (
        "fria.*",
        "Fundamental Rights Impact Assessment",
        [
            ("eu_ai_act", "EU-AIA Art.27(1)"),
        ],
        0.80,
    ),
    (
        "system-card.*",
        "AI system card (transparency disclosure)",
        [
            ("eu_ai_act", "EU-AIA Art.13(1)"),
            ("eu_ai_act", "EU-AIA Art.11(1)"),
            ("nist_ai_rmf", "NIST GOVERN 4.1"),
            (
                "singapore_maigf",
                "MAIGF — Stakeholder Interaction: decision-factor transparency",
            ),
            ("uk_ai_framework", "UK TRA-1"),
            ("australia_ai_ethics", "AU-P5.1"),
        ],
        0.80,
    ),
    (
        "model-card.*",
        "ML model card (capabilities and limitations)",
        [
            ("eu_ai_act", "EU-AIA Art.13(1)"),
            ("nist_ai_rmf", "NIST GOVERN 4.1"),
            ("canada_aida", "AIDA §10(1)"),
        ],
        0.75,
    ),
    (
        "transparency-disclosure.*",
        "Transparency disclosure document",
        [
            ("eu_ai_act", "EU-AIA Art.13(1)"),
            ("canada_aida", "AIDA §10(1)"),
            ("uk_ai_framework", "UK TRA-2"),
            (
                "singapore_maigf",
                "MAIGF — Stakeholder Interaction: AI involvement disclosure",
            ),
        ],
        0.75,
    ),
    (
        "*.audit.jsonl",
        "Audit log file (JSONL format)",
        [
            ("eu_ai_act", "EU-AIA Art.12(1)"),
            ("dora", "DORA Art.8(6)"),
            ("gdpr", "GDPR Art.30(1)"),
            ("india_dpdp", "DPDP Art.11(3)"),
            ("brazil_lgpd", "LGPD Art.37"),
        ],
        0.85,
    ),
    (
        ".acgs_assessment.json",
        "Cached ACGS compliance assessment (previous run)",
        [
            ("*", "evidence of prior compliance assessment activity"),
        ],
        0.55,
    ),
    (
        "incident-response-plan.*",
        "Incident response / business continuity plan",
        [
            ("dora", "DORA Art.11(1)"),
            ("dora", "DORA Art.17(6)"),
            ("iso_42001", "ISO 42001 §8.6"),
            ("nist_ai_rmf", "NIST MANAGE 2.2"),
        ],
        0.70,
    ),
    (
        "bias-assessment.*",
        "Bias / fairness assessment report",
        [
            ("eu_ai_act", "EU-AIA Art.10(2)"),
            ("us_fair_lending", "ECOA §704B(e)(2)(A)"),
            ("nyc_ll144", "NYC LL144 §20-871(b)"),
            ("australia_ai_ethics", "AU-P2.1"),
        ],
        0.75,
    ),
    (
        "data-governance-policy.*",
        "Data governance policy document",
        [
            ("gdpr", "GDPR Art.5(1)"),
            ("eu_ai_act", "EU-AIA Art.10(2)"),
            ("iso_42001", "ISO 42001 §8.3"),
            ("india_dpdp", "DPDP Art.8(1)"),
            ("china_ai", "CN-PIPL Art.51"),
        ],
        0.70,
    ),
    (
        "opt-out.*",
        "Opt-out / data subject rights procedure",
        [
            ("ccpa_cpra", "CCPA §1798.120"),
            ("gdpr", "GDPR Art.17(1)"),
            ("brazil_lgpd", "LGPD Art.18(VI)"),
            ("india_dpdp", "DPDP Art.13(1)"),
        ],
        0.65,
    ),
]


# ---------------------------------------------------------------------------
# Environment variable → article reference mapping
# ---------------------------------------------------------------------------

# Each entry: (env_var, value_hint, description, [(framework_id, ref), ...], confidence)
_ENV_EVIDENCE: list[tuple[str, str | None, str, list[tuple[str, str]], float]] = [
    (
        "ACGS_AUDIT_ENABLED",
        "true",
        "Audit logging explicitly enabled via environment variable",
        [
            ("eu_ai_act", "EU-AIA Art.12(1)"),
            ("dora", "DORA Art.8(6)"),
            ("gdpr", "GDPR Art.30(1)"),
            ("india_dpdp", "DPDP Art.11(3)"),
        ],
        0.80,
    ),
    (
        "ACGS_HUMAN_OVERSIGHT",
        None,  # any value counts
        "Human oversight mode configured via environment variable",
        [
            ("eu_ai_act", "EU-AIA Art.14(1)"),
            ("gdpr", "GDPR Art.22(3)"),
            ("canada_aida", "AIDA §8(1)"),
        ],
        0.75,
    ),
    (
        "GDPR_DATA_CONTROLLER",
        None,
        "GDPR data controller identity declared in environment",
        [
            ("gdpr", "GDPR Art.13(1)(a)"),
            ("gdpr", "GDPR Art.4(7)"),
        ],
        0.75,
    ),
    (
        "GDPR_DPO_CONTACT",
        None,
        "Data Protection Officer contact configured",
        [
            ("gdpr", "GDPR Art.37(1)"),
        ],
        0.80,
    ),
    (
        "CCPA_ENABLED",
        "true",
        "CCPA/CPRA compliance flag set in environment",
        [
            ("ccpa_cpra", "CCPA §1798.100(a)"),
            ("ccpa_cpra", "CCPA §1798.120"),
        ],
        0.70,
    ),
    (
        "CCPA_OPT_OUT_URL",
        None,
        "CCPA 'Do Not Sell or Share' opt-out URL configured",
        [
            ("ccpa_cpra", "CCPA §1798.120(2)"),
        ],
        0.80,
    ),
    (
        "DPDP_DATA_FIDUCIARY",
        None,
        "India DPDP data fiduciary identity declared",
        [
            ("india_dpdp", "DPDP Art.4(i)"),
            ("india_dpdp", "DPDP Art.11(1)"),
        ],
        0.75,
    ),
    (
        "LGPD_CONTROLLER",
        None,
        "Brazil LGPD data controller identity declared",
        [
            ("brazil_lgpd", "LGPD Art.5(VI)"),
            ("brazil_lgpd", "LGPD Art.23(I)"),
        ],
        0.75,
    ),
    (
        "CHINA_AI_PROVIDER",
        None,
        "China AI provider identity declared (algorithmic recommendation / GenAI)",
        [
            ("china_ai", "CN-ARS Art.5"),
            ("china_ai", "CN-GAI Art.5(1)"),
        ],
        0.75,
    ),
    (
        "ACGS_RISK_TIER",
        None,
        "EU AI Act risk tier explicitly configured in environment",
        [
            ("eu_ai_act", "EU-AIA Art.9(1)"),
        ],
        0.70,
    ),
    (
        "DORA_ENTITY_TYPE",
        None,
        "DORA financial entity type configured (ICT risk management scope)",
        [
            ("dora", "DORA Art.3(1)"),
            ("dora", "DORA Art.6(1)"),
        ],
        0.70,
    ),
    (
        "ACGS_CONSTITUTIONAL_HASH",
        None,
        "Constitutional hash configured — governance pinning active",
        [
            ("nist_ai_rmf", "NIST GOVERN 1.3"),
            ("iso_42001", "ISO 42001 §5.2"),
        ],
        0.80,
    ),
]


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------


class ACGSLiteImportCollector:
    """Check which acgs-lite components are importable in the current runtime.

    Each importable component generates evidence items for the article
    references it supports across all 20 frameworks.
    """

    def collect(self, system_description: dict[str, Any]) -> list[EvidenceItem]:  # noqa: ARG002
        items: list[EvidenceItem] = []
        for import_path, description, refs, confidence in _COMPONENT_EVIDENCE:
            if self._is_importable(import_path):
                # Group refs by framework_id for one item per framework
                fw_refs: dict[str, list[str]] = {}
                for fw_id, ref in refs:
                    fw_refs.setdefault(fw_id, []).append(ref)
                for fw_id, fw_ref_list in fw_refs.items():
                    items.append(
                        EvidenceItem(
                            framework_id=fw_id,
                            article_refs=tuple(fw_ref_list),
                            source=f"import:{import_path}",
                            description=description,
                            confidence=confidence,
                        )
                    )
        return items

    @staticmethod
    def _is_importable(import_path: str) -> bool:
        """Check if *import_path* is importable without raising."""
        parts = import_path.rsplit(".", 1)
        module_path = parts[0]
        try:
            import importlib

            mod = importlib.import_module(module_path)
            if len(parts) == 2:
                return hasattr(mod, parts[1])
            return True
        except (ImportError, ModuleNotFoundError):
            return False


class FileSystemCollector:
    """Scan the working directory for compliance artefacts.

    Searches *search_root* (default: ``Path.cwd()``) for files matching
    each pattern in :data:`_FILE_EVIDENCE`. Glob matching is non-recursive
    so that e.g. ``rules.yaml`` is not found deep inside ``node_modules/``.
    """

    def __init__(self, search_root: Path | None = None) -> None:
        self._root = search_root or Path.cwd()

    def collect(self, system_description: dict[str, Any]) -> list[EvidenceItem]:  # noqa: ARG002
        items: list[EvidenceItem] = []
        for pattern, description, refs, confidence in _FILE_EVIDENCE:
            matches = list(self._root.glob(pattern))
            if not matches:
                continue
            # Group refs by framework_id
            fw_refs: dict[str, list[str]] = {}
            for fw_id, ref in refs:
                fw_refs.setdefault(fw_id, []).append(ref)
            for fw_id, fw_ref_list in fw_refs.items():
                items.append(
                    EvidenceItem(
                        framework_id=fw_id,
                        article_refs=tuple(fw_ref_list),
                        source=f"file:{matches[0].name}",
                        description=f"{description} — found: {matches[0].name}",
                        confidence=confidence,
                    )
                )
        return items


class EnvironmentVarCollector:
    """Check environment variables that signal compliance configuration.

    Reads ``os.environ`` for each variable in :data:`_ENV_EVIDENCE`.  If
    the variable is set (and, where *value_hint* is given, non-empty), an
    :class:`EvidenceItem` is created for each referenced article.
    """

    def collect(self, system_description: dict[str, Any]) -> list[EvidenceItem]:  # noqa: ARG002
        items: list[EvidenceItem] = []
        for env_var, value_hint, description, refs, confidence in _ENV_EVIDENCE:
            val = os.environ.get(env_var, "")
            if not val:
                continue
            if value_hint is not None and val.lower() != value_hint.lower():
                continue
            fw_refs: dict[str, list[str]] = {}
            for fw_id, ref in refs:
                fw_refs.setdefault(fw_id, []).append(ref)
            for fw_id, fw_ref_list in fw_refs.items():
                items.append(
                    EvidenceItem(
                        framework_id=fw_id,
                        article_refs=tuple(fw_ref_list),
                        source=f"env:{env_var}",
                        description=f"{description} ({env_var}={val[:40]})",
                        confidence=confidence,
                    )
                )
        return items


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ComplianceEvidenceEngine:
    """Orchestrates all registered collectors and aggregates the results.

    Usage::

        engine = ComplianceEvidenceEngine()
        bundle = engine.collect({"system_id": "my-ai"})
        print(bundle.summary())

        # Customise collectors
        engine = ComplianceEvidenceEngine(
            collectors=[ACGSLiteImportCollector(), FileSystemCollector(Path("/my/project"))]
        )
    """

    def __init__(
        self,
        collectors: list[EvidenceCollector] | None = None,
    ) -> None:
        # Explicitly check None: an empty list [] must stay empty (not replaced
        # with defaults), because tests and callers pass [] to disable collection.
        self.collectors: list[EvidenceCollector] = (
            [ACGSLiteImportCollector(), FileSystemCollector(), EnvironmentVarCollector()]
            if collectors is None
            else collectors
        )

    def collect(self, system_description: dict[str, Any]) -> EvidenceBundle:
        """Run all collectors and return an :class:`EvidenceBundle`."""
        system_id: str = system_description.get("system_id", "unknown")
        all_items: list[EvidenceItem] = []
        for collector in self.collectors:
            all_items.extend(collector.collect(system_description))
        return EvidenceBundle(
            system_id=system_id,
            collected_at=datetime.now(timezone.utc).isoformat(),
            items=tuple(all_items),
        )


# ---------------------------------------------------------------------------
# Audit log evidence collector
# ---------------------------------------------------------------------------

# Maps audit entry types to article references with confidence factors
_AUDIT_TYPE_EVIDENCE: dict[str, list[tuple[str, str, float]]] = {
    "validation": [
        ("eu_ai_act", "EU-AIA Art.9(1)", 0.85),  # Risk management
        ("eu_ai_act", "EU-AIA Art.12(1)", 0.90),  # Automatic logging
        ("nist_ai_rmf", "NIST MEASURE 1.3", 0.80),
        ("iso_42001", "ISO 42001 §9.1", 0.80),
        ("dora", "DORA Art.8(6)", 0.80),
    ],
    "maci_check": [
        ("eu_ai_act", "EU-AIA Art.14(5)", 0.90),  # Human oversight design
        ("eu_ai_act", "EU-AIA Art.14(1)", 0.85),  # Effective oversight
        ("nist_ai_rmf", "NIST GOVERN 2.1", 0.80),
        ("iso_42001", "ISO 42001 §5.3", 0.80),
    ],
    "override": [
        ("eu_ai_act", "EU-AIA Art.14(4)", 0.90),  # Intervention capability
        ("gdpr", "GDPR Art.22(3)", 0.85),  # Right to contest
        ("nist_ai_rmf", "NIST MANAGE 1.2", 0.80),
    ],
}


class AuditLogEvidenceCollector:
    """Generate compliance evidence from actual governance audit log entries.

    Bridges runtime behavior to regulatory evidence: if the audit log
    contains validation entries, that's proof of Article 9 risk management.
    If it contains MACI checks, that's proof of Article 14 oversight.

    Args:
        audit_log: An :class:`~acgs_lite.audit.AuditLog` instance to analyze.
        min_entries: Minimum entries required to generate evidence (default 1).
    """

    def __init__(self, audit_log: Any, min_entries: int = 1) -> None:
        self._audit_log = audit_log
        self._min_entries = min_entries

    def collect(self, system_description: dict[str, Any]) -> list[EvidenceItem]:  # noqa: ARG002
        items: list[EvidenceItem] = []

        if not hasattr(self._audit_log, "entries"):
            return items

        entries = self._audit_log.entries
        if len(entries) < self._min_entries:
            return items

        # Count entries by type
        type_counts: dict[str, int] = {}
        for entry in entries:
            entry_type = getattr(entry, "type", "unknown")
            type_counts[entry_type] = type_counts.get(entry_type, 0) + 1

        total = len(entries)

        for entry_type, count in type_counts.items():
            refs = _AUDIT_TYPE_EVIDENCE.get(entry_type, [])
            if not refs:
                continue

            # Scale confidence by volume: 1 entry = base * 0.5, 100+ = base * 1.0
            volume_factor = min(1.0, 0.5 + (count / 200))

            # Group refs by framework
            fw_refs: dict[str, list[tuple[str, float]]] = {}
            for fw_id, ref, base_conf in refs:
                fw_refs.setdefault(fw_id, []).append((ref, base_conf * volume_factor))

            for fw_id, ref_list in fw_refs.items():
                article_refs = tuple(r for r, _ in ref_list)
                confidence = max(c for _, c in ref_list)
                items.append(
                    EvidenceItem(
                        framework_id=fw_id,
                        article_refs=article_refs,
                        source=f"audit:{entry_type}:{count}/{total}",
                        description=(
                            f"Runtime audit log contains {count} {entry_type} "
                            f"entries out of {total} total — governance actively enforced"
                        ),
                        confidence=round(confidence, 3),
                    )
                )

        # Chain integrity as additional evidence
        if hasattr(self._audit_log, "verify_chain") and self._audit_log.verify_chain():
            items.append(
                EvidenceItem(
                    framework_id="eu_ai_act",
                    article_refs=("EU-AIA Art.12(2)",),
                    source=f"audit:chain_valid:{total}",
                    description=(
                        f"Audit chain integrity verified — {total} entries, "
                        f"SHA-256 hash chain intact"
                    ),
                    confidence=0.95,
                )
            )

        return items


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------


def collect_evidence(
    system_description: dict[str, Any] | None = None,
    search_root: Path | None = None,
    audit_log: Any | None = None,
) -> EvidenceBundle:
    """Collect all available evidence for *system_description*.

    Shortcut for ``ComplianceEvidenceEngine().collect(system_description)``.

    Args:
        system_description: System metadata dict (may include ``system_id``,
            ``jurisdiction``, ``domain``).
        search_root: Override the filesystem search root (default: ``Path.cwd()``).
        audit_log: Optional :class:`~acgs_lite.audit.AuditLog` instance for
            runtime evidence collection.

    Returns:
        An :class:`EvidenceBundle` with all findings.
    """
    desc = system_description or {}
    collectors: list[EvidenceCollector] = [
        ACGSLiteImportCollector(),
        FileSystemCollector(search_root),
        EnvironmentVarCollector(),
    ]
    if audit_log is not None:
        collectors.append(AuditLogEvidenceCollector(audit_log))
    return ComplianceEvidenceEngine(collectors=collectors).collect(desc)


# ---------------------------------------------------------------------------
# Backward-compat alias: EvidenceRecord (pre-v2.5 name used by SOC 2 etc.)
# ---------------------------------------------------------------------------

import uuid as _uuid
from dataclasses import asdict as _asdict
from dataclasses import dataclass as _dc
from dataclasses import field as _field
from datetime import datetime as _datetime
from datetime import timezone as _timezone
from typing import Any as _Any

_NOT_ASSESSED = "not_assessed"


@_dc
class EvidenceRecord:
    """Backward-compatible evidence record (pre-v2.5 API).

    Has both the legacy SOC 2/GDPR fields (framework, control_id) and
    the concrete collector fields (system_id, ref) expected by tests.
    New code should use :class:`EvidenceItem` produced by collector classes.
    """

    record_id: str = _field(default_factory=lambda: str(_uuid.uuid4()))
    system_id: str = ""
    ref: str = ""
    framework: str = ""
    control_id: str = ""
    title: str = ""
    evidence_type: str = "attestation"
    collected_at: str = _field(
        default_factory=lambda: _datetime.now(_timezone.utc).isoformat(),
    )
    data: dict[str, _Any] = _field(default_factory=dict)
    status: str = _NOT_ASSESSED

    def to_dict(self) -> dict[str, _Any]:
        return _asdict(self)


# ---------------------------------------------------------------------------
# Concrete EvidenceCollector class (pre-v2.5 API, used by SOC 2 / GDPR tests)
# EvidenceCollector in the new API is a Protocol; this concrete class provides
# the old add()/records/records_for_ref()/summary()/clear() interface.
# ---------------------------------------------------------------------------


class _ConcreteEvidenceCollector:
    """Concrete evidence collector with add/retrieve/summary interface."""

    def __init__(self, system_id: str = "") -> None:
        self._system_id = system_id
        self._records: list[EvidenceRecord] = []

    @property
    def records(self) -> list[EvidenceRecord]:
        return list(self._records)

    def add(
        self,
        ref: str,
        evidence_type: str = "attestation",
        data: dict[str, _Any] | None = None,
    ) -> EvidenceRecord:
        rec = EvidenceRecord(
            system_id=self._system_id,
            ref=ref,
            control_id=ref,
            title=ref,
            evidence_type=evidence_type,
            data=data or {},
        )
        self._records.append(rec)
        return rec

    def records_for_ref(self, ref: str) -> list[EvidenceRecord]:
        return [r for r in self._records if r.ref == ref]

    def clear(self) -> None:
        self._records.clear()

    def summary(self) -> dict[str, _Any]:
        return {
            "system_id": self._system_id,
            "total_records": len(self._records),
            "unique_refs": sorted({r.ref for r in self._records}),
            "evidence_types": sorted({r.evidence_type for r in self._records}),
        }


# EvidenceCollectorImpl is the concrete instantiable class.
# compliance/__init__.py exports this as EvidenceCollector for backward
# compatibility with test_compliance.py (which does EvidenceCollector(system_id=...).
# The EvidenceCollector Protocol from the body of this file is kept for
# test_compliance_evidence.py which checks isinstance(obj, EvidenceCollector).
EvidenceCollectorImpl = _ConcreteEvidenceCollector

# Backward-compat aliases for the old SOC2/ISO/GDPR collector API.
# These were replaced by the generic collector pattern but old tests import them.
ComplianceFramework = EvidenceCollector  # Protocol alias
SOC2EvidenceCollector = _ConcreteEvidenceCollector
ISO27001EvidenceCollector = _ConcreteEvidenceCollector
GDPREvidenceCollector = _ConcreteEvidenceCollector
