"""Multi-framework compliance orchestrator.

Runs compliance assessment across all applicable regulatory frameworks
and produces a unified MultiFrameworkReport with cross-framework gap
analysis, overall scoring, and prioritized recommendations.

Constitutional Hash: 608508a9bd224290

Usage::

    from acgs_lite.compliance import MultiFrameworkAssessor

    assessor = MultiFrameworkAssessor()
    report = assessor.assess({"system_id": "my-system", "domain": "healthcare"})

    print(report.overall_score)          # 0.65
    print(report.frameworks_assessed)    # ("gdpr", "hipaa_ai", "nist_ai_rmf", ...)
    print(report.cross_framework_gaps)   # Common gaps across frameworks
"""

from __future__ import annotations

import dataclasses
import importlib.metadata
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

from acgs_lite.compliance.australia_ai_ethics import AustraliaAIEthicsFramework
from acgs_lite.compliance.base import (
    ChecklistStatus,
    ComplianceFramework,
    FrameworkAssessment,
    MultiFrameworkReport,
)
from acgs_lite.compliance.brazil_lgpd import BrazilLGPDFramework
from acgs_lite.compliance.canada_aida import CanadaAIDAFramework
from acgs_lite.compliance.ccpa_cpra import CCPACPRAFramework
from acgs_lite.compliance.china_ai import ChinaAIFramework
from acgs_lite.compliance.dora import DORAFramework
from acgs_lite.compliance.eu_ai_act import EUAIActFramework
from acgs_lite.compliance.gdpr import GDPRFramework
from acgs_lite.compliance.hipaa_ai import HIPAAAIFramework
from acgs_lite.compliance.igaming import IGamingFramework
from acgs_lite.compliance.india_dpdp import IndiaDPDPFramework
from acgs_lite.compliance.iso_42001 import ISO42001Framework
from acgs_lite.compliance.japan_ai_guidelines import JapanAIGuidelinesFramework
from acgs_lite.compliance.nist_ai_rmf import NISTAIRMFFramework
from acgs_lite.compliance.nyc_ll144 import NYCLL144Framework
from acgs_lite.compliance.oecd_ai import OECDAIFramework
from acgs_lite.compliance.singapore_maigf import SingaporeMAIGFFramework
from acgs_lite.compliance.soc2_ai import SOC2AIFramework
from acgs_lite.compliance.uk_ai_framework import UKAIFramework
from acgs_lite.compliance.us_fair_lending import USFairLendingFramework

# Registry of all available compliance frameworks
_FRAMEWORK_REGISTRY: dict[str, type] = {
    # Original 8
    "nist_ai_rmf": NISTAIRMFFramework,
    "iso_42001": ISO42001Framework,
    "gdpr": GDPRFramework,
    "soc2_ai": SOC2AIFramework,
    "hipaa_ai": HIPAAAIFramework,
    "us_fair_lending": USFairLendingFramework,
    "nyc_ll144": NYCLL144Framework,
    "oecd_ai": OECDAIFramework,
    # Round 2: +5
    "eu_ai_act": EUAIActFramework,
    "dora": DORAFramework,
    "canada_aida": CanadaAIDAFramework,
    "singapore_maigf": SingaporeMAIGFFramework,
    "uk_ai_framework": UKAIFramework,
    # Round 3: +5
    "india_dpdp": IndiaDPDPFramework,
    "australia_ai_ethics": AustraliaAIEthicsFramework,
    "brazil_lgpd": BrazilLGPDFramework,
    "china_ai": ChinaAIFramework,
    "ccpa_cpra": CCPACPRAFramework,
    # Round 4: iGaming vertical
    "igaming": IGamingFramework,
    # Round 5: +1
    "japan_ai_guidelines": JapanAIGuidelinesFramework,
}

# Jurisdiction -> frameworks that apply
_JURISDICTION_MAP: dict[str, list[str]] = {
    "united_states": ["nist_ai_rmf", "soc2_ai", "oecd_ai", "ccpa_cpra"],
    "european_union": ["gdpr", "eu_ai_act", "iso_42001", "oecd_ai"],
    "international": ["iso_42001", "oecd_ai"],
    "new_york_city": ["nist_ai_rmf", "soc2_ai", "nyc_ll144", "oecd_ai"],
    "canada": ["canada_aida", "nist_ai_rmf", "oecd_ai"],
    "united_kingdom": ["uk_ai_framework", "iso_42001", "oecd_ai", "igaming"],
    "malta": ["igaming", "eu_ai_act"],
    "gibraltar": ["igaming"],
    "singapore": ["singapore_maigf", "iso_42001", "oecd_ai"],
    "asean": ["singapore_maigf", "oecd_ai"],
    "japan": ["japan_ai_guidelines", "iso_42001", "oecd_ai"],
    "india": ["india_dpdp", "oecd_ai"],
    "australia": ["australia_ai_ethics", "oecd_ai"],
    "brazil": ["brazil_lgpd", "oecd_ai"],
    "china": ["china_ai"],
    "california": ["ccpa_cpra", "nist_ai_rmf"],
}

# Domain -> additional frameworks
_DOMAIN_MAP: dict[str, list[str]] = {
    "healthcare": ["hipaa_ai"],
    "medical": ["hipaa_ai"],
    "lending": ["us_fair_lending"],
    "credit": ["us_fair_lending"],
    "credit_scoring": ["us_fair_lending"],
    "financial": ["us_fair_lending", "soc2_ai", "dora"],
    "finance": ["us_fair_lending", "soc2_ai", "dora"],
    "fintech": ["dora", "soc2_ai"],
    "banking": ["dora", "us_fair_lending", "soc2_ai"],
    "insurance": ["dora", "soc2_ai"],
    "employment": ["nyc_ll144"],
    "hiring": ["nyc_ll144"],
    "general_purpose_ai": ["eu_ai_act"],
    "gpai": ["eu_ai_act"],
    "gambling": ["igaming"],
    "igaming": ["igaming"],
    "sports_betting": ["igaming"],
    "casino": ["igaming"],
    "betting": ["igaming"],
}

_plugins_loaded = False


def _load_plugins() -> None:
    """Discover and load third-party compliance frameworks via entry points.

    Entry point group: ``acgs_lite.compliance_frameworks``

    Example pyproject.toml for a plugin::

        [project.entry-points."acgs_lite.compliance_frameworks"]
        my_framework = "my_package:MyFrameworkClass"
    """
    global _plugins_loaded
    if _plugins_loaded:
        return
    _plugins_loaded = True

    try:
        eps = importlib.metadata.entry_points()
        # Python 3.12+ returns a SelectableGroups; 3.10-3.11 returns a dict
        if hasattr(eps, "select"):
            group = eps.select(group="acgs_lite.compliance_frameworks")
        else:
            group = eps.get("acgs_lite.compliance_frameworks", [])  # type: ignore[arg-type]

        for ep in group:
            if ep.name in _FRAMEWORK_REGISTRY:
                logger.debug("plugin %s skipped: ID already registered", ep.name)
                continue
            try:
                cls = ep.load()
                _FRAMEWORK_REGISTRY[ep.name] = cls
                logger.debug("plugin framework registered: %s", ep.name)
            except Exception as exc:
                logger.warning(
                    "failed to load compliance plugin %s: %s", ep.name, exc, exc_info=True
                )
    except Exception as exc:
        logger.debug("entry point discovery failed: %s", exc, exc_info=True)


def register_framework(framework_id: str, cls: type) -> None:
    """Programmatically register a compliance framework.

    Args:
        framework_id: Unique identifier (e.g. "my_custom_fw").
        cls: Framework class implementing the ComplianceFramework protocol.
    """
    _FRAMEWORK_REGISTRY[framework_id] = cls


def register_jurisdiction(jurisdiction: str, framework_ids: list[str]) -> None:
    """Add or extend a jurisdiction mapping.

    Args:
        jurisdiction: Jurisdiction key (e.g. "south_korea").
        framework_ids: List of framework IDs that apply.
    """
    existing = _JURISDICTION_MAP.get(jurisdiction, [])
    merged = list(dict.fromkeys(existing + framework_ids))
    _JURISDICTION_MAP[jurisdiction] = merged


def register_domain(domain: str, framework_ids: list[str]) -> None:
    """Add or extend a domain mapping.

    Args:
        domain: Domain key (e.g. "autonomous_vehicles").
        framework_ids: List of framework IDs that apply.
    """
    existing = _DOMAIN_MAP.get(domain, [])
    merged = list(dict.fromkeys(existing + framework_ids))
    _DOMAIN_MAP[domain] = merged


# ---------------------------------------------------------------------------
# Evidence integration
# ---------------------------------------------------------------------------


def _apply_evidence_to_assessment(
    assessment: FrameworkAssessment,
    bundle: Any,  # EvidenceBundle — imported lazily to avoid circular import
) -> FrameworkAssessment:
    """Upgrade PENDING checklist items to COMPLIANT when evidence exists.

    Walks the evidence bundle for items whose ``article_refs`` match a PENDING
    checklist item, then creates a new :class:`FrameworkAssessment` (via
    ``dataclasses.replace``) with updated items, score, and gaps.

    Args:
        assessment: Frozen FrameworkAssessment from a normal ``fw.assess()`` call.
        bundle: :class:`~acgs_lite.compliance.evidence.EvidenceBundle` with
            collected runtime / filesystem / env-var evidence.

    Returns:
        A new ``FrameworkAssessment`` with evidence applied, or the original
        unchanged if no matching evidence was found.
    """
    fw_id = assessment.framework_id
    evidence_items = bundle.for_framework(fw_id)  # includes "*" wildcards
    if not evidence_items:
        return assessment

    # Build ref → best evidence description (highest confidence wins)
    ref_to_ev: dict[str, str] = {}
    for ev in sorted(evidence_items, key=lambda e: e.confidence, reverse=True):
        for ref in ev.article_refs:
            if ref not in ref_to_ev:
                ref_to_ev[ref] = ev.description

    if not ref_to_ev:
        return assessment

    _compliant_statuses = {
        ChecklistStatus.COMPLIANT.value,
        ChecklistStatus.NOT_APPLICABLE.value,
    }
    _pending = ChecklistStatus.PENDING.value
    _compliant = ChecklistStatus.COMPLIANT.value

    updated: list[dict[str, Any]] = []
    changed = False
    for item_dict in assessment.items:
        item = dict(item_dict)
        if item.get("status") == _pending and item.get("ref") in ref_to_ev:
            item["status"] = _compliant
            item["evidence"] = ref_to_ev[item["ref"]]
            changed = True
        updated.append(item)

    if not changed:
        return assessment

    total = len(updated)
    compliant_count = sum(1 for i in updated if i.get("status") in _compliant_statuses)
    new_score = round(compliant_count / total, 4) if total else 1.0
    new_gaps = tuple(
        f"{i['ref']}: {str(i.get('requirement', ''))[:120]}"
        for i in updated
        if i.get("status") not in _compliant_statuses and i.get("blocking", True)
    )

    return dataclasses.replace(
        assessment,
        compliance_score=new_score,
        items=tuple(updated),
        gaps=new_gaps,
    )


# Gap categories that appear across multiple frameworks
_CROSS_FRAMEWORK_THEMES: dict[str, list[str]] = {
    "bias_testing": [
        "bias",
        "fairness",
        "discrimination",
        "disparate",
        "demographic",
    ],
    "data_governance": [
        "data governance",
        "data lineage",
        "training data",
        "data quality",
    ],
    "incident_response": [
        "incident",
        "breach",
        "notification",
        "response",
    ],
    "model_documentation": [
        "documentation",
        "technical documentation",
        "model inventory",
    ],
    "stakeholder_engagement": [
        "stakeholder",
        "affected",
        "community",
        "engagement",
    ],
}


class MultiFrameworkAssessor:
    """Run compliance assessment across multiple regulatory frameworks.

    Accepts a list of framework IDs to assess, or determines applicable
    frameworks automatically based on jurisdiction and domain.

    Args:
        frameworks: List of framework IDs to assess. If None, determines
            applicable frameworks based on system_description.

    Usage::

        # Explicit framework selection
        assessor = MultiFrameworkAssessor(frameworks=["gdpr", "nist_ai_rmf"])
        report = assessor.assess({"system_id": "my-system"})

        # Automatic framework selection
        assessor = MultiFrameworkAssessor()
        report = assessor.assess({
            "system_id": "my-system",
            "jurisdiction": "european_union",
            "domain": "healthcare",
        })
    """

    def __init__(self, frameworks: list[str] | None = None) -> None:
        """Initialize with an optional list of framework IDs to assess."""
        _load_plugins()
        self._requested_frameworks = frameworks
        self._instances: dict[str, ComplianceFramework] = {}

    def _resolve_frameworks(
        self,
        system_description: dict[str, Any],
    ) -> list[str]:
        """Determine which frameworks to run."""
        if self._requested_frameworks is not None:
            # Normalize CLI-style dashed IDs (e.g. "japan-ai-guidelines") to the
            # canonical underscore registry keys ("japan_ai_guidelines").
            resolved: list[str] = []
            for fid in self._requested_frameworks:
                key = fid if fid in _FRAMEWORK_REGISTRY else fid.replace("-", "_")
                if key in _FRAMEWORK_REGISTRY:
                    resolved.append(key)
            return resolved

        jurisdiction = system_description.get("jurisdiction", "").lower().replace(" ", "_")
        domain = system_description.get("domain", "").lower().replace(" ", "_")

        fw_ids: set[str] = set()

        # Add jurisdiction-based frameworks
        if jurisdiction in _JURISDICTION_MAP:
            fw_ids.update(_JURISDICTION_MAP[jurisdiction])

        # Add domain-based frameworks
        if domain in _DOMAIN_MAP:
            fw_ids.update(_DOMAIN_MAP[domain])

        # If nothing matched, run all
        if not fw_ids:
            fw_ids = set(_FRAMEWORK_REGISTRY.keys())

        return sorted(fw_ids)

    def _get_instance(self, framework_id: str) -> ComplianceFramework:
        """Get or create a framework instance."""
        if framework_id not in self._instances:
            cls = _FRAMEWORK_REGISTRY[framework_id]
            self._instances[framework_id] = cls()
        return self._instances[framework_id]

    def applicable_frameworks(
        self,
        jurisdiction: str,
        domain: str,
    ) -> list[str]:
        """Determine which frameworks apply based on jurisdiction and domain.

        Args:
            jurisdiction: Jurisdiction string (e.g. "european_union", "united_states").
            domain: Application domain (e.g. "healthcare", "lending").

        Returns:
            Sorted list of applicable framework IDs.

        """
        desc = {"jurisdiction": jurisdiction, "domain": domain}
        return self._resolve_frameworks(desc)

    def assess(self, system_description: dict[str, Any]) -> MultiFrameworkReport:
        """Run all applicable frameworks and return a unified report.

        Args:
            system_description: Dict describing the AI system. Expected keys:
                - system_id: str (required)
                - jurisdiction: str (optional, for auto-selection)
                - domain: str (optional, for auto-selection)
                - purpose: str (optional)
                - _evidence: :class:`~acgs_lite.compliance.evidence.EvidenceBundle`
                  (optional) — collected runtime evidence; upgrades matching PENDING
                  items to COMPLIANT automatically.
                - Additional framework-specific keys.

        Returns:
            Frozen MultiFrameworkReport with per-framework and cross-framework results.

        """
        system_id = system_description.get("system_id", "unknown")
        fw_ids = self._resolve_frameworks(system_description)
        evidence = system_description.get("_evidence")

        by_framework: dict[str, FrameworkAssessment] = {}
        for fid in fw_ids:
            fw = self._get_instance(fid)
            assessment = fw.assess(system_description)
            if evidence is not None:
                assessment = _apply_evidence_to_assessment(assessment, evidence)
            by_framework[fid] = assessment

        overall_score = _compute_overall_score(by_framework)
        acgs_total = _compute_acgs_coverage(by_framework)
        cross_gaps = _identify_cross_framework_gaps(by_framework)
        recommendations = _generate_prioritized_recommendations(by_framework, cross_gaps)

        return MultiFrameworkReport(
            system_id=system_id,
            frameworks_assessed=tuple(fw_ids),
            overall_score=overall_score,
            by_framework=by_framework,
            cross_framework_gaps=cross_gaps,
            acgs_lite_total_coverage=acgs_total,
            recommendations=recommendations,
            assessed_at=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def available_frameworks() -> dict[str, str]:
        """Return all registered framework IDs and names.

        Returns:
            Dict mapping framework_id to framework_name.

        """
        result: dict[str, str] = {}
        for fid, cls in sorted(_FRAMEWORK_REGISTRY.items()):
            instance = cls()
            result[fid] = instance.framework_name
        return result


def _compute_overall_score(
    by_framework: dict[str, FrameworkAssessment],
) -> float:
    """Compute weighted average compliance score across frameworks."""
    if not by_framework:
        return 0.0
    total = sum(a.compliance_score for a in by_framework.values())
    return round(total / len(by_framework), 4)


def _compute_acgs_coverage(
    by_framework: dict[str, FrameworkAssessment],
) -> float:
    """Compute average acgs-lite coverage across frameworks."""
    if not by_framework:
        return 0.0
    total = sum(a.acgs_lite_coverage for a in by_framework.values())
    return round(total / len(by_framework), 4)


def _identify_cross_framework_gaps(
    by_framework: dict[str, FrameworkAssessment],
) -> tuple[str, ...]:
    """Identify gap themes that appear across multiple frameworks."""
    # Collect all gap texts
    all_gaps: list[str] = []
    for assessment in by_framework.values():
        all_gaps.extend(assessment.gaps)

    if not all_gaps:
        return ()

    # Count theme occurrences across frameworks
    theme_counts: Counter[str] = Counter()
    all_gap_text = " ".join(g.lower() for g in all_gaps)

    for theme, keywords in _CROSS_FRAMEWORK_THEMES.items():
        for kw in keywords:
            if kw in all_gap_text:
                theme_counts[theme] += 1
                break

    # Report themes found in gaps
    cross_gaps: list[str] = []
    theme_descriptions = {
        "bias_testing": (
            "Bias testing and fairness assessment: required by multiple frameworks "
            "but not yet addressed."
        ),
        "data_governance": (
            "Data governance and lineage: training data quality and provenance "
            "requirements appear across frameworks."
        ),
        "incident_response": (
            "Incident response procedures: breach notification and failure "
            "response required by multiple regulations."
        ),
        "model_documentation": (
            "Model documentation: comprehensive AI system documentation "
            "required across multiple frameworks."
        ),
        "stakeholder_engagement": (
            "Stakeholder engagement: requirements to involve affected "
            "populations appear in multiple frameworks."
        ),
    }

    for theme, _count in theme_counts.most_common():
        if theme in theme_descriptions:
            cross_gaps.append(theme_descriptions[theme])

    return tuple(cross_gaps)


def _generate_prioritized_recommendations(
    by_framework: dict[str, FrameworkAssessment],
    cross_gaps: tuple[str, ...],
) -> tuple[str, ...]:
    """Generate prioritized recommendations from all frameworks."""
    recs: list[str] = []

    # Cross-framework gaps are highest priority
    if cross_gaps:
        recs.append(
            "PRIORITY: Address cross-framework gaps first, as they close "
            "compliance requirements across multiple regulations simultaneously."
        )

    # Count which acgs-lite features are used most
    feature_refs: Counter[str] = Counter()
    for assessment in by_framework.values():
        for item in assessment.items:
            feat = item.get("acgs_lite_feature")
            if feat and item.get("status") == "compliant":
                feature_refs[feat] += 1

    if feature_refs:
        top_feature = feature_refs.most_common(1)[0]
        recs.append(
            f"STRENGTH: '{top_feature[0]}' provides supporting technical measures across "
            f"{top_feature[1]} frameworks. Leverage this capability further."
        )

    # Add framework-specific recommendations (up to 3 per framework)
    for fid, assessment in sorted(by_framework.items()):
        for rec in assessment.recommendations[:3]:
            recs.append(f"[{fid}] {rec}")

    return tuple(recs)
