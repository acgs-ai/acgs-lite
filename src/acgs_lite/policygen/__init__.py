# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Adaptive governance-policy generation.

A small pipeline that turns a *pre-context* (a research brief about a governance
domain) into a valid acgs-lite constitution YAML, adapting severity, enforcement,
activation conditions, and the permission ceiling to the domain's risk level and
deployment environment:

    PreContextBuilder -> PreContext -> PolicyResearcher -> AdaptivePolicyGenerator -> YAML

* :class:`~acgs_lite.policygen.context.PreContextBuilder` assembles and enriches the
  brief deterministically (risk-area + framework detection, risk classification).
* :class:`~acgs_lite.policygen.research.PolicyResearcher` derives concrete
  requirements from a curated knowledge base, with an optional pluggable
  ``RuleSynthesisProvider`` for LLM-backed enrichment of free-text requirements.
* :class:`~acgs_lite.policygen.generator.AdaptivePolicyGenerator` builds the
  constitution via the existing ``ConstitutionBuilder``, serializes it, and verifies
  it round-trips through ``Constitution.from_yaml_str``.

Everything is deterministic and offline by default; the optional LLM provider is
injected by the caller, never imported at module load.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from acgs_lite.policygen.context import DomainRiskLevel, PreContext, PreContextBuilder
from acgs_lite.policygen.generator import AdaptivePolicyGenerator, GeneratedPolicy
from acgs_lite.policygen.manifest import CAPABILITY_MAP, ManifestScanResult, scan_manifests
from acgs_lite.policygen.research import PolicyRequirement, PolicyResearcher, ResearchReport

__all__ = [
    "AdaptivePolicyGenerator",
    "CAPABILITY_MAP",
    "DomainRiskLevel",
    "GeneratedPolicy",
    "ManifestScanResult",
    "PolicyRequirement",
    "PolicyResearcher",
    "PreContext",
    "PreContextBuilder",
    "ResearchReport",
    "scan_manifests",
]
