"""Canonical decision record shared across deterministic and adaptive governance layers.

This module provides a unified schema that normalizes both ``ValidationResult``
(from the deterministic acgs-lite engine) and ``GovernanceDecision`` (from the
adaptive governance bus) into one shape suitable for eval harnesses, LLM judges,
audit pipelines, and evolution fitness evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TriggeredRule:
    """A rule that was triggered during governance evaluation."""

    id: str
    text: str = ""
    severity: str = ""
    category: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "text": self.text,
            "severity": self.severity,
            "category": self.category,
        }


@dataclass(slots=True)
class GovernanceDecisionRecord:
    """Canonical decision record for cross-layer governance evaluation.

    Normalizes both ``ValidationResult`` and ``GovernanceDecision`` into a
    single schema consumable by eval harnesses, judges, and evolution engines.

    The ``decision`` field uses the test-suite convention: ``"allow"`` or ``"deny"``.
    """

    decision: str  # "allow" | "deny"
    triggered_rules: list[TriggeredRule] = field(default_factory=list)
    violations: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 1.0
    model_id: str = "deterministic"
    latency_ms: float = 0.0
    constitutional_hash: str = ""
    audit_entry_id: str = ""
    action: str = ""
    agent_id: str = ""
    rules_checked: int = 0
    timestamp: str = ""

    # --- dict-protocol compat for GovernanceTestSuite ---

    def __getitem__(self, key: str) -> Any:
        """Support dict-style access for backward compat with test suite."""
        if key == "decision":
            return self.decision
        if key == "triggered_rules":
            return [r.to_dict() for r in self.triggered_rules]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "triggered_rules": [r.to_dict() for r in self.triggered_rules],
            "violations": self.violations,
            "confidence": self.confidence,
            "model_id": self.model_id,
            "latency_ms": self.latency_ms,
            "constitutional_hash": self.constitutional_hash,
            "audit_entry_id": self.audit_entry_id,
            "action": self.action,
            "agent_id": self.agent_id,
            "rules_checked": self.rules_checked,
            "timestamp": self.timestamp,
        }

    def to_adapter_dict(self) -> dict[str, Any]:
        """Serialize with adapter-facing policy hash vocabulary."""
        from acgs_lite.legitimacy.receipt import to_receipt_dict

        return to_receipt_dict(self)


__all__ = ["GovernanceDecisionRecord", "TriggeredRule"]
