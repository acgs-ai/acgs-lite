"""exp182: PDP/PEP split — decoupled policy decision and enforcement.

Separates governance into two layers:
- PolicyDecisionPoint (PDP): evaluates actions against rules, returns decisions
- PolicyEnforcementPoint (PEP): applies decisions with context-specific behavior

Enables multiple enforcement points (API gateway, agent runtime, CI/CD) sharing
a single decision engine with different enforcement strategies per context.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from acgs_lite.legitimacy.decide import DecisionState, canonicalize_decision_state


class EnforcementAction(Enum):
    """What the PEP does with a decision."""

    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    LOG_ONLY = "log_only"
    REDIRECT = "redirect"
    THROTTLE = "throttle"
    QUARANTINE = "quarantine"


class DecisionOutcome(Enum):
    """PDP decision outcomes."""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    CONDITIONAL = "conditional"


@dataclass(frozen=True)
class PolicyDecision:
    """Immutable decision from the PDP."""

    decision_id: str
    outcome: DecisionOutcome
    action_text: str
    matched_rules: tuple[str, ...]
    severity: str
    confidence: float
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def decision_type(self) -> DecisionState:
        return canonicalize_decision_state(
            self.outcome,
            critical=self.severity == "critical",
            kill_switch=bool(
                self.metadata.get("kill_switch") or self.metadata.get("circuit_breaker")
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "outcome": self.outcome.value,
            "decision_type": self.decision_type,
            "action_text": self.action_text,
            "matched_rules": list(self.matched_rules),
            "severity": self.severity,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class EnforcementResult:
    """Result of PEP enforcement."""

    decision: PolicyDecision
    enforcement_action: EnforcementAction
    enforced_by: str
    enforced_at: datetime
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.to_dict(),
            "enforcement_action": self.enforcement_action.value,
            "enforced_by": self.enforced_by,
            "enforced_at": self.enforced_at.isoformat(),
            "details": self.details,
        }


class DecisionProvider(Protocol):
    """Protocol for anything that can produce governance decisions."""

    def decide(self, action_text: str, context: dict[str, Any] | None = None) -> PolicyDecision: ...


class PolicyDecisionPoint:
    """Evaluates actions against governance rules and returns decisions.

    Stateless decision engine that can be shared across multiple PEPs.
    """

    __slots__ = ("_name", "_rules", "_decision_log", "_max_log")

    def __init__(
        self,
        name: str = "default-pdp",
        rules: list[dict[str, Any]] | None = None,
        max_log: int = 10000,
    ) -> None:
        self._name = name
        self._rules: list[dict[str, Any]] = rules or []
        self._decision_log: list[PolicyDecision] = []
        self._max_log = max_log

    @property
    def name(self) -> str:
        return self._name

    def add_rule(self, rule: dict[str, Any]) -> None:
        self._rules.append(rule)

    def decide(
        self,
        action_text: str,
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate action against rules and return an immutable decision."""
        matched: list[str] = []
        max_severity = "low"
        severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        action_lower = action_text.lower()
        for rule in self._rules:
            keywords = rule.get("keywords", [])
            if any(kw in action_lower for kw in keywords):
                matched.append(rule.get("id", "unknown"))
                rule_sev = rule.get("severity", "low")
                if severity_rank.get(rule_sev, 0) > severity_rank.get(max_severity, 0):
                    max_severity = rule_sev

        if matched:
            outcome = DecisionOutcome.DENY
            if max_severity in ("low", "medium"):
                outcome = DecisionOutcome.CONDITIONAL
        else:
            outcome = DecisionOutcome.ALLOW

        decision = PolicyDecision(
            decision_id=uuid.uuid4().hex[:12],
            outcome=outcome,
            action_text=action_text,
            matched_rules=tuple(matched),
            severity=max_severity,
            confidence=1.0 if matched else 1.0,
            timestamp=datetime.now(timezone.utc),
            metadata={"context": context} if context else {},
        )

        if len(self._decision_log) < self._max_log:
            self._decision_log.append(decision)

        return decision

    def recent_decisions(self, limit: int = 50) -> list[PolicyDecision]:
        return self._decision_log[-limit:]

    def stats(self) -> dict[str, Any]:
        total = len(self._decision_log)
        if total == 0:
            return {"total": 0, "allow": 0, "deny": 0, "escalate": 0, "conditional": 0}
        by_outcome: dict[str, int] = {}
        for d in self._decision_log:
            key = d.outcome.value
            by_outcome[key] = by_outcome.get(key, 0) + 1
        return {"total": total, **by_outcome}


@dataclass
class EnforcementPolicy:
    """Maps decision outcomes to enforcement actions for a specific PEP context."""

    mapping: dict[DecisionOutcome, EnforcementAction] = field(default_factory=dict)

    @classmethod
    def strict(cls) -> EnforcementPolicy:
        return cls(
            mapping={
                DecisionOutcome.ALLOW: EnforcementAction.ALLOW,
                DecisionOutcome.DENY: EnforcementAction.BLOCK,
                DecisionOutcome.ESCALATE: EnforcementAction.QUARANTINE,
                DecisionOutcome.CONDITIONAL: EnforcementAction.WARN,
            }
        )

    @classmethod
    def permissive(cls) -> EnforcementPolicy:
        return cls(
            mapping={
                DecisionOutcome.ALLOW: EnforcementAction.ALLOW,
                DecisionOutcome.DENY: EnforcementAction.WARN,
                DecisionOutcome.ESCALATE: EnforcementAction.LOG_ONLY,
                DecisionOutcome.CONDITIONAL: EnforcementAction.ALLOW,
            }
        )

    @classmethod
    def audit_only(cls) -> EnforcementPolicy:
        return cls(
            mapping={
                DecisionOutcome.ALLOW: EnforcementAction.ALLOW,
                DecisionOutcome.DENY: EnforcementAction.LOG_ONLY,
                DecisionOutcome.ESCALATE: EnforcementAction.LOG_ONLY,
                DecisionOutcome.CONDITIONAL: EnforcementAction.LOG_ONLY,
            }
        )

    def resolve(self, outcome: DecisionOutcome) -> EnforcementAction:
        return self.mapping.get(outcome, EnforcementAction.BLOCK)


class PolicyEnforcementPoint:
    """Enforces governance decisions with context-specific behavior.

    Each PEP connects to a PDP for decisions but applies its own enforcement
    policy based on deployment context (API gateway, agent runtime, CI/CD).
    """

    __slots__ = ("_name", "_pdp", "_policy", "_enforcement_log", "_max_log")

    def __init__(
        self,
        name: str,
        pdp: DecisionProvider,
        policy: EnforcementPolicy | None = None,
        max_log: int = 10000,
    ) -> None:
        self._name = name
        self._pdp = pdp
        self._policy = policy or EnforcementPolicy.strict()
        self._enforcement_log: list[EnforcementResult] = []
        self._max_log = max_log

    @property
    def name(self) -> str:
        return self._name

    @property
    def policy(self) -> EnforcementPolicy:
        return self._policy

    def set_policy(self, policy: EnforcementPolicy) -> None:
        self._policy = policy

    def enforce(
        self,
        action_text: str,
        context: dict[str, Any] | None = None,
    ) -> EnforcementResult:
        """Request a decision from the PDP and enforce it according to local policy."""
        decision = self._pdp.decide(action_text, context)
        enforcement_action = self._policy.resolve(decision.outcome)

        result = EnforcementResult(
            decision=decision,
            enforcement_action=enforcement_action,
            enforced_by=self._name,
            enforced_at=datetime.now(timezone.utc),
            details={
                "pdp_outcome": decision.outcome.value,
                "local_action": enforcement_action.value,
                "matched_rules": list(decision.matched_rules),
            },
        )

        if len(self._enforcement_log) < self._max_log:
            self._enforcement_log.append(result)

        return result

    def is_allowed(self, action_text: str, context: dict[str, Any] | None = None) -> bool:
        """Convenience: returns True only if enforcement action is ALLOW."""
        result = self.enforce(action_text, context)
        return result.enforcement_action == EnforcementAction.ALLOW

    def recent_enforcements(self, limit: int = 50) -> list[EnforcementResult]:
        return self._enforcement_log[-limit:]

    def stats(self) -> dict[str, Any]:
        total = len(self._enforcement_log)
        if total == 0:
            return {"total": 0, "pep": self._name}
        by_action: dict[str, int] = {}
        for r in self._enforcement_log:
            key = r.enforcement_action.value
            by_action[key] = by_action.get(key, 0) + 1
        return {"total": total, "pep": self._name, **by_action}


class PEPNetwork:
    """Manages a network of PEPs sharing one or more PDPs.

    Provides centralized stats and policy management across enforcement points.
    """

    __slots__ = ("_peps", "_pdps")

    def __init__(self) -> None:
        self._peps: dict[str, PolicyEnforcementPoint] = {}
        self._pdps: dict[str, PolicyDecisionPoint] = {}

    def register_pdp(self, pdp: PolicyDecisionPoint) -> None:
        self._pdps[pdp.name] = pdp

    def register_pep(self, pep: PolicyEnforcementPoint) -> None:
        self._peps[pep.name] = pep

    def get_pep(self, name: str) -> PolicyEnforcementPoint | None:
        return self._peps.get(name)

    def get_pdp(self, name: str) -> PolicyDecisionPoint | None:
        return self._pdps.get(name)

    def all_pep_stats(self) -> list[dict[str, Any]]:
        return [pep.stats() for pep in self._peps.values()]

    def all_pdp_stats(self) -> list[dict[str, Any]]:
        return [pdp.stats() for pdp in self._pdps.values()]

    def network_summary(self) -> dict[str, Any]:
        total_enforcements = sum(s["total"] for s in self.all_pep_stats())
        total_decisions = sum(s["total"] for s in self.all_pdp_stats())
        return {
            "pdp_count": len(self._pdps),
            "pep_count": len(self._peps),
            "total_decisions": total_decisions,
            "total_enforcements": total_enforcements,
        }
