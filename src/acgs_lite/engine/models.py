"""Shared engine result models and helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .decision_record import GovernanceDecisionRecord
from dataclasses import dataclass, field
from typing import Any, NamedTuple

from acgs_lite.constitution import Severity
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.engine.enforcement import (
    EscalationRequest,
    IncidentAlert,
    NotificationEvent,
    ReviewRequest,
)


class Violation(NamedTuple):
    """A single rule violation (NamedTuple for C-speed construction)."""

    rule_id: str
    rule_text: str
    severity: Severity
    matched_content: str
    category: str


# Sentinel distinguishing an omitted list arg (-> fresh []) from an explicitly
# passed None, exactly reproducing dataclass default_factory semantics. Typed as
# Any so it is an accepted default for the list-typed __init__ params under mypy.
_MISSING: Any = object()


@dataclass(slots=True, init=False)
class ValidationResult:
    """Result of validating an action against the constitution."""

    valid: bool
    constitutional_hash: str
    violations: list[Violation] = field(default_factory=list)
    rules_checked: int = 0
    latency_ms: float = 0.0
    request_id: str = ""
    timestamp: str = ""
    action: str = ""
    agent_id: str = ""
    # Violations whose workflow_action is WARN (non-blocking, separated from violations).
    warnings: list[Violation] = field(default_factory=list)
    # The enforcement action that was applied to this validation result.
    action_taken: ViolationAction | None = None
    notifications: list[NotificationEvent] = field(default_factory=list)
    review_requests: list[ReviewRequest] = field(default_factory=list)
    escalations: list[EscalationRequest] = field(default_factory=list)
    incident_alerts: list[IncidentAlert] = field(default_factory=list)

    def __init__(
        self,
        valid: bool,
        constitutional_hash: str,
        violations: list[Violation] = _MISSING,
        rules_checked: int = 0,
        latency_ms: float = 0.0,
        request_id: str = "",
        timestamp: str = "",
        action: str = "",
        agent_id: str = "",
        warnings: list[Violation] = _MISSING,
        action_taken: ViolationAction | None = None,
        notifications: list[NotificationEvent] = _MISSING,
        review_requests: list[ReviewRequest] = _MISSING,
        escalations: list[EscalationRequest] = _MISSING,
        incident_alerts: list[IncidentAlert] = _MISSING,
    ) -> None:
        self.valid = valid
        self.constitutional_hash = constitutional_hash
        self.violations = [] if violations is _MISSING else violations
        self.rules_checked = rules_checked
        self.latency_ms = latency_ms
        self.request_id = request_id
        self.timestamp = timestamp
        self.action = action
        self.agent_id = agent_id
        self.warnings = [] if warnings is _MISSING else warnings
        self.action_taken = action_taken
        self.notifications = [] if notifications is _MISSING else notifications
        self.review_requests = [] if review_requests is _MISSING else review_requests
        self.escalations = [] if escalations is _MISSING else escalations
        self.incident_alerts = [] if incident_alerts is _MISSING else incident_alerts

    @property
    def blocking_violations(self) -> list[Violation]:
        """Violations that block execution (severity-based filter on violations list)."""
        return [v for v in self.violations if v.severity.blocks()]

    def to_decision_record(self) -> GovernanceDecisionRecord:
        """Convert to canonical :class:`GovernanceDecisionRecord`."""
        from .decision_record import GovernanceDecisionRecord, TriggeredRule

        triggered = [
            TriggeredRule(
                id=v.rule_id, text=v.rule_text, severity=v.severity.value, category=v.category
            )
            for v in self.violations
        ]
        violations_dicts = [
            {
                "rule_id": v.rule_id,
                "rule_text": v.rule_text,
                "severity": v.severity.value,
                "matched_content": v.matched_content,
                "category": v.category,
            }
            for v in self.violations
        ]
        return GovernanceDecisionRecord(
            decision="deny" if not self.valid else "allow",
            triggered_rules=triggered,
            violations=violations_dicts,
            confidence=1.0,
            model_id="deterministic",
            latency_ms=self.latency_ms,
            constitutional_hash=self.constitutional_hash,
            audit_entry_id=self.request_id,
            action=self.action,
            agent_id=self.agent_id,
            rules_checked=self.rules_checked,
            timestamp=self.timestamp,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "valid": self.valid,
            "constitutional_hash": self.constitutional_hash,
            "violations": [
                {
                    "rule_id": v.rule_id,
                    "rule_text": v.rule_text,
                    "severity": v.severity.value,
                    "matched_content": v.matched_content,
                    "category": v.category,
                }
                for v in self.violations
            ],
            "warnings": [
                {
                    "rule_id": v.rule_id,
                    "rule_text": v.rule_text,
                    "severity": v.severity.value,
                    "matched_content": v.matched_content,
                    "category": v.category,
                }
                for v in self.warnings
            ],
            "action_taken": self.action_taken.value if self.action_taken is not None else None,
            "notifications": [event.to_dict() for event in self.notifications],
            "review_requests": [request.to_dict() for request in self.review_requests],
            "escalations": [request.to_dict() for request in self.escalations],
            "incident_alerts": [alert.to_dict() for alert in self.incident_alerts],
            "rules_checked": self.rules_checked,
            "latency_ms": self.latency_ms,
            "request_id": self.request_id,
            "action": self.action,
            "agent_id": self.agent_id,
        }

    def to_adapter_dict(self) -> dict[str, Any]:
        """Serialize with adapter-facing policy hash vocabulary."""
        from acgs_lite.legitimacy.receipt import to_receipt_dict

        return to_receipt_dict(self)


def _dedup_violations(violations: list) -> list:
    """Deduplicate violations by (rule_id, matched_content) (called when len > 1).

    Keying on rule_id alone collapsed *distinct* findings that share a rule_id —
    two ``CODE-DANGEROUS-CALL``s for different calls, or two structural findings at
    different code sites — into one before the audit write, degrading the forensic
    record (M7). String-rule violations from a single action all carry the same
    ``matched_content`` (the action text), so they still collapse to one; only
    genuinely distinct findings are now preserved.
    """
    seen: set[tuple[str, str]] = set()
    result = []
    for v in violations:
        key = (v.rule_id, v.matched_content)
        if key not in seen:
            seen.add(key)
            result.append(v)
    return result


CustomValidator = Callable[[str, dict[str, Any]], list[Violation]]


__all__ = [
    "CustomValidator",
    "Severity",
    "ValidationResult",
    "ViolationAction",
    "Violation",
    "_dedup_violations",
]
