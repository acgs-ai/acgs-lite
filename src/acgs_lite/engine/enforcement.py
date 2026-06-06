"""Runtime enforcement artifacts for workflow_action dispatch."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from acgs_lite.constitution.rule import ViolationAction

DEFAULT_CHANNEL = "governance"
DEFAULT_QUEUE = "human_review"
DEFAULT_ESCALATION_QUEUE = "senior_governance_reviewer"
DEFAULT_HALT_CHANNEL = "governance_halt"


class ViolationLike(Protocol):
    """Minimal violation shape needed to build enforcement artifacts."""

    rule_id: str
    rule_text: str
    severity: Any
    matched_content: str
    category: str


def _severity_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


@dataclass(frozen=True, slots=True)
class NotificationEvent:
    """Serializable notification emitted for a blocking governance outcome."""

    rule_id: str
    rule_text: str
    severity: str
    category: str
    action: str
    matched_content: str
    channel: str = DEFAULT_CHANNEL

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_text": self.rule_text,
            "severity": self.severity,
            "category": self.category,
            "action": self.action,
            "matched_content": self.matched_content,
            "channel": self.channel,
        }


@dataclass(frozen=True, slots=True)
class ReviewRequest:
    """Serializable human-review queue item."""

    rule_id: str
    rule_text: str
    severity: str
    category: str
    action: str
    matched_content: str
    queue: str = DEFAULT_QUEUE
    status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_text": self.rule_text,
            "severity": self.severity,
            "category": self.category,
            "action": self.action,
            "matched_content": self.matched_content,
            "queue": self.queue,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class EscalationRequest:
    """Serializable escalation routed to a senior reviewer."""

    rule_id: str
    rule_text: str
    severity: str
    category: str
    action: str
    matched_content: str
    target: str = DEFAULT_ESCALATION_QUEUE
    status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_text": self.rule_text,
            "severity": self.severity,
            "category": self.category,
            "action": self.action,
            "matched_content": self.matched_content,
            "target": self.target,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class IncidentAlert:
    """Serializable incident emitted when validation halts execution."""

    rule_id: str
    rule_text: str
    severity: str
    category: str
    action: str
    matched_content: str
    alert_type: str = DEFAULT_HALT_CHANNEL
    status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_text": self.rule_text,
            "severity": self.severity,
            "category": self.category,
            "action": self.action,
            "matched_content": self.matched_content,
            "alert_type": self.alert_type,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class EnforcementOutcome:
    """Per-violation resolution produced by workflow_action dispatch."""

    rule_id: str
    workflow_action: ViolationAction
    blocking: bool
    notification: NotificationEvent | None = None
    review_request: ReviewRequest | None = None
    escalation: EscalationRequest | None = None
    incident_alert: IncidentAlert | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "workflow_action": self.workflow_action.value,
            "blocking": self.blocking,
            "notification": None if self.notification is None else self.notification.to_dict(),
            "review_request": None
            if self.review_request is None
            else self.review_request.to_dict(),
            "escalation": None if self.escalation is None else self.escalation.to_dict(),
            "incident_alert": None
            if self.incident_alert is None
            else self.incident_alert.to_dict(),
        }


@dataclass(slots=True)
class EnforcementResolution:
    """Aggregated runtime artifacts produced by validation dispatch."""

    blocking_violations: list[ViolationLike] = field(default_factory=list)
    warning_violations: list[ViolationLike] = field(default_factory=list)
    notifications: list[NotificationEvent] = field(default_factory=list)
    review_requests: list[ReviewRequest] = field(default_factory=list)
    escalations: list[EscalationRequest] = field(default_factory=list)
    incident_alerts: list[IncidentAlert] = field(default_factory=list)
    action_taken: ViolationAction | None = None
    primary_action: ViolationAction | None = None
    primary_violation: ViolationLike | None = None
    _outcome_specs: list[
        tuple[
            str,
            ViolationAction,
            bool,
            NotificationEvent | None,
            ReviewRequest | None,
            EscalationRequest | None,
            IncidentAlert | None,
        ]
    ] = field(default_factory=list, repr=False, compare=False)
    _outcomes_cache: list[EnforcementOutcome] | None = field(
        default=None, repr=False, compare=False
    )

    @property
    def outcomes(self) -> list[EnforcementOutcome]:
        cached = self._outcomes_cache
        if cached is None:
            cached = [
                EnforcementOutcome(
                    rule_id=s[0],
                    workflow_action=s[1],
                    blocking=s[2],
                    notification=s[3],
                    review_request=s[4],
                    escalation=s[5],
                    incident_alert=s[6],
                )
                for s in self._outcome_specs
            ]
            self._outcomes_cache = cached
        return cached

    def audit_metadata(self) -> dict[str, Any]:
        return {
            "action_taken": None if self.action_taken is None else self.action_taken.value,
            "notification_fired": bool(self.notifications),
            "human_review_queued": bool(self.review_requests),
            "escalation_triggered": bool(self.escalations),
            "incident_triggered": bool(self.incident_alerts),
            "notifications": [event.to_dict() for event in self.notifications],
            "review_requests": [request.to_dict() for request in self.review_requests],
            "escalations": [request.to_dict() for request in self.escalations],
            "incident_alerts": [alert.to_dict() for alert in self.incident_alerts],
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


_ACTION_PRIORITY = {
    ViolationAction.WARN: 0,
    ViolationAction.BLOCK: 1,
    ViolationAction.BLOCK_AND_NOTIFY: 2,
    ViolationAction.REQUIRE_HUMAN_REVIEW: 3,
    ViolationAction.ESCALATE: 4,
    ViolationAction.HALT: 5,
}


def resolve_enforcement(
    violations: list[ViolationLike],
    *,
    action_text: str,
    workflow_action_for_violation: Callable[[ViolationLike], ViolationAction],
) -> EnforcementResolution:
    """Resolve matched violations into runtime artifacts."""
    resolution = EnforcementResolution()
    best_priority = -1

    for violation in violations:
        workflow_action = workflow_action_for_violation(violation)
        severity = _severity_value(violation.severity)
        blocking = workflow_action is not ViolationAction.WARN

        notification = None
        review_request = None
        escalation = None
        incident_alert = None

        if workflow_action is ViolationAction.WARN:
            resolution.warning_violations.append(violation)
        else:
            resolution.blocking_violations.append(violation)

        if workflow_action is ViolationAction.BLOCK_AND_NOTIFY:
            notification = NotificationEvent(
                rule_id=violation.rule_id,
                rule_text=violation.rule_text,
                severity=severity,
                category=violation.category,
                action=action_text,
                matched_content=violation.matched_content,
            )
            resolution.notifications.append(notification)
        elif workflow_action is ViolationAction.REQUIRE_HUMAN_REVIEW:
            review_request = ReviewRequest(
                rule_id=violation.rule_id,
                rule_text=violation.rule_text,
                severity=severity,
                category=violation.category,
                action=action_text,
                matched_content=violation.matched_content,
            )
            resolution.review_requests.append(review_request)
        elif workflow_action is ViolationAction.ESCALATE:
            escalation = EscalationRequest(
                rule_id=violation.rule_id,
                rule_text=violation.rule_text,
                severity=severity,
                category=violation.category,
                action=action_text,
                matched_content=violation.matched_content,
            )
            resolution.escalations.append(escalation)
        elif workflow_action is ViolationAction.HALT:
            incident_alert = IncidentAlert(
                rule_id=violation.rule_id,
                rule_text=violation.rule_text,
                severity=severity,
                category=violation.category,
                action=action_text,
                matched_content=violation.matched_content,
            )
            resolution.incident_alerts.append(incident_alert)

        resolution._outcome_specs.append(
            (
                violation.rule_id,
                workflow_action,
                blocking,
                notification,
                review_request,
                escalation,
                incident_alert,
            )
        )

        priority = _ACTION_PRIORITY[workflow_action]
        if priority > best_priority:
            best_priority = priority
            resolution.primary_action = workflow_action
            resolution.primary_violation = violation

    resolution.action_taken = resolution.primary_action
    return resolution


__all__ = [
    "EnforcementOutcome",
    "EnforcementResolution",
    "EscalationRequest",
    "IncidentAlert",
    "NotificationEvent",
    "ReviewRequest",
    "resolve_enforcement",
]
