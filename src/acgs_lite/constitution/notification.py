"""exp197: GovernanceNotificationBus — event-driven governance notifications.

Pub/sub notification system for governance decisions with topic-based routing,
subscriber filters, priority channels, delivery tracking, and event replay.
Zero hot-path overhead (offline tooling only).
"""

from __future__ import annotations

import itertools
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NotificationPriority(Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class DeliveryStatus(Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    FILTERED = "filtered"


_NOTIFICATION_SEQ = itertools.count(1)


@dataclass
class GovernanceNotification:
    topic: str
    payload: dict[str, Any]
    priority: NotificationPriority = NotificationPriority.NORMAL
    source: str = ""
    notification_id: str = ""
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.notification_id:
            self.notification_id = f"notif-{int(self.created_at * 1000)}-{next(_NOTIFICATION_SEQ)}"


@dataclass
class Subscriber:
    name: str
    callback: Callable[[GovernanceNotification], None]
    topics: set[str] = field(default_factory=set)
    min_priority: NotificationPriority = NotificationPriority.LOW
    filter_fn: Callable[[GovernanceNotification], bool] | None = None
    active: bool = True

    def accepts(self, notification: GovernanceNotification) -> bool:
        if not self.active:
            return False
        if self.topics and notification.topic not in self.topics:
            return False
        priority_rank = {"low": 0, "normal": 1, "high": 2, "critical": 3}
        if priority_rank.get(notification.priority.value, 0) < priority_rank.get(
            self.min_priority.value, 0
        ):
            return False
        return not (self.filter_fn and not self.filter_fn(notification))


@dataclass
class DeliveryRecord:
    notification_id: str
    subscriber_name: str
    status: DeliveryStatus
    delivered_at: float = field(default_factory=time.time)
    error: str = ""


class GovernanceNotificationBus:
    """Event-driven pub/sub for governance decision notifications.

    Example::

        bus = GovernanceNotificationBus()

        def on_deny(n: GovernanceNotification) -> None:
            print(f"DENIED: {n.payload}")

        bus.subscribe(Subscriber("alert-service", on_deny, topics={"decision.deny"}))

        bus.publish(GovernanceNotification(
            topic="decision.deny",
            payload={"rule_id": "SAFE-001", "action": "invest in crypto"},
            priority=NotificationPriority.HIGH,
        ))
    """

    def __init__(self, *, max_history: int = 10000) -> None:
        self._subscribers: dict[str, Subscriber] = {}
        self._history: list[GovernanceNotification] = []
        self._delivery_log: list[DeliveryRecord] = []
        self._max_history = max_history

    def subscribe(self, subscriber: Subscriber) -> None:
        self._subscribers[subscriber.name] = subscriber

    def unsubscribe(self, name: str) -> bool:
        if name not in self._subscribers:
            return False
        del self._subscribers[name]
        return True

    def pause(self, name: str) -> bool:
        sub = self._subscribers.get(name)
        if not sub:
            return False
        sub.active = False
        return True

    def resume(self, name: str) -> bool:
        sub = self._subscribers.get(name)
        if not sub:
            return False
        sub.active = True
        return True

    def publish(self, notification: GovernanceNotification) -> list[DeliveryRecord]:
        self._history.append(notification)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]

        records: list[DeliveryRecord] = []
        for sub in self._subscribers.values():
            if not sub.accepts(notification):
                record = DeliveryRecord(
                    notification_id=notification.notification_id,
                    subscriber_name=sub.name,
                    status=DeliveryStatus.FILTERED,
                )
                self._delivery_log.append(record)
                records.append(record)
                continue

            try:
                sub.callback(notification)
                record = DeliveryRecord(
                    notification_id=notification.notification_id,
                    subscriber_name=sub.name,
                    status=DeliveryStatus.DELIVERED,
                )
            except Exception as exc:  # noqa: BLE001 — subscriber callbacks are user-supplied and may raise anything
                record = DeliveryRecord(
                    notification_id=notification.notification_id,
                    subscriber_name=sub.name,
                    status=DeliveryStatus.FAILED,
                    error=str(exc),
                )
            self._delivery_log.append(record)
            records.append(record)

        return records

    def publish_batch(
        self, notifications: list[GovernanceNotification]
    ) -> dict[str, list[DeliveryRecord]]:
        return {n.notification_id: self.publish(n) for n in notifications}

    def replay(
        self,
        *,
        topic: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[GovernanceNotification]:
        entries = self._history
        if topic:
            entries = [e for e in entries if e.topic == topic]
        if since:
            entries = [e for e in entries if e.created_at >= since]
        return entries[-limit:]

    def delivery_report(
        self,
        subscriber_name: str | None = None,
        status: DeliveryStatus | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        entries = self._delivery_log
        if subscriber_name:
            entries = [e for e in entries if e.subscriber_name == subscriber_name]
        if status:
            entries = [e for e in entries if e.status == status]
        return [
            {
                "notification_id": e.notification_id,
                "subscriber": e.subscriber_name,
                "status": e.status.value,
                "delivered_at": e.delivered_at,
                "error": e.error,
            }
            for e in entries[-limit:]
        ]

    def subscriber_stats(self) -> dict[str, dict[str, Any]]:
        stats: dict[str, dict[str, int]] = {}
        for record in self._delivery_log:
            if record.subscriber_name not in stats:
                stats[record.subscriber_name] = {"delivered": 0, "failed": 0, "filtered": 0}
            key = record.status.value
            if key in stats[record.subscriber_name]:
                stats[record.subscriber_name][key] += 1
        return stats

    def topics(self) -> set[str]:
        return {n.topic for n in self._history}

    def summary(self) -> dict[str, Any]:
        total = len(self._delivery_log)
        delivered = sum(1 for r in self._delivery_log if r.status == DeliveryStatus.DELIVERED)
        failed = sum(1 for r in self._delivery_log if r.status == DeliveryStatus.FAILED)
        return {
            "subscribers": list(self._subscribers.keys()),
            "subscriber_count": len(self._subscribers),
            "active_subscribers": sum(1 for s in self._subscribers.values() if s.active),
            "total_notifications": len(self._history),
            "total_deliveries": total,
            "delivered": delivered,
            "failed": failed,
            "delivery_rate": round(delivered / total, 4) if total else 1.0,
            "topics": sorted(self.topics()),
        }
