"""ACGS-Lite Notification & Alerting Integration.

Push governance violations, compliance drops, and audit-tamper events to
Slack, Microsoft Teams, or any generic webhook endpoint.

Usage::

    from acgs_lite import Constitution
    from acgs_lite.engine import GovernanceEngine
    from acgs_lite.integrations.notifications import (
        GovernanceNotifier,
        NotificationRouter,
        SlackNotifier,
        TeamsNotifier,
        WebhookNotifier,
    )

    engine = GovernanceEngine(Constitution.default())
    router = NotificationRouter([
        SlackNotifier(webhook_url="https://hooks.slack.com/services/..."),
        TeamsNotifier(webhook_url="https://outlook.office.com/webhook/..."),
        WebhookNotifier(url="https://my-siem.example.com/api/events"),
    ])
    notifier = GovernanceNotifier(engine=engine, router=router)

    # Now engine.validate() automatically fires notifications on violations.
    result = notifier.validate("deploy production without review", agent_id="bot-7")

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from acgs_lite.errors import ConstitutionalViolationError

logger = logging.getLogger(__name__)

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    HTTPX_AVAILABLE = False

# ---------------------------------------------------------------------------
# Severity ordering (higher numeric value = more severe)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#e01e5a",
    "HIGH": "#ff8c00",
    "MEDIUM": "#f2c744",
    "LOW": "#2196f3",
}

# Teams Adaptive Card header colors (hex without '#')
_TEAMS_COLORS: dict[str, str] = {
    "CRITICAL": "attention",
    "HIGH": "warning",
    "MEDIUM": "accent",
    "LOW": "good",
}


# ---------------------------------------------------------------------------
# GovernanceEvent
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GovernanceEvent:
    """A governance event suitable for push notification."""

    event_type: str  # violation, compliance_drop, audit_tamper, threshold_breach
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    agent_id: str
    action: str
    violations: list[dict[str, Any]] = field(default_factory=list)
    constitutional_hash: str = "608508a9bd224290"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the event to a plain dict."""
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "agent_id": self.agent_id,
            "action": self.action,
            "violations": self.violations,
            "constitutional_hash": self.constitutional_hash,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# NotificationChannel protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class NotificationChannel(Protocol):
    """Interface every notification channel must satisfy."""

    async def send(self, event: GovernanceEvent) -> bool:
        """Send *event* and return ``True`` on success."""
        ...

    @property
    def name(self) -> str:  # pragma: no cover
        ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_passes_filter(event_severity: str, minimum: str) -> bool:
    """Return ``True`` if *event_severity* meets or exceeds *minimum*."""
    return _SEVERITY_ORDER.get(event_severity.upper(), 0) >= _SEVERITY_ORDER.get(minimum.upper(), 0)


def _truncate(text: str, max_len: int = 200) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _first_rule_id(violations: list[dict[str, Any]]) -> str:
    if violations:
        return str(violations[0].get("rule_id", "unknown"))
    return "unknown"


# ---------------------------------------------------------------------------
# BaseNotifier — shared severity filtering and dispatch skeleton
# ---------------------------------------------------------------------------


class BaseNotifier:
    """Common base for notifier channels.

    Provides severity filtering, timeout management, and the public
    :meth:`send` entry-point.  Subclasses implement :meth:`_do_send` for the
    actual HTTP call and override the :attr:`name` property.
    """

    def __init__(
        self,
        *,
        severity_filter: str = "LOW",
        timeout: float = 5.0,
    ) -> None:
        self._severity_filter = severity_filter.upper()
        self._timeout = timeout

    @property
    def name(self) -> str:  # pragma: no cover — overridden by subclasses
        raise NotImplementedError

    @property
    def severity_filter(self) -> str:
        return self._severity_filter

    @property
    def timeout(self) -> float:
        return self._timeout

    def _should_send(self, event: GovernanceEvent) -> bool:
        """Return ``True`` when *event* severity meets the minimum filter."""
        return _severity_passes_filter(event.severity, self._severity_filter)

    async def send(self, event: GovernanceEvent) -> bool:
        """Check the severity filter, then delegate to :meth:`_do_send`."""
        if not self._should_send(event):
            return False
        return await self._do_send(event)

    async def _do_send(self, event: GovernanceEvent) -> bool:  # pragma: no cover
        raise NotImplementedError


# ---------------------------------------------------------------------------
# SlackNotifier
# ---------------------------------------------------------------------------


class SlackNotifier(BaseNotifier):
    """Posts governance events to Slack via an Incoming Webhook.

    Formats violations as Block Kit messages with color-coded attachments.
    """

    def __init__(
        self,
        *,
        webhook_url: str,
        channel: str | None = None,
        severity_filter: str = "LOW",
        timeout: float = 5.0,
    ) -> None:
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required for SlackNotifier. Install with: pip install httpx"
            )
        super().__init__(severity_filter=severity_filter, timeout=timeout)
        self._webhook_url = webhook_url
        self._channel = channel

    @property
    def name(self) -> str:
        return "slack"

    def _build_payload(self, event: GovernanceEvent) -> dict[str, Any]:
        severity = event.severity.upper()
        color = _SEVERITY_COLORS.get(severity, "#cccccc")
        rule_id = _first_rule_id(event.violations)
        action_snippet = _truncate(event.action)

        attachment: dict[str, Any] = {
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "Constitutional Violation Detected",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Agent ID:*\n{event.agent_id}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:*\n{severity}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Rule ID:*\n{rule_id}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Action:*\n{action_snippet}",
                        },
                    ],
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"Constitutional Hash: `{event.constitutional_hash}` "
                                f"| {event.timestamp}"
                            ),
                        },
                    ],
                },
            ],
        }

        payload: dict[str, Any] = {"attachments": [attachment]}
        if self._channel:
            payload["channel"] = self._channel
        return payload

    async def _do_send(self, event: GovernanceEvent) -> bool:
        payload = self._build_payload(event)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                self._webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            return 200 <= resp.status_code < 300


# ---------------------------------------------------------------------------
# TeamsNotifier
# ---------------------------------------------------------------------------


class TeamsNotifier(BaseNotifier):
    """Posts governance events to Microsoft Teams via an Incoming Webhook.

    Formats violations as Adaptive Cards.
    """

    def __init__(
        self,
        *,
        webhook_url: str,
        severity_filter: str = "LOW",
        timeout: float = 5.0,
    ) -> None:
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required for TeamsNotifier. Install with: pip install httpx"
            )
        super().__init__(severity_filter=severity_filter, timeout=timeout)
        self._webhook_url = webhook_url

    @property
    def name(self) -> str:
        return "teams"

    def _build_payload(self, event: GovernanceEvent) -> dict[str, Any]:
        severity = event.severity.upper()
        color_style = _TEAMS_COLORS.get(severity, "default")
        rule_id = _first_rule_id(event.violations)
        action_snippet = _truncate(event.action)

        card: dict[str, Any] = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": "Constitutional Violation Detected",
                                "weight": "Bolder",
                                "size": "Large",
                                "color": color_style,
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Agent ID", "value": event.agent_id},
                                    {"title": "Severity", "value": severity},
                                    {"title": "Rule ID", "value": rule_id},
                                ],
                            },
                            {
                                "type": "TextBlock",
                                "text": f"**Action:** {action_snippet}",
                                "wrap": True,
                            },
                            {
                                "type": "TextBlock",
                                "text": (f"Constitutional Hash: {event.constitutional_hash}"),
                                "size": "Small",
                                "isSubtle": True,
                            },
                        ],
                    },
                },
            ],
        }
        return card

    async def _do_send(self, event: GovernanceEvent) -> bool:
        payload = self._build_payload(event)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                self._webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            return 200 <= resp.status_code < 300


# ---------------------------------------------------------------------------
# WebhookNotifier
# ---------------------------------------------------------------------------


class WebhookNotifier(BaseNotifier):
    """Generic webhook -- POSTs the GovernanceEvent as JSON to any URL."""

    def __init__(
        self,
        *,
        url: str,
        headers: dict[str, str] | None = None,
        severity_filter: str = "LOW",
        timeout: float = 5.0,
    ) -> None:
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required for WebhookNotifier. Install with: pip install httpx"
            )
        super().__init__(severity_filter=severity_filter, timeout=timeout)
        self._url = url
        self._headers = {
            "Content-Type": "application/json",
            **(headers or {}),
        }

    @property
    def name(self) -> str:
        return "webhook"

    async def _do_send(self, event: GovernanceEvent) -> bool:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                self._url,
                content=json.dumps(event.to_dict()),
                headers=self._headers,
            )
            return 200 <= resp.status_code < 300


# ---------------------------------------------------------------------------
# NotificationRouter
# ---------------------------------------------------------------------------


class NotificationRouter:
    """Fan-out governance events to multiple notification channels.

    Errors in individual channels are logged but never raised, so one
    broken webhook cannot block the others.
    """

    def __init__(self, channels: list[NotificationChannel]) -> None:
        self._channels = list(channels)
        self._total_sent = 0
        self._total_failed = 0
        self._per_channel: dict[str, dict[str, int]] = {
            ch.name: {"sent": 0, "failed": 0} for ch in self._channels
        }
        self._stats_lock = threading.Lock()

    async def notify(self, event: GovernanceEvent) -> None:
        """Fan out *event* to every registered channel concurrently."""
        results = await asyncio.gather(
            *(self._safe_send(ch, event) for ch in self._channels),
            return_exceptions=True,
        )
        with self._stats_lock:
            for ch, result in zip(self._channels, results, strict=True):
                ch_name = ch.name
                if ch_name not in self._per_channel:
                    self._per_channel[ch_name] = {"sent": 0, "failed": 0}
                if isinstance(result, BaseException):
                    self._total_failed += 1
                    self._per_channel[ch_name]["failed"] += 1
                    logger.error(
                        "Notification channel %s raised %s",
                        ch_name,
                        type(result).__name__,
                    )
                elif result is True:
                    self._total_sent += 1
                    self._per_channel[ch_name]["sent"] += 1
                else:
                    pass

    @staticmethod
    async def _safe_send(channel: NotificationChannel, event: GovernanceEvent) -> bool:
        """Wrapper that converts exceptions into return values for gather."""
        return await channel.send(event)

    @property
    def stats(self) -> dict[str, Any]:
        with self._stats_lock:
            return {
                "total_sent": self._total_sent,
                "total_failed": self._total_failed,
                "per_channel": dict(self._per_channel),
            }


# ---------------------------------------------------------------------------
# GovernanceNotifier
# ---------------------------------------------------------------------------


class GovernanceNotifier:
    """Wraps a :class:`GovernanceEngine` so that violations automatically
    trigger push notifications through the provided :class:`NotificationRouter`.

    The wrapper delegates to the original ``engine.validate()`` and fires
    an async notification whenever the result contains blocking violations
    (or warnings, if *notify_on_warning* is enabled).

    Since ``GovernanceEngine.validate()`` is synchronous, notifications are
    dispatched via :func:`asyncio.run` (or the running loop when already
    inside one).
    """

    def __init__(
        self,
        *,
        engine: Any,  # GovernanceEngine -- use Any to avoid circular import
        router: NotificationRouter,
        notify_on_deny: bool = True,
        notify_on_warning: bool = False,
        notify_on_audit_tamper: bool = True,
        dispatch_timeout: float = 5.0,
    ) -> None:
        self._engine = engine
        self._router = router
        self.notify_on_deny = notify_on_deny
        self.notify_on_warning = notify_on_warning
        self.notify_on_audit_tamper = notify_on_audit_tamper
        self._dispatch_timeout = dispatch_timeout

    @property
    def engine(self) -> Any:
        return self._engine

    @property
    def router(self) -> NotificationRouter:
        return self._router

    def validate(
        self,
        action: str,
        *,
        agent_id: str = "anonymous",
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Validate *action* and fire notifications on violations.

        Returns the same :class:`ValidationResult` as the underlying engine.
        If the engine raises :class:`ConstitutionalViolationError` (strict
        mode), the notification is sent before re-raising.
        """
        try:
            result = self._engine.validate(action, agent_id=agent_id, context=context)
        except ConstitutionalViolationError as exc:
            # Strict-mode violation -- still notify, then re-raise.
            if self.notify_on_deny:
                event = GovernanceEvent(
                    event_type="violation",
                    severity=getattr(exc, "severity", "CRITICAL").upper(),
                    agent_id=agent_id,
                    action=action,
                    violations=[
                        {
                            "rule_id": exc.rule_id or "unknown",
                            "message": str(exc),
                        }
                    ],
                    constitutional_hash=getattr(self._engine, "_const_hash", "608508a9bd224290"),
                )
                self._dispatch(event)
            raise

        # Non-strict path: result is a ValidationResult dataclass.
        if not result.valid and result.violations:
            blocking = result.blocking_violations
            warnings = result.warnings

            if blocking and self.notify_on_deny:
                event = self._event_from_result(result, agent_id=agent_id, action=action)
                self._dispatch(event)
            elif warnings and self.notify_on_warning:
                event = self._event_from_result(
                    result,
                    agent_id=agent_id,
                    action=action,
                    severity_override="MEDIUM",
                )
                self._dispatch(event)

        return result

    # ------------------------------------------------------------------
    # Audit-tamper notification (call manually after verification)
    # ------------------------------------------------------------------

    async def check_audit_integrity(self) -> bool:
        """Verify the audit chain and notify if tampered.

        Returns ``True`` when the chain is intact.
        """
        audit_log = getattr(self._engine, "audit_log", None)
        if audit_log is None:
            return True
        verify = getattr(audit_log, "verify_chain", None)
        if verify is None:
            return True
        intact = bool(verify())
        if not intact and self.notify_on_audit_tamper:
            event = GovernanceEvent(
                event_type="audit_tamper",
                severity="CRITICAL",
                agent_id="system",
                action="Audit chain integrity check failed",
                constitutional_hash=getattr(self._engine, "_const_hash", "608508a9bd224290"),
            )
            await self._router.notify(event)
        return intact

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _event_from_result(
        result: Any,
        *,
        agent_id: str,
        action: str,
        severity_override: str | None = None,
    ) -> GovernanceEvent:
        violations_dicts = [
            {
                "rule_id": v.rule_id,
                "rule_text": v.rule_text,
                "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                "matched_content": v.matched_content,
                "category": v.category,
            }
            for v in result.violations
        ]
        # Pick highest severity from violations
        if severity_override:
            severity = severity_override
        else:
            max_sev = max(
                (_SEVERITY_ORDER.get(v.severity.value.upper(), 0) for v in result.violations),
                default=0,
            )
            severity = next((k for k, v in _SEVERITY_ORDER.items() if v == max_sev), "HIGH")
        return GovernanceEvent(
            event_type="violation",
            severity=severity,
            agent_id=agent_id,
            action=action,
            violations=violations_dicts,
            constitutional_hash=result.constitutional_hash,
        )

    def _dispatch(self, event: GovernanceEvent) -> None:
        """Run the async notification to completion from synchronous context.

        When no event loop is running, uses :func:`asyncio.run`.  When called
        from within an already-running loop (e.g. pytest-asyncio), spins up a
        short-lived thread with its own loop so the coroutine completes before
        this method returns.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            # Cannot call asyncio.run() inside a running loop.  Spawn a
            # one-shot thread so the notification runs to completion
            # synchronously from the caller's perspective.
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, self._router.notify(event))
                future.result(timeout=self._dispatch_timeout)
        else:
            asyncio.run(self._router.notify(event))
