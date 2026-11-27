"""Constitutional rules — the core of ACGS-Lite.

A Constitution is a set of Rules that govern agent behavior.
Rules can be loaded from YAML, dicts, or created programmatically.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .core import Rule


@dataclass(frozen=True)
class RuleSnapshot:
    """exp106: Immutable snapshot of a Rule's state at a point in time.

    Stored in ``Constitution.rule_history`` when a rule is updated via
    ``Constitution.update_rule()``. Enables change management dashboards,
    compliance audit trails, and rollback analysis.

    Attributes:
        rule_id: ID of the rule this snapshot belongs to.
        timestamp: Unix timestamp when this version was captured.
        version: Version number (1 = original, 2 = first update, ...).
        text: Rule text at this version.
        severity: Severity level at this version.
        enabled: Whether the rule was enabled at this version.
        keywords: Keywords at this version.
        category: Category at this version.
        subcategory: Subcategory at this version.
        workflow_action: Workflow action at this version.
        change_reason: Optional human-readable reason for this change.
    """

    rule_id: str
    timestamp: float
    version: int
    text: str
    severity: str
    enabled: bool
    keywords: tuple[str, ...]
    category: str
    subcategory: str
    workflow_action: str
    change_reason: str = ""

    @classmethod
    def from_rule(cls, rule: Rule, version: int, change_reason: str = "") -> RuleSnapshot:
        """Create a snapshot from a Rule instance."""
        return cls(
            rule_id=rule.id,
            timestamp=time.time(),
            version=version,
            text=rule.text,
            severity=rule.severity.value,
            enabled=rule.enabled,
            keywords=tuple(rule.keywords),
            category=rule.category,
            subcategory=rule.subcategory,
            workflow_action=rule.workflow_action,
            change_reason=change_reason,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise snapshot to a JSON-compatible dict."""
        return {
            "rule_id": self.rule_id,
            "timestamp": self.timestamp,
            "version": self.version,
            "text": self.text,
            "severity": self.severity,
            "enabled": self.enabled,
            "keywords": list(self.keywords),
            "category": self.category,
            "subcategory": self.subcategory,
            "workflow_action": self.workflow_action,
            "change_reason": self.change_reason,
        }


@dataclass(frozen=True, slots=True)
class ChangelogEntry:
    """exp128: Immutable record of a constitutional governance change.

    Captures what changed, when, by whom, and the constitutional hash
    before/after the change. Enables compliance audit trails, regulatory
    evidence, and change management dashboards.

    Attributes:
        timestamp: ISO 8601 timestamp of the change.
        change_type: Category of change — one of ``rule_added``,
            ``rule_removed``, ``rule_updated``, ``merged``,
            ``inherited``, ``imported``.
        rule_id: ID of the affected rule (empty string if N/A).
        actor: Identifier of the entity that made the change.
        details: Arbitrary metadata about the change.
        constitution_hash_before: Constitutional hash before the change.
        constitution_hash_after: Constitutional hash after the change.
    """

    timestamp: str
    change_type: str
    rule_id: str = ""
    actor: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    constitution_hash_before: str = ""
    constitution_hash_after: str = ""

    _VALID_CHANGE_TYPES: tuple[str, ...] = (
        "rule_added",
        "rule_removed",
        "rule_updated",
        "merged",
        "inherited",
        "imported",
    )

    def __post_init__(self) -> None:
        if self.change_type not in self._VALID_CHANGE_TYPES:
            msg = (
                f"Invalid change_type {self.change_type!r}; "
                f"expected one of {self._VALID_CHANGE_TYPES}"
            )
            raise ValueError(msg)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "timestamp": self.timestamp,
            "change_type": self.change_type,
            "rule_id": self.rule_id,
            "actor": self.actor,
            "details": self.details,
            "constitution_hash_before": self.constitution_hash_before,
            "constitution_hash_after": self.constitution_hash_after,
        }


class GovernanceChangelog:
    """exp128: Append-only governance change log.

    Records constitutional changes (rule additions, removals, updates,
    merges, inheritance, imports) with before/after hash provenance.
    Enables change management dashboards, compliance evidence, and
    regulatory audit trails.

    Follows the same query/summary/export pattern as ``AuditLedger``.

    Example::

        changelog = GovernanceChangelog()
        changelog.record(
            change_type="rule_added",
            rule_id="SAFE-001",
            actor="admin@corp.com",
            constitution_hash_before="abc123",
            constitution_hash_after="def456",
            details={"severity": "critical"},
        )
        recent = changelog.query(change_type="rule_added", since="2026-01-01")
    """

    __slots__ = ("_entries", "_max_entries", "_lock")

    def __init__(self, *, max_entries: int = 10_000) -> None:
        limit = max(0, max_entries)
        self._entries: deque[ChangelogEntry] = deque(maxlen=limit)
        self._max_entries = limit
        self._lock = threading.RLock()

    def record(
        self,
        change_type: str,
        *,
        rule_id: str = "",
        actor: str = "",
        details: dict[str, Any] | None = None,
        constitution_hash_before: str = "",
        constitution_hash_after: str = "",
        timestamp: str | None = None,
    ) -> ChangelogEntry:
        """Record a governance change.

        Args:
            change_type: Category — ``rule_added``, ``rule_removed``,
                ``rule_updated``, ``merged``, ``inherited``, ``imported``.
            rule_id: ID of the affected rule (if applicable).
            actor: Who made the change.
            details: Arbitrary metadata.
            constitution_hash_before: Hash before the change.
            constitution_hash_after: Hash after the change.
            timestamp: ISO 8601 timestamp (auto-generated if omitted).

        Returns:
            The created ``ChangelogEntry``.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        entry = ChangelogEntry(
            timestamp=ts,
            change_type=change_type,
            rule_id=rule_id,
            actor=actor,
            details=details or {},
            constitution_hash_before=constitution_hash_before,
            constitution_hash_after=constitution_hash_after,
        )
        with self._lock:
            self._entries.append(entry)
        return entry

    def query(
        self,
        *,
        change_type: str | None = None,
        rule_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[ChangelogEntry]:
        """Query the changelog with optional filters.

        Args:
            change_type: Filter by change type.
            rule_id: Filter to entries affecting this rule.
            since: ISO 8601 timestamp — entries at or after this time.
            until: ISO 8601 timestamp — entries before this time.

        Returns:
            List of matching entries in chronological order.
        """
        with self._lock:
            entries = list(self._entries)
        results: list[ChangelogEntry] = []
        for e in entries:
            if since is not None and e.timestamp < since:
                continue
            if until is not None and e.timestamp >= until:
                continue
            if change_type is not None and e.change_type != change_type:
                continue
            if rule_id is not None and e.rule_id != rule_id:
                continue
            results.append(e)
        return results

    def summary(self) -> dict[str, Any]:
        """Return a summary of changelog contents.

        Returns:
            dict with total, by_change_type counts, unique actors,
            time range, and affected rules.
        """
        with self._lock:
            entries = list(self._entries)
        total = len(entries)
        if total == 0:
            return {
                "total": 0,
                "by_change_type": {},
                "actors": [],
                "time_range": None,
                "affected_rules": [],
            }

        counts: dict[str, int] = {}
        actors: set[str] = set()
        rules: set[str] = set()

        for e in entries:
            counts[e.change_type] = counts.get(e.change_type, 0) + 1
            if e.actor:
                actors.add(e.actor)
            if e.rule_id:
                rules.add(e.rule_id)

        return {
            "total": total,
            "by_change_type": counts,
            "actors": sorted(actors),
            "time_range": {
                "earliest": entries[0].timestamp,
                "latest": entries[-1].timestamp,
            },
            "affected_rules": sorted(rules),
        }

    def export(self) -> list[dict[str, Any]]:
        """Export all entries as dicts for JSON serialization."""
        with self._lock:
            entries = list(self._entries)
        return [e.to_dict() for e in entries]

    def clear(self) -> None:
        """Clear all entries."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
