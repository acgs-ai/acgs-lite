"""Constitutional rules — the core of ACGS-Lite.

A Constitution is a set of Rules that govern agent behavior.
Rules can be loaded from YAML, dicts, or created programmatically.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import islice
from operator import itemgetter
from typing import Any


@dataclass(frozen=True, slots=True)
class GovernanceEvent:
    """exp100: Structured governance event for monitoring, alerting, and audit pipelines.

    Immutable record of a governance decision. Downstream systems (SIEM,
    observability dashboards, compliance logs) consume these events via
    ``to_dict()`` for JSON serialization or directly as typed objects.
    """

    event_type: (
        str  # "validation_allow" | "validation_deny" | "validation_escalate" | "maci_violation"
    )
    action: str
    decision: str  # "allow" | "deny" | "escalate"
    timestamp_ns: int  # monotonic nanoseconds for ordering
    rule_ids: tuple[str, ...] = ()
    severity: str = ""
    workflow_action: str = ""
    context_risk_score: float = 0.0
    agent_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON/JSONL output."""
        return {
            "event_type": self.event_type,
            "action": self.action,
            "decision": self.decision,
            "timestamp_ns": self.timestamp_ns,
            "rule_ids": list(self.rule_ids),
            "severity": self.severity,
            "workflow_action": self.workflow_action,
            "context_risk_score": self.context_risk_score,
            "agent_id": self.agent_id,
            "metadata": self.metadata,
        }


def create_governance_event(
    action: str,
    decision: str,
    *,
    rule_ids: Sequence[str] = (),
    severity: str = "",
    workflow_action: str = "",
    context_risk_score: float = 0.0,
    agent_id: str = "",
    metadata: dict[str, Any] | None = None,
) -> GovernanceEvent:
    """exp100: Factory for governance events with auto-populated fields.

    Args:
        action: The action that was validated.
        decision: The governance decision ("allow", "deny", "escalate").
        rule_ids: IDs of rules that triggered (empty for allow).
        severity: Highest severity among triggered rules.
        workflow_action: Recommended workflow action from the triggered rule.
        context_risk_score: Risk score from score_context_risk().
        agent_id: ID of the agent that submitted the action.
        metadata: Additional event metadata.

    Returns:
        Immutable GovernanceEvent ready for publishing.
    """
    event_type = f"validation_{decision}"
    return GovernanceEvent(
        event_type=event_type,
        action=action,
        decision=decision,
        timestamp_ns=time.monotonic_ns(),
        rule_ids=tuple(rule_ids),
        severity=severity,
        workflow_action=workflow_action,
        context_risk_score=context_risk_score,
        agent_id=agent_id,
        metadata=metadata or {},
    )


class GovernanceMetrics:
    """exp104: Lightweight governance statistics collector for observability.

    Tracks allow/deny/escalate counts, rule hit frequencies, and per-decision
    latency stats. Designed for export to Prometheus, OpenTelemetry, or
    custom dashboards. Thread-safe for single-writer use (typical governance
    engine pattern).

    Usage::

        metrics = GovernanceMetrics()
        metrics.record("allow", latency_us=3.2)
        metrics.record("deny", latency_us=5.1, rule_ids=["ACGS-001"])
        print(metrics.snapshot())
    """

    __slots__ = ("_counts", "_rule_hits", "_latencies", "_total")

    def __init__(self) -> None:
        self._counts: dict[str, int] = {"allow": 0, "deny": 0, "escalate": 0}
        self._rule_hits: dict[str, int] = {}
        self._latencies: list[float] = []
        self._total: int = 0

    def record(
        self,
        decision: str,
        *,
        latency_us: float = 0.0,
        rule_ids: Sequence[str] = (),
    ) -> None:
        """Record a governance decision.

        Args:
            decision: "allow", "deny", or "escalate".
            latency_us: Validation latency in microseconds.
            rule_ids: Rule IDs that triggered (for deny/escalate).
        """
        self._counts[decision] = self._counts.get(decision, 0) + 1
        self._total += 1
        if latency_us > 0:
            self._latencies.append(latency_us)
        for rid in rule_ids:
            self._rule_hits[rid] = self._rule_hits.get(rid, 0) + 1

    def snapshot(self) -> dict[str, Any]:
        """Return current metrics snapshot for export.

        Returns:
            dict with keys:
                - ``total_decisions``: total count
                - ``by_decision``: {allow: N, deny: N, escalate: N}
                - ``rule_hit_counts``: {rule_id: hit_count, ...}
                - ``latency``: {p50_us, p99_us, mean_us, count} or empty if no data
                - ``rates``: {allow_rate, deny_rate, escalate_rate} as floats
        """
        rates: dict[str, float] = {}
        if self._total > 0:
            for k, v in self._counts.items():
                rates[f"{k}_rate"] = v / self._total

        latency_stats: dict[str, float] = {}
        if self._latencies:
            sorted_lat = sorted(self._latencies)
            n = len(sorted_lat)
            latency_stats = {
                "p50_us": sorted_lat[n // 2],
                "p99_us": sorted_lat[int(n * 0.99)],
                "mean_us": sum(sorted_lat) / n,
                "count": float(n),
            }

        return {
            "total_decisions": self._total,
            "by_decision": dict(self._counts),
            "rule_hit_counts": dict(
                sorted(self._rule_hits.items(), key=lambda x: x[1], reverse=True)
            ),
            "latency": latency_stats,
            "rates": rates,
        }

    def reset(self) -> None:
        """Reset all counters. Call after exporting metrics."""
        self._counts = {"allow": 0, "deny": 0, "escalate": 0}
        self._rule_hits.clear()
        self._latencies.clear()
        self._total = 0

    def merge(self, other: GovernanceMetrics) -> GovernanceMetrics:
        """exp126: Return a new GovernanceMetrics combining self and other.

        Enables fleet-level analytics by aggregating metrics from multiple
        governance engine instances (e.g., across replicas or agents).

        Args:
            other: Another GovernanceMetrics instance to combine with.

        Returns:
            New GovernanceMetrics with combined counts, rule hits, and latencies.
            Neither self nor other is modified.

        Example::

            engine_a_metrics = GovernanceMetrics()
            engine_b_metrics = GovernanceMetrics()
            fleet_metrics = engine_a_metrics.merge(engine_b_metrics)
            print(fleet_metrics.snapshot())
        """
        merged = GovernanceMetrics()
        all_keys = set(self._counts) | set(other._counts)
        for k in all_keys:
            merged._counts[k] = self._counts.get(k, 0) + other._counts.get(k, 0)
        all_rules = set(self._rule_hits) | set(other._rule_hits)
        for rid in all_rules:
            merged._rule_hits[rid] = self._rule_hits.get(rid, 0) + other._rule_hits.get(rid, 0)
        merged._latencies = self._latencies + other._latencies
        merged._total = self._total + other._total
        return merged

    @classmethod
    def from_snapshot(cls, snapshot: dict[str, Any]) -> GovernanceMetrics:
        """exp126: Reconstruct a GovernanceMetrics from a snapshot dict.

        Enables metrics aggregation across process boundaries by deserialising
        from the output of :meth:`snapshot`.

        Args:
            snapshot: Dict as returned by :meth:`snapshot`.

        Returns:
            GovernanceMetrics instance with restored state.
        """
        m = cls()
        m._total = snapshot.get("total_decisions", 0)
        m._counts = dict(snapshot.get("by_decision", {}))
        m._rule_hits = dict(snapshot.get("rule_hit_counts", {}))
        latency = snapshot.get("latency", {})
        if latency and latency.get("count", 0) > 0:
            # Restore mean as synthetic samples to preserve count/mean;
            # p50/p99 are approximate for snapshot-reconstructed metrics.
            count = int(latency["count"])
            mean = latency.get("mean_us", 0.0)
            m._latencies = [mean] * count
        return m


class GovernanceSession:
    """exp113: Track governance decisions within an agent session.

    Maintains a bounded decision history for a single agent session, enabling:

    - Pattern detection (repeated denials, escalation spikes)
    - Anomaly alerting (deny rate exceeding threshold)
    - Session-level compliance reporting
    - Agent behavior profiling for trust scoring

    Usage::

        session = GovernanceSession("agent-42", max_history=100)
        session.record("allow", action="read customer list")
        session.record("deny", action="delete all records", rule_ids=["ACGS-001"])
        report = session.analyze()
        if report["anomalies"]:
            print("Governance anomaly detected!")
    """

    __slots__ = ("agent_id", "_max_history", "_decisions", "_deny_threshold")

    def __init__(
        self,
        agent_id: str,
        *,
        max_history: int = 200,
        deny_threshold: float = 0.3,
    ) -> None:
        """Initialize a governance session.

        Args:
            agent_id: ID of the agent being tracked.
            max_history: Maximum decisions to retain (FIFO eviction).
            deny_threshold: Deny rate above which an anomaly is flagged (0.0-1.0).
        """
        self.agent_id = agent_id
        limit = max(0, max_history)
        self._max_history = limit
        self._deny_threshold = deny_threshold
        self._decisions: deque[dict[str, Any]] = deque(maxlen=limit)

    def record(
        self,
        decision: str,
        *,
        action: str = "",
        rule_ids: Sequence[str] = (),
        severity: str = "",
    ) -> None:
        """Record a governance decision in this session.

        Args:
            decision: "allow", "deny", or "escalate".
            action: The action text that was validated.
            rule_ids: Rule IDs that triggered (for deny/escalate).
            severity: Severity of the highest-triggered rule.
        """
        entry = {
            "decision": decision,
            "action": action,
            "rule_ids": list(rule_ids),
            "severity": severity,
            "timestamp_ns": time.monotonic_ns(),
        }
        self._decisions.append(entry)

    def analyze(self) -> dict[str, Any]:
        """Analyze the session for patterns and anomalies.

        Returns:
            dict with keys:
                - ``agent_id``: the tracked agent ID
                - ``total_decisions``: count of decisions in history
                - ``by_decision``: {allow: N, deny: N, escalate: N}
                - ``deny_rate``: fraction of decisions that were denials
                - ``escalate_rate``: fraction that were escalations
                - ``top_triggered_rules``: most frequently triggered rule IDs
                - ``anomalies``: list of detected anomaly descriptions
                - ``recent_denials``: last 5 denial actions (for investigation)
        """
        total = len(self._decisions)
        if total == 0:
            return {
                "agent_id": self.agent_id,
                "total_decisions": 0,
                "by_decision": {"allow": 0, "deny": 0, "escalate": 0},
                "deny_rate": 0.0,
                "escalate_rate": 0.0,
                "top_triggered_rules": [],
                "anomalies": [],
                "recent_denials": [],
            }

        counts: dict[str, int] = {"allow": 0, "deny": 0, "escalate": 0}
        rule_hits: dict[str, int] = {}
        denials: list[dict[str, Any]] = []

        for d in self._decisions:
            counts[d["decision"]] = counts.get(d["decision"], 0) + 1
            if d["decision"] in ("deny", "escalate"):
                for rid in d["rule_ids"]:
                    rule_hits[rid] = rule_hits.get(rid, 0) + 1
            if d["decision"] == "deny":
                denials.append(d)

        deny_rate = counts.get("deny", 0) / total
        escalate_rate = counts.get("escalate", 0) / total

        top_rules = sorted(rule_hits.items(), key=lambda x: x[1], reverse=True)[:5]

        anomalies: list[str] = []
        if deny_rate > self._deny_threshold:
            anomalies.append(
                f"High deny rate: {deny_rate:.1%} exceeds threshold {self._deny_threshold:.1%}"
            )
        if total >= 10 and all(
            d["decision"] == "deny" for d in islice(reversed(self._decisions), 5)
        ):
            anomalies.append(
                "5 consecutive denials detected — possible policy conflict or rogue agent"
            )
        if escalate_rate > 0.5:
            anomalies.append(f"Escalation spike: {escalate_rate:.1%} of decisions escalated")

        return {
            "agent_id": self.agent_id,
            "total_decisions": total,
            "by_decision": counts,
            "deny_rate": deny_rate,
            "escalate_rate": escalate_rate,
            "top_triggered_rules": [{"rule_id": r, "hits": h} for r, h in top_rules],
            "anomalies": anomalies,
            "recent_denials": [
                {"action": d["action"], "rule_ids": d["rule_ids"]} for d in denials[-5:]
            ],
        }


class RuleEffectiveness:
    """exp114: Track rule fire rates and overrides for governance tuning.

    Monitors how often each rule triggers and how often those triggers lead
    to actual denials vs. overrides. Helps governance operators identify:

    - **Silent rules**: rules that never fire (may be misconfigured or redundant)
    - **Noisy rules**: rules that fire frequently but are often overridden
    - **Effective rules**: high fire rate with low override rate
    - **Tuning candidates**: rules whose severity may need adjustment

    Usage::

        tracker = RuleEffectiveness()
        tracker.record_fire("ACGS-001", overridden=False)
        tracker.record_fire("ACGS-002", overridden=True)
        report = tracker.report(total_validations=100)
    """

    __slots__ = ("_fires", "_overrides")

    def __init__(self) -> None:
        self._fires: dict[str, int] = {}
        self._overrides: dict[str, int] = {}

    def record_fire(self, rule_id: str, *, overridden: bool = False) -> None:
        """Record that a rule fired during validation.

        Args:
            rule_id: The rule that triggered.
            overridden: True if the denial was overridden (e.g., by HITL approval).
        """
        self._fires[rule_id] = self._fires.get(rule_id, 0) + 1
        if overridden:
            self._overrides[rule_id] = self._overrides.get(rule_id, 0) + 1

    def report(self, *, total_validations: int = 0) -> dict[str, Any]:
        """Generate effectiveness report for all tracked rules.

        Args:
            total_validations: Total number of validations run (for fire rate
                calculation). If 0, fire_rate is omitted.

        Returns:
            dict with keys:
                - ``rules``: list of per-rule effectiveness dicts sorted by
                  fire count descending, each with ``rule_id``, ``fires``,
                  ``overrides``, ``override_rate``, and optionally ``fire_rate``
                - ``silent_rules``: rule IDs that were tracked but never fired
                  (empty — tracked rules have at least 1 fire; use with
                  constitution rule IDs to find truly silent rules)
                - ``noisy_rules``: rules with override_rate > 0.5
                - ``effective_rules``: rules with fires > 0 and override_rate < 0.1
                - ``tuning_recommendations``: actionable suggestions
        """
        rules_data: list[dict[str, Any]] = []
        noisy: list[str] = []
        effective: list[str] = []
        recommendations: list[str] = []

        for rid in sorted(self._fires, key=lambda r: self._fires[r], reverse=True):
            fires = self._fires[rid]
            overrides = self._overrides.get(rid, 0)
            override_rate = overrides / fires if fires > 0 else 0.0

            entry: dict[str, Any] = {
                "rule_id": rid,
                "fires": fires,
                "overrides": overrides,
                "override_rate": override_rate,
            }
            if total_validations > 0:
                entry["fire_rate"] = fires / total_validations

            rules_data.append(entry)

            if override_rate > 0.5:
                noisy.append(rid)
                recommendations.append(
                    f"Rule {rid}: override rate {override_rate:.0%} — "
                    "consider lowering severity or refining keywords"
                )
            elif fires > 0 and override_rate < 0.1:
                effective.append(rid)

        return {
            "rules": rules_data,
            "silent_rules": [],
            "noisy_rules": noisy,
            "effective_rules": effective,
            "tuning_recommendations": recommendations,
        }

    def reset(self) -> None:
        """Reset all tracking data."""
        self._fires.clear()
        self._overrides.clear()


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """exp123: Single entry in the governance audit ledger.

    Uses wall-clock timestamps (ISO 8601) for compliance reconstruction,
    unlike ``GovernanceEvent`` which uses monotonic timestamps for ordering.
    """

    timestamp: str  # ISO 8601 UTC
    action: str
    decision: str  # "allow" | "deny" | "escalate"
    rule_ids: tuple[str, ...] = ()
    agent_id: str = ""
    severity: str = ""
    workflow_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON/JSONL export."""
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "decision": self.decision,
            "rule_ids": list(self.rule_ids),
            "agent_id": self.agent_id,
            "severity": self.severity,
            "workflow_action": self.workflow_action,
        }


class AuditLedger:
    """exp123: Queryable in-memory governance decision log.

    Records governance decisions with wall-clock timestamps, enabling
    compliance teams to reconstruct the decision history for any time
    period. Supports filtering by time range, decision type, agent,
    and rule ID.

    Unlike ``GovernanceSession`` (per-agent, monotonic timestamps) or
    ``GovernanceMetrics`` (aggregate counters), the audit ledger retains
    individual decision records queryable by wall-clock time.

    Usage::

        ledger = AuditLedger(max_entries=10000)
        ledger.record("read data", "allow", agent_id="agent-1")
        ledger.record("drop table", "deny", rule_ids=["ACGS-001"], agent_id="agent-2")

        # Query last hour
        recent = ledger.query(since="2026-03-14T10:00:00Z")
        denials = ledger.query(decision="deny")
        agent_log = ledger.query(agent_id="agent-2")
    """

    __slots__ = ("_entries", "_max_entries")

    def __init__(self, *, max_entries: int = 10000) -> None:
        limit = max(0, max_entries)
        self._entries: deque[AuditEntry] = deque(maxlen=limit)
        self._max_entries = limit

    def record(
        self,
        action: str,
        decision: str,
        *,
        rule_ids: Sequence[str] = (),
        agent_id: str = "",
        severity: str = "",
        workflow_action: str = "",
        timestamp: str | None = None,
    ) -> AuditEntry:
        """Record a governance decision.

        Args:
            action: The action text that was validated.
            decision: "allow", "deny", or "escalate".
            rule_ids: Rule IDs that triggered.
            agent_id: Agent that submitted the action.
            severity: Highest severity among triggered rules.
            workflow_action: Recommended downstream action.
            timestamp: ISO 8601 timestamp (auto-generated if omitted).

        Returns:
            The created AuditEntry.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        entry = AuditEntry(
            timestamp=ts,
            action=action,
            decision=decision,
            rule_ids=tuple(rule_ids),
            agent_id=agent_id,
            severity=severity,
            workflow_action=workflow_action,
        )
        self._entries.append(entry)
        return entry

    def query(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
        decision: str | None = None,
        agent_id: str | None = None,
        rule_id: str | None = None,
    ) -> list[AuditEntry]:
        """Query the ledger with optional filters.

        Args:
            since: ISO 8601 timestamp — only entries at or after this time.
            until: ISO 8601 timestamp — only entries before this time.
            decision: Filter by decision type ("allow", "deny", "escalate").
            agent_id: Filter by agent ID.
            rule_id: Filter to entries where this rule triggered.

        Returns:
            List of matching AuditEntry objects, chronological order.
        """
        results: list[AuditEntry] = []
        for e in self._entries:
            if since is not None and e.timestamp < since:
                continue
            if until is not None and e.timestamp >= until:
                continue
            if decision is not None and e.decision != decision:
                continue
            if agent_id is not None and e.agent_id != agent_id:
                continue
            if rule_id is not None and rule_id not in e.rule_ids:
                continue
            results.append(e)
        return results

    def summary(self) -> dict[str, Any]:
        """Return a summary of the ledger contents.

        Returns:
            dict with total, by_decision counts, unique agents,
            time range, and top triggered rules.
        """
        total = len(self._entries)
        if total == 0:
            return {
                "total": 0,
                "by_decision": {},
                "agents": [],
                "time_range": None,
                "top_rules": [],
            }

        counts: dict[str, int] = {}
        agents: set[str] = set()
        rule_hits: dict[str, int] = {}

        for e in self._entries:
            counts[e.decision] = counts.get(e.decision, 0) + 1
            if e.agent_id:
                agents.add(e.agent_id)
            for rid in e.rule_ids:
                rule_hits[rid] = rule_hits.get(rid, 0) + 1

        top_rules = sorted(rule_hits.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total": total,
            "by_decision": counts,
            "agents": sorted(agents),
            "time_range": {
                "earliest": self._entries[0].timestamp,
                "latest": self._entries[-1].timestamp,
            },
            "top_rules": [{"rule_id": r, "hits": h} for r, h in top_rules],
        }

    def export(self) -> list[dict[str, Any]]:
        """Export all entries as dicts for JSON serialization."""
        return [e.to_dict() for e in self._entries]

    def clear(self) -> None:
        """Clear all entries."""
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


class GovernanceSLO:
    """exp166: Governance Service Level Objective tracker with breach detection.

    Defines latency, compliance-rate, and deny-rate targets for a governance
    engine instance and evaluates whether recent decisions are meeting those
    targets. Breach alerts are emitted as structured dicts for integration
    with PagerDuty, OpsGenie, or Prometheus Alertmanager.

    Usage::

        slo = GovernanceSLO(
            name="production-governance",
            p99_latency_us=10.0,     # 10µs target
            compliance_rate=0.97,    # 97% allow rate
            max_deny_rate=0.05,      # 5% deny rate ceiling
            window_size=1000,        # evaluate over last 1000 decisions
        )

        # Record decisions via GovernanceMetrics, then evaluate:
        metrics = GovernanceMetrics()
        metrics.record("allow", latency_us=3.2)
        metrics.record("deny", latency_us=5.1, rule_ids=["ACGS-001"])

        report = slo.evaluate(metrics)
        if report["breached"]:
            for alert in report["alerts"]:
                send_alert(alert)

        # Check overall status:
        print(slo.status(metrics))  # "healthy" | "degraded" | "breached"
    """

    __slots__ = (
        "name",
        "p99_latency_us",
        "compliance_rate",
        "max_deny_rate",
        "window_size",
        "_breach_history",
    )

    def __init__(
        self,
        name: str = "governance",
        *,
        p99_latency_us: float = 10.0,
        compliance_rate: float = 0.97,
        max_deny_rate: float = 0.10,
        window_size: int = 1000,
    ) -> None:
        """Initialise an SLO with named targets.

        Args:
            name: Human-readable SLO name for alert labelling.
            p99_latency_us: Maximum acceptable p99 latency in microseconds.
            compliance_rate: Minimum acceptable allow-rate (0-1).
            max_deny_rate: Maximum acceptable deny-rate (0-1).
            window_size: Number of recent decisions to evaluate (rolling window).
        """
        self.name = name
        self.p99_latency_us = p99_latency_us
        self.compliance_rate = compliance_rate
        self.max_deny_rate = max_deny_rate
        self.window_size = window_size
        self._breach_history: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate(self, metrics: GovernanceMetrics) -> dict[str, Any]:
        """Evaluate SLO compliance against a GovernanceMetrics snapshot.

        Checks each objective (latency, compliance rate, deny rate) against
        the current metrics state. Breaches are appended to internal history
        for trend analysis via :meth:`breach_history`.

        Args:
            metrics: Live GovernanceMetrics instance to evaluate.

        Returns:
            dict with keys:
                - ``slo_name``: SLO identifier
                - ``evaluated_at``: ISO-8601 timestamp
                - ``total_decisions``: decisions evaluated
                - ``breached``: True if any objective is violated
                - ``objectives``: per-objective status dicts
                - ``alerts``: list of alert dicts for breached objectives
        """
        snapshot = metrics.snapshot()
        total = snapshot["total_decisions"]
        rates = snapshot.get("rates", {})
        latency = snapshot.get("latency", {})

        now_iso = datetime.now(timezone.utc).isoformat()

        objectives: list[dict[str, Any]] = []
        alerts: list[dict[str, Any]] = []

        # --- Latency objective ---
        p99_actual = latency.get("p99_us", 0.0) if latency else 0.0
        lat_ok = p99_actual <= self.p99_latency_us if latency else True
        lat_obj = {
            "objective": "p99_latency",
            "target_us": self.p99_latency_us,
            "actual_us": p99_actual,
            "met": lat_ok,
        }
        objectives.append(lat_obj)
        if not lat_ok:
            alerts.append(
                self._make_alert(
                    "p99_latency_breach",
                    f"p99 latency {p99_actual:.1f}µs exceeds SLO {self.p99_latency_us:.1f}µs",
                    severity="critical",
                    actual=p99_actual,
                    target=self.p99_latency_us,
                )
            )

        # --- Compliance rate objective ---
        allow_rate = rates.get("allow_rate", 1.0)
        comp_ok = allow_rate >= self.compliance_rate if total > 0 else True
        comp_obj = {
            "objective": "compliance_rate",
            "target": self.compliance_rate,
            "actual": round(allow_rate, 6),
            "met": comp_ok,
        }
        objectives.append(comp_obj)
        if not comp_ok:
            alerts.append(
                self._make_alert(
                    "compliance_rate_breach",
                    f"Allow rate {allow_rate:.2%} below SLO {self.compliance_rate:.2%}",
                    severity="warning",
                    actual=allow_rate,
                    target=self.compliance_rate,
                )
            )

        # --- Deny rate ceiling objective ---
        deny_rate = rates.get("deny_rate", 0.0)
        deny_ok = deny_rate <= self.max_deny_rate if total > 0 else True
        deny_obj = {
            "objective": "deny_rate",
            "target_max": self.max_deny_rate,
            "actual": round(deny_rate, 6),
            "met": deny_ok,
        }
        objectives.append(deny_obj)
        if not deny_ok:
            alerts.append(
                self._make_alert(
                    "deny_rate_breach",
                    f"Deny rate {deny_rate:.2%} exceeds SLO ceiling {self.max_deny_rate:.2%}",
                    severity="warning",
                    actual=deny_rate,
                    target=self.max_deny_rate,
                )
            )

        breached = bool(alerts)
        report: dict[str, Any] = {
            "slo_name": self.name,
            "evaluated_at": now_iso,
            "total_decisions": total,
            "breached": breached,
            "objectives": objectives,
            "alerts": alerts,
        }

        if breached:
            self._breach_history.append(
                {
                    "evaluated_at": now_iso,
                    "alerts": [a["alert_type"] for a in alerts],
                }
            )

        return report

    def status(self, metrics: GovernanceMetrics) -> str:
        """Return a human-readable health status string.

        Args:
            metrics: Live GovernanceMetrics instance to evaluate.

        Returns:
            ``"healthy"`` — all objectives met
            ``"degraded"`` — non-critical objective breached (compliance/deny)
            ``"breached"`` — critical objective breached (latency)
        """
        report = self.evaluate(metrics)
        if not report["breached"]:
            return "healthy"
        for alert in report["alerts"]:
            if alert.get("severity") == "critical":
                return "breached"
        return "degraded"

    def summary(self, metrics: GovernanceMetrics) -> dict[str, Any]:
        """Return a concise SLO summary for dashboards.

        Args:
            metrics: Live GovernanceMetrics instance to evaluate.

        Returns:
            dict with ``slo_name``, ``status``, ``breach_count``,
            ``objectives`` (name→met), and ``recent_breaches``.
        """
        report = self.evaluate(metrics)
        obj_summary = {o["objective"]: o["met"] for o in report["objectives"]}
        return {
            "slo_name": self.name,
            "status": self.status(metrics),
            "breach_count": len(self._breach_history),
            "objectives": obj_summary,
            "recent_breaches": self._breach_history[-5:],
        }

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def breach_history(self) -> list[dict[str, Any]]:
        """Return full breach event history for trend analysis.

        Returns:
            List of breach events, each with ``evaluated_at`` and ``alerts``.
        """
        return list(self._breach_history)

    def clear_history(self) -> None:
        """Reset the breach history (e.g., after a new deployment)."""
        self._breach_history.clear()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_alert(
        self,
        alert_type: str,
        message: str,
        *,
        severity: str,
        actual: float,
        target: float,
    ) -> dict[str, Any]:
        return {
            "alert_type": alert_type,
            "slo_name": self.name,
            "message": message,
            "severity": severity,
            "actual": actual,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def __repr__(self) -> str:
        return (
            f"GovernanceSLO(name={self.name!r}, "
            f"p99_latency_us={self.p99_latency_us}, "
            f"compliance_rate={self.compliance_rate}, "
            f"max_deny_rate={self.max_deny_rate})"
        )


# ── exp171: Cost attribution per governance decision ────────────────────────


@dataclass
class GovernanceCostModel:
    """exp171: Financial/operational cost attribution for governance decisions.

    Assigns cost weights to different governance outcomes (deny, escalate,
    human review) and tracks accumulated costs per rule, agent, and session.
    Enables FinOps and operational cost analysis for governance overhead.

    Cost units are abstract (e.g., USD, engineering-hours, or points) — the
    caller defines the unit system.  All fields default to sensible values
    that assume: deny=0, escalate=medium overhead, human_review=high overhead.

    Example::

        model = GovernanceCostModel(
            cost_per_deny=0.0,          # automated denials are free
            cost_per_escalate=5.0,      # 5 units = 5-min analyst interrupt
            cost_per_human_review=30.0, # 30 units = 30-min manual review
        )
        model.record("deny", rule_id="PRIVACY-001", agent_id="agent-42")
        model.record("escalate", rule_id="SAFETY-002", agent_id="agent-42")
        report = model.attribution_report()
        # {"total_cost": 5.0, "by_decision": ..., "by_rule": ..., "by_agent": ...}
    """

    cost_per_allow: float = 0.0
    cost_per_deny: float = 0.0
    cost_per_escalate: float = 5.0
    cost_per_human_review: float = 30.0

    # Internal accumulators (not frozen so we can mutate)
    _total_cost: float = field(default=0.0, init=False, repr=False)
    _decision_counts: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _decision_costs: dict[str, float] = field(default_factory=dict, init=False, repr=False)
    _rule_costs: dict[str, float] = field(default_factory=dict, init=False, repr=False)
    _rule_counts: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _agent_costs: dict[str, float] = field(default_factory=dict, init=False, repr=False)
    _agent_counts: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _event_log: list[dict[str, Any]] = field(default_factory=list, init=False, repr=False)

    def _cost_for_decision(self, decision: str, workflow_action: str = "") -> float:
        """Return cost for a single governance decision.

        ``workflow_action`` takes precedence over decision type for human-review
        routing: if ``workflow_action == "require_human_review"`` the higher cost
        applies regardless of the ``decision`` label.
        """
        if workflow_action == "require_human_review":
            return self.cost_per_human_review
        mapping = {
            "allow": self.cost_per_allow,
            "deny": self.cost_per_deny,
            "escalate": self.cost_per_escalate,
            "human_review": self.cost_per_human_review,
        }
        return mapping.get(decision, 0.0)

    def record(
        self,
        decision: str,
        *,
        rule_id: str = "",
        agent_id: str = "",
        workflow_action: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> float:
        """Record a governance decision and accumulate its cost.

        Args:
            decision: ``"allow"``, ``"deny"``, ``"escalate"``, or ``"human_review"``.
            rule_id:  ID of the triggering rule (empty for allow).
            agent_id: Agent or session identifier.
            workflow_action: Optional workflow routing hint (e.g.
                ``"require_human_review"``).
            metadata: Optional extra data stored in the event log.

        Returns:
            The cost incurred for this single decision.
        """
        cost = self._cost_for_decision(decision, workflow_action)
        self._total_cost += cost

        # Decision aggregates
        self._decision_counts[decision] = self._decision_counts.get(decision, 0) + 1
        self._decision_costs[decision] = self._decision_costs.get(decision, 0.0) + cost

        # Rule aggregates
        if rule_id:
            self._rule_costs[rule_id] = self._rule_costs.get(rule_id, 0.0) + cost
            self._rule_counts[rule_id] = self._rule_counts.get(rule_id, 0) + 1

        # Agent aggregates
        if agent_id:
            self._agent_costs[agent_id] = self._agent_costs.get(agent_id, 0.0) + cost
            self._agent_counts[agent_id] = self._agent_counts.get(agent_id, 0) + 1

        self._event_log.append(
            {
                "decision": decision,
                "cost": cost,
                "rule_id": rule_id,
                "agent_id": agent_id,
                "workflow_action": workflow_action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **(metadata or {}),
            }
        )
        return cost

    def attribution_report(self) -> dict[str, Any]:
        """Generate a cost attribution breakdown.

        Returns a dict with total cost and per-decision, per-rule, per-agent
        breakdowns, each sorted by cost descending.

        Returns::

            {
                "total_cost": 42.5,
                "event_count": 15,
                "by_decision": [{"decision": "escalate", "cost": 25.0, "count": 5}, ...],
                "by_rule": [{"rule_id": "SAFETY-001", "cost": 15.0, "count": 3}, ...],
                "by_agent": [{"agent_id": "agent-42", "cost": 30.0, "count": 6}, ...],
                "cost_model": {"allow": 0.0, "deny": 0.0, "escalate": 5.0, "human_review": 30.0},
            }
        """
        by_decision = sorted(
            [
                {
                    "decision": d,
                    "cost": self._decision_costs.get(d, 0.0),
                    "count": self._decision_counts.get(d, 0),
                }
                for d in self._decision_counts
            ],
            key=itemgetter("cost"),
            reverse=True,
        )
        by_rule = sorted(
            [
                {"rule_id": r, "cost": c, "count": self._rule_counts.get(r, 0)}
                for r, c in self._rule_costs.items()
            ],
            key=itemgetter("cost"),
            reverse=True,
        )
        by_agent = sorted(
            [
                {"agent_id": a, "cost": c, "count": self._agent_counts.get(a, 0)}
                for a, c in self._agent_costs.items()
            ],
            key=itemgetter("cost"),
            reverse=True,
        )
        return {
            "total_cost": self._total_cost,
            "event_count": len(self._event_log),
            "by_decision": by_decision,
            "by_rule": by_rule,
            "by_agent": by_agent,
            "cost_model": {
                "allow": self.cost_per_allow,
                "deny": self.cost_per_deny,
                "escalate": self.cost_per_escalate,
                "human_review": self.cost_per_human_review,
            },
        }

    def top_cost_rules(self, n: int = 5) -> list[dict[str, Any]]:
        """Return the top-N most expensive rules by accumulated cost."""
        return sorted(
            [
                {"rule_id": r, "cost": c, "count": self._rule_counts.get(r, 0)}
                for r, c in self._rule_costs.items()
            ],
            key=itemgetter("cost"),
            reverse=True,
        )[:n]

    def top_cost_agents(self, n: int = 5) -> list[dict[str, Any]]:
        """Return the top-N most expensive agents by accumulated cost."""
        return sorted(
            [
                {"agent_id": a, "cost": c, "count": self._agent_counts.get(a, 0)}
                for a, c in self._agent_costs.items()
            ],
            key=itemgetter("cost"),
            reverse=True,
        )[:n]

    def reset(self) -> None:
        """Reset all accumulators (e.g., start of a new billing period)."""
        self._total_cost = 0.0
        self._decision_counts.clear()
        self._decision_costs.clear()
        self._rule_costs.clear()
        self._rule_counts.clear()
        self._agent_costs.clear()
        self._agent_counts.clear()
        self._event_log.clear()

    def total_cost(self) -> float:
        """Current accumulated total cost."""
        return self._total_cost

    def event_log(self) -> list[dict[str, Any]]:
        """Full ordered event log (copy)."""
        return list(self._event_log)

    def __repr__(self) -> str:
        return (
            f"GovernanceCostModel(total_cost={self._total_cost:.2f}, "
            f"events={len(self._event_log)}, "
            f"escalate_cost={self.cost_per_escalate}, "
            f"human_review_cost={self.cost_per_human_review})"
        )


# ── exp172: Predictive governance analytics ─────────────────────────────────


@dataclass
class GovernanceForecaster:
    """exp172: Predictive governance analytics — trend-based violation forecasting.

    Maintains a rolling time-series of governance decisions and uses linear
    regression to project deny/escalate/compliance rates forward.  Designed
    for proactive governance: alert operators *before* a compliance breach
    occurs, not after.

    Each "window" represents one observation period (e.g., an hour, a day, or
    a benchmark run).  Call ``record_window()`` at the end of each period to
    add an observation, then ``forecast()`` to see projected rates.

    Example::

        forecaster = GovernanceForecaster(window_labels=["hour-1", "hour-2"])
        forecaster.record_window("hour-1", allow=80, deny=15, escalate=5)
        forecaster.record_window("hour-2", allow=70, deny=20, escalate=10)
        forecaster.record_window("hour-3", allow=60, deny=25, escalate=15)

        pred = forecaster.forecast(steps=2)
        # {"deny_rate": [0.31, 0.36], "escalate_rate": [...], ...}
    """

    max_windows: int = 100  # rolling history limit

    _windows: deque[dict[str, Any]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._windows = deque(maxlen=max(0, self.max_windows))

    # ------------------------------------------------------------------
    # Data ingestion
    # ------------------------------------------------------------------

    def record_window(
        self,
        label: str,
        *,
        allow: int = 0,
        deny: int = 0,
        escalate: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, float]:
        """Record a governance observation window.

        Args:
            label:    Human-readable window identifier (e.g. ``"2026-03-15T14:00"``).
            allow:    Number of allowed decisions in this window.
            deny:     Number of denied decisions.
            escalate: Number of escalated decisions.
            metadata: Optional extra context stored alongside the window.

        Returns:
            Dict with computed ``deny_rate``, ``escalate_rate``, and
            ``compliance_rate`` for this window.
        """
        total = allow + deny + escalate
        deny_rate = deny / total if total else 0.0
        escalate_rate = escalate / total if total else 0.0
        compliance_rate = allow / total if total else 1.0

        window = {
            "label": label,
            "allow": allow,
            "deny": deny,
            "escalate": escalate,
            "total": total,
            "deny_rate": deny_rate,
            "escalate_rate": escalate_rate,
            "compliance_rate": compliance_rate,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        }
        target_maxlen = max(0, self.max_windows)
        if self._windows.maxlen != target_maxlen:
            self._windows = deque(self._windows, maxlen=target_maxlen)
        self._windows.append(window)

        return {
            "deny_rate": deny_rate,
            "escalate_rate": escalate_rate,
            "compliance_rate": compliance_rate,
        }

    # ------------------------------------------------------------------
    # Forecasting helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _linear_trend(values: list[float]) -> tuple[float, float]:
        """Compute slope and intercept via ordinary least squares.

        Args:
            values: Observed time-series (equally spaced).

        Returns:
            ``(slope, intercept)`` pair.  Returns ``(0.0, values[-1])`` when
            fewer than 2 observations exist.
        """
        n = len(values)
        if n < 2:
            return 0.0, (values[0] if values else 0.0)
        # x = 0, 1, ..., n-1
        x_mean = (n - 1) / 2.0
        y_mean = sum(values) / n
        num = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
        denom = sum((i - x_mean) ** 2 for i in range(n))
        slope = num / denom if denom else 0.0
        intercept = y_mean - slope * x_mean
        return slope, intercept

    def _extrapolate(self, field: str, steps: int) -> list[float]:
        """Extrapolate *field* forward *steps* windows using linear trend."""
        values = [w[field] for w in self._windows]
        if not values:
            return [0.0] * steps
        slope, intercept = self._linear_trend(values)
        n = len(values)
        return [max(0.0, min(1.0, intercept + slope * (n + i))) for i in range(steps)]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def forecast(self, steps: int = 3) -> dict[str, Any]:
        """Forecast governance metrics for the next *steps* windows.

        Uses ordinary least-squares linear regression over the observed
        window history to project deny_rate, escalate_rate, and
        compliance_rate forward.

        Args:
            steps: Number of future windows to forecast (1-50).

        Returns::

            {
                "steps": 3,
                "history_windows": 5,
                "trend": {
                    "deny_rate": "increasing" | "stable" | "decreasing",
                    "escalate_rate": "increasing" | "stable" | "decreasing",
                    "compliance_rate": "increasing" | "stable" | "decreasing",
                },
                "forecast": {
                    "deny_rate": [0.18, 0.21, 0.24],
                    "escalate_rate": [0.06, 0.07, 0.08],
                    "compliance_rate": [0.76, 0.72, 0.68],
                },
                "alerts": [
                    {"type": "deny_rate_rising", "projected_at_step": 2, "value": 0.30},
                ],
            }
        """
        steps = max(1, min(50, steps))
        n = len(self._windows)

        deny_proj = self._extrapolate("deny_rate", steps)
        esc_proj = self._extrapolate("escalate_rate", steps)
        comp_proj = self._extrapolate("compliance_rate", steps)

        def _trend_label(values: list[float], field: str) -> str:
            if n < 2:
                return "stable"
            slope, _ = self._linear_trend(values)
            if slope > 0.005:
                return "increasing"
            if slope < -0.005:
                return "decreasing"
            return "stable"

        deny_vals = [w["deny_rate"] for w in self._windows]
        esc_vals = [w["escalate_rate"] for w in self._windows]
        comp_vals = [w["compliance_rate"] for w in self._windows]

        alerts: list[dict[str, Any]] = []
        DENY_ALERT_THRESHOLD = 0.30
        ESC_ALERT_THRESHOLD = 0.20
        COMP_ALERT_THRESHOLD = 0.70

        for i, dr in enumerate(deny_proj):
            if dr >= DENY_ALERT_THRESHOLD:
                alerts.append(
                    {
                        "type": "deny_rate_rising",
                        "projected_at_step": i + 1,
                        "value": round(dr, 4),
                        "threshold": DENY_ALERT_THRESHOLD,
                    }
                )
                break  # only alert on first breach
        for i, er in enumerate(esc_proj):
            if er >= ESC_ALERT_THRESHOLD:
                alerts.append(
                    {
                        "type": "escalate_rate_rising",
                        "projected_at_step": i + 1,
                        "value": round(er, 4),
                        "threshold": ESC_ALERT_THRESHOLD,
                    }
                )
                break
        for i, cr in enumerate(comp_proj):
            if cr < COMP_ALERT_THRESHOLD:
                alerts.append(
                    {
                        "type": "compliance_declining",
                        "projected_at_step": i + 1,
                        "value": round(cr, 4),
                        "threshold": COMP_ALERT_THRESHOLD,
                    }
                )
                break

        return {
            "steps": steps,
            "history_windows": n,
            "trend": {
                "deny_rate": _trend_label(deny_vals, "deny_rate"),
                "escalate_rate": _trend_label(esc_vals, "escalate_rate"),
                "compliance_rate": _trend_label(comp_vals, "compliance_rate"),
            },
            "forecast": {
                "deny_rate": [round(v, 4) for v in deny_proj],
                "escalate_rate": [round(v, 4) for v in esc_proj],
                "compliance_rate": [round(v, 4) for v in comp_proj],
            },
            "alerts": alerts,
        }

    def summary(self) -> dict[str, Any]:
        """Snapshot of current observed metrics across all recorded windows.

        Returns::

            {
                "windows_recorded": 5,
                "latest": {"deny_rate": 0.20, "escalate_rate": 0.10, ...},
                "average": {"deny_rate": 0.15, "escalate_rate": 0.08, ...},
            }
        """
        if not self._windows:
            return {"windows_recorded": 0, "latest": {}, "average": {}}
        n = len(self._windows)
        latest = self._windows[-1]
        avg_deny = sum(w["deny_rate"] for w in self._windows) / n
        avg_esc = sum(w["escalate_rate"] for w in self._windows) / n
        avg_comp = sum(w["compliance_rate"] for w in self._windows) / n
        return {
            "windows_recorded": n,
            "latest": {
                "deny_rate": round(latest["deny_rate"], 4),
                "escalate_rate": round(latest["escalate_rate"], 4),
                "compliance_rate": round(latest["compliance_rate"], 4),
            },
            "average": {
                "deny_rate": round(avg_deny, 4),
                "escalate_rate": round(avg_esc, 4),
                "compliance_rate": round(avg_comp, 4),
            },
        }

    def history(self) -> list[dict[str, Any]]:
        """Return a copy of the full window history."""
        return list(self._windows)

    def __repr__(self) -> str:
        return f"GovernanceForecaster(windows={len(self._windows)}, max_windows={self.max_windows})"
