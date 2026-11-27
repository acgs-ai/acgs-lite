"""Governance dashboard — metrics, timelines, and a minimal ASGI app.

Provides pure-data structures for governance observability and a
zero-dependency ASGI application that serves JSON APIs and a
self-contained HTML dashboard page.

Constitutional Hash: 608508a9bd224290

Usage::

    from acgs_lite.audit import AuditLog
    from acgs_lite.constitution import Constitution
    from acgs_lite.engine import GovernanceEngine
    from acgs_lite.integrations.dashboard import (
        GovernanceDashboard,
        create_dashboard_asgi_app,
    )

    constitution = Constitution.default()
    audit_log = AuditLog()
    engine = GovernanceEngine(constitution, audit_log=audit_log)
    dashboard = GovernanceDashboard(engine, audit_log, constitution)

    # Serve with any ASGI server:
    app = create_dashboard_asgi_app(dashboard)
    # e.g. uvicorn acgs_lite.integrations.dashboard:app
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import islice
from typing import Any

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution, Severity
from acgs_lite.engine import GovernanceEngine
from acgs_lite.engine.types import ValidationResult, Violation
from acgs_lite.errors import ConstitutionalViolationError

# ── Constants ──────────────────────────────────────────────────────────
_CONSTITUTIONAL_HASH = "608508a9bd224290"
_JSON_CT = [(b"content-type", b"application/json; charset=utf-8")]
_HTML_CT = [(b"content-type", b"text/html; charset=utf-8")]
ProposalProvider = Callable[[], Iterable[dict[str, Any]]]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[dict[str, Any], Receive, Send], Awaitable[None]]


# ── DashboardMetrics ───────────────────────────────────────────────────
@dataclass(slots=True)
class DashboardMetrics:
    """Point-in-time snapshot of governance metrics."""

    timestamp: str
    engine_stats: dict[str, Any]
    audit_chain_valid: bool
    total_rules: int
    rules_by_severity: dict[str, int]
    rules_by_category: dict[str, int]
    compliance_score: float
    recent_violations: list[dict[str, Any]]
    constitutional_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "timestamp": self.timestamp,
            "engine_stats": self.engine_stats,
            "audit_chain_valid": self.audit_chain_valid,
            "total_rules": self.total_rules,
            "rules_by_severity": self.rules_by_severity,
            "rules_by_category": self.rules_by_category,
            "compliance_score": self.compliance_score,
            "recent_violations": self.recent_violations,
            "constitutional_hash": self.constitutional_hash,
        }


# ── ViolationTimeline ──────────────────────────────────────────────────
class ViolationTimeline:
    """Chronological record of governance violations.

    Thread-safe for single-writer / multi-reader patterns (CPython GIL).
    Older entries are evicted when *max_entries* is exceeded.
    """

    __slots__ = ("_entries", "_max_entries")

    def __init__(self, *, max_entries: int = 1000) -> None:
        limit = max(0, max_entries)
        self._entries: deque[dict[str, Any]] = deque(maxlen=limit)
        self._max_entries = limit

    def record(
        self,
        violation: Violation,
        agent_id: str,
        timestamp: str | None = None,
    ) -> None:
        """Record a single violation event."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        entry = {
            "rule_id": violation.rule_id,
            "rule_text": violation.rule_text,
            "severity": (
                violation.severity.value
                if isinstance(violation.severity, Severity)
                else str(violation.severity)
            ),
            "matched_content": violation.matched_content,
            "category": violation.category,
            "agent_id": agent_id,
            "timestamp": ts,
        }
        self._entries.append(entry)

    def record_from_result(self, result: ValidationResult) -> None:
        """Bulk-record all violations from a ValidationResult."""
        for v in result.violations:
            self.record(v, result.agent_id, result.timestamp or None)

    def get_timeline(
        self,
        last_n: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return chronological violation entries."""
        if last_n is None:
            return list(self._entries)
        if last_n <= 0:
            return []
        if last_n >= len(self._entries):
            return list(self._entries)
        recent = list(islice(reversed(self._entries), last_n))
        recent.reverse()
        return recent

    def get_by_severity(self, severity: str) -> list[dict[str, Any]]:
        """Filter entries by severity level."""
        return [e for e in self._entries if e["severity"] == severity]

    def get_by_agent(self, agent_id: str) -> list[dict[str, Any]]:
        """Filter entries by agent identifier."""
        return [e for e in self._entries if e["agent_id"] == agent_id]

    def summary(self) -> dict[str, Any]:
        """Violation counts by severity and by hour bucket."""
        by_severity: dict[str, int] = defaultdict(int)
        by_hour: dict[str, int] = defaultdict(int)
        for entry in self._entries:
            by_severity[entry["severity"]] += 1
            ts = entry.get("timestamp", "")
            hour = ts[:13] if len(ts) >= 13 else ts
            by_hour[hour] += 1
        return {
            "total": len(self._entries),
            "by_severity": dict(by_severity),
            "by_hour": dict(by_hour),
        }


# ── GovernanceDashboard ────────────────────────────────────────────────
class GovernanceDashboard:
    """Aggregate facade over engine, audit log, and constitution.

    Provides metrics snapshots, a violation timeline, per-agent stats,
    and a ``validate_and_record`` convenience method that feeds the
    timeline automatically.
    """

    __slots__ = ("_engine", "_audit_log", "_constitution", "_timeline")

    def __init__(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
        constitution: Constitution,
    ) -> None:
        self._engine = engine
        self._audit_log = audit_log
        self._constitution = constitution
        self._timeline = ViolationTimeline()

    # ── public API ─────────────────────────────────────────────────

    def get_metrics(self) -> DashboardMetrics:
        """Build a point-in-time metrics snapshot."""
        stats = self._engine.stats
        rules = self._constitution.rules

        by_severity: dict[str, int] = defaultdict(int)
        by_category: dict[str, int] = defaultdict(int)
        for rule in rules:
            sev = rule.severity.value if isinstance(rule.severity, Severity) else str(rule.severity)
            by_severity[sev] += 1
            by_category[rule.category] += 1

        compliance = stats.get("compliance_rate", 1.0)

        recent = self._timeline.get_timeline(last_n=20)

        return DashboardMetrics(
            timestamp=datetime.now(timezone.utc).isoformat(),
            engine_stats=stats,
            audit_chain_valid=self._audit_log.verify_chain(),
            total_rules=len(rules),
            rules_by_severity=dict(by_severity),
            rules_by_category=dict(by_category),
            compliance_score=float(compliance),
            recent_violations=recent,
            constitutional_hash=self._constitution.hash,
        )

    def get_timeline(self) -> ViolationTimeline:
        """Access the internal violation timeline."""
        return self._timeline

    def validate_and_record(
        self,
        text: str,
        agent_id: str,
    ) -> ValidationResult:
        """Validate text and auto-record any violations to timeline."""
        try:
            result = self._engine.validate(text, agent_id=agent_id)
        except ConstitutionalViolationError:
            # In strict mode the engine raises; re-validate non-strictly to capture the full result.
            result = self._engine.validate(text, agent_id=agent_id, strict=False)
        if result.violations:
            self._timeline.record_from_result(result)
        return result

    def get_rule_coverage(self) -> dict[str, Any]:
        """Analyse which categories and severities have rules."""
        rules = self._constitution.rules
        categories: set[str] = set()
        severities: set[str] = set()
        tags: set[str] = set()
        for rule in rules:
            categories.add(rule.category)
            sev = rule.severity.value if isinstance(rule.severity, Severity) else str(rule.severity)
            severities.add(sev)
            if hasattr(rule, "tags"):
                tags.update(rule.tags)
        return {
            "total_rules": len(rules),
            "categories": sorted(categories),
            "severities": sorted(severities),
            "tags": sorted(tags),
            "category_count": len(categories),
            "severity_count": len(severities),
        }

    def get_agent_summary(self) -> dict[str, dict[str, Any]]:
        """Per-agent validation statistics from the audit log."""
        agents: dict[str, dict[str, Any]] = {}
        for entry in self._audit_log.entries:
            aid = entry.agent_id or "unknown"
            if aid not in agents:
                agents[aid] = {
                    "total_validations": 0,
                    "valid": 0,
                    "invalid": 0,
                    "violations": 0,
                }
            agents[aid]["total_validations"] += 1
            if entry.valid:
                agents[aid]["valid"] += 1
            else:
                agents[aid]["invalid"] += 1
            agents[aid]["violations"] += len(entry.violations)
        return agents

    def health_check(self) -> dict[str, Any]:
        """System health status."""
        chain_valid = self._audit_log.verify_chain()
        stats = self._engine.stats
        return {
            "status": "healthy" if chain_valid else "degraded",
            "audit_chain_valid": chain_valid,
            "total_validations": stats.get("total_validations", 0),
            "rules_loaded": len(self._constitution.rules),
            "constitutional_hash": self._constitution.hash,
            "expected_hash": _CONSTITUTIONAL_HASH,
            "hash_match": self._constitution.hash == _CONSTITUTIONAL_HASH,
        }

    def export_snapshot(self) -> dict[str, Any]:
        """Full dashboard state as a JSON-serializable dict."""
        return {
            "metrics": self.get_metrics().to_dict(),
            "timeline": self._timeline.get_timeline(),
            "timeline_summary": self._timeline.summary(),
            "rule_coverage": self.get_rule_coverage(),
            "agent_summary": self.get_agent_summary(),
            "health": self.health_check(),
        }


# ── ASGI App ───────────────────────────────────────────────────────────


def _json_response(
    data: Any,
    status: int = 200,
) -> tuple[bytes, int, list[tuple[bytes, bytes]]]:
    body = json.dumps(data, default=str).encode()
    return body, status, _JSON_CT


def _html_response(
    html: str,
    status: int = 200,
) -> tuple[bytes, int, list[tuple[bytes, bytes]]]:
    return html.encode(), status, _HTML_CT


_DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ACGS-Lite Governance Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f5f7fa;color:#1a1a2e;
padding:1.5rem}
h1{font-size:1.4rem;margin-bottom:1rem}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));
gap:1rem;margin-bottom:1.5rem}
.card{background:#fff;border-radius:8px;padding:1rem;
box-shadow:0 1px 3px rgba(0,0,0,.1)}
.card h3{font-size:.75rem;text-transform:uppercase;color:#666;
margin-bottom:.25rem}
.card .val{font-size:1.5rem;font-weight:700}
.ok{color:#16a34a}.warn{color:#dc2626}
table{width:100%;border-collapse:collapse;background:#fff;
border-radius:8px;overflow:hidden;
box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:1.5rem}
th,td{padding:.5rem .75rem;text-align:left;border-bottom:1px solid #eee}
th{background:#f0f0f5;font-size:.75rem;text-transform:uppercase}
.section{margin-bottom:1.5rem}
.section h2{font-size:1rem;margin-bottom:.75rem}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;
font-size:.75rem;margin:2px;background:#e0e7ff;color:#3730a3}
#error{color:#dc2626;margin:1rem 0;display:none}
</style>
</head>
<body>
<h1>ACGS-Lite Governance Dashboard</h1>
<div id="error"></div>
<div class="cards" id="kpi"></div>
<div class="section">
<h2>Recent Violations</h2>
<table><thead><tr>
<th>Time</th><th>Rule</th><th>Severity</th>
<th>Agent</th><th>Content</th>
</tr></thead><tbody id="violations"></tbody></table>
</div>
<div class="section">
<h2>Rule Distribution</h2>
<div id="rules"></div>
</div>
<script>
async function load(){
 try{
  const [mr,tr]=await Promise.all([
   fetch('/api/metrics').then(r=>r.json()),
   fetch('/api/timeline').then(r=>r.json())
  ]);
  const m=mr;
  document.getElementById('kpi').innerHTML=
   card('Total Validations',m.engine_stats.total_validations||0)+
   card('Violations',m.recent_violations.length)+
   card('Compliance',((m.compliance_score*100).toFixed(1))+'%')+
   card('Audit Chain',m.audit_chain_valid?
    '<span class="ok">VALID</span>':
    '<span class="warn">INVALID</span>')+
   card('Rules',m.total_rules)+
   card('Hash',m.constitutional_hash);
  const tb=document.getElementById('violations');
  const vs=tr.timeline||[];
  if(!vs.length){tb.innerHTML='<tr><td colspan=5>None</td></tr>';}
  else{tb.innerHTML=vs.slice(-20).reverse().map(v=>
   '<tr><td>'+esc(v.timestamp)+'</td><td>'+esc(v.rule_id)+
   '</td><td>'+esc(v.severity)+'</td><td>'+esc(v.agent_id)+
   '</td><td>'+esc((v.matched_content||'').slice(0,80))+
   '</td></tr>').join('');}
  const rd=document.getElementById('rules');
  rd.innerHTML=Object.entries(m.rules_by_severity).map(
   ([k,v])=>'<span class="tag">'+esc(k)+': '+v+'</span>'
  ).join('')+'<br>'+Object.entries(m.rules_by_category).map(
   ([k,v])=>'<span class="tag">'+esc(k)+': '+v+'</span>'
  ).join('');
 }catch(e){
  const el=document.getElementById('error');
  el.style.display='block';el.textContent='Load failed: '+e;
 }
}
function card(t,v){return '<div class="card"><h3>'+t+
 '</h3><div class="val">'+v+'</div></div>';}
function esc(s){const d=document.createElement('div');
 d.textContent=String(s);return d.innerHTML;}
load();setInterval(load,15000);
</script>
</body>
</html>
"""


def create_dashboard_asgi_app(
    dashboard: GovernanceDashboard,
    *,
    proposal_provider: ProposalProvider | None = None,
) -> ASGIApp:
    """Return a minimal ASGI application serving the dashboard.

    Routes:
        GET  /                                HTML dashboard page
        GET  /api/metrics                     Current metrics snapshot
        GET  /api/timeline                    Violation timeline entries
        GET  /api/health                      Health check
        GET  /api/rules                       Constitution rules list
        GET  /api/agents                      Per-agent summary
        GET  /api/suggestions                 Pending SuggestedRule objects
        GET  /api/proposals                   All governance proposals
        POST /api/proposals/{id}/vote         Cast a Polis vote
        POST /api/proposals/{id}/deploy       Deploy an approved proposal

    ``proposal_provider`` keeps this module decoupled from higher-level
    orchestration packages. Callers that have a proposal source can inject it;
    otherwise the endpoint returns an empty list.
    """

    def _load_proposals() -> list[dict[str, Any]]:
        if proposal_provider is None:
            return []
        try:
            return list(proposal_provider())
        except Exception:
            return []

    async def app(
        scope: dict[str, Any],
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            return

        path: str = scope.get("path", "/")
        method: str = scope.get("method", "GET")

        # ── Governance proposal endpoints ──────────────────────────────
        if path == "/api/suggestions" and method == "GET":
            body, status, headers = _json_response(
                {
                    "suggestions": [],
                    "count": 0,
                    "note": "Wire AutoSynthesizer to populate",
                }
            )
        elif path == "/api/proposals" and method == "GET":
            proposal_list = _load_proposals()
            body, status, headers = _json_response(
                {"proposals": proposal_list, "count": len(proposal_list)}
            )
        elif method == "POST" and path.startswith("/api/proposals/") and path.endswith("/vote"):
            # /api/proposals/{proposal_id}/vote
            parts = path.split("/")
            proposal_id = parts[3] if len(parts) >= 4 else ""
            query_string: str = scope.get("query_string", b"").decode()
            params: dict[str, str] = {}
            for pair in query_string.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    params[k] = v
            stakeholder_id = params.get("stakeholder_id", "")
            try:
                vote = int(params.get("vote", "0"))
            except ValueError:
                vote = 0
            body, status, headers = _json_response(
                {
                    "proposal_id": proposal_id,
                    "stakeholder_id": stakeholder_id,
                    "vote": vote,
                    # Stub: votes are not persisted — real implementation requires
                    # authenticated stakeholder identity and NMC session wiring.
                    "status": "stub_not_persisted",
                    "warning": "Vote endpoint is a stub. Authentication and persistence not implemented.",
                }
            )
        elif method == "POST" and path.startswith("/api/proposals/") and path.endswith("/deploy"):
            # /api/proposals/{proposal_id}/deploy
            parts = path.split("/")
            proposal_id = parts[3] if len(parts) >= 4 else ""
            body, status, headers = _json_response(
                {
                    "proposal_id": proposal_id,
                    "status": "deployment requires NMC consensus",
                }
            )
        # ── Original endpoints ─────────────────────────────────────────
        elif method != "GET":
            body, status, headers = _json_response(
                {"error": "Method not allowed"},
                405,
            )
        elif path == "/":
            body, status, headers = _html_response(_DASHBOARD_HTML)
        elif path == "/api/metrics":
            body, status, headers = _json_response(
                dashboard.get_metrics().to_dict(),
            )
        elif path == "/api/timeline":
            tl = dashboard.get_timeline()
            body, status, headers = _json_response(
                {"timeline": tl.get_timeline(), "summary": tl.summary()},
            )
        elif path == "/api/health":
            body, status, headers = _json_response(
                dashboard.health_check(),
            )
        elif path == "/api/rules":
            rules = dashboard._constitution.rules
            body, status, headers = _json_response(
                {
                    "rules": [
                        {
                            "id": r.id,
                            "text": r.text,
                            "severity": (
                                r.severity.value
                                if isinstance(r.severity, Severity)
                                else str(r.severity)
                            ),
                            "category": r.category,
                            "tags": (r.tags if hasattr(r, "tags") else []),
                            "enabled": r.enabled,
                        }
                        for r in rules
                    ],
                    "total": len(rules),
                    "coverage": dashboard.get_rule_coverage(),
                },
            )
        elif path == "/api/agents":
            body, status, headers = _json_response(
                dashboard.get_agent_summary(),
            )
        else:
            body, status, headers = _json_response(
                {"error": "Not found"},
                404,
            )

        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )

    return app
