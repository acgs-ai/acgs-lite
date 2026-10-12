"""Hackathon eval suite — validates all capability and regression evals.

Run: python -m pytest packages/acgs-lite/tests/test_hackathon_evals.py -v --import-mode=importlib
"""

from __future__ import annotations

import dataclasses

import pytest

# ── Regression: imports ──────────────────────────────────────────────────


class TestRegressionImports:
    """REG-*: all modules importable, API stable."""

    def test_reg_gl_01_gitlab_imports(self) -> None:
        from acgs_lite.integrations.gitlab import (
            GitLabGovernanceBot,
            GovernanceReport,
        )

        assert GovernanceReport is not None
        assert GitLabGovernanceBot is not None

    def test_reg_mcp_02_mcp_imports(self) -> None:
        from acgs_lite.integrations.mcp_server import create_mcp_server

        assert create_mcp_server is not None

    def test_reg_cr_01_cloud_run_imports(self) -> None:
        from acgs_lite.integrations.cloud_run_server import (
            app,
        )

        assert app is not None

    def test_reg_mcp_01_constitution_hash_stable(self) -> None:
        from acgs_lite.constitution import Constitution

        c1 = Constitution.default()
        c2 = Constitution.default()
        assert c1.hash == c2.hash
        assert len(c1.hash) == 16

    def test_reg_mcp_03_constitutional_hash_value(self) -> None:
        from acgs_lite.constitution import Constitution

        c = Constitution.default()
        assert c.hash == "608508a9bd224290", f"Hash changed: {c.hash}"

    def test_reg_gl_02_governance_report_fields(self) -> None:
        from acgs_lite.integrations.gitlab import GovernanceReport

        fields = {f.name for f in dataclasses.fields(GovernanceReport)}
        required = {
            "mr_iid",
            "title",
            "passed",
            "risk_score",
            "violations",
            "warnings",
            "commit_violations",
            "rules_checked",
            "constitutional_hash",
            "latency_ms",
        }
        missing = required - fields
        assert not missing, f"Missing fields: {missing}"

    def test_reg_gl_03_hash_in_ci_config(self) -> None:
        from acgs_lite.constitution import Constitution
        from acgs_lite.integrations.gitlab import create_gitlab_ci_config

        c = Constitution.default()
        config = create_gitlab_ci_config(c)
        assert c.hash in config


# ── Cloud Run ────────────────────────────────────────────────────────────


class TestCloudRun:
    """CAP-CR-*: Cloud Run server endpoints."""

    def test_cap_cr_01_health_endpoint(self) -> None:
        from starlette.testclient import TestClient

        from acgs_lite.integrations.cloud_run_server import app

        client = TestClient(app)
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert data["constitutional_hash"] == "608508a9bd224290"
        assert data["rules_loaded"] > 0

    def test_cap_cr_02_governance_summary(self) -> None:
        from starlette.testclient import TestClient

        from acgs_lite.integrations.cloud_run_server import app

        client = TestClient(app)
        r = client.get("/governance/summary")
        assert r.status_code == 200
        data = r.json()
        assert "constitutional_hash" in data
        assert "summary" in data

    def test_cap_cr_03_webhook_no_credentials(self) -> None:
        import os

        os.environ.pop("GITLAB_TOKEN", None)
        os.environ.pop("GITLAB_PROJECT_ID", None)

        import importlib

        from starlette.testclient import TestClient

        import acgs_lite.integrations.cloud_run_server as srv

        importlib.reload(srv)

        client = TestClient(srv.app)
        r = client.post(
            "/webhook",
            json={},
            headers={"X-Gitlab-Token": "any", "X-Gitlab-Event": "Merge Request Hook"},
        )
        assert r.status_code in (401, 503)

    def test_cap_cr_04_exactly_3_routes(self) -> None:
        from acgs_lite.integrations.cloud_run_server import app

        routes = {str(r.path) for r in app.routes}
        expected = {"/webhook", "/health", "/governance/summary"}
        assert expected == routes

    def test_cap_cr_05_cloud_logging_optional(self) -> None:
        from acgs_lite.integrations.cloud_run_server import app

        # Should import without raising, even without GCP credentials
        assert app is not None

    def test_reg_cr_02_health_always_healthy(self) -> None:
        from starlette.testclient import TestClient

        from acgs_lite.integrations.cloud_run_server import app

        client = TestClient(app)
        for _ in range(3):
            r = client.get("/health")
            assert r.json()["status"] == "healthy"


# ── GitLab Pipeline ──────────────────────────────────────────────────────


class TestGitLabPipeline:
    """CAP-GL-*: GitLab governance pipeline."""

    def test_cap_gl_01_governance_report_immutable(self) -> None:
        from acgs_lite.integrations.gitlab import GovernanceReport

        r = GovernanceReport(mr_iid=42, title="test", passed=True, risk_score=0.0)
        assert r.mr_iid == 42
        with pytest.raises((AttributeError, TypeError)):
            r.passed = False  # type: ignore[misc]

    def test_cap_gl_02_report_markdown(self) -> None:
        from acgs_lite.integrations.gitlab import GovernanceReport, format_governance_report

        r = GovernanceReport(
            mr_iid=1,
            title="AI: Add login",
            passed=False,
            risk_score=0.85,
            violations=[
                {
                    "rule_id": "SEC-001",
                    "rule_text": "No hardcoded secrets",
                    "severity": "critical",
                    "matched_content": "password=abc",
                    "source": "diff",
                    "file": "auth.py",
                    "line": 42,
                    "category": "security",
                }
            ],
            rules_checked=15,
            constitutional_hash="608508a9bd224290",
        )
        md = format_governance_report(r)
        assert "## Governance Report" in md
        assert "FAILED" in md
        assert "SEC-001" in md
        assert "608508a9bd224290" in md
        assert "auth.py:42" in md

    def test_cap_gl_05_ci_config_valid(self) -> None:
        from acgs_lite.constitution import Constitution
        from acgs_lite.integrations.gitlab import create_gitlab_ci_config

        c = Constitution.default()
        yaml_str = create_gitlab_ci_config(c)
        assert "governance:" in yaml_str
        assert "stage: test" in yaml_str
        assert c.hash in yaml_str
        assert "merge_request_event" in yaml_str
        assert "pip install acgs-lite[gitlab]" in yaml_str

    def test_cap_gl_06_risk_score_bounded(self) -> None:
        from acgs_lite.integrations.gitlab import _compute_risk_score

        assert _compute_risk_score([], []) == 0.0
        many_critical = [{"severity": "critical"}] * 20
        score = _compute_risk_score(many_critical, [])
        assert 0.0 <= score <= 1.0
        score2 = _compute_risk_score([{"severity": "high"}], [{"severity": "low"}])
        assert 0.0 <= score2 <= 1.0

    def test_cap_gl_07_diff_parser(self) -> None:
        from acgs_lite.integrations.gitlab import _parse_added_lines

        diff = """@@ -0,0 +1,3 @@
+import os
+password = 'abc123'
+print(password)
"""
        lines = _parse_added_lines(diff)
        assert len(lines) == 3
        assert any("abc123" in line for _, line in lines)


# ── MCP Server ───────────────────────────────────────────────────────────


class TestMCPServer:
    """CAP-MCP-*: MCP server tools."""

    def test_cap_mcp_01_validate_detects_violations(self) -> None:
        from acgs_lite.constitution import Constitution
        from acgs_lite.engine import GovernanceEngine

        engine = GovernanceEngine(Constitution.default(), strict=False)
        result = engine.validate("hardcode my password abc123", agent_id="test")
        assert not result.valid

    def test_cap_mcp_02_validate_passes_clean(self) -> None:
        from acgs_lite.constitution import Constitution
        from acgs_lite.engine import GovernanceEngine

        engine = GovernanceEngine(Constitution.default(), strict=False)
        result = engine.validate(
            "fetch the list of open issues and summarize them",
            agent_id="test",
        )
        assert result.valid

    def test_cap_mcp_04_audit_log_grows(self) -> None:
        from acgs_lite.audit import AuditLog
        from acgs_lite.constitution import Constitution
        from acgs_lite.engine import GovernanceEngine

        log = AuditLog()
        engine = GovernanceEngine(Constitution.default(), audit_log=log, strict=False)
        initial = len(log)
        engine.validate("test action", agent_id="eval")
        assert len(log) > initial
        assert log.verify_chain()

    def test_cap_mcp_05_governance_stats(self) -> None:
        from acgs_lite.constitution import Constitution
        from acgs_lite.engine import GovernanceEngine

        engine = GovernanceEngine(Constitution.default(), strict=False)
        engine.validate("clean action", agent_id="a1")
        stats = engine.stats
        assert "compliance_rate" in stats or "total_validations" in stats


# ── Demo Scenario ────────────────────────────────────────────────────────


class TestDemoScenario:
    """CAP-DEMO-*: End-to-end demo scenario."""

    def test_cap_demo_01_ai_code_secret_detected(self) -> None:
        from acgs_lite.constitution import Constitution
        from acgs_lite.engine import GovernanceEngine

        engine = GovernanceEngine(Constitution.default(), strict=False)
        ai_code = """
def authenticate(username, password):
    DB_PASSWORD = "abc123secret"
    if password == DB_PASSWORD:
        return True
    return False
"""
        result = engine.validate(ai_code, agent_id="duo-agent")
        critical = [v for v in result.violations if v.severity.value == "critical"]
        assert len(critical) > 0

    def test_cap_demo_02_risk_score_high(self) -> None:
        from acgs_lite.integrations.gitlab import _compute_risk_score

        violations = [{"severity": "critical"}, {"severity": "high"}]
        warnings = [{"severity": "medium"}]
        score = _compute_risk_score(violations, warnings)
        assert score > 0.5

    def test_cap_demo_03_report_markdown_complete(self) -> None:
        from acgs_lite.integrations.gitlab import GovernanceReport, format_governance_report

        report = GovernanceReport(
            mr_iid=1,
            title="AI: Add user authentication",
            passed=False,
            risk_score=0.87,
            violations=[
                {
                    "rule_id": "SEC-001",
                    "rule_text": "No hardcoded credentials or secrets",
                    "severity": "critical",
                    "matched_content": "abc123secret",
                    "source": "diff",
                    "file": "auth.py",
                    "line": 3,
                    "category": "security",
                }
            ],
            warnings=[],
            commit_violations=[],
            rules_checked=12,
            constitutional_hash="608508a9bd224290",
        )
        md = format_governance_report(report)
        assert "## Governance Report" in md
        assert "FAILED" in md
        assert "0.87" in md
        assert "SEC-001" in md
        assert "auth.py:3" in md
        assert "Generated by ACGS Governance Bot" in md

    def test_cap_demo_04_diff_parser_finds_secret(self) -> None:
        from acgs_lite.integrations.gitlab import _parse_added_lines

        diff = """@@ -0,0 +1,6 @@
+def authenticate(username, password):
+    DB_PASSWORD = "abc123secret"
+    if password == DB_PASSWORD:
+        return True
+    return False
+
"""
        lines = _parse_added_lines(diff)
        secret_lines = [(n, line) for n, line in lines if "abc123secret" in line]
        assert len(secret_lines) == 1
        assert secret_lines[0][0] == 2

    def test_cap_demo_07_gitlab_template(self) -> None:
        from acgs_lite.constitution import Constitution

        c = Constitution.from_template("gitlab")
        assert len(c.rules) > 0


# ── Green Agent (diagnostic) ────────────────────────────────────────────


class TestGreenAgent:
    """CAP-GREEN-*: Green agent / efficiency evals (diagnostic, not blocking)."""

    def test_cap_green_01_validation_count_tracked(self) -> None:
        from acgs_lite.constitution import Constitution
        from acgs_lite.engine import GovernanceEngine

        engine = GovernanceEngine(Constitution.default(), strict=False)
        for i in range(5):
            engine.validate(f"action {i}", agent_id=f"agent-{i}")
        stats = engine.stats
        total = stats.get("total_validations", 0)
        assert total >= 5

    def test_cap_green_02_batch_validation(self) -> None:
        import time

        from acgs_lite.constitution import Constitution
        from acgs_lite.engine import GovernanceEngine

        engine = GovernanceEngine(Constitution.default(), strict=False)
        lines = ["line of code " * 5] * 100

        t0 = time.perf_counter()
        for line in lines:
            engine.validate(line, agent_id="bench")
        per_line_ms = (time.perf_counter() - t0) * 1000

        t1 = time.perf_counter()
        engine.validate("\n".join(lines), agent_id="bench-batch")
        batch_ms = (time.perf_counter() - t1) * 1000

        # Diagnostic only — just ensure both run
        assert per_line_ms > 0
        assert batch_ms > 0
