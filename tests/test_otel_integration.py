"""Tests for the OpenTelemetry + Prometheus metrics integration.

All OpenTelemetry SDK classes are mocked so the tests run without
installing ``opentelemetry-api``, ``opentelemetry-sdk``, or
``opentelemetry-exporter-prometheus``.
"""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.engine import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError

# Action text known to trigger a violation in the default constitution
_VIOLATING_ACTION = "Agent will self-validate its output"
_SAFE_ACTION = "hello world"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def constitution() -> Constitution:
    return Constitution.default()


@pytest.fixture()
def audit_log() -> AuditLog:
    return AuditLog()


@pytest.fixture()
def engine(constitution: Constitution, audit_log: AuditLog) -> GovernanceEngine:
    return GovernanceEngine(constitution, audit_log=audit_log, strict=False)


@pytest.fixture()
def strict_engine(constitution: Constitution, audit_log: AuditLog) -> GovernanceEngine:
    return GovernanceEngine(constitution, audit_log=audit_log, strict=True)


# ---------------------------------------------------------------------------
# Helper: build GovernanceMetrics with mocked OTel instruments
# ---------------------------------------------------------------------------


def _make_metrics(
    engine: GovernanceEngine,
    audit_log: AuditLog,
) -> tuple:
    """Instantiate GovernanceMetrics with a mock meter provider.

    Returns (GovernanceMetrics, mock_counter, mock_histogram, mock_gauge).
    """
    mock_meter = MagicMock()
    mock_counter = MagicMock()
    mock_histogram = MagicMock()
    mock_gauge = MagicMock()

    mock_meter.create_counter.return_value = mock_counter
    mock_meter.create_histogram.return_value = mock_histogram
    mock_meter.create_gauge.return_value = mock_gauge

    mock_provider = MagicMock()
    mock_provider.get_meter.return_value = mock_meter

    with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", True):
        from acgs_lite.integrations.otel import GovernanceMetrics

        gm = GovernanceMetrics(engine, audit_log, meter_provider=mock_provider)

    return gm, mock_counter, mock_histogram, mock_gauge


# ---------------------------------------------------------------------------
# GovernanceMetrics -- OTel available
# ---------------------------------------------------------------------------


class TestGovernanceMetricsWithOTel:
    """Tests when OTEL_AVAILABLE = True (mocked SDK)."""

    def test_validate_records_counter_allow(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        gm, mock_counter, _hist, _gauge = _make_metrics(engine, audit_log)

        result = gm.validate(_SAFE_ACTION, agent_id="test-agent")

        assert result.valid is True
        mock_counter.add.assert_any_call(
            1,
            attributes={"agent_id": "test-agent", "decision": "allow"},
        )

    def test_validate_records_counter_deny(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        gm, mock_counter, _hist, _gauge = _make_metrics(engine, audit_log)

        result = gm.validate(_VIOLATING_ACTION, agent_id="bad-agent")

        assert result.valid is False
        mock_counter.add.assert_any_call(
            1,
            attributes={"agent_id": "bad-agent", "decision": "deny"},
        )

    def test_validate_records_latency_histogram(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        gm, _counter, mock_histogram, _gauge = _make_metrics(engine, audit_log)

        gm.validate(_SAFE_ACTION, agent_id="agent-1")

        assert mock_histogram.record.call_count == 1
        call_args = mock_histogram.record.call_args
        latency_ms = call_args[0][0]
        assert latency_ms >= 0.0
        assert call_args[1]["attributes"] == {"agent_id": "agent-1"}

    def test_validate_records_violations_counter(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        gm, mock_counter, _hist, _gauge = _make_metrics(engine, audit_log)

        result = gm.validate(_VIOLATING_ACTION, agent_id="violator")

        assert result.valid is False
        violation_calls = [
            c for c in mock_counter.add.call_args_list if c[1].get("attributes", {}).get("severity")
        ]
        assert len(violation_calls) >= 1
        for call in violation_calls:
            attrs = call[1]["attributes"]
            assert "agent_id" in attrs
            assert "severity" in attrs
            assert "rule_id" in attrs

    def test_compliance_gauge_updates(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        gm, _counter, _hist, mock_gauge = _make_metrics(engine, audit_log)

        gm.validate(_SAFE_ACTION, agent_id="agent-a")

        compliance_calls = [
            c
            for c in mock_gauge.set.call_args_list
            if c[1].get("attributes", {}).get("agent_id") == "agent-a"
        ]
        # Should have compliance score and chain_valid gauge calls
        assert len(compliance_calls) >= 1

    def test_audit_chain_valid_gauge(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        gm, _counter, _hist, mock_gauge = _make_metrics(engine, audit_log)

        gm.validate(_SAFE_ACTION, agent_id="chain-check")

        # Find chain_valid gauge call -- it should be 1 (valid chain)
        all_set_calls = mock_gauge.set.call_args_list
        chain_calls = [
            c
            for c in all_set_calls
            if c[0][0] in (0, 1) and c[1].get("attributes", {}).get("agent_id") == "chain-check"
        ]
        assert len(chain_calls) >= 1
        # Fresh audit log chain should be valid
        chain_value = chain_calls[0][0][0]
        assert chain_value == 1

    def test_rules_count_gauge_set_on_init(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        _gm, _counter, _hist, mock_gauge = _make_metrics(engine, audit_log)

        # rules_count gauge is set during __init__
        init_calls = [c for c in mock_gauge.set.call_args_list if c[1].get("attributes") is None]
        assert len(init_calls) >= 1
        rules_count = init_calls[0][0][0]
        assert rules_count > 0

    def test_stats_property(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", True):
            gm, _counter, _hist, _gauge = _make_metrics(engine, audit_log)

            gm.validate(_SAFE_ACTION, agent_id="stats-agent")
            stats = gm.stats

        assert stats["otel_available"] is True
        assert stats["validation_count"] == 1
        assert stats["last_latency_ms"] >= 0.0
        assert stats["audit_chain_valid"] is True
        assert stats["compliance_score"] >= 0.0
        assert "constitutional_hash" in stats
        assert "rules_count" in stats

    def test_validate_increments_internal_counts(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        gm, _counter, _hist, _gauge = _make_metrics(engine, audit_log)

        gm.validate("action one", agent_id="a1")
        gm.validate("action two", agent_id="a2")

        assert gm.stats["validation_count"] == 2

    def test_engine_property(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        gm, *_ = _make_metrics(engine, audit_log)
        assert gm.engine is engine

    def test_audit_log_property(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        gm, *_ = _make_metrics(engine, audit_log)
        assert gm.audit_log is audit_log

    def test_violation_count_increments(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        gm, *_ = _make_metrics(engine, audit_log)

        gm.validate(_VIOLATING_ACTION, agent_id="viol")
        assert gm.stats["violation_count"] >= 1


# ---------------------------------------------------------------------------
# GovernanceMetrics -- OTel NOT available (fallback)
# ---------------------------------------------------------------------------


class TestGovernanceMetricsFallback:
    """Tests when OTEL_AVAILABLE = False (noop stubs)."""

    def test_validate_works_without_otel(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", False):
            from acgs_lite.integrations.otel import GovernanceMetrics

            gm = GovernanceMetrics(engine, audit_log)
            result = gm.validate(_SAFE_ACTION, agent_id="fallback-agent")

        assert result.valid is True

    def test_stats_reports_otel_unavailable(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", False):
            from acgs_lite.integrations.otel import GovernanceMetrics

            gm = GovernanceMetrics(engine, audit_log)
            gm.validate("test", agent_id="x")

        stats = gm.stats
        assert stats["validation_count"] == 1

    def test_noop_stubs_accept_calls(self) -> None:
        from acgs_lite.integrations.otel import _NoopCounter, _NoopGauge, _NoopHistogram

        counter = _NoopCounter()
        counter.add(1, attributes={"k": "v"})

        gauge = _NoopGauge()
        gauge.set(42, attributes={"k": "v"})

        hist = _NoopHistogram()
        hist.record(1.5, attributes={"k": "v"})

    def test_noop_span_context_manager(self) -> None:
        from acgs_lite.integrations.otel import _NoopSpan

        span = _NoopSpan()
        with span as s:
            s.set_attribute("key", "value")
            s.set_status("OK")
        # No error raised

    def test_noop_tracer_returns_noop_span(self) -> None:
        from acgs_lite.integrations.otel import _NoopSpan, _NoopTracer

        tracer = _NoopTracer()
        span = tracer.start_as_current_span("test-span")
        assert isinstance(span, _NoopSpan)

    def test_fallback_deny_still_records(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", False):
            from acgs_lite.integrations.otel import GovernanceMetrics

            gm = GovernanceMetrics(engine, audit_log)
            result = gm.validate(_VIOLATING_ACTION, agent_id="fb")

        assert result.valid is False
        assert gm.stats["validation_count"] == 1


# ---------------------------------------------------------------------------
# GovernanceMetrics -- strict mode (raises on violation)
# ---------------------------------------------------------------------------


class TestGovernanceMetricsStrictMode:
    """Verify metrics are recorded even when validate() raises."""

    def test_strict_violation_records_metrics_then_raises(
        self,
        strict_engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        mock_meter = MagicMock()
        mock_counter = MagicMock()
        mock_histogram = MagicMock()
        mock_gauge = MagicMock()
        mock_meter.create_counter.return_value = mock_counter
        mock_meter.create_histogram.return_value = mock_histogram
        mock_meter.create_gauge.return_value = mock_gauge

        mock_provider = MagicMock()
        mock_provider.get_meter.return_value = mock_meter

        with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", True):
            from acgs_lite.integrations.otel import GovernanceMetrics

            gm = GovernanceMetrics(strict_engine, audit_log, meter_provider=mock_provider)

        with pytest.raises(ConstitutionalViolationError):
            gm.validate(_VIOLATING_ACTION, agent_id="strict-bad")

        # Counter should still have recorded (deny decision)
        deny_calls = [
            c
            for c in mock_counter.add.call_args_list
            if c[1].get("attributes", {}).get("decision") == "deny"
        ]
        assert len(deny_calls) >= 1
        assert gm.stats["validation_count"] == 1


# ---------------------------------------------------------------------------
# GovernanceMetricsMiddleware
# ---------------------------------------------------------------------------


class TestGovernanceMetricsMiddleware:
    """Tests for the ASGI middleware."""

    @pytest.mark.asyncio()
    @pytest.mark.parametrize("otel_metrics", [None, MagicMock()], ids=["sdk-absent", "sdk-present"])
    async def test_middleware_adds_span_for_http(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
        otel_metrics: object,
    ) -> None:
        mock_tracer = MagicMock()
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer.start_as_current_span.return_value = mock_span

        mock_tracer_provider = MagicMock()
        mock_tracer_provider.get_tracer.return_value = mock_tracer

        with (
            patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", True),
            patch("acgs_lite.integrations.otel.otel_metrics", otel_metrics),
        ):
            from acgs_lite.integrations.otel import GovernanceMetricsMiddleware

            gm, *_ = _make_metrics(engine, audit_log)
            inner_app = AsyncMock()
            middleware = GovernanceMetricsMiddleware(
                inner_app,
                gm,
                tracer_provider=mock_tracer_provider,
            )

        scope = {"type": "http", "path": "/api/test"}
        receive = AsyncMock()
        send = AsyncMock()

        await middleware(scope, receive, send)

        mock_tracer.start_as_current_span.assert_called_once_with("acgs.governance.request")
        mock_span.set_attribute.assert_any_call(
            "acgs.constitutional_hash",
            engine.constitution.hash,
        )
        inner_app.assert_called_once_with(scope, receive, send)

    @pytest.mark.asyncio()
    async def test_middleware_skips_non_http(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", False):
            from acgs_lite.integrations.otel import (
                GovernanceMetrics,
                GovernanceMetricsMiddleware,
            )

            gm = GovernanceMetrics(engine, audit_log)
            inner_app = AsyncMock()
            middleware = GovernanceMetricsMiddleware(inner_app, gm)

        scope = {"type": "websocket"}
        receive = AsyncMock()
        send = AsyncMock()

        await middleware(scope, receive, send)

        inner_app.assert_called_once_with(scope, receive, send)

    def test_middleware_uses_noop_tracer_when_otel_unavailable(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
    ) -> None:
        with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", False):
            from acgs_lite.integrations.otel import (
                GovernanceMetrics,
                GovernanceMetricsMiddleware,
                _NoopTracer,
            )

            gm = GovernanceMetrics(engine, audit_log)
            inner_app = AsyncMock()
            middleware = GovernanceMetricsMiddleware(inner_app, gm)

        assert isinstance(middleware._tracer, _NoopTracer)

    @pytest.mark.asyncio()
    @pytest.mark.parametrize("otel_metrics", [None, MagicMock()], ids=["sdk-absent", "sdk-present"])
    async def test_middleware_attaches_compliance_score(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
        otel_metrics: object,
    ) -> None:
        mock_tracer = MagicMock()
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer.start_as_current_span.return_value = mock_span

        mock_tracer_provider = MagicMock()
        mock_tracer_provider.get_tracer.return_value = mock_tracer

        with (
            patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", True),
            patch("acgs_lite.integrations.otel.otel_metrics", otel_metrics),
        ):
            from acgs_lite.integrations.otel import GovernanceMetricsMiddleware

            gm, *_ = _make_metrics(engine, audit_log)
            inner_app = AsyncMock()
            middleware = GovernanceMetricsMiddleware(
                inner_app,
                gm,
                tracer_provider=mock_tracer_provider,
            )

        await middleware({"type": "http"}, AsyncMock(), AsyncMock())

        mock_span.set_attribute.assert_any_call(
            "acgs.compliance_score",
            gm.stats["compliance_score"],
        )


# ---------------------------------------------------------------------------
# create_prometheus_app
# ---------------------------------------------------------------------------


class TestCreatePrometheusApp:
    """Tests for the Prometheus endpoint factory."""

    @pytest.mark.asyncio()
    async def test_returns_503_when_otel_unavailable(self) -> None:
        with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", False):
            from acgs_lite.integrations.otel import create_prometheus_app

            app = create_prometheus_app()

        assert callable(app)

        send = AsyncMock()
        receive = AsyncMock()
        scope = {"type": "http"}

        await app(scope, receive, send)

        start_call = send.call_args_list[0]
        assert start_call[0][0]["status"] == 503

    @pytest.mark.asyncio()
    async def test_returns_503_when_prometheus_unavailable(self) -> None:
        with (
            patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", True),
            patch("acgs_lite.integrations.otel.PROMETHEUS_AVAILABLE", False),
        ):
            from acgs_lite.integrations.otel import create_prometheus_app

            app = create_prometheus_app()

        assert callable(app)

        send = AsyncMock()
        receive = AsyncMock()
        scope = {"type": "http"}

        await app(scope, receive, send)

        start_call = send.call_args_list[0]
        assert start_call[0][0]["status"] == 503

    @pytest.mark.asyncio()
    async def test_returns_metrics_app_when_available(self) -> None:
        mock_generate_latest = MagicMock(return_value=b"# HELP test\n")

        with (
            patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", True),
            patch("acgs_lite.integrations.otel.PROMETHEUS_AVAILABLE", True),
            patch.dict("sys.modules", {"prometheus_client": MagicMock()}),
        ):
            import sys

            sys.modules["prometheus_client"].generate_latest = mock_generate_latest

            from acgs_lite.integrations.otel import create_prometheus_app

            app = create_prometheus_app()

        assert callable(app)

        send = AsyncMock()
        receive = AsyncMock()
        scope = {"type": "http"}

        await app(scope, receive, send)

        start_call = send.call_args_list[0]
        assert start_call[0][0]["status"] == 200

        body_call = send.call_args_list[1]
        assert body_call[0][0]["body"] == b"# HELP test\n"

    def test_app_is_asgi_callable(self) -> None:
        with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", False):
            from acgs_lite.integrations.otel import create_prometheus_app

            app = create_prometheus_app()

        assert callable(app)
        assert inspect.iscoroutinefunction(app)

    @pytest.mark.asyncio()
    async def test_503_body_text(self) -> None:
        with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", False):
            from acgs_lite.integrations.otel import create_prometheus_app

            app = create_prometheus_app()

        send = AsyncMock()
        await app({"type": "http"}, AsyncMock(), send)

        body_call = send.call_args_list[1]
        assert b"unavailable" in body_call[0][0]["body"].lower()


# ---------------------------------------------------------------------------
# Module-level availability flags
# ---------------------------------------------------------------------------


class TestAvailabilityFlags:
    """Verify the import-guard behaviour."""

    def test_otel_available_is_bool(self) -> None:
        from acgs_lite.integrations.otel import OTEL_AVAILABLE

        assert isinstance(OTEL_AVAILABLE, bool)

    def test_prometheus_available_is_bool(self) -> None:
        from acgs_lite.integrations.otel import PROMETHEUS_AVAILABLE

        assert isinstance(PROMETHEUS_AVAILABLE, bool)
