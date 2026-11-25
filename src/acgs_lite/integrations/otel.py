"""ACGS-Lite OpenTelemetry + Prometheus Metrics Integration.

Exports governance metrics via the OpenTelemetry SDK and optionally exposes
a Prometheus scrape endpoint.  Wraps a :class:`GovernanceEngine` and
:class:`AuditLog` pair so every ``validate()`` call automatically records
counters, histograms, and gauges.

Usage::

    from acgs_lite import Constitution
    from acgs_lite.audit import AuditLog
    from acgs_lite.engine import GovernanceEngine
    from acgs_lite.integrations.otel import GovernanceMetrics

    constitution = Constitution.default()
    audit_log = AuditLog()
    engine = GovernanceEngine(constitution, audit_log=audit_log)

    metrics = GovernanceMetrics(engine, audit_log)
    result = metrics.validate("deploy to production", agent_id="ci-agent")

Prometheus endpoint::

    from acgs_lite.integrations.otel import create_prometheus_app

    app = create_prometheus_app()
    # Mount at /metrics in your ASGI server

ASGI middleware::

    from acgs_lite.integrations.otel import GovernanceMetricsMiddleware

    app = GovernanceMetricsMiddleware(app, metrics)

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from acgs_lite.audit import AuditLog
from acgs_lite.engine import GovernanceEngine

logger = logging.getLogger(__name__)

try:
    from opentelemetry import metrics as otel_metrics
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.trace import TracerProvider

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    otel_metrics = None  # type: ignore[assignment]
    otel_trace = None  # type: ignore[assignment]
    MeterProvider = None  # type: ignore[assignment,misc]
    TracerProvider = None  # type: ignore[assignment,misc]

try:
    from opentelemetry.exporter.prometheus import PrometheusMetricReader

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    PrometheusMetricReader = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Noop stubs used when OTel is not installed
# ---------------------------------------------------------------------------


class _NoopCounter:
    """Silently discards ``add()`` calls when OTel is unavailable."""

    def add(self, amount: int | float, attributes: dict[str, str] | None = None) -> None:  # noqa: ARG002
        pass


class _NoopHistogram:
    """Silently discards ``record()`` calls when OTel is unavailable."""

    def record(self, value: float, attributes: dict[str, str] | None = None) -> None:  # noqa: ARG002
        pass


class _NoopGauge:
    """Silently discards ``set()`` calls when OTel is unavailable."""

    def set(self, value: int | float, attributes: dict[str, str] | None = None) -> None:  # noqa: ARG002
        pass


class _NoopSpan:
    """Minimal noop span supporting the context-manager protocol."""

    def set_attribute(self, key: str, value: Any) -> None:  # noqa: ARG002
        pass

    def set_status(self, status: Any) -> None:  # noqa: ARG002
        pass

    def __enter__(self) -> _NoopSpan:
        return self

    def __exit__(self, *args: object) -> None:
        pass


class _NoopTracer:
    """Returns ``_NoopSpan`` for ``start_as_current_span()``."""

    def start_as_current_span(self, name: str, **kwargs: Any) -> _NoopSpan:  # noqa: ARG002
        return _NoopSpan()


_METER_NAME = "acgs_lite.governance"
_TRACER_NAME = "acgs_lite.governance"


# ---------------------------------------------------------------------------
# GovernanceMetrics
# ---------------------------------------------------------------------------


class GovernanceMetrics:
    """Instrument a :class:`GovernanceEngine` with OpenTelemetry metrics.

    Each call to :meth:`validate` delegates to the wrapped engine and
    records the following metrics:

    * ``acgs.validations.total`` -- Counter (labels: agent_id, decision)
    * ``acgs.validations.violations`` -- Counter (labels: agent_id, severity, rule_id)
    * ``acgs.validations.latency_ms`` -- Histogram (labels: agent_id)
    * ``acgs.compliance.score`` -- Gauge (labels: agent_id)
    * ``acgs.audit.chain_valid`` -- Gauge (labels: agent_id)
    * ``acgs.constitution.rules_count`` -- Gauge
    * ``acgs.constitution.hash`` -- attached as a resource attribute

    Args:
        engine: The governance engine to wrap.
        audit_log: The audit log used by *engine*.  Required for chain
            validity and compliance score gauges.
        meter_provider: Optional custom ``MeterProvider``.  When *None*
            the global provider is used (or noops if OTel is absent).
    """

    def __init__(
        self,
        engine: GovernanceEngine,
        audit_log: AuditLog,
        *,
        meter_provider: Any | None = None,
    ) -> None:
        self._engine = engine
        self._audit_log = audit_log
        self._validation_count = 0
        self._violation_count = 0
        self._last_latency_ms = 0.0
        self._counters_lock = threading.Lock()

        if OTEL_AVAILABLE:
            if meter_provider is not None:
                meter = meter_provider.get_meter(_METER_NAME)
            else:
                meter = otel_metrics.get_meter(_METER_NAME)

            self._validations_total = meter.create_counter(
                name="acgs.validations.total",
                description="Total governance validation calls",
                unit="1",
            )
            self._violations_total = meter.create_counter(
                name="acgs.validations.violations",
                description="Total constitutional violations detected",
                unit="1",
            )
            self._latency_histogram = meter.create_histogram(
                name="acgs.validations.latency_ms",
                description="Validation latency in milliseconds",
                unit="ms",
            )
            self._compliance_gauge = meter.create_gauge(
                name="acgs.compliance.score",
                description="Current compliance score 0-100",
                unit="1",
            )
            self._chain_valid_gauge = meter.create_gauge(
                name="acgs.audit.chain_valid",
                description="1 if audit chain intact, 0 if tampered",
                unit="1",
            )
            self._rules_count_gauge = meter.create_gauge(
                name="acgs.constitution.rules_count",
                description="Number of active constitutional rules",
                unit="1",
            )
        else:
            self._validations_total = _NoopCounter()  # type: ignore[assignment]
            self._violations_total = _NoopCounter()  # type: ignore[assignment]
            self._latency_histogram = _NoopHistogram()  # type: ignore[assignment]
            self._compliance_gauge = _NoopGauge()  # type: ignore[assignment]
            self._chain_valid_gauge = _NoopGauge()  # type: ignore[assignment]
            self._rules_count_gauge = _NoopGauge()  # type: ignore[assignment]

        # Emit initial rules-count gauge
        self._rules_count_gauge.set(
            len(engine.constitution.active_rules()),
        )

    # -- public API --------------------------------------------------------

    @property
    def engine(self) -> GovernanceEngine:
        """The wrapped governance engine."""
        return self._engine

    @property
    def audit_log(self) -> AuditLog:
        """The audit log instance."""
        return self._audit_log

    def validate(
        self,
        action: str,
        *,
        agent_id: str = "anonymous",
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Validate *action* and record OTel metrics.

        All parameters are forwarded to the underlying engine's
        :meth:`~GovernanceEngine.validate`.

        Returns:
            The :class:`ValidationResult` from the engine.  When the engine
            raises :class:`ConstitutionalViolationError` (strict mode), the
            exception is re-raised after recording metrics.
        """
        from acgs_lite.errors import ConstitutionalViolationError

        start = time.perf_counter()
        result = None
        raised = False
        try:
            result = self._engine.validate(action, agent_id=agent_id, context=context)
        except ConstitutionalViolationError:
            raised = True
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0

            with self._counters_lock:
                self._last_latency_ms = elapsed_ms
                self._validation_count += 1

                if result is not None:
                    for _v in result.violations:
                        self._violation_count += 1

            decision = "deny" if raised or (result is not None and not result.valid) else "allow"
            attrs = {"agent_id": agent_id, "decision": decision}

            self._validations_total.add(1, attributes=attrs)
            self._latency_histogram.record(elapsed_ms, attributes={"agent_id": agent_id})

            if result is not None:
                for v in result.violations:
                    self._violations_total.add(
                        1,
                        attributes={
                            "agent_id": agent_id,
                            "severity": v.severity.value,
                            "rule_id": v.rule_id,
                        },
                    )

            compliance_rate = self._audit_log.compliance_rate
            self._compliance_gauge.set(
                compliance_rate * 100.0,
                attributes={"agent_id": agent_id},
            )
            chain_valid = 1 if self._audit_log.verify_chain() else 0
            self._chain_valid_gauge.set(
                chain_valid,
                attributes={"agent_id": agent_id},
            )
            self._rules_count_gauge.set(
                len(self._engine.constitution.active_rules()),
            )

        return result

    @property
    def stats(self) -> dict[str, Any]:
        """Return metrics statistics."""
        with self._counters_lock:
            validation_count = self._validation_count
            violation_count = self._violation_count
            last_latency_ms = self._last_latency_ms
        return {
            **self._engine.stats,
            "otel_available": OTEL_AVAILABLE,
            "prometheus_available": PROMETHEUS_AVAILABLE,
            "validation_count": validation_count,
            "violation_count": violation_count,
            "last_latency_ms": last_latency_ms,
            "audit_chain_valid": self._audit_log.verify_chain(),
            "compliance_score": self._audit_log.compliance_rate * 100.0,
            "constitutional_hash": self._engine.constitution.hash,
        }


# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------


class GovernanceMetricsMiddleware:
    """ASGI middleware that adds OTel tracing spans for governance checks.

    Wraps every HTTP request with a span named ``acgs.governance.request``.
    Governance statistics are attached as span attributes.

    Args:
        app: The ASGI application to wrap.
        governance_metrics: A :class:`GovernanceMetrics` instance whose
            stats are recorded on each request span.
        tracer_provider: Optional custom ``TracerProvider``.
    """

    def __init__(
        self,
        app: Any,
        governance_metrics: GovernanceMetrics,
        *,
        tracer_provider: Any | None = None,
    ) -> None:
        self._app = app
        self._metrics = governance_metrics

        if OTEL_AVAILABLE and tracer_provider is not None:
            self._tracer = tracer_provider.get_tracer(_TRACER_NAME)
        elif OTEL_AVAILABLE:
            self._tracer = otel_trace.get_tracer(_TRACER_NAME)
        else:
            self._tracer = _NoopTracer()  # type: ignore[assignment]

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        """ASGI entry point."""
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        with self._tracer.start_as_current_span("acgs.governance.request") as span:
            stats = self._metrics.stats
            span.set_attribute("acgs.constitutional_hash", stats.get("constitutional_hash", ""))
            span.set_attribute("acgs.rules_count", stats.get("rules_count", 0))
            span.set_attribute("acgs.compliance_score", stats.get("compliance_score", 0.0))
            span.set_attribute(
                "acgs.audit_chain_valid",
                stats.get("audit_chain_valid", False),
            )

            await self._app(scope, receive, send)


# ---------------------------------------------------------------------------
# Prometheus endpoint factory
# ---------------------------------------------------------------------------


def create_prometheus_app(
    *,
    meter_provider: Any | None = None,
) -> Any:
    """Return a minimal ASGI application that serves ``/metrics``.

    The app renders Prometheus exposition format using
    ``opentelemetry-exporter-prometheus``.  If the exporter or
    ``prometheus_client`` is not installed a stub app returning
    ``503 Service Unavailable`` is returned instead.

    Args:
        meter_provider: Optional ``MeterProvider`` with a
            ``PrometheusMetricReader`` attached.  When *None* the global
            provider is used.

    Returns:
        An ASGI callable suitable for mounting at ``/metrics``.
    """
    if not OTEL_AVAILABLE or not PROMETHEUS_AVAILABLE:
        logger.warning(
            "OpenTelemetry or Prometheus exporter not installed; /metrics endpoint will return 503",
        )

        async def _unavailable(scope: dict[str, Any], receive: Any, send: Any) -> None:  # noqa: ARG001
            await send(
                {
                    "type": "http.response.start",
                    "status": 503,
                    "headers": [[b"content-type", b"text/plain"]],
                },
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b"OpenTelemetry metrics unavailable",
                },
            )

        return _unavailable

    try:
        from prometheus_client import generate_latest

        async def _metrics_app(scope: dict[str, Any], receive: Any, send: Any) -> None:  # noqa: ARG001
            body = generate_latest()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        [b"content-type", b"text/plain; version=0.0.4; charset=utf-8"],
                    ],
                },
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": body,
                },
            )

        return _metrics_app
    except ImportError:
        logger.warning("prometheus_client not installed; /metrics endpoint will return 503")

        async def _fallback(scope: dict[str, Any], receive: Any, send: Any) -> None:  # noqa: ARG001
            await send(
                {
                    "type": "http.response.start",
                    "status": 503,
                    "headers": [[b"content-type", b"text/plain"]],
                },
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b"prometheus_client not installed",
                },
            )

        return _fallback
