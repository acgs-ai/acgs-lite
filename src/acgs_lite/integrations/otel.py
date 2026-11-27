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
import math
import re
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from acgs_lite.audit import AuditLog
from acgs_lite.engine import GovernanceEngine

logger = logging.getLogger(__name__)

try:
    from opentelemetry import metrics as otel_metrics
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.trace import Status, StatusCode

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    otel_metrics = None  # type: ignore[assignment]
    otel_trace = None  # type: ignore[assignment]
    MeterProvider = None  # type: ignore[assignment,misc]
    TracerProvider = None  # type: ignore[assignment,misc]
    Status = None  # type: ignore[assignment,misc]
    StatusCode = None  # type: ignore[assignment,misc]

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


# ---------------------------------------------------------------------------
# Experimental OpenTelemetry GenAI semantic convention spans
# ---------------------------------------------------------------------------

GEN_AI_OPERATION_EXECUTE_TOOL = "execute_tool"
GEN_AI_SYSTEM_ACGS = "acgs-lite"
_GENAI_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_RESERVED_GENAI_PREFIXES = (
    "gen_ai.",
    "acgs.receipt.",
    "acgs.outcome.",
    "acgs.governance.",
    "acgs.provider.",
)

OtelAttributeValue = str | int | float | bool


def _extract_attr(obj: Any, key: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, Mapping):
        return obj.get(key)
    return getattr(obj, key, None)


def _nonempty_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _validate_extra_attributes(
    extra_attributes: Mapping[str, OtelAttributeValue] | None,
) -> dict[str, OtelAttributeValue]:
    if extra_attributes is None:
        return {}
    if not isinstance(extra_attributes, Mapping):
        raise TypeError("extra_attributes must be a mapping")
    validated: dict[str, OtelAttributeValue] = {}
    for key, val in extra_attributes.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("extra_attributes keys must be non-empty strings")
        if key.startswith(_RESERVED_GENAI_PREFIXES):
            raise ValueError(f"extra_attributes cannot override reserved attribute {key!r}")
        if isinstance(val, (bool, int)):
            validated[key] = val
        elif isinstance(val, float):
            if not math.isfinite(val):
                raise ValueError(f"extra_attributes[{key!r}] float must be finite")
            validated[key] = val
        elif isinstance(val, str):
            validated[key] = val
        else:
            raise TypeError(
                f"extra_attributes[{key!r}] must be str, int, float, or bool, "
                f"got {type(val).__name__}"
            )
    return validated


def _resolve_receipt_identity(receipt_obj: Any, r_hash: str) -> str | None:
    if _GENAI_HEX64_RE.fullmatch(r_hash) is None:
        return None
    if not isinstance(receipt_obj, Mapping):
        try:
            from acgs_lite.legitimacy.identity import receipt_identity

            return receipt_identity(receipt_obj)
        except (ImportError, TypeError, ValueError):
            return None
    schema_version = _extract_attr(receipt_obj, "schema_version")
    version = "v2" if schema_version == 2 else "v1"
    return f"acgs:receipt:{version}:sha256:{r_hash}"


def build_genai_governance_attributes(
    *,
    tool_name: str,
    signed_receipt: Any | None = None,
    signed_outcome: Any | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    system: str = GEN_AI_SYSTEM_ACGS,
    contract_class: str | None = None,
    decision_override: str | None = None,
    extra_attributes: Mapping[str, OtelAttributeValue] | None = None,
) -> dict[str, OtelAttributeValue]:
    """Build experimental OTel GenAI semantic convention attributes for a tool call.

    Captures only governance identities, decision/outcome states, key IDs, and
    contract metadata — never raw prompt text, arguments, or secrets.
    """
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool_name must be a non-empty string")
    if not isinstance(system, str) or not system.strip():
        raise ValueError("system must be a non-empty string")

    validated_extra = _validate_extra_attributes(extra_attributes)

    attrs: dict[str, OtelAttributeValue] = {
        "gen_ai.operation.name": GEN_AI_OPERATION_EXECUTE_TOOL,
        "gen_ai.system": system,
        "gen_ai.tool.name": tool_name,
    }
    if (clean_agent_id := _nonempty_str(agent_id)) is not None:
        attrs["gen_ai.agent.id"] = clean_agent_id
    if (clean_agent_name := _nonempty_str(agent_name)) is not None:
        attrs["gen_ai.agent.name"] = clean_agent_name

    if signed_receipt is not None:
        nested_receipt = _extract_attr(signed_receipt, "receipt")
        receipt_obj = nested_receipt if nested_receipt is not None else signed_receipt

        decision = _nonempty_str(_extract_attr(receipt_obj, "decision_type"))
        if decision is not None:
            attrs["acgs.governance.decision"] = decision

        r_hash = _nonempty_str(_extract_attr(receipt_obj, "receipt_hash"))
        if r_hash is not None:
            attrs["acgs.receipt.hash"] = r_hash
            r_id = _resolve_receipt_identity(receipt_obj, r_hash)
            if r_id is not None:
                attrs["acgs.receipt.identity"] = r_id

        key_id = _nonempty_str(_extract_attr(signed_receipt, "key_id"))
        if key_id is not None:
            attrs["acgs.receipt.key_id"] = key_id

        algorithm = _nonempty_str(_extract_attr(signed_receipt, "algorithm"))
        if algorithm is not None:
            attrs["acgs.receipt.algorithm"] = algorithm

        schema_version = _extract_attr(receipt_obj, "schema_version")
        if type(schema_version) is int:
            attrs["acgs.receipt.schema_version"] = schema_version

    if (clean_override := _nonempty_str(decision_override)) is not None:
        attrs["acgs.governance.decision"] = clean_override

    if signed_outcome is not None:
        nested_outcome = _extract_attr(signed_outcome, "receipt")
        outcome_obj = nested_outcome if nested_outcome is not None else signed_outcome

        outcome_val = _extract_attr(outcome_obj, "outcome")
        if outcome_val is not None:
            raw_outcome = getattr(outcome_val, "value", outcome_val)
            if isinstance(raw_outcome, str) and raw_outcome.strip():
                attrs["acgs.outcome.status"] = raw_outcome.strip().upper()

        effect_key = _nonempty_str(_extract_attr(outcome_obj, "effect_key"))
        if effect_key is not None:
            attrs["acgs.outcome.effect_key"] = effect_key

        provider_id = _nonempty_str(_extract_attr(outcome_obj, "provider_id"))
        if provider_id is not None:
            attrs["acgs.outcome.provider_id"] = provider_id

        contract_digest = _nonempty_str(_extract_attr(outcome_obj, "provider_contract_digest"))
        if contract_digest is not None:
            attrs["acgs.outcome.provider_contract_digest"] = contract_digest

    if (clean_contract_class := _nonempty_str(contract_class)) is not None:
        attrs["acgs.provider.contract_class"] = clean_contract_class

    attrs.update(validated_extra)
    return attrs


class _GovernedToolSpanHandle:
    """Mutable handle yielded by :meth:`GenAIGovernanceTracer.trace_governed_tool`."""

    def __init__(
        self,
        *,
        tool_name: str,
        agent_id: str | None,
        agent_name: str | None,
        system: str,
        contract_class: str | None,
        extra_attributes: Mapping[str, OtelAttributeValue] | None,
    ) -> None:
        self._tool_name = tool_name
        self._agent_id = agent_id
        self._agent_name = agent_name
        self._system = system
        self._contract_class = contract_class
        self._extra_attributes = extra_attributes
        self._signed_receipt: Any | None = None
        self._signed_outcome: Any | None = None
        self._decision_override: str | None = None

    def attach_decision(
        self,
        signed_receipt: Any | None = None,
        *,
        decision_override: str | None = None,
    ) -> None:
        """Bind a signed pre-execution decision receipt to the active span."""
        self._signed_receipt = signed_receipt
        if decision_override is not None:
            self._decision_override = decision_override

    def attach_outcome(self, signed_outcome: Any) -> None:
        """Bind a signed post-execution outcome receipt to the active span."""
        self._signed_outcome = signed_outcome

    @property
    def attributes(self) -> dict[str, OtelAttributeValue]:
        """Compute the current sanitized OTel GenAI + ACGS attribute snapshot."""
        return build_genai_governance_attributes(
            tool_name=self._tool_name,
            signed_receipt=self._signed_receipt,
            signed_outcome=self._signed_outcome,
            agent_id=self._agent_id,
            agent_name=self._agent_name,
            system=self._system,
            contract_class=self._contract_class,
            decision_override=self._decision_override,
            extra_attributes=self._extra_attributes,
        )


def _span_failure_reason(
    attrs: Mapping[str, OtelAttributeValue],
    exc: BaseException | None,
) -> str | None:
    if exc is not None:
        return type(exc).__name__
    decision = str(attrs.get("acgs.governance.decision", "")).upper()
    if decision.startswith(("DENY", "HARD_DENY")):
        return f"governance decision {decision}"
    outcome_status = str(attrs.get("acgs.outcome.status", "")).upper()
    if outcome_status == "NOT_DONE":
        return "effect outcome NOT_DONE"
    return None


def _apply_span_status(
    span: Any,
    attrs: Mapping[str, OtelAttributeValue],
    *,
    exc: BaseException | None = None,
) -> None:
    if not OTEL_AVAILABLE or Status is None or StatusCode is None:
        return
    reason = _span_failure_reason(attrs, exc)
    if reason is not None:
        span.set_status(Status(StatusCode.ERROR, reason))
    else:
        span.set_status(Status(StatusCode.OK))


class GenAIGovernanceTracer:
    """Emit experimental OpenTelemetry GenAI spans with ACGS receipt provenance."""

    def __init__(
        self,
        *,
        tracer_provider: Any | None = None,
        system: str = GEN_AI_SYSTEM_ACGS,
    ) -> None:
        if not isinstance(system, str) or not system.strip():
            raise ValueError("system must be a non-empty string")
        self._system = system
        if OTEL_AVAILABLE and tracer_provider is not None:
            self._tracer = tracer_provider.get_tracer(_TRACER_NAME)
        elif OTEL_AVAILABLE:
            self._tracer = otel_trace.get_tracer(_TRACER_NAME)
        else:
            self._tracer = _NoopTracer()  # type: ignore[assignment]

    def record_receipt_span(
        self,
        *,
        tool_name: str,
        signed_receipt: Any | None = None,
        signed_outcome: Any | None = None,
        agent_id: str | None = None,
        agent_name: str | None = None,
        contract_class: str | None = None,
        decision_override: str | None = None,
        extra_attributes: Mapping[str, OtelAttributeValue] | None = None,
    ) -> dict[str, OtelAttributeValue]:
        """Emit a single completed ``execute_tool <tool_name>`` span from receipts."""
        attrs = build_genai_governance_attributes(
            tool_name=tool_name,
            signed_receipt=signed_receipt,
            signed_outcome=signed_outcome,
            agent_id=agent_id,
            agent_name=agent_name,
            system=self._system,
            contract_class=contract_class,
            decision_override=decision_override,
            extra_attributes=extra_attributes,
        )
        span_name = f"{GEN_AI_OPERATION_EXECUTE_TOOL} {tool_name}"
        with self._tracer.start_as_current_span(
            span_name,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            for key, val in attrs.items():
                span.set_attribute(key, val)
            _apply_span_status(span, attrs)
        return attrs

    @contextmanager
    def trace_governed_tool(
        self,
        *,
        tool_name: str,
        agent_id: str | None = None,
        agent_name: str | None = None,
        contract_class: str | None = None,
        extra_attributes: Mapping[str, OtelAttributeValue] | None = None,
    ) -> Iterator[_GovernedToolSpanHandle]:
        """Wrap a governed tool execution in an ``execute_tool`` GenAI span."""
        handle = _GovernedToolSpanHandle(
            tool_name=tool_name,
            agent_id=agent_id,
            agent_name=agent_name,
            system=self._system,
            contract_class=contract_class,
            extra_attributes=extra_attributes,
        )
        # Validate inputs eagerly before entering span.
        initial_attrs = handle.attributes
        span_name = f"{GEN_AI_OPERATION_EXECUTE_TOOL} {tool_name}"
        caught: BaseException | None = None
        with self._tracer.start_as_current_span(
            span_name,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            for key, val in initial_attrs.items():
                span.set_attribute(key, val)
            try:
                yield handle
            except BaseException as exc:
                caught = exc
                raise
            finally:
                final_attrs = handle.attributes
                for key, val in final_attrs.items():
                    span.set_attribute(key, val)
                _apply_span_status(span, final_attrs, exc=caught)
