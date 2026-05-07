"""Integration tests verifying governance spans reach Phoenix via InMemorySpanExporter.

Each test exercises one scenario through ``governance_span()`` and asserts on
the resulting span's name, status, and attributes per GOVERNANCE_ATTRIBUTES.md.
The InMemorySpanExporter stands in for Phoenix's OTLP collector — it accepts
the same OTLP data Phoenix would receive, so attribute presence/values here
prove the same data would land in Phoenix.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import StatusCode

from acgs_lite import Constitution, GovernedCallable

# Ensure local example directory is importable for governance_span
sys.path.insert(0, str(Path(__file__).parent))

CONSTITUTION_YAML = Path(__file__).parent / "constitution.yaml"


@pytest.fixture
def exporter_and_tracer():
    """Install a fresh in-memory exporter and patch the governance_span tracer.

    OTel disallows overriding the global TracerProvider once set, so instead
    of replacing it we attach a fresh ``TracerProvider`` to the
    ``governance_span`` module's tracer. Each test gets a clean exporter
    instance so spans don't leak between tests.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    # Patch the module-level tracer used by governance_span() directly so it
    # routes spans to our private provider regardless of what the global
    # provider is.
    import governance_span as gs_mod

    original_tracer = gs_mod.tracer
    gs_mod.tracer = provider.get_tracer("acgs.governed_execution")
    try:
        yield exporter
    finally:
        gs_mod.tracer = original_tracer
        exporter.clear()


@pytest.fixture
def gc():
    """A fresh GovernedCallable per test, with a clean audit log."""
    constitution = Constitution.from_yaml(str(CONSTITUTION_YAML))
    return GovernedCallable(
        constitution=constitution, agent_id="test-agent", strict=True
    )


def _gov_spans(exporter):
    return [
        s for s in exporter.get_finished_spans() if s.name == "acgs.governed_execution"
    ]


# ---------------------------------------------------------------------------
# allow
# ---------------------------------------------------------------------------


def test_allow_span_outcome(exporter_and_tracer, gc):
    from governance_span import governance_span

    def safe_fn(prompt):
        return f"Response: {prompt}"

    wrapped = gc(safe_fn)

    with governance_span(gc, wrapped, "What is Paris?", scenario="allow") as (
        span,
        result,
        err,
    ):
        assert result is not None
        assert err is None

    spans = _gov_spans(exporter_and_tracer)
    assert len(spans) >= 1
    gov = spans[0]
    assert gov.attributes.get("governance.decision.outcome") == "allow"
    assert gov.status.status_code == StatusCode.OK
    assert gov.attributes.get("acgs.fail_closed") is True
    # Receipt should be present after a successful allow path
    assert "acgs.receipt.id" in gov.attributes
    assert gov.attributes.get("acgs.receipt.id")  # non-empty


# ---------------------------------------------------------------------------
# deny
# ---------------------------------------------------------------------------


def test_deny_span_outcome(exporter_and_tracer, gc):
    from governance_span import governance_span

    def pii_fn(prompt):
        return f"Echo: {prompt}"

    wrapped = gc(pii_fn)

    with governance_span(
        gc, wrapped, "My SSN is 123-45-6789", scenario="deny"
    ) as (span, result, err):
        assert result is None
        assert err is not None

    spans = _gov_spans(exporter_and_tracer)
    assert len(spans) >= 1
    gov = spans[0]
    assert gov.attributes.get("governance.decision.outcome") == "deny"
    assert gov.status.status_code == StatusCode.ERROR
    # The deny rule should be identified
    assert gov.attributes.get("governance.decision.rule_id") == "no-pii"


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------


def test_review_span_outcome(exporter_and_tracer, gc):
    from governance_span import governance_span

    def payment_fn(prompt):
        return f"Processing: {prompt}"

    wrapped = gc(payment_fn)

    with governance_span(
        gc, wrapped, "Please initiate payment / wire transfer $1000", scenario="review"
    ) as (span, result, err):
        assert result is None
        assert err is not None

    spans = _gov_spans(exporter_and_tracer)
    assert len(spans) >= 1
    gov = spans[0]
    assert gov.attributes.get("governance.decision.outcome") == "review"
    # Pending review is NOT an error — operator may approve later
    assert gov.status.status_code == StatusCode.OK
    assert gov.attributes.get("acgs.review.outcome") == "pending"
    assert gov.attributes.get("acgs.review.auto_approved") is False
    assert gov.attributes.get("governance.decision.rule_id") == "require-review"


# ---------------------------------------------------------------------------
# fail-closed
# ---------------------------------------------------------------------------


def test_fail_closed_span_outcome(exporter_and_tracer, gc):
    from governance_span import governance_span

    def fail_fn(prompt):
        raise RuntimeError("Tool execution failed")

    wrapped = gc(fail_fn)

    with pytest.raises(RuntimeError), governance_span(
        gc, wrapped, "trigger failure", scenario="fail-closed"
    ) as (span, result, err):
        # We expect the span body to yield with err set, then re-raise
        # on context-manager exit.
        assert result is None
        assert err is not None

    spans = _gov_spans(exporter_and_tracer)
    assert len(spans) >= 1
    gov = spans[0]
    assert gov.attributes.get("governance.decision.outcome") == "fail-closed"
    assert gov.status.status_code == StatusCode.ERROR


# ---------------------------------------------------------------------------
# receipt correlation — allow path always carries receipt
# ---------------------------------------------------------------------------


def test_receipt_id_present_on_allow(exporter_and_tracer, gc):
    from governance_span import governance_span

    def safe_fn(prompt):
        return "ok"

    wrapped = gc(safe_fn)

    with governance_span(gc, wrapped, "safe input", scenario="allow") as (
        span,
        result,
        err,
    ):
        assert err is None

    spans = _gov_spans(exporter_and_tracer)
    gov = spans[0]
    assert "acgs.receipt.id" in gov.attributes
    assert gov.attributes.get("acgs.receipt.id")
    assert "acgs.receipt.hash" in gov.attributes
    assert gov.attributes.get("acgs.receipt.hash")


def test_governance_attributes_namespace_separation(exporter_and_tracer, gc):
    """Generic governance.* attrs must be present even on allow path; vendor
    acgs.* attrs supplement them. Schema is GOVERNANCE_ATTRIBUTES.md."""
    from governance_span import governance_span

    def safe_fn(prompt):
        return "ok"

    wrapped = gc(safe_fn)
    with governance_span(gc, wrapped, "safe", scenario="allow"):
        pass

    spans = _gov_spans(exporter_and_tracer)
    gov = spans[0]
    # Generic namespace
    assert gov.attributes.get("governance.decision.outcome") == "allow"
    assert gov.attributes.get("governance.decision.version") == "1.0"
    assert gov.attributes.get("governance.decision.reason")
    # Vendor namespace
    assert gov.attributes.get("acgs.policy.version") == "1.0"
    assert gov.attributes.get("acgs.fail_closed") is True
