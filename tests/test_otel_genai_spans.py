"""Tests for experimental OpenTelemetry GenAI semantic convention spans in otel.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from acgs_lite.integrations.otel import (
    GEN_AI_OPERATION_EXECUTE_TOOL,
    GEN_AI_SYSTEM_ACGS,
    GenAIGovernanceTracer,
    build_genai_governance_attributes,
)
from acgs_lite.legitimacy import (
    DecisionReceipt,
    Ed25519ReceiptSigner,
    EffectOutcome,
    ExecutionBoundary,
    OutcomeReceipt,
    receipt_identity,
    sign_outcome,
    sign_receipt,
)


def _sample_receipt(
    signer: Ed25519ReceiptSigner,
    *,
    decision_type: str = "ALLOW",
) -> tuple[DecisionReceipt, object]:
    boundary = ExecutionBoundary(
        allowed_method="issue_refund",
        allowed_scope="secret-should-not-leak-in-span",
        allowed_subjects=("acct_1",),
        expires_at="2026-12-31T00:00:00Z",
        single_use=True,
    )
    receipt = DecisionReceipt.create(
        request_id="req-otel-1",
        goal="secret-prompt-text-must-not-leak",
        proposed_method="issue_refund",
        decision_type=decision_type,
        authority_basis="constitution:default",
        matched_constraints=("R-1",),
        policy_version="1.0.0",
        denial_or_review_rationale="sensitive" if decision_type != "ALLOW" else None,
        execution_boundary=boundary,
        issued_at="2026-11-27T12:00:00+00:00",
        schema_version=2,
        grant_id="grant-otel-1",
        policy_digest="d" * 64,
        method_id="issue_refund",
        argument_digest="e" * 64,
    )
    return receipt, sign_receipt(receipt, signer, signed_at="2026-11-27T12:00:00+00:00")


def _sample_outcome(
    signer: Ed25519ReceiptSigner,
    decision_receipt: DecisionReceipt,
    *,
    outcome: EffectOutcome = EffectOutcome.DONE,
) -> object:
    rec = OutcomeReceipt(
        effect_key="acgs:effect:v1:" + "b" * 64,
        provider_id="stripe-sandbox",
        provider_contract_digest="c" * 64,
        decision_receipt_identity=receipt_identity(decision_receipt),
        grant_identity="grant-otel-1",
        outcome=outcome,
        recorded_at="2026-11-27T12:00:01+00:00",
        provider_reference="pi_secret_ref",
    )
    return sign_outcome(rec, signer)


def test_build_genai_attributes_from_signed_receipt_and_outcome() -> None:
    pytest.importorskip("cryptography")
    signer = Ed25519ReceiptSigner.from_seed(b"\x77" * 32, key_id="otel-key-1")
    raw_receipt, signed_receipt = _sample_receipt(signer, decision_type="ALLOW")
    signed_outcome = _sample_outcome(signer, raw_receipt, outcome=EffectOutcome.DONE)

    attrs = build_genai_governance_attributes(
        tool_name="issue_refund",
        signed_receipt=signed_receipt,
        signed_outcome=signed_outcome,
        agent_id="agent-7",
        agent_name="refund-bot",
        contract_class="FENCEABLE",
        extra_attributes={"acgs.custom.tenant_tier": "growth", "acgs.custom.dry_run": False},
    )

    assert attrs["gen_ai.operation.name"] == GEN_AI_OPERATION_EXECUTE_TOOL
    assert attrs["gen_ai.system"] == GEN_AI_SYSTEM_ACGS
    assert attrs["gen_ai.tool.name"] == "issue_refund"
    assert attrs["gen_ai.agent.id"] == "agent-7"
    assert attrs["gen_ai.agent.name"] == "refund-bot"
    assert attrs["acgs.governance.decision"] == "ALLOW"
    assert attrs["acgs.receipt.hash"] == raw_receipt.receipt_hash
    assert attrs["acgs.receipt.identity"] == receipt_identity(raw_receipt)
    assert attrs["acgs.receipt.key_id"] == "otel-key-1"
    assert attrs["acgs.receipt.algorithm"] == "ed25519"
    assert attrs["acgs.receipt.schema_version"] == 2
    assert attrs["acgs.outcome.status"] == "DONE"
    assert attrs["acgs.outcome.effect_key"] == "acgs:effect:v1:" + "b" * 64
    assert attrs["acgs.outcome.provider_id"] == "stripe-sandbox"
    assert attrs["acgs.outcome.provider_contract_digest"] == "c" * 64
    assert attrs["acgs.provider.contract_class"] == "FENCEABLE"
    assert attrs["acgs.custom.tenant_tier"] == "growth"
    assert attrs["acgs.custom.dry_run"] is False

    # Privacy invariant: raw prompt/scope/provider_reference strings must never appear
    rendered = repr(attrs)
    assert "secret-prompt-text-must-not-leak" not in rendered
    assert "secret-should-not-leak-in-span" not in rendered
    assert "pi_secret_ref" not in rendered

    # Dict-projected receipts work symmetrically
    dict_attrs = build_genai_governance_attributes(
        tool_name="issue_refund",
        signed_receipt=signed_receipt.to_dict(),  # type: ignore[attr-defined]
        signed_outcome=signed_outcome.to_dict(),  # type: ignore[attr-defined]
    )
    assert dict_attrs["acgs.receipt.identity"] == receipt_identity(raw_receipt)
    assert dict_attrs["acgs.outcome.status"] == "DONE"


def test_build_genai_attributes_validation() -> None:
    with pytest.raises(ValueError, match="tool_name"):
        build_genai_governance_attributes(tool_name="   ")

    with pytest.raises(ValueError, match="reserved attribute"):
        build_genai_governance_attributes(
            tool_name="issue_refund",
            extra_attributes={"gen_ai.tool.name": "hijack"},
        )

    with pytest.raises(TypeError, match="str, int, float, or bool"):
        build_genai_governance_attributes(
            tool_name="issue_refund",
            extra_attributes={"bad.list": [1, 2]},  # type: ignore[dict-item]
        )


def test_genai_tracer_records_ok_and_error_spans_with_mock_provider() -> None:
    pytest.importorskip("cryptography")
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry.trace import StatusCode

    signer = Ed25519ReceiptSigner.from_seed(b"\x88" * 32, key_id="otel-key-2")
    raw_allow, signed_allow = _sample_receipt(signer, decision_type="ALLOW")
    signed_not_done = _sample_outcome(signer, raw_allow, outcome=EffectOutcome.NOT_DONE)

    mock_span = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value = mock_span
    mock_ctx.__exit__.return_value = None
    mock_tracer = MagicMock()
    mock_tracer.start_as_current_span.return_value = mock_ctx
    mock_provider = MagicMock()
    mock_provider.get_tracer.return_value = mock_tracer

    with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", True):
        tracer = GenAIGovernanceTracer(tracer_provider=mock_provider)
        attrs = tracer.record_receipt_span(
            tool_name="issue_refund",
            signed_receipt=signed_allow,
            contract_class="FENCEABLE",
        )
        assert attrs["gen_ai.tool.name"] == "issue_refund"
        mock_tracer.start_as_current_span.assert_called_with(
            "execute_tool issue_refund",
            record_exception=False,
            set_status_on_exception=False,
        )
        mock_span.set_attribute.assert_any_call("acgs.governance.decision", "ALLOW")
        status_ok = mock_span.set_status.call_args.args[0]
        assert status_ok.status_code is StatusCode.OK

        # NOT_DONE outcome marks span as ERROR
        tracer.record_receipt_span(
            tool_name="issue_refund",
            signed_receipt=signed_allow,
            signed_outcome=signed_not_done,
        )
        status_err = mock_span.set_status.call_args.args[0]
        assert status_err.status_code is StatusCode.ERROR

        # Context manager attaches decision + outcome lazily and marks exception as ERROR
        with tracer.trace_governed_tool(
            tool_name="issue_refund", agent_id="agent-1"
        ) as span_handle:
            span_handle.attach_decision(signed_allow)
            span_handle.attach_outcome(
                _sample_outcome(signer, raw_allow, outcome=EffectOutcome.DONE)
            )
        assert mock_span.set_status.call_args.args[0].status_code is StatusCode.OK

        def _raise_boom() -> None:
            raise RuntimeError("boom")

        with (
            pytest.raises(RuntimeError, match="boom"),
            tracer.trace_governed_tool(tool_name="issue_refund") as _h,
        ):
            _raise_boom()
        assert mock_span.set_status.call_args_list[-1].args[0].status_code is StatusCode.ERROR


def test_genai_tracer_real_sdk_does_not_leak_exception_secrets() -> None:
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.trace import StatusCode

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = GenAIGovernanceTracer(tracer_provider=provider)

    def _fail_with_secret() -> None:
        raise RuntimeError("raw args: card=secret-123")

    with (
        pytest.raises(RuntimeError, match="card=secret-123"),
        tracer.trace_governed_tool(tool_name="charge_card", agent_id="agent-9"),
    ):
        _fail_with_secret()

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.status.status_code is StatusCode.ERROR
    assert span.status.description == "RuntimeError"
    assert span.events == ()
    assert "secret-123" not in repr(span.attributes)
    assert "secret-123" not in (span.status.description or "")


def test_genai_tracer_noop_fallback_when_otel_unavailable() -> None:
    with patch("acgs_lite.integrations.otel.OTEL_AVAILABLE", False):
        tracer = GenAIGovernanceTracer()
        attrs = tracer.record_receipt_span(tool_name="ping", decision_override="DENY_GOAL")
        assert attrs["acgs.governance.decision"] == "DENY_GOAL"
        with tracer.trace_governed_tool(tool_name="ping") as handle:
            handle.attach_decision(decision_override="ALLOW")
            assert handle.attributes["acgs.governance.decision"] == "ALLOW"
