"""Tests for the OpenShell governance integration skeleton."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any, cast

import pytest
from fastapi.routing import APIRoute

from acgs_lite.integrations.openshell_governance import (
    ActionContext,
    ActionEnvelope,
    ActionPayloadSummary,
    ActionRequirements,
    ActionType,
    ActorRef,
    ActorRole,
    DecisionType,
    ExecutionOutcome,
    OperationType,
    OutcomeStatus,
    ResourceRef,
    RiskLevel,
    create_openshell_governance_app,
)

try:  # FastAPI >= 0.138 defers router inclusion behind lazy wrappers
    from fastapi.routing import iter_route_contexts as _iter_route_contexts
except ImportError:  # older FastAPI flattens included routes into app.routes
    _iter_route_contexts = None


def _iter_api_routes(app: Any) -> Iterator[Any]:
    """Yield API-route-like objects (with ``.path``/``.endpoint``) for ``app``.

    Works with both the legacy flattened ``app.routes`` layout and FastAPI 0.138+,
    which stores included routers as lazy ``_IncludedRouter`` wrappers.
    """
    if _iter_route_contexts is not None:
        for ctx in _iter_route_contexts(app.routes):
            if isinstance(ctx.original_route, APIRoute):
                yield ctx
    else:
        for route in app.routes:
            if isinstance(route, APIRoute):
                yield route


def _route_endpoint(app: Any, path: str) -> Callable[..., Any]:
    for route in _iter_api_routes(app):
        if route.path == path:
            return cast(Callable[..., Any], route.endpoint)
    raise AssertionError(f"Route {path!r} not found")


def _make_action(*, risk: RiskLevel, operation: OperationType) -> ActionEnvelope:
    return ActionEnvelope(
        action_type=ActionType.GITHUB_WRITE,
        operation=operation,
        risk_level=risk,
        actor=ActorRef(
            actor_id="agent/openclaw-primary",
            role=ActorRole.PROPOSER,
            display_name="OpenClaw Main Agent",
            sandbox_id="sandbox-demo",
        ),
        resource=ResourceRef(
            uri="github://repo/org/repo/issues",
            kind="github_repo",
            tenant_id="tenant-acme",
        ),
        context=ActionContext(
            request_id="req_123",
            session_id="sess_456",
            environment="prod",
        ),
        requirements=ActionRequirements(
            requires_network=True,
            requires_secret=True,
            mutates_state=True,
        ),
        payload=ActionPayloadSummary(
            payload_hash="sha256:abcd1234",
            summary="Create an issue for an incident follow-up.",
            content_type="application/json",
            size_bytes=256,
        ),
        tags=["incident", "repo-write"],
    )


@pytest.mark.unit
class TestOpenShellGovernanceIntegration:
    def test_app_registers_expected_routes(self) -> None:
        app = create_openshell_governance_app()
        paths = {route.path for route in _iter_api_routes(app)}
        assert "/governance/evaluate-action" in paths
        assert "/governance/submit-for-approval" in paths
        assert "/governance/review-approval" in paths
        assert "/governance/record-outcome" in paths
        assert "/governance/examples" in paths

    def test_openapi_includes_request_examples(self) -> None:
        app = create_openshell_governance_app()
        schema = app.openapi()
        request_body = schema["paths"]["/governance/evaluate-action"]["post"]["requestBody"]
        examples = request_body["content"]["application/json"]["examples"]
        assert "high_risk_github_write" in examples

    async def test_evaluate_action_escalates_high_risk_write(self) -> None:
        app = create_openshell_governance_app()
        evaluate = _route_endpoint(app, "/governance/evaluate-action")
        response = await evaluate(_make_action(risk=RiskLevel.HIGH, operation=OperationType.WRITE))
        assert response.decision == DecisionType.ESCALATE.value
        assert response.action_allowed is False
        assert response.required_role == ActorRole.VALIDATOR.value
        assert response.compliance.is_compliant is None
        assert response.constitutional_hash == "608508a9bd224290"

    async def test_evaluate_action_denies_proposer_self_approval_via_maci(self) -> None:
        app = create_openshell_governance_app()
        evaluate = _route_endpoint(app, "/governance/evaluate-action")
        action = _make_action(risk=RiskLevel.LOW, operation=OperationType.APPROVE)
        response = await evaluate(action)
        assert response.decision == DecisionType.DENY.value
        assert response.action_allowed is False
        assert "MACI_VIOLATION" in response.reason_codes
        assert response.compliance.is_compliant is False

    async def test_review_approval_uses_quorum_state_machine(self) -> None:
        from acgs_lite.integrations.openshell_governance import (
            ApprovalReviewRequest,
            ApprovalSubmission,
        )

        app = create_openshell_governance_app()
        evaluate = _route_endpoint(app, "/governance/evaluate-action")
        submit_for_approval = _route_endpoint(app, "/governance/submit-for-approval")
        review_approval = _route_endpoint(app, "/governance/review-approval")

        evaluated = await evaluate(_make_action(risk=RiskLevel.HIGH, operation=OperationType.WRITE))
        pending = await submit_for_approval(
            ApprovalSubmission(
                decision_id=evaluated.decision_id,
                submitted_by=ActorRef(
                    actor_id="agent/openclaw-primary",
                    role=ActorRole.PROPOSER,
                    display_name="OpenClaw Main Agent",
                ),
                note="Submit for validator review",
            )
        )
        assert pending.decision == DecisionType.ESCALATE.value

        reviewed = await review_approval(
            ApprovalReviewRequest(
                decision_id=evaluated.decision_id,
                reviewer=ActorRef(
                    actor_id="human/alice",
                    role=ActorRole.VALIDATOR,
                    display_name="Alice Validator",
                ),
                approve=True,
                note="Approved after review.",
            )
        )
        assert reviewed.updated_decision.decision == DecisionType.REQUIRE_SEPARATE_EXECUTOR.value
        assert reviewed.updated_decision.required_role == ActorRole.EXECUTOR.value

    async def test_review_approval_blocks_self_validation_via_maci(self) -> None:
        from acgs_lite.integrations.openshell_governance import (
            ApprovalReviewRequest,
            ApprovalSubmission,
        )

        app = create_openshell_governance_app()
        evaluate = _route_endpoint(app, "/governance/evaluate-action")
        submit_for_approval = _route_endpoint(app, "/governance/submit-for-approval")
        review_approval = _route_endpoint(app, "/governance/review-approval")

        evaluated = await evaluate(_make_action(risk=RiskLevel.HIGH, operation=OperationType.WRITE))
        await submit_for_approval(
            ApprovalSubmission(
                decision_id=evaluated.decision_id,
                submitted_by=ActorRef(
                    actor_id="agent/openclaw-primary",
                    role=ActorRole.PROPOSER,
                ),
            )
        )
        reviewed = await review_approval(
            ApprovalReviewRequest(
                decision_id=evaluated.decision_id,
                reviewer=ActorRef(
                    actor_id="agent/openclaw-primary",
                    role=ActorRole.VALIDATOR,
                ),
                approve=True,
            )
        )
        assert reviewed.updated_decision.decision == DecisionType.DENY.value
        assert "MACI_SELF_VALIDATION_FORBIDDEN" in reviewed.updated_decision.reason_codes

    def test_stable_openshell_exports_available_from_root_packages(self) -> None:
        import acgs
        import acgs_lite
        import acgs_lite.openshell as openshell

        assert callable(acgs.create_openshell_governance_app)
        assert callable(acgs_lite.create_openshell_governance_router)
        assert openshell.ActionEnvelope is not None

    async def test_evaluate_action_allows_low_risk_read(self) -> None:
        app = create_openshell_governance_app()
        evaluate = _route_endpoint(app, "/governance/evaluate-action")
        action = _make_action(risk=RiskLevel.LOW, operation=OperationType.READ)
        action.requirements = ActionRequirements(requires_network=True, mutates_state=False)
        response = await evaluate(action)
        assert response.decision == DecisionType.ALLOW.value
        assert response.action_allowed is True
        assert response.compliance.status == "compliant"
        assert response.compliance.is_compliant is True

    async def test_record_outcome_writes_real_audit_chain(self) -> None:
        app = create_openshell_governance_app()
        record_outcome = _route_endpoint(app, "/governance/record-outcome")
        get_audit_log = _route_endpoint(app, "/governance/audit-log")

        outcome = ExecutionOutcome(
            decision_id="dec_001",
            request_id="req_123",
            executor=ActorRef(
                actor_id="agent/executor-worker",
                role=ActorRole.EXECUTOR,
                display_name="Sandbox Executor",
                sandbox_id="sandbox-demo",
            ),
            outcome_status=OutcomeStatus.SUCCEEDED,
            result_hash="sha256:result123",
            summary="GitHub issue created successfully.",
            latency_ms=123,
        )

        event = await record_outcome(outcome)
        audit_log = await get_audit_log(limit=10)

        assert event.event_type == "execution"
        assert event.details["audit_chain_valid"] is True
        assert event.details["audit_chain_hash"]
        assert audit_log["entry_count"] == 1
        assert audit_log["chain_valid"] is True
        assert audit_log["entries"][0]["id"] == event.id
