"""FastAPI router exposing :class:`ConstitutionLifecycle` over HTTP.

All **mutation** endpoints require an ``X-API-Key`` header whose value is
compared with the server's configured key using :func:`hmac.compare_digest`
(constant-time) to prevent timing-oracle attacks.

Actor identity comes from the ``X-Actor-ID`` header, **not** from the
request body.  This prevents a proposer from crafting a request body
that sets a different ``approver_id`` to bypass the self-approval guard.

Phase C / Phase E gap
~~~~~~~~~~~~~~~~~~~~~
``GET /active/{tenant}`` returns ``engine_binding_active: false`` until the
caller wires a :class:`~acgs_lite.engine.bundle_binding.BundleAwareGovernanceEngine`
to the validation path.  The field makes the gap discoverable rather than
silent.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import os
from typing import Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from acgs_lite._compat import constant_time_compare
from acgs_lite.constitution.activation import ActivationRecord
from acgs_lite.constitution.bundle import ConstitutionBundle
from acgs_lite.constitution.bundle_store import InMemoryBundleStore
from acgs_lite.constitution.evidence import InMemoryLifecycleAuditSink
from acgs_lite.constitution.lifecycle_service import (
    ConcurrentLifecycleError,
    ConstitutionLifecycle,
    LifecycleError,
)
from acgs_lite.errors import MACIViolationError
from acgs_lite.evals.schema import EvalScenario

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_ACTOR_HEADER = "X-Actor-ID"


# ── Pydantic request models ──────────────────────────────────────────────


class DraftRequest(BaseModel):
    tenant_id: str = Field(..., max_length=256, description="Tenant that owns the draft")
    name: str = Field("", max_length=256, description="Human-readable name for the bundle")

    model_config = {"json_schema_extra": {"example": {"tenant_id": "acme", "name": "v2-rules"}}}


class SubmitRequest(BaseModel):
    pass


class EvalScenarioRequest(BaseModel):
    id: str = Field(..., description="Unique scenario identifier")
    input_action: str = Field(..., description="Action string to validate")
    context: dict[str, Any] | None = Field(default=None, description="Optional validation context")
    expected_valid: bool = Field(default=True, description="Expected validation outcome")


class EvalRequest(BaseModel):
    scenarios: list[EvalScenarioRequest] = Field(
        ..., description="Non-empty list of scenarios to run (empty list rejected by service layer)"
    )
    pass_threshold: float = Field(
        default=1.0, gt=0.0, le=1.0, description="Fraction of scenarios that must pass"
    )
    eval_run_id: str | None = Field(default=None, description="Optional explicit run ID")

    model_config = {
        "json_schema_extra": {
            "example": {
                "scenarios": [{"id": "s1", "input_action": "check status", "expected_valid": True}],
                "pass_threshold": 1.0,
            }
        }
    }


class ApproveRequest(BaseModel):
    signature: str = Field(..., min_length=1, description="Audit signature for the approval")

    model_config = {"json_schema_extra": {"example": {"signature": "sha256:abcdef"}}}


class StageRequest(BaseModel):
    pass


class ActivateRequest(BaseModel):
    pass


class RollbackRequest(BaseModel):
    reason: str = Field(default="operator rollback", description="Reason for rollback")


class WithdrawRequest(BaseModel):
    reason: str = Field(default="withdrawn by proposer", description="Reason for withdrawal")


class RejectRequest(BaseModel):
    reason: str = Field(default="rejected by validator", description="Reason for rejection")


# ── Error envelope ────────────────────────────────────────────────────────


def _error(message: str, *, code: str, bundle_id: str | None = None, status_code: int) -> NoReturn:
    raise HTTPException(
        status_code=status_code,
        detail={"error": message, "code": code, "bundle_id": bundle_id},
    )


def _bundle_response(bundle: ConstitutionBundle) -> dict[str, Any]:
    data = bundle.model_dump(mode="json")
    return data


def _activation_response(record: ActivationRecord) -> dict[str, Any]:
    return record.model_dump(mode="json")


# ── Router factory ────────────────────────────────────────────────────────


def create_lifecycle_router(
    lifecycle: ConstitutionLifecycle | None = None,
    *,
    api_key: str | None = None,
) -> APIRouter:
    """Return an :class:`APIRouter` that exposes the lifecycle HTTP surface.

    :param lifecycle: Pre-constructed :class:`ConstitutionLifecycle` instance.
        When *None*, an in-memory instance is created (useful for tests).
    :param api_key: Secret used to authenticate mutation requests via
        ``X-API-Key``.  Reads from the ``ACGS_LIFECYCLE_API_KEY`` environment
        variable when *None*.  If neither is provided, authentication is
        **disabled** — suitable only for tests, never for production.
    """
    _lc = lifecycle or ConstitutionLifecycle(
        store=InMemoryBundleStore(),
        sink=InMemoryLifecycleAuditSink(),
    )
    _key: str | None = api_key or os.getenv("ACGS_LIFECYCLE_API_KEY")
    router = APIRouter(prefix="/constitution/lifecycle", tags=["constitution-lifecycle"])

    # ── Auth dependency ────────────────────────────────────────────────

    async def _require_auth(x_api_key: str | None = Depends(_API_KEY_HEADER)) -> None:
        if _key is None:
            return  # Auth disabled (no key configured)
        if x_api_key is None or not constant_time_compare(x_api_key, _key):
            _error("Invalid or missing API key", code="AUTH_REQUIRED", status_code=401)

    async def _get_actor(request: Request) -> str:
        actor = request.headers.get(_ACTOR_HEADER, "")
        if not actor:
            _error(f"Missing {_ACTOR_HEADER} header", code="ACTOR_REQUIRED", status_code=400)
        if len(actor) > 256:
            _error(
                f"{_ACTOR_HEADER} value exceeds 256 characters",
                code="ACTOR_TOO_LONG",
                status_code=400,
            )
        return actor

    # ── Exception helpers ──────────────────────────────────────────────

    def _handle_lifecycle_exc(exc: Exception, bundle_id: str | None = None) -> NoReturn:
        if isinstance(exc, MACIViolationError):
            _error(str(exc), code="MACI_VIOLATION", bundle_id=bundle_id, status_code=403)
        if isinstance(exc, ConcurrentLifecycleError):
            _error(str(exc), code="CONCURRENT_CONFLICT", bundle_id=bundle_id, status_code=409)
        if isinstance(exc, LifecycleError):
            _error(str(exc), code="LIFECYCLE_ERROR", bundle_id=bundle_id, status_code=400)
        if isinstance(exc, ValueError):
            _error(str(exc), code="INVALID_TRANSITION", bundle_id=bundle_id, status_code=400)
        raise exc

    # ── Endpoints ──────────────────────────────────────────────────────

    @router.post("/draft", dependencies=[Depends(_require_auth)])
    async def create_draft(body: DraftRequest, request: Request) -> dict[str, Any]:
        """Create a new constitution bundle draft."""
        actor = await _get_actor(request)
        try:
            bundle = await _lc.create_draft(
                tenant_id=body.tenant_id,
                proposer_id=actor,
            )
        except Exception as exc:
            _handle_lifecycle_exc(exc)
        return _bundle_response(bundle)

    @router.post("/{bundle_id}/submit", dependencies=[Depends(_require_auth)])
    async def submit_for_review(bundle_id: str, request: Request) -> dict[str, Any]:
        """Submit a draft bundle for review (DRAFT → REVIEW)."""
        actor = await _get_actor(request)
        try:
            bundle = await _lc.submit_for_review(bundle_id, actor)
        except LookupError:
            _error(
                f"Bundle {bundle_id!r} not found",
                code="NOT_FOUND",
                bundle_id=bundle_id,
                status_code=404,
            )
        except Exception as exc:
            _handle_lifecycle_exc(exc, bundle_id)
        return _bundle_response(bundle)

    @router.post("/{bundle_id}/review", dependencies=[Depends(_require_auth)])
    async def approve_review(bundle_id: str, request: Request) -> dict[str, Any]:
        """Reviewer sign-off on a bundle in REVIEW state (REVIEW → EVAL)."""
        actor = await _get_actor(request)
        try:
            bundle = await _lc.approve_review(bundle_id, actor)
        except LookupError:
            _error(
                f"Bundle {bundle_id!r} not found",
                code="NOT_FOUND",
                bundle_id=bundle_id,
                status_code=404,
            )
        except Exception as exc:
            _handle_lifecycle_exc(exc, bundle_id)
        return _bundle_response(bundle)

    @router.post("/{bundle_id}/eval", dependencies=[Depends(_require_auth)])
    async def run_evaluation(bundle_id: str, body: EvalRequest) -> dict[str, Any]:
        """Run evaluation scenarios against a bundle in EVAL state."""
        scenarios = [
            EvalScenario(
                id=s.id,
                input_action=s.input_action,
                context=s.context or {},
                expected_valid=s.expected_valid,
            )
            for s in body.scenarios
        ]
        try:
            bundle = await _lc.run_evaluation(
                bundle_id,
                scenarios=scenarios,
                eval_run_id=body.eval_run_id,
                pass_threshold=body.pass_threshold,
            )
        except LookupError:
            _error(
                f"Bundle {bundle_id!r} not found",
                code="NOT_FOUND",
                bundle_id=bundle_id,
                status_code=404,
            )
        except Exception as exc:
            _handle_lifecycle_exc(exc, bundle_id)
        return _bundle_response(bundle)

    @router.post("/{bundle_id}/approve", dependencies=[Depends(_require_auth)])
    async def approve(bundle_id: str, body: ApproveRequest, request: Request) -> dict[str, Any]:
        """Final MACI approval (`eval` → `approve`). Actor from `X-Actor-ID`."""
        actor = await _get_actor(request)
        try:
            bundle = await _lc.approve(bundle_id, actor, signature=body.signature)
        except LookupError:
            _error(
                f"Bundle {bundle_id!r} not found",
                code="NOT_FOUND",
                bundle_id=bundle_id,
                status_code=404,
            )
        except Exception as exc:
            _handle_lifecycle_exc(exc, bundle_id)
        return _bundle_response(bundle)

    @router.post("/{bundle_id}/stage", dependencies=[Depends(_require_auth)])
    async def stage(bundle_id: str, request: Request) -> dict[str, Any]:
        """Stage an approved bundle for activation (`approve` → `staged`)."""
        executor_id = await _get_actor(request)
        try:
            bundle = await _lc.stage(bundle_id, executor_id)
        except LookupError:
            _error(
                f"Bundle {bundle_id!r} not found",
                code="NOT_FOUND",
                bundle_id=bundle_id,
                status_code=404,
            )
        except Exception as exc:
            _handle_lifecycle_exc(exc, bundle_id)
        return _bundle_response(bundle)

    @router.post("/{bundle_id}/activate", dependencies=[Depends(_require_auth)])
    async def activate(bundle_id: str, request: Request) -> dict[str, Any]:
        """Activate a staged bundle (STAGED → ACTIVE)."""
        executor_id = await _get_actor(request)
        try:
            activation = await _lc.activate(bundle_id, executor_id)
        except LookupError:
            _error(
                f"Bundle {bundle_id!r} not found",
                code="NOT_FOUND",
                bundle_id=bundle_id,
                status_code=404,
            )
        except Exception as exc:
            _handle_lifecycle_exc(exc, bundle_id)
        return _activation_response(activation)

    @router.post("/{bundle_id}/rollback", dependencies=[Depends(_require_auth)])
    async def rollback(bundle_id: str, body: RollbackRequest, request: Request) -> dict[str, Any]:
        """Roll back the active bundle to its predecessor."""
        executor_id = await _get_actor(request)
        try:
            activation = await _lc.rollback(bundle_id, executor_id, reason=body.reason)
        except LookupError:
            _error(
                f"Bundle {bundle_id!r} not found",
                code="NOT_FOUND",
                bundle_id=bundle_id,
                status_code=404,
            )
        except Exception as exc:
            _handle_lifecycle_exc(exc, bundle_id)
        return _activation_response(activation)

    @router.post("/{bundle_id}/reject", dependencies=[Depends(_require_auth)])
    async def reject(bundle_id: str, body: RejectRequest, request: Request) -> dict[str, Any]:
        """Reject a bundle (VALIDATOR role). Any pre-active state → REJECTED."""
        actor = await _get_actor(request)
        try:
            bundle = await _lc.reject(bundle_id, actor, reason=body.reason)
        except LookupError:
            _error(
                f"Bundle {bundle_id!r} not found",
                code="NOT_FOUND",
                bundle_id=bundle_id,
                status_code=404,
            )
        except Exception as exc:
            _handle_lifecycle_exc(exc, bundle_id)
        return _bundle_response(bundle)

    @router.post("/{bundle_id}/withdraw", dependencies=[Depends(_require_auth)])
    async def withdraw(bundle_id: str, body: WithdrawRequest, request: Request) -> dict[str, Any]:
        """Withdraw a bundle before activation."""
        actor = await _get_actor(request)
        try:
            bundle = await _lc.withdraw(bundle_id, actor, reason=body.reason)
        except LookupError:
            _error(
                f"Bundle {bundle_id!r} not found",
                code="NOT_FOUND",
                bundle_id=bundle_id,
                status_code=404,
            )
        except Exception as exc:
            _handle_lifecycle_exc(exc, bundle_id)
        return _bundle_response(bundle)

    @router.get("/{bundle_id}", dependencies=[Depends(_require_auth)])
    async def get_bundle(bundle_id: str) -> dict[str, Any]:
        """Retrieve a bundle by ID."""
        bundle = await _lc.get_bundle(bundle_id)
        if bundle is None:
            _error(
                f"Bundle {bundle_id!r} not found",
                code="NOT_FOUND",
                bundle_id=bundle_id,
                status_code=404,
            )
        return _bundle_response(bundle)

    @router.get("/active/{tenant_id}", dependencies=[Depends(_require_auth)])
    async def get_active_bundle(tenant_id: str) -> dict[str, Any]:
        """Retrieve the active bundle for a tenant.

        The ``engine_binding_active`` field indicates whether a
        :class:`~acgs_lite.engine.bundle_binding.BundleAwareGovernanceEngine`
        is wired into the validation path.  It is always ``false`` here because
        this router does not manage the engine binding — wire Phase E for that.
        """
        bundle = await _lc.get_active_bundle(tenant_id)
        if bundle is None:
            _error(
                f"No active bundle for tenant {tenant_id!r}",
                code="NOT_FOUND",
                status_code=404,
            )
        data = _bundle_response(bundle)
        data["engine_binding_active"] = False
        data["engine_binding_note"] = (
            "Activation is recorded. Engine binding requires "
            "BundleAwareGovernanceEngine — see Phase E / bundle_binding.py."
        )
        return data

    @router.get("/history/{tenant_id}", dependencies=[Depends(_require_auth)])
    async def get_bundle_history(tenant_id: str) -> list[dict[str, Any]]:
        """List all bundles for a tenant in chronological order."""
        bundles = await _lc.get_bundle_history(tenant_id)
        return [_bundle_response(b) for b in bundles]

    return router
