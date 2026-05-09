# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""FastAPI microservice wrapper for GovernanceEngine."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
from collections.abc import AsyncGenerator
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

from acgs_lite._meta import VERSION
from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.cdp.store import InMemoryCDPBackend
from acgs_lite.constitution import Constitution
from acgs_lite.engine import GovernanceEngine
from acgs_lite.events import GovernanceEvent, get_event_bus
from acgs_lite.federation import federation_router
from acgs_lite.integrations.github_merge_queue import (
    MergeGroupReceiptRequest,
    build_receipt_outcome,
)
from acgs_lite.integrations.openshell_governance import (
    GovernanceStateBackend,
    GovernanceStateObservabilityHook,
    JsonFileGovernanceStateBackend,
    create_openshell_governance_router,
)
from acgs_lite.integrations.telegram_webhook import create_telegram_webhook_router

logger = logging.getLogger(__name__)

# Module-level CDP backend (shared across requests, replaceable for testing)
_cdp_backend: InMemoryCDPBackend = InMemoryCDPBackend()

if TYPE_CHECKING:
    from fastapi import FastAPI


class _AuditStoreLike(Protocol):
    def append(self, entry: AuditEntry) -> str: ...

    def get(self, entry_id: str) -> AuditEntry | None: ...

    def list_entries(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        agent_id: str | None = None,
    ) -> list[AuditEntry]: ...

    def count(self) -> int: ...

    def verify_chain(self) -> bool: ...


class _AuditStoreAdapter:
    """Present an AuditStore through the AuditLog interface expected by the engine."""

    def __init__(self, store: _AuditStoreLike) -> None:
        self._store = store

    @property
    def entries(self) -> list[AuditEntry]:
        total = self._store.count()
        return self._store.list_entries(limit=total if total > 0 else 1, offset=0)

    def record(self, entry: AuditEntry) -> str:
        return self._store.append(entry)

    def verify_chain(self) -> bool:
        return self._store.verify_chain()

    def __len__(self) -> int:
        return self._store.count()


def _env_flag(name: str) -> bool:
    value = os.getenv(name, "")
    return value.lower() in {"1", "true", "yes", "on"}


def _build_default_audit_store(path: str | Path) -> _AuditStoreLike | None:
    """Build an audit store from the optional external compatibility package."""
    try:
        module = import_module("acgs.audit_sqlite")
    except ImportError:
        return None

    store_cls = getattr(module, "SQLiteAuditStore", None)
    if store_cls is None:
        return None
    return cast(_AuditStoreLike, store_cls(path))


def create_governance_app(
    constitution: Constitution | None = None,
    *,
    audit_store: _AuditStoreLike | None = None,
    audit_db_path: str | Path = "acgs_audit.db",
    include_openshell_governance: bool = True,
    include_openshell_experimental: bool | None = None,
    openshell_observability_hook: GovernanceStateObservabilityHook | None = None,
    enable_external_acgs_audit_store: bool = False,
    openshell_state_backend: GovernanceStateBackend | None = None,
    openshell_state_path: str | Path | None = None,
    include_autonoma: bool = False,
    autonoma_scenarios_path: str | Path | None = None,
    include_lifecycle: bool | None = None,
    lifecycle_api_key: str | None = None,
    include_telegram: bool = False,
    telegram_webhook_path_secret: str | None = None,
    telegram_secret_token: str | None = None,
    api_key: str | None = None,
    require_auth: bool | None = True,
) -> FastAPI:
    """Create a FastAPI app exposing governance validation endpoints.

    Authentication
    --------------
    Set ``api_key`` (or the ``ACGS_API_KEY`` environment variable) to require
    an ``X-API-Key`` header on all mutating endpoints (``POST /validate``,
    ``POST/PUT/DELETE /rules``) and on audit / CDP read endpoints.  ``/health``
    is always public.

    ``require_auth`` controls behaviour when no key is configured:

    * ``True`` (default, since v2.10.0): refuse to start without ``api_key``
      / ``ACGS_API_KEY``.  Fail closed is the default to protect production
      deployments.
    * ``None``: log a loud startup warning but leave the app open.  This was
      the v2.9.x default; kept for explicit opt-in back-compat.
    * ``False``: silently allow unauthenticated access (opt-in insecure mode
      for local development).

    When ``include_openshell_governance`` is true, the app also mounts the
    stable OpenShell/OpenClaw governance router under ``/governance``.

    When ``audit_store`` is omitted, the server uses the legacy in-memory
    ``AuditLog`` by default.

    Set ``enable_external_acgs_audit_store=True`` to opt into trying the
    compatibility-layer store ``acgs.audit_sqlite.SQLiteAuditStore(audit_db_path)``
    when the external ``acgs`` package is installed.

    ``include_openshell_experimental`` is kept as a compatibility alias.

    Set ``include_lifecycle=True`` (or set the ``ACGS_LIFECYCLE_ENABLED``
    environment variable) to mount the constitution lifecycle router at
    ``/constitution/lifecycle/*``.  Use ``lifecycle_api_key`` (or
    ``ACGS_LIFECYCLE_API_KEY``) to require API-key authentication on mutation
    endpoints.

    Set ``include_telegram=True`` to mount a Telegram webhook endpoint at
    ``/telegram/webhook/{telegram_webhook_path_secret}``. Use
    ``telegram_secret_token`` to additionally enforce Telegram's
    ``X-Telegram-Bot-Api-Secret-Token`` header.
    """
    from fastapi import Depends, FastAPI, Header, HTTPException, Query

    resolved_api_key = api_key if api_key is not None else os.getenv("ACGS_API_KEY")
    if require_auth is True and not resolved_api_key:
        raise ValueError(
            "require_auth=True but no api_key / ACGS_API_KEY configured. "
            "Set api_key=... or ACGS_API_KEY env var, or pass require_auth=False "
            "to explicitly run unauthenticated (not recommended for production)."
        )
    if not resolved_api_key and require_auth is not False:
        logger.warning(
            "acgs-lite governance app is starting WITHOUT API-key authentication. "
            "All endpoints are publicly reachable. Set api_key=... or "
            "ACGS_API_KEY=... to protect /validate, /rules/*, /audit/*, /cdp/*. "
            "Pass require_auth=False to silence this warning, or require_auth=True "
            "to fail closed (default since v2.10.0)."
        )

    def _require_api_key(x_api_key: str | None = Header(default=None)) -> None:
        if not resolved_api_key:
            return
        if x_api_key is None or not secrets.compare_digest(x_api_key, resolved_api_key):
            raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")

    auth_deps = [Depends(_require_api_key)] if resolved_api_key else []

    gov_constitution = constitution if constitution is not None else Constitution.default()
    resolved_audit_store = audit_store
    if resolved_audit_store is None and enable_external_acgs_audit_store:
        resolved_audit_store = _build_default_audit_store(audit_db_path)
    audit_log: AuditLog | _AuditStoreAdapter
    if resolved_audit_store is None:
        audit_log = AuditLog()
    else:
        audit_log = _AuditStoreAdapter(resolved_audit_store)
    engine = GovernanceEngine(
        gov_constitution,
        audit_log=cast(Any, audit_log),
        strict=False,
        audit_mode="full",
    )
    app = FastAPI(title="acgs-lite-governance", version=VERSION)

    def _list_audit_entries(
        *,
        limit: int,
        offset: int,
        agent_id: str | None,
    ) -> list[AuditEntry]:
        if resolved_audit_store is not None:
            return resolved_audit_store.list_entries(limit=limit, offset=offset, agent_id=agent_id)

        entries = audit_log.entries
        if agent_id is not None:
            entries = [entry for entry in entries if entry.agent_id == agent_id]
        return entries[offset : offset + limit]

    def _audit_count() -> int:
        if resolved_audit_store is not None:
            return resolved_audit_store.count()
        return len(audit_log)

    def _audit_chain_valid() -> bool:
        if resolved_audit_store is not None:
            return resolved_audit_store.verify_chain()
        return audit_log.verify_chain()

    @app.post("/validate", dependencies=auth_deps)
    def validate_action(payload: dict[str, Any]) -> dict[str, Any]:
        action = cast(str, payload.get("action", ""))
        if not action.strip():
            raise HTTPException(status_code=422, detail="'action' must be a non-empty string")

        agent_id = payload.get("agent_id", "anonymous")
        if not isinstance(agent_id, str):
            raise HTTPException(status_code=422, detail="'agent_id' must be a string")

        context = payload.get("context", {})
        if not isinstance(context, dict):
            raise HTTPException(status_code=422, detail="'context' must be an object")

        result = engine.validate(
            action,
            agent_id=agent_id,
            context=context,
        )
        return result.to_dict()

    @app.post("/receipts", dependencies=auth_deps)
    def create_receipt(payload: dict[str, Any]) -> dict[str, Any]:
        repository = payload.get("repository", "")
        head_sha = payload.get("head_sha", "")
        head_ref = payload.get("head_ref", "")
        base_ref = payload.get("base_ref", "")
        action = cast(str, payload.get("action", ""))
        check_name = cast(str, payload.get("check_name", "acgs/merge-group"))
        agent_id = cast(str, payload.get("agent_id", "github-merge-queue"))
        source = cast(str, payload.get("source", "github.merge_group"))

        if not all(isinstance(value, str) and value.strip() for value in (repository, head_sha, head_ref, base_ref)):
            raise HTTPException(
                status_code=422,
                detail="'repository', 'head_sha', 'head_ref', and 'base_ref' must be non-empty strings",
            )
        if not action.strip():
            raise HTTPException(status_code=422, detail="'action' must be a non-empty string")

        context = payload.get("context", {})
        if not isinstance(context, dict):
            raise HTTPException(status_code=422, detail="'context' must be an object")

        request = MergeGroupReceiptRequest(
            repository=repository,
            head_sha=head_sha,
            head_ref=head_ref,
            base_ref=base_ref,
            action=action,
            check_name=check_name,
            agent_id=agent_id,
            source=source,
            context=context,
        )
        validation = engine.validate(action, agent_id=agent_id, context=context)
        outcome = build_receipt_outcome(
            request=request,
            validation=validation,
            constitutional_hash=gov_constitution.hash,
        )
        return outcome.to_dict()

    # --- Rules CRUD ---

    @app.get("/rules", dependencies=auth_deps)
    def list_rules() -> list[dict[str, Any]]:
        return [
            {
                "id": r.id,
                "text": r.text,
                "severity": r.severity.value,
                "keywords": r.keywords,
                "patterns": r.patterns,
                "category": r.category,
                "subcategory": r.subcategory,
                "workflow_action": r.workflow_action,
                "enabled": r.enabled,
                "tags": r.tags,
                "priority": r.priority,
            }
            for r in gov_constitution.rules
        ]

    @app.get("/rules/{rule_id}", dependencies=auth_deps)
    def get_rule(rule_id: str) -> dict[str, Any]:
        for r in gov_constitution.rules:
            if r.id == rule_id:
                return r.model_dump()
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")

    @app.post("/rules", status_code=201, dependencies=auth_deps)
    def create_rule(payload: dict[str, Any]) -> dict[str, Any]:
        from acgs_lite.constitution import Rule, Severity

        rule_id = payload.get("id", "")
        if not rule_id or not isinstance(rule_id, str):
            raise HTTPException(status_code=422, detail="'id' is required and must be a string")

        if any(r.id == rule_id for r in gov_constitution.rules):
            raise HTTPException(status_code=409, detail=f"Rule '{rule_id}' already exists")

        try:
            rule = Rule(
                id=rule_id,
                text=payload.get("text", ""),
                severity=Severity(payload.get("severity", "medium")),
                keywords=payload.get("keywords", []),
                patterns=payload.get("patterns", []),
                category=payload.get("category", "custom"),
                subcategory=payload.get("subcategory", ""),
                workflow_action=payload.get("workflow_action", "warn"),
                tags=payload.get("tags", []),
                priority=payload.get("priority", 50),
            )
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        gov_constitution.add_rule(rule)
        _rebuild_engine()
        return rule.model_dump()

    @app.put("/rules/{rule_id}", dependencies=auth_deps)
    def update_rule(rule_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        from acgs_lite.constitution import Rule, Severity

        existing = None
        for r in gov_constitution.rules:
            if r.id == rule_id:
                existing = r
                break
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")

        try:
            updated = Rule(
                id=rule_id,
                text=payload.get("text", existing.text),
                severity=Severity(payload.get("severity", existing.severity.value)),
                keywords=payload.get("keywords", existing.keywords),
                patterns=payload.get("patterns", existing.patterns),
                category=payload.get("category", existing.category),
                subcategory=payload.get("subcategory", existing.subcategory),
                workflow_action=payload.get("workflow_action", existing.workflow_action),
                tags=payload.get("tags", existing.tags),
                priority=payload.get("priority", existing.priority),
                enabled=payload.get("enabled", existing.enabled),
            )
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        gov_constitution.replace_rule(rule_id, updated)
        _rebuild_engine()
        return updated.model_dump()

    @app.delete("/rules/{rule_id}", status_code=204, dependencies=auth_deps)
    def delete_rule(rule_id: str) -> None:
        if not any(r.id == rule_id for r in gov_constitution.rules):
            raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
        gov_constitution.remove_rule(rule_id)
        _rebuild_engine()

    def _rebuild_engine() -> None:
        """Rebuild engine internals after rule changes."""
        nonlocal engine
        engine = GovernanceEngine(
            gov_constitution,
            audit_log=cast(Any, audit_log),
            strict=False,
            audit_mode="full",
        )

    # --- Audit Trail ---

    @app.get("/audit/entries", dependencies=auth_deps)
    def list_audit_entries(
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
        agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return [
            entry.to_dict()
            for entry in _list_audit_entries(limit=limit, offset=offset, agent_id=agent_id)
        ]

    @app.get("/audit/chain", dependencies=auth_deps)
    def audit_chain_status() -> dict[str, Any]:
        return {
            "valid": _audit_chain_valid(),
            "entry_count": _audit_count(),
        }

    @app.get("/audit/count", dependencies=auth_deps)
    def audit_count() -> dict[str, int]:
        return {"count": _audit_count()}

    # --- Constitutional Decision Provenance (CDP) ---

    @app.get("/cdp/records", dependencies=auth_deps)
    def list_cdp_records(
        tenant_id: str | None = None,
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        records = _cdp_backend.list(tenant_id=tenant_id, limit=limit, offset=offset)
        total = _cdp_backend.count(tenant_id=tenant_id)
        return {
            "records": [r.to_dict() for r in records],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @app.get("/cdp/records/{cdp_id}", dependencies=auth_deps)
    def get_cdp_record(cdp_id: str) -> dict[str, Any]:
        record = _cdp_backend.get(cdp_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"CDP record {cdp_id!r} not found")
        return record.to_dict()

    @app.get("/cdp/chain", dependencies=auth_deps)
    def cdp_chain_status(tenant_id: str | None = None) -> dict[str, Any]:
        is_valid, broken_ids = _cdp_backend.verify_chain(tenant_id=tenant_id)
        return {
            "valid": is_valid,
            "record_count": _cdp_backend.count(tenant_id=tenant_id),
            "broken_ids": broken_ids,
        }

    @app.get("/cdp/records/{cdp_id}/certificate", dependencies=auth_deps)
    def get_cdp_certificate(cdp_id: str, title: str = "AI Compliance Evidence Package") -> Any:
        """Return a PDF certificate for a CDP record.

        Requires the ``pdf`` optional extra (``pip install acgs-lite[pdf]``).
        """
        from fastapi.responses import Response

        record = _cdp_backend.get(cdp_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"CDP record {cdp_id!r} not found")
        try:
            from acgs_lite.cdp.certificate import generate_certificate
        except ImportError as exc:
            raise HTTPException(
                status_code=503,
                detail="PDF generation requires fpdf2. Install with: pip install acgs-lite[pdf]",
            ) from exc
        pdf_bytes = generate_certificate(record.to_dict(), title=title)
        filename = f"cdp-certificate-{cdp_id[:8]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # --- Health & Stats ---

    @app.get("/health")
    def health_check() -> dict[str, str]:
        return {"status": "ok", "engine": "ready"}

    @app.get("/stats", dependencies=auth_deps)
    def get_stats() -> dict[str, Any]:
        return {
            **engine.stats,
            "audit_entry_count": _audit_count(),
            "audit_chain_valid": _audit_chain_valid(),
        }

    if include_openshell_experimental is not None:
        include_openshell_governance = include_openshell_experimental

    if include_openshell_governance:
        state_backend = openshell_state_backend
        if state_backend is None and openshell_state_path is not None:
            state_backend = JsonFileGovernanceStateBackend(openshell_state_path)
        app.include_router(
            create_openshell_governance_router(
                audit_log=cast(Any, audit_log),
                observability_hook=openshell_observability_hook,
                state_backend=state_backend,
            )
        )

    if include_autonoma:
        from acgs_lite.autonoma import create_autonoma_router

        scenarios_path_resolved = Path(autonoma_scenarios_path) if autonoma_scenarios_path else None
        app.include_router(create_autonoma_router(scenarios_path=scenarios_path_resolved))

    if include_telegram:
        if telegram_webhook_path_secret is None:
            raise ValueError("telegram_webhook_path_secret is required when include_telegram=True")
        app.include_router(
            create_telegram_webhook_router(
                engine_getter=lambda: engine,
                webhook_path_secret=telegram_webhook_path_secret,
                secret_token=telegram_secret_token,
            )
        )

    _include_lifecycle = (
        include_lifecycle if include_lifecycle is not None else _env_flag("ACGS_LIFECYCLE_ENABLED")
    )
    if _include_lifecycle:
        from acgs_lite.constitution.lifecycle_router import create_lifecycle_router

        app.include_router(create_lifecycle_router(api_key=lifecycle_api_key))

    if os.getenv("ACGS_FEDERATION_ENABLED"):
        app.include_router(federation_router, prefix="/v1/federation")

    if os.getenv("ACGS_EVENTS_ENABLED"):
        from fastapi.responses import StreamingResponse

        @app.get("/v1/events/stream")
        async def stream_events() -> StreamingResponse:
            subscription = cast(AsyncGenerator[GovernanceEvent, None], get_event_bus().subscribe())

            async def next_event() -> GovernanceEvent:
                return await subscription.__anext__()

            async def event_stream() -> AsyncGenerator[str, None]:
                pending_event: asyncio.Task[Any] | None = None
                try:
                    while True:
                        if pending_event is None:
                            pending_event = asyncio.create_task(next_event())
                        try:
                            event = await asyncio.wait_for(
                                asyncio.shield(pending_event), timeout=30.0
                            )
                        except asyncio.TimeoutError:
                            yield 'data: {"type":"heartbeat"}\n\n'
                            continue
                        except StopAsyncIteration:
                            break
                        else:
                            pending_event = None
                            yield event.to_sse()
                finally:
                    if pending_event is not None:
                        pending_event.cancel()
                        await asyncio.gather(pending_event, return_exceptions=True)
                    await subscription.aclose()

            return StreamingResponse(event_stream(), media_type="text/event-stream")

    return app
