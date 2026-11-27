# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Autonoma Environment Factory endpoint.

Implements the three-action protocol (discover / up / down) for Autonoma
test orchestration.  The endpoint creates isolated test data environments
so E2E tests can run against deterministic scenario fixtures.

Security layers:
  1. Environment gating — returns 404 in production unless explicitly enabled.
  2. HMAC-SHA256 request signing — every request carries an ``x-signature`` header.
  3. Signed refs (JWT) — ``up`` signs created entity refs; ``down`` verifies before deleting.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any

try:
    import jwt
except ImportError as _exc:
    raise ImportError(
        "Autonoma requires PyJWT. Install with: pip install acgs-lite[autonoma]"
    ) from _exc

try:
    import structlog
except ImportError:
    import logging as _logging

    structlog = None  # type: ignore[assignment]

import yaml

from acgs_lite._compat import constant_time_compare

try:
    from fastapi import APIRouter, HTTPException, Request, Response
except ImportError as _exc:
    raise ImportError(
        "Autonoma requires FastAPI. Install with: pip install acgs-lite[autonoma]"
    ) from _exc

from pydantic import BaseModel, Field

if structlog is not None:
    logger = structlog.get_logger(__name__)
else:
    import logging as _logging

    _fallback_logger = _logging.getLogger(__name__)

    class _StructlogCompat:
        """Adapter so structlog-style keyword calls work with stdlib logging."""

        def _log(self, level: str, event: str, **kw: object) -> None:
            extra = " ".join(f"{k}={v}" for k, v in kw.items())
            getattr(_fallback_logger, level)(f"{event} {extra}".strip())

        def error(self, event: str, **kw: object) -> None:
            self._log("error", event, **kw)

        def info(self, event: str, **kw: object) -> None:
            self._log("info", event, **kw)

        def warning(self, event: str, **kw: object) -> None:
            self._log("warning", event, **kw)

    logger = _StructlogCompat()  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------

_SIGNING_SECRET_VAR = "AUTONOMA_SIGNING_SECRET"
_JWT_SECRET_VAR = "AUTONOMA_JWT_SECRET"
_ENABLE_VAR = "AUTONOMA_ENV_FACTORY_ENABLED"

# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class DiscoverRequest(BaseModel):
    action: str = "discover"


class EnvironmentInfo(BaseModel):
    name: str
    description: str
    fingerprint: str


class DiscoverResponse(BaseModel):
    environments: list[EnvironmentInfo]


class UpRequest(BaseModel):
    action: str = "up"
    environment: str
    testRunId: str  # noqa: N815  (protocol field name)


class UpResponse(BaseModel):
    auth: dict[str, Any]
    refs: dict[str, Any]
    refsToken: str  # noqa: N815
    metadata: dict[str, Any] = Field(default_factory=dict)
    expiresInSeconds: int = 7200  # noqa: N815


class DownRequest(BaseModel):
    action: str = "down"
    testRunId: str  # noqa: N815
    refs: dict[str, Any]
    refsToken: str  # noqa: N815


class DownResponse(BaseModel):
    ok: bool = True


class ErrorResponse(BaseModel):
    error: str
    code: str


# ---------------------------------------------------------------------------
# Scenario loading and fingerprinting
# ---------------------------------------------------------------------------

_SCENARIO_CACHE: dict[str, list[dict[str, Any]]] = {}


def _find_scenarios_path() -> Path:
    """Locate ``autonoma/scenarios.md`` relative to the repository root."""
    # Walk upward from this file to find the repo root containing ``autonoma/``
    candidate = Path(__file__).resolve()
    for _ in range(10):
        candidate = candidate.parent
        scenarios_path = candidate / "autonoma" / "scenarios.md"
        if scenarios_path.is_file():
            return scenarios_path
    raise FileNotFoundError("autonoma/scenarios.md not found in any parent directory")


def _parse_scenarios(path: Path | None = None) -> list[dict[str, Any]]:
    """Parse the YAML front-matter from ``scenarios.md``."""
    cache_key = str(path or "default")
    if cache_key in _SCENARIO_CACHE:
        return _SCENARIO_CACHE[cache_key]

    resolved_path = path or _find_scenarios_path()
    text = resolved_path.read_text(encoding="utf-8")

    # Extract YAML front-matter between --- delimiters
    match = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
    if not match:
        raise ValueError("No YAML front-matter found in scenarios.md")

    front_matter = yaml.safe_load(match.group(1))
    scenarios: list[dict[str, Any]] = front_matter.get("scenarios", [])
    _SCENARIO_CACHE[cache_key] = scenarios
    return scenarios


def _fingerprint(scenario: dict[str, Any]) -> str:
    """Compute a deterministic 16-char hex fingerprint for a scenario.

    The fingerprint is derived from the scenario's structural descriptor
    (entity types and count) so it changes only when the scenario shape changes.
    """
    descriptor = {
        "name": scenario["name"],
        "entity_count": scenario.get("entity_count", 0),
        "entity_types": sorted(scenario.get("entity_types", [])),
    }
    canonical = json.dumps(descriptor, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# HMAC verification
# ---------------------------------------------------------------------------


def _get_signing_secret() -> str:
    secret = os.environ.get(_SIGNING_SECRET_VAR, "")
    if not secret:
        raise HTTPException(
            status_code=500,
            detail="AUTONOMA_SIGNING_SECRET not configured",
        )
    return secret


def _verify_hmac(body: bytes, signature: str) -> None:
    """Verify HMAC-SHA256 signature of the raw request body."""
    secret = _get_signing_secret()
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not constant_time_compare(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")


# ---------------------------------------------------------------------------
# JWT utilities for refs tokens
# ---------------------------------------------------------------------------


def _get_jwt_secret() -> str:
    secret = os.environ.get(_JWT_SECRET_VAR, "")
    if not secret:
        raise HTTPException(
            status_code=500,
            detail="AUTONOMA_JWT_SECRET not configured",
        )
    return secret


def _sign_refs(refs: dict[str, Any]) -> str:
    """Create a JWT containing the refs payload, signed with the internal secret."""
    return jwt.encode({"refs": refs}, _get_jwt_secret(), algorithm="HS256")


def _verify_refs_token(refs: dict[str, Any], refs_token: str) -> None:
    """Decode the JWT and verify that the refs match the request body."""
    try:
        decoded = jwt.decode(refs_token, _get_jwt_secret(), algorithms=["HS256"])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=403,
            detail=json.dumps({"error": "Invalid refs token", "code": "INVALID_REFS_TOKEN"}),
        ) from exc

    decoded_refs = decoded.get("refs", {})
    if decoded_refs != refs:
        raise HTTPException(
            status_code=403,
            detail=json.dumps({"error": "Refs mismatch", "code": "INVALID_REFS_TOKEN"}),
        )


# ---------------------------------------------------------------------------
# Scenario builders — create / tear-down test data
# ---------------------------------------------------------------------------

# In-memory store for active test run data keyed by testRunId.
_active_runs: dict[str, dict[str, Any]] = {}


def _build_standard_scenario(test_run_id: str) -> dict[str, Any]:
    """Build refs for the ``standard`` scenario."""
    rule_ids = [
        "SAFE-001",
        "PRIV-001",
        "BIAS-001",
        "TRANS-001",
        "OVER-001",
        "FIN-001",
        "SEC-001",
        "DEPR-001",
        "COND-001",
        "TEMP-001",
    ]
    audit_ids = [f"AUD-STD-{i:03d}" for i in range(1, 9)]
    user_ids = ["dev-alice", "admin-bob", "compliance-carol", "clinical-dave", "visitor-eve"]
    framework_ids = [
        "eu_ai_act",
        "gdpr",
        "hipaa",
        "nist_ai_rmf",
        "soc2",
        "ccpa_cpra",
        "uk_ai_framework",
        "dora",
        "china_ai",
    ]
    return {
        "rule_ids": rule_ids,
        "audit_ids": audit_ids,
        "user_ids": user_ids,
        "framework_ids": framework_ids,
        "testRunId": test_run_id,
    }


def _build_empty_scenario(test_run_id: str) -> dict[str, Any]:
    """Build refs for the ``empty`` scenario."""
    return {
        "rule_ids": [],
        "audit_ids": [],
        "user_ids": [],
        "framework_ids": [],
        "testRunId": test_run_id,
    }


def _build_large_scenario(test_run_id: str) -> dict[str, Any]:
    """Build refs for the ``large`` scenario."""
    category_prefix_map = {
        "safety": ("SAFE", 20),
        "privacy": ("PRIV", 20),
        "fairness": ("FAIR", 15),
        "transparency": ("TRANS", 15),
        "security": ("SEC", 15),
        "oversight": ("OVER", 15),
        "general": ("GEN", 10),
        "custom": ("CUST", 10),
    }
    rule_ids: list[str] = []
    for _cat, (prefix, count) in category_prefix_map.items():
        for i in range(1, count + 1):
            rule_ids.append(f"{prefix}-{i:03d}")

    audit_ids = [f"AUD-LRG-{i:04d}" for i in range(1, 1001)]
    user_ids = ["dev-alice", "admin-bob", "compliance-carol", "clinical-dave", "visitor-eve"]
    framework_ids = [
        "eu_ai_act",
        "gdpr",
        "hipaa",
        "nist_ai_rmf",
        "soc2",
        "ccpa_cpra",
        "uk_ai_framework",
        "dora",
        "china_ai",
    ]
    return {
        "rule_ids": rule_ids,
        "audit_ids": audit_ids,
        "user_ids": user_ids,
        "framework_ids": framework_ids,
        "testRunId": test_run_id,
    }


_SCENARIO_BUILDERS: dict[str, Any] = {
    "standard": _build_standard_scenario,
    "empty": _build_empty_scenario,
    "large": _build_large_scenario,
}


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


def create_autonoma_router(
    *,
    scenarios_path: Path | None = None,
) -> APIRouter:
    """Create the Autonoma Environment Factory router.

    Parameters
    ----------
    scenarios_path:
        Explicit path to ``scenarios.md``. When ``None``, the file is
        auto-discovered by walking parent directories.
    """
    router = APIRouter(tags=["autonoma"])

    @router.post("/api/autonoma")
    async def autonoma_environment_factory(request: Request) -> Response:
        """Autonoma Environment Factory — discover / up / down."""
        # Layer 1: Environment gating
        enabled = os.environ.get(_ENABLE_VAR, "").lower()
        if enabled not in ("1", "true", "yes"):
            raise HTTPException(status_code=404, detail="Not found")

        # Read raw body for HMAC verification
        raw_body = await request.body()

        # Layer 2: HMAC signature verification
        signature = request.headers.get("x-signature", "")
        if not signature:
            raise HTTPException(status_code=401, detail="Missing x-signature header")
        _verify_hmac(raw_body, signature)

        # Parse JSON
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON") from exc

        action = payload.get("action", "")

        if action == "discover":
            return _handle_discover(scenarios_path)
        elif action == "up":
            return _handle_up(payload)
        elif action == "down":
            return _handle_down(payload)
        else:
            return Response(
                content=json.dumps({"error": "Unknown action", "code": "UNKNOWN_ACTION"}),
                status_code=400,
                media_type="application/json",
            )

    return router


def _handle_discover(scenarios_path: Path | None) -> Response:
    """Handle the ``discover`` action."""
    try:
        scenarios = _parse_scenarios(scenarios_path)
    except FileNotFoundError as exc:
        logger.error("scenario_discovery_failed", error=type(exc).__name__)
        raise HTTPException(
            status_code=500,
            detail="autonoma/scenarios.md not found. "
            "Set autonoma_scenarios_path when calling create_governance_app() "
            "for non-repository installs.",
        ) from exc
    except ValueError as exc:
        logger.error("scenario_discovery_failed", error=type(exc).__name__)
        raise HTTPException(status_code=500, detail="Failed to parse scenarios") from exc

    # Only advertise scenarios that have registered builders so discover and up
    # stay consistent (Codex review fix #4).
    environments = [
        {
            "name": s["name"],
            "description": s.get("description", "").strip(),
            "fingerprint": _fingerprint(s),
        }
        for s in scenarios
        if s["name"] in _SCENARIO_BUILDERS
    ]
    return Response(
        content=json.dumps({"environments": environments}),
        status_code=200,
        media_type="application/json",
    )


def _handle_up(payload: dict[str, Any]) -> Response:
    """Handle the ``up`` action — create test data."""
    environment = payload.get("environment", "")
    test_run_id = payload.get("testRunId", "")

    if not environment or not test_run_id:
        raise HTTPException(
            status_code=400,
            detail=json.dumps(
                {
                    "error": "Missing required fields: environment, testRunId",
                    "code": "UP_FAILED",
                }
            ),
        )

    builder = _SCENARIO_BUILDERS.get(environment)
    if builder is None:
        return Response(
            content=json.dumps(
                {
                    "error": f"Unknown environment: {environment}",
                    "code": "UNKNOWN_ENVIRONMENT",
                }
            ),
            status_code=400,
            media_type="application/json",
        )

    try:
        refs = builder(test_run_id)
    except Exception as exc:
        logger.error("scenario_up_failed", error=type(exc).__name__, environment=environment)
        return Response(
            content=json.dumps({"error": "Failed to create environment", "code": "UP_FAILED"}),
            status_code=500,
            media_type="application/json",
        )

    refs_token = _sign_refs(refs)
    _active_runs[test_run_id] = refs

    auth: dict[str, Any] = {
        "headers": {
            "X-Test-Run-Id": test_run_id,
            "X-API-Key": f"acgs_test_{test_run_id}",
        },
    }

    response_data = {
        "auth": auth,
        "refs": refs,
        "refsToken": refs_token,
        "metadata": {"environment": environment, "testRunId": test_run_id},
        "expiresInSeconds": 7200,
    }
    return Response(
        content=json.dumps(response_data),
        status_code=200,
        media_type="application/json",
    )


def _handle_down(payload: dict[str, Any]) -> Response:
    """Handle the ``down`` action — tear down test data."""
    test_run_id = payload.get("testRunId", "")
    refs = payload.get("refs", {})
    refs_token = payload.get("refsToken", "")

    if not test_run_id or not refs or not refs_token:
        raise HTTPException(
            status_code=400,
            detail=json.dumps(
                {
                    "error": "Missing required fields: testRunId, refs, refsToken",
                    "code": "DOWN_FAILED",
                }
            ),
        )

    # Layer 3: Verify JWT and compare refs
    _verify_refs_token(refs, refs_token)

    # Layer 4: Verify testRunId matches the signed refs
    signed_run_id = refs.get("testRunId", "")
    if signed_run_id != test_run_id:
        raise HTTPException(
            status_code=403,
            detail=json.dumps(
                {
                    "error": "testRunId does not match signed refs",
                    "code": "TESTRUNID_MISMATCH",
                }
            ),
        )

    # Clean up the active run
    _active_runs.pop(test_run_id, None)

    return Response(
        content=json.dumps({"ok": True}),
        status_code=200,
        media_type="application/json",
    )
