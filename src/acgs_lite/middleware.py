# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""ACGS-Lite HTTP Middleware.

Framework-agnostic ASGI and WSGI middleware that validates HTTP request
and response bodies against constitutional rules. Works with FastAPI,
Starlette, Flask, Django, and any ASGI/WSGI-compatible framework.

Usage::

    # FastAPI / Starlette
    from acgs_lite.middleware import GovernanceASGIMiddleware
    app.add_middleware(GovernanceASGIMiddleware, constitution=my_rules)

    # Flask
    from acgs_lite.middleware import GovernanceWSGIMiddleware
    app.wsgi_app = GovernanceWSGIMiddleware(app.wsgi_app)

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.engine import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError

logger = logging.getLogger(__name__)

# Default paths to skip governance checks
DEFAULT_SKIP_PATHS: frozenset[str] = frozenset(
    {
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/metrics",
        "/favicon.ico",
        "/openapi.json",
        "/docs",
        "/redoc",
    }
)

# HTTP methods that have request bodies
BODY_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


# Values of the X-Governance-Valid response header. The header describes the
# request body only: "true" and "false" mean validation ran and did or did not
# find a blocking violation; "unchecked" means nothing was validated (no body,
# an empty body, or validation itself failed).
GOVERNANCE_VALID = "true"
GOVERNANCE_INVALID = "false"
GOVERNANCE_UNCHECKED = "unchecked"


def _validate_non_strict(engine: GovernanceEngine, text: str, *, agent_id: str) -> Any:
    """Validate text in non-strict mode via per-call override (no instance mutation)."""
    return engine.validate(text, agent_id=agent_id, strict=False)


def _header_state(result: Any) -> str:
    """Map a validation result to an X-Governance-Valid header value."""
    return GOVERNANCE_VALID if getattr(result, "valid", False) is True else GOVERNANCE_INVALID


class GovernanceASGIMiddleware:
    """ASGI middleware that validates request/response bodies.

    Validates:
    - Request bodies (POST/PUT/PATCH) against constitutional rules
    - Response bodies (non-blocking, adds X-Governance headers)

    Usage::

        from fastapi import FastAPI
        from acgs_lite.middleware import GovernanceASGIMiddleware

        app = FastAPI()
        app.add_middleware(GovernanceASGIMiddleware)

        # With custom constitution:
        app.add_middleware(
            GovernanceASGIMiddleware,
            constitution=my_rules,
            skip_paths={"/health", "/internal"},
        )
    """

    def __init__(
        self,
        app: Any,
        *,
        constitution: Constitution | None = None,
        skip_paths: set[str] | frozenset[str] | None = None,
        agent_id: str = "http-middleware",
        strict: bool = False,
        validate_responses: bool = True,
    ) -> None:
        self.app = app
        self.constitution = constitution or Constitution.default()
        self.audit_log = AuditLog()
        self.engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict,
            audit_mode="full",
        )
        self.skip_paths = skip_paths if skip_paths is not None else DEFAULT_SKIP_PATHS
        self.agent_id = agent_id
        self.validate_responses = validate_responses

    async def _buffer_request_messages(
        self,
        receive: Callable[[], Awaitable[dict[str, Any]]],
    ) -> tuple[list[dict[str, Any]], list[bytes]]:
        """Read the full request body so strict governance can block before app execution."""
        messages: list[dict[str, Any]] = []
        body_chunks: list[bytes] = []

        while True:
            message = await receive()
            messages.append(message)
            if message.get("type") != "http.request":
                break
            body = message.get("body", b"")
            if body:
                body_chunks.append(body)
            if not message.get("more_body", False):
                break

        return messages, body_chunks

    def _make_receive_replay(
        self,
        messages: list[dict[str, Any]],
    ) -> Callable[[], Awaitable[dict[str, Any]]]:
        pending = list(messages)

        async def replay_receive() -> dict[str, Any]:
            if pending:
                return pending.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        return replay_receive

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()

        # Skip configured paths
        if path in self.skip_paths:
            await self.app(scope, receive, send)
            return

        # For body methods, validate request body
        governance_state = GOVERNANCE_UNCHECKED
        governance_violations: list[str] = []

        if method in BODY_METHODS:
            request_messages, body_chunks = await self._buffer_request_messages(receive)
            replay_receive = self._make_receive_replay(request_messages)

            if body_chunks:
                request_text = b"".join(body_chunks).decode("utf-8", errors="replace")
                governance_state = self._validate_text(request_text, f"{self.agent_id}:request")

            if self.validate_responses:
                # We need to buffer response too
                response_body_chunks: list[bytes] = []

                async def send_wrapper(message: dict[str, Any]) -> None:
                    if message["type"] == "http.response.start":
                        # Add governance headers
                        extra_headers = [
                            (b"x-governance-hash", self.constitution.hash.encode()),
                            (b"x-governance-valid", governance_state.encode()),
                        ]
                        if governance_violations:
                            extra_headers.append(
                                (
                                    b"x-governance-violations",
                                    ",".join(governance_violations).encode(),
                                )
                            )

                        existing = list(message.get("headers", []))
                        existing.extend(extra_headers)
                        message = {**message, "headers": existing}

                    elif message["type"] == "http.response.body":
                        body = message.get("body", b"")
                        if body:
                            response_body_chunks.append(body)

                    await send(message)

                await self.app(scope, replay_receive, send_wrapper)

                # Validate response body (non-blocking)
                if response_body_chunks:
                    response_text = b"".join(response_body_chunks).decode("utf-8", errors="replace")
                    self._validate_output(response_text)

            else:
                await self.app(scope, replay_receive, send)
        else:
            # GET/HEAD/OPTIONS — just pass through with governance headers
            if self.validate_responses:

                async def send_with_headers(message: dict[str, Any]) -> None:
                    if message["type"] == "http.response.start":
                        existing = list(message.get("headers", []))
                        existing.extend(
                            [
                                (b"x-governance-hash", self.constitution.hash.encode()),
                                (b"x-governance-valid", GOVERNANCE_UNCHECKED.encode()),
                            ]
                        )
                        message = {**message, "headers": existing}
                    await send(message)

                await self.app(scope, receive, send_with_headers)
            else:
                await self.app(scope, receive, send)

    def _validate_text(self, text: str, agent_id: str) -> str:
        """Validate text and return the X-Governance-Valid value for it.

        A blocking violation raises in strict mode. Any other failure is logged
        and reported as unchecked, never as valid.
        """
        try:
            # Try to parse as JSON and extract meaningful text
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    # Extract common text fields
                    text_parts: list[str] = []
                    for key in ("content", "text", "message", "query", "input", "prompt"):
                        if key in data and isinstance(data[key], str):
                            text_parts.append(data[key])
                    text = " ".join(text_parts) if text_parts else json.dumps(data)
            except (json.JSONDecodeError, ValueError):
                pass  # Use raw text

            if text.strip():
                return _header_state(self.engine.validate(text, agent_id=agent_id))
        except ConstitutionalViolationError:
            raise
        except Exception as e:
            logger.warning("Governance middleware validation error: %s", e)
        return GOVERNANCE_UNCHECKED

    def _validate_output(self, text: str) -> None:
        """Validate output text non-blocking."""
        try:
            if text.strip():
                result = _validate_non_strict(
                    self.engine,
                    text[:2000],
                    agent_id=f"{self.agent_id}:response",
                )
                if not result.valid:
                    logger.warning(
                        "HTTP response governance violations: %s",
                        [v.rule_id for v in result.violations],
                    )
        except Exception as e:
            logger.debug("Governance middleware output validation error: %s", e)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            **self.engine.stats,
            "agent_id": self.agent_id,
            "audit_chain_valid": self.audit_log.verify_chain(),
        }


class GovernanceWSGIMiddleware:
    """WSGI middleware that validates request/response bodies.

    Usage::

        from flask import Flask
        from acgs_lite.middleware import GovernanceWSGIMiddleware

        app = Flask(__name__)
        app.wsgi_app = GovernanceWSGIMiddleware(app.wsgi_app)
    """

    def __init__(
        self,
        app: Any,
        *,
        constitution: Constitution | None = None,
        skip_paths: set[str] | frozenset[str] | None = None,
        agent_id: str = "http-middleware",
        strict: bool = False,
    ) -> None:
        self.app = app
        self.constitution = constitution or Constitution.default()
        self.audit_log = AuditLog()
        self.engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict,
            audit_mode="full",
        )
        self.skip_paths = skip_paths if skip_paths is not None else DEFAULT_SKIP_PATHS
        self.agent_id = agent_id

    def __call__(
        self,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
    ) -> Any:
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET").upper()

        # Skip configured paths
        if path in self.skip_paths:
            return self.app(environ, start_response)

        # Validate request body for body methods
        governance_state = GOVERNANCE_UNCHECKED
        if method in BODY_METHODS:
            content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
            if content_length > 0:
                body = environ["wsgi.input"].read(content_length)
                # Reset the input stream so the app can read it
                environ["wsgi.input"] = io.BytesIO(body)

                try:
                    text = body.decode("utf-8", errors="replace")
                    if text.strip():
                        governance_state = _header_state(
                            _validate_non_strict(
                                self.engine,
                                text[:2000],
                                agent_id=f"{self.agent_id}:request",
                            )
                        )
                except ConstitutionalViolationError:
                    raise
                except Exception as e:
                    logger.warning("WSGI governance validation error: %s", e)

        # Add governance headers to response
        def governed_start_response(status: str, headers: list[tuple[str, str]], *args: Any) -> Any:
            headers.append(("X-Governance-Hash", self.constitution.hash))
            headers.append(("X-Governance-Valid", governance_state))
            return start_response(status, headers, *args)

        return self.app(environ, governed_start_response)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            **self.engine.stats,
            "agent_id": self.agent_id,
            "audit_chain_valid": self.audit_log.verify_chain(),
        }
