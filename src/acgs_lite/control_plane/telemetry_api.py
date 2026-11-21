"""Read-only telemetry endpoint and a self-contained HTML dashboard.

:func:`snapshot_json` and :func:`render_dashboard_html` are pure and need no
web framework. :func:`create_telemetry_app` builds a FastAPI app; fastapi is
the optional ``server`` extra and is imported only inside that function, so
importing this module stays core-only.

Every route is GET-only and requires ``Authorization: Bearer <token>``
checked by the injected ``auth_token_verifier`` -- a missing or invalid
token, or a verifier that raises, is a 401 (fail closed). The OpenAPI and
docs routes are disabled. The dashboard escapes every value and is served
with ``Content-Security-Policy: default-src 'none'; style-src
'unsafe-inline'`` (no scripts, no external resources).

This module deliberately has no ``from __future__ import annotations``:
FastAPI resolves the route signatures at runtime and the ``Request`` type is
a local of :func:`create_telemetry_app`.
"""

import dataclasses
import html
import math
from collections.abc import Callable, Mapping
from typing import Any, cast

from acgs_lite.control_plane.breaker import TriggerCircuitBreaker
from acgs_lite.control_plane.telemetry import DEFAULT_REWORK_WINDOW_S, OversightMetrics, Segment

__all__ = [
    "DASHBOARD_CSP",
    "create_telemetry_app",
    "render_dashboard_html",
    "snapshot_json",
]

DASHBOARD_CSP = "default-src 'none'; style-src 'unsafe-inline'"
_JSON_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


def snapshot_json(
    metrics: OversightMetrics,
    *,
    breaker: TriggerCircuitBreaker | None = None,
    rework_window_s: float = DEFAULT_REWORK_WINDOW_S,
) -> dict[str, Any]:
    """The metrics snapshot plus breaker states, JSON-serializable."""
    snapshot = metrics.snapshot(rework_window_s=rework_window_s)
    snapshot["breakers"] = _breakers(breaker)
    return snapshot


def _breakers(breaker: TriggerCircuitBreaker | None) -> list[dict[str, Any]]:
    if breaker is None:
        return []
    return [
        {**dataclasses.asdict(status), "state": status.state.value} for status in breaker.statuses()
    ]


def _format(value: object) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4g}"
    return str(value)


def _flatten(value: object, prefix: str, rows: list[tuple[str, str]]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            _flatten(item, f"{prefix}.{key}" if prefix else str(key), rows)
    elif isinstance(value, (list, tuple)):
        if not value:
            rows.append((prefix, "(none)"))
        for index, item in enumerate(value):
            _flatten(item, f"{prefix}[{index}]", rows)
    else:
        rows.append((prefix, _format(value)))


def render_dashboard_html(snapshot: Mapping[str, Any]) -> str:
    """One escaped HTML table per snapshot section; no scripts or links."""
    sections = []
    for name, value in snapshot.items():
        rows: list[tuple[str, str]] = []
        _flatten(value, "", rows)
        body = "".join(
            f"<tr><th>{html.escape(key or name)}</th><td>{html.escape(cell)}</td></tr>"
            for key, cell in rows
        )
        sections.append(f"<h2>{html.escape(str(name))}</h2><table>{body}</table>")
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Oversight telemetry</title>"
        "<style>body{font-family:sans-serif;margin:1rem}table{border-collapse:collapse}"
        "th,td{border:1px solid #999;padding:2px 6px;text-align:left}</style>"
        "</head><body><h1>Oversight telemetry</h1>" + "".join(sections) + "</body></html>"
    )


# TODO(control-plane-gap): the bearer scheme is matched case-insensitively
# (RFC 7235) and the token is stripped; constant-time comparison, token
# rotation, rate limiting and framing protection (X-Frame-Options /
# frame-ancestors) are left to the injected verifier and the hosting proxy.
def _bearer_ok(header: str | None, verifier: Callable[[str], bool]) -> bool:
    if not isinstance(header, str):
        return False
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return False
    try:
        return verifier(token) is True
    except Exception:
        return False


def create_telemetry_app(
    metrics: OversightMetrics,
    *,
    auth_token_verifier: Callable[[str], bool],
    breaker: TriggerCircuitBreaker | None = None,
) -> Any:
    """Build the read-only FastAPI app (needs the ``server`` extra)."""
    if not isinstance(metrics, OversightMetrics):
        raise TypeError("metrics must be an OversightMetrics")
    if not callable(auth_token_verifier):
        raise TypeError("auth_token_verifier must be callable")
    try:
        from fastapi import Depends, FastAPI, HTTPException, Request
        from fastapi.responses import HTMLResponse, JSONResponse
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise ImportError(
            "create_telemetry_app needs fastapi: pip install 'acgs-lite[server]'"
        ) from exc

    def require_token(request: Request) -> None:
        if not _bearer_ok(request.headers.get("authorization"), auth_token_verifier):
            raise HTTPException(
                status_code=401,
                detail="unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def bad_request(exc: Exception) -> HTTPException:
        return HTTPException(status_code=400, detail=str(exc))

    def window(value: float | None, label: str) -> float | None:
        if value is not None and not math.isfinite(value):
            raise bad_request(ValueError(f"{label} must be finite"))
        return value

    def respond(payload: Any) -> JSONResponse:
        return JSONResponse(payload, headers=_JSON_HEADERS)

    app = FastAPI(
        title="acgs-lite oversight telemetry",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        dependencies=[Depends(require_token)],
    )

    @app.get("/telemetry/snapshot")
    def snapshot() -> JSONResponse:
        return respond(snapshot_json(metrics, breaker=breaker))

    @app.get("/telemetry/override-rate")
    def override_rate(
        segment: str = "all", since: float | None = None, until: float | None = None
    ) -> JSONResponse:
        try:
            result = metrics.override_rate(
                cast(Segment, segment),
                since=window(since, "since"),
                until=window(until, "until"),
            )
        except ValueError as exc:
            raise bad_request(exc) from exc
        return respond(dataclasses.asdict(result))

    @app.get("/telemetry/approval-latency")
    def approval_latency(
        segment: str = "all", since: float | None = None, until: float | None = None
    ) -> JSONResponse:
        try:
            result = metrics.approval_latency(
                cast(Segment, segment),
                since=window(since, "since"),
                until=window(until, "until"),
            )
        except ValueError as exc:
            raise bad_request(exc) from exc
        return respond(dataclasses.asdict(result))

    @app.get("/telemetry/verifier")
    def verifier(
        verifier_id: str | None = None,
        segment: str = "all",
        since: float | None = None,
        until: float | None = None,
    ) -> JSONResponse:
        try:
            result = metrics.verifier_precision_recall(
                verifier_id,
                segment=cast(Segment, segment),
                since=window(since, "since"),
                until=window(until, "until"),
            )
        except ValueError as exc:
            raise bad_request(exc) from exc
        return respond({"positive_class": "fail", **dataclasses.asdict(result)})

    @app.get("/telemetry/rework")
    def rework(
        segment: str = "all",
        window_s: float = DEFAULT_REWORK_WINDOW_S,
        since: float | None = None,
        until: float | None = None,
    ) -> JSONResponse:
        try:
            result = metrics.post_merge_rework_rate(
                window_s,
                cast(Segment, segment),
                since=window(since, "since"),
                until=window(until, "until"),
            )
        except ValueError as exc:
            raise bad_request(exc) from exc
        return respond({"window_s": window_s, **dataclasses.asdict(result)})

    @app.get("/telemetry/breakers")
    def breakers() -> JSONResponse:
        return respond(_breakers(breaker))

    @app.get("/telemetry/dashboard")
    def dashboard() -> HTMLResponse:
        page = render_dashboard_html(snapshot_json(metrics, breaker=breaker))
        return HTMLResponse(
            page,
            headers={**_JSON_HEADERS, "Content-Security-Policy": DASHBOARD_CSP},
        )

    return app
