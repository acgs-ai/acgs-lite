"""X-Governance-Valid must report what validation found, not a constant.

Every assertion goes through the middleware call path (a real WSGI call or an
ASGI test client), never through the private validation helpers.
"""

from __future__ import annotations

import io
import logging
from typing import Any

import pytest

from acgs_lite import Constitution, Rule, Severity
from acgs_lite.middleware import GovernanceASGIMiddleware, GovernanceWSGIMiddleware

HEADER = "X-Governance-Valid"


def _constitution() -> Constitution:
    return Constitution.from_rules(
        [
            Rule(
                id="BAN-SQL",
                text="No SQL",
                severity=Severity.CRITICAL,
                keywords=["drop table"],
            ),
        ]
    )


def _raise(*args: Any, **kwargs: Any) -> None:
    raise RuntimeError("engine down")


# ── WSGI ─────────────────────────────────────────────────────────────────────


def _wsgi_call(
    middleware: GovernanceWSGIMiddleware,
    method: str,
    body: bytes | None = None,
) -> dict[str, str]:
    captured: dict[str, str] = {}

    def start_response(status: str, headers: list[tuple[str, str]], *args: Any) -> None:
        captured.update(headers)

    environ: dict[str, Any] = {"REQUEST_METHOD": method, "PATH_INFO": "/api"}
    if body is not None:
        environ["CONTENT_LENGTH"] = str(len(body))
        environ["wsgi.input"] = io.BytesIO(body)
    middleware(environ, start_response)
    return captured


def _wsgi_middleware() -> GovernanceWSGIMiddleware:
    def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    return GovernanceWSGIMiddleware(app, constitution=_constitution())


@pytest.mark.integration
class TestWSGIGovernanceValidHeader:
    def test_violating_body_is_reported_false(self) -> None:
        headers = _wsgi_call(_wsgi_middleware(), "POST", b'{"content": "drop table users"}')
        assert headers[HEADER] == "false"

    def test_clean_body_is_reported_true(self) -> None:
        headers = _wsgi_call(_wsgi_middleware(), "POST", b'{"content": "hello there"}')
        assert headers[HEADER] == "true"

    def test_request_without_body_is_unchecked(self) -> None:
        headers = _wsgi_call(_wsgi_middleware(), "GET")
        assert headers[HEADER] == "unchecked"

    def test_whitespace_body_is_unchecked(self) -> None:
        headers = _wsgi_call(_wsgi_middleware(), "POST", b"   ")
        assert headers[HEADER] == "unchecked"

    def test_validation_error_is_unchecked_and_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        middleware = _wsgi_middleware()
        middleware.engine.validate = _raise  # type: ignore[method-assign]
        with caplog.at_level(logging.WARNING, logger="acgs_lite.middleware"):
            headers = _wsgi_call(middleware, "POST", b'{"content": "hello there"}')
        assert headers[HEADER] == "unchecked"
        assert any(record.levelno == logging.WARNING for record in caplog.records)

    def test_hash_header_still_present(self) -> None:
        headers = _wsgi_call(_wsgi_middleware(), "GET")
        assert headers["X-Governance-Hash"]


# ── ASGI ─────────────────────────────────────────────────────────────────────


def _asgi_client() -> tuple[Any, GovernanceASGIMiddleware]:
    pytest.importorskip("httpx")
    starlette_apps = pytest.importorskip("starlette.applications")
    starlette_responses = pytest.importorskip("starlette.responses")
    starlette_routing = pytest.importorskip("starlette.routing")
    starlette_testclient = pytest.importorskip("starlette.testclient")

    async def api(request: Any) -> Any:
        return starlette_responses.JSONResponse({"status": "ok"})

    inner = starlette_apps.Starlette(
        routes=[starlette_routing.Route("/api", api, methods=["GET", "POST"])]
    )
    middleware = GovernanceASGIMiddleware(inner, constitution=_constitution(), strict=False)
    return starlette_testclient.TestClient(middleware), middleware


@pytest.mark.integration
class TestASGIGovernanceValidHeader:
    def test_violating_body_is_reported_false(self) -> None:
        client, _ = _asgi_client()
        response = client.post("/api", json={"content": "drop table users"})
        assert response.headers[HEADER] == "false"

    def test_clean_body_is_reported_true(self) -> None:
        client, _ = _asgi_client()
        response = client.post("/api", json={"content": "hello there"})
        assert response.headers[HEADER] == "true"

    def test_get_is_unchecked(self) -> None:
        client, _ = _asgi_client()
        response = client.get("/api")
        assert response.headers[HEADER] == "unchecked"

    def test_post_without_body_is_unchecked(self) -> None:
        client, _ = _asgi_client()
        response = client.post("/api")
        assert response.headers[HEADER] == "unchecked"

    def test_validation_error_is_unchecked_and_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        client, middleware = _asgi_client()
        middleware.engine.validate = _raise  # type: ignore[method-assign]
        with caplog.at_level(logging.WARNING, logger="acgs_lite.middleware"):
            response = client.post("/api", json={"content": "hello there"})
        assert response.headers[HEADER] == "unchecked"
        assert any(record.levelno == logging.WARNING for record in caplog.records)
