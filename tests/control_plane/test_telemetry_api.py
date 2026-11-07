"""Phase 4: read-only telemetry endpoint and dashboard.

The pure helpers (snapshot_json, render_dashboard_html) run without fastapi;
the app tests need the optional ``server`` extra (fastapi + httpx).
"""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.control_plane import Principal, PrincipalKind
from acgs_lite.control_plane.breaker import BreakerPolicy, TriggerCircuitBreaker
from acgs_lite.control_plane.evidence import EvidenceSource, ExternalRunRef
from acgs_lite.control_plane.telemetry import (
    InMemoryTelemetryStore,
    OversightMetrics,
    TelemetryRecorder,
)
from acgs_lite.control_plane.telemetry_api import (
    DASHBOARD_CSP,
    render_dashboard_html,
    snapshot_json,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

ROOT = Path(__file__).resolve().parents[2]
CI = Principal("ci-bot", PrincipalKind.SERVICE)
ALICE = Principal("alice", PrincipalKind.HUMAN)
TOKEN = "s3cret-token"
DAY = 86400.0


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _metrics() -> tuple[OversightMetrics, TriggerCircuitBreaker]:
    clock = Clock(100 * DAY)
    store = InMemoryTelemetryStore()
    breaker = TriggerCircuitBreaker(BreakerPolicy(max_rollbacks=1), store, clock=clock)
    rec = TelemetryRecorder(store, CI, clock=clock)
    rec.record_decision("d1", PrincipalKind.AGENT, True)
    rec.record_decision("d2", PrincipalKind.HUMAN, False)
    rec.record_override("d1", ALICE, "human_overrode_allow")
    rec.record_approval_requested("sha256:" + "a" * 64, at=clock.now - 30)
    rec.record_approval_granted("sha256:" + "a" * 64, "bob")
    rec.record_verifier_verdict("c1", "v1", "fail")
    rec.record_ground_truth(
        "c1", "fail", run_ref=ExternalRunRef("github", "1", EvidenceSource.CI_SYSTEM)
    )
    rec.record_merge("c1", author_kind="agent", author_id="agent-1", at=0)
    rec.record_rework("c1", "revert", source="ci_system", at=DAY)
    rec.record_rollback("loop-a", "c1")
    return OversightMetrics(store, clock=clock), breaker


class TestPureHelpers:
    def test_snapshot_json_includes_breakers(self) -> None:
        metrics, breaker = _metrics()
        snapshot = snapshot_json(metrics, breaker=breaker)
        assert snapshot["breakers"][0]["trigger_id"] == "loop-a"
        assert snapshot["breakers"][0]["state"] == "open"
        assert snapshot["override_rate"]["agent"]["value"] == 1.0
        assert snapshot_json(metrics)["breakers"] == []
        json.dumps(snapshot)

    def test_dashboard_escapes_malicious_ids(self) -> None:
        evil = "<script>alert(1)</script>"
        snapshot: dict[str, Any] = {
            "generated_at": 1.0,
            "verifier": {"by_verifier": {evil: {"precision": None, "tp": 1}}},
            "breakers": [{"trigger_id": evil, "state": "open", "reason": '"><img src=x>'}],
            "empty": [],
        }
        page = render_dashboard_html(snapshot)
        assert "<script" not in page
        assert "<img" not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
        assert "n/a" in page and "(none)" in page
        assert "http" not in page  # no external resources

    def test_importing_the_api_module_does_not_import_fastapi(self) -> None:
        code = (
            "import sys, acgs_lite.control_plane.telemetry_api\nprint('fastapi' in sys.modules)\n"
        )
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        completed = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env=env,
            check=True,
            timeout=120,
        )
        assert completed.stdout.strip() == "False"


def _client(app: Any) -> Any:
    """A TestClient, or skip without the optional ``server`` extra."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    return TestClient(app)


def _app(metrics: OversightMetrics, **kwargs: Any) -> Any:
    pytest.importorskip("fastapi")
    from acgs_lite.control_plane.telemetry_api import create_telemetry_app

    return create_telemetry_app(metrics, **kwargs)


AUTH = {"Authorization": f"Bearer {TOKEN}"}
ENDPOINTS = [
    "/telemetry/snapshot",
    "/telemetry/override-rate",
    "/telemetry/approval-latency",
    "/telemetry/verifier",
    "/telemetry/rework",
    "/telemetry/breakers",
    "/telemetry/dashboard",
]


def _verifier(token: str) -> bool:
    return token == TOKEN


@pytest.fixture()
def setup() -> Iterator[tuple[Any, OversightMetrics, Any]]:
    metrics, breaker = _metrics()
    app = _app(metrics, auth_token_verifier=_verifier, breaker=breaker)
    with _client(app) as client:
        yield client, metrics, app


class TestAuth:
    @pytest.mark.parametrize("path", ENDPOINTS)
    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Authorization": TOKEN},
            {"Authorization": f"Basic {TOKEN}"},
            {"Authorization": "Bearer "},
            {"Authorization": "Bearer wrong"},
        ],
    )
    def test_missing_or_invalid_token_is_401(
        self, setup: tuple[Any, OversightMetrics, Any], path: str, headers: dict[str, str]
    ) -> None:
        client, _, _ = setup
        response = client.get(path, headers=headers)
        assert response.status_code == 401
        assert TOKEN not in response.text

    def test_verifier_raising_is_401(self) -> None:
        metrics, _ = _metrics()

        def explode(token: str) -> bool:
            raise RuntimeError("verifier down")

        def truthy(token: str) -> bool:
            return "yes"  # type: ignore[return-value]  # not exactly True

        for verifier in (explode, truthy):
            with _client(_app(metrics, auth_token_verifier=verifier)) as c:
                assert c.get("/telemetry/snapshot", headers=AUTH).status_code == 401

    def test_constructor_type_checks(self) -> None:
        metrics, _ = _metrics()
        with pytest.raises(TypeError):
            _app("metrics", auth_token_verifier=_verifier)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            _app(metrics, auth_token_verifier="token")


class TestEndpoints:
    def test_each_metric_is_queryable(self, setup: tuple[Any, OversightMetrics, Any]) -> None:
        client, metrics, _ = setup

        def get(path: str, **params: Any) -> Any:
            response = client.get(path, headers=AUTH, params=params)
            assert response.status_code == 200, response.text
            assert response.headers["cache-control"] == "no-store"
            return response.json()

        assert get("/telemetry/override-rate", segment="agent") == dataclasses.asdict(
            metrics.override_rate("agent")
        )
        assert get("/telemetry/override-rate", since=0, until=10**9)["denominator"] == 2
        latency = get("/telemetry/approval-latency")
        assert latency == dataclasses.asdict(metrics.approval_latency())
        assert latency["p50_s"] == 30
        verifier = get("/telemetry/verifier", verifier_id="v1", segment="agent")
        assert verifier["positive_class"] == "fail"
        assert (verifier["tp"], verifier["precision"], verifier["recall"]) == (1, 1.0, 1.0)
        rework = get("/telemetry/rework", segment="agent", window_s=14 * DAY)
        assert (rework["numerator"], rework["denominator"], rework["window_s"]) == (
            1,
            1,
            14 * DAY,
        )
        breakers = get("/telemetry/breakers")
        assert [(b["trigger_id"], b["state"]) for b in breakers] == [("loop-a", "open")]
        snapshot = get("/telemetry/snapshot")
        assert set(snapshot) >= {
            "override_rate",
            "approval_latency",
            "verifier",
            "post_merge_rework",
            "breakers",
        }

    @pytest.mark.parametrize(
        ("path", "params"),
        [
            ("/telemetry/override-rate", {"segment": "robots"}),
            ("/telemetry/override-rate", {"since": "inf"}),
            ("/telemetry/verifier", {"segment": "robots"}),
            ("/telemetry/rework", {"window_s": -1}),
            ("/telemetry/rework", {"segment": "robots"}),
            ("/telemetry/approval-latency", {"until": "nan"}),
        ],
    )
    def test_bad_query_is_400(
        self,
        setup: tuple[Any, OversightMetrics, Any],
        path: str,
        params: dict[str, Any],
    ) -> None:
        client, _, _ = setup
        assert client.get(path, headers=AUTH, params=params).status_code == 400

    def test_dashboard_html_and_csp(self, setup: tuple[Any, OversightMetrics, Any]) -> None:
        client, _, _ = setup
        response = client.get("/telemetry/dashboard", headers=AUTH)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert response.headers["content-security-policy"] == DASHBOARD_CSP
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "<script" not in response.text
        assert "loop-a" in response.text

    def test_read_only_routes(self, setup: tuple[Any, OversightMetrics, Any]) -> None:
        client, _, app = setup
        from fastapi.routing import APIRoute

        routes = [route for route in app.routes if isinstance(route, APIRoute)]
        assert sorted(route.path for route in routes) == sorted(ENDPOINTS)
        for route in routes:
            assert route.methods <= {"GET", "HEAD"}
        for docs in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(docs, headers=AUTH).status_code == 404
        for method in ("post", "put", "delete", "patch"):
            response = getattr(client, method)("/telemetry/snapshot", headers=AUTH)
            assert response.status_code in (401, 405)
            assert response.status_code != 200
