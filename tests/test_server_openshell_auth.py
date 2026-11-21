"""API-key enforcement on the OpenShell governance router mounted by the server.

Every request goes through ``TestClient`` so the assertions cover the wiring in
``create_governance_app``, not the router in isolation.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from acgs_lite.server import create_governance_app  # noqa: E402

KEY = "test-key-for-openshell-auth"
PREFIX = "/governance/"


def _governance_operations(app: FastAPI) -> list[tuple[str, str]]:
    """Return every (METHOD, path) the app serves under ``/governance/``."""
    operations = [
        (method.upper(), path)
        for path, item in app.openapi()["paths"].items()
        if path.startswith(PREFIX)
        for method in item
    ]
    if not operations:
        pytest.fail("OpenShell governance router is not mounted; precondition not met")
    return sorted(operations)


def _statuses(client: TestClient, headers: dict[str, str]) -> dict[tuple[str, str], int]:
    return {
        (method, path): client.request(method, path, json={}, headers=headers).status_code
        for method, path in _governance_operations(client.app)
    }


@pytest.mark.unit
def test_governance_routes_cover_mutations_and_audit_read() -> None:
    operations = _governance_operations(create_governance_app(api_key=KEY))

    assert ("POST", "/governance/record-outcome") in operations
    assert ("POST", "/governance/evaluate-action") in operations
    assert ("GET", "/governance/audit-log") in operations


@pytest.mark.unit
def test_governance_routes_reject_missing_api_key() -> None:
    client = TestClient(create_governance_app(api_key=KEY))

    statuses = _statuses(client, headers={})

    assert set(statuses.values()) == {401}, statuses


@pytest.mark.unit
def test_governance_routes_reject_wrong_api_key() -> None:
    client = TestClient(create_governance_app(api_key=KEY))

    statuses = _statuses(client, headers={"X-API-Key": "wrong-key"})

    assert set(statuses.values()) == {401}, statuses


@pytest.mark.unit
def test_governance_routes_accept_correct_api_key() -> None:
    client = TestClient(create_governance_app(api_key=KEY))

    statuses = _statuses(client, headers={"X-API-Key": KEY})

    assert 401 not in statuses.values(), statuses
    assert statuses[("GET", "/governance/audit-log")] == 200


@pytest.mark.unit
def test_governance_routes_read_key_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACGS_API_KEY", KEY)
    client = TestClient(create_governance_app())

    assert set(_statuses(client, headers={}).values()) == {401}
    assert 401 not in _statuses(client, headers={"X-API-Key": KEY}).values()


@pytest.mark.unit
def test_governance_routes_open_only_in_explicit_insecure_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ACGS_API_KEY", raising=False)
    client = TestClient(create_governance_app(require_auth=False))

    statuses = _statuses(client, headers={})

    assert 401 not in statuses.values(), statuses
    assert statuses[("GET", "/governance/audit-log")] == 200


@pytest.mark.unit
def test_unauthenticated_record_outcome_writes_no_audit_entry() -> None:
    client = TestClient(create_governance_app(api_key=KEY))
    headers = {"X-API-Key": KEY}
    before = client.get("/audit/count", headers=headers).json()["count"]

    resp = client.post(
        "/governance/record-outcome",
        json={
            "decision_id": "dec_001",
            "request_id": "req_1",
            "executor": {"actor_id": "agent/exec", "role": "executor", "sandbox_id": "sb"},
            "outcome_status": "succeeded",
            "result_hash": "sha256:abc",
            "summary": "done",
            "latency_ms": 5,
        },
    )

    assert resp.status_code == 401
    assert client.get("/audit/count", headers=headers).json()["count"] == before
