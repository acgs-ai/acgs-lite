"""Refusal paths of the lifecycle HTTP router, driven through TestClient.

Every refused request must map to its error envelope and leave the bundle
store exactly as it was (fail closed: a refusal never changes state).
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from acgs_lite.constitution.bundle_store import InMemoryBundleStore  # noqa: E402
from acgs_lite.constitution.evidence import InMemoryLifecycleAuditSink  # noqa: E402
from acgs_lite.constitution.lifecycle_router import create_lifecycle_router  # noqa: E402
from acgs_lite.constitution.lifecycle_service import ConstitutionLifecycle  # noqa: E402

pytestmark = pytest.mark.unit

BASE = "/constitution/lifecycle"


def _headers(actor: str) -> dict[str, str]:
    return {"X-API-Key": "k", "X-Actor-ID": actor}


def _client(lifecycle: ConstitutionLifecycle, **tc_kw: Any) -> TestClient:
    app = FastAPI()
    app.include_router(create_lifecycle_router(lifecycle, api_key="k"))
    return TestClient(app, **tc_kw)


def _lifecycle() -> tuple[ConstitutionLifecycle, InMemoryBundleStore]:
    store = InMemoryBundleStore()
    return ConstitutionLifecycle(store=store, sink=InMemoryLifecycleAuditSink()), store


def test_actor_header_over_256_chars_rejected() -> None:
    lifecycle, store = _lifecycle()
    client = _client(lifecycle)

    resp = client.post(f"{BASE}/draft", json={"tenant_id": "t"}, headers=_headers("a" * 257))

    assert resp.status_code == 400
    assert resp.json()["detail"] == {
        "error": "X-Actor-ID value exceeds 256 characters",
        "code": "ACTOR_TOO_LONG",
        "bundle_id": None,
    }
    assert store.list_bundles("t") == []


@pytest.mark.parametrize(
    ("endpoint", "body", "actor", "status", "code"),
    [
        ("approve", {"signature": "sig"}, "proposer-1", 400, "LIFECYCLE_ERROR"),
        ("stage", None, "proposer-1", 400, "INVALID_TRANSITION"),
        ("activate", None, "proposer-1", 400, "INVALID_TRANSITION"),
        ("rollback", {}, "proposer-1", 400, "INVALID_TRANSITION"),
        ("reject", {}, "validator-1", 400, "INVALID_TRANSITION"),
        ("withdraw", {}, "validator-1", 403, "MACI_VIOLATION"),
    ],
)
def test_refused_transition_on_draft_maps_to_400_or_403(
    endpoint: str, body: dict[str, Any] | None, actor: str, status: int, code: str
) -> None:
    lifecycle, store = _lifecycle()
    client = _client(lifecycle)
    created = client.post(f"{BASE}/draft", json={"tenant_id": "t1"}, headers=_headers("proposer-1"))
    assert created.status_code == 200
    bundle_id = created.json()["bundle_id"]

    kwargs: dict[str, Any] = {"headers": _headers(actor)}
    if body is not None:
        kwargs["json"] = body
    resp = client.post(f"{BASE}/{bundle_id}/{endpoint}", **kwargs)

    assert resp.status_code == status
    detail = resp.json()["detail"]
    assert detail["code"] == code
    assert detail["bundle_id"] == bundle_id
    if endpoint == "approve":
        assert "cannot be the same actor as the proposer" in detail["error"]
    if endpoint == "withdraw":
        assert detail["error"] == "Only the original proposer may withdraw a bundle"

    # The refused transition had no side effect.
    after = client.get(f"{BASE}/{bundle_id}", headers=_headers(actor))
    assert after.status_code == 200
    assert after.json()["status"] == "draft"
    assert after.json()["status_history"] == []
    assert len(store.list_bundles("t1")) == 1


def test_unexpected_lifecycle_error_is_not_swallowed() -> None:
    store = InMemoryBundleStore()

    class _StoreOffline(ConstitutionLifecycle):
        async def create_draft(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("store offline")

    lifecycle = _StoreOffline(store=store, sink=InMemoryLifecycleAuditSink())

    with pytest.raises(RuntimeError, match="store offline"):
        _client(lifecycle).post(f"{BASE}/draft", json={"tenant_id": "t"}, headers=_headers("p"))

    resp = _client(lifecycle, raise_server_exceptions=False).post(
        f"{BASE}/draft", json={"tenant_id": "t"}, headers=_headers("p")
    )
    assert resp.status_code == 500
    assert "bundle_id" not in resp.text
    assert store.list_bundles("t") == []
