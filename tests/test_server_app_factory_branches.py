"""create_governance_app factory flags, validation errors and audit-store wiring."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

import acgs_lite.server as server_mod  # noqa: E402
from acgs_lite.audit import AuditEntry  # noqa: E402
from acgs_lite.cdp.record import CDPRecordV1  # noqa: E402
from acgs_lite.cdp.store import InMemoryCDPBackend  # noqa: E402
from acgs_lite.constitution import Constitution, Rule, Severity  # noqa: E402
from acgs_lite.integrations.openshell_governance import (  # noqa: E402
    ActionContext,
    ActionEnvelope,
    ActionPayloadSummary,
    ActionRequirements,
    ActionType,
    ActorRef,
    ActorRole,
    ExecutionOutcome,
    OperationType,
    OutcomeStatus,
    ResourceRef,
    RiskLevel,
)
from acgs_lite.server import _AuditStoreAdapter, create_governance_app  # noqa: E402

KEY = "top-secret"
HDR = {"X-API-Key": KEY}


class _RecordingAuditStore:
    def __init__(self, path: Any = None) -> None:
        self.path = path
        self.verify_calls = 0
        self._entries: list[AuditEntry] = []

    def append(self, entry: AuditEntry) -> str:
        self._entries.append(entry)
        return entry.id

    def get(self, entry_id: str) -> AuditEntry | None:
        return next((e for e in self._entries if e.id == entry_id), None)

    def list_entries(
        self, *, limit: int = 100, offset: int = 0, agent_id: str | None = None
    ) -> list[AuditEntry]:
        entries = self._entries
        if agent_id is not None:
            entries = [e for e in entries if e.agent_id == agent_id]
        return entries[offset : offset + limit]

    def count(self) -> int:
        return len(self._entries)

    def verify_chain(self) -> bool:
        self.verify_calls += 1
        return True


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ACGS_API_KEY",
        "ACGS_EVENTS_ENABLED",
        "ACGS_LIFECYCLE_ENABLED",
        "ACGS_FEDERATION_ENABLED",
        "AUTONOMA_ENV_FACTORY_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)


def _make_action() -> ActionEnvelope:
    return ActionEnvelope(
        action_type=ActionType.GITHUB_WRITE,
        operation=OperationType.READ,
        risk_level=RiskLevel.LOW,
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
        context=ActionContext(request_id="req_123", session_id="sess_456", environment="prod"),
        requirements=ActionRequirements(
            requires_network=False, requires_secret=False, mutates_state=False
        ),
        payload=ActionPayloadSummary(
            payload_hash="sha256:abcd1234",
            summary="Read issues.",
            content_type="application/json",
            size_bytes=16,
        ),
        tags=["read"],
    )


# --- audit store wiring -------------------------------------------------------


@pytest.mark.unit
def test_custom_audit_store_backs_stats_and_chain() -> None:
    store = _RecordingAuditStore()
    client = TestClient(create_governance_app(audit_store=store, api_key=KEY))

    assert (
        client.post(
            "/validate", headers=HDR, json={"action": "draft note", "agent_id": "a1"}
        ).status_code
        == 200
    )

    stats = client.get("/stats", headers=HDR)
    assert stats.status_code == 200
    body = stats.json()
    assert body["total_validations"] == 1
    assert body["audit_entry_count"] == 1
    assert body["audit_chain_valid"] is True
    assert store.verify_calls >= 1

    chain = client.get("/audit/chain", headers=HDR)
    assert chain.status_code == 200
    assert chain.json() == {"valid": True, "entry_count": 1}


@pytest.mark.unit
def test_record_outcome_writes_through_custom_audit_store() -> None:
    store = _RecordingAuditStore()
    client = TestClient(create_governance_app(audit_store=store, api_key=KEY))
    outcome = ExecutionOutcome(
        decision_id="dec_001",
        request_id="req_1",
        executor=ActorRef(actor_id="agent/exec", role=ActorRole.EXECUTOR, sandbox_id="sb"),
        outcome_status=OutcomeStatus.SUCCEEDED,
        result_hash="sha256:abc",
        summary="done",
        latency_ms=5,
    )

    resp = client.post(
        "/governance/record-outcome", headers=HDR, json=outcome.model_dump(mode="json")
    )

    assert resp.status_code == 201
    assert resp.json()["details"]["audit_chain_valid"] is True
    assert store.count() == 1
    assert store.verify_calls >= 1


@pytest.mark.unit
def test_audit_store_adapter_len_contract_matches_store_count() -> None:
    # No HTTP route reaches __len__: this is an adapter contract test, not route coverage.
    store = _RecordingAuditStore()
    client = TestClient(create_governance_app(audit_store=store, api_key=KEY))
    for action in ("first note", "second note"):
        client.post("/validate", headers=HDR, json={"action": action})
    assert store.count() == 2

    assert len(_AuditStoreAdapter(store)) == store.count()


@pytest.mark.unit
def test_external_audit_store_is_built_from_acgs_module(tmp_path: Path) -> None:
    created: list[_RecordingAuditStore] = []

    def factory(path: Any) -> _RecordingAuditStore:
        store = _RecordingAuditStore(path)
        created.append(store)
        return store

    fake_module = types.SimpleNamespace(SQLiteAuditStore=factory)
    db_path = tmp_path / "a.db"
    with patch("acgs_lite.server.import_module", return_value=fake_module) as mock_import:
        client = TestClient(
            create_governance_app(
                enable_external_acgs_audit_store=True, audit_db_path=db_path, api_key=KEY
            )
        )
        assert (
            client.post("/validate", headers=HDR, json={"action": "draft note"}).status_code == 200
        )
        count = client.get("/audit/count", headers=HDR)

    assert count.json() == {"count": 1}
    mock_import.assert_called_with("acgs.audit_sqlite")
    assert len(created) == 1
    assert created[0].path == db_path


@pytest.mark.unit
def test_external_audit_module_without_store_falls_back_to_memory(tmp_path: Path) -> None:
    with patch("acgs_lite.server.import_module", return_value=types.SimpleNamespace()):
        client = TestClient(
            create_governance_app(
                enable_external_acgs_audit_store=True,
                audit_db_path=tmp_path / "a.db",
                api_key=KEY,
            )
        )
        assert (
            client.post("/validate", headers=HDR, json={"action": "draft note"}).status_code == 200
        )
        chain = client.get("/audit/chain", headers=HDR)

    assert chain.json() == {"valid": True, "entry_count": 1}


# --- request validation -------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("payload", "detail"),
    [
        pytest.param({"action": ""}, "'action' must be a non-empty string", id="empty-action"),
        pytest.param(
            {"action": "x", "agent_id": 5}, "'agent_id' must be a string", id="agent-id-int"
        ),
        pytest.param(
            {"action": "x", "context": []}, "'context' must be an object", id="context-list"
        ),
    ],
)
def test_validate_rejects_malformed_input(payload: dict[str, Any], detail: str) -> None:
    client = TestClient(create_governance_app(api_key=KEY))

    resp = client.post("/validate", headers=HDR, json=payload)

    assert resp.status_code == 422
    assert resp.json()["detail"] == detail


@pytest.mark.unit
def test_rules_reject_invalid_severity_without_changing_state() -> None:
    constitution = Constitution.from_rules(
        [Rule(id="R-1", text="No foo", severity=Severity.HIGH, keywords=["foo"])]
    )
    client = TestClient(create_governance_app(constitution, api_key=KEY))

    created = client.post(
        "/rules", headers=HDR, json={"id": "R-2", "text": "t", "severity": "bogus"}
    )
    assert created.status_code == 422
    assert client.get("/rules/R-2", headers=HDR).status_code == 404

    updated = client.put("/rules/R-1", headers=HDR, json={"severity": "bogus"})
    assert updated.status_code == 422
    current = client.get("/rules/R-1", headers=HDR)
    assert current.status_code == 200
    assert current.json()["severity"] == "high"


# --- CDP certificate ----------------------------------------------------------


@pytest.mark.unit
def test_cdp_certificate_missing_record_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server_mod, "_cdp_backend", InMemoryCDPBackend())
    client = TestClient(create_governance_app(api_key=KEY))

    resp = client.get("/cdp/records/missing/certificate", headers=HDR)

    assert resp.status_code == 404
    assert "missing" in resp.json()["detail"]


@pytest.mark.unit
def test_cdp_certificate_import_guard_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exercises the route's import guard for acgs_lite.cdp.certificate (a None
    # sys.modules entry forces ImportError); it does not model an install without fpdf2.
    backend = InMemoryCDPBackend()
    record = CDPRecordV1(cdp_id="cert-1", tenant_id="default")
    record.finalize()
    backend.save(record)
    monkeypatch.setattr(server_mod, "_cdp_backend", backend)
    monkeypatch.setitem(sys.modules, "acgs_lite.cdp.certificate", None)
    client = TestClient(create_governance_app(api_key=KEY))

    resp = client.get("/cdp/records/cert-1/certificate", headers=HDR)

    assert resp.status_code == 503
    assert "fpdf2" in resp.json()["detail"]


# --- optional routers ---------------------------------------------------------


@pytest.mark.unit
def test_openshell_experimental_flag_disables_router() -> None:
    disabled = TestClient(create_governance_app(include_openshell_experimental=False, api_key=KEY))
    enabled_app = create_governance_app(api_key=KEY)

    resp = disabled.post(
        "/governance/evaluate-action", headers=HDR, json=_make_action().model_dump(mode="json")
    )

    assert resp.status_code == 404
    assert "/governance/evaluate-action" in enabled_app.openapi()["paths"]


@pytest.mark.unit
def test_openshell_state_path_persists_decisions(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    client = TestClient(create_governance_app(openshell_state_path=state_path, api_key=KEY))

    resp = client.post(
        "/governance/evaluate-action", headers=HDR, json=_make_action().model_dump(mode="json")
    )

    assert resp.status_code == 200
    decision_id = resp.json()["decision_id"]
    assert state_path.exists()
    assert decision_id in state_path.read_text()


@pytest.mark.unit
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "openshell governance router is mounted without the API-key dependency "
        "(server.py include_router ~796); create_governance_app docstring promises "
        "the key guards all mutating endpoints"
    ),
)
def test_openshell_record_outcome_requires_api_key() -> None:
    client = TestClient(create_governance_app(api_key=KEY))
    outcome = ExecutionOutcome(
        decision_id="dec_001",
        request_id="req_1",
        executor=ActorRef(actor_id="agent/exec", role=ActorRole.EXECUTOR, sandbox_id="sb"),
        outcome_status=OutcomeStatus.SUCCEEDED,
        result_hash="sha256:abc",
        summary="done",
        latency_ms=5,
    )
    if "/governance/record-outcome" not in client.app.openapi()["paths"]:
        pytest.fail("openshell governance router is not mounted; precondition not met")

    resp = client.post("/governance/record-outcome", json=outcome.model_dump(mode="json"))

    assert resp.status_code in (401, 403)


@pytest.mark.unit
def test_autonoma_router_mounted_and_requires_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTONOMA_ENV_FACTORY_ENABLED", "1")
    client = TestClient(create_governance_app(include_autonoma=True, api_key=KEY))

    resp = client.post("/api/autonoma", content="{}")

    assert resp.status_code == 401
    assert resp.json()["detail"] == "Missing x-signature header"


@pytest.mark.unit
def test_telegram_requires_webhook_path_secret() -> None:
    with pytest.raises(ValueError, match="telegram_webhook_path_secret is required"):
        create_governance_app(include_telegram=True, api_key=KEY)
