"""Tests for FastAPI governance microservice wrapper."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any, cast
from unittest.mock import patch

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from acgs_lite import Constitution, Rule, Severity
from acgs_lite.audit import AuditEntry
from acgs_lite.server import create_governance_app

try:  # FastAPI >= 0.138 defers router inclusion behind lazy wrappers
    from fastapi.routing import iter_route_contexts as _iter_route_contexts
except ImportError:  # older FastAPI flattens included routes into app.routes
    _iter_route_contexts = None


def _iter_api_routes(app: Any) -> Iterator[Any]:
    """Yield API-route-like objects (with ``.path``/``.endpoint``) for ``app``.

    Works with both the legacy flattened ``app.routes`` layout and FastAPI 0.138+,
    which stores included routers as lazy ``_IncludedRouter`` wrappers.
    """
    if _iter_route_contexts is not None:
        for ctx in _iter_route_contexts(app.routes):
            if isinstance(ctx.original_route, APIRoute):
                yield ctx
    else:
        for route in app.routes:
            if isinstance(route, APIRoute):
                yield route


class _DummyAuditStore:
    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def append(self, entry: AuditEntry) -> str:
        self._entries.append(entry)
        return entry.id

    def get(self, entry_id: str) -> AuditEntry | None:
        for entry in self._entries:
            if entry.id == entry_id:
                return entry
        return None

    def list_entries(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        agent_id: str | None = None,
    ) -> list[AuditEntry]:
        entries = self._entries
        if agent_id is not None:
            entries = [entry for entry in entries if entry.agent_id == agent_id]
        return entries[offset : offset + limit]

    def count(self) -> int:
        return len(self._entries)

    def verify_chain(self) -> bool:
        return True


@pytest.mark.unit
class TestGovernanceServer:
    @staticmethod
    def _make_app(
        tmp_path: Any,
        constitution: Constitution | None = None,
    ) -> Any:
        return create_governance_app(
            constitution if constitution is not None else Constitution.default(),
            audit_db_path=tmp_path / "audit.db",
            require_auth=False,
        )

    @staticmethod
    def _route_endpoint(app: Any, path: str) -> Callable[..., dict[str, Any]]:
        for route in _iter_api_routes(app):
            if route.path == path:
                return cast(Callable[..., dict[str, Any]], route.endpoint)
        raise AssertionError(f"Route {path!r} not found")

    def test_validate_endpoint_allows_safe_action(self, tmp_path: Any) -> None:
        app = self._make_app(tmp_path)
        validate = self._route_endpoint(app, "/validate")
        data = validate({"action": "deploy to staging"})
        assert data["valid"] is True
        assert data["rules_checked"] >= 1

    def test_validate_endpoint_reports_violation(self, tmp_path: Any) -> None:
        constitution = Constitution.from_rules(
            [
                Rule(
                    id="S-001",
                    text="No self approval",
                    severity=Severity.CRITICAL,
                    keywords=["self-approve"],
                )
            ]
        )
        app = self._make_app(tmp_path, constitution)
        validate = self._route_endpoint(app, "/validate")
        data = validate({"action": "self-approve merge"})
        assert data["valid"] is False
        assert any(v["rule_id"] == "S-001" for v in data["violations"])

    def test_stats_endpoint_reports_validation_count(self, tmp_path: Any) -> None:
        app = self._make_app(tmp_path)
        validate = self._route_endpoint(app, "/validate")
        get_stats = self._route_endpoint(app, "/stats")

        validate({"action": "safe action one"})
        validate({"action": "safe action two"})

        stats = get_stats()
        assert stats["total_validations"] >= 2
        assert stats["audit_entry_count"] >= 2
        assert "audit_chain_valid" in stats  # presence check (value may differ in fast audit mode)
        assert "constitutional_hash" in stats

    def test_audit_endpoints_expose_entries_count_and_chain(self, tmp_path: Any) -> None:
        app = self._make_app(tmp_path)
        client = TestClient(app)

        client.post("/validate", json={"action": "draft note", "agent_id": "alpha"})
        client.post("/validate", json={"action": "publish note", "agent_id": "beta"})

        count_response = client.get("/audit/count")
        assert count_response.status_code == 200
        assert count_response.json() == {"count": 2}

        chain_response = client.get("/audit/chain")
        assert chain_response.status_code == 200
        chain_data = chain_response.json()
        assert "valid" in chain_data
        assert chain_data["entry_count"] == 2

        filtered_response = client.get(
            "/audit/entries", params={"agent_id": "alpha", "limit": 10, "offset": 0}
        )
        assert filtered_response.status_code == 200
        entries = filtered_response.json()
        assert len(entries) == 1
        assert entries[0]["agent_id"] == "alpha"
        assert entries[0]["action"] == "draft note"

    def test_custom_audit_store_is_used_when_provided(self) -> None:
        app = create_governance_app(audit_store=_DummyAuditStore(), require_auth=False)
        client = TestClient(app)

        client.post("/validate", json={"action": "approve change", "agent_id": "store-agent"})

        count_response = client.get("/audit/count")
        assert count_response.status_code == 200
        assert count_response.json() == {"count": 1}

        entries_response = client.get("/audit/entries", params={"agent_id": "store-agent"})
        assert entries_response.status_code == 200
        assert len(entries_response.json()) == 1

    def test_external_acgs_audit_store_is_opt_in(self, tmp_path: Any) -> None:
        with patch("acgs_lite.server.import_module") as import_module_mock:
            app = create_governance_app(audit_db_path=tmp_path / "audit.db", require_auth=False)
            client = TestClient(app)
            response = client.get("/audit/count")

        assert response.status_code == 200
        assert response.json() == {"count": 0}
        import_module_mock.assert_not_called()

    def test_external_acgs_audit_store_attempted_when_enabled(self, tmp_path: Any) -> None:
        with patch("acgs_lite.server.import_module", side_effect=ImportError):
            app = create_governance_app(
                audit_db_path=tmp_path / "audit.db",
                enable_external_acgs_audit_store=True,
                require_auth=False,
            )
            client = TestClient(app)
            response = client.get("/audit/count")

        assert response.status_code == 200
        assert response.json() == {"count": 0}

    def test_app_mounts_experimental_openshell_routes_by_default(self, tmp_path: Any) -> None:
        app = self._make_app(tmp_path)
        evaluate = self._route_endpoint(app, "/governance/evaluate-action")
        assert callable(evaluate)

    def test_lifecycle_env_flag_parses_false_values(self, tmp_path: Any) -> None:
        with patch.dict("os.environ", {"ACGS_LIFECYCLE_ENABLED": "false"}, clear=False):
            app = create_governance_app(audit_db_path=tmp_path / "audit.db", require_auth=False)

        with pytest.raises(AssertionError):
            self._route_endpoint(app, "/constitution/lifecycle/draft")

    def test_lifecycle_env_flag_parses_true_values(self, tmp_path: Any) -> None:
        with patch.dict("os.environ", {"ACGS_LIFECYCLE_ENABLED": "yes"}, clear=False):
            app = create_governance_app(audit_db_path=tmp_path / "audit.db", require_auth=False)

        draft = self._route_endpoint(app, "/constitution/lifecycle/draft")
        assert callable(draft)
