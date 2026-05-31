"""Tests for the LitServe integration.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import sys
import types
from unittest.mock import patch

import pytest

# Stub litserve (not installed) before importing GovernedLitAPI so the guard
# passes without requiring litserve in CI. fastapi IS installed, so we do NOT
# stub it — overwriting sys.modules["fastapi"] at module level would corrupt
# the import state for unrelated test modules collected in the same session.
_litserve_stub = types.ModuleType("litserve")


class _StubLitAPI:
    pass


_litserve_stub.LitAPI = _StubLitAPI
sys.modules.setdefault("litserve", _litserve_stub)
sys.modules["litserve"] = _litserve_stub

from fastapi import HTTPException as _HTTPException  # noqa: E402

from acgs_lite.constitution import Constitution, Rule, Severity  # noqa: E402
from acgs_lite.engine import GovernanceEngine  # noqa: E402
from acgs_lite.errors import MACIViolationError  # noqa: E402
from acgs_lite.integrations.litserve import LITSERVE_AVAILABLE, GovernedLitAPI  # noqa: E402
from acgs_lite.maci import MACIRole  # noqa: E402


def test_valid_request_passes_through() -> None:
    class ValidAPI(GovernedLitAPI):
        def model_setup(self, device: str) -> None:
            self.device = device

        def model_predict(self, request: dict[str, str]) -> dict[str, str]:
            return {"result": "ok"}

    api = ValidAPI(constitution=Constitution.default(), maci_role=MACIRole.VALIDATOR)
    api.setup(device="cpu")

    result = api.predict({"input": "hello world"})

    assert result == {"result": "ok"}


def test_input_violation_raises_422(monkeypatch: pytest.MonkeyPatch) -> None:
    import acgs_lite.integrations.litserve as litserve_mod

    class InputGuardAPI(GovernedLitAPI):
        def model_setup(self, device: str) -> None:
            self.device = device

        def model_predict(self, request: dict[str, str]) -> dict[str, str]:
            return {"result": "ok"}

    constitution = Constitution.from_rules(
        [
            Rule(
                id="NO-SSN",
                text="No SSN",
                severity=Severity.CRITICAL,
                keywords=["ssn"],
            )
        ]
    )
    monkeypatch.setattr(
        litserve_mod,
        "_CONSTITUTIONAL_HASH",
        GovernanceEngine(constitution)._const_hash,
    )
    api = InputGuardAPI(constitution=constitution, maci_role=MACIRole.VALIDATOR)
    api.setup(device="cpu")

    with pytest.raises(_HTTPException) as exc_info:
        api.predict({"input": "my ssn is 123-45-6789"})

    assert exc_info.value.status_code == 422


def test_output_violation_raises_422(monkeypatch: pytest.MonkeyPatch) -> None:
    import acgs_lite.integrations.litserve as litserve_mod

    class OutputGuardAPI(GovernedLitAPI):
        def model_setup(self, device: str) -> None:
            self.device = device

        def model_predict(self, request: dict[str, str]) -> dict[str, str]:
            return {"result": "the secret is here"}

    constitution = Constitution.from_rules(
        [
            Rule(
                id="NO-PII",
                text="No PII in output",
                severity=Severity.HIGH,
                keywords=["secret"],
            )
        ]
    )
    monkeypatch.setattr(
        litserve_mod,
        "_CONSTITUTIONAL_HASH",
        GovernanceEngine(constitution)._const_hash,
    )
    api = OutputGuardAPI(constitution=constitution, maci_role=MACIRole.VALIDATOR)
    api.setup(device="cpu")

    with pytest.raises(_HTTPException) as exc_info:
        api.predict({"input": "safe input"})

    assert exc_info.value.status_code == 422


def test_constitutional_hash_mismatch_raises_on_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    import acgs_lite.integrations.litserve as litserve_mod

    class HashGuardAPI(GovernedLitAPI):
        def model_setup(self, device: str) -> None:
            self.device = device

        def model_predict(self, request: dict[str, str]) -> dict[str, str]:
            return {"result": "ok"}

    monkeypatch.setattr(litserve_mod, "_CONSTITUTIONAL_HASH", "wronghash000000")
    api = HashGuardAPI(constitution=Constitution.default(), maci_role=MACIRole.VALIDATOR)

    with pytest.raises(RuntimeError, match="constitutional hash mismatch"):
        api.setup(device="cpu")


def test_unexpected_exception_raises_500() -> None:
    class BoomAPI(GovernedLitAPI):
        def model_setup(self, device: str) -> None:
            self.device = device

        def model_predict(self, request: dict[str, str]) -> dict[str, str]:
            raise ValueError("boom")

    api = BoomAPI(constitution=Constitution.default(), maci_role=MACIRole.VALIDATOR)
    api.setup(device="cpu")

    with pytest.raises(_HTTPException) as exc_info:
        api.predict({"input": "safe input"})

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail["error"] == "governance_error"


def test_maci_validator_role_enforced() -> None:
    class MACIAPI(GovernedLitAPI):
        def model_setup(self, device: str) -> None:
            self.device = device

        def model_predict(self, request: dict[str, str]) -> dict[str, str]:
            return {"result": "ok"}

    api = MACIAPI(
        constitution=Constitution.default(),
        maci_role=MACIRole.VALIDATOR,
    )
    api.setup(device="cpu")

    assert api._maci is not None
    with (
        pytest.raises(_HTTPException) as exc_info,
        patch.object(
            api._maci,
            "check",
            side_effect=MACIViolationError(
                "blocked",
                actor_role=MACIRole.VALIDATOR.value,
                attempted_action="execute",
            ),
        ),
    ):
        api.predict({"input": "safe"})

    assert exc_info.value.status_code == 403


def test_audit_entries_populated() -> None:
    class AuditAPI(GovernedLitAPI):
        def model_setup(self, device: str) -> None:
            self.device = device

        def model_predict(self, request: dict[str, str]) -> dict[str, str]:
            return {"result": "ok"}

    api = AuditAPI(constitution=Constitution.default(), maci_role=MACIRole.VALIDATOR)
    api.setup(device="cpu")
    api.predict({"input": "hello world"})

    assert len(api.audit_entries) > 0


def test_no_litserve_guard() -> None:
    assert LITSERVE_AVAILABLE is True
    assert GovernedLitAPI is not object
