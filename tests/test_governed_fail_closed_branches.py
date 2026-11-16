"""GovernedAgent / GovernedCallable: agent-protocol refusals, CDP degradation
paths and production fail-closed raises (the wrapped callable never runs)."""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Iterator
from typing import Any, cast

import pytest

import acgs_lite.governed as governed_mod
from acgs_lite import GovernedAgent, MACIRole
from acgs_lite.audit import AuditLog, JSONLAuditBackend
from acgs_lite.cdp.store import InMemoryCDPBackend
from acgs_lite.compliance.runtime_checker import RuntimeComplianceChecker
from acgs_lite.compliance.runtime_obligations import (
    ObligationSeverity,
    ObligationType,
    RuntimeObligation,
)
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.errors import GovernanceError
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import (
    AuthorizationProfile,
    LegitimacyInvariantError,
    TrustedExecutionContext,
)
from acgs_lite.legitimacy.ledger import AttemptStatus
from acgs_lite.provider_capabilities import (
    CapabilityLevel,
    CapabilityStability,
    CapabilitySupportLevel,
    ProviderCapabilityProfile,
    RequestShape,
    reset_capability_registry,
)

pytest.importorskip("cryptography")
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner, SignedReceipt  # noqa: E402

pytestmark = [pytest.mark.unit]

GOVERNED_LOGGER = "acgs_lite.governed"


def ga(agent: Any, **kw: Any) -> GovernedAgent:
    kw.setdefault("agent_id", "a1")
    return GovernedAgent(agent, maci_role=MACIRole.EXECUTOR, **kw)


def plain(input: str, **kwargs: Any) -> str:
    return f"plain:{input}"


def _raiser(exc: BaseException) -> Any:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise exc

    return fail


# -- agent protocol --------------------------------------------------------


def test_run_refuses_agent_without_protocol() -> None:
    with pytest.raises(GovernanceError, match="is not callable") as excinfo:
        ga(object()).run("hello", governance_action="execute")
    assert excinfo.value.rule_id == "AGENT-PROTOCOL"


def test_arun_refuses_agent_without_protocol() -> None:
    with pytest.raises(GovernanceError, match="is not callable") as excinfo:
        asyncio.run(ga(object()).arun("hello", governance_action="execute"))
    assert excinfo.value.rule_id == "AGENT-PROTOCOL"


class AsyncRunAgent:
    async def run(self, input: str, **kwargs: Any) -> str:
        return f"async-run:{input}"


class SyncRunAgent:
    def run(self, input: str, **kwargs: Any) -> str:
        return f"sync-run:{input}"


@pytest.mark.parametrize(
    ("agent", "expected"),
    [
        (AsyncRunAgent(), "async-run:hi"),
        (SyncRunAgent(), "sync-run:hi"),
        (plain, "plain:hi"),
    ],
    ids=["async-run", "sync-run", "plain-callable"],
)
def test_arun_dispatches_each_agent_shape(agent: Any, expected: str) -> None:
    assert asyncio.run(ga(agent).arun("hi", governance_action="execute")) == expected


# -- capability profile discovery ------------------------------------------


@pytest.fixture()
def _clean_capability_registry() -> Iterator[None]:
    reset_capability_registry()
    yield
    reset_capability_registry()


def _profile() -> ProviderCapabilityProfile:
    return ProviderCapabilityProfile(
        provider_id="openai-test",
        model_id="gpt-4o",
        display_name="gpt-4o",
        provider_type="openai",
        structured_output=CapabilityLevel.FULL,
        support_level=CapabilitySupportLevel.DOCUMENTED,
        request_shape=RequestShape.OPENAI_RESPONSE_FORMAT_JSON_SCHEMA,
        evidence_source="test://fixture",
        checked_at="2026-04-08",
        stability=CapabilityStability.STABLE,
    )


class ProfiledAgent:
    capability_profile = _profile()

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, input: str, **kwargs: Any) -> str:
        self.calls.append(dict(kwargs))
        return "ok"


@pytest.mark.usefixtures("_clean_capability_registry")
def test_capability_profile_is_discovered_on_the_agent() -> None:
    agent = ProfiledAgent()
    governed = GovernedAgent(
        agent,
        constitution=Constitution.from_rules(
            [
                Rule(
                    id="STATE",
                    text="State must be approved or rejected.",
                    severity=Severity.HIGH,
                    keywords=["approved", "rejected"],
                )
            ]
        ),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    assert governed.run("safe input", governance_action="execute") == "ok"
    response_format = cast(dict[str, Any], agent.calls[0]["response_format"])
    assert response_format["type"] == "json_schema"


# -- CDP emission degradation (observability only; decision already made) ----


def test_cdp_falls_back_when_server_backend_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("ACGS_CDP_ENABLED", "true")
    monkeypatch.setitem(sys.modules, "acgs_lite.server", None)
    caplog.set_level(logging.DEBUG, logger=GOVERNED_LOGGER)

    assert ga(plain).run("hi", governance_action="execute") == "plain:hi"
    assert "server backend unavailable" in caplog.text


def test_cdp_uses_the_server_backend_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    import acgs_lite.server as server_mod

    backend = InMemoryCDPBackend()
    monkeypatch.setattr(server_mod, "_cdp_backend", backend)
    monkeypatch.setenv("ACGS_CDP_ENABLED", "true")

    assert ga(plain, agent_id="server-backend-probe").run("hi", governance_action="execute") == (
        "plain:hi"
    )
    assert [record.subject_id for record in backend.save_calls] == ["server-backend-probe"]


def test_unsatisfied_blocking_obligation_escalates_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    obligation = RuntimeObligation(
        ObligationType.HITL_REQUIRED,
        "eu_ai_act",
        "EU-AIA Art.14(1)",
        "hitl",
        satisfied=False,
        severity=ObligationSeverity.BLOCKING,
    )
    monkeypatch.setattr(RuntimeComplianceChecker, "check", lambda self, ctx: [obligation])
    backend = InMemoryCDPBackend()

    assert ga(plain, cdp_backend=backend).run("hi", governance_action="execute") == "plain:hi"
    assert backend.save_calls[0].verdict == "conditional"


def _crashing_checker(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []

    def check(self: Any, ctx: dict[str, Any]) -> Any:
        seen.append(ctx)
        raise RuntimeError("checker down")

    monkeypatch.setattr(RuntimeComplianceChecker, "check", check)
    return seen


def test_compliance_checker_crash_still_emits_and_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    seen = _crashing_checker(monkeypatch)
    backend = InMemoryCDPBackend()
    caplog.set_level(logging.ERROR, logger=GOVERNED_LOGGER)

    assert ga(plain, cdp_backend=backend).run("hi", governance_action="execute") == "plain:hi"
    assert len(seen) == 1
    assert backend.count() == 1
    assert "runtime compliance check failed" in caplog.text


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="compliance checker crash recorded as allow; should be 'error'",
)
def test_compliance_checker_crash_is_not_recorded_as_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _crashing_checker(monkeypatch)
    backend = InMemoryCDPBackend()

    ga(plain, cdp_backend=backend).run("hi", governance_action="execute")
    # Setup guards raise Failed (not AssertionError), so a broken setup is a real failure.
    if len(seen) != 1:
        pytest.fail("the crashing compliance checker was never called")
    if backend.count() != 1:
        pytest.fail("no CDP record was saved")
    assert backend.save_calls[0].verdict != "allow"


def test_intervention_handler_crash_is_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    evaluated: list[dict[str, Any]] = []

    class CrashingInterventions:
        def evaluate(self, record: dict[str, Any]) -> None:
            evaluated.append(record)
            raise RuntimeError("handler down")

    backend = InMemoryCDPBackend()
    caplog.set_level(logging.ERROR, logger=GOVERNED_LOGGER)
    governed = ga(plain, cdp_backend=backend, intervention_engine=CrashingInterventions())

    assert governed.run("hi", governance_action="execute") == "plain:hi"
    assert len(evaluated) == 1 and backend.count() == 1
    assert "intervention handler failed" in caplog.text


def test_cdp_backend_save_failure_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    saved: list[Any] = []

    class FailingBackend:
        def save(self, record: Any) -> None:
            saved.append(record)
            raise OSError("disk full")

    caplog.set_level(logging.ERROR, logger=GOVERNED_LOGGER)

    assert ga(plain, cdp_backend=FailingBackend()).run("hi", governance_action="execute") == (
        "plain:hi"
    )
    assert len(saved) == 1
    assert "emission failed" in caplog.text


# -- GovernedCallable production fail-closed raises -------------------------


def _production_signing() -> dict[str, object]:
    """Pinned, non-ephemeral Ed25519 execution signer the production profile requires."""
    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    return {
        "receipt_signer": signer,
        "trusted_execution_keys": {signer.key_id: signer.public_key_hex()},
    }


def _guard(**kwargs: Any) -> GovernedCallable:
    return GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        **_production_signing(),
        **kwargs,
    )


def _charge(guard: GovernedCallable, calls: list[Any]) -> Any:
    @guard
    def charge(amount: int) -> str:
        calls.append(amount)
        return f"charged:{amount}"

    return charge


def test_required_durable_audit_needs_durable_backend() -> None:
    with pytest.raises(LegitimacyInvariantError, match="durable backend"):
        _guard(audit_log=AuditLog(), require_durable_audit=True)


def test_withdrawn_trusted_context_is_refused() -> None:
    calls: list[str] = []
    guard = _guard(
        trusted_execution_context=TrustedExecutionContext(
            actor_id="authenticated-host-actor",
            scope="tenant-a",
            allowed_subjects=frozenset({"account-1"}),
        ),
        require_trusted_context=True,
    )

    @guard
    def action(account_id: str, *, tenant_id: str = "tenant-a") -> str:
        calls.append(account_id)
        return account_id

    grant = action.issue_grant("account-1")
    guard.trusted_execution_context = None  # withdrawn after construction

    with pytest.raises(
        LegitimacyInvariantError, match="required trusted execution context is missing"
    ):
        action("account-1", execution_grant=grant)
    assert calls == []


def test_raw_human_approval_is_refused_in_production() -> None:
    calls: list[int] = []
    charge = _charge(_guard(), calls)
    grant = charge.issue_grant(10)

    with pytest.raises(LegitimacyInvariantError, match="raw human_approval is not executable"):
        charge(10, execution_grant=grant, human_approval={"approver": "x"})
    assert calls == []


@pytest.mark.parametrize(
    "guard_factory",
    [_guard, lambda: GovernedCallable(Constitution.default())],
    ids=["production", "compat"],
)
def test_non_grant_object_is_refused(guard_factory: Any) -> None:
    calls: list[int] = []
    charge = _charge(guard_factory(), calls)

    with pytest.raises(LegitimacyInvariantError, match="Invalid execution grant type"):
        charge(10, execution_grant="not-a-grant")
    assert calls == []


def test_grant_release_failure_disables_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    guard = _guard()
    charge = _charge(guard, calls)
    grant = charge.issue_grant(10)

    with monkeypatch.context() as m:
        m.setattr(guard, "_release_signed_grant", _raiser(RuntimeError("release")))
        m.setattr(guard._ledger, "finalize", _raiser(OSError("ledger offline")))
        with pytest.raises(RuntimeError, match="release"):
            charge(10, execution_grant=grant, execution_attempt_id="a1")
    assert calls == []
    assert guard._execution_disabled is True

    # Disabled is sticky: no new grant is minted and the old one cannot run.
    with pytest.raises(LegitimacyInvariantError, match="disabled"):
        charge.issue_grant(10)
    with pytest.raises(LegitimacyInvariantError, match="disabled"):
        charge(10, execution_grant=grant, execution_attempt_id="a2")
    assert calls == []


def test_undigestible_result_is_reported_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    guard = _guard()

    @guard
    def op() -> dict[str, bool]:
        calls.append(1)
        return {"ok": True}

    grant = op.issue_grant()
    monkeypatch.setattr(governed_mod, "digest_output", lambda value: None)

    with pytest.raises(LegitimacyInvariantError, match="result is unknown") as excinfo:
        op(execution_grant=grant, execution_attempt_id="o1")
    assert str(excinfo.value.__cause__) == "side-effect result cannot be digested"
    assert calls == [1]
    assert guard._ledger._attempts["o1"].status is AttemptStatus.PARTIAL


def test_interrupt_during_durable_completion_disables_execution(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    audit = AuditLog(backend=JSONLAuditBackend(tmp_path / "a.jsonl"))
    guard = _guard(audit_log=audit, require_durable_audit=True)
    charge = _charge(guard, calls)
    grant = charge.issue_grant(10)
    real_record_durable = audit.record_durable

    def record_durable(entry: Any, *args: Any, **kwargs: Any) -> Any:
        # The pre-execution entry is written; only the completion confirmation is cut.
        if entry.type == "execution_completed":
            raise KeyboardInterrupt
        return real_record_durable(entry, *args, **kwargs)

    monkeypatch.setattr(audit, "record_durable", record_durable)
    monkeypatch.setattr(guard._ledger, "mark_unknown", _raiser(OSError("ledger offline")))

    with pytest.raises(KeyboardInterrupt):
        charge(10, execution_grant=grant, execution_attempt_id="k1")
    assert calls == [10]
    assert guard._execution_disabled is True


@pytest.mark.parametrize("attempt_id", ["", 7], ids=["empty", "non-string"])
def test_malformed_attempt_id_is_refused(attempt_id: object) -> None:
    calls: list[int] = []
    charge = _charge(_guard(), calls)
    grant = charge.issue_grant(10)

    with pytest.raises(
        LegitimacyInvariantError, match="execution_attempt_id must be a non-empty string"
    ):
        charge(10, execution_grant=grant, execution_attempt_id=attempt_id)
    assert calls == []


def test_signature_verification_error_fails_authenticity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    charge = _charge(_guard(), calls)
    grant = charge.issue_grant(10)
    monkeypatch.setattr(SignedReceipt, "verify", _raiser(ValueError("bad key")))

    with pytest.raises(LegitimacyInvariantError, match="authenticity check failed"):
        charge(10, execution_grant=grant)
    assert calls == []
