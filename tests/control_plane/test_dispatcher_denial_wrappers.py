"""GovernedToolDispatcher: collaborator failures and late revocations become
denials, and the tool is never invoked."""

from __future__ import annotations

import contextlib
import copy
import re
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import acgs_lite.control_plane.dispatcher as dispatcher_mod
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    AutonomyController,
    BudgetLedger,
    BudgetLimits,
    ChangeOwnershipRegistry,
    CredentialIssuer,
    ErrorBudget,
    EvidenceSource,
    ExternalRunRef,
    GovernedToolDispatcher,
    IncidentMutationLock,
    PolicyDecisionPoint,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    RunbookDenied,
    RunValidation,
    StaticIdentityDirectory,
    ToolDenied,
    TrustedRunRegistry,
    WriteGrant,
)
from acgs_lite.control_plane.dispatcher import backup_subject_digest

pytest.importorskip("cryptography")
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

ADMIN = Principal("root-admin", PrincipalKind.HUMAN)
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
AGENT_2 = Principal("agent-2", PrincipalKind.AGENT, system_id="sys-a")
HUMAN = Principal("alice", PrincipalKind.HUMAN)
BOT = Principal("bot-1", PrincipalKind.AGENT, system_id="sys-a")
SERVICE = Principal("backups", PrincipalKind.SERVICE)
WRITE_ARGS = {"path": "workspace/a.txt"}
BACKUP_ARGS = {"path": "workspace/data.txt"}


def _grants() -> list[WriteGrant]:
    return [
        WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",)),
        WriteGrant("alice", PrincipalKind.HUMAN, ("**",)),
    ]


def _dispatcher(
    pdp: PolicyDecisionPoint, permissions: RepositoryPermissions | None = None, **kw: Any
) -> GovernedToolDispatcher:
    return GovernedToolDispatcher(
        pdp,
        permissions=permissions or RepositoryPermissions(pdp.registry, _grants()),
        tool_tiers=kw.pop("tool_tiers", {"write": ActionTier.T1}),
        **kw,
    )


def _with_write(d: GovernedToolDispatcher, calls: list[Any]) -> GovernedToolDispatcher:
    def write(path: str) -> str:
        calls.append(path)
        return "written"

    d.register("write", write, path_params={"path"}, merge_capable=False)
    return d


def _raiser(exc: BaseException) -> Any:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise exc

    return fail


# -- construction --------------------------------------------------------


def test_constructor_rejects_mismatched_or_malformed_collaborators(
    pdp: PolicyDecisionPoint, tmp_path: Path
) -> None:
    other = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path / "other"))
    with pytest.raises(ValueError, match="ownership and pdp"):
        _dispatcher(pdp, ownership=ChangeOwnershipRegistry(other, admin=ADMIN))
    with pytest.raises(ValueError, match="backup_workflows"):
        _dispatcher(pdp, backup_workflows="backups")
    with pytest.raises(TypeError, match="backup_consumption_registry"):
        _dispatcher(pdp, backup_consumption_registry=object())


# -- pre-PDP argument checks ------------------------------------------------


def test_argument_snapshot_failure_is_denied(
    pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    d = _with_write(_dispatcher(pdp), calls)
    monkeypatch.setattr(
        dispatcher_mod, "copy", SimpleNamespace(deepcopy=_raiser(MemoryError("no memory")))
    )

    with pytest.raises(ToolDenied, match="arguments cannot be snapshotted: MemoryError"):
        d.dispatch(AGENT, "write", WRITE_ARGS)
    assert calls == []


def test_default_argument_snapshot_failure_is_denied(
    pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    d = _dispatcher(pdp)

    def write(path: str, mode: str = "w") -> str:
        calls.append(path)
        return "written"

    d.register("write", write, path_params={"path"}, opaque_params={"mode"}, merge_capable=False)
    real_deepcopy = copy.deepcopy
    seen: list[int] = []

    def deepcopy_once(value: Any, *args: Any) -> Any:
        seen.append(1)
        if len(seen) == 1:
            return real_deepcopy(value, *args)
        raise MemoryError("no memory")

    monkeypatch.setattr(dispatcher_mod, "copy", SimpleNamespace(deepcopy=deepcopy_once))

    with pytest.raises(ToolDenied, match="default arguments cannot be snapshotted: MemoryError"):
        d.dispatch(AGENT, "write", WRITE_ARGS)
    assert len(seen) == 2
    assert calls == []


def test_non_string_command_argument_is_denied(gated_pdp: PolicyDecisionPoint) -> None:
    calls: list[Any] = []
    d = _dispatcher(gated_pdp, tool_tiers={"sh": ActionTier.T2})

    def sh(cmd: str) -> str:
        calls.append(cmd)
        return "ran"

    d.register("sh", sh, command_param="cmd", merge_capable=False)

    with pytest.raises(ToolDenied, match="command argument 'cmd' must be a string"):
        d.dispatch(HUMAN, "sh", {"cmd": ["ls"]})
    assert calls == []


def test_unresolvable_read_target_is_left_to_the_pdp(pdp: PolicyDecisionPoint) -> None:
    calls: list[Any] = []
    d = _dispatcher(pdp, tool_tiers={"read": ActionTier.T0}, read_only_tools=frozenset({"read"}))

    def read(path: str) -> str:
        calls.append(path)
        return "contents"

    d.register("read", read, path_params={"path"}, merge_capable=False)

    # The pre-PDP read loop skips the unresolvable path; the PDP default-denies it.
    with pytest.raises(ToolDenied, match=re.escape("no permit matched (default deny)")):
        d.dispatch(AGENT, "read", {"path": "../outside.txt"})
    assert calls == []


def test_non_action_tier_claim_is_denied(pdp: PolicyDecisionPoint) -> None:
    calls: list[Any] = []
    d = _with_write(_dispatcher(pdp), calls)

    with pytest.raises(ToolDenied, match="caller-supplied tier is not an ActionTier"):
        d.dispatch(AGENT, "write", WRITE_ARGS, tier=99)  # type: ignore[arg-type]
    assert calls == []


def test_is_async_reports_registration(pdp: PolicyDecisionPoint) -> None:
    d = _dispatcher(pdp, tool_tiers={"write": ActionTier.T1, "awrite": ActionTier.T1})

    def write(path: str) -> str:
        return "written"

    async def awrite(path: str) -> str:
        return "written"

    d.register("write", write, path_params={"path"}, merge_capable=False)
    d.register("awrite", awrite, path_params={"path"}, merge_capable=False)

    assert d.is_async("awrite") is True
    assert d.is_async("write") is False
    assert d.is_async("missing") is False


# -- T3 backup evidence ----------------------------------------------------


class FakeRunVerifier:
    """An ExternalRunVerifier whose digest attestation and validation are set."""

    verifier_id = "fake-verifier"

    def __init__(self, attests: bool, error: Exception | None = None) -> None:
        self.attests_artifact_digest = attests
        self.error = error
        self.validated: list[ExternalRunRef] = []

    def validate(self, ref: ExternalRunRef) -> RunValidation:
        self.validated.append(ref)
        if self.error is not None:
            raise self.error
        return RunValidation(True, "ok", self.verifier_id)


@pytest.fixture()
def backup(tmp_path: Path, ledger_pdp: PolicyDecisionPoint, approver_factory: Any) -> Any:
    """A T3 ``delete`` tool behind a persistent backup registry (``runs``)
    holding one successful backup run bound to ``BACKUP_ARGS``."""
    runs = TrustedRunRegistry(
        path=tmp_path / "audit" / "backup-runs.jsonl",
        registry=ledger_pdp.registry,
        signer=Ed25519ReceiptSigner.from_seed(b"durable-backup-test".ljust(32, b"0")),
    )
    ref = ExternalRunRef(
        "backups",
        "run-1",
        EvidenceSource.CI_SYSTEM,
        artifact_digest=backup_subject_digest("delete", BACKUP_ARGS),
    )
    runs.register_run(SERVICE, ref, conclusion="success")
    calls: list[Any] = []
    signers = [approver_factory("bob"), approver_factory("carol")]

    def make(verifier: Any = None) -> GovernedToolDispatcher:
        d = GovernedToolDispatcher(
            ledger_pdp,
            permissions=RepositoryPermissions(
                ledger_pdp.registry, [WriteGrant(AGENT.id, AGENT.kind, ("workspace/**",))]
            ),
            tool_tiers={"delete": ActionTier.T3},
            run_verifier=runs if verifier is None else verifier,
            backup_consumption_registry=runs,
            backup_workflows={"backups"},
        )
        d.register(
            "delete", lambda path: calls.append(path), path_params={"path"}, merge_capable=False
        )
        return d

    def kwargs(d: GovernedToolDispatcher) -> dict[str, Any]:
        kw: dict[str, Any] = {"backup_run": ref, "requested_by": "olivia"}
        digest = d.action_hash_for(AGENT, "delete", BACKUP_ARGS, **kw)
        return {**kw, "approvals": [sign(digest) for sign in signers]}

    return SimpleNamespace(make=make, kwargs=kwargs, runs=runs, ref=ref, calls=calls)


def test_verifier_that_cannot_attest_digest_is_denied(backup: Any) -> None:
    verifier = FakeRunVerifier(attests=False)
    d = backup.make(verifier)

    with pytest.raises(ToolDenied, match="run verifier cannot attest the backup digest"):
        d.dispatch(AGENT, "delete", BACKUP_ARGS, backup_run=backup.ref, requested_by="olivia")
    assert verifier.validated == []
    assert backup.calls == []


def test_verifier_crash_is_denied(backup: Any) -> None:
    verifier = FakeRunVerifier(attests=True, error=RuntimeError("verifier down"))
    d = backup.make(verifier)

    with pytest.raises(ToolDenied, match="backup run unverifiable: RuntimeError"):
        d.dispatch(AGENT, "delete", BACKUP_ARGS, backup_run=backup.ref, requested_by="olivia")
    assert verifier.validated == [backup.ref]
    assert backup.calls == []


def test_unreadable_consumption_state_is_denied(
    backup: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = backup.make()
    kw = backup.kwargs(d)
    monkeypatch.setattr(backup.runs, "backup_consumed", _raiser(OSError("registry offline")))

    with pytest.raises(ToolDenied, match="backup consumption state unavailable"):
        d.dispatch(AGENT, "delete", BACKUP_ARGS, **kw)
    assert backup.calls == []


def test_failed_consumption_claim_is_denied(backup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    d = backup.make()
    kw = backup.kwargs(d)
    monkeypatch.setattr(backup.runs, "consume_backup", _raiser(OSError("fsync failed")))

    # The denial is correct, but the source reports a storage failure as "backup run
    # already consumed", which is misleading (source issue, not fixed here), so the
    # reason text is deliberately not pinned.
    with pytest.raises(ToolDenied):
        d.dispatch(AGENT, "delete", BACKUP_ARGS, **kw)
    assert backup.calls == []
    assert not backup.runs.backup_consumed(backup.ref)


# -- collaborator exceptions inside authorisation --------------------------


def _assert_caused_by(excinfo: pytest.ExceptionInfo[ToolDenied], marker: str) -> None:
    """The denial wraps the exception raised by the injected collaborator."""
    cause = excinfo.value.__cause__
    assert isinstance(cause, RuntimeError) and str(cause) == marker


def test_budget_charge_crash_is_denied(
    pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    budgets = BudgetLedger()
    budgets.start_run(AGENT, BudgetLimits())
    d = _with_write(_dispatcher(pdp, budgets=budgets), calls)
    monkeypatch.setattr(budgets, "try_charge", _raiser(RuntimeError("try_charge")))

    with pytest.raises(ToolDenied, match="harness check failed: RuntimeError") as excinfo:
        d.dispatch(AGENT, "write", WRITE_ARGS)
    _assert_caused_by(excinfo, "try_charge")
    assert calls == []


def test_final_admission_crash_is_denied(
    pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    budgets = BudgetLedger()
    budgets.start_run(AGENT, BudgetLimits())
    autonomy = AutonomyController(ErrorBudget(), budgets)
    d = _with_write(_dispatcher(pdp, budgets=budgets, autonomy=autonomy), calls)
    monkeypatch.setattr(autonomy, "admitted_level", _raiser(RuntimeError("admitted_level")))

    with pytest.raises(ToolDenied, match="harness check failed: RuntimeError") as excinfo:
        d.dispatch(AGENT, "write", WRITE_ARGS)
    _assert_caused_by(excinfo, "admitted_level")
    assert calls == []


def test_credential_verification_crash_is_denied(
    pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    issuer = CredentialIssuer()
    cred = issuer.issue(AGENT, scopes={"tool:write"})
    d = _with_write(_dispatcher(pdp, credential_issuer=issuer, require_credential=True), calls)
    monkeypatch.setattr(issuer, "verify", _raiser(RuntimeError("verify")))

    with pytest.raises(ToolDenied, match="harness check failed: RuntimeError") as excinfo:
        d.dispatch(AGENT, "write", WRITE_ARGS, credential=cred.token)
    _assert_caused_by(excinfo, "verify")
    assert calls == []


@pytest.fixture()
def attested(pdp: PolicyDecisionPoint) -> Any:
    """A dispatcher whose credential issuer is backed by an identity directory."""
    directory = StaticIdentityDirectory.from_mapping(
        {
            "version": 1,
            "identities": [
                {
                    "id": "alice",
                    "kind": "human",
                    "admin": True,
                    "public_key": Ed25519ReceiptSigner.from_seed(b"A" * 32).public_key_hex(),
                },
                {"id": "bot-1", "kind": "agent", "system_id": "sys-a"},
            ],
        }
    )
    issuer = CredentialIssuer(identity=directory)
    calls: list[Any] = []
    permissions = RepositoryPermissions(
        pdp.registry, [WriteGrant("bot-1", PrincipalKind.AGENT, ("workspace/**",))]
    )
    d = _with_write(
        _dispatcher(pdp, permissions, credential_issuer=issuer, require_credential=True), calls
    )
    token = issuer.issue(BOT, scopes={"tool:write"}).token
    return SimpleNamespace(
        directory=directory, issuer=issuer, dispatcher=d, token=token, calls=calls
    )


def test_attested_identity_verification_crash_is_denied(
    attested: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(attested.issuer, "verify", _raiser(RuntimeError("verify")))

    with pytest.raises(ToolDenied, match="harness check failed: RuntimeError") as excinfo:
        attested.dispatcher.dispatch(BOT, "write", WRITE_ARGS, credential=attested.token)
    _assert_caused_by(excinfo, "verify")
    assert attested.calls == []


def test_principal_removed_from_directory_is_denied(
    attested: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(attested.directory, "lookup", lambda principal_id: None)

    with pytest.raises(ToolDenied, match="credential principal is not in the identity directory"):
        attested.dispatcher.dispatch(BOT, "write", WRITE_ARGS, credential=attested.token)
    assert attested.calls == []


# -- Phase 5: runbooks, ownership, permissions, incident lock ---------------


def test_runbook_planning_crash_is_denied(p5: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(p5.runbooks, "check_execution", _raiser(RuntimeError("check")))

    with pytest.raises(ToolDenied, match="tier planning failed: RuntimeError"):
        p5.dispatcher.dispatch(
            AGENT,
            "write_file",
            {"path": p5.worktree + "/a.txt"},
            runbook_id="rb",
            runbook_hash="h",
            change_id="c1",
        )
    assert p5.calls == []


def test_runbook_rate_limit_spent_after_pdp_is_denied(
    p5: Any, runbook_data: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = p5.approve_runbook(runbook_data())
    real_check = p5.runbooks._check_execution
    consumed: list[bool] = []

    def exhausted_on_consume(*args: Any, consume: bool, **kwargs: Any) -> Any:
        # The pure pre-PDP check passes; only the post-PDP spend is refused.
        if consume:
            consumed.append(True)
            raise RunbookDenied("rate limit exhausted")
        return real_check(*args, consume=consume, **kwargs)

    monkeypatch.setattr(p5.runbooks, "_check_execution", exhausted_on_consume)

    with pytest.raises(ToolDenied, match="runbook rejected: rate limit exhausted"):
        p5.dispatcher.dispatch(
            AGENT,
            "write_file",
            {"path": p5.worktree + "/a.txt"},
            runbook_id="rb-restart-cache",
            runbook_hash=digest,
            change_id="c1",
        )
    assert consumed == [True]
    assert p5.calls == []


def test_change_reassigned_between_checks_is_denied(
    p5: Any, runbook_data: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = p5.approve_runbook(runbook_data())
    ownership = p5.ownership
    real_assert_writer = ownership.assert_writer
    outcomes: list[str] = []

    def assert_writer(*args: Any, **kwargs: Any) -> Any:
        try:
            owned = real_assert_writer(*args, **kwargs)
        except Exception:
            outcomes.append("denied")
            raise
        outcomes.append("allowed")
        if len(outcomes) == 1:
            # An admin reassigns the change after the pre-PDP ownership check.
            ownership.release(ADMIN, "c1")
            ownership.assign(ADMIN, "c1", AGENT_2, p5.worktree)
        return owned

    monkeypatch.setattr(ownership, "assert_writer", assert_writer)

    with pytest.raises(ToolDenied, match="is not the writer of change 'c1'") as excinfo:
        p5.dispatcher.dispatch(
            AGENT,
            "write_file",
            {"path": p5.worktree + "/a.txt"},
            runbook_id="rb-restart-cache",
            runbook_hash=digest,
            change_id="c1",
        )
    assert str(excinfo.value).count("change ownership: 'agent-1' is not the writer") == 1
    assert outcomes == ["allowed", "denied"]
    assert p5.calls == []


class RevocablePermissions(RepositoryPermissions):
    """Repository permissions whose grants an admin can revoke at any time;
    ``revoke_after_checks`` schedules that revocation after N write checks."""

    def __init__(self, registry: Any, grants: list[WriteGrant]) -> None:
        super().__init__(registry, grants)
        self.checks: list[bool] = []
        self.revoke_after_checks: int | None = None

    def revoke_all(self) -> None:
        self._grants = ()

    def can_write(self, principal: Principal, path: str) -> bool:
        allowed = super().can_write(principal, path)
        self.checks.append(allowed)
        if len(self.checks) == self.revoke_after_checks:
            self.revoke_all()
        return allowed


def test_grant_revoked_after_pdp_is_denied(pdp: PolicyDecisionPoint) -> None:
    calls: list[Any] = []
    permissions = RevocablePermissions(pdp.registry, _grants())
    # Revoked once the pre-PDP IAM check has passed, before the post-PDP pass.
    permissions.revoke_after_checks = 1
    d = _with_write(_dispatcher(pdp, permissions), calls)

    with pytest.raises(ToolDenied, match="repository permissions deny write to 'workspace/a.txt'"):
        d.dispatch(AGENT, "write", WRITE_ARGS)
    assert permissions.checks == [True, False]
    assert calls == []


def test_incident_state_corrupted_during_lease_is_denied(
    pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    lock = IncidentMutationLock(registry=pdp.registry)
    d = _with_write(_dispatcher(pdp, incident_lock=lock), calls)
    real_execution = lock.execution
    leased: list[Principal] = []

    @contextlib.contextmanager
    def execution(principal: Principal) -> Iterator[None]:
        with real_execution(principal):
            leased.append(principal)
            # The state file is corrupted once the real lease is held.
            lock.state_path.write_text("{bad", encoding="utf-8")
            yield

    monkeypatch.setattr(lock, "execution", execution)

    with pytest.raises(
        ToolDenied,
        match=re.escape("incident lock state unreadable (JSONDecodeError); writes denied"),
    ):
        d.dispatch(AGENT, "write", WRITE_ARGS)
    assert leased == [AGENT]
    assert calls == []
