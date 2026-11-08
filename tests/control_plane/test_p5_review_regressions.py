"""Regression tests for the PR #241 (phase 5) review threads."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    EvidenceSource,
    ExternalRunRef,
    InMemoryReceiptStore,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    PromotionGate,
    PromotionRejected,
    ReceiptKind,
    ReceiptLedger,
    TrustedRunRegistry,
)
from acgs_lite.control_plane.budgets import BudgetLedger, BudgetLimits
from acgs_lite.control_plane.change_ownership import ChangeOwnershipRegistry, OwnershipDenied
from acgs_lite.control_plane.core_write import CoreChangeWriter, CoreWriteRejected
from acgs_lite.control_plane.evaluator import DeterministicEvaluator, EvaluatorService
from acgs_lite.control_plane.evidence import RunValidation
from acgs_lite.control_plane.incident import IncidentLockError, IncidentMutationLock
from acgs_lite.control_plane.roles import Role, RoleAssignments
from acgs_lite.control_plane.runbook import (
    ExitCodePredicate,
    ExternalRunPredicate,
    predicate_satisfied,
)
from acgs_lite.control_plane.verifier import (
    ReplayVerifier,
    VerdictOutcome,
    VerifierPolicy,
    VerifierRejected,
    VerifierVerdict,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

ADMIN = Principal("root-admin", PrincipalKind.HUMAN)
COMMANDER = Principal("carol", PrincipalKind.HUMAN)
BOB = Principal("bob", PrincipalKind.HUMAN)
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
SERVICE = Principal("evaluator-svc", PrincipalKind.SERVICE)
DIGEST = "sha256:" + "c" * 64


class TestOwnershipPaths:
    """241.1 / 241.8 / 241.21."""

    def test_symlinked_worktree_ancestor_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "control-plane").mkdir()
        (tmp_path / "workspace").mkdir()
        (tmp_path / "workspace" / "link").symlink_to(
            tmp_path / "control-plane", target_is_directory=True
        )
        owners = ChangeOwnershipRegistry(
            DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)), admin=ADMIN
        )
        owners.assign(ADMIN, "c1", AGENT, "workspace/link/owned")
        with pytest.raises(OwnershipDenied, match="symlink"):
            owners.assert_writer(AGENT, "c1", "workspace/link/owned/payload.md")

    def test_only_the_configured_admin_assigns_or_releases(self, tmp_path: Path) -> None:
        owners = ChangeOwnershipRegistry(
            DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)), admin=ADMIN
        )
        with pytest.raises(OwnershipDenied, match="configured HUMAN admin"):
            owners.assign(BOB, "c1", AGENT, "workspace/wt/c1")
        owners.assign(ADMIN, "c1", AGENT, "workspace/wt/c1")
        with pytest.raises(OwnershipDenied, match="configured HUMAN admin"):
            owners.release(BOB, "c1")
        assert owners.get("c1") is not None
        with pytest.raises(TypeError):
            ChangeOwnershipRegistry(DEFAULT_IMMUTABLE_CORE, admin=AGENT)


class TestRoleKind:
    """241.7: an AGENT sharing a human's id does not hold the human's role."""

    def test_has_role_checks_kind(self) -> None:
        roles = RoleAssignments(ADMIN)
        roles.assign(ADMIN, "c1", Role.APPROVER, BOB)
        assert roles.has_role("c1", Role.APPROVER, BOB)
        assert not roles.has_role("c1", Role.APPROVER, Principal("bob", PrincipalKind.AGENT))


def _lock(tmp_path: Path, **kw: Any) -> IncidentMutationLock:
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    path = tmp_path / "control-plane" / "incident" / "lock.json"
    return IncidentMutationLock(path, registry=registry, **kw)


class TestIncidentLock:
    """241.3 / 241.12 / 241.13 / 241.11."""

    def test_heartbeat_needs_matching_kind(self, tmp_path: Path) -> None:
        lock = _lock(tmp_path)
        lock.declare_incident(COMMANDER, "inc-1")
        lock.heartbeat(COMMANDER)
        with pytest.raises(IncidentLockError, match="heartbeats"):
            lock.heartbeat(Principal("carol", PrincipalKind.AGENT))

    def test_lifecycle_is_serialised_across_instances(self, tmp_path: Path) -> None:
        first = _lock(tmp_path)
        first.declare_incident(COMMANDER, "inc-1")
        second = _lock(tmp_path)
        done = threading.Event()
        errors: list[Exception] = []

        def acquire() -> None:
            try:
                second.acquire(BOB, "inc-1", commander=COMMANDER)
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)
            done.set()

        with first._locked():
            worker = threading.Thread(target=acquire)
            worker.start()
            # The other instance's read/check/write waits for the file lock.
            assert not done.wait(0.3)
        worker.join(5)
        assert done.is_set() and not errors
        with pytest.raises(IncidentLockError, match="held by"):
            first.acquire(AGENT, "inc-1", commander=COMMANDER)

    def test_stale_tombstone_after_failed_declare_denies(
        self, tmp_path: Path, ledger_pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        lock = _lock(tmp_path, pdp=ledger_pdp)
        lock.declare_incident(COMMANDER, "inc-a")
        lock.resolve(COMMANDER)

        def crash(payload: Any) -> None:
            raise OSError("disk gone")

        monkeypatch.setattr(lock, "_write", crash)
        with pytest.raises(OSError):
            lock.declare_incident(COMMANDER, "inc-b")  # receipted, state not replaced
        restarted = _lock(tmp_path, pdp=ledger_pdp)
        denial = restarted.write_denial(BOB)
        assert denial is not None and "unreadable" in denial


class TestIncidentRecheckAfterDecision:
    """241.9 / 241.14: a listener declaring an incident mid-decision."""

    def test_core_write(
        self,
        tmp_path: Path,
        constitution: Constitution,
        permit_all: PolicySet,
        approval_gate: Any,
        approver_factory: Any,
    ) -> None:
        pytest.importorskip("cryptography")
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        lock = IncidentMutationLock(registry=registry)

        def declare(decision: Any) -> None:
            if decision.allowed and lock.state() is None:
                lock.declare_incident(COMMANDER, "inc-late")

        with PolicyDecisionPoint.for_constitution(
            constitution,
            permit_all,
            approval_gate=approval_gate,
            registry=registry,
            listeners=[declare],
        ) as pdp:
            writer = CoreChangeWriter(pdp, incident_lock=lock)
            approval = approver_factory("dave")(writer.action_hash_for(BOB, "policy/x.yaml", b"x"))
            with pytest.raises(CoreWriteRejected, match="incident"):
                writer.write_core(BOB, "policy/x.yaml", b"x", approvals=[approval])
            assert lock.state() is not None  # the listener did run on an allow
        assert not (tmp_path / "policy" / "x.yaml").exists()

    def test_promotion(
        self, tmp_path: Path, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        pytest.importorskip("cryptography")
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        ledger = ReceiptLedger(
            Ed25519ReceiptSigner.from_seed(b"\x09" * 32, key_id="gate"),
            store=InMemoryReceiptStore(),
        )
        runs = TrustedRunRegistry()
        run = ExternalRunRef("ci", "7", EvidenceSource.CI_SYSTEM, artifact_digest=DIGEST)
        runs.register_run(Principal("ci-bot", PrincipalKind.SERVICE), run, conclusion="success")
        lock = _lock(tmp_path)

        def declare(decision: Any) -> None:
            if decision.allowed and lock.state() is None:
                lock.declare_incident(COMMANDER, "inc-late")

        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger, listeners=[declare]
        ) as pdp:
            gate = PromotionGate(ledger, runs, pdp=pdp, incident_lock=lock)
            with pytest.raises(PromotionRejected, match="incident"):
                gate.promote(
                    Principal("alice", PrincipalKind.HUMAN),
                    "cand-1",
                    candidate_digest=DIGEST,
                    evidence=[run],
                    approvers=[BOB],
                )
        assert not any(s.receipt.kind is ReceiptKind.PROMOTION for s in ledger.receipts())


class _NonAttestingVerifier:
    """Validates runs but never checks artifact_digest (like GitHub w/o fetch)."""

    verifier_id = "non-attesting"
    attests_artifact_digest = False

    def validate(self, ref: ExternalRunRef) -> RunValidation:
        return RunValidation(True, "green run", self.verifier_id)


class TestVerifierEvidence:
    """241.6 / 241.16 / 241.17 / 241.4."""

    def _ref(self) -> ExternalRunRef:
        return ExternalRunRef("ci", "9", EvidenceSource.CI_SYSTEM, artifact_digest=DIGEST)

    def test_unattested_digest_is_not_an_anchor(self) -> None:
        policy = VerifierPolicy(_NonAttestingVerifier())
        verdict = VerifierVerdict(
            verifier_id="v",
            candidate_digest=DIGEST,
            outcome=VerdictOutcome.PASS,
            evidence=(self._ref(),),
            rationale="r",
        )
        reasons = policy.check_verdict(verdict, DIGEST)
        assert any("does not attest" in reason for reason in reasons)
        replay = ReplayVerifier(_NonAttestingVerifier()).verify(DIGEST, [self._ref()])
        assert replay.outcome is VerdictOutcome.FAIL

    def test_anchored_fail_verdict_is_rejected(self) -> None:
        runs = TrustedRunRegistry()
        runs.register_run(SERVICE, self._ref(), conclusion="success", artifact_digest=DIGEST)
        policy = VerifierPolicy(runs)
        verifier = ReplayVerifier(runs)
        verdict = VerifierVerdict(
            verifier_id=verifier.verifier_id,
            candidate_digest=DIGEST,
            outcome=VerdictOutcome.FAIL,
            evidence=(self._ref(),),
            rationale="patch is wrong",
        )
        assert policy.check_verdict(verdict, DIGEST) == ()
        with pytest.raises(VerifierRejected, match="fail"):
            policy.accept(verifier, verdict, DIGEST, proposer_model_family="x", proposer_vendor="y")


class TestSuccessPredicate:
    """241.2 / 241.15: the approved predicate decides success."""

    def test_exit_code(self) -> None:
        predicate = ExitCodePredicate(kind="exit_code", equals=0)
        assert predicate_satisfied(predicate, 0, None)
        assert predicate_satisfied(predicate, {"exit_code": 0}, None)
        assert not predicate_satisfied(predicate, 1, None)
        assert not predicate_satisfied(predicate, "ok", None)  # missing evidence
        assert not predicate_satisfied(predicate, False, None)

    def test_external_run(self) -> None:
        runs = TrustedRunRegistry()
        ref = ExternalRunRef("github-actions", "1", EvidenceSource.CI_SYSTEM)
        predicate = ExternalRunPredicate(
            kind="external_run", provider="github-actions", workflow=".github/workflows/ci.yml"
        )
        assert not predicate_satisfied(predicate, ref, runs)  # not registered
        runs.register_run(SERVICE, ref, conclusion="success")
        assert predicate_satisfied(predicate, ref, runs)
        assert not predicate_satisfied(predicate, ref, None)
        assert not predicate_satisfied(predicate, "done", runs)


class TestEvaluatorService:
    """241.5 / 241.18 / 241.19."""

    def _evaluator(self, tmp_path: Path) -> DeterministicEvaluator:
        import json

        suite = {
            "version": 1,
            "suite_id": "demo-heldout",
            "pass_threshold": 0.5,
            "cases": [
                {"case_id": "c1", "artifact": "prompt", "require_all": ["cite"], "forbid_any": []},
                {"case_id": "c2", "artifact": "skill", "require_all": ["retry"], "forbid_any": []},
            ],
        }
        path = tmp_path / "heldout" / "suite.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(suite), encoding="utf-8")
        return DeterministicEvaluator(
            "heldout/suite.json", registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        )

    def test_restarted_service_reuses_its_run(self, tmp_path: Path) -> None:
        runs = TrustedRunRegistry()
        evaluator = self._evaluator(tmp_path)
        candidate = {"prompt": "cite", "skill": "retry"}
        _, first = EvaluatorService(evaluator, SERVICE, runs).evaluate(candidate)
        _, again = EvaluatorService(evaluator, SERVICE, runs).evaluate(candidate)
        assert again == first

    @pytest.mark.parametrize(("granularity", "expected"), [(0.3, 0.3), (0.6, 0.0), (0.5, 0.5)])
    def test_granularity_floors_by_the_step(
        self, tmp_path: Path, granularity: float, expected: float
    ) -> None:
        service = EvaluatorService(self._evaluator(tmp_path), SERVICE, TrustedRunRegistry())
        budgets = BudgetLedger()
        budgets.start_run(AGENT, BudgetLimits(iterations=5))
        submit = service.submission_handle(AGENT, budgets, granularity=granularity)
        assert submit({"prompt": "cite"}) == pytest.approx(expected)  # raw score 0.5


def test_demo_write_file_refuses_dotdot(tmp_path: Path) -> None:
    """241.20: the demo tool acts on the normalised path only."""
    from acgs_lite.control_plane import demo_loop

    registered: dict[str, Any] = {}

    class _Dispatcher:
        def register(self, name: str, fn: Any, **kw: Any) -> None:
            registered[name] = fn

    class _CP:
        dispatcher = _Dispatcher()

    demo_loop._install_tools(tmp_path, _CP(), [])  # type: ignore[arg-type]
    registered["write_file"]("workspace/other/../demo/file.md", "x")
    assert (tmp_path / "workspace" / "demo" / "file.md").read_text() == "x"
    assert not (tmp_path / "workspace" / "other").exists()
    with pytest.raises(ValueError):
        registered["write_file"]("../escape.md", "x")


class TestDeclareWriteFailureLiveInstances:
    """Security re-review (HIGH): a receipted declare whose state write fails
    must deny writes on live instances, without a restart."""

    def test_live_instances_deny(
        self, tmp_path: Path, ledger_pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        lock = _lock(tmp_path, pdp=ledger_pdp)
        lock.declare_incident(COMMANDER, "inc-a")
        lock.resolve(COMMANDER)
        other = _lock(tmp_path, pdp=ledger_pdp)  # built before the failed declare
        assert lock.write_denial(BOB) is None and other.write_denial(BOB) is None

        def crash(payload: Any) -> None:
            raise OSError("disk gone")

        monkeypatch.setattr(lock, "_write", crash)
        with pytest.raises(OSError):
            lock.declare_incident(COMMANDER, "inc-b")
        assert lock.write_denial(BOB) is not None
        assert other.write_denial(BOB) is not None


def _hold_and_run(lock: IncidentMutationLock, action: Any) -> list[Any]:
    """Run *action* in a thread while this thread holds the incident lock;
    return [outcome] once it finishes (it must wait for the lock)."""
    outcome: list[Any] = []
    done = threading.Event()

    def run() -> None:
        try:
            outcome.append(action())
        except Exception as exc:
            outcome.append(exc)
        done.set()

    with lock._locked():
        worker = threading.Thread(target=run)
        worker.start()
        assert not done.wait(0.3), "commit did not wait for the incident lock"
    worker.join(5)
    assert done.is_set()
    return outcome


class TestCommitHoldsIncidentLock:
    """Security re-review (LOW): recheck and commit run under the lock."""

    def test_core_write_waits(
        self,
        tmp_path: Path,
        constitution: Constitution,
        permit_all: PolicySet,
        approval_gate: Any,
        approver_factory: Any,
    ) -> None:
        pytest.importorskip("cryptography")
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        lock = _lock(tmp_path)
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, approval_gate=approval_gate, registry=registry
        ) as pdp:
            writer = CoreChangeWriter(pdp, incident_lock=lock)
            approval = approver_factory("dave")(writer.action_hash_for(BOB, "policy/x.yaml", b"x"))
            outcome = _hold_and_run(
                lock, lambda: writer.write_core(BOB, "policy/x.yaml", b"x", approvals=[approval])
            )
        assert outcome[0].allowed
        assert (tmp_path / "policy" / "x.yaml").read_bytes() == b"x"

    def test_promotion_waits(
        self, tmp_path: Path, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        pytest.importorskip("cryptography")
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        ledger = ReceiptLedger(
            Ed25519ReceiptSigner.from_seed(b"\x0a" * 32, key_id="gate"),
            store=InMemoryReceiptStore(),
        )
        runs = TrustedRunRegistry()
        run = ExternalRunRef("ci", "8", EvidenceSource.CI_SYSTEM, artifact_digest=DIGEST)
        runs.register_run(Principal("ci-bot", PrincipalKind.SERVICE), run, conclusion="success")
        lock = _lock(tmp_path)
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, receipt_ledger=ledger
        ) as pdp:
            gate = PromotionGate(ledger, runs, pdp=pdp, incident_lock=lock)
            outcome = _hold_and_run(
                lock,
                lambda: gate.promote(
                    Principal("alice", PrincipalKind.HUMAN),
                    "cand-2",
                    candidate_digest=DIGEST,
                    evidence=[run],
                    approvers=[BOB],
                ),
            )
        assert outcome[0].receipt.kind is ReceiptKind.PROMOTION


class TestFreshDeploymentDeclareFailure:
    """Round-2 re-review (HIGH): no state file yet, failed first declare."""

    def test_instance_built_before_declare_denies(
        self, tmp_path: Path, ledger_pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        declarer = _lock(tmp_path, pdp=ledger_pdp)
        other = _lock(tmp_path, pdp=ledger_pdp)
        assert not declarer.state_path.exists()
        assert other.write_denial(BOB) is None

        def crash(payload: Any) -> None:
            raise OSError("disk gone")

        monkeypatch.setattr(declarer, "_write", crash)
        with pytest.raises(OSError):
            declarer.declare_incident(COMMANDER, "inc-first")
        assert not declarer.state_path.exists()
        assert other.write_denial(BOB) is not None
        assert declarer.write_denial(BOB) is not None
