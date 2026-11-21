"""Shared fixtures for control-plane tests."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
)
from acgs_lite.control_plane.approvals import ApprovalAuthority, ApprovalGate, SignedApproval

ADMIN = Principal("root-admin", PrincipalKind.HUMAN)

PERMIT_ALL = {
    "version": 1,
    "statements": [
        {"id": "permit-all", "effect": "permit", "actions": ["*"], "resources": ["**"]},
    ],
}


@pytest.fixture()
def constitution() -> Constitution:
    return Constitution.default()


@pytest.fixture()
def permit_all() -> PolicySet:
    return PolicySet.from_mapping(PERMIT_ALL)


@pytest.fixture()
def agent() -> Principal:
    return Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")


@pytest.fixture()
def human() -> Principal:
    return Principal("alice", PrincipalKind.HUMAN)


@pytest.fixture()
def pdp(
    constitution: Constitution, permit_all: PolicySet, tmp_path: Path
) -> Iterator[PolicyDecisionPoint]:
    """A deliberately permissive PDP: only the invariants stand in the way."""
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    with PolicyDecisionPoint.for_constitution(constitution, permit_all, registry=registry) as point:
        yield point


@pytest.fixture()
def approval_authority() -> ApprovalAuthority:
    return ApprovalAuthority()


@pytest.fixture()
def approval_gate(approval_authority: ApprovalAuthority) -> ApprovalGate:
    return ApprovalGate(approval_authority)


@pytest.fixture()
def gated_pdp(
    constitution: Constitution, permit_all: PolicySet, approval_gate: ApprovalGate, tmp_path: Path
) -> Iterator[PolicyDecisionPoint]:
    """Permissive PDP whose approvers come only from signed approvals."""
    with PolicyDecisionPoint.for_constitution(
        constitution,
        permit_all,
        approval_gate=approval_gate,
        registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)),
    ) as point:
        yield point


@pytest.fixture()
def approver_factory(
    approval_authority: ApprovalAuthority,
) -> Callable[..., Callable[..., SignedApproval]]:
    """``approver_factory("bob")`` registers bob's key and returns a signer
    ``sign(action_hash, **kw) -> SignedApproval`` (needs ``cryptography``)."""
    from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

    def make(
        name: str, *, system_id: str | None = None, roles: frozenset[str] = frozenset()
    ) -> Callable[..., SignedApproval]:
        signer = Ed25519ReceiptSigner.from_seed(
            hashlib.sha256(name.encode()).digest(), key_id=f"key-{name}"
        )
        approver = Principal(name, PrincipalKind.HUMAN, system_id=system_id, roles=roles)
        approval_authority.register_approver(
            ADMIN, approver, signer.public_key_hex(), key_id=f"key-{name}"
        )

        def sign(action_hash: str, **kwargs: Any) -> SignedApproval:
            return SignedApproval.create(
                signer, approver=approver, action_hash=action_hash, **kwargs
            )

        return sign

    return make


def _runbook_data(**overrides: Any) -> dict[str, Any]:
    from datetime import datetime, timezone

    data: dict[str, Any] = {
        "runbook_id": "rb-restart-cache",
        "version": 1,
        "action_tier": 1,
        "scope_selector": {
            "tools": ["write_*"],
            "paths": ["workspace/**"],
            "principals": ["agent-1"],
            "principal_kinds": ["agent"],
            "system_ids": [],
        },
        "max_blast_radius": 3,
        "rate_limit": {"max_executions": 5, "per_seconds": 60},
        "required_approver_role": "sre",
        "rollback_command": ["git", "revert", "--no-edit", "HEAD"],
        "success_predicate": {"kind": "exit_code", "equals": 0},
        "stop_conditions": [
            {"kind": "max_failures", "count": 3},
            {"kind": "breaker_open"},
        ],
        "owner": "olivia",
        "last_tested": datetime.now(timezone.utc).date().isoformat(),
    }
    data.update(overrides)
    return data


@pytest.fixture()
def runbook_data() -> Callable[..., dict[str, Any]]:
    """``runbook_data(**overrides)`` -> a valid T1 runbook mapping."""
    return _runbook_data


@pytest.fixture()
def sre() -> Principal:
    """A human runbook approver holding the ``sre`` role."""
    return Principal("sam", PrincipalKind.HUMAN, roles=frozenset({"sre"}))


RUNBOOK_APPROVER = Principal("rita", PrincipalKind.HUMAN)


@pytest.fixture()
def ledger_pdp(
    tmp_path: Any, constitution: Constitution, permit_all: PolicySet, approval_gate: ApprovalGate
) -> Iterator[PolicyDecisionPoint]:
    """A gated PDP over a tmp repo root, bound to an in-memory receipt ledger."""
    pytest.importorskip("cryptography")
    from acgs_lite.control_plane import DEFAULT_IMMUTABLE_CORE, InMemoryReceiptStore, ReceiptLedger
    from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

    ledger = ReceiptLedger(
        Ed25519ReceiptSigner.from_seed(b"ledger-seed".ljust(32, b"0"), key_id="test-ledger"),
        store=InMemoryReceiptStore(),
    )
    with PolicyDecisionPoint.for_constitution(
        constitution,
        permit_all,
        approval_gate=approval_gate,
        receipt_ledger=ledger,
        registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)),
    ) as point:
        yield point


@pytest.fixture()
def runbook_signer(
    approver_factory: Callable[..., Callable[..., SignedApproval]],
) -> Callable[..., SignedApproval]:
    """Signer of ``rita``, the registered human runbook approver."""
    pytest.importorskip("cryptography")
    return approver_factory("rita")


@pytest.fixture()
def roles() -> Any:
    """Admin-written role assignments: ``rita`` holds the ``sre`` capability."""
    from acgs_lite.control_plane.roles import RoleAssignments

    assignments = RoleAssignments(ADMIN)
    assignments.grant_capability(ADMIN, "sre", RUNBOOK_APPROVER)
    return assignments


@pytest.fixture()
def rb(
    constitution: Constitution,
    permit_all: PolicySet,
    approval_gate: ApprovalGate,
    runbook_signer: Callable[..., SignedApproval],
    roles: Any,
    sre: Principal,
) -> Iterator[Any]:
    """``rb.make(core=DEFAULT_IMMUTABLE_CORE, **kw)`` -> RunbookRegistry over a
    gated PDP; ``rb.approve(registry, data, **kw)`` -> hash, signed by rita and
    submitted by ``sre`` (sam)."""
    from types import SimpleNamespace

    from acgs_lite.control_plane import DEFAULT_IMMUTABLE_CORE
    from acgs_lite.control_plane.runbook import RunbookRegistry

    pdps: list[PolicyDecisionPoint] = []

    def make(core: Any = DEFAULT_IMMUTABLE_CORE, **kw: Any) -> RunbookRegistry:
        pdp = PolicyDecisionPoint.for_constitution(
            constitution, permit_all, approval_gate=approval_gate, registry=core
        )
        pdps.append(pdp)
        return RunbookRegistry(core, pdp=pdp, roles=roles, **kw)

    def approve(registry: RunbookRegistry, data: Any, **kw: Any) -> str:
        digest = registry.approval_hash(sre, data)
        return registry.approve(sre, data, approvals=[runbook_signer(digest)], **kw)

    yield SimpleNamespace(make=make, approve=approve, roles=roles, signer=runbook_signer)
    for pdp in pdps:
        pdp.close()


@pytest.fixture()
def p5(
    tmp_path: Any,
    constitution: Constitution,
    permit_all: PolicySet,
    approval_gate: ApprovalGate,
    runbook_signer: Callable[..., SignedApproval],
    roles: Any,
    sre: Principal,
) -> Iterator[Any]:
    """A Phase-5 dispatcher (profiles, runbooks, review queue, ownership,
    incident lock, backup run verifier) over a tmp repo root.

    Tools: ``write_file(path, content)`` / ``write_many(paths)`` (reversible,
    blast = #paths), ``delete_file(path)`` (data-destroying),
    ``read_file(path)`` (read-only T0), ``legacy_write(path)`` (static T1, no
    profile), ``git_commit(path, branch)`` and ``pr.merge(pr)``. ``agent-1``
    owns change ``c1`` at ``workspace/wt/agent-1/c1``.
    """
    from types import SimpleNamespace

    from acgs_lite.control_plane import (
        DEFAULT_IMMUTABLE_CORE,
        ActionTier,
        GovernedToolDispatcher,
        RepositoryPermissions,
        TrustedRunRegistry,
        WriteGrant,
    )
    from acgs_lite.control_plane.change_ownership import ChangeOwnershipRegistry
    from acgs_lite.control_plane.incident import IncidentMutationLock
    from acgs_lite.control_plane.runbook import RunbookRegistry
    from acgs_lite.control_plane.tier_policy import ActionProfile, ReviewQueue

    root = str(tmp_path)
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(root)
    worktree = "workspace/wt/agent-1/c1"
    (tmp_path / worktree).mkdir(parents=True)
    calls: list[tuple[str, Any]] = []

    def writes(arguments: Any) -> ActionProfile:
        paths = arguments.get("paths") or [arguments.get("path")]
        return ActionProfile(True, False, len(paths), False)

    def destroys(arguments: Any) -> ActionProfile:
        return ActionProfile(False, True, 1, False, has_verified_backup=True)

    def reads(arguments: Any) -> ActionProfile:
        return ActionProfile(True, False, 0, False, read_only=True)

    def novel(arguments: Any) -> ActionProfile:
        return ActionProfile(True, False, 1, True)

    def write_file(path: str, content: str = "") -> str:
        if content == "boom":
            raise RuntimeError("tool failed")
        calls.append(("write_file", path))
        return "written"

    def write_many(paths: list[str]) -> str:
        calls.append(("write_many", paths))
        return "written"

    def delete_file(path: str) -> str:
        calls.append(("delete_file", path))
        return "deleted"

    def read_file(path: str) -> str:
        calls.append(("read_file", path))
        return "contents"

    def legacy_write(path: str) -> str:
        calls.append(("legacy_write", path))
        return "written"

    def git_commit(path: str, branch: str) -> str:
        calls.append(("git_commit", branch))
        return "committed"

    def merge(pr: str) -> str:
        calls.append(("pr.merge", pr))
        return "merged"

    with PolicyDecisionPoint.for_constitution(
        constitution, permit_all, approval_gate=approval_gate, registry=registry
    ) as pdp:
        permissions = RepositoryPermissions(
            registry,
            [
                WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",)),
                WriteGrant("agent-2", PrincipalKind.AGENT, ("workspace/**",)),
                WriteGrant("alice", PrincipalKind.HUMAN, ("**",)),
            ],
        )
        runbooks = RunbookRegistry(registry, pdp=pdp, roles=roles)
        review = ReviewQueue()
        ownership = ChangeOwnershipRegistry(registry, admin=ADMIN)
        ownership.assign(ADMIN, "c1", Principal("agent-1", PrincipalKind.AGENT, "sys-a"), worktree)
        incident = IncidentMutationLock(registry=registry)
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        runs = TrustedRunRegistry(
            path=tmp_path / "audit" / "runs.jsonl",
            registry=registry,
            signer=Ed25519ReceiptSigner.from_seed(b"backup-registry".ljust(32, b"0")),
        )
        dispatcher = GovernedToolDispatcher(
            pdp,
            permissions=permissions,
            tool_tiers={"legacy_write": ActionTier.T1},
            read_only_tools=frozenset({"read_file"}),
            runbooks=runbooks,
            review_queue=review,
            ownership=ownership,
            incident_lock=incident,
            run_verifier=runs,
            backup_workflows={"backups"},
            # Phase 5 fixture models a trusted host that authenticates principals.
            trust_host_identity=True,
        )
        dispatcher.register(
            "write_file",
            write_file,
            path_params={"path"},
            opaque_params={"content"},
            profile=writes,
            merge_capable=False,
        )
        dispatcher.register(
            "write_many", write_many, path_params={"paths"}, profile=writes, merge_capable=False
        )
        dispatcher.register(
            "delete_file", delete_file, path_params={"path"}, profile=destroys, merge_capable=False
        )
        dispatcher.register(
            "read_file", read_file, path_params={"path"}, profile=reads, merge_capable=False
        )
        dispatcher.register("legacy_write", legacy_write, path_params={"path"}, merge_capable=False)
        dispatcher.register(
            "git_commit",
            git_commit,
            path_params={"path"},
            opaque_params={"branch"},
            profile=writes,
            branch_param="branch",
            merge_capable=False,
        )
        dispatcher.register(
            "pr.merge", merge, opaque_params={"pr"}, profile=novel, merge_capable=True
        )

        def approve_runbook(data: Any, **kw: Any) -> str:
            digest = runbooks.approval_hash(sre, data)
            return runbooks.approve(sre, data, approvals=[runbook_signer(digest)], **kw)

        yield SimpleNamespace(
            approve_runbook=approve_runbook,
            roles=roles,
            root=tmp_path,
            registry=registry,
            pdp=pdp,
            dispatcher=dispatcher,
            runbooks=runbooks,
            review=review,
            ownership=ownership,
            incident=incident,
            runs=runs,
            calls=calls,
            worktree=worktree,
        )
