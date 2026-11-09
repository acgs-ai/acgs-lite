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
