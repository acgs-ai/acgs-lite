"""Phase 5: explicit roles and separation of duties."""

from __future__ import annotations

import pytest

from acgs_lite.control_plane import Principal, PrincipalKind
from acgs_lite.control_plane.roles import Role, RoleAssignments, RoleConflict

pytestmark = [pytest.mark.unit]

ADMIN = Principal("root-admin", PrincipalKind.HUMAN)
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
HARNESS = Principal("harness", PrincipalKind.SERVICE)
VERIFIER = Principal("verifier-svc", PrincipalKind.SERVICE)
BOB = Principal("bob", PrincipalKind.HUMAN)


@pytest.mark.parametrize("role", [Role.APPROVER, Role.MERGER, Role.INCIDENT_COMMANDER])
def test_agent_never_human_only_role(role: Role) -> None:
    with pytest.raises(RoleConflict):
        RoleAssignments(ADMIN).assign(ADMIN, "c1", role, AGENT)


@pytest.mark.parametrize("role", [Role.APPROVER, Role.MERGER, Role.VERIFIER])
def test_proposer_cannot_hold_conflicting_role(role: Role) -> None:
    roles = RoleAssignments(ADMIN)
    roles.assign(ADMIN, "c1", Role.PROPOSER, BOB)
    with pytest.raises(RoleConflict, match="proposer"):
        roles.assign(ADMIN, "c1", role, BOB)
    other = RoleAssignments(ADMIN)
    other.assign(ADMIN, "c1", role, BOB)
    with pytest.raises(RoleConflict, match="proposer"):
        other.assign(ADMIN, "c1", Role.PROPOSER, BOB)
    # A different change is a different separation scope.
    other.assign(ADMIN, "c2", Role.PROPOSER, BOB)


def test_full_assignment_and_queries() -> None:
    roles = RoleAssignments(ADMIN)
    roles.assign(ADMIN, "c1", Role.PROPOSER, AGENT)
    roles.assign(ADMIN, "c1", "executor", HARNESS)
    roles.assign(ADMIN, "c1", Role.VERIFIER, VERIFIER)
    roles.assign(ADMIN, "c1", Role.APPROVER, BOB)
    roles.assign(ADMIN, "c1", Role.MERGER, BOB)
    roles.assign(ADMIN, "c1", Role.INCIDENT_COMMANDER, BOB)
    assert roles.holders("c1", Role.PROPOSER) == (AGENT,)
    assert roles.has_role("c1", Role.MERGER, BOB)
    roles.require("c1", Role.APPROVER, BOB)
    with pytest.raises(RoleConflict, match="does not hold"):
        roles.require("c1", Role.MERGER, AGENT)


def test_kind_and_admin_rules() -> None:
    roles = RoleAssignments(ADMIN)
    with pytest.raises(RoleConflict, match="configured admin"):
        roles.assign(AGENT, "c1", Role.PROPOSER, AGENT)
    with pytest.raises(RoleConflict, match="cannot hold"):
        roles.assign(ADMIN, "c1", Role.EXECUTOR, AGENT)
    with pytest.raises(RoleConflict, match="cannot hold"):
        roles.assign(ADMIN, "c1", Role.VERIFIER, AGENT)
    with pytest.raises(RoleConflict, match="change_id"):
        roles.assign(ADMIN, "", Role.PROPOSER, AGENT)
    with pytest.raises(RoleConflict, match="Principal"):
        roles.assign(ADMIN, "c1", Role.PROPOSER, "agent-1")  # type: ignore[arg-type]


def test_non_admin_cross_grant_refused_and_receipted(ledger_pdp: object) -> None:
    """R1: two ordinary humans cannot grant each other capabilities; only the
    configured admin (or a capability_admin it appointed) can; every grant,
    revoke and refusal is in the receipt ledger."""
    from acgs_lite.control_plane import PolicyDecisionPoint

    assert isinstance(ledger_pdp, PolicyDecisionPoint)
    alice = Principal("alice", PrincipalKind.HUMAN)
    roles = RoleAssignments(ADMIN, pdp=ledger_pdp)
    for granter, grantee in ((alice, BOB), (BOB, alice)):
        with pytest.raises(RoleConflict, match="configured admin"):
            roles.grant_capability(granter, "incident_admin", grantee)
    with pytest.raises(RoleConflict, match="themselves"):
        roles.grant_capability(ADMIN, "sre", ADMIN)
    roles.grant_capability(ADMIN, "capability_admin", alice)
    with pytest.raises(RoleConflict, match="only the admin grants capability_admin"):
        roles.grant_capability(alice, "capability_admin", BOB)
    with pytest.raises(RoleConflict, match="themselves"):
        roles.grant_capability(alice, "sre", alice)
    roles.grant_capability(alice, "sre", BOB)
    assert roles.has_capability(BOB, "sre") and not roles.has_capability(alice, "sre")
    with pytest.raises(RoleConflict, match="configured admin"):
        roles.revoke_capability(BOB, "sre", BOB)
    assert roles.revoke_capability(ADMIN, "sre", BOB) is True
    with pytest.raises(RoleConflict, match="malformed"):
        roles.grant_capability(ADMIN, "bad cap", BOB)
    with pytest.raises(RoleConflict, match="HUMAN"):
        roles.grant_capability(ADMIN, "sre", AGENT)
    receipts = [r.receipt for r in ledger_pdp.receipt_ledger.receipts()]  # type: ignore[union-attr]
    granted = [r for r in receipts if r.action == "roles.grant" and r.allowed]
    refused = [r for r in receipts if not r.allowed]
    assert len(granted) == 2 and len(refused) >= 5
    assert any(r.action == "roles.revoke" and r.allowed for r in receipts)


def test_constructor_requires_admin() -> None:
    with pytest.raises(RoleConflict):
        RoleAssignments(AGENT)
    with pytest.raises(TypeError):
        RoleAssignments(ADMIN, pdp="pdp")  # type: ignore[arg-type]
    assert RoleAssignments(ADMIN).admin is ADMIN
