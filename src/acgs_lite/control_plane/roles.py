"""Roles of a self-improvement change and their separation.

* PROPOSER -- writes the change, on its own worktree/branch only
  (:mod:`.change_ownership`).
* EXECUTOR -- the harness (SERVICE) that runs governed tools.
* VERIFIER -- an independent checker (SERVICE or HUMAN) of a different model
  tier or vendor than the proposer (:mod:`.verifier`).
* APPROVER, MERGER, INCIDENT_COMMANDER -- humans only.

Organisation capabilities (``sre``, ``promotion.approve``,
``incident_commander``, ``incident_admin``, ...) are granted per principal
by a HUMAN admin (:meth:`RoleAssignments.grant_capability`) and are what the
runbook registry, the promotion gate and the incident lock check -- never the
self-asserted :attr:`Principal.roles`. Only HUMANs hold capabilities.

Conflict rules: one canonical principal cannot be PROPOSER and also
APPROVER, MERGER or VERIFIER of the same change, and an AGENT can never hold
APPROVER, MERGER or INCIDENT_COMMANDER.

Evidence: METR -- automated graders approved patches that maintainers would
not have merged (~24pp gap), so the grader is not the merger and agents
cannot merge (also INV-AGENT-NO-MERGE). DGM -- a self-modifying agent gamed
its own checks, so proposer and verifier are distinct parties.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping
from typing import TYPE_CHECKING

from acgs_lite._compat import StrEnum
from acgs_lite.control_plane.principal import Principal, PrincipalKind

if TYPE_CHECKING:
    from acgs_lite.control_plane.identity import AdminAttestor
    from acgs_lite.control_plane.pdp import PolicyDecisionPoint

__all__ = [
    "CAP_CAPABILITY_ADMIN",
    "CAP_INCIDENT_ADMIN",
    "CAP_INCIDENT_COMMANDER",
    "CAP_PROMOTION_APPROVE",
    "HUMAN_ONLY_ROLES",
    "PROPOSER_EXCLUSIVE_ROLES",
    "Role",
    "RoleAssignments",
    "RoleConflict",
]


class Role(StrEnum):
    PROPOSER = "proposer"
    EXECUTOR = "executor"
    VERIFIER = "verifier"
    APPROVER = "approver"
    MERGER = "merger"
    INCIDENT_COMMANDER = "incident_commander"


HUMAN_ONLY_ROLES = frozenset({Role.APPROVER, Role.MERGER, Role.INCIDENT_COMMANDER})
PROPOSER_EXCLUSIVE_ROLES = frozenset({Role.APPROVER, Role.MERGER, Role.VERIFIER})
# TODO(control-plane-gap): the allowed principal kinds per role are design
# inference (e.g. an executor harness is a SERVICE); adjust per deployment.
_ALLOWED_KINDS: Mapping[Role, frozenset[PrincipalKind]] = {
    Role.PROPOSER: frozenset({PrincipalKind.AGENT, PrincipalKind.HUMAN}),
    Role.EXECUTOR: frozenset({PrincipalKind.SERVICE}),
    Role.VERIFIER: frozenset({PrincipalKind.SERVICE, PrincipalKind.HUMAN}),
    Role.APPROVER: frozenset({PrincipalKind.HUMAN}),
    Role.MERGER: frozenset({PrincipalKind.HUMAN}),
    Role.INCIDENT_COMMANDER: frozenset({PrincipalKind.HUMAN}),
}


CAP_PROMOTION_APPROVE = "promotion.approve"
CAP_INCIDENT_COMMANDER = "incident_commander"
CAP_INCIDENT_ADMIN = "incident_admin"
CAP_CAPABILITY_ADMIN = "capability_admin"
_CAPABILITY = re.compile(r"[A-Za-z0-9._:-]{1,128}")


class RoleConflict(PermissionError):
    """An assignment would break role separation."""


class RoleAssignments:
    """Per-change role table and organisation capabilities.

    Bound at construction to the deployment's configured HUMAN *admin*. Only
    the admin -- or a human the admin granted ``capability_admin`` -- may
    grant, revoke or assign; only the admin grants ``capability_admin``; the
    admin can never be a grantee (it may not mint approver powers it would
    then use alone). With *pdp* every grant and revoke (and every refused
    attempt) is published through the PDP, so it lands in the PDP's bound
    receipt ledger -- no new signing path.
    """

    def __init__(
        self,
        admin: Principal,
        *,
        pdp: PolicyDecisionPoint | None = None,
        admin_attestor: AdminAttestor | None = None,
    ) -> None:
        if not isinstance(admin, Principal) or admin.kind is not PrincipalKind.HUMAN:
            raise RoleConflict("RoleAssignments needs the configured HUMAN admin")
        if pdp is not None:
            from acgs_lite.control_plane.pdp import PolicyDecisionPoint

            if not isinstance(pdp, PolicyDecisionPoint):
                raise TypeError("pdp must be a PolicyDecisionPoint")
        from acgs_lite.control_plane.identity import checked_attestor

        self._attestor = checked_attestor(admin_attestor)
        self._admin = admin
        self._pdp = pdp
        self._lock = threading.Lock()
        self._roles: dict[str, dict[Role, dict[str, Principal]]] = {}
        self._capabilities: dict[str, dict[str, Principal]] = {}

    @property
    def admin(self) -> Principal:
        return self._admin

    def _is_admin(self, principal: object) -> bool:
        return (
            isinstance(principal, Principal)
            and principal.kind is PrincipalKind.HUMAN
            and principal.canonical_id == self._admin.canonical_id
        )

    def _may_administer(self, principal: object) -> bool:
        return self._is_admin(principal) or self.has_capability(principal, CAP_CAPABILITY_ADMIN)

    def _refuse(self, granter: object, action: str, resource: str, reason: str) -> RoleConflict:
        if self._pdp is not None:
            self._pdp.record_denial(
                reason,
                principal_id=str(getattr(granter, "id", "") or ""),
                action=action,
                resource=resource,
                error="role_grant_refused",
            )
        return RoleConflict(reason)

    def _receipt(self, granter: Principal, action: str, resource: str) -> None:
        pdp = self._pdp
        if pdp is None:
            return
        from acgs_lite.control_plane.context import DecisionRequest
        from acgs_lite.control_plane.tiers import ActionTier

        decision, _ = pdp._decide_attested(
            DecisionRequest(granter, action, resource, ActionTier.T1)
        )
        if not decision.allowed:
            raise RoleConflict(f"PDP denied {action}: {decision.reason}")

    def _attest(self, granter: object, credential: str | None, action: str, resource: str) -> None:
        """Phase 6a: with an attestor the granter must prove it is the
        directory human it claims to be (admin or capability_admin)."""
        if self._attestor is None:
            return
        try:
            self._attestor.require(granter, credential, admin_only=False)
        except PermissionError as exc:
            raise self._refuse(granter, action, resource, str(exc)) from exc

    def grant_capability(
        self,
        granter: Principal,
        capability: str,
        principal: Principal,
        *,
        admin_credential: str | None = None,
    ) -> None:
        """Grant an organisation capability to a HUMAN (receipted)."""
        if not isinstance(capability, str) or not _CAPABILITY.fullmatch(capability):
            raise self._refuse(granter, "roles.grant", "capability/?", "malformed capability")
        resource = f"capability/{capability}/{getattr(principal, 'id', '?')}"
        self._attest(granter, admin_credential, "roles.grant", resource)
        if not self._may_administer(granter):
            raise self._refuse(
                granter,
                "roles.grant",
                resource,
                "only the configured admin (or a capability_admin) grants capabilities",
            )
        if capability == CAP_CAPABILITY_ADMIN and not self._is_admin(granter):
            raise self._refuse(
                granter, "roles.grant", resource, "only the admin grants capability_admin"
            )
        if not isinstance(principal, Principal) or principal.kind is not PrincipalKind.HUMAN:
            raise self._refuse(
                granter, "roles.grant", resource, "capabilities are held by HUMAN principals only"
            )
        if self._is_admin(principal) or principal.canonical_id == granter.canonical_id:
            raise self._refuse(
                granter,
                "roles.grant",
                resource,
                "the admin (or a granter) can never grant a capability to themselves",
            )
        self._receipt(granter, "roles.grant", resource)
        with self._lock:
            self._capabilities.setdefault(capability, {})[principal.canonical_id] = principal

    def revoke_capability(
        self,
        granter: Principal,
        capability: str,
        principal: Principal,
        *,
        admin_credential: str | None = None,
    ) -> bool:
        resource = f"capability/{capability}/{getattr(principal, 'id', '?')}"
        self._attest(granter, admin_credential, "roles.revoke", resource)
        if not self._may_administer(granter):
            raise self._refuse(
                granter,
                "roles.revoke",
                resource,
                "only the configured admin (or a capability_admin) revokes capabilities",
            )
        self._receipt(granter, "roles.revoke", resource)
        with self._lock:
            members = self._capabilities.get(capability, {})
            return members.pop(getattr(principal, "canonical_id", ""), None) is not None

    def has_capability(self, principal: object, capability: str) -> bool:
        """True only for a HUMAN granted *capability* (same id and kind)."""
        if not isinstance(principal, Principal) or principal.kind is not PrincipalKind.HUMAN:
            return False
        with self._lock:
            holder = self._capabilities.get(capability, {}).get(principal.canonical_id)
        return holder is not None and holder.kind is principal.kind

    def assign(
        self,
        admin: Principal,
        change_id: str,
        role: Role | str,
        principal: Principal,
        *,
        admin_credential: str | None = None,
    ) -> None:
        if self._attestor is not None:
            self._attestor.require(admin, admin_credential, admin_only=False, error=RoleConflict)
        if not self._may_administer(admin):
            raise RoleConflict("only the configured admin (or a capability_admin) assigns roles")
        if not isinstance(change_id, str) or not change_id:
            raise RoleConflict("change_id must be a non-empty string")
        if not isinstance(principal, Principal):
            raise RoleConflict("principal must be a Principal")
        wanted = Role(role)
        if principal.kind not in _ALLOWED_KINDS[wanted]:
            raise RoleConflict(f"a {principal.kind.value} cannot hold role {wanted.value}")
        with self._lock:
            table = self._roles.setdefault(change_id, {})
            held = {r for r, members in table.items() if principal.canonical_id in members}
            if wanted is Role.PROPOSER and held & PROPOSER_EXCLUSIVE_ROLES:
                raise RoleConflict("the proposer cannot also approve, merge or verify its change")
            if wanted in PROPOSER_EXCLUSIVE_ROLES and Role.PROPOSER in held:
                raise RoleConflict(f"the proposer cannot also be {wanted.value} of its change")
            table.setdefault(wanted, {})[principal.canonical_id] = principal

    def holders(self, change_id: str, role: Role | str) -> tuple[Principal, ...]:
        with self._lock:
            return tuple(self._roles.get(change_id, {}).get(Role(role), {}).values())

    def has_role(self, change_id: str, role: Role | str, principal: Principal) -> bool:
        if not isinstance(principal, Principal):
            return False
        with self._lock:
            members = self._roles.get(change_id, {}).get(Role(role), {})
            holder = members.get(principal.canonical_id)
        # Same id *and* kind: an AGENT named like the human approver is not it.
        return holder is not None and holder.kind is principal.kind

    def require(self, change_id: str, role: Role | str, principal: Principal) -> None:
        if not self.has_role(change_id, role, principal):
            raise RoleConflict(
                f"{getattr(principal, 'id', principal)!r} does not hold role "
                f"{Role(role).value} for change {change_id!r}"
            )
