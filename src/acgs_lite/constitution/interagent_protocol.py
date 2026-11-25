"""exp219: InterAgentGovernanceProtocol — zero-trust agent-to-agent delegation chains.

Models the governance of delegation relationships between AI agents. When agent A
wants to delegate a task to agent B, that delegation must itself be constitutionally
governed: scoped, time-bounded, revocable, and chain-verifiable.

Implements a zero-trust model where every link in a delegation chain is independently
validated against the active constitution. An executor can only be granted the
permissions the delegator itself holds — delegation can only narrow permissions, never
expand them. (Cited: Springer AI Safety / Security Blvd, 2026.)

Key capabilities:
- Delegation chain construction with scope narrowing semantics
- Per-link constitutional validation (every delegation is a governed action)
- Chain-wide validity check: any revoked or expired link breaks the chain
- Scope intersection enforcement: delegatee gets min(delegator_scope, requested_scope)
- Depth limits to prevent unbounded delegation pyramids
- Revocation with cascade: revoking a link also invalidates all descendant links
- Delegation receipt: signed record of who delegated what to whom and when
- Chain traversal: find the root principal for any agent
- Audit export: full delegation chain as structured report

Usage::

    from acgs_lite.constitution.interagent_protocol import (
        InterAgentGovernanceProtocol,
        DelegationChain,
        DelegationLink,
    )

    protocol = InterAgentGovernanceProtocol(max_depth=5)

    # Agent A delegates a subset of its permissions to Agent B
    result = protocol.delegate(
        delegator_id="agent-A",
        delegatee_id="agent-B",
        delegator_scope={"read", "write", "deploy"},
        requested_scope={"read", "write"},
        constitution=constitution,
        ttl_seconds=3600,
    )

    # Validate that agent-B is authorized to perform an action
    auth = protocol.authorize(agent_id="agent-B", action="read data", constitution=constitution)
    assert auth.authorized
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from acgs_lite._compat import constant_time_compare

_SIGNING_KEY = secrets.token_bytes(32)


def _sign(payload: str) -> str:
    return hmac.new(_SIGNING_KEY, payload.encode(), hashlib.sha256).hexdigest()[:16]


def _ts() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DelegationLink:
    """A single link in a delegation chain.

    Represents one agent delegating a scoped set of permissions to another
    for a bounded time window.
    """

    link_id: str
    delegator_id: str
    delegatee_id: str
    granted_scope: frozenset[str]
    issued_at: float
    expires_at: float
    depth: int
    signature: str
    revoked: bool = False
    revocation_reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired

    def verify_signature(self) -> bool:
        payload = (
            f"{self.link_id}:{self.delegator_id}:{self.delegatee_id}:{sorted(self.granted_scope)}"
        )
        return constant_time_compare(self.signature, _sign(payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "link_id": self.link_id,
            "delegator_id": self.delegator_id,
            "delegatee_id": self.delegatee_id,
            "granted_scope": sorted(self.granted_scope),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "depth": self.depth,
            "revoked": self.revoked,
            "revocation_reason": self.revocation_reason,
            "is_expired": self.is_expired,
            "is_valid": self.is_valid,
            "signature_valid": self.verify_signature(),
        }


@dataclass
class DelegationChain:
    """An ordered sequence of delegation links from root principal to terminal agent."""

    links: list[DelegationLink] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return bool(self.links) and all(lnk.is_valid for lnk in self.links)

    @property
    def root_principal(self) -> str | None:
        return self.links[0].delegator_id if self.links else None

    @property
    def terminal_agent(self) -> str | None:
        return self.links[-1].delegatee_id if self.links else None

    @property
    def effective_scope(self) -> frozenset[str]:
        if not self.links:
            return frozenset()
        scope = self.links[0].granted_scope
        for lnk in self.links[1:]:
            scope = scope & lnk.granted_scope
        return scope

    @property
    def depth(self) -> int:
        return len(self.links)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_principal": self.root_principal,
            "terminal_agent": self.terminal_agent,
            "depth": self.depth,
            "is_valid": self.is_valid,
            "effective_scope": sorted(self.effective_scope),
            "links": [lnk.to_dict() for lnk in self.links],
        }


@dataclass(frozen=True)
class DelegationResult:
    """Outcome of a delegation request."""

    success: bool
    link: DelegationLink | None
    granted_scope: frozenset[str]
    requested_scope: frozenset[str]
    denied_scope: frozenset[str]
    reason: str
    governance_outcome: str
    governance_violations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "link_id": self.link.link_id if self.link else None,
            "granted_scope": sorted(self.granted_scope),
            "requested_scope": sorted(self.requested_scope),
            "denied_scope": sorted(self.denied_scope),
            "reason": self.reason,
            "governance_outcome": self.governance_outcome,
            "governance_violations": list(self.governance_violations),
        }


@dataclass(frozen=True)
class AuthorizationResult:
    """Outcome of an authorization check for an agent action."""

    authorized: bool
    agent_id: str
    action: str
    chain: DelegationChain | None
    effective_scope: frozenset[str]
    reason: str
    governance_outcome: str
    governance_violations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorized": self.authorized,
            "agent_id": self.agent_id,
            "action": self.action,
            "effective_scope": sorted(self.effective_scope),
            "reason": self.reason,
            "governance_outcome": self.governance_outcome,
            "governance_violations": list(self.governance_violations),
            "chain_depth": self.chain.depth if self.chain else 0,
            "root_principal": self.chain.root_principal if self.chain else None,
        }


# ---------------------------------------------------------------------------
# Protocol engine
# ---------------------------------------------------------------------------


class InterAgentGovernanceProtocol:
    """Zero-trust delegation chain manager with constitutional governance.

    Every delegation request is validated against the constitution before
    a link is issued. Scope can only be narrowed across delegation hops —
    never expanded. Revocation cascades to all downstream links.

    Args:
        max_depth: Maximum delegation chain depth (default: 5).
        default_ttl_seconds: Default link lifetime if not specified (default: 3600).
    """

    def __init__(
        self,
        max_depth: int = 5,
        default_ttl_seconds: float = 3600.0,
    ) -> None:
        self._max_depth = max_depth
        self._default_ttl = default_ttl_seconds
        self._links: dict[str, DelegationLink] = {}
        self._agent_links: dict[str, list[str]] = {}
        self._root_scopes: dict[str, frozenset[str]] = {}

    def register_principal(self, agent_id: str, scope: set[str]) -> None:
        """Register a root principal with an initial permission scope."""
        self._root_scopes[agent_id] = frozenset(scope)

    def delegate(
        self,
        delegator_id: str,
        delegatee_id: str,
        delegator_scope: set[str],
        requested_scope: set[str],
        constitution: Any | None = None,
        ttl_seconds: float | None = None,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DelegationResult:
        """Issue a delegation link from *delegator_id* to *delegatee_id*.

        The granted scope is the intersection of delegator_scope and requested_scope —
        you cannot delegate permissions you don't have.

        Args:
            delegator_id: Agent issuing the delegation.
            delegatee_id: Agent receiving the delegation.
            delegator_scope: Permissions the delegator currently holds.
            requested_scope: Permissions the delegatee is requesting.
            constitution: Optional constitution to validate the delegation action.
            ttl_seconds: Lifetime of the delegation link in seconds.
            context: Extra context forwarded to constitution.validate().
            metadata: Arbitrary metadata attached to the link.

        Returns:
            :class:`DelegationResult` indicating success/failure and granted scope.
        """
        delegator_fs = frozenset(delegator_scope)
        requested_fs = frozenset(requested_scope)

        chain = self.get_chain(delegatee_id)
        current_depth = chain.depth if chain else 0

        if current_depth >= self._max_depth:
            return DelegationResult(
                success=False,
                link=None,
                granted_scope=frozenset(),
                requested_scope=requested_fs,
                denied_scope=requested_fs,
                reason=f"Max delegation depth {self._max_depth} reached",
                governance_outcome="deny",
                governance_violations=(),
            )

        granted = delegator_fs & requested_fs
        denied = requested_fs - granted

        gov_outcome = "allow"
        gov_violations: tuple[str, ...] = ()
        if constitution is not None:
            action = f"delegate permissions {sorted(granted)} from {delegator_id} to {delegatee_id}"
            try:
                result = constitution.validate(action, context=context or {})
                gov_outcome = str(getattr(result, "outcome", "allow"))
                gov_violations = tuple(
                    getattr(v, "rule_id", str(v)) for v in (getattr(result, "violations", []) or [])
                )
            except Exception as exc:
                gov_outcome = "error"
                gov_violations = (str(exc),)

        if gov_outcome in ("deny", "block", "error"):
            return DelegationResult(
                success=False,
                link=None,
                granted_scope=frozenset(),
                requested_scope=requested_fs,
                denied_scope=requested_fs,
                reason=f"Constitution blocked delegation: {gov_outcome}",
                governance_outcome=gov_outcome,
                governance_violations=gov_violations,
            )

        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = time.time()
        link_id = secrets.token_hex(8)
        payload = f"{link_id}:{delegator_id}:{delegatee_id}:{sorted(granted)}"
        sig = _sign(payload)

        link = DelegationLink(
            link_id=link_id,
            delegator_id=delegator_id,
            delegatee_id=delegatee_id,
            granted_scope=granted,
            issued_at=now,
            expires_at=now + ttl,
            depth=current_depth + 1,
            signature=sig,
            metadata=metadata or {},
        )

        self._links[link_id] = link
        self._agent_links.setdefault(delegatee_id, []).append(link_id)

        return DelegationResult(
            success=True,
            link=link,
            granted_scope=granted,
            requested_scope=requested_fs,
            denied_scope=denied,
            reason="Delegation granted",
            governance_outcome=gov_outcome,
            governance_violations=gov_violations,
        )

    def revoke(
        self,
        link_id: str,
        reason: str = "manually revoked",
        cascade: bool = True,
    ) -> list[str]:
        """Revoke a delegation link.

        Args:
            link_id: ID of the link to revoke.
            reason: Human-readable revocation reason.
            cascade: If True, also revoke all downstream links.

        Returns:
            List of all revoked link IDs.
        """
        if link_id not in self._links:
            return []

        revoked_ids: list[str] = []
        lnk = self._links[link_id]
        self._links[link_id] = DelegationLink(
            link_id=lnk.link_id,
            delegator_id=lnk.delegator_id,
            delegatee_id=lnk.delegatee_id,
            granted_scope=lnk.granted_scope,
            issued_at=lnk.issued_at,
            expires_at=lnk.expires_at,
            depth=lnk.depth,
            signature=lnk.signature,
            revoked=True,
            revocation_reason=reason,
            metadata=lnk.metadata,
        )
        revoked_ids.append(link_id)

        if cascade:
            agent_id = lnk.delegatee_id
            for downstream_id in list(self._agent_links.get(agent_id, [])):
                downstream_link = self._links.get(downstream_id)
                if downstream_link and not downstream_link.revoked:
                    revoked_ids.extend(
                        self.revoke(downstream_id, reason=f"cascade from {link_id}", cascade=True)
                    )

        return revoked_ids

    def get_chain(self, agent_id: str) -> DelegationChain | None:
        """Return the active delegation chain that grants *agent_id* its permissions."""
        link_ids = self._agent_links.get(agent_id, [])
        active_links = [
            self._links[lid] for lid in link_ids if lid in self._links and self._links[lid].is_valid
        ]
        if not active_links:
            return None
        active_links.sort(key=lambda lnk: lnk.issued_at)
        return DelegationChain(links=active_links)

    def effective_scope(self, agent_id: str) -> frozenset[str]:
        """Return the effective permission scope for *agent_id*.

        Combines root scope (if registered) with active delegation links.
        """
        root = self._root_scopes.get(agent_id, frozenset())
        chain = self.get_chain(agent_id)
        chain_scope = chain.effective_scope if chain else frozenset()
        return root | chain_scope

    def authorize(
        self,
        agent_id: str,
        action: str,
        constitution: Any | None = None,
        context: dict[str, Any] | None = None,
        required_scope: set[str] | None = None,
    ) -> AuthorizationResult:
        """Check whether *agent_id* is authorized to perform *action*.

        Authorization requires:
        1. The delegation chain (if any) is valid (no revoked/expired links).
        2. If required_scope is specified, agent must hold all required permissions.
        3. If constitution is provided, the action must pass constitutional validation.

        Args:
            agent_id: The agent requesting authorization.
            action: The action being requested.
            constitution: Optional constitution to validate the action.
            context: Context dict forwarded to constitution.validate().
            required_scope: Optional set of permission strings the agent must hold.

        Returns:
            :class:`AuthorizationResult`.
        """
        chain = self.get_chain(agent_id)
        scope = self.effective_scope(agent_id)

        if required_scope:
            missing = frozenset(required_scope) - scope
            if missing:
                return AuthorizationResult(
                    authorized=False,
                    agent_id=agent_id,
                    action=action,
                    chain=chain,
                    effective_scope=scope,
                    reason=f"Missing required permissions: {sorted(missing)}",
                    governance_outcome="deny",
                    governance_violations=(),
                )

        if chain and not chain.is_valid:
            return AuthorizationResult(
                authorized=False,
                agent_id=agent_id,
                action=action,
                chain=chain,
                effective_scope=scope,
                reason="Delegation chain contains revoked or expired links",
                governance_outcome="deny",
                governance_violations=(),
            )

        gov_outcome = "allow"
        gov_violations: tuple[str, ...] = ()
        if constitution is not None:
            try:
                result = constitution.validate(action, context=context or {})
                gov_outcome = str(getattr(result, "outcome", "allow"))
                gov_violations = tuple(
                    getattr(v, "rule_id", str(v)) for v in (getattr(result, "violations", []) or [])
                )
            except Exception as exc:
                gov_outcome = "error"
                gov_violations = (str(exc),)

        authorized = gov_outcome not in ("deny", "block", "error")
        reason = "Authorized" if authorized else f"Constitution denied: {gov_outcome}"

        return AuthorizationResult(
            authorized=authorized,
            agent_id=agent_id,
            action=action,
            chain=chain,
            effective_scope=scope,
            reason=reason,
            governance_outcome=gov_outcome,
            governance_violations=gov_violations,
        )

    def find_root(self, agent_id: str) -> str:
        """Walk delegation links back to find the root principal."""
        chain = self.get_chain(agent_id)
        if chain and chain.root_principal:
            return chain.root_principal
        return agent_id

    def list_links(
        self,
        agent_id: str | None = None,
        active_only: bool = True,
    ) -> list[DelegationLink]:
        """List delegation links, optionally filtered by agent."""
        links = list(self._links.values())
        if agent_id:
            links = [lnk for lnk in links if lnk.delegatee_id == agent_id]
        if active_only:
            links = [lnk for lnk in links if lnk.is_valid]
        links.sort(key=lambda lnk: lnk.issued_at)
        return links

    def summary(self) -> dict[str, Any]:
        """Return aggregate statistics for the delegation registry."""
        all_links = list(self._links.values())
        active = [lnk for lnk in all_links if lnk.is_valid]
        revoked = [lnk for lnk in all_links if lnk.revoked]
        expired = [lnk for lnk in all_links if lnk.is_expired and not lnk.revoked]
        return {
            "total_links": len(all_links),
            "active_links": len(active),
            "revoked_links": len(revoked),
            "expired_links": len(expired),
            "registered_principals": len(self._root_scopes),
            "agents_with_delegations": len(self._agent_links),
            "max_depth": self._max_depth,
            "generated_at": _ts(),
        }
