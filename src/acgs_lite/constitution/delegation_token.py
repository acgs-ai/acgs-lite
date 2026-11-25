"""exp198: VerifiableDelegationToken — signed delegation tokens.

Transport-agnostic, HMAC-signed delegation tokens with scope constraints,
expiry, chain verification, revocation, and self-contained authority proof.
Extends exp176 DelegationRegistry with portable token format.
Zero hot-path overhead (offline tooling only).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from acgs_lite._compat import constant_time_compare


class TokenStatus(Enum):
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID_SIGNATURE = "invalid_signature"
    SCOPE_VIOLATION = "scope_violation"


@dataclass
class DelegationScope:
    permissions: set[str] = field(default_factory=set)
    resource_patterns: list[str] = field(default_factory=list)
    max_depth: int = 1
    excluded_actions: set[str] = field(default_factory=set)

    def allows(self, permission: str, resource: str = "*") -> bool:
        if permission in self.excluded_actions:
            return False
        if self.permissions and permission not in self.permissions:
            return False
        if self.resource_patterns:
            return any(self._match(pat, resource) for pat in self.resource_patterns)
        return True

    def narrow(self, child_scope: DelegationScope) -> DelegationScope:
        narrowed_perms = (
            self.permissions & child_scope.permissions
            if self.permissions and child_scope.permissions
            else (self.permissions or child_scope.permissions)
        )
        narrowed_excluded = self.excluded_actions | child_scope.excluded_actions
        return DelegationScope(
            permissions=narrowed_perms,
            resource_patterns=child_scope.resource_patterns or self.resource_patterns,
            max_depth=min(self.max_depth, child_scope.max_depth),
            excluded_actions=narrowed_excluded,
        )

    @staticmethod
    def _match(pattern: str, resource: str) -> bool:
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return resource.startswith(pattern[:-1])
        return pattern == resource

    def to_dict(self) -> dict[str, Any]:
        return {
            "permissions": sorted(self.permissions),
            "resource_patterns": self.resource_patterns,
            "max_depth": self.max_depth,
            "excluded_actions": sorted(self.excluded_actions),
        }


@dataclass
class VerifiableDelegationToken:
    issuer: str
    subject: str
    scope: DelegationScope
    issued_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    parent_token_id: str = ""
    chain_depth: int = 0
    token_id: str = ""
    signature: str = ""
    nonce: str = ""

    def __post_init__(self) -> None:
        if not self.token_id:
            self.token_id = f"dtkn-{int(self.issued_at * 1000)}-{id(self) % 100000}"
        if not self.nonce:
            self.nonce = hashlib.sha256(f"{self.token_id}{time.time()}".encode()).hexdigest()[:8]
        if self.expires_at == 0.0:
            self.expires_at = self.issued_at + 3600

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def payload(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "scope": self.scope.to_dict(),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "parent_token_id": self.parent_token_id,
            "chain_depth": self.chain_depth,
            "nonce": self.nonce,
        }

    def to_dict(self) -> dict[str, Any]:
        result = self.payload()
        result["signature"] = self.signature
        return result


class DelegationTokenAuthority:
    """Issues, verifies, and manages delegation tokens.

    Example::

        authority = DelegationTokenAuthority(signing_key="my-secret-key")

        scope = DelegationScope(
            permissions={"read_rules", "validate"},
            max_depth=2,
        )
        token = authority.issue("admin", "agent-007", scope, ttl_seconds=7200)

        result = authority.verify(token)
        assert result.status == TokenStatus.VALID

        child = authority.delegate(token, "agent-007", "agent-008",
                                   DelegationScope(permissions={"read_rules"}))
        assert authority.verify(child).status == TokenStatus.VALID
    """

    def __init__(self, signing_key: str = "default-governance-key") -> None:
        self._signing_key = signing_key.encode()
        self._revoked: set[str] = set()
        self._issued: list[VerifiableDelegationToken] = []

    def issue(
        self,
        issuer: str,
        subject: str,
        scope: DelegationScope,
        *,
        ttl_seconds: float = 3600,
        parent_token_id: str = "",
        chain_depth: int = 0,
    ) -> VerifiableDelegationToken:
        now = time.time()
        token = VerifiableDelegationToken(
            issuer=issuer,
            subject=subject,
            scope=scope,
            issued_at=now,
            expires_at=now + ttl_seconds,
            parent_token_id=parent_token_id,
            chain_depth=chain_depth,
        )
        token.signature = self._sign(token)
        self._issued.append(token)
        return token

    def verify(self, token: VerifiableDelegationToken) -> VerificationResult:
        if token.token_id in self._revoked:
            return VerificationResult(TokenStatus.REVOKED, token.token_id)

        expected_sig = self._sign(token)
        if not constant_time_compare(token.signature, expected_sig):
            return VerificationResult(TokenStatus.INVALID_SIGNATURE, token.token_id)

        if token.is_expired:
            return VerificationResult(TokenStatus.EXPIRED, token.token_id)

        if token.parent_token_id and token.parent_token_id in self._revoked:
            return VerificationResult(
                TokenStatus.REVOKED, token.token_id, reason="Parent token revoked"
            )

        return VerificationResult(TokenStatus.VALID, token.token_id)

    def delegate(
        self,
        parent_token: VerifiableDelegationToken,
        delegator: str,
        delegatee: str,
        child_scope: DelegationScope,
        *,
        ttl_seconds: float = 1800,
    ) -> VerifiableDelegationToken | None:
        if parent_token.subject != delegator:
            return None
        if parent_token.chain_depth >= parent_token.scope.max_depth:
            return None

        parent_check = self.verify(parent_token)
        if parent_check.status != TokenStatus.VALID:
            return None

        narrowed = parent_token.scope.narrow(child_scope)
        remaining_ttl = parent_token.expires_at - time.time()
        effective_ttl = min(ttl_seconds, remaining_ttl)
        if effective_ttl <= 0:
            return None

        return self.issue(
            delegator,
            delegatee,
            narrowed,
            ttl_seconds=effective_ttl,
            parent_token_id=parent_token.token_id,
            chain_depth=parent_token.chain_depth + 1,
        )

    def check_permission(
        self, token: VerifiableDelegationToken, permission: str, resource: str = "*"
    ) -> VerificationResult:
        base_check = self.verify(token)
        if base_check.status != TokenStatus.VALID:
            return base_check
        if not token.scope.allows(permission, resource):
            return VerificationResult(
                TokenStatus.SCOPE_VIOLATION,
                token.token_id,
                reason=f"Permission '{permission}' on '{resource}' not in scope",
            )
        return VerificationResult(TokenStatus.VALID, token.token_id)

    def revoke(self, token_id: str) -> bool:
        self._revoked.add(token_id)
        return True

    def revoke_chain(self, token_id: str) -> int:
        self._revoked.add(token_id)
        count = 1
        for t in self._issued:
            if t.parent_token_id == token_id and t.token_id not in self._revoked:
                count += self.revoke_chain(t.token_id)
        return count

    def active_tokens(self) -> list[dict[str, Any]]:
        return [
            t.to_dict()
            for t in self._issued
            if t.token_id not in self._revoked and not t.is_expired
        ]

    def chain_for(self, token_id: str) -> list[str]:
        chain: list[str] = []
        current = token_id
        visited: set[str] = set()
        while current and current not in visited:
            visited.add(current)
            chain.append(current)
            parent = next((t.parent_token_id for t in self._issued if t.token_id == current), "")
            current = parent
        chain.reverse()
        return chain

    def summary(self) -> dict[str, Any]:
        now = time.time()
        active = [t for t in self._issued if t.token_id not in self._revoked and not t.is_expired]
        expired = [t for t in self._issued if t.expires_at < now]
        return {
            "total_issued": len(self._issued),
            "active": len(active),
            "revoked": len(self._revoked),
            "expired": len(expired),
            "max_chain_depth": max((t.chain_depth for t in self._issued), default=0),
        }

    def _sign(self, token: VerifiableDelegationToken) -> str:
        payload_bytes = json.dumps(token.payload(), sort_keys=True).encode()
        return hmac.new(self._signing_key, payload_bytes, hashlib.sha256).hexdigest()[:32]


@dataclass
class VerificationResult:
    status: TokenStatus
    token_id: str
    reason: str = ""
    verified_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "token_id": self.token_id,
            "reason": self.reason,
            "verified_at": self.verified_at,
        }
