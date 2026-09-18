"""Authenticated execution grants distinct from evidence receipts."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from acgs_lite.legitimacy.invariants import LegitimacyInvariantError
from acgs_lite.legitimacy.invocation import InvocationBinding, PolicyBinding
from acgs_lite.legitimacy.receipt import DecisionReceipt, ExecutionBoundary


class AuthorizationProfile(str, Enum):
    """Constructor-selected execution authorization profile."""

    PRODUCTION = "production"
    COMPATIBILITY = "compatibility"


AUTHORIZATION_MAC_DOMAIN = b"acgs-grant-v1\x00"
TRUSTED_CONTEXT_DOMAIN = b"acgs-trusted-context-v1\x00"


@dataclass(slots=True, frozen=True)
class TrustedExecutionContext:
    """Host-supplied actor and tenant bounds; the host performs authentication."""

    actor_id: str
    scope: str
    allowed_subjects: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.actor_id, str) or not self.actor_id.strip():
            raise LegitimacyInvariantError("trusted context actor_id must be non-empty")
        if not isinstance(self.scope, str) or not self.scope.strip():
            raise LegitimacyInvariantError("trusted context scope must be non-empty")
        if not isinstance(self.allowed_subjects, frozenset) or not self.allowed_subjects:
            raise LegitimacyInvariantError("trusted context allowed_subjects must be non-empty")
        if any(not isinstance(subject, str) or not subject for subject in self.allowed_subjects):
            raise LegitimacyInvariantError("trusted context subjects must be non-empty strings")

    @property
    def digest(self) -> str:
        payload = {
            "actor_id": self.actor_id,
            "scope": self.scope,
            "allowed_subjects": sorted(self.allowed_subjects),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(TRUSTED_CONTEXT_DOMAIN + canonical.encode("utf-8")).hexdigest()

    def authorize(self, invocation: InvocationBinding) -> None:
        if invocation.scope != self.scope:
            raise LegitimacyInvariantError("trusted context scope mismatch")
        if not invocation.subjects:
            raise LegitimacyInvariantError("trusted context requires bound subjects")
        if not set(invocation.subjects).issubset(self.allowed_subjects):
            raise LegitimacyInvariantError("trusted context subjects are not allowed")


@runtime_checkable
class GrantResolver(Protocol):
    """Injected lookup for a previously issued grant. No storage in this module."""

    def resolve(self, grant_id: str) -> ExecutionGrant: ...


@runtime_checkable
class AsyncGrantResolver(Protocol):
    """Async counterpart of :class:`GrantResolver`."""

    async def resolve(self, grant_id: str) -> ExecutionGrant: ...


@dataclass(slots=True, frozen=True)
class ExecutionGrant:
    """Opaque-enough in-process capability. HMAC is process-local authenticity."""

    grant_id: str
    issuer_id: str
    receipt: DecisionReceipt
    method_id: str
    argument_digest: str
    policy_digest: str
    scope: str | None
    subjects: tuple[str, ...]
    issued_at: str
    expires_at: str | None
    single_use: bool
    binding_mac: str
    context_digest: str | None = None
    # Keeping the target alive prevents reuse of its MAC-bound process-local id.
    callable_target: Callable[..., Any] | None = field(default=None, repr=False, compare=False)

    def to_evidence_dict(self) -> dict[str, Any]:
        """Serializable evidence. The MAC is omitted so this cannot be replayed as a grant."""
        return {
            "grant_id": self.grant_id,
            "issuer_id": self.issuer_id,
            "receipt_hash": self.receipt.receipt_hash,
            "method_id": self.method_id,
            "argument_digest": self.argument_digest,
            "policy_digest": self.policy_digest,
            "scope": self.scope,
            "subjects": list(self.subjects),
            "context_digest": self.context_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "single_use": self.single_use,
        }


class ExecutionAuthority:
    """Mints and verifies same-instance grants with a per-authority HMAC key."""

    def __init__(self) -> None:
        self.issuer_id = uuid.uuid4().hex
        self._secret = secrets.token_bytes(32)

    def issue(
        self,
        *,
        receipt: DecisionReceipt,
        invocation: InvocationBinding,
        policy: PolicyBinding,
        expires_at: str | None = None,
        single_use: bool = True,
        context_digest: str | None = None,
        callable_target: Callable[..., Any] | None = None,
    ) -> ExecutionGrant:
        issued_at = datetime.now(timezone.utc).isoformat()
        grant_id = uuid.uuid4().hex
        mac = self._mac(
            grant_id=grant_id,
            receipt_hash=receipt.receipt_hash,
            method_id=invocation.method_id,
            argument_digest=invocation.argument_digest,
            policy_digest=policy.digest,
            scope=invocation.scope,
            subjects=invocation.subjects,
            context_digest=context_digest,
            issued_at=issued_at,
            expires_at=expires_at,
            single_use=single_use,
            callable_target=callable_target,
        )
        return ExecutionGrant(
            grant_id=grant_id,
            issuer_id=self.issuer_id,
            receipt=receipt,
            method_id=invocation.method_id,
            argument_digest=invocation.argument_digest,
            policy_digest=policy.digest,
            scope=invocation.scope,
            subjects=invocation.subjects,
            context_digest=context_digest,
            issued_at=issued_at,
            expires_at=expires_at,
            single_use=single_use,
            binding_mac=mac,
            callable_target=callable_target,
        )

    def verify(
        self,
        grant: ExecutionGrant,
        *,
        invocation: InvocationBinding,
        policy: PolicyBinding,
        context_digest: str | None = None,
    ) -> None:
        if grant.issuer_id != self.issuer_id:
            raise LegitimacyInvariantError("grant issuer does not match this authority")
        expected = self._mac(
            grant_id=grant.grant_id,
            receipt_hash=grant.receipt.receipt_hash,
            method_id=grant.method_id,
            argument_digest=grant.argument_digest,
            policy_digest=grant.policy_digest,
            scope=grant.scope,
            subjects=grant.subjects,
            context_digest=grant.context_digest,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            single_use=grant.single_use,
            callable_target=grant.callable_target,
        )
        if not hmac.compare_digest(expected, grant.binding_mac):
            raise LegitimacyInvariantError("grant authenticity check failed")
        if not grant.receipt.verify_hash():
            raise LegitimacyInvariantError("grant receipt integrity check failed")
        if grant.method_id != invocation.method_id:
            raise LegitimacyInvariantError("grant method identity mismatch")
        if grant.argument_digest != invocation.argument_digest:
            raise LegitimacyInvariantError("invocation binding mismatch")
        if grant.policy_digest != policy.digest:
            raise LegitimacyInvariantError("policy binding mismatch")
        if grant.context_digest != context_digest:
            raise LegitimacyInvariantError("trusted execution context binding mismatch")
        if grant.expires_at is not None:
            try:
                expires = datetime.fromisoformat(grant.expires_at)
            except ValueError as exc:
                raise LegitimacyInvariantError("grant expiry is not parseable") from exc
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires:
                raise LegitimacyInvariantError("grant has expired")

    def _mac(
        self,
        *,
        grant_id: str,
        receipt_hash: str,
        method_id: str,
        argument_digest: str,
        policy_digest: str,
        scope: str | None,
        subjects: tuple[str, ...],
        context_digest: str | None,
        issued_at: str,
        expires_at: str | None,
        single_use: bool,
        callable_target: Callable[..., Any] | None = None,
    ) -> str:
        payload = {
            "grant_id": grant_id,
            "receipt_hash": receipt_hash,
            "method_id": method_id,
            "argument_digest": argument_digest,
            "policy_digest": policy_digest,
            "scope": scope,
            "subjects": list(subjects),
            "context_digest": context_digest,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "single_use": single_use,
        }
        if callable_target is not None:
            payload["callable_identity"] = str(id(callable_target))
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        digest = hmac.new(
            self._secret,
            AUTHORIZATION_MAC_DOMAIN + canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return digest


def build_issue_receipt(
    *,
    func: Callable[..., Any],
    invocation: InvocationBinding,
    policy: PolicyBinding,
) -> DecisionReceipt:
    """Kernel-built evidence receipt. Callers cannot supply the receipt being bound."""
    boundary = ExecutionBoundary(
        allowed_method=func.__name__,
        allowed_scope=invocation.scope,
        allowed_subjects=invocation.subjects,
        expires_at=None,
        single_use=True,
    )
    return DecisionReceipt.create(
        request_id=f"grant-{uuid.uuid4().hex}",
        goal=f"Authorized invocation of {invocation.method_id}",
        proposed_method=func.__name__,
        decision_type="ALLOW",
        authority_basis="acgs-lite:execution-authority",
        matched_constraints=("execution-grant-issued",),
        policy_version=policy.version,
        required_controls=(),
        execution_boundary=boundary,
    )


def authorization_envelope_json(invocation: InvocationBinding, policy: PolicyBinding) -> str:
    """Canonical envelope covered by a v2 execution signature."""
    payload = {
        "method_id": invocation.method_id,
        "argument_digest": invocation.argument_digest,
        "policy_digest": policy.digest,
        "scope": invocation.scope,
        "subjects": list(invocation.subjects),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)


def parse_authorization_envelope(authorization_json: str) -> dict[str, Any]:
    if not isinstance(authorization_json, str):
        raise LegitimacyInvariantError("authorization envelope must be a string")
    try:
        payload = json.loads(authorization_json)
    except (json.JSONDecodeError, TypeError) as exc:
        raise LegitimacyInvariantError("authorization envelope is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise LegitimacyInvariantError("authorization envelope must be an object")
    return payload


def resolve_profile(
    requested: AuthorizationProfile | str | None,
) -> AuthorizationProfile:
    """Constructor-only profile selection. Unset defaults to compatibility."""
    if requested is None:
        return AuthorizationProfile.COMPATIBILITY
    if isinstance(requested, AuthorizationProfile):
        return requested
    try:
        return AuthorizationProfile(str(requested))
    except ValueError as exc:
        raise LegitimacyInvariantError(f"unknown authorization profile: {requested!r}") from exc


def extract_authorization_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Pop authorization transport kwargs. Fail closed if more than one token is present."""
    tokens = {
        "decision_receipt": kwargs.pop("decision_receipt", None),
        "acgs_receipt": kwargs.pop("acgs_receipt", None),
        "execution_grant": kwargs.pop("execution_grant", None),
        "acgs_grant": kwargs.pop("acgs_grant", None),
        "signed_receipt": kwargs.pop("signed_receipt", None),
        "grant_id": kwargs.pop("grant_id", None),
    }
    present = {name: value for name, value in tokens.items() if value is not None}
    aliases = set()
    if "decision_receipt" in present:
        aliases.add("receipt")
    if "acgs_receipt" in present:
        aliases.add("receipt")
    if "execution_grant" in present:
        aliases.add("grant")
    if "acgs_grant" in present:
        aliases.add("grant")
    if "signed_receipt" in present:
        aliases.add("signed")
    if "grant_id" in present:
        aliases.add("id")
    if len(aliases) > 1:
        raise LegitimacyInvariantError("exactly one authorization token is permitted")
    human_approval = kwargs.pop("human_approval", None)
    present["human_approval"] = human_approval
    present["execution_attempt_id"] = kwargs.pop("execution_attempt_id", None)
    return present


__all__ = [
    "AUTHORIZATION_MAC_DOMAIN",
    "AsyncGrantResolver",
    "AuthorizationProfile",
    "ExecutionAuthority",
    "ExecutionGrant",
    "GrantResolver",
    "TrustedExecutionContext",
    "authorization_envelope_json",
    "build_issue_receipt",
    "extract_authorization_kwargs",
    "parse_authorization_envelope",
    "resolve_profile",
]
