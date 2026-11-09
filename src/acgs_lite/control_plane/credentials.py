"""Short-TTL scoped credentials issued by the harness, never by the agent.

The :class:`CredentialIssuer` holds a per-issuer 32-byte HMAC secret
(``secrets.token_bytes``) that never leaves the harness. Tokens are opaque
``<base64url payload>.<hex HMAC-SHA256>`` strings; they expire, can be revoked
one by one (:meth:`CredentialIssuer.revoke`) or all at once per principal
(:meth:`CredentialIssuer.revoke_principal` bumps a revocation epoch), and a
TTL above ``max_ttl_s`` is refused.

Evidence: STOP -- agents flipped ``use_sandbox`` and a warning in the prompt
did not help, so authority must come from something the model cannot mint.
An agent may request a credential only for itself and never for a scope that
touches the immutable core.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from acgs_lite.control_plane.immutable_core import DEFAULT_IMMUTABLE_CORE, ImmutableCoreRegistry
from acgs_lite.control_plane.invariants import ACTION_NAMESPACE_CATEGORIES
from acgs_lite.control_plane.principal import Principal, PrincipalKind, canonical_principal_id

__all__ = [
    "DEFAULT_CREDENTIAL_TTL_S",
    "MAX_CREDENTIAL_TTL_S",
    "CredentialInvalid",
    "CredentialIssuanceRefused",
    "CredentialIssuer",
    "ScopedCredential",
    "scope_touches_core",
]

# TODO(control-plane-gap): 5 min default / 15 min cap are design inference
# (short enough to bound a leaked token, long enough for one agent step).
DEFAULT_CREDENTIAL_TTL_S = 300.0
MAX_CREDENTIAL_TTL_S = 900.0
_TOKEN_DOMAIN = b"acgs-control-plane-credential-v1\x00"
_SCOPE = re.compile(r"[A-Za-z0-9._:/*@-]{1,256}")
_PAYLOAD_KEYS = frozenset({"cid", "pid", "scopes", "iat", "exp", "epoch", "obo"})
_PRINCIPAL_ID = re.compile(r"[A-Za-z0-9._@:-]+")


class CredentialInvalid(Exception):
    """A token failed verification (tampered, expired, revoked, wrong scope)."""


class CredentialIssuanceRefused(PermissionError):
    """The issuer refused to mint a credential."""


@dataclass(frozen=True)
class ScopedCredential:
    token: str
    principal_id: str
    scopes: frozenset[str]
    issued_at: float
    expires_at: float
    credential_id: str
    on_behalf_of: str | None = None
    """Canonical id of the original requester this session acts for (signed)."""


def scope_touches_core(
    scope: str, registry: ImmutableCoreRegistry = DEFAULT_IMMUTABLE_CORE
) -> bool:
    """True for scopes in a core action namespace or naming a core path.

    ``tool:<name>`` scopes name a tool, not a path; the dispatcher still
    checks every path that tool receives.
    """
    head, _, rest = scope.partition(":")
    head = head.lower()
    if head in ACTION_NAMESPACE_CATEGORIES or head in {"core", "admin", "*"}:
        return True
    if "*" in scope and head != "tool":
        return True
    if head == "path":
        return registry.is_core(rest)
    return False


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    """Strict urlsafe base64: no foreign characters, canonical encoding only."""
    raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    if _b64encode(raw) != text:
        raise ValueError("non-canonical base64")
    return raw


class CredentialIssuer:
    """Mint and verify short-lived, scoped, revocable tokens."""

    def __init__(
        self,
        hmac_key: bytes | None = None,
        *,
        default_ttl_s: float = DEFAULT_CREDENTIAL_TTL_S,
        max_ttl_s: float = MAX_CREDENTIAL_TTL_S,
        registry: ImmutableCoreRegistry = DEFAULT_IMMUTABLE_CORE,
        clock: Callable[[], float] = time.time,
    ) -> None:
        key = secrets.token_bytes(32) if hmac_key is None else hmac_key
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("hmac_key must be at least 32 bytes")
        for label, value in (("default_ttl_s", default_ttl_s), ("max_ttl_s", max_ttl_s)):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{label} must be a number")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{label} must be positive and finite")
        if default_ttl_s > max_ttl_s:
            raise ValueError("default_ttl_s must not exceed max_ttl_s")
        self._key = key
        self._default_ttl = float(default_ttl_s)
        self._max_ttl = float(max_ttl_s)
        self._registry = registry
        self._clock = clock
        self._lock = threading.Lock()
        self._revoked: set[str] = set()
        self._epochs: dict[str, int] = {}

    def __repr__(self) -> str:
        return f"CredentialIssuer(max_ttl_s={self._max_ttl})"

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("CredentialIssuer cannot be pickled (it holds the signing key)")

    @property
    def max_ttl_s(self) -> float:
        return self._max_ttl

    def _mac(self, payload: bytes) -> str:
        return hmac.new(self._key, _TOKEN_DOMAIN + payload, hashlib.sha256).hexdigest()

    def issue(
        self,
        principal: Principal,
        *,
        scopes: Iterable[str],
        ttl_s: float | None = None,
        requester: Principal | None = None,
        on_behalf_of: str | None = None,
    ) -> ScopedCredential:
        """Mint a credential for *principal*.

        ``requester`` is who asked (``None``: the harness itself). An AGENT
        requester may only ask for itself, and no non-human principal is ever
        given a scope that touches the immutable core.
        """
        if not isinstance(principal, Principal):
            raise CredentialIssuanceRefused("principal must be a Principal")
        scope_set = frozenset([scopes] if isinstance(scopes, str) else scopes)
        if not scope_set or not all(isinstance(s, str) and _SCOPE.fullmatch(s) for s in scope_set):
            raise CredentialIssuanceRefused("scopes must be non-empty scope strings")
        if requester is not None:
            if not isinstance(requester, Principal):
                raise CredentialIssuanceRefused("requester must be a Principal")
            if (
                requester.kind is PrincipalKind.AGENT
                and requester.canonical_id != principal.canonical_id
            ):
                raise CredentialIssuanceRefused("an agent may not request credentials for others")
        non_human = principal.kind is not PrincipalKind.HUMAN or (
            requester is not None and requester.kind is not PrincipalKind.HUMAN
        )
        if non_human:
            core = sorted(s for s in scope_set if scope_touches_core(s, self._registry))
            if core:
                raise CredentialIssuanceRefused(f"scopes touch the immutable core: {core}")
        ttl = self._default_ttl if ttl_s is None else ttl_s
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl):
            raise CredentialIssuanceRefused("ttl_s must be a finite number")
        if ttl <= 0 or ttl > self._max_ttl:
            raise CredentialIssuanceRefused(f"ttl_s must be in (0, {self._max_ttl}]")
        obo: str | None = None
        if on_behalf_of is not None:
            if not isinstance(on_behalf_of, str) or not _PRINCIPAL_ID.fullmatch(on_behalf_of):
                raise CredentialIssuanceRefused("on_behalf_of must be a canonical principal id")
            obo = canonical_principal_id(on_behalf_of)
            if obo == principal.canonical_id:
                raise CredentialIssuanceRefused("a principal cannot act on behalf of itself")
            if requester is not None and requester.kind is PrincipalKind.AGENT:
                raise CredentialIssuanceRefused("an agent may not name its own requester")
        now = float(self._clock())
        pid = principal.canonical_id
        with self._lock:
            epoch = self._epochs.get(pid, 0)
        credential_id = uuid.uuid4().hex
        expires = now + float(ttl)
        payload = {
            "cid": credential_id,
            "pid": pid,
            "scopes": sorted(scope_set),
            "iat": now,
            "exp": expires,
            "epoch": epoch,
            "obo": obo,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        token = _b64encode(raw) + "." + self._mac(raw)
        return ScopedCredential(
            token=token,
            principal_id=pid,
            scopes=scope_set,
            issued_at=now,
            expires_at=expires,
            credential_id=credential_id,
            on_behalf_of=obo,
        )

    def verify(
        self,
        token: object,
        *,
        required_scope: str,
        principal: Principal | None = None,
        now: float | None = None,
    ) -> ScopedCredential:
        """Return the credential or raise :class:`CredentialInvalid`."""
        if not isinstance(token, str) or token.count(".") != 1:
            raise CredentialInvalid("malformed token")
        body, mac = token.split(".")
        if "+" in body or "/" in body:
            raise CredentialInvalid("malformed token")
        try:
            raw = _b64decode(body)
        except (binascii.Error, ValueError) as exc:
            raise CredentialInvalid("malformed token") from exc
        if not hmac.compare_digest(self._mac(raw), mac):
            raise CredentialInvalid("bad token signature")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:  # pragma: no cover - MAC checked first
            raise CredentialInvalid("malformed token payload") from exc
        if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
            raise CredentialInvalid("malformed token payload")  # pragma: no cover
        current = float(self._clock()) if now is None else float(now)
        if current >= float(payload["exp"]):
            raise CredentialInvalid("credential expired")
        pid = str(payload["pid"])
        with self._lock:
            if payload["cid"] in self._revoked:
                raise CredentialInvalid("credential revoked")
            if payload["epoch"] != self._epochs.get(pid, 0):
                raise CredentialInvalid("credential revoked (principal epoch)")
        if principal is not None and canonical_principal_id(principal.id) != pid:
            raise CredentialInvalid("credential belongs to another principal")
        scopes = frozenset(payload["scopes"])
        if required_scope not in scopes:
            raise CredentialInvalid(f"credential lacks scope {required_scope!r}")
        return ScopedCredential(
            token=token,
            principal_id=pid,
            scopes=scopes,
            issued_at=float(payload["iat"]),
            expires_at=float(payload["exp"]),
            credential_id=str(payload["cid"]),
            on_behalf_of=None if payload["obo"] is None else str(payload["obo"]),
        )

    # TODO(control-plane-gap): revocations and epochs live in memory; a
    # restarted issuer that reuses its key forgets them (L6). Short TTLs bound
    # the exposure; durable revocation is a later phase.

    def revoke(self, credential_id: str) -> None:
        with self._lock:
            self._revoked.add(credential_id)

    def revoke_principal(self, principal_id: str) -> None:
        """Invalidate every credential issued so far to *principal_id*."""
        pid = canonical_principal_id(principal_id)
        with self._lock:
            self._epochs[pid] = self._epochs.get(pid, 0) + 1
