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
from typing import TYPE_CHECKING, Any

from acgs_lite.control_plane.immutable_core import DEFAULT_IMMUTABLE_CORE, ImmutableCoreRegistry
from acgs_lite.control_plane.invariants import ACTION_NAMESPACE_CATEGORIES
from acgs_lite.control_plane.principal import Principal, PrincipalKind, canonical_principal_id

if TYPE_CHECKING:
    from acgs_lite.control_plane.identity import (
        HumanAuthenticator,
        IdentityProvider,
        VerifiedHumanSession,
    )

__all__ = [
    "ADMIN_SCOPE",
    "DEFAULT_CREDENTIAL_TTL_S",
    "MAX_ADMIN_CREDENTIAL_TTL_S",
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
# Phase 6a: the scope an admin (or attested human operator) call carries.
ADMIN_SCOPE = "admin:control-plane"
# TODO(control-plane-gap): 60 s for any "admin:*" credential is design
# inference (one interactive admin step); configurable via admin_max_ttl_s.
MAX_ADMIN_CREDENTIAL_TTL_S = 60.0
# v2 (Phase 6a): the principal kind ("knd") is signed and required.
_TOKEN_DOMAIN = b"acgs-control-plane-credential-v2\x00"
_SCOPE = re.compile(r"[A-Za-z0-9._:/*@-]{1,256}")
_PAYLOAD_KEYS = frozenset({"cid", "pid", "knd", "scopes", "iat", "exp", "epoch", "obo"})
# Phase 4: "trg" (trigger) and "sys" (the principal's system_id) are present
# only when set; an absent "sys" means system_id None.
_OPTIONAL_KEYS = frozenset({"trg", "sys"})
_TRIGGER_ID = re.compile(r"[A-Za-z0-9._:/@+-]{1,256}")
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
    kind: PrincipalKind
    """The principal kind at issuance (signed; must match on use)."""
    on_behalf_of: str | None = None
    """Canonical id of the original requester this session acts for (signed)."""
    trigger_id: str | None = None
    """The autonomous trigger this session runs under (signed, Phase 4)."""
    system_id: str | None = None
    """The principal's system_id at issuance (signed; must match on use)."""


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


# TODO(control-plane-gap): 16 KiB bounds a token far above any real payload
# (scopes are short names); design inference.
MAX_TOKEN_CHARS = 16 * 1024
_MAC_HEX = re.compile(r"[0-9a-f]{64}")


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
        identity: IdentityProvider | None = None,
        admin_max_ttl_s: float = MAX_ADMIN_CREDENTIAL_TTL_S,
    ) -> None:
        """With *identity* every principal must match its directory entry and
        HUMAN credentials are minted only by :meth:`issue_for_human`."""
        key = secrets.token_bytes(32) if hmac_key is None else hmac_key
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("hmac_key must be at least 32 bytes")
        for label, value in (
            ("default_ttl_s", default_ttl_s),
            ("max_ttl_s", max_ttl_s),
            ("admin_max_ttl_s", admin_max_ttl_s),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{label} must be a number")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{label} must be positive and finite")
        if default_ttl_s > max_ttl_s:
            raise ValueError("default_ttl_s must not exceed max_ttl_s")
        self._key = key
        self._default_ttl = float(default_ttl_s)
        self._max_ttl = float(max_ttl_s)
        self._admin_max_ttl = min(float(admin_max_ttl_s), self._max_ttl)
        self._registry = registry
        self._clock = clock
        self._lock = threading.Lock()
        self._revoked: set[str] = set()
        self._used: dict[str, float] = {}
        """Consumed single-use credential id -> its expiry (pruned once expired)."""
        self._epochs: dict[str, int] = {}
        self._identity = identity
        self._authenticator: HumanAuthenticator | None = None
        if identity is not None:
            from acgs_lite.control_plane.identity import HumanAuthenticator, IdentityProvider

            if not isinstance(identity, IdentityProvider):
                raise TypeError("identity must be an IdentityProvider")
            self._authenticator = HumanAuthenticator(identity, clock=clock)

    @property
    def identity(self) -> IdentityProvider | None:
        return self._identity

    @property
    def human_authenticator(self) -> HumanAuthenticator | None:
        """The challenge-response authenticator whose sessions this issuer redeems."""
        return self._authenticator

    def _check_directory(self, principal: Principal, label: str) -> None:
        identity = self._identity
        if identity is None:
            return
        entry = identity.lookup(principal.id)
        if entry is None:
            raise CredentialIssuanceRefused(
                f"{label} {principal.id!r} is not in the identity directory"
            )
        if entry.kind is not principal.kind:
            raise CredentialIssuanceRefused(
                f"{label} kind {principal.kind.value!r} differs from the directory "
                f"({entry.kind.value!r})"
            )
        if entry.system_id != principal.system_id:
            raise CredentialIssuanceRefused(f"{label} system_id differs from the directory")

    def _attest_requester(self, requester: Principal, credential: object) -> None:
        """Phase 6a: a requester choosing obo/trigger_id must be the harness
        (``requester=None``) or a HUMAN presenting its own verified, single-use
        ``requester_credential`` (scope :data:`ADMIN_SCOPE`)."""
        if requester.kind is not PrincipalKind.HUMAN:
            raise CredentialIssuanceRefused(
                "only the harness or an attested human requester may choose "
                "on_behalf_of or trigger_id"
            )
        if credential is None:
            raise CredentialIssuanceRefused(
                "a human requester choosing on_behalf_of or trigger_id needs a "
                "verified requester_credential"
            )
        try:
            self.consume(credential, required_scope=ADMIN_SCOPE, principal=requester)
        except CredentialInvalid as exc:
            raise CredentialIssuanceRefused(f"requester_credential refused: {exc}") from exc

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
        trigger_id: str | None = None,
        requester_credential: str | None = None,
    ) -> ScopedCredential:
        """Mint a credential for *principal*.

        With an identity provider, a *requester* that chooses ``on_behalf_of``
        or ``trigger_id`` must be a HUMAN presenting ``requester_credential``
        (its own verified, single-use ``admin:control-plane`` credential).

        ``trigger_id`` binds the session to one autonomous trigger; the
        dispatcher then uses it instead of a caller-supplied value. An AGENT
        requester may not choose it.

        ``requester`` is who asked (``None``: the harness itself). An AGENT
        requester may only ask for itself, and no non-human principal is ever
        given a scope that touches the immutable core.
        """
        if not isinstance(principal, Principal):
            raise CredentialIssuanceRefused("principal must be a Principal")
        if self._identity is not None:
            if principal.kind is PrincipalKind.HUMAN:
                raise CredentialIssuanceRefused(
                    "HUMAN credentials are issued only through issue_for_human()"
                )
            self._check_directory(principal, "principal")
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
            self._check_directory(requester, "requester")
        non_human = principal.kind is not PrincipalKind.HUMAN or (
            requester is not None and requester.kind is not PrincipalKind.HUMAN
        )
        if non_human:
            core = sorted(s for s in scope_set if scope_touches_core(s, self._registry))
            if core:
                raise CredentialIssuanceRefused(f"scopes touch the immutable core: {core}")
        obo: str | None = None
        if on_behalf_of is not None:
            if not isinstance(on_behalf_of, str) or not _PRINCIPAL_ID.fullmatch(on_behalf_of):
                raise CredentialIssuanceRefused("on_behalf_of must be a canonical principal id")
            obo = canonical_principal_id(on_behalf_of)
            if obo == principal.canonical_id:
                raise CredentialIssuanceRefused("a principal cannot act on behalf of itself")
            if requester is not None and requester.kind is PrincipalKind.AGENT:
                raise CredentialIssuanceRefused("an agent may not name its own requester")
            self._check_obo(obo, requester)
        if (
            obo is None
            and requester is not None
            and requester.kind is PrincipalKind.HUMAN
            and requester_credential is not None
            and requester.canonical_id != principal.canonical_id
        ):
            # A human requester who authenticates is always the bound original
            # requester (attested below); leaving it unbound would let a caller
            # name another. Unproven requesters stay unbound, and the
            # dispatcher refuses unbound credentials for agent T2+ calls.
            obo = requester.canonical_id
            self._check_obo(obo, requester)
        if trigger_id is not None:
            if not isinstance(trigger_id, str) or not _TRIGGER_ID.fullmatch(trigger_id):
                raise CredentialIssuanceRefused("trigger_id must match [A-Za-z0-9._:/@+-]{1,256}")
            if requester is not None and requester.kind is PrincipalKind.AGENT:
                raise CredentialIssuanceRefused("an agent may not choose its own trigger")
        # Every input is validated before the requester credential is spent.
        ttl = self._validated_ttl(scope_set, ttl_s)
        if self._token_size_bound(principal, scope_set, obo, trigger_id) > MAX_TOKEN_CHARS:
            raise CredentialIssuanceRefused(
                f"credential would exceed {MAX_TOKEN_CHARS} characters (too many/long scopes)"
            )
        if (
            self._identity is not None
            and requester is not None
            and (obo is not None or trigger_id is not None)
        ):
            self._attest_requester(requester, requester_credential)
        return self._mint(principal, scope_set, ttl, obo, trigger_id)

    def _check_obo(self, obo: str, requester: Principal | None) -> None:
        """Phase 6a: with identity, ``on_behalf_of`` is bound. An (attested)
        HUMAN requester may only name itself; the harness may name any
        directory HUMAN, never an unknown id."""
        identity = self._identity
        if identity is None:
            return
        if requester is not None and requester.kind is PrincipalKind.HUMAN:
            if obo != requester.canonical_id:
                raise CredentialIssuanceRefused(
                    "a human requester may only name itself as on_behalf_of"
                )
            return
        entry = identity.lookup(obo)
        if entry is None or entry.kind is not PrincipalKind.HUMAN:
            raise CredentialIssuanceRefused(
                "on_behalf_of must name a human in the identity directory"
            )

    def issue_for_human(
        self,
        session: VerifiedHumanSession,
        *,
        scopes: Iterable[str],
        ttl_s: float | None = None,
    ) -> ScopedCredential:
        """Mint a HUMAN credential from a :class:`~.identity.VerifiedHumanSession`.

        The session is redeemed (one-shot) against this issuer's own
        :attr:`human_authenticator`; the principal comes from the directory.
        """
        from acgs_lite.control_plane.identity import HumanAuthenticationFailed

        authenticator = self._authenticator
        if authenticator is None:
            raise CredentialIssuanceRefused("issue_for_human needs an identity provider")
        try:
            principal = authenticator.redeem(session)
        except HumanAuthenticationFailed as exc:
            raise CredentialIssuanceRefused(f"human session refused: {exc}") from exc
        scope_set = frozenset([scopes] if isinstance(scopes, str) else scopes)
        if not scope_set or not all(isinstance(s, str) and _SCOPE.fullmatch(s) for s in scope_set):
            raise CredentialIssuanceRefused("scopes must be non-empty scope strings")
        return self._mint(principal, scope_set, self._validated_ttl(scope_set, ttl_s), None, None)

    def _validated_ttl(self, scope_set: frozenset[str], ttl_s: float | None) -> float:
        admin = any(scope.partition(":")[0].lower() == "admin" for scope in scope_set)
        cap = self._admin_max_ttl if admin else self._max_ttl
        ttl = (
            (min(self._default_ttl, cap) if admin else self._default_ttl)
            if ttl_s is None
            else ttl_s
        )
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl):
            raise CredentialIssuanceRefused("ttl_s must be a finite number")
        if ttl <= 0 or ttl > cap:
            label = "admin-scope " if admin else ""
            raise CredentialIssuanceRefused(f"{label}ttl_s must be in (0, {cap}]")
        return float(ttl)

    def _token_size_bound(
        self,
        principal: Principal,
        scope_set: frozenset[str],
        obo: str | None,
        trigger_id: str | None,
    ) -> int:
        """Upper bound of the token _mint would produce (same claims; the
        variable-width numbers at their widest), so issuance never returns a
        token authenticate() rejects."""
        payload: dict[str, Any] = {
            "cid": "0" * 32,
            "pid": principal.canonical_id,
            "knd": principal.kind.value,
            "scopes": sorted(scope_set),
            "iat": -1.0e300,
            "exp": -1.0e300,
            "epoch": 10**18,
            "obo": obo,
        }
        if trigger_id is not None:
            payload["trg"] = trigger_id
        if principal.system_id is not None:
            payload["sys"] = principal.system_id
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return len(_b64encode(raw)) + 1 + len(self._mac(raw))

    def _mint(
        self,
        principal: Principal,
        scope_set: frozenset[str],
        ttl: float,
        obo: str | None,
        trigger_id: str | None,
    ) -> ScopedCredential:
        now = float(self._clock())
        pid = principal.canonical_id
        with self._lock:
            epoch = self._epochs.get(pid, 0)
        credential_id = uuid.uuid4().hex
        expires = now + float(ttl)
        payload = {
            "cid": credential_id,
            "pid": pid,
            "knd": principal.kind.value,
            "scopes": sorted(scope_set),
            "iat": now,
            "exp": expires,
            "epoch": epoch,
            "obo": obo,
        }
        if trigger_id is not None:
            payload["trg"] = trigger_id
        if principal.system_id is not None:
            payload["sys"] = principal.system_id
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        token = _b64encode(raw) + "." + self._mac(raw)
        return ScopedCredential(
            token=token,
            principal_id=pid,
            scopes=scope_set,
            issued_at=now,
            expires_at=expires,
            credential_id=credential_id,
            kind=principal.kind,
            on_behalf_of=obo,
            trigger_id=trigger_id,
            system_id=principal.system_id,
        )

    def verify(
        self,
        token: object,
        *,
        required_scope: str | None,
        principal: Principal | None = None,
        now: float | None = None,
    ) -> ScopedCredential:
        """Return the credential or raise :class:`CredentialInvalid`.

        ``required_scope=None`` checks identity only (signature, expiry,
        revocation and the principal's id, kind and system_id)."""
        credential = self.authenticate(token, now=now)
        if principal is not None and principal.canonical_id != credential.principal_id:
            raise CredentialInvalid("credential belongs to another principal")
        if principal is not None and principal.system_id != credential.system_id:
            raise CredentialInvalid("credential was issued for another system_id")
        if principal is not None and principal.kind is not credential.kind:
            raise CredentialInvalid(
                f"credential was issued for another principal kind ({credential.kind.value}, "
                f"not {principal.kind.value})"
            )
        if required_scope is not None and required_scope not in credential.scopes:
            raise CredentialInvalid(f"credential lacks scope {required_scope!r}")
        return credential

    def authenticate(self, token: object, *, now: float | None = None) -> ScopedCredential:
        """Verify signature, expiry and revocation, but no scope or principal."""
        # Shape first, so no malformed input (non-ASCII, huge, odd MAC) ever
        # reaches base64 or compare_digest (which raises TypeError on
        # non-ASCII str): every malformed token is CredentialInvalid.
        if (
            not isinstance(token, str)
            or len(token) > MAX_TOKEN_CHARS
            or not token.isascii()
            or token.count(".") != 1
        ):
            raise CredentialInvalid("malformed token")
        body, mac = token.split(".")
        if not body or "+" in body or "/" in body or not _MAC_HEX.fullmatch(mac):
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
        if (
            not isinstance(payload, dict)
            or not set(payload) >= _PAYLOAD_KEYS
            or not set(payload) - _PAYLOAD_KEYS <= _OPTIONAL_KEYS
        ):
            raise CredentialInvalid("malformed token payload")  # pragma: no cover
        current = float(self._clock()) if now is None else float(now)
        if current >= float(payload["exp"]):
            raise CredentialInvalid("credential expired")
        pid = str(payload["pid"])
        with self._lock:
            if payload["cid"] in self._used:
                raise CredentialInvalid("credential already used")
            if payload["cid"] in self._revoked:
                raise CredentialInvalid("credential revoked")
            if payload["epoch"] != self._epochs.get(pid, 0):
                raise CredentialInvalid("credential revoked (principal epoch)")
        try:
            kind = PrincipalKind(payload["knd"])
        except ValueError as exc:  # pragma: no cover - MAC checked first
            raise CredentialInvalid("malformed token payload") from exc
        signed_system = payload.get("sys")
        scopes = frozenset(payload["scopes"])
        return ScopedCredential(
            token=token,
            principal_id=pid,
            scopes=scopes,
            issued_at=float(payload["iat"]),
            expires_at=float(payload["exp"]),
            credential_id=str(payload["cid"]),
            kind=kind,
            on_behalf_of=None if payload["obo"] is None else str(payload["obo"]),
            trigger_id=None if payload.get("trg") is None else str(payload["trg"]),
            system_id=None if signed_system is None else str(signed_system),
        )

    def consume(
        self,
        token: object,
        *,
        required_scope: str | None,
        principal: Principal | None = None,
    ) -> ScopedCredential:
        """:meth:`verify`, then revoke the credential: single use, atomic.

        Of two concurrent consumers of one token, exactly one succeeds.
        """
        credential = self.verify(token, required_scope=required_scope, principal=principal)
        now = float(self._clock())
        with self._lock:
            if credential.credential_id in self._used:
                raise CredentialInvalid("credential already used")
            # Expired entries can never verify again: drop them (bounded set).
            for cid in [c for c, exp in self._used.items() if exp <= now]:
                del self._used[cid]
            self._used[credential.credential_id] = credential.expires_at
        return credential

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
