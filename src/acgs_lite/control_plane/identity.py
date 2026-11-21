"""Attested identities: who a principal *is*, decided by a core file.

Phase 6a. A :class:`~.principal.Principal` is a host assertion; on its own,
``Principal("bot-1", HUMAN)`` passes every human-only check. This module
gives the harness an authority that the agent cannot mint:

* :class:`StaticIdentityDirectory` (an :class:`IdentityProvider`) maps each
  canonical id to its kind, system_id, roles and admin flag. It is loaded
  from a YAML file whose path the immutable-core registry classifies as
  ``CoreCategory.IAM`` (default ``iam/identities.yaml``), so an agent can
  never edit it. Exactly one entry is the admin, and it is HUMAN. Every
  HUMAN entry pins an Ed25519 public key.
* :class:`HumanAuthenticator` proves that a human holds that key. It issues a
  short-lived nonce challenge; the human signs it; a valid response yields a
  one-shot :class:`VerifiedHumanSession` whose principal is built *from the
  directory* (kind, system_id and roles never come from the caller).
  Challenges and sessions are single use, so replay is refused.
* :class:`AdminAttestor` checks that an admin call carries a verified HUMAN
  credential (scope :data:`ADMIN_SCOPE`) for the pinned directory admin, or,
  with ``admin_only=False``, for the directory human named as the actor.

Ed25519 comes from the ``cryptography`` extra through
:mod:`acgs_lite.legitimacy.signing`, imported lazily; without it every
challenge response is refused (fail closed).
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypeAlias, runtime_checkable

import yaml

from acgs_lite.control_plane.immutable_core import CoreCategory, ImmutableCoreRegistry
from acgs_lite.control_plane.principal import (
    ADMIN_SCOPE,
    Principal,
    PrincipalKind,
    canonical_principal_id,
)

if TYPE_CHECKING:
    import acgs_lite.control_plane.credentials as credential_types

    CredentialIssuer: TypeAlias = "credential_types.CredentialIssuer"

__all__ = [
    "ADMIN_SCOPE",
    "DEFAULT_CHALLENGE_TTL_S",
    "DEFAULT_IDENTITY_PATH",
    "DEFAULT_SESSION_TTL_S",
    "KILL_SWITCH_ENGAGE_SCOPE",
    "MAX_PENDING_PER_PRINCIPAL",
    "AdminAttestationFailed",
    "AdminAttestor",
    "HumanAuthenticationFailed",
    "HumanAuthenticator",
    "HumanChallenge",
    "IdentityDirectoryError",
    "IdentityEntry",
    "IdentityProvider",
    "StaticIdentityDirectory",
    "VerifiedHumanSession",
    "checked_attestor",
]

# TODO(control-plane-gap): a static core-file directory is the default
# identity source; an OIDC-backed IdentityProvider is design inference and
# only the Protocol hook exists.
DEFAULT_IDENTITY_PATH = "iam/identities.yaml"
# TODO(control-plane-gap): 60 s to answer a challenge and 60 s to redeem the
# verified session are design inference (long enough for a signing step,
# short enough to bound a stolen response).
DEFAULT_CHALLENGE_TTL_S = 60.0
DEFAULT_SESSION_TTL_S = 60.0
# TODO(control-plane-gap): pending challenges and sessions live in memory
# (bounded by this cap); durable nonce state is a later phase.
MAX_PENDING = 1024
# TODO(control-plane-gap): 8 open challenges per human is design inference
# (enough for retries); beyond it the oldest is evicted, never refused.
MAX_PENDING_PER_PRINCIPAL = 8
# A SERVICE operator (CI, a watchdog) engages the kill switch with this scope.
KILL_SWITCH_ENGAGE_SCOPE = "halt:engage"
_CHALLENGE_DOMAIN = b"acgs-control-plane-human-challenge-v1\x00"
_PUBLIC_KEY = re.compile(r"[0-9a-f]{64}")
_SIGNATURE = re.compile(r"[0-9a-f]{128}")
_ENTRY_KEYS = frozenset({"id", "kind", "system_id", "roles", "admin", "public_key"})


class IdentityDirectoryError(ValueError):
    """The identity directory is malformed or inconsistent."""


class HumanAuthenticationFailed(PermissionError):
    """A human challenge could not be issued or its response was refused."""


class AdminAttestationFailed(PermissionError):
    """An admin call lacks a verified HUMAN credential for the admin."""


@dataclass(frozen=True)
class IdentityEntry:
    """One directory entry; :meth:`principal` is the attested Principal."""

    id: str
    kind: PrincipalKind
    system_id: str | None = None
    roles: frozenset[str] = field(default_factory=frozenset)
    admin: bool = False
    public_key_hex: str | None = None

    def principal(self) -> Principal:
        return Principal(self.id, self.kind, system_id=self.system_id, roles=self.roles)

    @property
    def canonical_id(self) -> str:
        return canonical_principal_id(self.id)


@runtime_checkable
class IdentityProvider(Protocol):
    """Source of attested identities (static file today, OIDC later)."""

    def lookup(self, principal_id: str) -> IdentityEntry | None:
        """The entry for *principal_id* (compared casefolded), else ``None``."""
        ...

    @property
    def admin(self) -> IdentityEntry:
        """The single HUMAN admin entry."""
        ...


def _entry(raw: object, index: int) -> IdentityEntry:
    if not isinstance(raw, Mapping):
        raise IdentityDirectoryError(f"identity #{index} must be a mapping")
    unknown = set(raw) - _ENTRY_KEYS
    if unknown:
        raise IdentityDirectoryError(f"identity #{index} has unknown keys {sorted(unknown)}")
    try:
        kind = PrincipalKind(str(raw.get("kind")))
    except ValueError as exc:
        raise IdentityDirectoryError(f"identity #{index} has an invalid kind") from exc
    roles = raw.get("roles", [])
    if not isinstance(roles, list) or not all(isinstance(r, str) and r for r in roles):
        raise IdentityDirectoryError(f"identity #{index} roles must be a list of strings")
    admin = raw.get("admin", False)
    if not isinstance(admin, bool):
        raise IdentityDirectoryError(f"identity #{index} admin must be a boolean")
    key = raw.get("public_key")
    if kind is PrincipalKind.HUMAN:
        if not isinstance(key, str) or not _PUBLIC_KEY.fullmatch(key):
            raise IdentityDirectoryError(
                f"human identity #{index} needs public_key (64 lowercase hex chars)"
            )
    elif key is not None:
        raise IdentityDirectoryError(f"identity #{index}: public_key is for human entries only")
    principal_id, system_id = raw.get("id"), raw.get("system_id")
    if not isinstance(principal_id, str) or not isinstance(system_id, (str, type(None))):
        raise IdentityDirectoryError(f"identity #{index}: id and system_id must be strings")
    try:
        principal = Principal(principal_id, kind, system_id, frozenset(roles))
    except ValueError as exc:
        raise IdentityDirectoryError(f"identity #{index}: {exc}") from exc
    return IdentityEntry(principal.id, kind, principal.system_id, principal.roles, admin, key)


class StaticIdentityDirectory:
    """An :class:`IdentityProvider` backed by a fixed list of entries."""

    def __init__(self, entries: Iterable[IdentityEntry]) -> None:
        by_id: dict[str, IdentityEntry] = {}
        for entry in entries:
            if not isinstance(entry, IdentityEntry):
                raise IdentityDirectoryError("entries must be IdentityEntry objects")
            if entry.canonical_id in by_id:
                raise IdentityDirectoryError(f"duplicate identity {entry.id!r}")
            by_id[entry.canonical_id] = entry
        admins = [entry for entry in by_id.values() if entry.admin]
        if len(admins) != 1:
            raise IdentityDirectoryError(
                f"the directory needs exactly one admin entry, found {len(admins)}"
            )
        if admins[0].kind is not PrincipalKind.HUMAN:
            raise IdentityDirectoryError("the admin entry must be a human")
        self._entries = by_id
        self._admin = admins[0]

    @classmethod
    def from_mapping(cls, data: object) -> StaticIdentityDirectory:
        """Parse ``{"version": 1, "identities": [...]}``."""
        if not isinstance(data, Mapping) or set(data) != {"version", "identities"}:
            raise IdentityDirectoryError("directory must be {version: 1, identities: [...]}")
        if data["version"] != 1:
            raise IdentityDirectoryError("unsupported directory version")
        items = data["identities"]
        if not isinstance(items, list):
            raise IdentityDirectoryError("identities must be a list")
        return cls(_entry(raw, index) for index, raw in enumerate(items))

    @classmethod
    def load(cls, relative_path: str, registry: ImmutableCoreRegistry) -> StaticIdentityDirectory:
        """Load the YAML file at *relative_path*, which must be IAM core."""
        if registry.repo_root is None:
            raise IdentityDirectoryError("the registry needs a repo_root")
        if registry.classify(relative_path) is not CoreCategory.IAM:
            raise IdentityDirectoryError(
                f"identity directory {relative_path!r} must be immutable-core iam"
            )
        try:
            text = (Path(registry.repo_root) / relative_path).read_text(encoding="utf-8")
            data = yaml.safe_load(text)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise IdentityDirectoryError(f"identity directory unreadable: {exc}") from exc
        return cls.from_mapping(data)

    def lookup(self, principal_id: str) -> IdentityEntry | None:
        if not isinstance(principal_id, str):
            return None
        return self._entries.get(canonical_principal_id(principal_id))

    @property
    def admin(self) -> IdentityEntry:
        return self._admin


@dataclass(frozen=True)
class HumanChallenge:
    """A nonce the human signs (Ed25519 over :attr:`message`)."""

    challenge_id: str
    principal_id: str
    nonce: str
    expires_at: float

    @property
    def message(self) -> bytes:
        body = {
            "cid": self.challenge_id,
            "exp": self.expires_at,
            "nonce": self.nonce,
            "pid": self.principal_id,
        }
        return _CHALLENGE_DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )


@dataclass(frozen=True)
class VerifiedHumanSession:
    """Proof of key possession; redeemable once by the issuing authenticator."""

    session_id: str
    principal: Principal
    """Built from the directory entry, never from the caller."""
    authenticated_at: float
    expires_at: float


class HumanAuthenticator:
    """One-shot, nonce-bound, expiring Ed25519 challenge-response."""

    def __init__(
        self,
        identity: IdentityProvider,
        *,
        challenge_ttl_s: float = DEFAULT_CHALLENGE_TTL_S,
        session_ttl_s: float = DEFAULT_SESSION_TTL_S,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(identity, IdentityProvider):
            raise TypeError("identity must be an IdentityProvider")
        for label, value in (
            ("challenge_ttl_s", challenge_ttl_s),
            ("session_ttl_s", session_ttl_s),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
                raise ValueError(f"{label} must be a positive number")
        self._identity = identity
        self._challenge_ttl = float(challenge_ttl_s)
        self._session_ttl = float(session_ttl_s)
        self._clock = clock
        self._lock = threading.Lock()
        self._pending: dict[str, HumanChallenge] = {}
        self._sessions: dict[str, VerifiedHumanSession] = {}

    @property
    def identity(self) -> IdentityProvider:
        return self._identity

    def _human(self, principal_id: object) -> IdentityEntry:
        entry = self._identity.lookup(principal_id) if isinstance(principal_id, str) else None
        if entry is None or entry.kind is not PrincipalKind.HUMAN or not entry.public_key_hex:
            raise HumanAuthenticationFailed("not a human in the identity directory")
        return entry

    def issue_challenge(self, principal_id: str) -> HumanChallenge:
        entry = self._human(principal_id)
        now = float(self._clock())
        challenge = HumanChallenge(
            uuid.uuid4().hex, entry.canonical_id, secrets.token_hex(32), now + self._challenge_ttl
        )
        with self._lock:
            for cid in [c for c, p in self._pending.items() if p.expires_at <= now]:
                del self._pending[cid]
            # Evict rather than refuse, so spamming challenges for a human can
            # never lock that human (or anyone else) out: the oldest pending
            # challenge of this principal goes first, then the oldest overall.
            mine = [c for c, p in self._pending.items() if p.principal_id == entry.canonical_id]
            if len(mine) >= MAX_PENDING_PER_PRINCIPAL:
                del self._pending[mine[0]]
            while len(self._pending) >= MAX_PENDING:
                del self._pending[next(iter(self._pending))]
            self._pending[challenge.challenge_id] = challenge
        return challenge

    def verify_response(
        self, challenge: HumanChallenge, signature_hex: str
    ) -> VerifiedHumanSession:
        """Consume *challenge* and check the signature; one attempt only."""
        from acgs_lite.legitimacy.signing import (
            SIGNATURE_ALGORITHM,
            ReceiptSigningUnavailable,
            verify_signature,
        )

        if not isinstance(challenge, HumanChallenge):
            raise HumanAuthenticationFailed("challenge must be a HumanChallenge")
        with self._lock:
            stored = self._pending.pop(challenge.challenge_id, None)
        if stored is None:
            raise HumanAuthenticationFailed("unknown or already used challenge")
        if stored != challenge:
            raise HumanAuthenticationFailed("challenge does not match the issued one")
        now = float(self._clock())
        if now >= stored.expires_at:
            raise HumanAuthenticationFailed("challenge expired")
        entry = self._human(stored.principal_id)
        if not isinstance(signature_hex, str) or not _SIGNATURE.fullmatch(signature_hex):
            raise HumanAuthenticationFailed("malformed signature")
        try:
            valid = verify_signature(
                SIGNATURE_ALGORITHM, str(entry.public_key_hex), stored.message, signature_hex
            )
        except ReceiptSigningUnavailable as exc:  # pragma: no cover - needs the extra absent
            raise HumanAuthenticationFailed("Ed25519 unavailable") from exc
        if not valid:
            raise HumanAuthenticationFailed("bad challenge signature")
        session = VerifiedHumanSession(
            uuid.uuid4().hex, entry.principal(), now, now + self._session_ttl
        )
        with self._lock:
            for sid in [s for s, v in self._sessions.items() if v.expires_at <= now]:
                del self._sessions[sid]
            if len(self._sessions) >= MAX_PENDING:
                raise HumanAuthenticationFailed("too many open sessions")
            self._sessions[session.session_id] = session
        return session

    def redeem(self, session: VerifiedHumanSession) -> Principal:
        """Consume *session* (issued here, unexpired) and return its principal."""
        if not isinstance(session, VerifiedHumanSession):
            raise HumanAuthenticationFailed("session must be a VerifiedHumanSession")
        with self._lock:
            stored = self._sessions.pop(session.session_id, None)
        if stored is None or stored != session:
            raise HumanAuthenticationFailed("unknown or already redeemed session")
        if float(self._clock()) >= stored.expires_at:
            raise HumanAuthenticationFailed("session expired")
        return stored.principal


class AdminAttestor:
    """Check that an admin (or human-operator) call carries a verified,
    single-use credential for the actor: consumed on success, so one
    credential authorises exactly one operation."""

    def __init__(self, issuer: CredentialIssuer) -> None:
        from acgs_lite.control_plane.credentials import CredentialIssuer

        if type(issuer) is not CredentialIssuer or issuer.identity is None:
            raise TypeError("AdminAttestor needs a CredentialIssuer with an identity provider")
        self._issuer = issuer
        self._identity: IdentityProvider = issuer.identity

    @property
    def admin(self) -> Principal:
        return self._identity.admin.principal()

    @property
    def identity(self) -> IdentityProvider:
        return self._identity

    def require(
        self,
        actor: object,
        credential: object,
        *,
        admin_only: bool = True,
        error: type[Exception] = AdminAttestationFailed,
        scope: str = ADMIN_SCOPE,
        kinds: frozenset[PrincipalKind] = frozenset({PrincipalKind.HUMAN}),
    ) -> Principal:
        """Return the directory principal behind *credential*, else raise *error*.

        The credential must be valid, carry *scope*, have a kind in *kinds*
        (HUMAN by default) and belong to *actor* (id, kind and system_id).
        With *admin_only* the actor must also be the pinned directory admin.
        On success the credential is revoked (single use, atomic).
        """
        from acgs_lite.control_plane.credentials import CredentialInvalid

        if not isinstance(actor, Principal):
            raise error("admin attestation: actor must be a Principal")
        if credential is None:
            raise error("admin attestation: a verified human admin_credential is required")
        try:
            session = self._issuer.verify(credential, required_scope=scope, principal=actor)
            entry = self._identity.lookup(session.principal_id)
            if session.kind not in kinds or entry is None:
                raise error("admin attestation: not an allowed directory principal")
            if admin_only and entry.canonical_id != self._identity.admin.canonical_id:
                raise error("admin attestation: not the directory admin")
            self._issuer.consume(credential, required_scope=scope, principal=actor)
        except CredentialInvalid as exc:
            raise error(f"admin attestation: {exc}") from exc
        return entry.principal()


def checked_attestor(attestor: object) -> AdminAttestor | None:
    """Type-check an optional ``admin_attestor=`` argument."""
    if attestor is not None and type(attestor) is not AdminAttestor:
        raise TypeError("admin_attestor must be an AdminAttestor")
    return attestor
