"""Signed, single-use approvals and separation-of-duties quorums.

Phase 1/2 trusted ``approvers=`` Principals asserted by the host. Phase 3
replaces them with :class:`SignedApproval` objects:

* signed (Ed25519, domain ``acgs-control-plane-approval-v1``) by a key that a
  *human admin* registered for a *human* approver in the harness-side
  :class:`ApprovalAuthority`; agents and services can never be approvers;
* bound to one :func:`~acgs_lite.control_plane.action_hash.action_hash`, so an
  approval cannot be replayed against different arguments;
* short-lived and single-use (the nonce is consumed when the approved call
  executes);
* counted by :class:`ApprovalGate` only when the approver is not the
  requester, not the authoring principal (``attributes["authored_by"]``),
  not the *original* requester on whose behalf the principal acts
  (``attributes["requested_by"]``, e.g. the human who asked an agent to make
  the change -- they may not approve their own request by proxy), and not a
  sibling of an agent requester (same ``system_id`` or a registered member of
  that system). Both attributes are part of the action hash.
* one Ed25519 public key belongs to exactly one approver: registering the
  same key for a second approver is refused, so one key holder cannot fill a
  two-person quorum alone.

Evidence: in the Replit incident an agent deleted a live production database
during a natural-language code freeze; nothing outside the agent could stop
it. Hence an independent two-person gate that the agent cannot satisfy for
itself (it cannot sign, register, or count as an approver).

The ``cryptography`` extra provides Ed25519; it is imported lazily through
:mod:`acgs_lite.legitimacy.signing`. Without it every approval is rejected
(fail closed).
"""

from __future__ import annotations

import collections
import hashlib
import logging
import math
import re
import secrets
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from acgs_lite.control_plane.action_hash import action_hash, approval_subject, canonical_json
from acgs_lite.control_plane.context import DecisionRequest
from acgs_lite.control_plane.principal import Principal, PrincipalKind, canonical_principal_id
from acgs_lite.control_plane.tiers import ActionTier
from acgs_lite.legitimacy.signing import SIGNATURE_ALGORITHM, ReceiptSigner, verify_signature

if TYPE_CHECKING:
    from acgs_lite.control_plane.telemetry import OversightEvent, TelemetryRecorder

__all__ = [
    "APPROVAL_SIGNATURE_DOMAIN",
    "DEFAULT_APPROVAL_TTL_S",
    "DEFAULT_CLOCK_SKEW_S",
    "DEFAULT_QUORUM_POLICIES",
    "ApprovalAuthority",
    "ApprovalGate",
    "ApprovalRegistrationRejected",
    "QuorumPolicy",
    "QuorumResult",
    "SignedApproval",
]

logger = logging.getLogger(__name__)

APPROVAL_SIGNATURE_DOMAIN = b"acgs-control-plane-approval-v1\x00"
# Distinct action hashes remembered as "approval requested" (telemetry dedupe).
_MAX_REQUESTED_TRACKED = 4096
# TODO(control-plane-gap): approval TTL (15 min) and clock skew (30 s) are
# design inference; no primary evidence for either value.
DEFAULT_APPROVAL_TTL_S = 900.0
DEFAULT_CLOCK_SKEW_S = 30.0

_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_PUBLIC_KEY = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
# Tiers whose requests need a configured quorum (mirrors dispatcher.APPROVAL_GATE_MIN_TIER).
_GATED_MIN_TIER = ActionTier.T2


class ApprovalRegistrationRejected(ValueError):
    """Raised when an approver or system member registration is refused."""


@dataclass(frozen=True)
class QuorumPolicy:
    """How many distinct, independent human approvals a tier needs."""

    min_approvals: int
    required_roles: frozenset[str] = frozenset()
    ttl_s: float = DEFAULT_APPROVAL_TTL_S

    def __post_init__(self) -> None:
        if (
            isinstance(self.min_approvals, bool)
            or not isinstance(self.min_approvals, int)
            or self.min_approvals < 1
        ):
            raise ValueError("min_approvals must be an int >= 1")
        roles = frozenset(self.required_roles)
        if not all(isinstance(role, str) and role for role in roles):
            raise ValueError("required_roles must be non-empty strings")
        object.__setattr__(self, "required_roles", roles)
        if (
            isinstance(self.ttl_s, bool)
            or not isinstance(self.ttl_s, (int, float))
            or not math.isfinite(self.ttl_s)
            or self.ttl_s <= 0
        ):
            raise ValueError("ttl_s must be a positive finite number")


# TODO(control-plane-gap): quorum sizes (T2 -> 1, T3 -> 2) are design
# inference; the Replit incident motivates "more than the agent", the numbers
# are convention. Configure per deployment.
DEFAULT_QUORUM_POLICIES: Mapping[ActionTier, QuorumPolicy] = MappingProxyType(
    {ActionTier.T2: QuorumPolicy(1), ActionTier.T3: QuorumPolicy(2)}
)


@dataclass(frozen=True)
class SignedApproval:
    """One human's signed approval of one action hash."""

    approval_id: str
    approver_id: str
    approver_kind: str
    action_hash: str
    issued_at: float
    expires_at: float
    nonce: str
    key_id: str
    signature: str

    def signing_payload(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "approver_id": self.approver_id,
            "approver_kind": self.approver_kind,
            "action_hash": self.action_hash,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "key_id": self.key_id,
        }

    def signing_message(self) -> bytes:
        return APPROVAL_SIGNATURE_DOMAIN + canonical_json(self.signing_payload()).encode("utf-8")

    @classmethod
    def create(
        cls,
        signer: ReceiptSigner,
        *,
        approver: Principal,
        action_hash: str,
        ttl_s: float = DEFAULT_APPROVAL_TTL_S,
        now: float | None = None,
        approval_id: str | None = None,
        nonce: str | None = None,
    ) -> SignedApproval:
        """Approver-side helper: sign *action_hash* with the approver's key.

        Runs wherever the human's key lives (their device, an HSM), never in
        the agent process.
        """
        issued = time.time() if now is None else float(now)
        draft = cls(
            approval_id=approval_id or uuid.uuid4().hex,
            approver_id=approver.id,
            approver_kind=approver.kind.value,
            action_hash=action_hash,
            issued_at=issued,
            expires_at=issued + float(ttl_s),
            nonce=nonce or secrets.token_hex(16),
            key_id=signer.key_id,
            signature="",
        )
        signature = signer.sign(draft.signing_message())
        return cls(**{**draft.signing_payload(), "signature": signature})


@dataclass(frozen=True)
class QuorumResult:
    """The gate's verdict for one request.

    ``approvers`` are the *registered* Principals behind the counted
    approvals (aligned with ``counted_approvals``); nothing the caller
    asserted about an approver survives into them.
    """

    satisfied: bool
    action_hash: str
    required: int
    counted_approver_ids: tuple[str, ...] = ()
    approvers: tuple[Principal, ...] = ()
    counted_approvals: tuple[SignedApproval, ...] = ()
    rejected: tuple[tuple[str, str], ...] = ()
    missing_roles: frozenset[str] = field(default_factory=frozenset)
    # Earliest signed-approval prefix satisfying both count and role coverage.
    # Observability only: all counted approvals are still consumed.
    completion_approver_ids: tuple[str, ...] = ()
    telemetry_cycle_id: str | None = None
    telemetry_requested_at: float | None = None


@dataclass(frozen=True)
class _ApproverKey:
    approver: Principal
    public_key_hex: str


def _require_human(principal: object, label: str) -> Principal:
    if not isinstance(principal, Principal) or principal.kind is not PrincipalKind.HUMAN:
        raise ApprovalRegistrationRejected(f"{label} must be a HUMAN Principal")
    return principal


class ApprovalAuthority:
    """Harness-side registry of approver keys and system memberships.

    Only a HUMAN admin registers keys, only for a HUMAN approver other than
    the admin. The agent process must never hold a reference to this object.
    """

    # TODO(control-plane-gap): the admin Principal itself is host-asserted;
    # binding admin actions to an authenticated session (or a signed admin
    # key) is a later phase.

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._keys: dict[str, _ApproverKey] = {}
        self._key_owner: dict[str, str] = {}
        self._members: dict[str, set[str]] = {}

    def register_approver(
        self,
        admin: Principal,
        approver: Principal,
        public_key_hex: str,
        *,
        key_id: str | None = None,
    ) -> str:
        """Register *approver*'s Ed25519 public key; returns its key id."""
        _require_human(admin, "admin")
        _require_human(approver, "approver")
        if admin.canonical_id == approver.canonical_id:
            raise ApprovalRegistrationRejected("an admin cannot register their own approver key")
        if not isinstance(public_key_hex, str) or not _PUBLIC_KEY.fullmatch(public_key_hex):
            raise ApprovalRegistrationRejected("public_key_hex must be 64 lowercase hex chars")
        kid = key_id or hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]
        if not isinstance(kid, str) or not _TOKEN.fullmatch(kid):
            raise ApprovalRegistrationRejected("key_id must match [A-Za-z0-9._:-]{1,128}")
        with self._lock:
            if kid in self._keys:
                raise ApprovalRegistrationRejected(f"key id {kid!r} is already registered")
            owner = self._key_owner.get(public_key_hex)
            if owner is not None and owner != approver.canonical_id:
                raise ApprovalRegistrationRejected(
                    "this public key is already bound to a different approver"
                )
            if any(approver.canonical_id in ids for ids in self._members.values()):
                raise ApprovalRegistrationRejected(
                    "a registered system member (agent) cannot be an approver"
                )
            self._keys[kid] = _ApproverKey(approver, public_key_hex)
            self._key_owner[public_key_hex] = approver.canonical_id
        return kid

    def revoke_approver(self, admin: Principal, key_id: str) -> bool:
        _require_human(admin, "admin")
        with self._lock:
            entry = self._keys.pop(key_id, None)
            if entry is None:
                return False
            if not any(k.public_key_hex == entry.public_key_hex for k in self._keys.values()):
                self._key_owner.pop(entry.public_key_hex, None)
            return True

    def register_system_member(self, admin: Principal, member: Principal) -> None:
        """Record *member* (an agent or service) as part of its ``system_id``.

        Members of a system never count as approvers for any agent of that
        system (sibling exclusion), even under a different principal kind.
        """
        _require_human(admin, "admin")
        if not isinstance(member, Principal) or member.system_id is None:
            raise ApprovalRegistrationRejected("member must be a Principal with a system_id")
        if member.kind is PrincipalKind.HUMAN:
            raise ApprovalRegistrationRejected("system members are agents or services")
        with self._lock:
            if any(k.approver.canonical_id == member.canonical_id for k in self._keys.values()):
                raise ApprovalRegistrationRejected(
                    "a registered approver cannot be a system member"
                )
            self._members.setdefault(member.system_id, set()).add(member.canonical_id)

    def is_system_member(self, system_id: str | None, principal_id: str) -> bool:
        if system_id is None:
            return False
        with self._lock:
            return canonical_principal_id(principal_id) in self._members.get(system_id, set())

    def lookup(self, key_id: object) -> tuple[Principal, str] | None:
        if not isinstance(key_id, str):
            return None
        with self._lock:
            entry = self._keys.get(key_id)
        return None if entry is None else (entry.approver, entry.public_key_hex)


def _is_number(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


class ApprovalGate:
    """Count the approvals that independently approve one request.

    :meth:`evaluate` never raises and never consumes; :meth:`consume`
    atomically spends the nonces of a satisfied result right before the
    approved action runs, so concurrent replays lose.

    Phase 4: with ``telemetry=`` the gate records APPROVAL_REQUESTED the
    first time it sees an action hash in a new approval cycle (any non-dry-run
    evaluation, satisfied or not, or :meth:`note_approval_requested` from
    ``GovernedToolDispatcher.action_hash_for``) and one APPROVAL_GRANTED per
    approver in the earliest quorum-completing prefix when a quorum is consumed.
    Later surplus approvals are still consumed but cannot inflate latency.
    The GRANTED time is the
    approval's signed ``issued_at`` clamped to [first seen, consumption], so
    an agent sitting on a signed approval does not inflate the latency. An
    approval signed before the gate first saw the hash (pre-collected)
    yields latency 0 and is reported as ``pre_approved``. ``issued_at`` is
    the signer's clock; the recorder must use the same (wall) clock. Best
    effort: telemetry errors are counted (:attr:`telemetry_failures`), never
    raised.
    """

    # TODO(control-plane-gap): consumed nonces live in memory; a restarted
    # harness forgets them (the short TTL bounds the replay window).

    def __init__(
        self,
        authority: ApprovalAuthority,
        *,
        policies: Mapping[ActionTier, QuorumPolicy] = DEFAULT_QUORUM_POLICIES,
        clock: Callable[[], float] = time.time,
        max_clock_skew_s: float = DEFAULT_CLOCK_SKEW_S,
        telemetry: TelemetryRecorder | None = None,
    ) -> None:
        if telemetry is not None:
            from acgs_lite.control_plane.telemetry import TelemetryRecorder

            if type(telemetry) is not TelemetryRecorder:
                raise TypeError("telemetry must be a TelemetryRecorder")
        if not isinstance(authority, ApprovalAuthority):
            raise TypeError("authority must be an ApprovalAuthority")
        checked: dict[ActionTier, QuorumPolicy] = {}
        for tier, policy in policies.items():
            if not isinstance(policy, QuorumPolicy):
                raise TypeError("policies must map ActionTier to QuorumPolicy")
            checked[ActionTier(tier)] = policy
        if not _is_number(max_clock_skew_s) or max_clock_skew_s < 0:
            raise ValueError("max_clock_skew_s must be a finite number >= 0")
        self._authority = authority
        self._policies = MappingProxyType(checked)
        self._clock = clock
        self._skew = float(max_clock_skew_s)
        self._lock = threading.Lock()
        self._consumed: set[tuple[str, str]] = set()
        self._telemetry = telemetry
        self._requested: collections.OrderedDict[str, tuple[float, str]] = collections.OrderedDict()
        self._resolved: set[str] = set()  # quorum consumed or human denied
        self.telemetry_failures = 0
        if telemetry is not None:
            self._telemetry_call(telemetry.store.subscribe, self._observe_approval_denial)

    @property
    def authority(self) -> ApprovalAuthority:
        return self._authority

    def policy_for(self, tier: ActionTier) -> QuorumPolicy | None:
        return self._policies.get(tier)

    def is_consumed(self, approval: SignedApproval) -> bool:
        with self._lock:
            return (str(approval.key_id), str(approval.nonce)) in self._consumed

    def consume(self, result: QuorumResult) -> bool:
        """Spend every counted approval of *result*; False if any was spent."""
        keys = [(str(a.key_id), str(a.nonce)) for a in result.counted_approvals]
        with self._lock:
            if any(key in self._consumed for key in keys):
                return False
            self._consumed.update(keys)
        telemetry = self._telemetry
        if telemetry is not None:
            self._record_granted(telemetry, result)
        return True

    def _record_granted(self, telemetry: TelemetryRecorder, result: QuorumResult) -> None:
        try:
            now = float(telemetry.clock())
            with self._lock:
                current = self._requested.get(result.action_hash)
                requested_at = result.telemetry_requested_at
                if current is not None and current[1] == result.telemetry_cycle_id:
                    self._resolved.add(result.action_hash)
        except Exception as exc:
            logger.warning("approval telemetry failed: %s", type(exc).__name__)
            with self._lock:
                self.telemetry_failures += 1
            return
        completion_ids = set(result.completion_approver_ids)
        for approver_id, approval in zip(
            result.counted_approver_ids, result.counted_approvals, strict=False
        ):
            if approver_id not in completion_ids:
                continue
            at = min(float(approval.issued_at), now)
            if requested_at is not None:
                at = max(at, min(requested_at, now))
            self._telemetry_call(
                telemetry.record_approval_granted,
                result.action_hash,
                approver_id,
                cycle_id=result.telemetry_cycle_id,
                at=at,
            )

    def _telemetry_call(
        self, fn: Callable[..., object], *args: object, at: float | None = None, **kwargs: object
    ) -> None:
        try:
            if at is None:
                fn(*args, **kwargs)
            else:
                fn(*args, at=at, **kwargs)
        except Exception as exc:
            logger.warning("approval telemetry failed: %s", type(exc).__name__)
            with self._lock:
                self.telemetry_failures += 1

    def _observe_approval_denial(self, event: OversightEvent) -> None:
        """Resolve telemetry cycles only; a denial never changes authorization."""
        from acgs_lite.control_plane.telemetry import ApprovalDenied

        if not isinstance(event, ApprovalDenied):
            return
        with self._lock:
            current = self._requested.get(event.action_hash)
            if current is None or event.at < current[0]:
                return
            if event.cycle_id is not None and event.cycle_id != current[1]:
                return
            self._resolved.add(event.action_hash)

    def _evict_one(self) -> None:
        """Drop the oldest resolved request; only if none is resolved, the
        oldest pending one (lock held).

        TODO(control-plane-gap): with more than _MAX_REQUESTED_TRACKED pending
        requests the oldest pending requested_at is lost; its GRANTED time is
        then clamped only by consumption time.
        """
        for key in self._requested:
            if key in self._resolved:
                del self._requested[key]
                self._resolved.discard(key)
                return
        self._requested.popitem(last=False)

    def note_approval_requested(
        self, action_hash: str, *, principal_kind: PrincipalKind | None = None
    ) -> tuple[float, str] | None:
        """Record one pending cycle; start another after consumption or human denial."""
        telemetry = self._telemetry
        if telemetry is None or not isinstance(action_hash, str) or not action_hash:
            return None
        try:
            now = float(telemetry.clock())
        except Exception as exc:
            logger.warning("approval telemetry failed: %s", type(exc).__name__)
            with self._lock:
                self.telemetry_failures += 1
            return None
        with self._lock:
            if action_hash in self._requested and action_hash not in self._resolved:
                return self._requested[action_hash]
            cycle = (now, uuid.uuid4().hex)
            self._requested[action_hash] = cycle
            self._requested.move_to_end(action_hash)
            self._resolved.discard(action_hash)
            while len(self._requested) > _MAX_REQUESTED_TRACKED:
                self._evict_one()
        self._telemetry_call(
            telemetry.record_approval_requested,
            action_hash,
            principal_kind=principal_kind,
            cycle_id=cycle[1],
            at=now,
        )
        return cycle

    def evaluate(
        self,
        request: DecisionRequest,
        approvals: Iterable[object],
        *,
        record_request: bool = True,
    ) -> QuorumResult:
        """Return the quorum verdict for *request*; never raises.

        ``record_request=False`` (dry runs) skips the APPROVAL_REQUESTED
        telemetry; it never changes the verdict."""
        try:
            result = self._evaluate(request, tuple(approvals))
            if record_request and result.required > 0:
                cycle = self.note_approval_requested(
                    result.action_hash, principal_kind=request.principal.kind
                )
                if cycle is not None:
                    result = replace(
                        result, telemetry_requested_at=cycle[0], telemetry_cycle_id=cycle[1]
                    )
            return result
        except Exception as exc:
            return QuorumResult(
                satisfied=False,
                action_hash="",
                required=0,
                rejected=(("*", f"approval evaluation failed: {type(exc).__name__}"),),
            )

    def _evaluate(self, request: DecisionRequest, approvals: Sequence[object]) -> QuorumResult:
        policy = self.policy_for(request.tier) if isinstance(request.tier, ActionTier) else None
        required = policy.min_approvals if policy is not None else 0
        if policy is None and (
            not isinstance(request.tier, ActionTier) or request.tier >= _GATED_MIN_TIER
        ):
            # An approval-gated tier without a configured quorum is a
            # misconfiguration, not a zero-approval quorum.
            return QuorumResult(
                satisfied=False,
                action_hash="",
                required=0,
                rejected=(("*", f"no quorum policy configured for tier {request.tier!r}"),),
            )
        try:
            expected = action_hash(request)
        except Exception as exc:
            return QuorumResult(
                satisfied=False,
                action_hash="",
                required=required,
                rejected=tuple(
                    (str(getattr(a, "approval_id", "?")), f"action hash unavailable: {exc}")
                    for a in approvals
                )
                or (("*", "action hash unavailable"),),
            )
        now = float(self._clock())
        requester = request.principal
        # Exclusions come from the same subject the action hash binds: a path
        # sub-request is approved as its parent tool call, so its author and
        # original requester are the parent's.
        subject_attributes = approval_subject(request).attributes
        author = subject_attributes.get("authored_by")
        author_id = canonical_principal_id(author) if isinstance(author, str) and author else None
        original = subject_attributes.get("requested_by")
        requested_by = (
            canonical_principal_id(original) if isinstance(original, str) and original else None
        )
        counted: list[SignedApproval] = []
        approvers: list[Principal] = []
        seen: set[str] = set()
        rejected: list[tuple[str, str]] = []
        for approval in approvals:
            label = str(getattr(approval, "approval_id", "?"))
            outcome = self._check(
                approval, expected, requester, author_id, requested_by, policy, now
            )
            if isinstance(outcome, str):
                rejected.append((label, outcome))
                continue
            if outcome.canonical_id in seen:
                rejected.append((label, "duplicate approver (counted once)"))
                continue
            seen.add(outcome.canonical_id)
            counted.append(cast(SignedApproval, approval))
            approvers.append(outcome)
        covered = frozenset(role for a in approvers for role in a.roles)
        missing = (policy.required_roles - covered) if policy is not None else frozenset()
        satisfied = len(counted) >= required and not missing
        completion: list[str] = []
        if satisfied and required > 0:
            completion_roles: set[str] = set()
            for _approval, approver in sorted(
                zip(counted, approvers, strict=False), key=lambda pair: pair[0].issued_at
            ):
                completion.append(approver.canonical_id)
                completion_roles.update(approver.roles)
                if len(completion) >= required and (
                    policy is None or policy.required_roles <= completion_roles
                ):
                    break
        return QuorumResult(
            satisfied=satisfied,
            action_hash=expected,
            required=required,
            counted_approver_ids=tuple(a.canonical_id for a in approvers),
            approvers=tuple(approvers),
            counted_approvals=tuple(counted),
            rejected=tuple(rejected),
            missing_roles=missing,
            completion_approver_ids=tuple(completion),
        )

    def _check(
        self,
        approval: object,
        expected: str,
        requester: Principal,
        author_id: str | None,
        requested_by: str | None,
        policy: QuorumPolicy | None,
        now: float,
    ) -> Principal | str:
        """Return the registered approver Principal, or a rejection reason."""
        if type(approval) is not SignedApproval:
            return "not a SignedApproval"
        for name in ("approval_id", "approver_kind", "nonce", "key_id"):
            value = getattr(approval, name)
            if not isinstance(value, str) or not _TOKEN.fullmatch(value):
                return f"malformed {name}"
        try:
            # approver_id is a principal id ("bob@example.com"), not a token.
            Principal(approval.approver_id, PrincipalKind.HUMAN)
        except (TypeError, ValueError):
            return "malformed approver_id"
        if not isinstance(approval.signature, str) or not approval.signature:
            return "missing signature"
        if not isinstance(approval.action_hash, str) or not _HASH.fullmatch(approval.action_hash):
            return "malformed action_hash"
        if not _is_number(approval.issued_at) or not _is_number(approval.expires_at):
            return "malformed validity window"
        entry = self._authority.lookup(approval.key_id)
        if entry is None:
            return "unknown approver key"
        approver, public_key_hex = entry
        if approver.kind is not PrincipalKind.HUMAN or approval.approver_kind != "human":
            return "approver is not human"
        if canonical_principal_id(approval.approver_id) != approver.canonical_id:
            return "approver id does not match the registered key"
        try:
            valid = verify_signature(
                SIGNATURE_ALGORITHM,
                public_key_hex,
                approval.signing_message(),
                approval.signature,
            )
        except Exception as exc:
            return f"signature unverifiable: {type(exc).__name__}"
        if not valid:
            return "invalid signature"
        if approval.action_hash != expected:
            return "approval is bound to a different action"
        ttl = policy.ttl_s if policy is not None else DEFAULT_APPROVAL_TTL_S
        if approval.expires_at <= approval.issued_at:
            return "empty validity window"
        if approval.expires_at - approval.issued_at > ttl + self._skew:
            return "approval lifetime exceeds the policy TTL"
        if approval.issued_at > now + self._skew:
            return "approval issued in the future"
        if now >= approval.expires_at:
            return "approval expired"
        if self.is_consumed(approval):
            return "approval nonce already consumed (replay)"
        if approver.canonical_id == requester.canonical_id:
            return "requester cannot approve their own request"
        if author_id is not None and approver.canonical_id == author_id:
            return "authoring principal cannot approve"
        if requested_by is not None and approver.canonical_id == requested_by:
            return "original requester cannot approve their own request"
        if requester.kind is PrincipalKind.AGENT:
            # TODO(control-plane-gap): sibling exclusion by system_id and
            # registered membership is design inference; no primary source
            # defines "sibling" for agent fleets.
            if requester.system_id is not None and approver.system_id == requester.system_id:
                return "sibling of the requesting agent's system"
            if self._authority.is_system_member(requester.system_id, approver.id):
                return "registered member of the requesting agent's system"
        return approver
