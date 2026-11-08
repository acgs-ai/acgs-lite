"""Incident mutation lock: during an incident only one party may write.

Evidence: Replit -- during an incident (a code freeze) an agent kept
mutating production and destroyed data. While an incident is declared, every
write-class dispatch by a principal that does not hold the lock is denied
(read-only T0 tools stay available for diagnosis), humans included: two
humans racing fixes is also a second writer.

Only a HUMAN incident commander declares, designates the single holder
(agent or human), transfers, releases and resolves. State lives in one JSON
file (default ``control-plane/incident/lock.json``, under the
``control-plane/**`` core pattern, so no agent tool can write it) and is
re-read on every check, so a lock declared by one process is enforced by
every other. Any read or parse error counts as "incident declared, nobody
holds the lock" (fail closed). Writes are atomic (temp file + rename).

The state file is never deleted: resolving writes a ``resolved`` tombstone,
and every lifecycle event is appended to ``history.jsonl`` next to it. A
missing state file after any incident was ever declared (history present,
or seen by this process) therefore denies writes. With ``roles=`` only a
holder of the ``incident_commander`` capability may declare, and a holder of
``incident_admin`` may take over command of a *stale* incident
(:meth:`IncidentMutationLock.take_over`, logged in the history).

With ``pdp=`` (a PDP bound to an ApprovalGate and a receipt ledger) declare,
resolve and take-over are PDP decisions, so each is a signed ledger receipt.
On construction the lock replays those receipts: an incident declared and
not resolved survives the loss of the whole state directory (which is then
*not* recreated -- writes stay denied). Staleness is measured from the last
activity of the commander or holder (any lifecycle event or
:meth:`IncidentMutationLock.heartbeat`), and a take-over needs a signed
approval from a *second* ``incident_admin`` over the take-over's action hash.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import re
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from acgs_lite.control_plane.immutable_core import ImmutableCoreRegistry
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.tiers import ActionTier

if TYPE_CHECKING:
    from acgs_lite.control_plane.approvals import SignedApproval
    from acgs_lite.control_plane.context import DecisionRequest
    from acgs_lite.control_plane.identity import AdminAttestor
    from acgs_lite.control_plane.pdp import PolicyDecisionPoint

from acgs_lite.control_plane.roles import (
    CAP_INCIDENT_ADMIN,
    CAP_INCIDENT_COMMANDER,
    RoleAssignments,
)

__all__ = [
    "DEFAULT_INCIDENT_STATE_PATH",
    "IncidentLockError",
    "IncidentMutationLock",
    "IncidentState",
    "LockToken",
]

DEFAULT_INCIDENT_STATE_PATH = Path("control-plane") / "incident" / "lock.json"
DECLARE_ACTION = "incident.declare"
RESOLVE_ACTION = "incident.resolve"
TAKEOVER_ACTION = "incident.take_over"
_INCIDENT_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_STATE_KEYS = frozenset({"version", "status", "incident_id", "commander", "holder", "declared_at"})
_STATUSES = frozenset({"active", "resolved"})
# TODO(control-plane-gap): 4 h before an incident counts as stale for a
# break-glass takeover is a design inference; configurable per lock.
DEFAULT_STALE_AFTER_S = 4 * 3600.0


class IncidentLockError(PermissionError):
    """An incident operation was refused."""


@dataclass(frozen=True)
class LockToken:
    incident_id: str
    holder_id: str
    holder_kind: str


@dataclass(frozen=True)
class IncidentState:
    incident_id: str
    commander_id: str
    holder_id: str | None
    holder_kind: str | None
    declared_at: float
    status: str = "active"


def _principal_dict(principal: Principal) -> dict[str, str]:
    return {"id": principal.canonical_id, "kind": principal.kind.value}


def _parse(data: object) -> IncidentState:
    if not isinstance(data, Mapping) or set(data) != _STATE_KEYS or data["version"] != 1:
        raise ValueError("malformed incident state")
    if data["status"] not in _STATUSES:
        raise ValueError("malformed incident status")
    incident_id = data["incident_id"]
    commander = data["commander"]
    holder = data["holder"]
    declared_at = data["declared_at"]
    if not isinstance(incident_id, str) or not _INCIDENT_ID.fullmatch(incident_id):
        raise ValueError("malformed incident id")
    if not isinstance(commander, Mapping) or commander.get("kind") != PrincipalKind.HUMAN.value:
        raise ValueError("incident commander must be human")
    if not isinstance(commander.get("id"), str):
        raise ValueError("malformed commander")
    if holder is not None and (
        not isinstance(holder, Mapping)
        or not isinstance(holder.get("id"), str)
        or holder.get("kind") not in {k.value for k in PrincipalKind}
    ):
        raise ValueError("malformed holder")
    if isinstance(declared_at, bool) or not isinstance(declared_at, (int, float)):
        raise ValueError("malformed declared_at")
    return IncidentState(
        incident_id=incident_id,
        commander_id=commander["id"],
        holder_id=None if holder is None else holder["id"],
        holder_kind=None if holder is None else holder["kind"],
        declared_at=float(declared_at),
        status=data["status"],
    )


class IncidentMutationLock:
    """Cross-process single-writer lock for incidents."""

    def __init__(
        self,
        state_path: str | Path = DEFAULT_INCIDENT_STATE_PATH,
        *,
        registry: ImmutableCoreRegistry | None = None,
        clock: Callable[[], float] = time.time,
        roles: RoleAssignments | None = None,
        stale_after_s: float = DEFAULT_STALE_AFTER_S,
        pdp: PolicyDecisionPoint | None = None,
        admin_attestor: AdminAttestor | None = None,
    ) -> None:
        """With *admin_attestor* every commander operation needs the
        commander's verified single-use HUMAN ``admin_credential=``."""
        from acgs_lite.control_plane.identity import checked_attestor

        self._attestor = checked_attestor(admin_attestor)
        if roles is not None and type(roles) is not RoleAssignments:
            raise TypeError("roles must be a RoleAssignments")
        if pdp is not None:
            from acgs_lite.control_plane.pdp import PolicyDecisionPoint

            if (
                not isinstance(pdp, PolicyDecisionPoint)
                or pdp.receipt_ledger is None
                or pdp.approval_gate is None
            ):
                raise TypeError("pdp must be a PolicyDecisionPoint with a ledger and a gate")
        self._pdp = pdp
        path = Path(state_path)
        if not path.is_absolute() and registry is not None and registry.repo_root:
            path = Path(registry.repo_root) / path
        if registry is not None and not registry.is_core(str(path)):
            raise ValueError("incident state must live under the immutable core")
        # TODO(control-plane-gap): without a registry the state path is not
        # checked against the core; pass one so no agent tool can write it.
        self._ledger_seen = 0
        self._ledger_scan: str | None = None
        self._ledger_incident = self._ledger_unresolved()
        self._ledger_open = self._ledger_incident is not None
        if not self._ledger_open:
            # Never recreate a deleted directory while the ledger says an
            # incident is open: the missing state must keep denying writes.
            path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._history = path.parent / "history.jsonl"
        self._clock = clock
        self._lock = threading.Lock()
        self._roles = roles
        self._stale_after = float(stale_after_s)
        self._ever_declared = self._ledger_open or self._history.exists() or path.exists()

    def _ledger_unresolved(self) -> str | None:
        """The incident id of the PDP ledger's last incident.declare with no
        later resolve, else ``None``.

        Cross-instance visibility holds only for instances sharing one PDP /
        receipt ledger (consistent with the single-writer receipt store); an
        instance with its own ledger never sees another's declare.
        """
        pdp = self._pdp
        ledger = None if pdp is None else pdp.receipt_ledger
        if ledger is None:
            return None
        # Incremental: only receipts appended since the last scan are read, so
        # re-checking on every write decision stays cheap.
        receipts = ledger.receipts()
        start = self._ledger_seen if self._ledger_seen <= len(receipts) else 0
        open_incident = self._ledger_scan if start else None
        for signed in receipts[start:]:
            receipt = signed.receipt
            if not receipt.allowed:
                continue
            if receipt.action == DECLARE_ACTION:
                open_incident = receipt.resource
            elif receipt.action == RESOLVE_ACTION:
                open_incident = None
        self._ledger_seen = len(receipts)
        self._ledger_scan = open_incident
        return open_incident

    @contextlib.contextmanager
    def _execution_guard(self, *, exclusive: bool) -> Iterator[None]:
        """Pin incident ownership without blocking an event-loop caller."""
        try:
            fcntl: Any = importlib.import_module("fcntl")
        except ImportError as exc:  # pragma: no cover - non-POSIX only
            raise IncidentLockError("incident execution lease needs POSIX flock") from exc
        try:
            handle = open(self._path.with_name(self._path.name + ".execution.flock"), "a+b")  # noqa: SIM115
        except OSError as exc:
            raise IncidentLockError("incident execution lease unavailable") from exc
        with handle:
            try:
                mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                fcntl.flock(handle.fileno(), mode | fcntl.LOCK_NB)
            except OSError as exc:
                raise IncidentLockError("incident execution is active or transitioning") from exc
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @contextlib.contextmanager
    def execution(self, principal: Principal) -> Iterator[None]:
        """Keep the current writer authorized throughout one execution body."""
        with self._execution_guard(exclusive=False):
            denial = self.write_denial(principal)
            if denial is not None:
                raise IncidentLockError(denial)
            yield

    @contextlib.contextmanager
    def _transition(self) -> Iterator[None]:
        # All ownership-changing lifecycle operations refuse an active writer;
        # a tool calling transfer itself must never wait on its own lease.
        with self._execution_guard(exclusive=True), self._locked():
            yield

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialise a lifecycle read/check/write across threads *and*
        processes (instances sharing the state file): ``flock`` on a sidecar
        lock file. It is opened without creating directories, so a deleted
        state directory still fails closed."""
        try:
            fcntl: Any = importlib.import_module("fcntl")
        except ImportError as exc:  # pragma: no cover - non-POSIX only
            raise IncidentLockError("incident lock needs POSIX flock") from exc
        with self._lock:
            try:
                # Entered with `with handle:` below; the open is split out so an
                # OSError maps to IncidentLockError.
                handle = open(self._path.with_name(self._path.name + ".flock"), "a+b")  # noqa: SIM115
            except OSError as exc:
                raise IncidentLockError(f"incident lock unavailable: {type(exc).__name__}") from exc
            with handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _decide(
        self,
        principal: Principal,
        action: str,
        incident_id: str,
        tier: ActionTier = ActionTier.T1,
        attributes: Mapping[str, Any] | None = None,
        approvals: tuple[SignedApproval, ...] = (),
    ) -> None:
        """Publish a lifecycle step through the PDP (receipted); deny -> raise."""
        if self._pdp is None:
            return
        decision, _ = self._pdp._decide_attested(
            self._request(principal, action, incident_id, tier, attributes, approvals)
        )
        if not decision.allowed:
            raise IncidentLockError(f"PDP denied {action}: {decision.reason}")

    @staticmethod
    def _request(
        principal: Principal,
        action: str,
        incident_id: str,
        tier: ActionTier,
        attributes: Mapping[str, Any] | None,
        approvals: tuple[SignedApproval, ...] = (),
    ) -> DecisionRequest:
        from acgs_lite.control_plane.context import DecisionRequest

        return DecisionRequest(
            principal=principal,
            action=action,
            resource=incident_id,
            tier=tier,
            attributes=dict(attributes or {}),
            approvals=approvals,
        )

    @property
    def state_path(self) -> Path:
        return self._path

    # -- state file ----------------------------------------------------

    def state(self) -> IncidentState | None:
        """The active incident, ``None`` if none; raises on unreadable state
        (including a missing state file once any incident was declared)."""
        if not self._path.parent.is_dir():
            raise OSError("incident state directory is missing")
        try:
            text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            if self._ever_declared or self._ledger_open or self._history.exists():
                raise OSError("incident state file missing after an incident") from None
            if self._pdp is not None and self._ledger_unresolved() is not None:
                # Fresh deployment: another instance's declare is receipted but
                # its state write failed -- the ledger, not the file, decides.
                raise OSError(
                    "incident declared in the receipt ledger; state file missing"
                ) from None
            return None
        state = _parse(json.loads(text))
        self._ever_declared = True
        if self._pdp is not None:
            # Re-read the ledger tail: another instance (or this one, whose
            # state write failed) may have receipted a replacement incident
            # since. A live reader can miss the resolved intermediate state.
            ledger_incident = self._ledger_unresolved()
            self._ledger_open = ledger_incident is not None
            self._ledger_incident = ledger_incident
        if self._ledger_open and (
            state.status == "resolved" or state.incident_id != self._ledger_incident
        ):
            # The receipt ledger says an incident is open; a resolved (or
            # different) state file is a stale tombstone from a crashed
            # declare, not permission to write.
            raise OSError("incident state disagrees with the receipt ledger")
        return None if state.status == "resolved" else state

    def _log(self, event: str, actor: Principal, **detail: Any) -> None:
        record = {"event": event, "actor": _principal_dict(actor), "at": self._clock(), **detail}
        with open(self._history, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def history(self) -> tuple[dict[str, Any], ...]:
        try:
            lines = self._history.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return ()
        return tuple(json.loads(line) for line in lines if line.strip())

    def _write(self, payload: Mapping[str, Any]) -> None:
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".lock-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def _payload(
        self,
        state: IncidentState,
        holder: Principal | None,
        *,
        status: str = "active",
        commander_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "version": 1,
            "status": status,
            "incident_id": state.incident_id,
            "commander": {
                "id": commander_id or state.commander_id,
                "kind": PrincipalKind.HUMAN.value,
            },
            "holder": None if holder is None else _principal_dict(holder),
            "declared_at": state.declared_at,
        }

    def _attest(self, commander: Principal, credential: str | None) -> None:
        if self._attestor is not None:
            self._attestor.require(commander, credential, admin_only=False, error=IncidentLockError)

    def _require_commander(
        self, commander: Principal, credential: str | None = None
    ) -> IncidentState:
        if not isinstance(commander, Principal) or commander.kind is not PrincipalKind.HUMAN:
            raise IncidentLockError("only a HUMAN incident commander may do this")
        self._attest(commander, credential)
        try:
            state = self.state()
        except (OSError, ValueError) as exc:
            raise IncidentLockError(f"incident state unreadable: {type(exc).__name__}") from exc
        if state is None:
            raise IncidentLockError("no incident is declared")
        if state.commander_id != commander.canonical_id:
            raise IncidentLockError("only the declaring incident commander may do this")
        return state

    # -- commander API ---------------------------------------------------

    def declare_incident(
        self, commander: Principal, incident_id: str, *, admin_credential: str | None = None
    ) -> IncidentState:
        if not isinstance(commander, Principal) or commander.kind is not PrincipalKind.HUMAN:
            raise IncidentLockError("only a HUMAN may declare an incident")
        self._attest(commander, admin_credential)
        if self._roles is not None and not self._roles.has_capability(
            commander, CAP_INCIDENT_COMMANDER
        ):
            raise IncidentLockError("declaring needs the incident_commander capability")
        if not isinstance(incident_id, str) or not _INCIDENT_ID.fullmatch(incident_id):
            raise IncidentLockError("incident_id must match [A-Za-z0-9._:-]{1,128}")
        with self._transition():
            try:
                existing = self.state()
            except (OSError, ValueError) as exc:
                raise IncidentLockError(f"incident state unreadable: {type(exc).__name__}") from exc
            if existing is not None:
                raise IncidentLockError(f"incident {existing.incident_id!r} is already declared")
            self._decide(commander, DECLARE_ACTION, incident_id)
            # The declare is receipted: deny writes from now on, even if the
            # state write below fails (state() then disagrees -> denied).
            self._ever_declared = True
            self._ledger_open = self._pdp is not None
            self._ledger_incident = incident_id if self._ledger_open else None
            state = IncidentState(incident_id, commander.canonical_id, None, None, self._clock())
            self._write(self._payload(state, None))
            self._log("declare", commander, incident_id=incident_id)
            return state

    def acquire(
        self,
        principal: Principal,
        incident_id: str,
        *,
        commander: Principal,
        admin_credential: str | None = None,
    ) -> LockToken:
        """Designate *principal* as the single holder (commander-approved).

        A second acquire while the lock is held is refused; use
        :meth:`transfer` to move it.
        """
        if not isinstance(principal, Principal):
            raise IncidentLockError("holder must be a Principal")
        with self._transition():
            state = self._require_commander(commander, admin_credential)
            if state.incident_id != incident_id:
                raise IncidentLockError("incident id mismatch")
            if state.holder_id is not None:
                raise IncidentLockError(f"incident mutation lock held by {state.holder_id}")
            self._write(self._payload(state, principal))
            self._log("acquire", commander, holder=_principal_dict(principal))
        return LockToken(incident_id, principal.canonical_id, principal.kind.value)

    def transfer(
        self, commander: Principal, new_holder: Principal, *, admin_credential: str | None = None
    ) -> LockToken:
        if not isinstance(new_holder, Principal):
            raise IncidentLockError("holder must be a Principal")
        with self._transition():
            state = self._require_commander(commander, admin_credential)
            self._write(self._payload(state, new_holder))
            self._log("transfer", commander, holder=_principal_dict(new_holder))
        return LockToken(state.incident_id, new_holder.canonical_id, new_holder.kind.value)

    def release(self, commander: Principal, *, admin_credential: str | None = None) -> None:
        """Release the holder; the incident stays declared (nobody may write)."""
        with self._transition():
            state = self._require_commander(commander, admin_credential)
            self._write(self._payload(state, None))
            self._log("release", commander)

    def resolve(self, commander: Principal, *, admin_credential: str | None = None) -> None:
        """End the incident."""
        with self._transition():
            state = self._require_commander(commander, admin_credential)
            self._decide(commander, RESOLVE_ACTION, state.incident_id)
            self._write(self._payload(state, None, status="resolved"))
            self._ledger_open = False
            self._ledger_incident = None
            self._log("resolve", commander, incident_id=state.incident_id)

    def heartbeat(self, principal: Principal) -> None:
        """The commander or the holder proves it is still active."""
        with self._locked():
            try:
                state = self.state()
            except (OSError, ValueError) as exc:
                raise IncidentLockError(f"incident state unreadable: {type(exc).__name__}") from exc
            if state is None:
                raise IncidentLockError("no incident is declared")
            # Id *and* kind, as in write_denial(): an AGENT sharing the
            # commander's id must not keep the incident fresh.
            is_commander = (
                isinstance(principal, Principal)
                and principal.kind is PrincipalKind.HUMAN
                and principal.canonical_id == state.commander_id
            )
            is_holder = (
                isinstance(principal, Principal)
                and state.holder_id is not None
                and principal.canonical_id == state.holder_id
                and principal.kind.value == state.holder_kind
            )
            if not (is_commander or is_holder):
                raise IncidentLockError("only the commander or the holder sends heartbeats")
            self._log("heartbeat", principal, incident_id=state.incident_id)

    def last_activity(self, state: IncidentState) -> float:
        """Latest lifecycle event or heartbeat by the commander or the holder."""
        active: set[tuple[str, str | None]] = {(state.commander_id, PrincipalKind.HUMAN.value)}
        if state.holder_id is not None:
            active.add((state.holder_id, state.holder_kind))
        latest = state.declared_at
        for event in self.history():
            actor = event.get("actor")
            at = event.get("at")
            if (
                isinstance(actor, Mapping)
                and (actor.get("id"), actor.get("kind")) in active
                and isinstance(at, (int, float))
                and not isinstance(at, bool)
            ):
                latest = max(latest, float(at))
        return latest

    def takeover_request(
        self,
        admin: Principal,
        reason: str,
        approvals: tuple[SignedApproval, ...] = (),
    ) -> DecisionRequest:
        """The ``incident.take_over`` request a second incident_admin signs."""
        state = self.state()
        if state is None:
            raise IncidentLockError("no incident is declared")
        return self._request(
            admin,
            TAKEOVER_ACTION,
            state.incident_id,
            ActionTier.T2,
            {"previous_commander": state.commander_id, "reason": reason},
            approvals,
        )

    def take_over(
        self,
        admin: Principal,
        reason: str,
        *,
        approvals: Sequence[SignedApproval] = (),
        admin_credential: str | None = None,
    ) -> IncidentState:
        """Break glass: a human holding ``incident_admin`` takes command of a
        stale incident (no commander/holder activity for ``stale_after_s``),
        with a signed approval from a *second* incident_admin; receipted and
        logged. The holder is released."""
        self._attest(admin, admin_credential)
        if self._roles is None or self._pdp is None:
            raise IncidentLockError("break-glass takeover needs role assignments and a PDP")
        if not self._roles.has_capability(admin, CAP_INCIDENT_ADMIN):
            raise IncidentLockError("takeover needs the incident_admin capability")
        if not isinstance(reason, str) or not reason.strip():
            raise IncidentLockError("a takeover needs a reason")
        with self._transition():
            try:
                state = self.state()
            except (OSError, ValueError) as exc:
                raise IncidentLockError(f"incident state unreadable: {type(exc).__name__}") from exc
            if state is None:
                raise IncidentLockError("no incident is declared")
            if state.commander_id == admin.canonical_id:
                raise IncidentLockError("the current commander cannot take over")
            if self._clock() - self.last_activity(state) < self._stale_after:
                raise IncidentLockError("incident is not stale; the commander or holder is active")
            request = self.takeover_request(admin, reason, tuple(approvals))
            gate = self._pdp.approval_gate
            if gate is None:  # pragma: no cover - refused at construction
                raise IncidentLockError("no approval gate")
            quorum = gate.evaluate(request, request.approvals, record_request=False)
            seconds = [
                a
                for a in quorum.approvers
                if a.canonical_id not in {admin.canonical_id, state.commander_id}
                and self._roles.has_capability(a, CAP_INCIDENT_ADMIN)
            ]
            if not quorum.satisfied or not seconds:
                raise IncidentLockError(
                    "takeover needs a signed approval from a second incident_admin"
                )
            decision, _ = self._pdp._decide_attested(request)
            if not decision.allowed:
                raise IncidentLockError(f"PDP denied takeover: {decision.reason}")
            self._write(self._payload(state, None, commander_id=admin.canonical_id))
            self._log(
                "takeover",
                admin,
                incident_id=state.incident_id,
                previous_commander=state.commander_id,
                approved_by=seconds[0].canonical_id,
                reason=reason,
            )
            return IncidentState(
                state.incident_id, admin.canonical_id, None, None, state.declared_at
            )

    # -- enforcement ---------------------------------------------------

    def write_denial(self, principal: Principal) -> str | None:
        """Why *principal* may not write now, or ``None``. Fail closed."""
        try:
            state = self.state()
        except Exception as exc:
            return f"incident lock state unreadable ({type(exc).__name__}); writes denied"
        if state is None:
            return None
        if state.holder_id is None:
            return f"incident {state.incident_id} declared; mutation lock held by nobody"
        if (
            not isinstance(principal, Principal)
            or principal.canonical_id != state.holder_id
            or principal.kind.value != state.holder_kind
        ):
            return f"incident mutation lock held by {state.holder_id}"
        return None
