"""Oversight telemetry: typed events, append-only stores and four metrics.

Phase 4 measures whether human oversight of self-improving agents works:

* **override rate** -- how often a human reverses an automated decision;
* **approval latency** -- how long a T2+ action waits for its signed quorum;
* **verifier precision/recall** -- how well the verifier's verdicts match
  ground truth established independently of the agent;
* **post-merge rework rate** -- how often a merged change is reverted, fixed
  up or hot-fixed within a window, segmented by agent vs human authors.

Evidence: METR (Mar 2026) found maintainer merge decisions on 296 AI-written
patches ran ~24 percentage points below the SWE-bench grader's pass rate --
a grader pass is not an accepted change. Hence verifier precision/recall is
measured against ground truth from external runs or human review, and
post-merge rework is tracked separately for agent and human authors. DGM:
the agent faked its own success logs, so agents never author the telemetry
that judges them -- an AGENT recorder is refused, and ground truth or rework
evidence from an AGENT principal or an ``AGENT_LOG`` source is rejected.

Design choices (not from a primary source):

* An *override* is a human reversing an automated (PDP) decision
  (``human_overrode_allow`` / ``human_overrode_deny``). A human correcting a
  verifier verdict is recorded as :class:`GroundTruth` with source
  ``HUMAN_REVIEW`` and shows up in precision/recall instead.
* For the verifier, **"fail" is the positive class**: the verifier's job is
  to catch bad changes, so recall is the share of truly failing subjects it
  flagged and precision the share of its "fail" verdicts that were right.
* A zero denominator yields ``value=None``, never 0.

TODO(control-plane-gap): ``Principal.kind`` is host-asserted (see
:mod:`.principal`); a host that hands an agent a SERVICE principal lets it
record telemetry. Binding recorders to an authenticated harness session is a
later phase.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import logging
import math
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Literal, Protocol, cast, runtime_checkable

from acgs_lite._compat import StrEnum
from acgs_lite.control_plane.autonomy import AutonomyController, FailureKind
from acgs_lite.control_plane.evidence import (
    EvidenceSource,
    ExternalRunRef,
    require_audit_store_path,
)
from acgs_lite.control_plane.immutable_core import DEFAULT_IMMUTABLE_CORE, ImmutableCoreRegistry
from acgs_lite.control_plane.principal import Principal, PrincipalKind

if TYPE_CHECKING:
    from acgs_lite.control_plane.identity import AdminAttestor

__all__ = [
    "DEFAULT_REWORK_WINDOW_S",
    "DEFAULT_TELEMETRY_STORE_PATH",
    "AgentTelemetryRejected",
    "ApprovalDenied",
    "ApprovalGranted",
    "ApprovalRequested",
    "AuthorKind",
    "ConfusionMetric",
    "DecisionObserved",
    "EventKind",
    "GroundTruth",
    "InMemoryTelemetryStore",
    "JSONLTelemetryStore",
    "LatencyMetric",
    "Merge",
    "OversightEvent",
    "OversightMetrics",
    "Override",
    "OverrideDirection",
    "RateMetric",
    "Rework",
    "ReworkKind",
    "Rollback",
    "Segment",
    "TelemetryAutonomyBridge",
    "TelemetryRecorder",
    "TelemetryStore",
    "TelemetryStoreCorrupted",
    "VerificationFailed",
    "Verdict",
    "VerifierVerdict",
    "event_from_dict",
]

logger = logging.getLogger(__name__)

DEFAULT_TELEMETRY_STORE_PATH = "audit/oversight-telemetry.jsonl"
# TODO(control-plane-gap): the 14-day post-merge rework window is design
# inference (no primary evidence for the value); it is a per-query parameter.
DEFAULT_REWORK_WINDOW_S = 14 * 86400.0

Segment = Literal["agent", "human", "all"]
_SEGMENTS = frozenset({"agent", "human", "all"})

_ID = re.compile(r"[A-Za-z0-9._:/@+-]{1,256}")
_HASH = re.compile(r"sha256:[0-9a-f]{64}")


class AgentTelemetryRejected(PermissionError):
    """An AGENT tried to author telemetry, or evidence came from an agent."""


class TelemetryStoreCorrupted(ValueError):
    """A persisted telemetry line is malformed (the store fails to open)."""


class EventKind(StrEnum):
    DECISION = "decision"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    OVERRIDE = "override"
    VERIFIER_VERDICT = "verifier_verdict"
    GROUND_TRUTH = "ground_truth"
    MERGE = "merge"
    REWORK = "rework"
    ROLLBACK = "rollback"
    VERIFICATION_FAILED = "verification_failed"


class Verdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class AuthorKind(StrEnum):
    AGENT = "agent"
    HUMAN = "human"


class OverrideDirection(StrEnum):
    HUMAN_OVERRODE_ALLOW = "human_overrode_allow"
    HUMAN_OVERRODE_DENY = "human_overrode_deny"


class ReworkKind(StrEnum):
    REVERT = "revert"
    FIXUP = "fixup"
    HOTFIX = "hotfix"


def _check_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{label} must match [A-Za-z0-9._:/@+-]{{1,256}}: {value!r}")
    return value


def _check_optional_id(value: object, label: str) -> str | None:
    return None if value is None else _check_id(value, label)


def _reject_agent_source(source: EvidenceSource, label: str) -> None:
    if source is EvidenceSource.AGENT_LOG:
        raise AgentTelemetryRejected(f"{label} from an agent log is not evidence")


@dataclass(frozen=True, kw_only=True)
class OversightEvent:
    """Common fields of every telemetry record. ``at`` is recorder-clock
    seconds (wall time by default); one store must use one clock."""

    kind: ClassVar[EventKind]
    at: float
    recorded_by: str
    recorder_kind: PrincipalKind
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def __post_init__(self) -> None:
        if (
            isinstance(self.at, bool)
            or not isinstance(self.at, (int, float))
            or not math.isfinite(self.at)
        ):
            raise ValueError("at must be a finite number")
        object.__setattr__(self, "at", float(self.at))
        _check_id(self.recorded_by, "recorded_by")
        object.__setattr__(self, "recorder_kind", PrincipalKind(self.recorder_kind))
        if self.recorder_kind is PrincipalKind.AGENT:
            raise AgentTelemetryRejected("agents may not record oversight telemetry")
        _check_id(self.event_id, "event_id")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"kind": self.kind.value}
        for item in dataclasses.fields(self):
            value = getattr(self, item.name)
            if isinstance(value, ExternalRunRef):
                value = value.to_dict()
            elif isinstance(value, StrEnum):
                value = value.value
            data[item.name] = value
        return data


@dataclass(frozen=True, kw_only=True)
class DecisionObserved(OversightEvent):
    """One published PDP decision (the override-rate denominator).

    ``group_id`` is the ``tool.call`` decision id of the dispatch this
    decision belongs to (its per-path decisions share it); ``None`` for a
    standalone decision."""

    kind: ClassVar[EventKind] = EventKind.DECISION
    decision_id: str
    principal_kind: PrincipalKind | None
    allowed: bool
    group_id: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.decision_id, "decision_id")
        if self.principal_kind is not None:
            object.__setattr__(self, "principal_kind", PrincipalKind(self.principal_kind))
        if not isinstance(self.allowed, bool):
            raise ValueError("allowed must be a bool")
        _check_optional_id(self.group_id, "group_id")


@dataclass(frozen=True, kw_only=True)
class _ApprovalEvent(OversightEvent):
    action_hash: str

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.action_hash, str) or not _HASH.fullmatch(self.action_hash):
            raise ValueError("action_hash must be 'sha256:<64 lowercase hex>'")


@dataclass(frozen=True, kw_only=True)
class ApprovalRequested(_ApprovalEvent):
    kind: ClassVar[EventKind] = EventKind.APPROVAL_REQUESTED
    principal_kind: PrincipalKind | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.principal_kind is not None:
            object.__setattr__(self, "principal_kind", PrincipalKind(self.principal_kind))


@dataclass(frozen=True, kw_only=True)
class ApprovalGranted(_ApprovalEvent):
    kind: ClassVar[EventKind] = EventKind.APPROVAL_GRANTED
    approver_id: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.approver_id, "approver_id")


@dataclass(frozen=True, kw_only=True)
class ApprovalDenied(_ApprovalEvent):
    kind: ClassVar[EventKind] = EventKind.APPROVAL_DENIED
    approver_id: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.approver_id, "approver_id")


@dataclass(frozen=True, kw_only=True)
class Override(OversightEvent):
    """A human reversing the automated decision ``decision_id``."""

    kind: ClassVar[EventKind] = EventKind.OVERRIDE
    decision_id: str
    overrider_id: str
    direction: OverrideDirection

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.decision_id, "decision_id")
        _check_id(self.overrider_id, "overrider_id")
        object.__setattr__(self, "direction", OverrideDirection(self.direction))


@dataclass(frozen=True, kw_only=True)
class VerifierVerdict(OversightEvent):
    kind: ClassVar[EventKind] = EventKind.VERIFIER_VERDICT
    subject_id: str
    verifier_id: str
    predicted: Verdict

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.subject_id, "subject_id")
        _check_id(self.verifier_id, "verifier_id")
        object.__setattr__(self, "predicted", Verdict(self.predicted))


@dataclass(frozen=True, kw_only=True)
class GroundTruth(OversightEvent):
    """The independently established outcome for ``subject_id``.

    ``source`` is an external run (``run_ref`` required, same source) or
    ``HUMAN_REVIEW`` (``reviewer_id`` required); never ``AGENT_LOG``.
    """

    kind: ClassVar[EventKind] = EventKind.GROUND_TRUTH
    subject_id: str
    actual: Verdict
    source: EvidenceSource
    run_ref: ExternalRunRef | None = None
    reviewer_id: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.subject_id, "subject_id")
        object.__setattr__(self, "actual", Verdict(self.actual))
        object.__setattr__(self, "source", EvidenceSource(self.source))
        _reject_agent_source(self.source, "ground truth")
        if self.run_ref is not None:
            if not isinstance(self.run_ref, ExternalRunRef):
                raise ValueError("run_ref must be an ExternalRunRef")
            _reject_agent_source(self.run_ref.source, "ground truth")
            if self.run_ref.source is not self.source:
                raise ValueError("run_ref.source must match source")
        _check_optional_id(self.reviewer_id, "reviewer_id")
        if self.source is EvidenceSource.HUMAN_REVIEW:
            if self.reviewer_id is None:
                raise ValueError("HUMAN_REVIEW ground truth needs a reviewer_id")
        elif self.run_ref is None:
            raise ValueError("external ground truth needs a run_ref")


@dataclass(frozen=True, kw_only=True)
class Merge(OversightEvent):
    """``change_id`` merged at ``at`` (``merged_at``)."""

    kind: ClassVar[EventKind] = EventKind.MERGE
    change_id: str
    author_kind: AuthorKind
    author_id: str
    system_id: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.change_id, "change_id")
        object.__setattr__(self, "author_kind", AuthorKind(self.author_kind))
        _check_id(self.author_id, "author_id")
        _check_optional_id(self.system_id, "system_id")

    @property
    def merged_at(self) -> float:
        return self.at


@dataclass(frozen=True, kw_only=True)
class Rework(OversightEvent):
    """``change_id`` was reverted, fixed up or hot-fixed at ``at``."""

    kind: ClassVar[EventKind] = EventKind.REWORK
    change_id: str
    rework_kind: ReworkKind
    source: EvidenceSource

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.change_id, "change_id")
        object.__setattr__(self, "rework_kind", ReworkKind(self.rework_kind))
        object.__setattr__(self, "source", EvidenceSource(self.source))
        _reject_agent_source(self.source, "rework evidence")


@dataclass(frozen=True, kw_only=True)
class _TriggerEvent(OversightEvent):
    """Attributed to the agent (``agent_id``/``agent_system_id``) when known."""

    trigger_id: str
    agent_id: str | None = None
    agent_system_id: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.trigger_id, "trigger_id")
        if self.agent_id is not None:
            # Same canonical charset as principals (raises ValueError).
            Principal(self.agent_id, PrincipalKind.AGENT, system_id=self.agent_system_id)
        elif self.agent_system_id is not None:
            raise ValueError("agent_system_id needs an agent_id")

    def agent(self) -> Principal | None:
        if self.agent_id is None:
            return None
        return Principal(self.agent_id, PrincipalKind.AGENT, system_id=self.agent_system_id)


@dataclass(frozen=True, kw_only=True)
class Rollback(_TriggerEvent):
    kind: ClassVar[EventKind] = EventKind.ROLLBACK
    change_id: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.change_id, "change_id")


@dataclass(frozen=True, kw_only=True)
class VerificationFailed(_TriggerEvent):
    kind: ClassVar[EventKind] = EventKind.VERIFICATION_FAILED
    subject_id: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _check_id(self.subject_id, "subject_id")


_EVENT_TYPES: Mapping[EventKind, type[OversightEvent]] = {
    cls.kind: cls
    for cls in (
        DecisionObserved,
        ApprovalRequested,
        ApprovalGranted,
        ApprovalDenied,
        Override,
        VerifierVerdict,
        GroundTruth,
        Merge,
        Rework,
        Rollback,
        VerificationFailed,
    )
}


def event_from_dict(data: object) -> OversightEvent:
    """Strict inverse of :meth:`OversightEvent.to_dict` (raises ``ValueError``)."""
    if not isinstance(data, Mapping):
        raise ValueError("telemetry event must be a mapping")
    try:
        cls = _EVENT_TYPES[EventKind(str(data.get("kind")))]
    except ValueError as exc:
        raise ValueError(f"unknown telemetry event kind {data.get('kind')!r}") from exc
    names = {item.name for item in dataclasses.fields(cls)}
    payload = {key: value for key, value in data.items() if key != "kind"}
    if set(payload) - names:
        raise ValueError(f"unknown telemetry event keys: {sorted(set(payload) - names)}")
    if isinstance(payload.get("run_ref"), Mapping):
        payload["run_ref"] = ExternalRunRef.from_dict(payload["run_ref"])
    try:
        return cls(**payload)
    except TypeError as exc:
        raise ValueError(f"malformed {cls.kind.value} event: {exc}") from exc


# -- stores -------------------------------------------------------------

Listener = Callable[[OversightEvent], None]


@runtime_checkable
class TelemetryStore(Protocol):
    """Append-only event store. ``subscribe`` listeners run after each append."""

    def append(self, event: OversightEvent) -> None: ...

    def read_all(self) -> tuple[OversightEvent, ...]: ...

    def subscribe(self, listener: Listener) -> None: ...


def _admit(event: object) -> OversightEvent:
    if not isinstance(event, OversightEvent) or type(event) not in _EVENT_TYPES.values():
        raise TypeError("event must be an OversightEvent")
    if event.recorder_kind is PrincipalKind.AGENT:  # pragma: no cover - refused in __post_init__
        raise AgentTelemetryRejected("agents may not record oversight telemetry")
    return event


class _Listeners:
    def __init__(self) -> None:
        self._listeners: list[Listener] = []
        self._listeners_lock = threading.Lock()
        self.listener_failures = 0

    def subscribe(self, listener: Listener) -> None:
        if not callable(listener):
            raise TypeError("listener must be callable")
        with self._listeners_lock:
            self._listeners.append(listener)

    def _notify(self, event: OversightEvent) -> None:
        with self._listeners_lock:
            listeners = tuple(self._listeners)
        for listener in listeners:
            try:
                listener(event)
            except Exception as exc:
                logger.error("telemetry listener failed: %s", type(exc).__name__)
                with self._listeners_lock:
                    self.listener_failures += 1


class InMemoryTelemetryStore(_Listeners):
    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._events: list[OversightEvent] = []

    def append(self, event: OversightEvent) -> None:
        admitted = _admit(event)
        with self._lock:
            self._events.append(admitted)
        self._notify(admitted)

    def read_all(self) -> tuple[OversightEvent, ...]:
        with self._lock:
            return tuple(self._events)


class JSONLTelemetryStore(_Listeners):
    """One event per line, in the core ``AUDIT_LOG`` area (agents cannot
    write there). Append-only: ``flock`` + write + ``fsync``, rolled back on
    a partial write. Every line is parsed strictly on open; a malformed line
    fails the open (:class:`TelemetryStoreCorrupted`). A final line without
    a newline (a writer crashed mid-append) is moved to
    ``<path>.torn-<ns>`` in the same AUDIT_LOG directory and truncated, on
    open and before every append (:attr:`torn_tails` counts them);
    :meth:`read_all` skips an unterminated final line.

    TODO(control-plane-gap): lines are not signed or hash-chained (unlike
    receipts); tamper evidence relies on the AUDIT_LOG core protection.
    """

    def __init__(
        self,
        path: str | Path = DEFAULT_TELEMETRY_STORE_PATH,
        *,
        registry: ImmutableCoreRegistry = DEFAULT_IMMUTABLE_CORE,
    ) -> None:
        super().__init__()
        self._path = require_audit_store_path(path, registry)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.torn_tails = 0
        fcntl = importlib.import_module("fcntl")
        with self._lock, open(self._path, "a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                self._heal_tail(handle)
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        self.read_all()

    @property
    def path(self) -> Path:
        return self._path

    def _heal_tail(self, handle: Any) -> None:
        """Quarantine and truncate an unterminated final line (lock held)."""
        size = os.fstat(handle.fileno()).st_size
        if size == 0:
            return
        handle.seek(size - 1)
        if handle.read(1) == b"\n":
            return
        handle.seek(0)
        data = handle.read(size)
        cut = data.rfind(b"\n") + 1
        quarantine = self._path.with_name(f"{self._path.name}.torn-{time.time_ns()}")
        with open(quarantine, "xb") as torn:
            torn.write(data[cut:])
            torn.flush()
            os.fsync(torn.fileno())
        handle.truncate(cut)
        handle.flush()
        os.fsync(handle.fileno())
        self.torn_tails += 1
        logger.error("telemetry store torn tail quarantined to %s", quarantine.name)

    def append(self, event: OversightEvent) -> None:
        admitted = _admit(event)
        fcntl = importlib.import_module("fcntl")
        line = (
            json.dumps(admitted.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        with self._lock, open(self._path, "a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                self._heal_tail(handle)
                size = os.fstat(handle.fileno()).st_size
                try:
                    handle.write(line)
                    handle.flush()
                    # TODO(control-plane-gap): this fsync runs synchronously on the
                    # PDP decision path (record_decision / approval REQUESTED). A slow
                    # disk delays decide() without changing its result; an async or
                    # batched writer is unproven design work.
                    os.fsync(handle.fileno())
                except BaseException:
                    handle.truncate(size)
                    raise
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        self._notify(admitted)

    def read_all(self) -> tuple[OversightEvent, ...]:
        if not self._path.exists():
            return ()
        events: list[OversightEvent] = []
        with open(self._path, encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                if not line.endswith("\n"):
                    break  # unterminated tail: an append in progress (or torn)
                try:
                    events.append(event_from_dict(json.loads(line)))
                except (ValueError, TypeError, PermissionError) as exc:
                    raise TelemetryStoreCorrupted(f"telemetry line {number}: {exc}") from exc
        return tuple(events)


# -- recorder -----------------------------------------------------------


def _require_human(principal: object, label: str) -> Principal:
    if not isinstance(principal, Principal) or principal.kind is not PrincipalKind.HUMAN:
        raise AgentTelemetryRejected(f"{label} must be a HUMAN Principal")
    return principal


class TelemetryRecorder:
    """Builds and appends events on behalf of one HUMAN or SERVICE recorder
    (the harness, CI, a review bot). An AGENT recorder is refused."""

    def __init__(
        self,
        store: TelemetryStore,
        recorder: Principal,
        *,
        clock: Callable[[], float] = time.time,
        admin_attestor: AdminAttestor | None = None,
    ) -> None:
        """With *admin_attestor* every human-attributed record (approval
        denied, override, human ground truth) needs the human's verified
        single-use ``admin_credential=``."""
        from acgs_lite.control_plane.identity import checked_attestor

        self._attestor = checked_attestor(admin_attestor)
        if not isinstance(store, TelemetryStore):
            raise TypeError("store must implement TelemetryStore")
        if not isinstance(recorder, Principal):
            raise TypeError("recorder must be a Principal")
        if recorder.kind is PrincipalKind.AGENT:
            raise AgentTelemetryRejected(
                "agents may not record the telemetry that judges them (DGM/METR)"
            )
        self._store = store
        self._recorder = recorder
        self._clock = clock

    @property
    def store(self) -> TelemetryStore:
        return self._store

    def _human(self, principal: object, label: str, credential: str | None) -> Principal:
        human = _require_human(principal, label)
        if self._attestor is not None:
            self._attestor.require(
                human, credential, admin_only=False, error=AgentTelemetryRejected
            )
        return human

    @property
    def clock(self) -> Callable[[], float]:
        return self._clock

    def _common(self, at: float | None) -> dict[str, Any]:
        return {
            "at": float(self._clock()) if at is None else at,
            "recorded_by": self._recorder.id,
            "recorder_kind": self._recorder.kind,
        }

    def _append(self, event: OversightEvent) -> OversightEvent:
        self._store.append(event)
        return event

    def record_decision(
        self,
        decision_id: str,
        principal_kind: PrincipalKind | None,
        allowed: bool,
        *,
        group_id: str | None = None,
        at: float | None = None,
    ) -> OversightEvent:
        return self._append(
            DecisionObserved(
                decision_id=decision_id,
                principal_kind=principal_kind,
                allowed=allowed,
                group_id=group_id,
                **self._common(at),
            )
        )

    def record_approval_requested(
        self,
        action_hash: str,
        *,
        principal_kind: PrincipalKind | None = None,
        at: float | None = None,
    ) -> OversightEvent:
        return self._append(
            ApprovalRequested(
                action_hash=action_hash, principal_kind=principal_kind, **self._common(at)
            )
        )

    def record_approval_granted(
        self, action_hash: str, approver_id: str, *, at: float | None = None
    ) -> OversightEvent:
        return self._append(
            ApprovalGranted(action_hash=action_hash, approver_id=approver_id, **self._common(at))
        )

    def record_approval_denied(
        self,
        action_hash: str,
        approver: Principal,
        *,
        at: float | None = None,
        admin_credential: str | None = None,
    ) -> OversightEvent:
        """A human approver explicitly declined to approve *action_hash*."""
        human = self._human(approver, "approver", admin_credential)
        return self._append(
            ApprovalDenied(action_hash=action_hash, approver_id=human.id, **self._common(at))
        )

    def record_override(
        self,
        decision_id: str,
        overrider: Principal,
        direction: OverrideDirection | str,
        *,
        at: float | None = None,
        admin_credential: str | None = None,
    ) -> OversightEvent:
        """*overrider* (HUMAN) reversed the automated decision *decision_id*."""
        human = self._human(overrider, "overrider", admin_credential)
        return self._append(
            Override(
                decision_id=decision_id,
                overrider_id=human.id,
                direction=OverrideDirection(direction),
                **self._common(at),
            )
        )

    def record_verifier_verdict(
        self,
        subject_id: str,
        verifier_id: str,
        predicted: Verdict | str,
        *,
        at: float | None = None,
    ) -> OversightEvent:
        return self._append(
            VerifierVerdict(
                subject_id=subject_id,
                verifier_id=verifier_id,
                predicted=Verdict(predicted),
                **self._common(at),
            )
        )

    def record_ground_truth(
        self,
        subject_id: str,
        actual: Verdict | str,
        *,
        run_ref: ExternalRunRef | None = None,
        reviewer: Principal | None = None,
        at: float | None = None,
        admin_credential: str | None = None,
    ) -> OversightEvent:
        """Ground truth from an external run (*run_ref*) or a HUMAN *reviewer*."""
        if run_ref is not None and reviewer is not None:
            raise ValueError("pass run_ref or reviewer, not both")
        if reviewer is not None:
            human = self._human(reviewer, "reviewer", admin_credential)
            return self._append(
                GroundTruth(
                    subject_id=subject_id,
                    actual=Verdict(actual),
                    source=EvidenceSource.HUMAN_REVIEW,
                    reviewer_id=human.id,
                    **self._common(at),
                )
            )
        if not isinstance(run_ref, ExternalRunRef):
            raise ValueError("ground truth needs an ExternalRunRef or a HUMAN reviewer")
        return self._append(
            GroundTruth(
                subject_id=subject_id,
                actual=Verdict(actual),
                source=run_ref.source,
                run_ref=run_ref,
                **self._common(at),
            )
        )

    def record_merge(
        self,
        change_id: str,
        *,
        author_kind: AuthorKind | str,
        author_id: str,
        system_id: str | None = None,
        at: float | None = None,
    ) -> OversightEvent:
        return self._append(
            Merge(
                change_id=change_id,
                author_kind=AuthorKind(author_kind),
                author_id=author_id,
                system_id=system_id,
                **self._common(at),
            )
        )

    def record_rework(
        self,
        change_id: str,
        rework_kind: ReworkKind | str,
        *,
        source: EvidenceSource | str,
        at: float | None = None,
    ) -> OversightEvent:
        return self._append(
            Rework(
                change_id=change_id,
                rework_kind=ReworkKind(rework_kind),
                source=EvidenceSource(source),
                **self._common(at),
            )
        )

    @staticmethod
    def _agent_fields(agent: Principal | None) -> dict[str, Any]:
        if agent is None:
            return {}
        if not isinstance(agent, Principal) or agent.kind is not PrincipalKind.AGENT:
            raise ValueError("agent must be an AGENT Principal")
        return {"agent_id": agent.id, "agent_system_id": agent.system_id}

    def record_rollback(
        self,
        trigger_id: str,
        change_id: str,
        *,
        agent: Principal | None = None,
        at: float | None = None,
    ) -> OversightEvent:
        return self._append(
            Rollback(
                trigger_id=trigger_id,
                change_id=change_id,
                **self._agent_fields(agent),
                **self._common(at),
            )
        )

    def record_verification_failed(
        self,
        trigger_id: str,
        subject_id: str,
        *,
        agent: Principal | None = None,
        at: float | None = None,
    ) -> OversightEvent:
        return self._append(
            VerificationFailed(
                trigger_id=trigger_id,
                subject_id=subject_id,
                **self._agent_fields(agent),
                **self._common(at),
            )
        )


# -- metrics ------------------------------------------------------------


@dataclass(frozen=True)
class RateMetric:
    """``value = numerator / denominator``; ``None`` when the denominator is 0.

    ``immature``: merges younger than the rework window (excluded).
    ``unmatched``: overrides naming a decision that was never observed.
    """

    numerator: int
    denominator: int
    value: float | None
    immature: int = 0
    unmatched: int = 0


@dataclass(frozen=True)
class LatencyMetric:
    """Seconds from first APPROVAL_REQUESTED to quorum completion (the last
    recorded grant) or the first DENIED, whichever is earlier."""

    count: int
    p50_s: float | None
    p90_s: float | None
    p99_s: float | None
    max_s: float | None
    pending: int
    pre_approved: int = 0
    """Resolved at latency <= 0: approvals signed before the gate first saw
    the request (pre-collected); excluded from the percentiles."""


@dataclass(frozen=True)
class ConfusionMetric:
    """Positive class = ``fail`` (the verifier's job is to catch bad changes)."""

    tp: int
    fp: int
    fn: int
    tn: int
    precision: float | None
    recall: float | None
    unlabeled: int


def _ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def _percentile(sorted_values: list[float], q: float) -> float | None:
    """Nearest-rank percentile (no interpolation); ``None`` if empty."""
    if not sorted_values:
        return None
    rank = max(1, math.ceil(q * len(sorted_values)))
    return sorted_values[rank - 1]


def _check_segment(segment: object) -> Segment:
    if segment not in _SEGMENTS:
        raise ValueError("segment must be 'agent', 'human' or 'all'")
    return cast(Segment, segment)


def _in_window(at: float, since: float | None, until: float | None) -> bool:
    return (since is None or at >= since) and (until is None or at <= until)


_SEGMENT_KIND: Mapping[str, PrincipalKind] = {
    "agent": PrincipalKind.AGENT,
    "human": PrincipalKind.HUMAN,
}


class OversightMetrics:
    """Read-only queries over a :class:`TelemetryStore`. ``clock`` (same
    clock as the recorder) decides which merges are still immature."""

    def __init__(self, store: TelemetryStore, *, clock: Callable[[], float] = time.time) -> None:
        if not isinstance(store, TelemetryStore):
            raise TypeError("store must implement TelemetryStore")
        self._store = store
        self._clock = clock
        self._event_batch: tuple[OversightEvent, ...] | None = None

    def _read_all(self) -> tuple[OversightEvent, ...]:
        return self._store.read_all() if self._event_batch is None else self._event_batch

    def _events(self, kind: type[OversightEvent]) -> list[Any]:
        return [event for event in self._read_all() if type(event) is kind]

    def override_rate(
        self,
        segment: Segment = "all",
        *,
        since: float | None = None,
        until: float | None = None,
    ) -> RateMetric:
        """Overridden decisions / observed automated decisions.

        Segment = the kind of the principal the decision was about (SERVICE
        and unknown principals count only under ``"all"``). The unit is one
        dispatch: a tool call's ``tool.call`` decision and its per-path
        decisions share a ``group_id`` and count once (standalone decisions
        count by their own id). Dry runs record no decisions. A unit
        overridden twice counts once.
        """
        _check_segment(segment)
        units: dict[str, str] = {}
        first: dict[str, DecisionObserved] = {}
        for event in self._events(DecisionObserved):
            unit = event.group_id or event.decision_id
            units[event.decision_id] = unit
            first.setdefault(unit, event)
        in_scope = {
            unit
            for unit, event in first.items()
            if _in_window(event.at, since, until)
            and (segment == "all" or event.principal_kind is _SEGMENT_KIND[segment])
        }
        overridden: set[str] = set()
        unmatched = 0
        for event in self._events(Override):
            unit = units.get(event.decision_id)
            if unit is None:
                unmatched += 1
            elif unit in in_scope:
                overridden.add(unit)
        return RateMetric(
            numerator=len(overridden),
            denominator=len(in_scope),
            value=_ratio(len(overridden), len(in_scope)),
            unmatched=unmatched,
        )

    def approval_latency(
        self, segment: Segment = "all", *, since: float | None = None, until: float | None = None
    ) -> LatencyMetric:
        """Latency of requests in the window, segmented by requesting principal.

        Legacy requests without attribution and SERVICE requests count only
        under ``all``. Repeated requests retain the earliest attribution.
        """
        _check_segment(segment)
        requested: dict[str, ApprovalRequested] = {}
        for event in self._events(ApprovalRequested):
            if event.action_hash not in requested or event.at < requested[event.action_hash].at:
                requested[event.action_hash] = event
        # Grants are emitted for the earliest approval prefix satisfying both
        # quorum count and roles, so it completed at the latest (a T3 request
        # approved at +10s and +90s took 90s, not 10s). A denial resolves at
        # the first denial.
        completed: dict[str, float] = {}
        denied: dict[str, float] = {}
        for event in self._read_all():
            if not isinstance(event, (ApprovalGranted, ApprovalDenied)):
                continue
            request = requested.get(event.action_hash)
            if request is None or event.at < request.at:
                continue
            if isinstance(event, ApprovalGranted):
                completed[event.action_hash] = max(
                    event.at, completed.get(event.action_hash, event.at)
                )
            else:
                denied[event.action_hash] = min(event.at, denied.get(event.action_hash, event.at))
        resolved: dict[str, float] = dict(completed)
        for action_hash, at in denied.items():
            resolved[action_hash] = min(at, resolved.get(action_hash, at))
        latencies: list[float] = []
        pending = pre_approved = 0
        for action_hash, request in requested.items():
            start = request.at
            if not _in_window(start, since, until):
                continue
            if segment != "all" and request.principal_kind is not _SEGMENT_KIND[segment]:
                continue
            end = resolved.get(action_hash)
            if end is None:
                pending += 1
            elif end - start <= 0:
                pre_approved += 1
            else:
                latencies.append(end - start)
        latencies.sort()
        return LatencyMetric(
            count=len(latencies),
            p50_s=_percentile(latencies, 0.50),
            p90_s=_percentile(latencies, 0.90),
            p99_s=_percentile(latencies, 0.99),
            max_s=latencies[-1] if latencies else None,
            pending=pending,
            pre_approved=pre_approved,
        )

    def _author_kinds(self) -> dict[str, AuthorKind]:
        kinds: dict[str, AuthorKind] = {}
        for event in self._events(Merge):
            kinds.setdefault(event.change_id, event.author_kind)
        return kinds

    def verifier_precision_recall(
        self,
        verifier_id: str | None = None,
        *,
        segment: Segment = "all",
        since: float | None = None,
        until: float | None = None,
    ) -> ConfusionMetric:
        """Latest verdict per (verifier, subject) in the window vs the latest
        ground truth for the subject. Verdicts without ground truth count as
        ``unlabeled`` (never guessed). ``segment`` joins ``subject_id`` to a
        merged ``change_id``'s author kind; unmerged subjects appear only
        under ``"all"``."""
        _check_segment(segment)
        return self._verifier_metrics(since=since, until=until).get(
            (verifier_id, segment), ConfusionMetric(0, 0, 0, 0, None, None, 0)
        )

    def _verifier_metrics(
        self, *, since: float | None = None, until: float | None = None
    ) -> dict[tuple[str | None, Segment], ConfusionMetric]:
        """Build shared latest-evidence indexes and aggregate every segment once."""
        truths: dict[str, GroundTruth] = {}
        for truth in self._events(GroundTruth):
            current = truths.get(truth.subject_id)
            if current is None or truth.at >= current.at:
                truths[truth.subject_id] = truth
        verdicts: dict[tuple[str, str], VerifierVerdict] = {}
        for verdict in self._events(VerifierVerdict):
            if not _in_window(verdict.at, since, until):
                continue
            key = (verdict.verifier_id, verdict.subject_id)
            current_verdict = verdicts.get(key)
            if current_verdict is None or verdict.at >= current_verdict.at:
                verdicts[key] = verdict
        authors = self._author_kinds()
        counts: dict[tuple[str | None, Segment], list[int]] = {}
        for (verifier_id, subject_id), verdict in verdicts.items():
            truth = truths.get(subject_id)
            if truth is None:
                bucket = 4  # unlabeled
            elif verdict.predicted is Verdict.FAIL:
                bucket = 0 if truth.actual is Verdict.FAIL else 1  # tp / fp
            else:
                bucket = 2 if truth.actual is Verdict.FAIL else 3  # fn / tn
            segments: list[Segment] = ["all"]
            author = authors.get(subject_id)
            if author in (AuthorKind.AGENT, AuthorKind.HUMAN):
                segments.append(author.value)
            for segment in segments:
                for selected in (None, verifier_id):
                    counts.setdefault((selected, segment), [0, 0, 0, 0, 0])[bucket] += 1
        return {
            key: ConfusionMetric(
                tp=tp,
                fp=fp,
                fn=fn,
                tn=tn,
                precision=_ratio(tp, tp + fp),
                recall=_ratio(tp, tp + fn),
                unlabeled=unlabeled,
            )
            for key, (tp, fp, fn, tn, unlabeled) in counts.items()
        }

    def verifier_ids(self) -> tuple[str, ...]:
        return tuple(sorted({event.verifier_id for event in self._events(VerifierVerdict)}))

    def post_merge_rework_rate(
        self,
        window_s: float = DEFAULT_REWORK_WINDOW_S,
        segment: Segment = "all",
        *,
        since: float | None = None,
        until: float | None = None,
    ) -> RateMetric:
        """Merged changes reworked within ``window_s`` of merging / mature
        merged changes. Merges younger than ``window_s`` are excluded from
        the denominator and reported as ``immature``."""
        _check_segment(segment)
        if (
            isinstance(window_s, bool)
            or not isinstance(window_s, (int, float))
            or not math.isfinite(window_s)
            or window_s <= 0
        ):
            raise ValueError("window_s must be a positive finite number")
        now = float(self._clock())
        merges: dict[str, Merge] = {}
        for merge in self._events(Merge):
            current = merges.get(merge.change_id)
            if current is None or merge.at < current.at:
                merges[merge.change_id] = merge
        reworks: dict[str, list[float]] = {}
        for rework in self._events(Rework):
            reworks.setdefault(rework.change_id, []).append(rework.at)
        mature = reworked = immature = 0
        for change_id, merge in merges.items():
            if not _in_window(merge.at, since, until):
                continue
            if segment != "all" and merge.author_kind is not AuthorKind(segment):
                continue
            if now - merge.at < window_s:
                immature += 1
                continue
            mature += 1
            if any(merge.at <= at <= merge.at + window_s for at in reworks.get(change_id, ())):
                reworked += 1
        return RateMetric(
            numerator=reworked,
            denominator=mature,
            value=_ratio(reworked, mature),
            immature=immature,
        )

    def snapshot(self, *, rework_window_s: float = DEFAULT_REWORK_WINDOW_S) -> dict[str, Any]:
        """All four metrics (plus agent/human segments) as JSON-ready data."""
        now = float(self._clock())
        # A fresh query instance keeps concurrent callers independent and every
        # section on one immutable store version, with one JSONL parse.
        batch = OversightMetrics(self._store, clock=lambda: now)
        batch._event_batch = tuple(self._read_all())
        return batch._snapshot_data(rework_window_s=rework_window_s)

    def _snapshot_data(self, *, rework_window_s: float) -> dict[str, Any]:
        segments: tuple[Segment, ...] = ("all", "agent", "human")
        verifiers = self._verifier_metrics()
        empty = ConfusionMetric(0, 0, 0, 0, None, None, 0)
        return {
            "generated_at": float(self._clock()),
            "override_rate": {s: dataclasses.asdict(self.override_rate(s)) for s in segments},
            "approval_latency": {s: dataclasses.asdict(self.approval_latency(s)) for s in segments},
            "verifier": {
                "positive_class": Verdict.FAIL.value,
                "segments": {
                    s: dataclasses.asdict(verifiers.get((None, s), empty)) for s in segments
                },
                "by_verifier": {
                    vid: dataclasses.asdict(verifiers[(vid, "all")]) for vid in self.verifier_ids()
                },
            },
            "post_merge_rework": {
                "window_s": rework_window_s,
                "segments": {
                    s: dataclasses.asdict(self.post_merge_rework_rate(rework_window_s, s))
                    for s in segments
                },
            },
        }


# -- error-budget link --------------------------------------------------


class TelemetryAutonomyBridge:
    """Store listener: agent-attributed VERIFICATION_FAILED and ROLLBACK
    events feed :class:`AutonomyController`'s error budget, so exhaustion
    demotes without manual calls. Events without an ``agent_id`` are ignored.

    Do not also call ``record_failure`` for the same failures, or they count
    twice.
    """

    def __init__(self, autonomy: AutonomyController) -> None:
        if not isinstance(autonomy, AutonomyController):
            raise TypeError("autonomy must be an AutonomyController")
        self._autonomy = autonomy

    def attach(self, store: TelemetryStore) -> TelemetryAutonomyBridge:
        store.subscribe(self)
        return self

    def __call__(self, event: OversightEvent) -> None:
        if not isinstance(event, (VerificationFailed, Rollback)):
            return
        agent = event.agent()
        if agent is None:
            return
        if isinstance(event, Rollback):
            self._autonomy.record_rollback(agent)
        else:
            self._autonomy.record_failure(agent, FailureKind.VERIFICATION_FAILED)
