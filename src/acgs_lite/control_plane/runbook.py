"""Machine-readable runbooks: the only pre-authorisation path to tier T1.

A T1 action is reversible, narrow and covered by an *approved* runbook. The
runbook is policy: it lives under ``control-plane/runbooks/**`` (immutable
core, ``POLICY`` category), only a HUMAN holding the runbook's
``required_approver_role`` may approve it, and the approval records the
runbook's hash. Before every T1 execution the dispatcher re-validates, in
:meth:`RunbookRegistry.check_execution`: the caller-cited hash equals the
approved hash (and, for file-backed runbooks, the file on disk still hashes
to it), the runbook is not stale, its scope selector matches the tool, every
path and the principal, the blast radius is within ``max_blast_radius``, the
rate limit has room (atomic check-and-consume) and no stop condition has
tripped. Anything else denies.

Evidence: Replit -- an agent destroyed production state during a freeze that
existed only as an instruction; a runbook is a harness-checked artefact with
an owner, a rollback command and stop conditions, not a prompt. STOP -- the
scope selector may never reach the immutable core (validated at load and per
path at execution), so a runbook cannot pre-authorise editing the sandbox
flag or the evaluator. Merge-capable tools are never covered by a runbook
(METR: grader != merger), whatever the tool globs say.

Approval (Phase 5 hardening) is a PDP decision: a HUMAN requester submits
``runbook.approve`` (tier T2) with a :class:`~.approvals.SignedApproval` over
its action hash (which binds the runbook hash) from a key registered in the
:class:`~.approvals.ApprovalAuthority`; the attested approver must hold the
runbook's ``required_approver_role`` as a capability in
:class:`~.roles.RoleAssignments` (never the self-asserted
``Principal.roles``) and must not be the owner. The PDP consumes the approval
and emits the decision receipt to its bound ledger.

The schema is a pydantic v2 model; :func:`runbook_json_schema` exports it and
``control-plane/runbook.schema.json`` is the checked-in copy (a test asserts
equality -- regenerate it when pydantic is bumped, the generator output can
change between minor versions).
"""

from __future__ import annotations

import collections
import fnmatch
import hashlib
import json
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

from acgs_lite.control_plane.evidence import ExternalRunRef, ExternalRunVerifier
from acgs_lite.control_plane.iam import _overlapping_core_pattern
from acgs_lite.control_plane.immutable_core import (
    CoreCategory,
    ImmutableCoreRegistry,
    compile_glob,
)
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.tiers import ActionTier

if TYPE_CHECKING:
    from acgs_lite.control_plane.approvals import SignedApproval
    from acgs_lite.control_plane.context import DecisionRequest
    from acgs_lite.control_plane.pdp import PolicyDecisionPoint
    from acgs_lite.control_plane.roles import RoleAssignments

__all__ = [
    "DEFAULT_MAX_RUNBOOK_AGE_DAYS",
    "RUNBOOK_HASH_DOMAIN",
    "BreakerOpenStop",
    "BudgetFractionStop",
    "ErrorRateStop",
    "ExitCodePredicate",
    "ExternalRunPredicate",
    "MaxFailuresStop",
    "RateLimit",
    "Runbook",
    "RunbookDenied",
    "RunbookRegistry",
    "RunbookRejected",
    "ScopeSelector",
    "StopSignals",
    "check_runbook_scope",
    "is_stale",
    "load_runbook_file",
    "parse_runbook",
    "runbook_hash",
    "runbook_json_schema",
]

RUNBOOK_HASH_DOMAIN = b"acgs-control-plane-runbook-v1\x00"
RUNBOOK_APPROVE_ACTION = "runbook.approve"
RUNBOOK_APPROVAL_TIER = ActionTier.T2
# TODO(control-plane-gap): 90 days of runbook validity is a design inference
# (no primary source for how often a runbook must be re-exercised);
# configurable per RunbookRegistry.
DEFAULT_MAX_RUNBOOK_AGE_DAYS = 90

_ID = r"^[A-Za-z0-9._-]{1,128}$"
_PRINCIPAL_ID = r"^[A-Za-z0-9._@:-]{1,256}$"
_ROLE = r"^[A-Za-z0-9._:-]{1,128}$"
_GLOB = r"^[^\x00-\x1f\x7f]{1,512}$"
_ARG = r"^[^\x00]{1,4096}$"

_Id = Annotated[StrictStr, Field(pattern=_ID)]
_PrincipalId = Annotated[StrictStr, Field(pattern=_PRINCIPAL_ID)]
_Glob = Annotated[StrictStr, Field(pattern=_GLOB)]
_Fraction = Annotated[float, Field(gt=0, le=1, allow_inf_nan=False, strict=True)]


class RunbookRejected(ValueError):
    """A runbook (or its approval) is malformed or not acceptable."""


class RunbookDenied(PermissionError):
    """A T1 execution under a runbook is not authorised."""


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ScopeSelector(_Frozen):
    """What a runbook may touch: tool-name globs (``fnmatch``), repo path globs
    (root-anchored repo-glob semantics, see :func:`~.immutable_core.compile_glob`)
    and the principals (canonical ids) and/or system cohorts it is for."""

    tools: Annotated[tuple[_Glob, ...], Field(min_length=1)]
    paths: Annotated[tuple[_Glob, ...], Field(min_length=1)]
    principals: tuple[_PrincipalId, ...] = ()
    system_ids: tuple[_PrincipalId, ...] = ()
    allow_pathless: bool = False
    """A tool call that names no path is outside the scope unless this is set."""


class RateLimit(_Frozen):
    max_executions: Annotated[StrictInt, Field(ge=1)]
    per_seconds: Annotated[StrictInt, Field(ge=1)]


class ExternalRunPredicate(_Frozen):
    """Success = a run of *workflow* at *provider* validated by the run verifier."""

    kind: Literal["external_run"]
    provider: _Id
    workflow: Annotated[StrictStr, Field(pattern=r"^[A-Za-z0-9._/@+-]{1,256}$")]


class ExitCodePredicate(_Frozen):
    kind: Literal["exit_code"]
    equals: StrictInt


class MaxFailuresStop(_Frozen):
    """Stop after *count* failed executions under this runbook."""

    kind: Literal["max_failures"]
    count: Annotated[StrictInt, Field(ge=1)]


class ErrorRateStop(_Frozen):
    """Stop once failures/executions >= *max_rate* (after *min_samples*)."""

    kind: Literal["error_rate"]
    max_rate: _Fraction
    min_samples: Annotated[StrictInt, Field(ge=1)]


class BudgetFractionStop(_Frozen):
    """Stop once the principal has used >= *max_fraction* of its iteration budget."""

    kind: Literal["budget_fraction"]
    max_fraction: _Fraction


class BreakerOpenStop(_Frozen):
    """Stop while the dispatching trigger's circuit breaker is not CLOSED."""

    kind: Literal["breaker_open"]


SuccessPredicate = Annotated[ExternalRunPredicate | ExitCodePredicate, Field(discriminator="kind")]
StopCondition = Annotated[
    MaxFailuresStop | ErrorRateStop | BudgetFractionStop | BreakerOpenStop,
    Field(discriminator="kind"),
]


class Runbook(_Frozen):
    """One approved, machine-checkable procedure. Every field is required."""

    runbook_id: _Id
    version: Annotated[StrictInt, Field(ge=1)]
    action_tier: ActionTier
    scope_selector: ScopeSelector
    max_blast_radius: Annotated[StrictInt, Field(ge=1)]
    rate_limit: RateLimit
    required_approver_role: Annotated[StrictStr, Field(pattern=_ROLE)]
    rollback_command: Annotated[
        tuple[Annotated[StrictStr, Field(pattern=_ARG)], ...], Field(min_length=1)
    ]
    """argv list, never a shell string."""
    success_predicate: SuccessPredicate
    stop_conditions: Annotated[tuple[StopCondition, ...], Field(min_length=1)]
    owner: _PrincipalId
    """Canonical id of the accountable human."""
    last_tested: date


def runbook_json_schema() -> dict[str, Any]:
    """JSON Schema of :class:`Runbook` (checked in as ``control-plane/runbook.schema.json``)."""
    schema = Runbook.model_json_schema()
    schema["$id"] = "https://acgs.ai/schemas/control-plane/runbook.schema.json"
    return schema


def parse_runbook(data: object) -> Runbook:
    """Strict parse; any schema violation raises :class:`RunbookRejected`."""
    if isinstance(data, Runbook):
        return data
    if not isinstance(data, Mapping):
        raise RunbookRejected("runbook must be a mapping")
    try:
        return Runbook.model_validate(dict(data))
    except ValidationError as exc:
        raise RunbookRejected(f"invalid runbook: {exc.error_count()} error(s): {exc}") from exc


def _canonical(runbook: Runbook) -> str:
    return json.dumps(
        runbook.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def runbook_hash(runbook: Runbook) -> str:
    """``sha256:<hex>`` over canonical JSON (domain ``acgs-control-plane-runbook-v1``)."""
    if not isinstance(runbook, Runbook):
        raise TypeError("runbook must be a Runbook")
    digest = hashlib.sha256(RUNBOOK_HASH_DOMAIN + _canonical(runbook).encode("utf-8"))
    return "sha256:" + digest.hexdigest()


def check_runbook_scope(runbook: Runbook, registry: ImmutableCoreRegistry) -> None:
    """Reject a scope selector that could reach the immutable core.

    Path globs are checked for literal-prefix overlap with every root-anchored
    core pattern (``**`` and ``*``-prefixed globs overlap everything);
    unanchored core patterns (``**/.env*``) are enforced per path at
    execution (:meth:`RunbookRegistry.check_execution`).
    """
    selector = runbook.scope_selector
    if not selector.principals and not selector.system_ids:
        raise RunbookRejected("scope_selector must name principals or system_ids")
    if selector.allow_pathless and any(ch in tool for tool in selector.tools for ch in "*?[]"):
        raise RunbookRejected("allow_pathless requires exact tool names (no glob selectors)")
    for glob in selector.paths:
        cleaned = glob[2:] if glob.startswith("./") else glob
        if cleaned.startswith("/") or "\\" in cleaned or ".." in cleaned.split("/"):
            raise RunbookRejected(f"scope path glob must be relative and inside root: {glob!r}")
        overlap = _overlapping_core_pattern(cleaned, registry)
        if overlap is not None:
            raise RunbookRejected(f"scope path glob {glob!r} overlaps immutable core {overlap!r}")


def is_stale(
    runbook: Runbook, today: date, max_age_days: int = DEFAULT_MAX_RUNBOOK_AGE_DAYS
) -> bool:
    """True when *runbook* was last tested more than *max_age_days* ago (or in the future)."""
    age = (today - runbook.last_tested).days
    return age > max_age_days or age < 0


def load_runbook_file(path: str | Path, registry: ImmutableCoreRegistry) -> Runbook:
    """Load a JSON/YAML runbook from a ``POLICY`` core path and validate its scope."""
    raw = str(path)
    category = registry.classify(raw)
    if category is not CoreCategory.POLICY:
        raise RunbookRejected(f"runbook file {raw!r} must be immutable-core POLICY, got {category}")
    candidate = Path(raw)
    if not candidate.is_absolute() and registry.repo_root is not None:
        candidate = Path(registry.repo_root) / candidate
    try:
        text = candidate.read_text(encoding="utf-8")
        data = json.loads(text) if candidate.suffix == ".json" else yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise RunbookRejected(f"runbook file unreadable: {type(exc).__name__}") from exc
    runbook = parse_runbook(data)
    check_runbook_scope(runbook, registry)
    return runbook


@dataclass(frozen=True)
class StopSignals:
    """Harness-observed state the stop conditions are evaluated against."""

    breaker_open: bool = False
    budget_fraction: float | None = None
    """Fraction of the principal's iteration budget already used (None = unknown)."""


@dataclass
class _Approved:
    runbook: Runbook
    digest: str
    approved_by: str
    source_path: Path | None
    executions: dict[str, collections.deque[float]]
    """Rate-limit windows keyed by canonical principal id."""
    successes: int = 0
    failures: int = 0


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _require_human(principal: object, label: str) -> Principal:
    if not isinstance(principal, Principal) or principal.kind is not PrincipalKind.HUMAN:
        raise RunbookRejected(f"{label} must be a HUMAN principal (agents cannot approve)")
    return principal


def predicate_satisfied(
    predicate: SuccessPredicate, value: object, run_verifier: ExternalRunVerifier | None
) -> bool:
    """``exit_code``: an int result, a mapping's ``exit_code`` or a
    ``returncode`` attribute must equal ``equals``. ``external_run``: the
    result must be (or carry under ``external_run``) an ExternalRunRef of
    ``provider`` that *run_verifier* validates."""
    if isinstance(predicate, ExitCodePredicate):
        code: object = value
        if isinstance(value, Mapping):
            code = value.get("exit_code")
        elif not isinstance(value, int):
            code = getattr(value, "returncode", getattr(value, "exit_code", None))
        return isinstance(code, int) and not isinstance(code, bool) and code == predicate.equals
    if isinstance(predicate, ExternalRunPredicate):
        # TODO(control-plane-gap): ExternalRunRef carries no workflow, so the
        # predicate's workflow is enforced only by verifiers that allow-list
        # workflows (GitHubActionsRunVerifier).
        raw = value.get("external_run") if isinstance(value, Mapping) else value
        ref = ExternalRunRef.from_dict(raw) if isinstance(raw, Mapping) else raw
        if not isinstance(ref, ExternalRunRef) or ref.provider != predicate.provider:
            return False
        if run_verifier is None:
            return False
        return run_verifier.validate(ref).valid is True
    return False


class RunbookRegistry:
    """Harness-side store of approved runbooks (the agent never holds it)."""

    def __init__(
        self,
        registry: ImmutableCoreRegistry,
        *,
        pdp: PolicyDecisionPoint,
        roles: RoleAssignments,
        max_runbook_age_days: int = DEFAULT_MAX_RUNBOOK_AGE_DAYS,
        clock: Callable[[], float] = time.monotonic,
        today: Callable[[], date] = _today,
    ) -> None:
        from acgs_lite.control_plane.pdp import PolicyDecisionPoint
        from acgs_lite.control_plane.roles import RoleAssignments

        if not isinstance(registry, ImmutableCoreRegistry):
            raise TypeError("registry must be an ImmutableCoreRegistry")
        if not isinstance(pdp, PolicyDecisionPoint) or pdp.approval_gate is None:
            raise TypeError("pdp must be a PolicyDecisionPoint with an ApprovalGate")
        if pdp.registry != registry:
            raise ValueError("pdp and runbook registry must use the same immutable-core registry")
        if type(roles) is not RoleAssignments:
            raise TypeError("roles must be a RoleAssignments")
        self._pdp = pdp
        self._roles = roles
        if (
            isinstance(max_runbook_age_days, bool)
            or not isinstance(max_runbook_age_days, int)
            or max_runbook_age_days < 0
        ):
            raise ValueError("max_runbook_age_days must be an int >= 0")
        self._registry = registry
        self._max_age = max_runbook_age_days
        self._clock = clock
        self._today = today
        self._lock = threading.Lock()
        self._approved: dict[str, _Approved] = {}

    @property
    def registry(self) -> ImmutableCoreRegistry:
        return self._registry

    def approval_request(
        self,
        requester: Principal,
        runbook: Runbook | Mapping[str, Any],
        approvals: Sequence[SignedApproval] = (),
    ) -> DecisionRequest:
        """The ``runbook.approve`` request; approvers sign its action hash."""
        from acgs_lite.control_plane.context import DecisionRequest

        parsed = parse_runbook(runbook)
        return DecisionRequest(
            principal=requester,
            action=RUNBOOK_APPROVE_ACTION,
            resource=parsed.runbook_id,
            tier=RUNBOOK_APPROVAL_TIER,
            attributes={
                "runbook_hash": runbook_hash(parsed),
                "runbook_owner": parsed.owner,
                "required_role": parsed.required_approver_role,
            },
            approvals=tuple(approvals),
        )

    def approval_hash(self, requester: Principal, runbook: Runbook | Mapping[str, Any]) -> str:
        from acgs_lite.control_plane.action_hash import action_hash

        return action_hash(self.approval_request(requester, runbook))

    def approve(
        self,
        requester: Principal,
        runbook: Runbook | Mapping[str, Any],
        *,
        approvals: Sequence[SignedApproval],
        source_path: str | Path | None = None,
    ) -> str:
        """Approve *runbook* through the PDP; returns its hash.

        *requester* is the HUMAN submitting it. *approvals* must include a
        signed approval of :meth:`approval_hash` by a registered human (not the
        requester, not the owner) holding ``required_approver_role`` in the
        role assignments. The PDP consumes it and receipts the decision.
        With *source_path* the runbook must be the file's content, and every
        execution re-reads and re-hashes the file.
        """
        human = _require_human(requester, "requester")
        parsed = parse_runbook(runbook)
        check_runbook_scope(parsed, self._registry)
        digest = runbook_hash(parsed)
        resolved: Path | None = None
        if source_path is not None:
            on_disk = load_runbook_file(source_path, self._registry)
            if runbook_hash(on_disk) != digest:
                raise RunbookRejected("runbook does not match its source file")
            resolved = self._resolve(source_path)
        request = self.approval_request(human, parsed, tuple(approvals))
        gate = self._pdp.approval_gate
        if gate is None:  # pragma: no cover - refused at construction
            raise RunbookRejected("no approval gate")
        quorum = gate.evaluate(request, request.approvals, record_request=False)
        owner = parsed.owner.casefold()
        qualified = [
            approver
            for approver in quorum.approvers
            if approver.canonical_id != owner
            and self._roles.has_capability(approver, parsed.required_approver_role)
        ]
        if not quorum.satisfied or not qualified:
            raise RunbookRejected(
                "runbook approval needs a signed approval from a registered human "
                f"(not the owner) holding role {parsed.required_approver_role!r}"
            )
        decision, decided = self._pdp._decide_attested(request)
        if not decision.allowed or decided is None:
            raise RunbookRejected(f"PDP denied runbook approval: {decision.reason}")
        with self._lock:
            self._approved[parsed.runbook_id] = _Approved(
                parsed, digest, qualified[0].id, resolved, {}
            )
        return digest

    def _resolve(self, path: str | Path) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute() and self._registry.repo_root is not None:
            candidate = Path(self._registry.repo_root) / candidate
        return candidate

    def revoke(self, admin: Principal, runbook_id: str) -> bool:
        _require_human(admin, "admin")
        with self._lock:
            return self._approved.pop(runbook_id, None) is not None

    def approved(self, runbook_id: str) -> tuple[Runbook, str] | None:
        with self._lock:
            entry = self._approved.get(runbook_id)
            return None if entry is None else (entry.runbook, entry.digest)

    def outcome_succeeded(
        self, runbook_id: str, value: object, run_verifier: ExternalRunVerifier | None
    ) -> bool:
        """Evaluate the approved runbook's ``success_predicate`` against what
        the tool returned. Missing or unverifiable evidence is a failure."""
        approved = self.approved(runbook_id)
        if approved is None:
            return False
        try:
            return predicate_satisfied(approved[0].success_predicate, value, run_verifier)
        except Exception:
            return False

    def record_outcome(self, runbook_id: str, *, success: bool) -> None:
        """Harness: count one execution outcome (feeds the stop conditions)."""
        with self._lock:
            entry = self._approved.get(runbook_id)
            if entry is None:
                return
            if success:
                entry.successes += 1
            else:
                entry.failures += 1

    def check_execution(
        self,
        runbook_id: object,
        cited_hash: object,
        *,
        tool_name: str,
        paths: Sequence[str],
        principal: Principal,
        blast_radius: int,
        signals: StopSignals | None = None,
        consume: bool = True,
        merge_capable: bool = False,
    ) -> Runbook:
        """Validate a T1 execution and (if *consume*) spend one rate-limit slot.

        Raises :class:`RunbookDenied` with the first failing reason.
        """
        if not isinstance(runbook_id, str) or not isinstance(cited_hash, str):
            raise RunbookDenied("T1 execution requires runbook_id and runbook_hash")
        with self._lock:
            entry = self._approved.get(runbook_id)
            if entry is None:
                raise RunbookDenied(f"runbook {runbook_id!r} is not approved")
            if cited_hash != entry.digest:
                raise RunbookDenied("runbook hash does not match the approved hash (tampered?)")
            runbook = entry.runbook
            source = entry.source_path
        if source is not None:
            try:
                on_disk = load_runbook_file(source, self._registry)
            except RunbookRejected as exc:
                raise RunbookDenied(f"runbook file failed re-validation: {exc}") from exc
            if runbook_hash(on_disk) != entry.digest:
                raise RunbookDenied("runbook file changed since approval (tampered)")
        if merge_capable:
            raise RunbookDenied("merge-capable tools are never covered by a runbook")
        if runbook.action_tier is not ActionTier.T1:
            raise RunbookDenied(f"runbook is {runbook.action_tier.name}, not a T1 runbook")
        try:
            today = self._today()
        except Exception as exc:
            raise RunbookDenied(f"date unavailable: {type(exc).__name__}") from exc
        if is_stale(runbook, today, self._max_age):
            raise RunbookDenied(
                f"runbook last tested {runbook.last_tested.isoformat()} is stale "
                f"(> {self._max_age} days)"
            )
        self._check_scope(runbook, tool_name, paths, principal)
        if isinstance(blast_radius, bool) or not isinstance(blast_radius, int):
            raise RunbookDenied("blast radius must be an int")
        if blast_radius > runbook.max_blast_radius:
            raise RunbookDenied(
                f"blast radius {blast_radius} exceeds runbook max {runbook.max_blast_radius}"
            )
        with self._lock:
            current = self._approved.get(runbook_id)
            if current is not entry:
                raise RunbookDenied("runbook approval changed during validation")
            self._check_stop(entry, signals if signals is not None else StopSignals())
            try:
                now = float(self._clock())
            except Exception as exc:
                raise RunbookDenied(f"clock unavailable: {type(exc).__name__}") from exc
            horizon = now - runbook.rate_limit.per_seconds
            window = entry.executions.setdefault(principal.canonical_id, collections.deque())
            while window and window[0] <= horizon:
                window.popleft()
            if len(window) >= runbook.rate_limit.max_executions:
                raise RunbookDenied(
                    f"runbook rate limit {runbook.rate_limit.max_executions}/"
                    f"{runbook.rate_limit.per_seconds}s exceeded"
                )
            if consume:
                window.append(now)
        return runbook

    def _check_scope(
        self, runbook: Runbook, tool_name: str, paths: Iterable[str], principal: Principal
    ) -> None:
        selector = runbook.scope_selector
        if not any(fnmatch.fnmatchcase(tool_name, glob) for glob in selector.tools):
            raise RunbookDenied(f"tool {tool_name!r} is outside the runbook scope")
        principal_ok = principal.canonical_id in {p.casefold() for p in selector.principals} or (
            principal.system_id is not None
            and principal.system_id in {s.casefold() for s in selector.system_ids}
        )
        if not principal_ok:
            raise RunbookDenied(f"principal {principal.id!r} is outside the runbook scope")
        paths = list(paths)
        if not paths and not selector.allow_pathless:
            raise RunbookDenied("a path-less call is outside the runbook scope (allow_pathless)")
        regexes = [compile_glob(g[2:] if g.startswith("./") else g) for g in selector.paths]
        for path in paths:
            normalized = self._registry.normalize(path)
            if normalized is None or self._registry.is_core(normalized):
                raise RunbookDenied(f"path {path!r} is immutable core (never runbook scope)")
            if not any(regex.fullmatch(normalized) for regex in regexes):
                raise RunbookDenied(f"path {path!r} is outside the runbook scope")

    @staticmethod
    def _check_stop(entry: _Approved, signals: StopSignals) -> None:
        total = entry.successes + entry.failures
        for condition in entry.runbook.stop_conditions:
            if isinstance(condition, MaxFailuresStop) and entry.failures >= condition.count:
                raise RunbookDenied(f"stop condition max_failures({condition.count}) tripped")
            if (
                isinstance(condition, ErrorRateStop)
                and total >= condition.min_samples
                and entry.failures / total >= condition.max_rate
            ):
                raise RunbookDenied(f"stop condition error_rate({condition.max_rate}) tripped")
            if isinstance(condition, BudgetFractionStop) and (
                signals.budget_fraction is None or signals.budget_fraction >= condition.max_fraction
            ):
                raise RunbookDenied(
                    f"stop condition budget_fraction({condition.max_fraction}) tripped "
                    "(or budget unknown)"
                )
            if isinstance(condition, BreakerOpenStop) and signals.breaker_open:
                raise RunbookDenied("stop condition breaker_open tripped")
