"""The tool-call chokepoint: every agent tool invocation goes through here.

Registration is declarative and checked against the tool's real signature:
every parameter must be declared as a *path* parameter, an *opaque* parameter
or the *command* parameter of a shell-like tool. Tools with ``*args``,
``**kwargs``, positional-only or undeclared parameters are refused, and calls
with argument names the signature does not have are denied. Path detection is
therefore not a guess based on argument names.

For one call the dispatcher snapshots the arguments once (``deepcopy``; the
same copy is authorised and passed to the tool, closing the TOCTOU window) and
then requires, in order:

1. well-formed arguments: declared path parameters hold a string or a flat
   list of strings; every other value is built from str/bytes/numbers/None and
   lists/tuples/sets/frozensets/dicts. Only exact built-in types are accepted;
   subclasses and custom mappings are denied before copying or traversal;
2. shell-like tools (``command_param``) are human-only; for humans, no
   command token may resolve to an immutable-core path;
3. for write tools: no *directory-like* path outside the scratch prefixes
   while the registry has unanchored (``**/``) patterns, because deleting a
   parent directory deletes the core files beneath it;
4. PDP permits for a ``tool.call`` decision (``attributes["paths"]`` = the
   declared paths plus every string leaf, at any depth, that classifies as
   core) and for one ``file.write`` (or ``file.read`` for read-only tools)
   decision per such path;
5. repository permissions: ``RepositoryPermissions.can_write`` for every path
   a write tool receives (an independent second layer; it is required).

Phase 3 adds harness-side pre-checks, all before step 1 and none operable by
the agent: the :class:`~.killswitch.KillSwitch` (engaged or unreadable ->
deny everything, T0 included); an optional short-TTL scoped credential
(``require_credential=True``: a token from the harness's
:class:`~.credentials.CredentialIssuer` whose principal matches and whose
scopes include ``tool:<name>``; Phase 6a: with a directory-backed issuer the
credential is verified first, its signed kind and system_id must equal the
passed principal's, and they are the ones every later check sees); resource budgets (one iteration charged per
dispatch; exhausted -> deny, or with an autonomy controller -> demotion); and
the :class:`~.autonomy.AutonomyController` level (P0_ONLY -> read-only T0
tools only, SUSPENDED -> nothing). T2/T3 tools need an
:class:`~.approvals.ApprovalGate` on the PDP (refused at construction and
registration otherwise); approvals are bound to the ``tool.call`` action hash,
which covers the arguments digest, and are consumed right before the tool
runs. Host-asserted ``approvers=`` are ignored by a gated PDP.

Phase 4: with ``breaker=`` (a :class:`~.breaker.TriggerCircuitBreaker` with
a :class:`~.breaker.TriggerRegistry`) every non-HUMAN dispatch must name a
``trigger_id`` bound to that principal or its system cohort (taken from the
credential session when it carries one) and is denied while that trigger --
or, with cohort suspension, any trigger of its cohort -- is not CLOSED.
Dry runs (:meth:`GovernedToolDispatcher.authorize_without_consuming`) check
the breaker without spending a half-open probe and record no telemetry.
:meth:`GovernedToolDispatcher.action_hash_for` on a T2+ tool tells the
approval gate a quorum was requested (approval-latency telemetry).

Phase 5: a tool registered with ``profile=`` (an
:class:`~.tier_policy.ActionProfile` factory, host code over the snapshotted
arguments) gets its tier *computed per call* by
:func:`~.tier_policy.classify_tier` -- irreversibility and blast radius, never
confidence. ``tool_tiers`` then only raises the computed tier (a floor), and
a caller-supplied ``tier=`` lower than the computed one is refused (it is
otherwise ignored). With ``runbooks=`` every T1 dispatch must cite an
approved runbook (``runbook_id`` + ``runbook_hash``), validated before the
tool runs (hash, staleness, scope, blast radius, rate limit, stop
conditions); each T1 execution is queued for post-hoc human review
(``review_queue=``). A non-human T3 dispatch needs a backup run
(``backup_run=``) validated by ``run_verifier=``. With ``ownership=`` every
write must name the ``change_id`` its writer owns and stay inside that
change's worktree (and branch, via ``branch_param``). With
``incident_lock=`` a declared incident denies every write-class dispatch by
anyone but the lock holder (humans included). Merge/approve actions by
non-humans are forbidden by INV-AGENT-NO-MERGE.

TODO(control-plane-gap): tools registered without ``profile=`` still take
their tier from the host's static ``tool_tiers`` map, and without
``runbooks=`` a legacy static-T1 tool needs no runbook (Phase 1-4
compatibility); :func:`~acgs_lite.control_plane.facade.build_control_plane`
always configures runbooks.

Any failure raises :class:`ToolDenied` and the tool function is never called.
Tools absent from ``tool_tiers`` are tier T2 and writers even if listed as
read-only (unless registered with a profile). A directory argument that
contains a root-anchored core pattern (``cwd="."``, ``cwd="src"``) is itself
core.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import os
import posixpath
import re
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from acgs_lite.control_plane.action_hash import arguments_digest
from acgs_lite.control_plane.approvals import ApprovalGate, SignedApproval
from acgs_lite.control_plane.autonomy import AutonomyController, AutonomyLevel, FailureKind
from acgs_lite.control_plane.breaker import BreakerState, TriggerCircuitBreaker, valid_trigger_id
from acgs_lite.control_plane.budgets import BudgetLedger
from acgs_lite.control_plane.change_ownership import (
    AGENT_NO_MERGE_ACTIONS,
    ChangeOwnershipRegistry,
    OwnershipDenied,
)
from acgs_lite.control_plane.context import DecisionRequest
from acgs_lite.control_plane.credentials import (
    CredentialInvalid,
    CredentialIssuer,
    ScopedCredential,
)
from acgs_lite.control_plane.evidence import (
    EvidenceSource,
    ExternalRunRef,
    ExternalRunVerifier,
    RunValidation,
    _attests_digest,
)
from acgs_lite.control_plane.iam import RepositoryPermissions
from acgs_lite.control_plane.incident import IncidentMutationLock
from acgs_lite.control_plane.invariants import requested_by_problem
from acgs_lite.control_plane.killswitch import KillSwitch
from acgs_lite.control_plane.pdp import Decision, PolicyDecisionPoint
from acgs_lite.control_plane.principal import Principal, PrincipalKind, canonical_principal_id
from acgs_lite.control_plane.runbook import RunbookDenied, RunbookRegistry, StopSignals
from acgs_lite.control_plane.tier_policy import (
    DEFAULT_NARROW_MAX_BLAST_RADIUS,
    ActionProfile,
    ProfileFactory,
    ReviewQueue,
    classify_tier,
    t3_execution_problem,
)
from acgs_lite.control_plane.tiers import ActionTier

__all__ = [
    "DEFAULT_SCRATCH_PREFIXES",
    "GovernedToolDispatcher",
    "ToolDenied",
    "backup_subject_digest",
    "opaque_ref",
    "ToolResult",
]

UNKNOWN_TOOL_TIER = ActionTier.T2
SHELL_MIN_TIER = ActionTier.T2
# Tools at or above this tier are approval-gated (signed quorum).
APPROVAL_GATE_MIN_TIER = ActionTier.T2
# TODO(control-plane-gap): scratch prefixes (where directory-shaped writes are
# allowed despite unanchored core patterns) are a design inference; configure
# them per deployment.
DEFAULT_SCRATCH_PREFIXES = ("scratch/", "workspace/", "tmp/")
MAX_ARGUMENT_DEPTH = 32
# TODO(control-plane-gap): the merge-like name heuristic is a backstop for a
# forgotten flag, not a classifier; hosts must still set merge_capable.
_MERGE_LIKE_NAME = re.compile(r"merge|approve|squash|land|push", re.IGNORECASE)

_SCALARS = (bool, int, float, type(None))
# TODO(control-plane-gap): shell-command inspection is best-effort tokenising
# (split on whitespace, quotes and shell metacharacters); variable expansion,
# globbing, command substitution and interpreter one-liners are not modelled.
# Agents get shell only with a declared non-core cwd and no core tokens.
_SHELL_SPLIT = re.compile(r"[\s;&|<>()`'\"=$,{}]+")


def opaque_ref(decision: Decision) -> str:
    """The reference an agent may see for a denial (a decision-id prefix);
    the reason itself goes only to the audit log and the receipt."""
    return decision.decision_id[:12]


class ToolDenied(Exception):
    """Raised instead of invoking a tool. ``decision`` is the first denial."""

    def __init__(self, decision: Decision, decisions: tuple[Decision, ...] = ()) -> None:
        super().__init__(decision.reason)
        self.decision = decision
        self.decisions = decisions or (decision,)

    @property
    def ref(self) -> str:
        """:func:`opaque_ref` of the first denial (safe to show the agent)."""
        return opaque_ref(self.decision)


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    value: Any
    decisions: tuple[Decision, ...]


@dataclass(frozen=True)
class _ToolSpec:
    fn: Callable[..., Any]
    signature: inspect.Signature
    path_params: frozenset[str]
    command_param: str | None
    tier: ActionTier
    """Static tier, or (with ``profile``) the floor the computed tier is raised to."""
    read_only: bool
    profile: ProfileFactory | None = None
    branch_param: str | None = None
    merge_capable: bool = False


@dataclass(frozen=True)
class _CallPlan:
    """The harness-computed tier of one call and what it rests on."""

    tier: ActionTier
    profile: ActionProfile | None
    runbook_id: str | None
    runbook_hash: str | None
    blast_radius: int
    backup_key: tuple[str, str] | None = None
    merge_capable: bool = False


@dataclass(frozen=True)
class _Authorized:
    spec: _ToolSpec
    args: dict[str, Any]
    decisions: tuple[Decision, ...]
    plan: _CallPlan


class _Denied(Exception):
    """Internal: a pre-PDP denial reason."""


def _as_names(values: Iterable[str], label: str) -> frozenset[str]:
    if isinstance(values, str):
        raise ValueError(f"{label} must be a collection of names, not a string")
    names = frozenset(values)
    if not all(isinstance(name, str) and name for name in names):
        raise ValueError(f"{label} must contain non-empty strings")
    return names


def _string_leaves(value: Any, out: list[str], depth: int = 0) -> None:
    if depth > MAX_ARGUMENT_DEPTH:
        raise _Denied("arguments nested too deeply")
    # Only built-ins have non-overridable traversal/decoding semantics. Check
    # before copying too, since subclasses may customize __deepcopy__.
    value_type = type(value)
    if value_type is str:
        out.append(value)
    elif value_type is bytes:
        try:
            out.append(value.decode("utf-8"))
        except UnicodeDecodeError:
            return
    elif any(value_type is scalar for scalar in _SCALARS):
        return
    elif value_type is dict:
        for key, item in value.items():
            _string_leaves(key, out, depth + 1)
            _string_leaves(item, out, depth + 1)
    elif any(value_type is container for container in (list, tuple, set, frozenset)):
        for item in value:
            _string_leaves(item, out, depth + 1)
    else:
        raise _Denied(f"unsupported argument type {type(value).__name__}")


def _tool_call_attributes(
    paths: list[str],
    read_only: bool,
    digest: str,
    authored_by: str | None,
    requested_by: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Attributes of the ``tool.call`` request (the approval subject).

    Phase-5 keys (``action_profile``, ``runbook_id``/``runbook_hash``,
    ``backup_run``, ``change_id``) appear only when present, so earlier
    digests are unchanged."""
    attributes: dict[str, Any] = {
        "paths": list(paths),
        "tool_read_only": read_only,
        "arguments_digest": digest,
    }
    if authored_by is not None:
        attributes["authored_by"] = authored_by
    if requested_by is not None:
        attributes["requested_by"] = requested_by
    if extra:
        attributes.update(extra)
    return attributes


BACKUP_SUBJECT_DOMAIN = b"acgs-control-plane-backup-subject-v1\x00"


def backup_subject_digest(tool_name: str, arguments: Mapping[str, Any]) -> str:
    """The ``artifact_digest`` a backup run must carry to prove a backup *of
    this exact action* (tool + arguments): a backup of one table cannot cover
    dropping another."""
    import hashlib

    payload = tool_name.encode("utf-8") + b"\x00" + arguments_digest(arguments).encode("ascii")
    return "sha256:" + hashlib.sha256(BACKUP_SUBJECT_DOMAIN + payload).hexdigest()


def _plan_attributes(
    plan: _CallPlan, backup_run: ExternalRunRef | None, change_id: str | None
) -> dict[str, Any]:
    extra: dict[str, Any] = {}
    if plan.profile is not None:
        extra["action_profile"] = plan.profile.to_canonical()
    if plan.runbook_id is not None:
        extra["runbook_id"] = plan.runbook_id
        extra["runbook_hash"] = plan.runbook_hash
    if backup_run is not None:
        extra["backup_run"] = backup_run.to_dict()
    if change_id is not None:
        extra["change_id"] = change_id
    if plan.merge_capable:
        extra["merge_capable"] = True
    return extra


class GovernedToolDispatcher:
    """Gate tool functions behind PDP decisions and repository permissions."""

    def __init__(
        self,
        pdp: PolicyDecisionPoint,
        *,
        permissions: RepositoryPermissions,
        tool_tiers: Mapping[str, ActionTier],
        read_only_tools: frozenset[str] = frozenset(),
        scratch_prefixes: Iterable[str] = DEFAULT_SCRATCH_PREFIXES,
        kill_switch: KillSwitch | None = None,
        credential_issuer: CredentialIssuer | None = None,
        require_credential: bool = False,
        budgets: BudgetLedger | None = None,
        autonomy: AutonomyController | None = None,
        breaker: TriggerCircuitBreaker | None = None,
        runbooks: RunbookRegistry | None = None,
        review_queue: ReviewQueue | None = None,
        ownership: ChangeOwnershipRegistry | None = None,
        incident_lock: IncidentMutationLock | None = None,
        run_verifier: ExternalRunVerifier | None = None,
        backup_workflows: Iterable[str] = (),
        narrow_max_blast_radius: int = DEFAULT_NARROW_MAX_BLAST_RADIUS,
    ) -> None:
        if runbooks is not None:
            if type(runbooks) is not RunbookRegistry:
                raise TypeError("runbooks must be a RunbookRegistry")
            if runbooks.registry != pdp.registry:
                raise ValueError("runbooks and pdp must use the same immutable-core registry")
            if review_queue is None:
                raise ValueError("runbooks need a review_queue (T1 actions get post-hoc review)")
        if review_queue is not None and not isinstance(review_queue, ReviewQueue):
            raise TypeError("review_queue must be a ReviewQueue")
        if ownership is not None:
            if type(ownership) is not ChangeOwnershipRegistry:
                raise TypeError("ownership must be a ChangeOwnershipRegistry")
            if ownership.registry != pdp.registry:
                raise ValueError("ownership and pdp must use the same immutable-core registry")
        if incident_lock is not None and type(incident_lock) is not IncidentMutationLock:
            raise TypeError("incident_lock must be an IncidentMutationLock")
        if run_verifier is not None and not isinstance(run_verifier, ExternalRunVerifier):
            raise TypeError("run_verifier must be an ExternalRunVerifier")
        # Validated (and normalised) the same way classify_tier does.
        classify_tier(
            ActionProfile(True, False, 0, False, read_only=True),
            narrow_max_blast_radius=narrow_max_blast_radius,
        )
        self._runbooks = runbooks
        self._review_queue = review_queue
        self._ownership = ownership
        self._incident_lock = incident_lock
        self._run_verifier = run_verifier
        if isinstance(backup_workflows, str):
            raise ValueError("backup_workflows must be a collection of provider ids")
        # TODO(control-plane-gap): run records carry no timestamp, so backup
        # freshness (max age) is not enforced; only allow-listed backup
        # workflows, action-bound digests and single use are.
        self._backup_workflows = frozenset(backup_workflows)
        self._consumed_backups: set[tuple[str, str]] = set()
        self._backup_lock = threading.Lock()
        self._narrow = narrow_max_blast_radius
        if not isinstance(pdp, PolicyDecisionPoint):
            raise TypeError("pdp must be a PolicyDecisionPoint")
        if not isinstance(permissions, RepositoryPermissions):
            raise TypeError("permissions must be a RepositoryPermissions")
        if permissions.registry != pdp.registry:
            raise ValueError("permissions and pdp must use the same immutable-core registry")
        if kill_switch is not None and type(kill_switch) is not KillSwitch:
            raise TypeError("kill_switch must be a KillSwitch")
        if credential_issuer is not None and type(credential_issuer) is not CredentialIssuer:
            raise TypeError("credential_issuer must be a CredentialIssuer")
        if require_credential and credential_issuer is None:
            raise ValueError("require_credential=True needs a credential_issuer")
        if budgets is not None and not isinstance(budgets, BudgetLedger):
            raise TypeError("budgets must be a BudgetLedger")
        if autonomy is not None and not isinstance(autonomy, AutonomyController):
            raise TypeError("autonomy must be an AutonomyController")
        if breaker is not None and type(breaker) is not TriggerCircuitBreaker:
            raise TypeError("breaker must be a TriggerCircuitBreaker")
        if breaker is not None and breaker.registry is None:
            raise ValueError("a breaker needs a TriggerRegistry (trigger bindings)")
        if breaker is not None and breaker.autonomy is not None:
            if autonomy is not None and autonomy is not breaker.autonomy:
                # The breaker would demote one controller while dispatch
                # enforces another, so a breaker reset would silently restore
                # autonomy the breaker's controller still withholds.
                raise ValueError("autonomy must be the breaker's AutonomyController")
            # The demotions a breaker makes must be enforced here too.
            autonomy = breaker.autonomy
        if autonomy is not None and autonomy.budgets is not budgets:
            # A controller watching a ledger the dispatcher never charges
            # would never see exhaustion.
            raise ValueError("autonomy must use the same BudgetLedger as the dispatcher")
        if pdp.approval_gate is None and any(
            ActionTier(tier) >= APPROVAL_GATE_MIN_TIER for tier in tool_tiers.values()
        ):
            raise ValueError("T2/T3 tools require a PDP configured with an ApprovalGate")
        self._pdp = pdp
        self._gate: ApprovalGate | None = pdp.approval_gate
        self._kill_switch = kill_switch if kill_switch is not None else pdp.kill_switch
        self._credentials = credential_issuer
        self._require_credential = bool(require_credential)
        self._attests_identity = (
            self._require_credential
            and credential_issuer is not None
            and credential_issuer.identity is not None
        )
        self._budgets = budgets
        self._autonomy = autonomy
        self._breaker = breaker
        self._permissions = permissions
        self._registry = pdp.registry
        self._tool_tiers = {name: ActionTier(tier) for name, tier in tool_tiers.items()}
        self._read_only_tools = frozenset(read_only_tools)
        prefixes = []
        for prefix in scratch_prefixes:
            normalized = self._registry.normalize(prefix)
            if normalized is None or normalized == "." or self._registry.is_core(normalized):
                raise ValueError(f"invalid or core scratch prefix: {prefix!r}")
            prefixes.append(normalized.lower() + "/")
        self._scratch_prefixes = tuple(prefixes)
        self._tools: dict[str, _ToolSpec] = {}

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def tier_for(self, tool_name: str) -> ActionTier:
        return self._tool_tiers.get(tool_name, UNKNOWN_TOOL_TIER)

    def is_read_only(self, tool_name: str) -> bool:
        spec = self._tools.get(tool_name)
        if spec is not None:
            return spec.read_only
        return tool_name in self._tool_tiers and tool_name in self._read_only_tools

    def tier_of_call(
        self,
        principal: Principal,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        runbook_id: str | None = None,
        runbook_hash: str | None = None,
        backup_run: ExternalRunRef | None = None,
        trigger_id: str | None = None,
    ) -> ActionTier:
        """The tier the dispatcher computes for this call (pure; raises
        ``ValueError`` when the call would be refused before the PDP)."""
        try:
            spec, args, declared, core_leaves = self._check(principal, tool_name, arguments)
            paths = list(dict.fromkeys([*declared, *core_leaves]))
            return self._plan(
                principal,
                spec,
                tool_name,
                args,
                paths,
                runbook_id=runbook_id,
                runbook_hash=runbook_hash,
                backup_run=backup_run,
                trigger_id=trigger_id,
                session=None,
            ).tier
        except _Denied as exc:
            raise ValueError(str(exc)) from exc

    def action_hash_for(
        self,
        principal: Principal,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        authored_by: str | None = None,
        requested_by: str | None = None,
        runbook_id: str | None = None,
        runbook_hash: str | None = None,
        backup_run: ExternalRunRef | None = None,
        change_id: str | None = None,
        trigger_id: str | None = None,
    ) -> str:
        """The action hash an approver must sign to approve this exact call.

        Pure: no decision is recorded and no budget is charged. Raises
        ``ValueError`` for a call that fails the pre-PDP argument checks.
        For a T2+ tool it notes the approval request for telemetry. Pass the
        same Phase-5 keywords as the dispatch (they are part of the hash).
        """
        from acgs_lite.control_plane.action_hash import action_hash

        try:
            spec, args, declared, core_leaves = self._check(principal, tool_name, arguments)
            paths = list(dict.fromkeys([*declared, *core_leaves]))
            plan = self._plan(
                principal,
                spec,
                tool_name,
                args,
                paths,
                runbook_id=runbook_id,
                runbook_hash=runbook_hash,
                backup_run=backup_run,
                trigger_id=trigger_id,
                session=None,
            )
        except _Denied as exc:
            raise ValueError(str(exc)) from exc
        tool_call = _tool_call_attributes(
            paths,
            spec.read_only,
            arguments_digest(args),
            authored_by,
            requested_by,
            _plan_attributes(plan, backup_run, change_id),
        )
        digest = action_hash(
            DecisionRequest(
                principal=principal,
                action="tool.call",
                resource=tool_name,
                tier=plan.tier,
                attributes=tool_call,
            )
        )
        if self._gate is not None and plan.tier >= APPROVAL_GATE_MIN_TIER:
            self._gate.note_approval_requested(digest, principal_kind=principal.kind)
        return digest

    def register(
        self,
        name: str,
        fn: Callable[..., Any],
        *,
        path_params: Iterable[str] = (),
        opaque_params: Iterable[str] = (),
        command_param: str | None = None,
        profile: ProfileFactory | None = None,
        branch_param: str | None = None,
        merge_capable: bool,
        merge_capable_override_reason: str | None = None,
    ) -> None:
        """Register *fn* under *name*, classifying every signature parameter.

        Tier and read-only status are frozen at registration. A tool with a
        ``command_param`` is shell-like: it must be tier >= T2 and cannot be
        read-only. Re-registration is refused.

        With *profile* (Phase 5) the tier is computed per call from the
        :class:`~.tier_policy.ActionProfile` the factory returns; such a tool
        may reach T2/T3, so it needs a PDP with an ApprovalGate, and
        ``tool_tiers[name]`` (if any) is only a floor. *branch_param* names an
        opaque parameter holding a git branch, checked against the change
        owner's branch. *merge_capable* marks a tool that merges or approves
        changes: no AGENT/SERVICE may run it (INV-AGENT-NO-MERGE) and no
        runbook covers it. It is required (no default): a merge tool that
        forgot the flag would otherwise be runnable by agents. A name that
        looks like a merge/approve/squash/land/push operation registered with
        ``merge_capable=False`` needs a non-empty
        *merge_capable_override_reason*. Tools named in
        ``AGENT_NO_MERGE_ACTIONS`` are merge-capable regardless.
        """
        if not isinstance(merge_capable, bool):
            raise TypeError("merge_capable must be a bool")
        if (
            not merge_capable
            and isinstance(name, str)
            and _MERGE_LIKE_NAME.search(name)
            and not (
                isinstance(merge_capable_override_reason, str)
                and merge_capable_override_reason.strip()
            )
        ):
            raise ValueError(
                f"tool {name!r} looks merge-capable: pass merge_capable=True or a "
                "merge_capable_override_reason"
            )
        if profile is not None and not callable(profile):
            raise TypeError("profile must be a callable returning an ActionProfile")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("tool name must be a non-empty string")
        if not callable(fn):
            raise TypeError("tool must be callable")
        if name in self._tools:
            raise ValueError(f"tool {name!r} is already registered")
        signature = inspect.signature(fn)
        params = signature.parameters
        for param in params.values():
            if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
                raise ValueError(f"tool {name!r}: *args/**kwargs hide arguments from review")
            if param.kind is param.POSITIONAL_ONLY:
                raise ValueError(f"tool {name!r}: positional-only parameters are not supported")
        paths = _as_names(path_params, "path_params")
        opaque = _as_names(opaque_params, "opaque_params")
        command: frozenset[str] = (
            frozenset() if command_param is None else frozenset({command_param})
        )
        if paths & opaque or paths & command or opaque & command:
            raise ValueError(f"tool {name!r}: a parameter may be classified only once")
        declared = paths | opaque | command
        if declared != set(params):
            unknown = sorted(declared - set(params))
            unclassified = sorted(set(params) - declared)
            raise ValueError(
                f"tool {name!r}: unknown params {unknown}, unclassified params {unclassified}"
            )
        if branch_param is not None and branch_param not in opaque:
            raise ValueError(f"tool {name!r}: branch_param must be one of the opaque params")
        if profile is None:
            tier = self.tier_for(name)
            read_only = self.is_read_only(name)
        else:
            tier = self._tool_tiers.get(name, ActionTier.T0)
            read_only = name in self._read_only_tools
            if self._gate is None:
                raise ValueError(
                    f"tool {name!r} has an action profile (may compute T2/T3): it requires "
                    "a PDP with an ApprovalGate"
                )
        if command_param is not None and (read_only or (profile is None and tier < SHELL_MIN_TIER)):
            raise ValueError(f"shell-like tool {name!r} must be tier >= T2 and not read-only")
        if tier >= APPROVAL_GATE_MIN_TIER and self._gate is None:
            raise ValueError(
                f"tool {name!r} is tier {tier.name}: T2/T3 tools require a PDP with an ApprovalGate"
            )
        merges = merge_capable or name.lower() in AGENT_NO_MERGE_ACTIONS
        self._tools[name] = _ToolSpec(
            fn, signature, paths, command_param, tier, read_only, profile, branch_param, merges
        )

    # -- authorisation -------------------------------------------------

    def _pre_denial(
        self,
        principal: object,
        tool_name: object,
        reason: str,
        *,
        telemetry: bool = True,
        credential_id: str | None = None,
    ) -> ToolDenied:
        decision = self._pdp._record_denial(
            reason,
            principal_id=str(getattr(principal, "id", "") or ""),
            action="tool.call",
            resource=tool_name if isinstance(tool_name, str) else "",
            error="dispatch_denied",
            telemetry=telemetry,
            principal_kind=principal.kind if isinstance(principal, Principal) else None,
            credential_id=credential_id,
        )
        return ToolDenied(decision)

    def _leaf_is_core(self, value: str) -> bool:
        normalized = self._registry.normalize(value)
        if normalized is None:
            stripped = value.strip()
            if not stripped:
                # Empty or whitespace-only opaque content names no path.
                # (Declared path parameters are authorised as paths anyway,
                # so an empty *path* argument is still denied.)
                return False
            if stripped != value:
                # " evaluator/x.py" is one strip() away from a core path:
                # judge the token a tool would actually use.
                return self._leaf_is_core(stripped)
            # An unresolvable single token ("/etc/x", "evaluator%2fx") is a
            # suspicious path; multi-word text and file contents are not paths.
            return not any(ch.isspace() for ch in value)
        return self._registry.is_core(normalized)

    def _is_directory_like(self, raw: str) -> bool:
        normalized = self._registry.normalize(raw)
        if normalized is None:
            return False  # already core; the PDP denies it
        if raw.endswith("/") or normalized == ".":
            return True
        if "." not in normalized.rsplit("/", 1)[-1]:
            return True
        # A suffix is not evidence of a regular file: directories can have
        # dots too. Outside scratch, unknown targets must remain restricted.
        # A host that permits ordinary file updates binds a repository root
        # so the existing target can be checked before authorization.
        root = self._registry.repo_root
        return root is None or not os.path.isfile(posixpath.join(root, normalized))

    def _in_scratch(self, raw: str) -> bool:
        normalized = self._registry.normalize(raw)
        if normalized is None:
            return False
        candidate = normalized.lower() + "/"
        return any(candidate.startswith(prefix) for prefix in self._scratch_prefixes)

    def _shell_core_tokens(self, command: str, cwd: str | None) -> list[str]:
        hits = []
        for token in _SHELL_SPLIT.split(command):
            if not token:
                continue
            candidates = [token]
            if cwd and not token.startswith(("/", "~", "-")):
                candidates.append(cwd.rstrip("/") + "/" + token)
            if any(self._leaf_is_core(candidate) for candidate in candidates):
                hits.append(token)
        return hits

    @staticmethod
    def _snapshot(arguments: object) -> dict[str, Any]:
        if type(arguments) is not dict:
            raise _Denied("tool arguments must be a built-in dict")
        _string_leaves(arguments, [])
        snapshot = copy.deepcopy(dict(arguments))
        if not all(isinstance(key, str) for key in snapshot):
            raise _Denied("argument names must be strings")
        return snapshot

    def _check(
        self, principal: object, tool_name: object, arguments: object
    ) -> tuple[_ToolSpec, dict[str, Any], list[str], list[str]]:
        """Pre-PDP checks. Returns (spec, snapshot, declared paths, core leaves)."""
        if not isinstance(principal, Principal):
            raise _Denied("principal must be a Principal")
        if not isinstance(tool_name, str) or tool_name not in self._tools:
            raise _Denied(f"tool {tool_name!r} is not registered")
        spec = self._tools[tool_name]
        try:
            args = self._snapshot(arguments)
        except _Denied:
            raise
        except Exception as exc:
            raise _Denied(f"arguments cannot be snapshotted: {type(exc).__name__}") from exc
        unknown = sorted(set(args) - set(spec.signature.parameters))
        if unknown:
            raise _Denied(f"unknown arguments {unknown}")
        try:
            bound = spec.signature.bind(**args)
        except TypeError as exc:
            raise _Denied(f"arguments do not match the tool signature: {exc}") from exc
        # Python fills omitted parameters from their defaults at call time, so
        # the defaults are part of what the tool receives: authorise (and
        # invoke with) the complete argument set, deep-copied so a mutable
        # default is not shared between calls.
        bound.apply_defaults()
        try:
            _string_leaves(bound.arguments, [])
            args = copy.deepcopy(dict(bound.arguments))
        except _Denied:
            raise
        except Exception as exc:
            raise _Denied(f"default arguments cannot be snapshotted: {type(exc).__name__}") from exc

        declared: list[str] = []
        for param in sorted(spec.path_params):
            value = args.get(param)
            if value is None:
                continue
            if isinstance(value, str):
                declared.append(value)
            elif isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
                declared.extend(value)
            else:
                raise _Denied(f"path argument {param!r} must be a string or list of strings")

        leaves: list[str] = []
        _string_leaves(args, leaves)
        core_leaves = [leaf for leaf in leaves if self._leaf_is_core(leaf)]

        if spec.command_param is not None:
            command = args.get(spec.command_param)
            if not isinstance(command, str):
                raise _Denied(f"command argument {spec.command_param!r} must be a string")
            if principal.kind is not PrincipalKind.HUMAN:
                # Token scanning cannot model `cd ..`, `${e}or`, globbing or
                # interpreter one-liners, so agents get no shell at all.
                # TODO(control-plane-gap): re-enable for agents only behind a
                # register()-time sandbox attestation that the core is mounted
                # read-only (OS-level), not behind better string matching.
                raise _Denied(
                    "shell-like tools are human-only until an OS sandbox mounts the core read-only"
                )
            cwd = args.get("cwd") if "cwd" in spec.path_params else None
            hits = self._shell_core_tokens(command, cwd if isinstance(cwd, str) else None)
            if hits:
                raise _Denied(f"shell command references immutable-core paths {hits}")
            if not self._permissions.has_unrestricted_write(principal):
                # A shell command can write any path, and its targets cannot
                # be extracted reliably, so path-scoped grants cannot be
                # enforced on it: only a principal granted "**" may use it.
                raise _Denied("shell-like tools need an unrestricted ('**') repository write grant")

        if not spec.read_only and self._registry.has_unanchored_patterns():
            for path in declared:
                if self._registry.is_core(path):
                    # Preserve the specific PDP denial for core targets.
                    continue
                if self._is_directory_like(path) and not self._in_scratch(path):
                    raise _Denied(f"directory-like write target {path!r} may contain core files")
        return spec, args, declared, core_leaves

    # -- Phase 5: tier, runbook, backup, ownership ----------------------

    def _stop_signals(
        self, principal: Principal, trigger_id: str | None, session: ScopedCredential | None
    ) -> StopSignals:
        """Breaker and budget state for runbook stop conditions (fail closed:
        an unknown trigger under a breaker reads as open)."""
        breaker_open = False
        breaker = self._breaker
        if breaker is not None:
            trigger = (
                session.trigger_id if session is not None and session.trigger_id else trigger_id
            )
            if trigger is None:
                breaker_open = principal.kind is not PrincipalKind.HUMAN
            else:
                breaker_open = breaker.state(trigger) is not BreakerState.CLOSED
        fraction = None if self._budgets is None else self._budgets.used_fraction(principal)
        return StopSignals(breaker_open=breaker_open, budget_fraction=fraction)

    def _backup_problem(
        self, backup_run: ExternalRunRef | None, tool_name: str, args: Mapping[str, Any]
    ) -> str | None:
        """Why *backup_run* does not prove a backup of this exact action, or None."""
        verifier = self._run_verifier
        if backup_run is None or verifier is None:
            return "no backup run (or no run verifier configured)"
        if backup_run.source is EvidenceSource.AGENT_LOG:
            return "agent-written logs are not backup evidence"
        if backup_run.provider not in self._backup_workflows:
            return f"backup run provider {backup_run.provider!r} is not an allow-listed workflow"
        if backup_run.artifact_digest != backup_subject_digest(tool_name, args):
            return "backup run is not bound to this action's arguments"
        if not _attests_digest(verifier, backup_run):
            return "run verifier cannot attest the backup digest"
        with self._backup_lock:
            if (backup_run.provider, backup_run.run_id) in self._consumed_backups:
                return "backup run already consumed by another action"
        try:
            result = verifier.validate(backup_run)
        except Exception as exc:
            return f"backup run unverifiable: {type(exc).__name__}"
        if not isinstance(result, RunValidation) or result.valid is not True:
            return "backup run not independently validated"
        return None

    def _consume_backup(self, key: tuple[str, str]) -> bool:
        with self._backup_lock:
            if key in self._consumed_backups:
                return False
            self._consumed_backups.add(key)
            return True

    def _plan(
        self,
        principal: Principal,
        spec: _ToolSpec,
        tool_name: str,
        args: Mapping[str, Any],
        paths: list[str],
        *,
        runbook_id: object,
        runbook_hash: object,
        backup_run: object,
        trigger_id: str | None,
        session: ScopedCredential | None,
        claimed_tier: object = None,
    ) -> _CallPlan:
        """Compute this call's tier from its action profile (never from the
        caller) and validate the runbook / backup it rests on. Pure: the
        runbook rate limit is checked here but only consumed after the PDP."""
        if backup_run is not None and not isinstance(backup_run, ExternalRunRef):
            raise _Denied("backup_run must be an ExternalRunRef")
        profile: ActionProfile | None = None
        if spec.profile is not None:
            try:
                profile = spec.profile(MappingProxyType(copy.deepcopy(dict(args))))
            except Exception as exc:
                raise _Denied(f"action profile factory failed: {type(exc).__name__}") from exc
            if not isinstance(profile, ActionProfile):
                raise _Denied("action profile factory must return an ActionProfile")
            if profile.read_only is not spec.read_only:
                raise _Denied("action profile read_only disagrees with the tool registration")
        blast_radius = profile.blast_radius if profile is not None else max(1, len(paths))
        runbook = None
        if runbook_id is not None or runbook_hash is not None:
            if self._runbooks is None:
                raise _Denied("runbook cited but no runbook registry is configured")
            try:
                runbook = self._runbooks.check_execution(
                    runbook_id,
                    runbook_hash,
                    tool_name=tool_name,
                    paths=paths,
                    principal=principal,
                    blast_radius=blast_radius,
                    signals=self._stop_signals(principal, trigger_id, session),
                    consume=False,
                    merge_capable=spec.merge_capable,
                )
            except RunbookDenied as exc:
                raise _Denied(f"runbook rejected: {exc}") from exc
        if profile is None:
            tier = spec.tier
        else:
            computed = classify_tier(profile, runbook=runbook, narrow_max_blast_radius=self._narrow)
            tier = max(computed, spec.tier)
        if spec.command_param is not None:
            tier = max(tier, SHELL_MIN_TIER)
        if tier == ActionTier.T1 and self._runbooks is not None and runbook is None:
            raise _Denied(
                "T1 execution requires runbook_id and runbook_hash of an approved runbook"
            )
        if claimed_tier is not None:
            if isinstance(claimed_tier, bool) or not isinstance(claimed_tier, int):
                raise _Denied("caller-supplied tier is not an ActionTier")
            try:
                claimed = ActionTier(claimed_tier)
            except ValueError as exc:
                raise _Denied("caller-supplied tier is not an ActionTier") from exc
            if claimed < tier:
                raise _Denied(
                    f"caller-supplied tier {claimed.name} is lower than the computed tier {tier.name}"
                )
        backup_key: tuple[str, str] | None = None
        if tier == ActionTier.T3 and principal.kind is not PrincipalKind.HUMAN:
            ref = backup_run if isinstance(backup_run, ExternalRunRef) else None
            backup_problem = self._backup_problem(ref, tool_name, args)
            problem = t3_execution_problem(
                principal, backup_verified=backup_problem is None, profile=profile
            )
            if problem is not None:
                detail = f" ({backup_problem})" if backup_problem else ""
                raise _Denied(problem + detail)
            if ref is not None:
                backup_key = (ref.provider, ref.run_id)
        use_runbook = runbook is not None and tier == ActionTier.T1
        return _CallPlan(
            tier=tier,
            profile=profile,
            runbook_id=runbook.runbook_id if use_runbook and runbook is not None else None,
            runbook_hash=runbook_hash if use_runbook and isinstance(runbook_hash, str) else None,
            blast_radius=blast_radius,
            backup_key=backup_key,
            merge_capable=spec.merge_capable,
        )

    def _ownership_check(
        self,
        principal: Principal,
        spec: _ToolSpec,
        args: Mapping[str, Any],
        paths: Iterable[str],
        change_id: object,
    ) -> None:
        owners = self._ownership
        if spec.read_only:
            return
        branch: object = None
        if spec.branch_param is not None:
            # Resolve the branch the tool will really see (signature defaults
            # included): an omitted ``branch="main"`` default is still "main".
            bound = spec.signature.bind_partial(**args)
            bound.apply_defaults()
            branch = bound.arguments.get(spec.branch_param)
            if owners is None and principal.kind is not PrincipalKind.HUMAN:
                raise _Denied("branch-writing tools need change ownership for non-humans")
        if owners is None:
            return
        if change_id is None:
            if principal.kind is not PrincipalKind.HUMAN:
                raise _Denied("writes under change ownership must name the writer's change_id")
            return
        targets = list(paths)
        try:
            if spec.branch_param is not None:
                owned = owners.assert_writer(principal, change_id, None)
                if not isinstance(branch, str) or branch != owned.branch:
                    raise OwnershipDenied(
                        f"branch {branch!r} is not the change branch {owned.branch!r}"
                    )
            if not targets:
                owners.assert_writer(principal, change_id, None)
            for path in targets:
                owners.assert_writer(principal, change_id, path)
        except OwnershipDenied as exc:
            raise _Denied(f"change ownership: {exc}") from exc

    def _verify_credential(
        self, principal: Principal, tool_name: str | None, credential: object
    ) -> ScopedCredential | None:
        """``tool_name=None`` verifies identity only (no scope check)."""
        if not self._require_credential:
            return None
        issuer = self._credentials
        if issuer is None:  # pragma: no cover - refused at construction
            raise _Denied("no credential issuer")
        try:
            return issuer.verify(
                credential,
                required_scope=None if tool_name is None else f"tool:{tool_name}",
                principal=principal,
            )
        except CredentialInvalid as exc:
            raise _Denied(f"credential rejected: {exc}") from exc

    def is_async(self, tool_name: str) -> bool:
        """True if *tool_name* is a registered coroutine function."""
        spec = self._tools.get(tool_name)
        return spec is not None and inspect.iscoroutinefunction(spec.fn)

    @staticmethod
    def _resolve_requested_by(
        principal: Principal,
        tier: ActionTier,
        requested_by: str | None,
        session: ScopedCredential | None,
    ) -> str | None:
        """The original requester: from the credential session when it names
        one (a different caller-supplied value is refused), else the caller's
        value. Required for AGENT requests at T2+."""
        if session is not None and session.on_behalf_of is not None:
            if requested_by is not None and canonical_principal_id(requested_by) != (
                session.on_behalf_of
            ):
                raise _Denied("requested_by does not match the credential session")
            requested_by = session.on_behalf_of
        if (
            session is not None
            and session.on_behalf_of is None
            and principal.kind is PrincipalKind.AGENT
            and tier >= APPROVAL_GATE_MIN_TIER
        ):
            # A credentialed agent's requester must come from the issuing
            # session; a caller-supplied value could name an approver.
            raise _Denied("credential is not bound to an original requester (on_behalf_of)")
        if principal.kind is PrincipalKind.AGENT and tier >= APPROVAL_GATE_MIN_TIER:
            # TODO(control-plane-gap): without require_credential the original
            # requester is caller-asserted; it should always be bound from the
            # credential-issuing session.
            problem = requested_by_problem(principal, requested_by)
            if problem is not None:
                raise _Denied(problem)
        return requested_by

    def _breaker_check(
        self,
        principal: Principal,
        trigger_id: str | None,
        session: ScopedCredential | None,
        consume: bool,
    ) -> None:
        breaker = self._breaker
        if breaker is None or principal.kind is PrincipalKind.HUMAN:
            return
        registry = breaker.registry
        if registry is None:  # pragma: no cover - refused at construction
            raise _Denied("no trigger registry")
        if session is not None and session.trigger_id is not None:
            if trigger_id is not None and trigger_id != session.trigger_id:
                raise _Denied("trigger_id does not match the credential session")
            trigger_id = session.trigger_id
        # TODO(control-plane-gap): without require_credential the trigger_id is
        # caller-asserted; the registry binding bounds which triggers it may name.
        if trigger_id is None:
            raise _Denied("non-human dispatch under a circuit breaker must name its trigger_id")
        if not valid_trigger_id(trigger_id):
            raise _Denied("invalid trigger_id")
        if not registry.is_bound(trigger_id, principal):
            raise _Denied(f"trigger {trigger_id} not bound to principal")
        for cohort in registry.cohorts_of(principal):
            if breaker.cohort_suspended(cohort, probing=trigger_id):
                raise _Denied(f"system cohort {cohort} suspended (a bound trigger is not closed)")
        if not breaker.allow_autonomous(trigger_id, consume=consume):
            raise _Denied(f"trigger {trigger_id} autonomous mode suspended (circuit breaker open)")

    def _autonomy_check(self, principal: Principal, read_t0: bool) -> None:
        if principal.kind is PrincipalKind.HUMAN or self._autonomy is None:
            return
        level = self._autonomy.level(principal)
        if level is AutonomyLevel.SUSPENDED:
            raise _Denied("autonomy suspended")
        if level is AutonomyLevel.P0_ONLY and not read_t0:
            raise _Denied("autonomy demoted to P0_ONLY: read-only T0 tools only")

    def _final_admission(
        self,
        principal: Principal,
        tool_name: str,
        read_t0: bool,
        trigger_id: str | None,
        session: ScopedCredential | None,
    ) -> None:
        """Re-admit after the PDP: a failure observed meanwhile may have
        tripped the breaker, suspended the cohort or demoted the agent. Only
        here is the half-open probe spent (atomically, if still available)."""
        try:
            autonomy = self._autonomy
            if (
                autonomy is not None
                and principal.kind is not PrincipalKind.HUMAN
                and autonomy.is_demoted(principal)
                and not read_t0
            ):
                # is_demoted(), not level(): level() would also demote on the
                # budget this very call was just charged against.
                raise _Denied("autonomy demoted to P0_ONLY: read-only T0 tools only")
            self._breaker_check(principal, trigger_id, session, consume=True)
        except _Denied as exc:
            raise self._pre_denial(principal, tool_name, str(exc)) from exc
        except Exception as exc:
            raise self._pre_denial(
                principal, tool_name, f"harness check failed: {type(exc).__name__}"
            ) from exc

    def _harness_checks(
        self,
        principal: Principal,
        spec: _ToolSpec,
        tier: ActionTier,
        trigger_id: str | None = None,
        session: ScopedCredential | None = None,
        consume: bool = True,
    ) -> None:
        """Kill-switch-independent harness gates; raise :class:`_Denied`."""
        governed = principal.kind is not PrincipalKind.HUMAN
        read_t0 = spec.read_only and tier == ActionTier.T0
        if self._incident_lock is not None and not read_t0:
            # Humans too: during an incident there is exactly one writer.
            denial = self._incident_lock.write_denial(principal)
            if denial is not None:
                raise _Denied(denial)
        budgets = self._budgets
        if governed and budgets is not None:
            # TODO(control-plane-gap): no run means no enforceable budget, so
            # the call is denied; hosts must start_run() before dispatching.
            if not budgets.has_run(principal):
                raise _Denied("no budget run started for this principal")
            state = budgets.state(principal)
            if state.is_exhausted:
                if self._autonomy is not None:
                    self._autonomy.demote(
                        principal, "resource budget exhausted: " + ", ".join(state.exhausted)
                    )
                if self._autonomy is None or not read_t0:
                    raise _Denied("budget exhausted: " + ", ".join(state.exhausted))
        self._autonomy_check(principal, read_t0)
        # Availability only: the half-open probe is spent in _final_admission,
        # once the call has passed every other check (a denied call must not
        # burn the trigger's only probe).
        self._breaker_check(principal, trigger_id, session, consume=False)
        if governed and budgets is not None:
            # Atomic check-and-charge, after every other harness gate passed,
            # so concurrent calls cannot overshoot and a call never trips the
            # budget it is being admitted under.
            if budgets.try_charge(principal, iterations=1) is None and not (
                self._autonomy is not None and read_t0
            ):
                raise _Denied("budget exhausted")

    def _kill_switch_engaged(self) -> bool:
        # The dispatcher may hold a different switch than its PDP; either one
        # engaged (or unreadable) halts execution.
        for switch in (self._kill_switch, self._pdp.kill_switch):
            if switch is None:
                continue
            try:
                if switch.is_engaged():
                    return True
            except Exception:
                return True
        return False

    def _record_denial_failure(self, principal: object) -> None:
        autonomy = self._autonomy
        if autonomy is None or not isinstance(principal, Principal):
            return
        try:
            autonomy.record_failure(principal, FailureKind.POLICY_DENIAL)
        except Exception:  # pragma: no cover - record_failure is defensive
            return

    def _authorize(
        self,
        principal: Principal,
        tool_name: str,
        arguments: object,
        *,
        approvers: Iterable[Principal] = (),
        approvals: Iterable[SignedApproval] = (),
        authored_by: str | None = None,
        credential: object = None,
        consume: bool = False,
        requested_by: str | None = None,
        trigger_id: str | None = None,
        runbook_id: str | None = None,
        runbook_hash: str | None = None,
        backup_run: ExternalRunRef | None = None,
        change_id: str | None = None,
        tier: object = None,
    ) -> _Authorized:
        if self._kill_switch_engaged():
            raise self._pre_denial(principal, tool_name, "kill switch engaged", telemetry=consume)
        attested: ScopedCredential | None = None
        # Phase 6b: the verified credential's id, recorded on every receipt.
        cid: str | None = None
        if self._attests_identity:
            # Phase 6a: with a directory-backed issuer the credential's
            # identity is verified first and its signed kind/system_id drive
            # every later check; a host label that disagrees is denied, never
            # trusted. The tool scope is still checked at its usual place.
            try:
                attested = self._verify_credential(principal, None, credential)
            except _Denied as exc:
                raise self._pre_denial(principal, tool_name, str(exc), telemetry=consume) from exc
            except Exception as exc:
                raise self._pre_denial(
                    principal,
                    tool_name,
                    f"harness check failed: {type(exc).__name__}",
                    telemetry=consume,
                ) from exc
            if attested is None:  # pragma: no cover - require_credential is set
                raise self._pre_denial(principal, tool_name, "no attested credential")
            identity = self._credentials.identity if self._credentials is not None else None
            entry = None if identity is None else identity.lookup(attested.principal_id)
            if entry is None or entry.kind is not attested.kind:
                raise self._pre_denial(
                    principal, tool_name, "credential principal is not in the identity directory"
                )
            # The whole principal (id, kind, system_id, roles) is the directory's.
            principal = entry.principal()
            cid = attested.credential_id
        try:
            spec, args, declared, core_leaves = self._check(principal, tool_name, arguments)
            approver_tuple = tuple(approvers)
            approval_tuple = tuple(approvals)
            for label, value in (
                ("authored_by", authored_by),
                ("requested_by", requested_by),
                ("change_id", change_id),
            ):
                if value is not None and (not isinstance(value, str) or not value):
                    raise _Denied(f"{label} must be a non-empty string")
            digest = arguments_digest(args)
        except _Denied as exc:
            self._record_denial_failure(principal)
            raise self._pre_denial(
                principal, tool_name, str(exc), telemetry=consume, credential_id=cid
            ) from exc
        except (TypeError, ValueError) as exc:
            self._record_denial_failure(principal)
            raise self._pre_denial(
                principal, tool_name, f"invalid call: {exc}", telemetry=consume, credential_id=cid
            ) from exc
        paths = list(dict.fromkeys([*declared, *core_leaves]))
        try:
            session = self._verify_credential(principal, tool_name, credential)
        except _Denied as exc:
            raise self._pre_denial(
                principal, tool_name, str(exc), telemetry=consume, credential_id=cid
            ) from exc
        except Exception as exc:
            raise self._pre_denial(
                principal,
                tool_name,
                f"harness check failed: {type(exc).__name__}",
                telemetry=consume,
                credential_id=cid,
            ) from exc
        if session is not None:
            cid = session.credential_id
        try:
            plan = self._plan(
                principal,
                spec,
                tool_name,
                args,
                paths,
                runbook_id=runbook_id,
                runbook_hash=runbook_hash,
                backup_run=backup_run,
                trigger_id=trigger_id,
                session=session,
                claimed_tier=tier,
            )
            self._ownership_check(
                principal,
                spec,
                args,
                [p for p in paths if not self._registry.is_core(p)],
                change_id,
            )
        except _Denied as exc:
            self._record_denial_failure(principal)
            raise self._pre_denial(
                principal, tool_name, str(exc), telemetry=consume, credential_id=cid
            ) from exc
        except Exception as exc:
            raise self._pre_denial(
                principal,
                tool_name,
                f"tier planning failed: {type(exc).__name__}",
                telemetry=consume,
                credential_id=cid,
            ) from exc
        try:
            requested_by = self._resolve_requested_by(principal, plan.tier, requested_by, session)
            self._harness_checks(principal, spec, plan.tier, trigger_id, session, consume)
        except _Denied as exc:
            raise self._pre_denial(
                principal, tool_name, str(exc), telemetry=consume, credential_id=cid
            ) from exc
        except Exception as exc:
            raise self._pre_denial(
                principal,
                tool_name,
                f"harness check failed: {type(exc).__name__}",
                telemetry=consume,
                credential_id=cid,
            ) from exc

        tool_call = _tool_call_attributes(
            paths,
            spec.read_only,
            digest,
            authored_by,
            requested_by,
            _plan_attributes(plan, backup_run, change_id),
        )
        requests = [
            DecisionRequest(
                principal=principal,
                action="tool.call",
                resource=tool_name,
                tier=plan.tier,
                approvers=approver_tuple,
                attributes=dict(tool_call),
                approvals=approval_tuple,
                credential_id=cid,
            )
        ]
        path_action = "file.read" if spec.read_only else "file.write"
        requests.extend(
            DecisionRequest(
                principal=principal,
                action=path_action,
                resource=path,
                tier=plan.tier,
                approvers=approver_tuple,
                attributes={"via_tool": tool_name, "tool_call": dict(tool_call)},
                approvals=approval_tuple,
                credential_id=cid,
            )
            for path in paths
        )
        if not spec.read_only:
            # IAM first for non-core paths, so an IAM deny never burns
            # approvals (core paths are always denied by the PDP for write
            # tools, which consumes nothing). The full IAM pass below stays.
            for path in paths:
                if not self._registry.is_core(path) and not self._permissions.can_write(
                    principal, path
                ):
                    self._record_denial_failure(principal)
                    raise self._pre_denial(
                        principal,
                        tool_name,
                        f"repository permissions deny write to {path!r}",
                        telemetry=consume,
                        credential_id=cid,
                    )
        # The PDP is the single consumption point for approvals.
        decisions = self._pdp._decide_tool_call(requests, consume=consume)
        denied = [decision for decision in decisions if not decision.allowed]
        if denied:
            self._record_denial_failure(principal)
            raise ToolDenied(denied[0], decisions)
        try:
            # Every path (core included) must be the writer's, post-PDP.
            self._ownership_check(principal, spec, args, paths, change_id)
        except _Denied as exc:
            self._record_denial_failure(principal)
            raise self._pre_denial(
                principal, tool_name, str(exc), telemetry=consume, credential_id=cid
            ) from exc
        if not spec.read_only:
            for path in paths:
                if not self._permissions.can_write(principal, path):
                    self._record_denial_failure(principal)
                    raise self._pre_denial(
                        principal,
                        tool_name,
                        f"repository permissions deny write to {path!r}",
                        telemetry=consume,
                        credential_id=cid,
                    )
        if consume and plan.runbook_id is not None and self._runbooks is not None:
            # Atomic re-validation that spends one rate-limit slot, only once
            # the PDP has permitted the call.
            try:
                self._runbooks.check_execution(
                    plan.runbook_id,
                    plan.runbook_hash,
                    tool_name=tool_name,
                    paths=paths,
                    principal=principal,
                    blast_radius=plan.blast_radius,
                    signals=self._stop_signals(principal, trigger_id, session),
                    consume=True,
                )
            except RunbookDenied as exc:
                self._record_denial_failure(principal)
                raise self._pre_denial(
                    principal, tool_name, f"runbook rejected: {exc}", credential_id=cid
                ) from exc
        if consume and plan.backup_key is not None and not self._consume_backup(plan.backup_key):
            self._record_denial_failure(principal)
            raise self._pre_denial(
                principal, tool_name, "backup run already consumed", credential_id=cid
            )
        if consume:
            read_t0 = spec.read_only and plan.tier == ActionTier.T0
            self._final_admission(principal, tool_name, read_t0, trigger_id, session)
        return _Authorized(spec, args, decisions, plan)

    def _after_run(
        self,
        principal: Principal,
        tool_name: str,
        auth: _Authorized,
        *,
        success: bool,
        value: object = None,
    ) -> None:
        """T1 bookkeeping: runbook outcome (stop conditions) + post-hoc review.

        A normal return is a success only if the approved runbook's
        ``success_predicate`` holds for the returned value."""
        plan = auth.plan
        if plan.runbook_id is None or plan.runbook_hash is None:
            return
        if self._runbooks is not None:
            if success:
                success = self._runbooks.outcome_succeeded(
                    plan.runbook_id, value, self._run_verifier
                )
            self._runbooks.record_outcome(plan.runbook_id, success=success)
        if self._review_queue is not None:
            self._review_queue.record(
                decision_id=auth.decisions[0].decision_id if auth.decisions else "",
                runbook_id=plan.runbook_id,
                runbook_hash=plan.runbook_hash,
                principal_id=principal.id,
                tool_name=tool_name,
            )

    def _recheck_kill_switch(
        self, principal: Principal, tool_name: str, auth: _Authorized | None = None
    ) -> None:
        """Closes the authorise-then-invoke window (TOCTOU), sync and async:
        the kill switch, and for writes the incident mutation lock."""
        if self._kill_switch_engaged():
            raise self._pre_denial(principal, tool_name, "kill switch engaged")
        lock = self._incident_lock
        if lock is not None and auth is not None:
            if not (auth.spec.read_only and auth.plan.tier == ActionTier.T0):
                denial = lock.write_denial(principal)
                if denial is not None:
                    raise self._pre_denial(principal, tool_name, denial)

    def _run_on_authorized(
        self,
        principal: Principal,
        tool_name: str,
        auth: _Authorized,
        hook: Callable[[tuple[Decision, ...]], None] | None,
    ) -> None:
        if hook is None:
            return
        try:
            hook(auth.decisions)
        except Exception as exc:
            credential_id = auth.decisions[0].credential_id if auth.decisions else None
            raise self._pre_denial(
                principal,
                tool_name,
                f"pre-execution hook failed: {type(exc).__name__}",
                credential_id=credential_id,
            ) from exc

    def authorize_without_consuming(
        self,
        principal: Principal,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        approvers: Iterable[Principal] = (),
        approvals: Iterable[SignedApproval] = (),
        authored_by: str | None = None,
        requested_by: str | None = None,
        credential: str | None = None,
        trigger_id: str | None = None,
        runbook_id: str | None = None,
        runbook_hash: str | None = None,
        backup_run: ExternalRunRef | None = None,
        change_id: str | None = None,
        tier: ActionTier | None = None,
    ) -> tuple[Decision, ...]:
        """Dry run: all-permit decisions for the call or :class:`ToolDenied`.

        WARNING: approvals are *not* consumed (nor the runbook rate limit),
        so these decisions are not authority to act -- run the tool only
        through :meth:`dispatch` / :meth:`adispatch`. It does charge an
        iteration.
        """
        return self._authorize(
            principal,
            tool_name,
            arguments,
            approvers=approvers,
            approvals=approvals,
            authored_by=authored_by,
            credential=credential,
            consume=False,
            requested_by=requested_by,
            trigger_id=trigger_id,
            runbook_id=runbook_id,
            runbook_hash=runbook_hash,
            backup_run=backup_run,
            change_id=change_id,
            tier=tier,
        ).decisions

    def dispatch(
        self,
        principal: Principal,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        approvers: Iterable[Principal] = (),
        approvals: Iterable[SignedApproval] = (),
        authored_by: str | None = None,
        requested_by: str | None = None,
        credential: str | None = None,
        trigger_id: str | None = None,
        runbook_id: str | None = None,
        runbook_hash: str | None = None,
        backup_run: ExternalRunRef | None = None,
        change_id: str | None = None,
        tier: ActionTier | None = None,
        on_authorized: Callable[[tuple[Decision, ...]], None] | None = None,
    ) -> ToolResult:
        """Authorise then invoke a synchronous tool with the authorised snapshot.

        ``approvals`` are signed approvals of this exact call (see
        :meth:`action_hash_for`); ``authored_by`` names the principal that
        authored the change and ``requested_by`` the original requester on
        whose behalf the principal acts; neither may approve it. ``approvers`` is kept for
        API compatibility and is ignored by a PDP with an ApprovalGate.
        ``trigger_id`` names the autonomous trigger an agent acts under
        (required for agents when the dispatcher has a breaker).
        Phase 5: ``runbook_id``/``runbook_hash`` cite the approved runbook of
        a T1 call, ``backup_run`` proves the backup of a non-human T3 call,
        ``change_id`` names the change the writer owns, and ``tier`` (a
        caller's claim) is refused when lower than the computed tier and
        otherwise ignored. Phase 6b: ``on_authorized`` (harness code, e.g. the
        socket service's intent record) runs after authorisation and before
        the tool; if it raises, the call is denied and the tool never runs.
        """
        auth = self._authorize(
            principal,
            tool_name,
            arguments,
            approvers=approvers,
            approvals=approvals,
            authored_by=authored_by,
            credential=credential,
            consume=True,
            requested_by=requested_by,
            trigger_id=trigger_id,
            runbook_id=runbook_id,
            runbook_hash=runbook_hash,
            backup_run=backup_run,
            change_id=change_id,
            tier=tier,
        )
        if inspect.iscoroutinefunction(auth.spec.fn):
            raise TypeError(f"tool {tool_name!r} is async; use adispatch()")
        # The hook first, then the TOCTOU recheck, so a halt engaged while the
        # hook ran (e.g. a slow durable intent write) still stops the tool.
        self._run_on_authorized(principal, tool_name, auth, on_authorized)
        self._recheck_kill_switch(principal, tool_name, auth)
        try:
            value = auth.spec.fn(**auth.args)
        except BaseException:
            self._after_run(principal, tool_name, auth, success=False)
            raise
        self._after_run(principal, tool_name, auth, success=True, value=value)
        return ToolResult(tool_name, value, auth.decisions)

    async def adispatch(
        self,
        principal: Principal,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        approvers: Iterable[Principal] = (),
        approvals: Iterable[SignedApproval] = (),
        authored_by: str | None = None,
        requested_by: str | None = None,
        credential: str | None = None,
        trigger_id: str | None = None,
        runbook_id: str | None = None,
        runbook_hash: str | None = None,
        backup_run: ExternalRunRef | None = None,
        change_id: str | None = None,
        tier: ActionTier | None = None,
        on_authorized: Callable[[tuple[Decision, ...]], None] | None = None,
    ) -> ToolResult:
        """Authorise (off the event loop) then invoke a sync or async tool."""
        auth = await asyncio.to_thread(
            lambda: self._authorize(
                principal,
                tool_name,
                arguments,
                approvers=tuple(approvers),
                approvals=tuple(approvals),
                authored_by=authored_by,
                credential=credential,
                consume=True,
                requested_by=requested_by,
                trigger_id=trigger_id,
                runbook_id=runbook_id,
                runbook_hash=runbook_hash,
                backup_run=backup_run,
                change_id=change_id,
                tier=tier,
            )
        )
        # The hook first, then the TOCTOU recheck, so a halt engaged while the
        # hook ran (e.g. a slow durable intent write) still stops the tool.
        self._run_on_authorized(principal, tool_name, auth, on_authorized)
        self._recheck_kill_switch(principal, tool_name, auth)
        try:
            value = auth.spec.fn(**auth.args)
            if inspect.isawaitable(value):
                value = await value
        except BaseException:
            self._after_run(principal, tool_name, auth, success=False)
            raise
        self._after_run(principal, tool_name, auth, success=True, value=value)
        return ToolResult(tool_name, value, auth.decisions)
