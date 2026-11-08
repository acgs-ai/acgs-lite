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
   lists/tuples/sets/mappings (anything else is opaque and denied);
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
scopes include ``tool:<name>``); resource budgets (one iteration charged per
dispatch; exhausted -> deny, or with an autonomy controller -> demotion); and
the :class:`~.autonomy.AutonomyController` level (P0_ONLY -> read-only T0
tools only, SUSPENDED -> nothing). T2/T3 tools need an
:class:`~.approvals.ApprovalGate` on the PDP (refused at construction and
registration otherwise); approvals are bound to the ``tool.call`` action hash,
which covers the arguments digest, and are consumed right before the tool
runs. Host-asserted ``approvers=`` are ignored by a gated PDP.

Any failure raises :class:`ToolDenied` and the tool function is never called.
Tools absent from ``tool_tiers`` are tier T2 and writers even if listed as
read-only. A directory argument that contains a root-anchored core pattern
(``cwd="."``, ``cwd="src"``) is itself core.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import os
import posixpath
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from acgs_lite.control_plane.action_hash import arguments_digest
from acgs_lite.control_plane.approvals import ApprovalGate, SignedApproval
from acgs_lite.control_plane.autonomy import AutonomyController, AutonomyLevel, FailureKind
from acgs_lite.control_plane.budgets import BudgetLedger
from acgs_lite.control_plane.context import DecisionRequest
from acgs_lite.control_plane.credentials import (
    CredentialInvalid,
    CredentialIssuer,
    ScopedCredential,
)
from acgs_lite.control_plane.iam import RepositoryPermissions
from acgs_lite.control_plane.invariants import requested_by_problem
from acgs_lite.control_plane.killswitch import KillSwitch
from acgs_lite.control_plane.pdp import Decision, PolicyDecisionPoint
from acgs_lite.control_plane.principal import Principal, PrincipalKind, canonical_principal_id
from acgs_lite.control_plane.tiers import ActionTier

__all__ = [
    "DEFAULT_SCRATCH_PREFIXES",
    "GovernedToolDispatcher",
    "ToolDenied",
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

_SCALARS = (bool, int, float, type(None))
# TODO(control-plane-gap): shell-command inspection is best-effort tokenising
# (split on whitespace, quotes and shell metacharacters); variable expansion,
# globbing, command substitution and interpreter one-liners are not modelled.
# Agents get shell only with a declared non-core cwd and no core tokens.
_SHELL_SPLIT = re.compile(r"[\s;&|<>()`'\"=$,{}]+")


class ToolDenied(Exception):
    """Raised instead of invoking a tool. ``decision`` is the first denial."""

    def __init__(self, decision: Decision, decisions: tuple[Decision, ...] = ()) -> None:
        super().__init__(decision.reason)
        self.decision = decision
        self.decisions = decisions or (decision,)


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
    read_only: bool


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
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, bytes):
        try:
            out.append(value.decode("utf-8"))
        except UnicodeDecodeError:
            return
    elif isinstance(value, _SCALARS):
        return
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _string_leaves(key, out, depth + 1)
            _string_leaves(item, out, depth + 1)
    elif isinstance(value, (list, tuple, set, frozenset)):
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
) -> dict[str, Any]:
    """Attributes of the ``tool.call`` request (the approval subject)."""
    attributes: dict[str, Any] = {
        "paths": list(paths),
        "tool_read_only": read_only,
        "arguments_digest": digest,
    }
    if authored_by is not None:
        attributes["authored_by"] = authored_by
    if requested_by is not None:
        attributes["requested_by"] = requested_by
    return attributes


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
    ) -> None:
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
        self._budgets = budgets
        self._autonomy = autonomy
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
        return tool_name in self._tool_tiers and tool_name in self._read_only_tools

    def action_hash_for(
        self,
        principal: Principal,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        authored_by: str | None = None,
        requested_by: str | None = None,
    ) -> str:
        """The action hash an approver must sign to approve this exact call.

        Pure: no decision is recorded and no budget is charged. Raises
        ``ValueError`` for a call that fails the pre-PDP argument checks.
        """
        from acgs_lite.control_plane.action_hash import action_hash

        try:
            spec, args, declared, core_leaves = self._check(principal, tool_name, arguments)
        except _Denied as exc:
            raise ValueError(str(exc)) from exc
        tool_call = _tool_call_attributes(
            list(dict.fromkeys([*declared, *core_leaves])),
            spec.read_only,
            arguments_digest(args),
            authored_by,
            requested_by,
        )
        return action_hash(
            DecisionRequest(
                principal=principal,
                action="tool.call",
                resource=tool_name,
                tier=spec.tier,
                attributes=tool_call,
            )
        )

    def register(
        self,
        name: str,
        fn: Callable[..., Any],
        *,
        path_params: Iterable[str] = (),
        opaque_params: Iterable[str] = (),
        command_param: str | None = None,
    ) -> None:
        """Register *fn* under *name*, classifying every signature parameter.

        Tier and read-only status are frozen at registration. A tool with a
        ``command_param`` is shell-like: it must be tier >= T2 and cannot be
        read-only. Re-registration is refused.
        """
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
        tier = self.tier_for(name)
        read_only = self.is_read_only(name)
        if command_param is not None and (tier < SHELL_MIN_TIER or read_only):
            raise ValueError(f"shell-like tool {name!r} must be tier >= T2 and not read-only")
        if tier >= APPROVAL_GATE_MIN_TIER and self._gate is None:
            raise ValueError(
                f"tool {name!r} is tier {tier.name}: T2/T3 tools require a PDP with an ApprovalGate"
            )
        self._tools[name] = _ToolSpec(fn, signature, paths, command_param, tier, read_only)

    # -- authorisation -------------------------------------------------

    def _pre_denial(self, principal: object, tool_name: object, reason: str) -> ToolDenied:
        decision = self._pdp.record_denial(
            reason,
            principal_id=str(getattr(principal, "id", "") or ""),
            action="tool.call",
            resource=tool_name if isinstance(tool_name, str) else "",
            error="dispatch_denied",
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
        # TODO(control-plane-gap): repo_root=None is the norm for p1-p5
        # integrators (only the p6 facade binds a root), and then a dotted
        # last segment ("app/v1.2") is taken for a file, so an agent may
        # delete/overwrite a directory holding unanchored core files
        # (app/v1.2/.env). Even with a root, the isdir fallback misses a
        # not-yet-existing dotted directory such as "app/v1.2/" created later.
        root = self._registry.repo_root
        return root is not None and os.path.isdir(posixpath.join(root, normalized))

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
        if not isinstance(arguments, Mapping):
            raise _Denied("tool arguments must be a mapping")
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
            args = copy.deepcopy(dict(bound.arguments))
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
                if self._is_directory_like(path) and not self._in_scratch(path):
                    # TODO(control-plane-gap): "directory-like" is inferred from
                    # a trailing slash, a missing extension or an existing dir
                    # under repo_root; extension-bearing directory names slip.
                    raise _Denied(f"directory-like write target {path!r} may contain core files")
        return spec, args, declared, core_leaves

    def _verify_credential(
        self, principal: Principal, tool_name: str, credential: object
    ) -> ScopedCredential | None:
        if not self._require_credential:
            return None
        issuer = self._credentials
        if issuer is None:  # pragma: no cover - refused at construction
            raise _Denied("no credential issuer")
        try:
            return issuer.verify(
                credential, required_scope=f"tool:{tool_name}", principal=principal
            )
        except CredentialInvalid as exc:
            raise _Denied(f"credential rejected: {exc}") from exc

    @staticmethod
    def _resolve_requested_by(
        principal: Principal,
        spec: _ToolSpec,
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
        if principal.kind is PrincipalKind.AGENT and spec.tier >= APPROVAL_GATE_MIN_TIER:
            # TODO(control-plane-gap): without require_credential the original
            # requester is caller-asserted; it should always be bound from the
            # credential-issuing session.
            problem = requested_by_problem(principal, requested_by)
            if problem is not None:
                raise _Denied(problem)
        return requested_by

    def _harness_checks(self, principal: Principal, spec: _ToolSpec) -> None:
        """Kill-switch-independent harness gates; raise :class:`_Denied`."""
        governed = principal.kind is not PrincipalKind.HUMAN
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
                if self._autonomy is None or not (spec.read_only and spec.tier == ActionTier.T0):
                    raise _Denied("budget exhausted: " + ", ".join(state.exhausted))
        if governed and self._autonomy is not None:
            level = self._autonomy.level(principal)
            if level is AutonomyLevel.SUSPENDED:
                raise _Denied("autonomy suspended")
            if level is AutonomyLevel.P0_ONLY and not (
                spec.read_only and spec.tier == ActionTier.T0
            ):
                raise _Denied("autonomy demoted to P0_ONLY: read-only T0 tools only")
        if governed and budgets is not None:
            # Atomic check-and-charge, after every other harness gate passed,
            # so concurrent calls cannot overshoot and a call never trips the
            # budget it is being admitted under.
            if budgets.try_charge(principal, iterations=1) is None and not (
                self._autonomy is not None and spec.read_only and spec.tier == ActionTier.T0
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
        approvers: Iterable[Principal],
        approvals: Iterable[SignedApproval] = (),
        authored_by: str | None = None,
        credential: object = None,
        consume: bool = False,
        requested_by: str | None = None,
    ) -> tuple[_ToolSpec, dict[str, Any], tuple[Decision, ...]]:
        if self._kill_switch_engaged():
            raise self._pre_denial(principal, tool_name, "kill switch engaged")
        try:
            spec, args, declared, core_leaves = self._check(principal, tool_name, arguments)
            approver_tuple = tuple(approvers)
            approval_tuple = tuple(approvals)
            for label, value in (("authored_by", authored_by), ("requested_by", requested_by)):
                if value is not None and (not isinstance(value, str) or not value):
                    raise _Denied(f"{label} must be a principal id string")
            digest = arguments_digest(args)
        except _Denied as exc:
            self._record_denial_failure(principal)
            raise self._pre_denial(principal, tool_name, str(exc)) from exc
        except (TypeError, ValueError) as exc:
            self._record_denial_failure(principal)
            raise self._pre_denial(principal, tool_name, f"invalid call: {exc}") from exc
        try:
            session = self._verify_credential(principal, tool_name, credential)
            requested_by = self._resolve_requested_by(principal, spec, requested_by, session)
            self._harness_checks(principal, spec)
        except _Denied as exc:
            raise self._pre_denial(principal, tool_name, str(exc)) from exc
        except Exception as exc:
            raise self._pre_denial(
                principal, tool_name, f"harness check failed: {type(exc).__name__}"
            ) from exc

        paths = list(dict.fromkeys([*declared, *core_leaves]))
        tool_call = _tool_call_attributes(paths, spec.read_only, digest, authored_by, requested_by)
        requests = [
            DecisionRequest(
                principal=principal,
                action="tool.call",
                resource=tool_name,
                tier=spec.tier,
                approvers=approver_tuple,
                attributes=dict(tool_call),
                approvals=approval_tuple,
            )
        ]
        path_action = "file.read" if spec.read_only else "file.write"
        requests.extend(
            DecisionRequest(
                principal=principal,
                action=path_action,
                resource=path,
                tier=spec.tier,
                approvers=approver_tuple,
                attributes={"via_tool": tool_name, "tool_call": dict(tool_call)},
                approvals=approval_tuple,
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
                        principal, tool_name, f"repository permissions deny write to {path!r}"
                    )
        # The PDP is the single consumption point for approvals.
        decisions = self._pdp._decide_tool_call(requests, consume=consume)
        denied = [decision for decision in decisions if not decision.allowed]
        if denied:
            self._record_denial_failure(principal)
            raise ToolDenied(denied[0], decisions)
        if not spec.read_only:
            for path in paths:
                if not self._permissions.can_write(principal, path):
                    self._record_denial_failure(principal)
                    raise self._pre_denial(
                        principal, tool_name, f"repository permissions deny write to {path!r}"
                    )
        return spec, args, decisions

    def _recheck_kill_switch(self, principal: Principal, tool_name: str) -> None:
        """Closes the authorise-then-invoke window (TOCTOU), sync and async."""
        if self._kill_switch_engaged():
            raise self._pre_denial(principal, tool_name, "kill switch engaged")

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
    ) -> tuple[Decision, ...]:
        """Dry run: all-permit decisions for the call or :class:`ToolDenied`.

        WARNING: approvals are *not* consumed, so these decisions are not
        authority to act -- run the tool only through :meth:`dispatch` /
        :meth:`adispatch`. It does charge an iteration.
        """
        return self._authorize(
            principal,
            tool_name,
            arguments,
            approvers,
            approvals,
            authored_by,
            credential,
            False,
            requested_by,
        )[2]

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
    ) -> ToolResult:
        """Authorise then invoke a synchronous tool with the authorised snapshot.

        ``approvals`` are signed approvals of this exact call (see
        :meth:`action_hash_for`); ``authored_by`` names the principal that
        authored the change and ``requested_by`` the original requester on
        whose behalf the principal acts; neither may approve it. ``approvers`` is kept for
        API compatibility and is ignored by a PDP with an ApprovalGate.
        """
        spec, args, decisions = self._authorize(
            principal,
            tool_name,
            arguments,
            approvers,
            approvals,
            authored_by,
            credential,
            consume=True,
            requested_by=requested_by,
        )
        if inspect.iscoroutinefunction(spec.fn):
            raise TypeError(f"tool {tool_name!r} is async; use adispatch()")
        self._recheck_kill_switch(principal, tool_name)
        return ToolResult(tool_name, spec.fn(**args), decisions)

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
    ) -> ToolResult:
        """Authorise (off the event loop) then invoke a sync or async tool."""
        approver_tuple = tuple(approvers)
        approval_tuple = tuple(approvals)
        spec, args, decisions = await asyncio.to_thread(
            self._authorize,
            principal,
            tool_name,
            arguments,
            approver_tuple,
            approval_tuple,
            authored_by,
            credential,
            True,
            requested_by,
        )
        self._recheck_kill_switch(principal, tool_name)
        value = spec.fn(**args)
        if inspect.isawaitable(value):
            value = await value
        return ToolResult(tool_name, value, decisions)
