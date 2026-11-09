"""Non-overridable constitution invariants.

The PDP evaluates these forbids before, and in addition to, any loaded policy
set. No caller can remove or reorder them and no permit can override them.

Evidence:

* STOP / Darwin Goedel Machine (see :mod:`.immutable_core`): agents edited the
  sandbox flag and faked evaluation logs, so writes to the core are forbidden
  in code (INV-CORE-WRITE, INV-TOOL-ARG-CORE), not by prompt.
* Replit incident: an agent deleted a live production database during a
  natural-language code freeze. Irreversible (T3) actions therefore need two
  distinct human approvers other than the requester (INV-T3-TWO-PERSON).
  Phase 3: with an ApprovalGate on the PDP, approvers are only those that
  signed approvals attest (INV-APPROVAL-QUORUM), and core edits are a
  distinct human-only change class (INV-HUMAN-ONLY-CHANGE-CLASS).
* METR (Mar 2026): maintainer merge rates ran ~24pp below the SWE-bench
  grader on 296 AI-written patches, i.e. automated graders over-approve.
  Phase 5: the grader is not the merger -- no AGENT or SERVICE may merge or
  approve a change (INV-AGENT-NO-MERGE).
* Phase 5 tiers grade irreversibility, not confidence: a request carrying an
  ``action_profile`` may not claim a tier below the profile's floor
  (INV-TIER-FLOOR; T3 for irreversible/data-destroying, T1 otherwise).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

import acgs_lite.control_plane.change_ownership as ownership_module
from acgs_lite.control_plane.action_hash import approval_subject
from acgs_lite.control_plane.change_class import (
    CORE_HUMAN_ONLY_CATEGORIES,
    ChangeClass,
    classify_category,
)
from acgs_lite.control_plane.context import DecisionContext, DecisionRequest, is_write_action
from acgs_lite.control_plane.immutable_core import CoreCategory, ImmutableCoreRegistry
from acgs_lite.control_plane.policy import PolicyEffect, PolicyStatement
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.tiers import ActionTier

__all__ = [
    "ACTION_NAMESPACE_CATEGORIES",
    "CONSTITUTION_INVARIANTS",
    "HUMAN_CORE_CHANGE_MIN_TIER",
    "HUMAN_ONLY_CHANGE_CATEGORIES",
    "HUMAN_ONLY_CHANGE_MIN_APPROVALS",
    "SENSITIVE_READ_CATEGORIES",
    "T3_MIN_APPROVERS",
    "core_category_for",
    "has_two_person_approval",
    "tool_paths",
]

# Actions in these namespaces act on the core regardless of the resource
# string (``policy.update`` on a policy id, ``audit.truncate`` on a log name).
ACTION_NAMESPACE_CATEGORIES: Mapping[str, CoreCategory] = {
    "policy": CoreCategory.POLICY,
    "constitution": CoreCategory.POLICY,
    "evaluator": CoreCategory.EVALUATOR,
    "heldout": CoreCategory.HELDOUT_DATA,
    "sandbox": CoreCategory.SANDBOX_CONFIG,
    "allowlist": CoreCategory.TOOL_ALLOWLIST,
    "tool_allowlist": CoreCategory.TOOL_ALLOWLIST,
    "credentials": CoreCategory.CREDENTIALS,
    "secrets": CoreCategory.CREDENTIALS,
    "promotion": CoreCategory.PROMOTION_GATE,
    "audit": CoreCategory.AUDIT_LOG,
    "iam": CoreCategory.IAM,
    "ci": CoreCategory.CI_RULES,
    "control_plane": CoreCategory.CONTROL_PLANE,
    "memory_policy": CoreCategory.MEMORY_WRITE_POLICY,
    "memory_write_policy": CoreCategory.MEMORY_WRITE_POLICY,
}

HUMAN_ONLY_CHANGE_CATEGORIES = CORE_HUMAN_ONLY_CATEGORIES
# Categories an agent may not even read: credentials (exfiltration),
# held-out data (reading the test set defeats the evaluation), and the
# evaluator and its suites (reading the grader enables score gaming).
# TODO(control-plane-gap): evaluator answer keys have no dedicated category;
# put them under heldout/ until one exists.
SENSITIVE_READ_CATEGORIES = frozenset(
    {
        CoreCategory.CREDENTIALS,
        CoreCategory.HELDOUT_DATA,
        CoreCategory.EVALUATOR,
        CoreCategory.TEST_SUITE,
    }
)
# TODO(control-plane-gap): the T2 floor for human core changes is a design
# inference (no autonomous/pre-authorised T0/T1 path into the core). Phase 3
# adds the CORE_HUMAN_ONLY change class on top; no primary evidence for "T2".
HUMAN_CORE_CHANGE_MIN_TIER = ActionTier.T2
# Second-human rule for core changes; the number 1 is convention.
HUMAN_ONLY_CHANGE_MIN_APPROVALS = 1
# A core change must name the exact content it writes, so the action hash
# (and therefore the approval) binds the content, not just the target.
CONTENT_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
# Two-person rule; Replit motivates "more than one", the number 2 is convention.
T3_MIN_APPROVERS = 2


def core_category_for(
    request: DecisionRequest, registry: ImmutableCoreRegistry
) -> CoreCategory | None:
    """Stamp the core category of a request (PDP-only; never caller supplied).

    ``tool.*`` resources are tool *names*, not paths, so they are not
    classified here; INV-TOOL-ARG-CORE and the dispatcher's per-path
    ``file.write`` requests cover the paths a tool touches.
    """
    namespace = request.action.split(".", 1)[0].lower() if "." in request.action else ""
    if namespace in ACTION_NAMESPACE_CATEGORIES:
        return ACTION_NAMESPACE_CATEGORIES[namespace]
    if namespace == "tool":
        return None
    return registry.classify(request.resource)


def has_two_person_approval(request: DecisionRequest) -> bool:
    """>= 2 approvers, distinct canonical ids, all HUMAN, none the requester."""
    approvers = request.approvers
    if not all(isinstance(approver, Principal) for approver in approvers):
        return False
    ids = [approver.canonical_id for approver in approvers]
    return (
        len(approvers) >= T3_MIN_APPROVERS
        and len(set(ids)) == len(ids)
        and all(approver.kind is PrincipalKind.HUMAN for approver in approvers)
        and request.principal.canonical_id not in ids
    )


def tool_paths(attributes: Mapping[str, Any]) -> tuple[str, ...]:
    """Return ``attributes["paths"]``; malformed values raise (PDP denies)."""
    raw = attributes.get("paths")
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, (list, tuple)) and all(isinstance(item, str) for item in raw):
        return tuple(raw)
    raise TypeError("attributes['paths'] must be a string or a list of strings")


def _core_write_by_non_human(ctx: DecisionContext) -> bool:
    request = ctx.request
    return (
        request.principal.kind is not PrincipalKind.HUMAN
        and is_write_action(request.action)
        and ctx.core_category is not None
    )


def _all_core_categories(ctx: DecisionContext) -> frozenset[CoreCategory]:
    """``ctx.core_category`` plus every other category the resource path
    matches: precedence picks one category for display, but a restriction
    from any matching category must still apply (``policies/.env`` is
    POLICY *and* CREDENTIALS)."""
    if ctx.core_category is None:
        return frozenset()
    request = ctx.request
    return frozenset({ctx.core_category}) | ctx.registry.categories(request.resource)


def _sensitive_access_by_non_human(ctx: DecisionContext) -> bool:
    return ctx.request.principal.kind is not PrincipalKind.HUMAN and bool(
        _all_core_categories(ctx) & SENSITIVE_READ_CATEGORIES
    )


def _human_only_change_below_floor(ctx: DecisionContext) -> bool:
    request = ctx.request
    return (
        is_write_action(request.action)
        and bool(_all_core_categories(ctx) & HUMAN_ONLY_CHANGE_CATEGORIES)
        and request.tier < HUMAN_CORE_CHANGE_MIN_TIER
    )


def _core_change_without_attested_second_human(ctx: DecisionContext) -> bool:
    request = ctx.request
    if not any(
        classify_category(request.action, category) is ChangeClass.CORE_HUMAN_ONLY
        for category in _all_core_categories(ctx)
    ):
        return False
    if (
        request.principal.kind is not PrincipalKind.HUMAN
        or request.tier < HUMAN_CORE_CHANGE_MIN_TIER
    ):
        return True
    digest = request.attributes.get("content_digest")
    if not isinstance(digest, str) or not CONTENT_DIGEST_PATTERN.fullmatch(digest):
        return True
    # The digest must have been computed by the harness from the real bytes
    # (CoreChangeWriter), never claimed by the caller.
    if (
        request.attributes.get("content_digest_source") != "harness"
        or not ctx.content_digest_attested
    ):
        return True
    # Host-asserted approvers never count: only an ApprovalGate attests them.
    if not ctx.approvals_verified:
        return True
    others = {
        approver.canonical_id
        for approver in request.approvers
        if isinstance(approver, Principal)
        and approver.kind is PrincipalKind.HUMAN
        and approver.canonical_id != request.principal.canonical_id
    }
    return len(others) < HUMAN_ONLY_CHANGE_MIN_APPROVALS


_REQUESTER_ID = re.compile(r"[A-Za-z0-9._@:-]+")


def requested_by_problem(principal: Principal, requested_by: object) -> str | None:
    """Why *requested_by* is unacceptable for an agent's T2+ request, or None."""
    if requested_by is None:
        return "requested_by required for agent requests at tier >= T2"
    if not isinstance(requested_by, str) or not _REQUESTER_ID.fullmatch(requested_by):
        return "requested_by must be a canonical principal id"
    if requested_by.casefold() == principal.canonical_id:
        return "requested_by must differ from the requesting agent"
    return None


def _agent_without_original_requester(ctx: DecisionContext) -> bool:
    request = ctx.request
    if request.principal.kind is not PrincipalKind.AGENT or request.tier < ActionTier.T2:
        return False
    subject = approval_subject(request)
    return (
        requested_by_problem(request.principal, subject.attributes.get("requested_by")) is not None
    )


def _approval_quorum_unmet(ctx: DecisionContext) -> bool:
    return ctx.quorum is not None and not ctx.quorum.satisfied


def _t3_without_two_person(ctx: DecisionContext) -> bool:
    return ctx.request.tier == ActionTier.T3 and not has_two_person_approval(ctx.request)


def _tool_touches_core(ctx: DecisionContext) -> bool:
    request = ctx.request
    if request.action.lower() != "tool.call":
        return False
    paths = tool_paths(request.attributes)
    if request.attributes.get("tool_read_only") is True:
        return False
    return any(ctx.registry.is_core(path) for path in paths)


def _merge_by_non_human(ctx: DecisionContext) -> bool:
    request = ctx.request
    if request.principal.kind is PrincipalKind.HUMAN:
        return False
    names = {request.action.lower()}
    if request.action.lower() == "tool.call":
        names.add(request.resource.lower())
    via_tool = request.attributes.get("via_tool")
    if isinstance(via_tool, str):
        names.add(via_tool.lower())
    tool_call = request.attributes.get("tool_call")
    flagged = request.attributes.get("merge_capable") is True or (
        isinstance(tool_call, Mapping) and tool_call.get("merge_capable") is True
    )
    return flagged or bool(names & ownership_module.AGENT_NO_MERGE_ACTIONS)


_PROFILE_KEYS = frozenset(
    {"reversible", "data_destroying", "blast_radius", "novel", "has_verified_backup", "read_only"}
)


def _profile_floor(raw: object) -> ActionTier:
    """Lowest tier an action profile can ever classify to (raises if malformed,
    which the PDP turns into a deny). The PDP cannot see the runbook, so a
    reversible write floors at T1, never T2."""
    if not isinstance(raw, Mapping) or set(raw) != _PROFILE_KEYS:
        raise ValueError("malformed action_profile")
    for key in _PROFILE_KEYS - {"blast_radius"}:
        if not isinstance(raw[key], bool):
            raise ValueError("malformed action_profile")
    if raw["data_destroying"] or not raw["reversible"]:
        return ActionTier.T3
    if raw["read_only"]:
        return ActionTier.T0
    return ActionTier.T1


def _tier_below_profile_floor(ctx: DecisionContext) -> bool:
    # TODO(control-plane-gap): a host that builds a DecisionRequest without an
    # action_profile still asserts its tier; only the dispatcher path is bound.
    attributes = ctx.request.attributes
    raw = attributes.get("action_profile")
    tool_call = attributes.get("tool_call")
    if raw is None and isinstance(tool_call, Mapping):
        raw = tool_call.get("action_profile")
    if raw is None:
        return False
    return ctx.request.tier < _profile_floor(raw)


def _invariant(statement_id: str, description: str, condition: Any) -> PolicyStatement:
    return PolicyStatement(
        id=statement_id,
        effect=PolicyEffect.FORBID,
        principal_kinds=None,
        actions=("*",),
        resources=("**",),
        condition=condition,
        description=description,
    )


CONSTITUTION_INVARIANTS: tuple[PolicyStatement, ...] = (
    _invariant(
        "INV-CORE-WRITE",
        "Non-human principals never write to the immutable core.",
        _core_write_by_non_human,
    ),
    _invariant(
        "INV-CORE-SENSITIVE-READ",
        "Non-human principals may not read credentials, held-out data or the evaluator.",
        _sensitive_access_by_non_human,
    ),
    _invariant(
        "INV-CORE-HUMAN-ONLY-CHANGE",
        "Changes to a CORE_HUMAN_ONLY category need tier >= T2.",
        _human_only_change_below_floor,
    ),
    _invariant(
        "INV-T3-TWO-PERSON",
        "T3 actions need >= 2 distinct human approvers other than the requester.",
        _t3_without_two_person,
    ),
    _invariant(
        "INV-TOOL-ARG-CORE",
        "A non-read-only tool call may not receive an immutable-core path argument.",
        _tool_touches_core,
    ),
    _invariant(
        "INV-APPROVAL-QUORUM",
        "With an ApprovalGate, the tier's signed-approval quorum must be met.",
        _approval_quorum_unmet,
    ),
    _invariant(
        "INV-AGENT-REQUESTED-BY",
        "Agent requests at tier >= T2 must name a distinct original requester.",
        _agent_without_original_requester,
    ),
    _invariant(
        "INV-HUMAN-ONLY-CHANGE-CLASS",
        "Core changes need a HUMAN at tier >= T2, a content_digest, and an attested "
        "approval from another human.",
        _core_change_without_attested_second_human,
    ),
    _invariant(
        "INV-AGENT-NO-MERGE",
        "No AGENT or SERVICE may merge or approve a change (grader != merger).",
        _merge_by_non_human,
    ),
    _invariant(
        "INV-TIER-FLOOR",
        "A request may not claim a tier below its action profile's floor.",
        _tier_below_profile_floor,
    ),
)
