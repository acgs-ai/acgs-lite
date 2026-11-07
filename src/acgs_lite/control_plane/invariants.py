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
* METR (Mar 2026): maintainer merge rates ran ~24pp below the SWE-bench
  grader on 296 AI-written patches, i.e. automated graders over-approve.
  Noted here; addressed by later phases (independent review gates).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

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
}

HUMAN_ONLY_CHANGE_CATEGORIES = frozenset(
    {
        CoreCategory.POLICY,
        CoreCategory.TOOL_ALLOWLIST,
        CoreCategory.EVALUATOR,
        CoreCategory.IAM,
        CoreCategory.CI_RULES,
        CoreCategory.AUDIT_LOG,
        CoreCategory.CONTROL_PLANE,
    }
)
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
# inference (no autonomous/pre-authorised T0/T1 path into the core); Phase 3
# replaces it with a distinct change class. No primary evidence for "T2".
HUMAN_CORE_CHANGE_MIN_TIER = ActionTier.T2
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


def _sensitive_access_by_non_human(ctx: DecisionContext) -> bool:
    return (
        ctx.request.principal.kind is not PrincipalKind.HUMAN
        and ctx.core_category in SENSITIVE_READ_CATEGORIES
    )


def _human_only_change_below_floor(ctx: DecisionContext) -> bool:
    request = ctx.request
    return (
        is_write_action(request.action)
        and ctx.core_category in HUMAN_ONLY_CHANGE_CATEGORIES
        and request.tier < HUMAN_CORE_CHANGE_MIN_TIER
    )


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
        "Changes to policy/allowlist/evaluator/IAM/CI/audit/control plane need tier >= T2.",
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
)
