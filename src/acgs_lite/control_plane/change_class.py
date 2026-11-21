"""Change classes: which writes only a human may make.

Phase 1 expressed "human-only" as a tier floor (INV-CORE-HUMAN-ONLY-CHANGE),
which a human could meet alone. Phase 3 makes edits to the things that judge
or constrain an agent -- constitution/policy, tool allowlist, evaluator and
its suites, held-out data, IAM, CI rules, audit log, control plane, promotion
gate, sandbox config and the memory-write policy -- a distinct
:attr:`ChangeClass.CORE_HUMAN_ONLY` class: a HUMAN requester at tier >= T2
*plus* a signed approval from a different human, attested by an
:class:`~acgs_lite.control_plane.approvals.ApprovalGate`
(INV-HUMAN-ONLY-CHANGE-CLASS). There is no agent, service, sibling or
self-approval path.

Evidence: STOP -- agents disabled their own sandbox flag and a prompt warning
did not reduce the rate, so the restriction is enforced by the harness, not
the model; Replit -- an agent destroyed production state during a freeze, so
a second human must approve.
"""

from __future__ import annotations

from acgs_lite._compat import StrEnum
from acgs_lite.control_plane.context import DecisionRequest, is_write_action
from acgs_lite.control_plane.immutable_core import CoreCategory, ImmutableCoreRegistry

__all__ = [
    "CORE_HUMAN_ONLY_CATEGORIES",
    "OPERATIONAL_ACTIONS",
    "ChangeClass",
    "classify_category",
    "classify_change",
]


class ChangeClass(StrEnum):
    ROUTINE = "routine"
    CORE_HUMAN_ONLY = "core_human_only"


# Credentials are excluded on purpose: agents may neither read nor write them
# (INV-CORE-SENSITIVE-READ, INV-CORE-WRITE) and rotation is an IAM concern.
# TODO(control-plane-gap): category membership is design inference.
CORE_HUMAN_ONLY_CATEGORIES = frozenset(
    {
        CoreCategory.POLICY,
        CoreCategory.TOOL_ALLOWLIST,
        CoreCategory.EVALUATOR,
        CoreCategory.TEST_SUITE,
        CoreCategory.HELDOUT_DATA,
        CoreCategory.IAM,
        CoreCategory.CI_RULES,
        CoreCategory.AUDIT_LOG,
        CoreCategory.CONTROL_PLANE,
        CoreCategory.PROMOTION_GATE,
        CoreCategory.SANDBOX_CONFIG,
        CoreCategory.MEMORY_WRITE_POLICY,
    }
)


# Operating a core component through its own governed entry point is not a
# change *to* it: ``promotion.promote`` is gated by PromotionGate (external
# evidence + approvers), whereas writing promotion/** edits the gate.
OPERATIONAL_ACTIONS = frozenset({"promotion.promote"})


def classify_category(action: object, category: CoreCategory | None) -> ChangeClass:
    """Pure classification from an action and its PDP-stamped core category."""
    if isinstance(action, str) and action.lower() in OPERATIONAL_ACTIONS:
        return ChangeClass.ROUTINE
    if is_write_action(action) and category in CORE_HUMAN_ONLY_CATEGORIES:
        return ChangeClass.CORE_HUMAN_ONLY
    return ChangeClass.ROUTINE


def classify_change(request: DecisionRequest, registry: ImmutableCoreRegistry) -> ChangeClass:
    """Classify *request* the way the PDP does (namespace first, then path)."""
    from acgs_lite.control_plane.invariants import core_category_for

    return classify_category(request.action, core_category_for(request, registry))
