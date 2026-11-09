"""Control plane for self-improving agents (Phase 1: immutable core).

Mutating agents must never be able to write to the things that judge them.
The immutable core is protected twice, by independent code paths:

* the policy engine (:class:`PolicyDecisionPoint` with non-overridable
  :data:`CONSTITUTION_INVARIANTS`, enforced at the
  :class:`GovernedToolDispatcher` chokepoint); and
* repository permissions (:class:`RepositoryPermissions`, a generated
  CODEOWNERS file and the ``immutable-core-guard`` CI workflow).

Import from ``acgs_lite.control_plane``; nothing here is re-exported from the
top-level ``acgs_lite`` package.
"""

from __future__ import annotations

from acgs_lite.control_plane.context import (
    READ_ONLY_ACTIONS,
    WRITE_VERBS,
    DecisionContext,
    DecisionRequest,
    is_write_action,
)
from acgs_lite.control_plane.dispatcher import GovernedToolDispatcher, ToolDenied, ToolResult
from acgs_lite.control_plane.iam import (
    IAMGrantRejected,
    RepositoryPermissions,
    WriteGrant,
    render_codeowners,
)
from acgs_lite.control_plane.immutable_core import (
    DEFAULT_IMMUTABLE_CORE,
    CoreCategory,
    ImmutableCoreError,
    ImmutableCoreRegistry,
    normalize_path,
)
from acgs_lite.control_plane.invariants import CONSTITUTION_INVARIANTS
from acgs_lite.control_plane.pdp import (
    Decision,
    PolicyDecisionPoint,
    PolicyEffect,
    PolicyParseError,
    PolicySet,
    PolicyStatement,
)
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.tiers import ActionTier

__all__ = [
    "CONSTITUTION_INVARIANTS",
    "DEFAULT_IMMUTABLE_CORE",
    "READ_ONLY_ACTIONS",
    "WRITE_VERBS",
    "ActionTier",
    "CoreCategory",
    "Decision",
    "DecisionContext",
    "DecisionRequest",
    "GovernedToolDispatcher",
    "IAMGrantRejected",
    "ImmutableCoreError",
    "ImmutableCoreRegistry",
    "PolicyDecisionPoint",
    "PolicyEffect",
    "PolicyParseError",
    "PolicySet",
    "PolicyStatement",
    "Principal",
    "PrincipalKind",
    "RepositoryPermissions",
    "ToolDenied",
    "ToolResult",
    "WriteGrant",
    "is_write_action",
    "normalize_path",
    "render_codeowners",
]
