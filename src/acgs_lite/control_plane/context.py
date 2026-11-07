"""Decision requests and the PDP-stamped decision context."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from acgs_lite.control_plane.immutable_core import CoreCategory, ImmutableCoreRegistry
from acgs_lite.control_plane.principal import Principal
from acgs_lite.control_plane.tiers import ActionTier

__all__ = [
    "READ_ONLY_ACTIONS",
    "WRITE_VERBS",
    "DecisionContext",
    "DecisionRequest",
    "is_write_action",
]

INPUTS_DIGEST_DOMAIN = b"acgs-lite/control-plane/decision-request/v1\n"

# Documented mutating verbs. Membership is informational: any action that is
# not in READ_ONLY_ACTIONS is treated as a write (fail closed).
WRITE_VERBS = frozenset(
    {
        "write",
        "delete",
        "create",
        "modify",
        "move",
        "rename",
        "chmod",
        "chown",
        "truncate",
        "append",
        "update",
        "merge",
        "approve",
        "deploy",
        "exec",
        "execute",
        "call",
        "run",
        "push",
        "publish",
        "promote",
        "grant",
        "revoke",
    }
)
# Exact, full-action allowlist. Matching the last dotted segment alone let
# ``file.delete.list`` pass as a read.
# TODO(control-plane-gap): the allowlist is a design inference; extend it per
# deployment rather than loosening the match.
READ_ONLY_ACTIONS = frozenset(
    {
        "file.read",
        "file.list",
        "file.stat",
        "dir.list",
        "repo.read",
        "repo.list",
        "tool.query",
        "db.query",
        "policy.read",
        "audit.read",
        "state.observe",
        "metrics.get",
    }
)


def is_write_action(action: object) -> bool:
    """Return ``False`` only for an action in :data:`READ_ONLY_ACTIONS`
    (compared case-insensitively). Everything else counts as a write."""
    if not isinstance(action, str) or not action:
        return True
    return action.lower() not in READ_ONLY_ACTIONS


@dataclass(frozen=True)
class DecisionRequest:
    """What a principal asks to do. ``action`` is a dotted verb such as
    ``file.write`` or ``tool.call``; ``resource`` is a repo path or a tool name.

    The PDP re-validates every field, so a request mutated after construction
    (for example via ``object.__setattr__``) still fails closed.
    """

    principal: Principal
    action: str
    resource: str
    tier: ActionTier
    approvers: tuple[Principal, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)
    expected_constitution_hash: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "approvers", tuple(self.approvers))
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))

    def canonical(self) -> dict[str, Any]:
        """JSON-ready projection used for :meth:`inputs_digest`."""
        return {
            "principal": self.principal.to_canonical(),
            "action": self.action,
            "resource": self.resource,
            "tier": int(self.tier),
            "approvers": [approver.to_canonical() for approver in self.approvers],
            "attributes": dict(self.attributes),
            "expected_constitution_hash": self.expected_constitution_hash,
        }

    def inputs_digest(self) -> str:
        """SHA-256 over canonical JSON of the request (cited by receipts).

        Raises ``TypeError``/``ValueError`` for attributes that are not plain
        JSON; the PDP turns that into a deny.
        """
        canonical = json.dumps(
            self.canonical(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        return hashlib.sha256(INPUTS_DIGEST_DOMAIN + canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DecisionContext:
    """A request plus the fields only the PDP may stamp."""

    request: DecisionRequest
    constitution_hash: str
    policy_digest: str
    core_category: CoreCategory | None
    registry: ImmutableCoreRegistry
