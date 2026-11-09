"""Action hashes: the exact thing a signed approval approves.

An approval that names only a tool or an action can be replayed against
different arguments, so every approval is bound to ``action_hash(request)``:
SHA-256 (domain ``acgs-control-plane-action-v1``) over canonical JSON of the
requester (canonical id, kind, system id), the action, the resource, the tier
and a digest of the attributes. Approvers are excluded so an approval can be
signed before it is attached to the request it approves.

Dispatcher sub-requests (one ``file.write``/``file.read`` per path a tool
touches) carry their parent ``tool.call`` attributes under ``"tool_call"``;
:func:`approval_subject` rebuilds that parent so one approval of the tool call
covers the paths derived from the same arguments, and nothing else.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeAlias

import acgs_lite.control_plane.context as context_types

if TYPE_CHECKING:
    DecisionRequest: TypeAlias = "context_types.DecisionRequest"

__all__ = [
    "ACTION_HASH_DOMAIN",
    "MAX_CANONICAL_DEPTH",
    "action_hash",
    "approval_subject",
    "arguments_digest",
    "attributes_digest",
    "canonical_json",
]

ACTION_HASH_DOMAIN = b"acgs-control-plane-action-v1\x00"
_ATTRIBUTES_DOMAIN = b"acgs-control-plane-action-attributes-v1\x00"
_ARGUMENTS_DOMAIN = b"acgs-control-plane-tool-arguments-v4\x00"
MAX_CANONICAL_DEPTH = 32
_SUB_REQUEST_ACTIONS = frozenset({"file.read", "file.write"})


def canonical_json(value: object) -> str:
    """Deterministic JSON (sorted keys, no NaN); raises for non-JSON values."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _sha256(domain: bytes, text: str) -> str:
    return "sha256:" + hashlib.sha256(domain + text.encode("utf-8")).hexdigest()


def attributes_digest(attributes: Mapping[str, Any]) -> str:
    """Digest of plain-JSON attributes (raises ``TypeError``/``ValueError`` otherwise)."""
    return _sha256(_ATTRIBUTES_DOMAIN, canonical_json(dict(attributes)))


def _canonical_value(value: object, depth: int = 0, seen_mutable: set[int] | None = None) -> object:
    if depth > MAX_CANONICAL_DEPTH:
        raise ValueError("arguments nested too deeply")
    if seen_mutable is None:
        seen_mutable = set()
    if isinstance(value, (Mapping, list, set)):
        identity = id(value)
        if identity in seen_mutable:
            raise ValueError("aliased mutable argument containers are not supported")
        # Keep identities across sibling branches, not only along the recursion
        # stack: deepcopy preserves shared objects as well as actual cycles.
        seen_mutable.add(identity)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite float argument")
        return value
    if isinstance(value, bytes):
        return {"$bytes": value.hex()}
    if isinstance(value, Mapping):
        items = [
            [
                _canonical_value(k, depth + 1, seen_mutable),
                _canonical_value(v, depth + 1, seen_mutable),
            ]
            for k, v in value.items()
        ]
        return {"$map": items}
    if isinstance(value, list):
        return [_canonical_value(item, depth + 1, seen_mutable) for item in value]
    if isinstance(value, tuple):
        return {"$tuple": [_canonical_value(item, depth + 1, seen_mutable) for item in value]}
    if isinstance(value, (set, frozenset)):
        tag = "$frozenset" if isinstance(value, frozenset) else "$set"
        return {
            tag: sorted(
                (_canonical_value(i, depth + 1, seen_mutable) for i in value), key=canonical_json
            )
        }
    raise TypeError(f"unsupported argument type {type(value).__name__}")


def arguments_digest(arguments: Mapping[str, Any]) -> str:
    """Digest of tool arguments, preserving list/tuple and set/frozenset identity.

    Tuples and frozensets have distinct tags because invocation preserves
    these types. Mapping entries preserve insertion order because tools can
    observe it, including through **kwargs. Mappings are tagged separately,
    so user keys cannot imitate a container tag. Shared mutable containers
    and cycles are rejected: the value encoding cannot describe their alias
    relationships, which deepcopy would preserve for invocation. Repeated
    immutable values remain supported. The v4 domain invalidates approvals
    made before alias rejection; they must be issued again.
    """
    return _sha256(_ARGUMENTS_DOMAIN, canonical_json(_canonical_value(dict(arguments))))


def approval_subject(request: DecisionRequest) -> DecisionRequest:
    """The request an approval must be bound to.

    A dispatcher sub-request (``file.read``/``file.write`` whose
    ``attributes["tool_call"]`` lists ``request.resource`` among its paths)
    resolves to its parent ``tool.call``; every other request is its own
    subject.
    """
    # TODO(control-plane-gap): a host that builds DecisionRequests directly
    # can attach a ``tool_call`` parent to a path write; the approval then
    # covers only paths the approved tool call itself lists. Agents never
    # build DecisionRequests on the governed (dispatcher) path.
    attributes = request.attributes
    via_tool = attributes.get("via_tool")
    tool_call = attributes.get("tool_call")
    if (
        isinstance(request.action, str)
        and request.action.lower() in _SUB_REQUEST_ACTIONS
        and isinstance(via_tool, str)
        and isinstance(tool_call, Mapping)
    ):
        paths = tool_call.get("paths")
        # The child must be the operation the approved tool performs: a
        # read-only tool's approval never covers a write (and vice versa).
        expected_child = "file.read" if tool_call.get("tool_read_only") is True else "file.write"
        if (
            isinstance(paths, list)
            and request.resource in paths
            and request.action.lower() == expected_child
        ):
            return context_types.DecisionRequest(
                principal=request.principal,
                action="tool.call",
                resource=via_tool,
                tier=request.tier,
                attributes=dict(tool_call),
            )
    return request


def action_hash(request: DecisionRequest) -> str:
    """``"sha256:<hex>"`` binding an approval to *request* (approvers excluded).

    Raises ``TypeError``/``ValueError`` for attributes that are not plain
    JSON; :class:`~acgs_lite.control_plane.approvals.ApprovalGate` then
    rejects every approval (fail closed).
    """
    subject = approval_subject(request)
    principal = subject.principal
    payload = {
        "principal": {
            "id": principal.canonical_id,
            "kind": principal.kind.value,
            "system_id": principal.system_id,
        },
        "action": subject.action,
        "resource": subject.resource,
        "tier": int(subject.tier),
        "attributes_digest": attributes_digest(subject.attributes),
    }
    return _sha256(ACTION_HASH_DOMAIN, canonical_json(payload))
