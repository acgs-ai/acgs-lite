"""Approvals bind the actual built-in container types passed to tools."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from acgs_lite.control_plane import (
    ActionTier,
    GovernedToolDispatcher,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.action_hash import arguments_digest

pytestmark = [pytest.mark.unit, pytest.mark.red_team]
HUMAN = Principal("alice", PrincipalKind.HUMAN)


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "approved,substitute",
    [
        ({"a": 1, "b": 2}, {"b": 2, "a": 1}),
        ([1, 2], (1, 2)),
        ((1, 2), [1, 2]),
        ({1, 2}, frozenset({1, 2})),
        (frozenset({1, 2}), {1, 2}),
    ],
)
async def test_approval_cannot_switch_container_type(
    gated_pdp: Any,
    approver_factory: Any,
    approval_gate: Any,
    asynchronous: bool,
    approved: Any,
    substitute: Any,
) -> None:
    calls = []
    dispatcher = GovernedToolDispatcher(
        gated_pdp,
        permissions=RepositoryPermissions(
            gated_pdp.registry, [WriteGrant(HUMAN.id, HUMAN.kind, ("workspace/**",))]
        ),
        tool_tiers={"edit": ActionTier.T2},
    )

    def tool(path, payload):
        calls.append(payload)

    dispatcher.register("edit", tool, path_params={"path"}, opaque_params={"payload"})
    args = {"path": "workspace/data.txt", "payload": {"nested": approved}}
    approval = approver_factory("bob")(dispatcher.action_hash_for(HUMAN, "edit", args))
    changed = {**args, "payload": {"nested": substitute}}
    with pytest.raises(ToolDenied):
        if asynchronous:
            await dispatcher.adispatch(HUMAN, "edit", changed, approvals=[approval])
        else:
            dispatcher.dispatch(HUMAN, "edit", changed, approvals=[approval])
    assert calls == []
    assert not approval_gate.is_consumed(approval)
    if asynchronous:
        await dispatcher.adispatch(HUMAN, "edit", args, approvals=[approval])
    else:
        dispatcher.dispatch(HUMAN, "edit", args, approvals=[approval])
    assert type(calls[0]["nested"]) is type(approved)
    assert calls[0]["nested"] == approved


def test_container_tags_are_unambiguous_and_order_stable() -> None:
    values = [[1, 2], (1, 2), {1, 2}, frozenset({1, 2}), {"$tuple": [1, 2]}, {"$frozenset": [1, 2]}]
    assert len({arguments_digest({"x": value}) for value in values}) == len(values)
    assert arguments_digest({"x": frozenset((1, 2))}) == arguments_digest({"x": frozenset((2, 1))})
    assert arguments_digest({"x": (1, 2)}) != arguments_digest({"x": (2, 1)})


def test_legacy_ambiguous_approval_digest_is_invalidated() -> None:
    # v1 encoded both {"x": [1, 2]} and {"x": (1, 2)} identically.
    old_message = b'acgs-control-plane-tool-arguments-v1\x00{"$map":[["x",[1,2]]]}'
    old_digest = "sha256:" + hashlib.sha256(old_message).hexdigest()
    assert arguments_digest({"x": [1, 2]}) != old_digest
    assert arguments_digest({"x": (1, 2)}) != old_digest


def test_argument_mapping_order_is_bound() -> None:
    assert arguments_digest({"a": 1, "b": 2}) != arguments_digest({"b": 2, "a": 1})
    assert arguments_digest({"x": {"a": 1, "b": 2}}) != arguments_digest({"x": {"b": 2, "a": 1}})


def test_legacy_order_insensitive_digest_is_invalidated() -> None:
    old_message = b'acgs-control-plane-tool-arguments-v2\x00{"$map":[["a",1],["b",2]]}'
    old_digest = "sha256:" + hashlib.sha256(old_message).hexdigest()
    assert arguments_digest({"a": 1, "b": 2}) != old_digest
    assert arguments_digest({"b": 2, "a": 1}) != old_digest
