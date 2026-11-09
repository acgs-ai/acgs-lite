"""Approvals must not equate independent containers with mutable aliases."""

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


@pytest.mark.parametrize("kind", [list, dict, set])
@pytest.mark.parametrize("nested", [False, True])
def test_mutable_aliases_are_rejected(kind: Any, nested: bool) -> None:
    shared = kind()
    left = (shared,) if nested else shared
    right = {"inner": shared} if nested else shared
    with pytest.raises(ValueError, match="aliased mutable"):
        arguments_digest({"left": left, "right": right})
    # Equal but independent containers are valid.
    arguments_digest({"left": kind(), "right": kind()})


@pytest.mark.parametrize("kind", [list, dict])
def test_mutable_cycles_are_rejected(kind: Any) -> None:
    cyclic = kind()
    if kind is list:
        cyclic.append((cyclic,))
    else:
        cyclic["self"] = cyclic
    with pytest.raises(ValueError, match="aliased mutable"):
        arguments_digest({"payload": cyclic})


def test_immutable_repeated_values_remain_valid() -> None:
    shared = (1, 2)
    assert arguments_digest({"left": shared, "right": shared})
    assert arguments_digest({"left": "value", "right": "value"})


def test_legacy_alias_ambiguous_digest_is_invalidated() -> None:
    message = b'acgs-control-plane-tool-arguments-v3\x00{"$map":[["left",[]],["right",[]]]}'
    old = "sha256:" + hashlib.sha256(message).hexdigest()
    assert arguments_digest({"left": [], "right": []}) != old


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async_sync", "async_coroutine"])
@pytest.mark.parametrize("kind", [list, dict, set])
@pytest.mark.parametrize("cycle", [False, True])
async def test_alias_substitution_denied_without_consuming_approval(
    gated_pdp: Any,
    approver_factory: Any,
    approval_gate: Any,
    mode: str,
    kind: Any,
    cycle: bool,
) -> None:
    calls = []
    dispatcher = GovernedToolDispatcher(
        gated_pdp,
        permissions=RepositoryPermissions(
            gated_pdp.registry, [WriteGrant(HUMAN.id, HUMAN.kind, ("workspace/**",))]
        ),
        tool_tiers={"edit": ActionTier.T2},
        trust_host_identity=True,
    )

    def edit(path, left, right):
        if kind is list:
            left[0].append(1)
        elif kind is dict:
            left[0][1] = 2
        else:
            left[0].add(1)
        calls.append(bool(right["inner"]))

    async def aedit(path, left, right):
        edit(path, left, right)

    dispatcher.register(
        "edit",
        aedit if mode == "async_coroutine" else edit,
        path_params={"path"},
        opaque_params={"left", "right"},
        merge_capable=False,
    )
    args = {"path": "workspace/data.txt", "left": (kind(),), "right": {"inner": kind()}}
    approval = approver_factory("bob")(dispatcher.action_hash_for(HUMAN, "edit", args))
    shared = kind()
    if cycle:
        # The wrapper can cycle even when the aliased leaf is a set.
        wrapper = [shared]
        wrapper.append(wrapper)
        changed = {**args, "left": wrapper, "right": {"inner": shared}}
    else:
        changed = {**args, "left": (shared,), "right": {"inner": shared}}

    async def invoke(arguments):
        if mode == "sync":
            return dispatcher.dispatch(HUMAN, "edit", arguments, approvals=[approval])
        return await dispatcher.adispatch(HUMAN, "edit", arguments, approvals=[approval])

    with pytest.raises(ToolDenied):
        await invoke(changed)
    assert not calls
    assert not approval_gate.is_consumed(approval)
    await invoke(args)
    assert calls == [False]
    assert approval_gate.is_consumed(approval)
