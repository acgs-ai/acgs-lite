"""Shared fixtures for control-plane tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
)

PERMIT_ALL = {
    "version": 1,
    "statements": [
        {"id": "permit-all", "effect": "permit", "actions": ["*"], "resources": ["**"]},
    ],
}


@pytest.fixture()
def constitution() -> Constitution:
    return Constitution.default()


@pytest.fixture()
def permit_all() -> PolicySet:
    return PolicySet.from_mapping(PERMIT_ALL)


@pytest.fixture()
def agent() -> Principal:
    return Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")


@pytest.fixture()
def human() -> Principal:
    return Principal("alice", PrincipalKind.HUMAN)


@pytest.fixture()
def pdp(constitution: Constitution, permit_all: PolicySet) -> Iterator[PolicyDecisionPoint]:
    """A deliberately permissive PDP: only the invariants stand in the way."""
    with PolicyDecisionPoint.for_constitution(constitution, permit_all) as point:
        yield point
