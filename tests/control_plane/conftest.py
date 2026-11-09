"""Shared fixtures for control-plane tests."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
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
def pdp(
    constitution: Constitution, permit_all: PolicySet, tmp_path: Path
) -> Iterator[PolicyDecisionPoint]:
    """A deliberately permissive PDP: only the invariants stand in the way."""
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    with PolicyDecisionPoint.for_constitution(constitution, permit_all, registry=registry) as point:
        yield point
