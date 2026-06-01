"""Drift guard for the repo's machine-readable agent index (U6).

`agent-index.json` (repo root) is authored in the same schema the library's
`AgentRegistry` consumes. These tests load it through the registry so a malformed
or duplicate entry fails CI rather than silently going undiscoverable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acgs_lite.agents import AgentRegistry

_INDEX_PATH = Path(__file__).resolve().parent.parent / "agent-index.json"


@pytest.fixture(scope="module")
def registry() -> AgentRegistry:
    # The index is a committed repo artifact, not an optional extra: a missing file
    # means drift (deleted/moved/renamed), which must fail CI rather than skip.
    assert _INDEX_PATH.exists(), (
        f"agent index missing at {_INDEX_PATH} — it is a committed repo artifact "
        "that backs agent discovery (Layer 2); removing or moving it is drift."
    )
    return AgentRegistry.from_manifest(_INDEX_PATH)


def test_index_loads_with_profiles(registry: AgentRegistry) -> None:
    assert len(registry) >= 1


def test_every_entry_is_valid_and_named(registry: AgentRegistry) -> None:
    for profile in registry.list_profiles(active_only=False):
        assert profile.agent_id.strip()
        assert profile.name.strip()


def test_agent_ids_are_unique(registry: AgentRegistry) -> None:
    ids = [p.agent_id for p in registry.list_profiles(active_only=False)]
    assert len(ids) == len(set(ids)), f"duplicate agent_id in index: {ids}"


def test_governance_review_ranks_first_for_governance_task(registry: AgentRegistry) -> None:
    ranked = registry.candidates_for("review a branch for governance regressions")
    assert ranked, "expected at least one candidate for a governance review task"
    assert ranked[0][0].agent_id == "governance-branch-review"


@pytest.mark.parametrize(
    ("task", "expected_agent_id"),
    (
        ("write documentation for the agent readiness command", "docs"),
        ("prepare a package release and changelog", "release"),
        ("implement a planned code change with tests", "coder"),
        ("research official docs for a framework decision", "researcher"),
    ),
)
def test_added_agent_roles_rank_first_for_representative_tasks(
    registry: AgentRegistry,
    task: str,
    expected_agent_id: str,
) -> None:
    ranked = registry.candidates_for(task)
    assert ranked, f"expected at least one candidate for {task!r}"
    assert ranked[0][0].agent_id == expected_agent_id
