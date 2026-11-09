"""Runbook authorization binds both principal identity and kind."""

from typing import Any

import pytest

from acgs_lite.control_plane import DEFAULT_IMMUTABLE_CORE, Principal, PrincipalKind
from acgs_lite.control_plane.runbook import (
    RunbookDenied,
    RunbookRejected,
    parse_runbook,
    runbook_hash,
)

pytestmark = [pytest.mark.unit]


def test_runbook_path_scope_does_not_widen_posix_case(runbook_data: Any, rb: Any) -> None:
    data = runbook_data()
    registry = rb.make(DEFAULT_IMMUTABLE_CORE)
    digest = rb.approve(registry, data)
    arguments = dict(
        tool_name="write_file",
        principal=Principal("agent-1", PrincipalKind.AGENT),
        blast_radius=1,
        consume=False,
    )
    registry.check_execution(data["runbook_id"], digest, paths=["workspace/ok.txt"], **arguments)
    with pytest.raises(RunbookDenied, match="outside the runbook scope"):
        registry.check_execution(
            data["runbook_id"], digest, paths=["Workspace/ok.txt"], **arguments
        )


def test_untyped_scope_requires_reapproval(runbook_data: Any) -> None:
    data = runbook_data()
    data["scope_selector"].pop("principal_kinds", None)
    with pytest.raises(RunbookRejected):
        parse_runbook(data)


@pytest.mark.parametrize("kinds", [[], ["unknown"], [1]])
def test_invalid_kinds_rejected(runbook_data: Any, kinds: list[Any]) -> None:
    data = runbook_data()
    data["scope_selector"]["principal_kinds"] = kinds
    with pytest.raises(RunbookRejected):
        parse_runbook(data)


def test_principal_kind_change_invalidates_approval_hash(runbook_data: Any) -> None:
    data = runbook_data()
    original = runbook_hash(parse_runbook(data))
    data["scope_selector"]["principal_kinds"] = ["human"]
    assert runbook_hash(parse_runbook(data)) != original


@pytest.mark.parametrize("cohort", [False, True])
def test_human_scope_cannot_be_inherited_by_agent(runbook_data: Any, rb: Any, cohort: bool) -> None:
    data = runbook_data()
    data["scope_selector"].update(
        principal_kinds=["human"],
        principals=[] if cohort else ["operator"],
        system_ids=["shared"] if cohort else [],
    )
    registry = rb.make(DEFAULT_IMMUTABLE_CORE)
    digest = rb.approve(registry, data)
    arguments = dict(
        tool_name="write_file", paths=["workspace/ok.txt"], blast_radius=1, consume=False
    )
    registry.check_execution(
        data["runbook_id"],
        digest,
        principal=Principal("operator", PrincipalKind.HUMAN, system_id="shared"),
        **arguments,
    )
    for kind in (PrincipalKind.AGENT, PrincipalKind.SERVICE):
        with pytest.raises(RunbookDenied, match="kind"):
            registry.check_execution(
                data["runbook_id"],
                digest,
                principal=Principal("operator", kind, system_id="shared"),
                **arguments,
            )
