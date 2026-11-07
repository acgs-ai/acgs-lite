"""Boundary violations through the tool dispatcher chokepoint, plus IAM."""

from __future__ import annotations

from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    GovernedToolDispatcher,
    IAMGrantRejected,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

CORE_TARGETS = [
    "evaluator/score.py",
    "policies/main.yaml",
    "config/tool_allowlist.json",
    ".github/workflows/x.yml",
    "audit/log.jsonl",
    "src/acgs_lite/control_plane/pdp.py",
    "src/acgs_lite/fail_closed.py",
    "data/heldout/test.jsonl",
    "secrets/x",
    "ok/../evaluator/x.py",
    "/etc/passwd",
    "../outside.py",
]
TIERS = {
    "write_file": ActionTier.T1,
    "write_many": ActionTier.T1,
    "read_file": ActionTier.T0,
    "rm": ActionTier.T3,
    "async_tool": ActionTier.T1,
    "async_writer": ActionTier.T1,
}


def grants() -> RepositoryPermissions:
    return RepositoryPermissions(
        DEFAULT_IMMUTABLE_CORE,
        [
            WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",)),
            WriteGrant("alice", PrincipalKind.HUMAN, ("**",)),
        ],
    )


class Recorder:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def write_file(self, path: str, content: str = "") -> str:
        self.calls.append({"path": path, "content": content})
        return "done"

    def write_many(self, paths: list[str], meta: Any = None) -> str:
        self.calls.append({"paths": paths, "meta": meta})
        return "done"


def _dispatcher(
    pdp: PolicyDecisionPoint, permissions: RepositoryPermissions | None = None
) -> tuple[GovernedToolDispatcher, Recorder]:
    recorder = Recorder()
    dispatcher = GovernedToolDispatcher(
        pdp,
        permissions=permissions or grants(),
        tool_tiers=TIERS,
        read_only_tools=frozenset({"read_file", "unlisted_reader"}),
    )
    dispatcher.register(
        "write_file", recorder.write_file, path_params={"path"}, opaque_params={"content"}
    )
    dispatcher.register(
        "write_many", recorder.write_many, path_params={"paths"}, opaque_params={"meta"}
    )
    return dispatcher, recorder


class TestCoreBoundaryViaDispatcher:
    @pytest.mark.parametrize("target", CORE_TARGETS)
    def test_agent_write_to_core_never_invokes_tool(
        self, pdp: PolicyDecisionPoint, agent: Principal, target: str
    ) -> None:
        dispatcher, recorder = _dispatcher(pdp)
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(agent, "write_file", {"path": target, "content": "x"})
        assert recorder.calls == []
        assert not excinfo.value.decision.allowed

    def test_list_and_nested_paths(self, pdp: PolicyDecisionPoint, agent: Principal) -> None:
        dispatcher, recorder = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(agent, "write_many", {"paths": ["workspace/a.py", "secrets/k"]})
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(
                agent, "write_many", {"paths": [], "meta": {"target": "policies/p.yaml"}}
            )
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(agent, "write_many", {"paths": [], "meta": [[{"p": "audit/x"}]]})
        assert recorder.calls == []

    def test_agent_write_outside_core_runs(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        dispatcher, recorder = _dispatcher(pdp)
        result = dispatcher.dispatch(agent, "write_file", {"path": "workspace/x.py"})
        assert result.value == "done"
        assert recorder.calls == [{"path": "workspace/x.py", "content": ""}]
        assert [d.action for d in result.decisions] == ["tool.call", "file.write"]
        assert all(d.allowed for d in result.decisions)

    def test_file_content_is_not_a_path(self, pdp: PolicyDecisionPoint, agent: Principal) -> None:
        dispatcher, recorder = _dispatcher(pdp)
        content = "line one\nsee evaluator/x.py for details\n"
        dispatcher.dispatch(agent, "write_file", {"path": "workspace/x.md", "content": content})
        assert recorder.calls[0]["content"] == content

    def test_read_only_tool_may_read_core(self, pdp: PolicyDecisionPoint, agent: Principal) -> None:
        dispatcher, _ = _dispatcher(pdp)

        def read_file(path: str) -> str:
            return f"read {path}"

        dispatcher.register("read_file", read_file, path_params={"path"})
        result = dispatcher.dispatch(agent, "read_file", {"path": ".github/workflows/ci.yml"})
        assert result.value == "read .github/workflows/ci.yml"
        assert [d.action for d in result.decisions] == ["tool.call", "file.read"]
        assert dispatcher.is_read_only("read_file")
        for sensitive in ("secrets/prod.key", "evaluator/x.py", "eval_suites/a.py"):
            with pytest.raises(ToolDenied) as excinfo:
                dispatcher.dispatch(agent, "read_file", {"path": sensitive})
            assert "INV-CORE-SENSITIVE-READ" in excinfo.value.decision.determining_policies

    def test_unknown_tier_tool_is_a_writer_even_if_marked_read_only(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        dispatcher, _ = _dispatcher(pdp)
        called: list[str] = []

        def unlisted_reader(path: str) -> None:
            called.append(path)

        dispatcher.register("unlisted_reader", unlisted_reader, path_params={"path"})
        assert dispatcher.tier_for("unlisted_reader") is ActionTier.T2
        assert not dispatcher.is_read_only("unlisted_reader")
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(agent, "unlisted_reader", {"path": "evaluator/x.py"})
        assert called == []

    def test_t3_tool_needs_two_humans(self, pdp: PolicyDecisionPoint, human: Principal) -> None:
        dispatcher, _ = _dispatcher(pdp)
        ran: list[bool] = []

        def rm(path: str) -> None:
            ran.append(True)

        dispatcher.register("rm", rm, path_params={"path"})
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(human, "rm", {"path": "workspace/db"})
        assert "INV-T3-TWO-PERSON" in excinfo.value.decision.determining_policies
        approvers = (Principal("bob", PrincipalKind.HUMAN), Principal("carol", PrincipalKind.HUMAN))
        dispatcher.dispatch(human, "rm", {"path": "workspace/db"}, approvers=approvers)
        assert ran == [True]

    @pytest.mark.parametrize(
        ("tool", "args"),
        [
            ("not_registered", {"path": "workspace/x"}),
            ("write_file", {"path": 42}),
            ("write_many", {"paths": ["ok", 3]}),
            ("write_file", "not-a-mapping"),
            ("write_file", {"path": "workspace/x.py", "extra": 1}),
            ("write_file", {}),
            ("write_many", {"paths": [], "meta": object()}),
            (None, {}),
        ],
    )
    def test_pre_pdp_denials(
        self, pdp: PolicyDecisionPoint, agent: Principal, tool: Any, args: Any
    ) -> None:
        dispatcher, recorder = _dispatcher(pdp)
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(agent, tool, args)
        assert recorder.calls == []
        assert excinfo.value.decision.error == "dispatch_denied"
        assert excinfo.value.decision.constitution_hash == pdp.constitution_hash

    def test_non_string_argument_key_denied(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        dispatcher, recorder = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(agent, "write_file", {1: "x"})  # type: ignore[dict-item]
        assert recorder.calls == []

    def test_non_principal_and_bad_approvers_denied(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        dispatcher, recorder = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch("agent-1", "write_file", {"path": "workspace/x"})  # type: ignore[arg-type]
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(agent, "write_file", {"path": "workspace/x.py"}, approvers=3)  # type: ignore[arg-type]
        assert recorder.calls == []

    def test_default_deny_policy_blocks_everything(
        self, constitution: Constitution, agent: Principal
    ) -> None:
        empty = PolicySet.from_mapping({"version": 1, "statements": []})
        with PolicyDecisionPoint.for_constitution(constitution, empty) as pdp:
            dispatcher, recorder = _dispatcher(pdp)
            with pytest.raises(ToolDenied):
                dispatcher.dispatch(agent, "write_file", {"path": "workspace/x.py"})
        assert recorder.calls == []

    def test_registration_rules(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, recorder = _dispatcher(pdp)
        assert dispatcher.tool_names == ("write_file", "write_many")

        def one(path: str) -> None:
            return None

        def varkw(**kwargs: Any) -> None:
            return None

        def varargs(*args: Any) -> None:
            return None

        def posonly(path: str, /) -> None:
            return None

        with pytest.raises(ValueError):
            dispatcher.register("write_file", one, path_params={"path"})
        with pytest.raises(ValueError):
            dispatcher.register("", one, path_params={"path"})
        with pytest.raises(TypeError):
            dispatcher.register("x", "not callable")  # type: ignore[arg-type]
        for bad in (varkw, varargs):
            with pytest.raises(ValueError):
                dispatcher.register("bad", bad)
        with pytest.raises(ValueError):
            dispatcher.register("bad", posonly, path_params={"path"})
        with pytest.raises(ValueError):
            dispatcher.register("bad", one)  # unclassified parameter
        with pytest.raises(ValueError):
            dispatcher.register("bad", one, path_params={"path", "ghost"})
        with pytest.raises(ValueError):
            dispatcher.register("bad", one, path_params={"path"}, opaque_params={"path"})
        with pytest.raises(ValueError):
            dispatcher.register("bad", one, path_params="path")
        with pytest.raises(ValueError):
            dispatcher.register("bad", one, path_params={""})

    def test_constructor_requires_matching_permissions(self, pdp: PolicyDecisionPoint) -> None:
        with pytest.raises(TypeError):
            GovernedToolDispatcher("pdp", permissions=grants(), tool_tiers={})  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            GovernedToolDispatcher(pdp, permissions=None, tool_tiers={})  # type: ignore[arg-type]
        other = RepositoryPermissions(DEFAULT_IMMUTABLE_CORE.with_repo_root("/elsewhere"))
        with pytest.raises(ValueError):
            GovernedToolDispatcher(pdp, permissions=other, tool_tiers={})
        for prefix in ("evaluator/", ".", "../x"):
            with pytest.raises(ValueError):
                GovernedToolDispatcher(
                    pdp, permissions=grants(), tool_tiers={}, scratch_prefixes=(prefix,)
                )

    def test_sync_dispatch_refuses_async_tool(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        dispatcher, _ = _dispatcher(pdp)

        async def async_tool(path: str) -> str:
            return path

        dispatcher.register("async_tool", async_tool, path_params={"path"})
        with pytest.raises(TypeError):
            dispatcher.dispatch(agent, "async_tool", {"path": "workspace/x.py"})


class TestAsyncDispatch:
    async def test_async_tool_runs_when_permitted(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        dispatcher, _ = _dispatcher(pdp)

        async def async_tool(path: str) -> str:
            return f"async {path}"

        dispatcher.register("async_tool", async_tool, path_params={"path"})
        result = await dispatcher.adispatch(agent, "async_tool", {"path": "workspace/x.py"})
        assert result.value == "async workspace/x.py"
        sync_result = await dispatcher.adispatch(agent, "write_file", {"path": "workspace/y.py"})
        assert sync_result.value == "done"

    async def test_async_denial_never_awaits_tool(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        dispatcher, _ = _dispatcher(pdp)
        ran: list[bool] = []

        async def async_writer(path: str) -> None:
            ran.append(True)

        dispatcher.register("async_writer", async_writer, path_params={"path"})
        with pytest.raises(ToolDenied):
            await dispatcher.adispatch(agent, "async_writer", {"path": "evaluator/x.py"})
        assert ran == []


class TestRepositoryPermissions:
    @pytest.mark.parametrize(
        "glob",
        [
            "**",
            "*",
            "*.py",
            "evaluator/**",
            "eval*",
            "src/**",
            ".github/workflows/*",
            "policies/x.yaml",
        ],
    )
    def test_agent_grant_overlapping_core_rejected(self, glob: str) -> None:
        with pytest.raises(IAMGrantRejected):
            RepositoryPermissions(
                DEFAULT_IMMUTABLE_CORE, [WriteGrant("agent-1", PrincipalKind.AGENT, (glob,))]
            )

    def test_human_grant_may_cover_core(self, human: Principal) -> None:
        perms = RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE, [WriteGrant("alice", PrincipalKind.HUMAN, ("**",))]
        )
        assert perms.registry is DEFAULT_IMMUTABLE_CORE
        assert perms.can_write(human, "evaluator/x.py")
        assert not perms.can_write(human, "../outside")

    def test_agent_grant_outside_core(self, agent: Principal) -> None:
        perms = RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE, [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))]
        )
        assert perms.grants[0].path_globs == ("workspace/**",)
        assert perms.can_write(agent, "workspace/a.py")
        assert not perms.can_write(agent, "other/a.py")
        assert not perms.can_write(agent, "workspace/.env")
        assert not perms.can_write(agent, "workspace/../evaluator/x.py")
        impostor = Principal("agent-1", PrincipalKind.HUMAN)
        assert not perms.can_write(impostor, "workspace/a.py")
        assert not perms.can_write("agent-1", "workspace/a.py")  # type: ignore[arg-type]

    def test_grant_matches_canonical_id(self) -> None:
        perms = RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE, [WriteGrant("Agent-1", PrincipalKind.AGENT, ("workspace/**",))]
        )
        assert perms.can_write(Principal("agent-1", PrincipalKind.AGENT), "workspace/a.py")

    def test_no_grant_means_no_write(self, human: Principal) -> None:
        assert not RepositoryPermissions(DEFAULT_IMMUTABLE_CORE).can_write(human, "workspace/a")

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"principal_id": "", "principal_kind": PrincipalKind.AGENT, "path_globs": ("a/**",)},
            {"principal_id": "a", "principal_kind": PrincipalKind.AGENT, "path_globs": ()},
            {
                "principal_id": "a",
                "principal_kind": PrincipalKind.AGENT,
                "path_globs": ("/abs/**",),
            },
            {"principal_id": "a", "principal_kind": PrincipalKind.AGENT, "path_globs": ("a/../b",)},
            {"principal_id": "a", "principal_kind": PrincipalKind.AGENT, "path_globs": (" a",)},
        ],
    )
    def test_invalid_grants(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(IAMGrantRejected):
            WriteGrant(**kwargs)

    def test_grant_string_glob_and_type_checks(self) -> None:
        grant = WriteGrant("a", "agent", "./workspace/**")  # type: ignore[arg-type]
        assert grant.path_globs == ("workspace/**",)
        with pytest.raises(IAMGrantRejected):
            RepositoryPermissions("registry", [])  # type: ignore[arg-type]
        with pytest.raises(IAMGrantRejected):
            RepositoryPermissions(DEFAULT_IMMUTABLE_CORE, ["grant"])  # type: ignore[list-item]


class TestDeniedByBothLayers:
    """IAM and the PDP are separate code paths; each must hold on its own."""

    def test_permissive_pdp_iam_denies_at_dispatch(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        # PDP permits everything outside the core; IAM never granted other/**.
        dispatcher, recorder = _dispatcher(pdp)
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(agent, "write_file", {"path": "other/notes.md"})
        assert "repository permissions deny" in excinfo.value.decision.reason
        assert recorder.calls == []

    def test_iam_grant_exists_pdp_denies_core(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        perms = grants()
        assert perms.can_write(agent, "workspace/x.py")
        dispatcher, recorder = _dispatcher(pdp, perms)
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(
                agent, "write_many", {"paths": ["workspace/x.py", "evaluator/x.py"]}
            )
        assert excinfo.value.decision.error is None  # a PDP forbid, not an IAM denial
        assert recorder.calls == []

    @pytest.mark.parametrize("target", ["evaluator/score.py", "policies/main.yaml"])
    def test_agent_evaluator_and_policy_modification_denied_by_both(
        self, pdp: PolicyDecisionPoint, agent: Principal, target: str
    ) -> None:
        assert not grants().can_write(agent, target)
        dispatcher, recorder = _dispatcher(pdp)
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(agent, "write_file", {"path": target})
        assert recorder.calls == []
        policies = {p for d in excinfo.value.decisions for p in d.determining_policies}
        assert {"INV-CORE-WRITE", "INV-TOOL-ARG-CORE"} <= policies

    def test_iam_module_does_not_import_pdp(self) -> None:
        import ast
        import inspect

        from acgs_lite.control_plane import iam

        tree = ast.parse(inspect.getsource(iam))
        modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        assert not any(m.endswith(("pdp", "policy", "invariants", "dispatcher")) for m in modules)
