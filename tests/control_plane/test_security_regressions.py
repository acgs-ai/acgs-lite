"""Regression tests for the Phase 1 security review (reviewer PoCs poc.py/poc2.py).

Each test reproduces one confirmed bypass. Before the fix every one of these
calls was ALLOWED (see the review PoC output); they must now deny.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    Decision,
    DecisionContext,
    DecisionRequest,
    GovernedToolDispatcher,
    ImmutableCoreRegistry,
    PolicyDecisionPoint,
    PolicyEffect,
    PolicySet,
    PolicyStatement,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
    is_write_action,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

ROOT = Path(__file__).resolve().parents[2]
AGENT = Principal("agent-1", PrincipalKind.AGENT)
HUMAN = Principal("alice", PrincipalKind.HUMAN)


def _permissions(registry: ImmutableCoreRegistry = DEFAULT_IMMUTABLE_CORE) -> RepositoryPermissions:
    return RepositoryPermissions(
        registry,
        [
            WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**", "examples/**", "app/**")),
            WriteGrant("alice", PrincipalKind.HUMAN, ("**",)),
        ],
    )


class Sink:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def record(self, value: Any) -> str:
        self.calls.append(value)
        return "ok"


@pytest.fixture()
def sink() -> Sink:
    return Sink()


@pytest.fixture()
def dispatcher(pdp: PolicyDecisionPoint, sink: Sink) -> GovernedToolDispatcher:
    d = GovernedToolDispatcher(
        pdp,
        permissions=_permissions(pdp.registry),
        tool_tiers={"write": ActionTier.T1, "rm": ActionTier.T1, "shell": ActionTier.T2},
    )

    def write(
        path: str, output_file: str = "", p: str = "", edits: Any = None, args: Any = None
    ) -> str:
        return sink.record(
            {"path": path, "output_file": output_file, "p": p, "edits": edits, "args": args}
        )

    def rm(path: str) -> str:
        return sink.record(path)

    def shell(command: str, cwd: str | None = None) -> str:
        return sink.record((command, cwd))

    d.register(
        "write",
        write,
        path_params={"path"},
        opaque_params={"output_file", "p", "edits", "args"},
    )
    d.register("rm", rm, path_params={"path"})
    d.register("shell", shell, path_params={"cwd"}, command_param="command")
    return d


def _denied(dispatcher: GovernedToolDispatcher, name: str, args: Any, sink: Sink) -> ToolDenied:
    with pytest.raises(ToolDenied) as excinfo:
        dispatcher.dispatch(AGENT, name, args)
    assert sink.calls == []
    return excinfo.value


class TestCritical1PathExtraction:
    def test_kwargs_tool_refused_at_registration(self, dispatcher: GovernedToolDispatcher) -> None:
        def write_file(**kw: Any) -> None:
            return None

        with pytest.raises(ValueError, match=r"\*args/\*\*kwargs"):
            dispatcher.register("write_file", write_file)

    def test_claude_code_style_file_path_tool(
        self, dispatcher: GovernedToolDispatcher, sink: Sink
    ) -> None:
        def write_tool(file_path: str, content: str) -> str:
            return sink.record(file_path)

        dispatcher.register(
            "Write", write_tool, path_params={"file_path"}, opaque_params={"content"}
        )
        args = {"file_path": "src/acgs_lite/control_plane/invariants.py", "content": "X=()"}
        _denied(dispatcher, "Write", args, sink)

    @pytest.mark.parametrize(
        "args",
        [
            {"path": "workspace/x.py", "output_file": "evaluator/x.py"},
            {"path": "workspace/x.py", "p": "src/acgs_lite/control_plane/pdp.py"},
            {"path": "workspace/x.py", "edits": [[{"path": "evaluator/x.py"}]]},
            {"path": "workspace/x.py", "args": ["evaluator/x.py"]},
            {"path": "workspace/x.py", "edits": {"policies/p.yaml": "content"}},
            {"path": "workspace/x.py", "edits": [b"secrets/key"]},
        ],
        ids=["output_file", "short-key", "nested-list-dict", "list-of-str", "dict-key", "bytes"],
    )
    def test_core_string_leaf_anywhere_denies(
        self, dispatcher: GovernedToolDispatcher, sink: Sink, args: dict[str, Any]
    ) -> None:
        denial = _denied(dispatcher, "write", args, sink)
        policies = {p for d in denial.decisions for p in d.determining_policies}
        assert "INV-TOOL-ARG-CORE" in policies

    def test_undeclared_argument_denied(
        self, dispatcher: GovernedToolDispatcher, sink: Sink
    ) -> None:
        _denied(dispatcher, "write", {"path": "workspace/x.py", "file_path": "evaluator/x"}, sink)

    @pytest.mark.parametrize(
        "command",
        [
            # Re-review PoCs: all were ALLOWED with cwd="workspace".
            'cd "$(dirname "$PWD")" && e=evaluat && echo pwn > ${e}or/score.py',
            "touch evalu*/score.py",
            "python3 -c \"open('evalu'+'ator/x.py','w')\"",
            "ls -la",
        ],
    )
    @pytest.mark.parametrize("cwd", [None, "workspace"])
    def test_shell_is_human_only(
        self, dispatcher: GovernedToolDispatcher, sink: Sink, command: str, cwd: str | None
    ) -> None:
        denial = _denied(dispatcher, "shell", {"command": command, "cwd": cwd}, sink)
        assert denial.decision.reason == (
            "shell-like tools are human-only until an OS sandbox mounts the core read-only"
        )
        service = Principal("ci-svc", PrincipalKind.SERVICE)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(service, "shell", {"command": command, "cwd": cwd})
        assert sink.calls == []

    @pytest.mark.parametrize(
        "command",
        [
            "echo pwn > evaluator/score.py",
            "cp x ../src/acgs_lite/fail_closed.py",
            "rm -rf ..",
            "sed -i s/a/b/ ../policies/main.yaml",
            "cat ../secrets/prod.key",
            'python -c \'open("../evaluator/x","w")\'',
        ],
    )
    def test_human_shell_core_tokens_denied(
        self, dispatcher: GovernedToolDispatcher, sink: Sink, command: str
    ) -> None:
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(HUMAN, "shell", {"command": command, "cwd": "workspace"})
        assert "immutable-core" in excinfo.value.decision.reason
        assert sink.calls == []

    def test_human_benign_shell_allowed(
        self, dispatcher: GovernedToolDispatcher, sink: Sink
    ) -> None:
        dispatcher.dispatch(HUMAN, "shell", {"command": "ls -la && echo hi", "cwd": "workspace"})
        assert sink.calls == [("ls -la && echo hi", "workspace")]

    def test_shell_tool_must_be_t2(self, pdp: PolicyDecisionPoint) -> None:
        d = GovernedToolDispatcher(
            pdp, permissions=_permissions(pdp.registry), tool_tiers={"sh": ActionTier.T1}
        )

        def sh(command: str) -> None:
            return None

        with pytest.raises(ValueError, match="tier >= T2"):
            d.register("sh", sh, command_param="command")


class TestHigh2TrustedComputingBase:
    @pytest.mark.parametrize(
        "path",
        [
            "src/acgs_lite/fail_closed.py",
            "src/acgs_lite/audit.py",
            "src/acgs_lite/legitimacy/invocation.py",
            "src/acgs_lite/_compat.py",
            "src/acgs_lite/__init__.py",
            "pyproject.toml",
            "uv.lock",
            "tests/conftest.py",
        ],
    )
    def test_tcb_paths_are_core(self, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.is_core(path)

    def test_fail_closed_write_denied(self, dispatcher: GovernedToolDispatcher, sink: Sink) -> None:
        _denied(dispatcher, "write", {"path": "src/acgs_lite/fail_closed.py"}, sink)

    def test_import_closure_is_core(self) -> None:
        roots = [
            "acgs_lite.control_plane.pdp",
            "acgs_lite.control_plane.dispatcher",
            "acgs_lite.control_plane.invariants",
            "acgs_lite.control_plane.iam",
            "acgs_lite.integrations.control_plane_mcp",
        ]
        code = (
            "import importlib, json, sys\n"
            f"for m in {roots!r}: importlib.import_module(m)\n"
            "print(json.dumps(sorted({getattr(v, '__file__', None) or '' for k, v in "
            "sys.modules.items() if k == 'acgs_lite' or k.startswith('acgs_lite.')})))\n"
        )
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        completed = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env=env,
            check=True,
            timeout=120,
        )
        files = [f for f in json.loads(completed.stdout) if f]
        assert len(files) > 20
        relative = [Path(f).resolve().relative_to(ROOT).as_posix() for f in files]
        uncovered = [path for path in relative if not DEFAULT_IMMUTABLE_CORE.is_core(path)]
        assert uncovered == [], f"import-closure modules missing from the core: {uncovered}"


class TestMedium3Toctou:
    class Flip(Mapping[str, Any]):
        """Returns a benign path on first read, a core path afterwards."""

        def __init__(self) -> None:
            self.reads = 0

        def _value(self) -> str:
            self.reads += 1
            return "workspace/ok.txt" if self.reads == 1 else "evaluator/x.py"

        def __getitem__(self, key: str) -> Any:
            if key != "path":
                raise KeyError(key)
            return self._value()

        def __iter__(self) -> Iterator[str]:
            return iter(["path"])

        def __len__(self) -> int:
            return 1

    def test_flipping_mapping(self, dispatcher: GovernedToolDispatcher, sink: Sink) -> None:
        with pytest.raises(ToolDenied, match="built-in dict"):
            dispatcher.dispatch(AGENT, "rm", self.Flip())
        assert sink.calls == []

    def _mutating_dispatcher(
        self,
        constitution: Constitution,
        permit_all: PolicySet,
        sink: Sink,
        target: list[str],
        tmp_path: Path,
    ) -> tuple[GovernedToolDispatcher, PolicyDecisionPoint]:
        def mutate(decision: Decision) -> None:
            target[0] = "evaluator/x.py"

        pdp = PolicyDecisionPoint.for_constitution(
            constitution,
            permit_all,
            listeners=[mutate],
            registry=DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path)),
        )
        d = GovernedToolDispatcher(
            pdp, permissions=_permissions(pdp.registry), tool_tiers={"many": ActionTier.T1}
        )

        def many(paths: list[str]) -> str:
            return sink.record(list(paths))

        d.register("many", many, path_params={"paths"})
        return d, pdp

    def test_argument_mutated_during_authorisation(
        self, constitution: Constitution, permit_all: PolicySet, sink: Sink, tmp_path: Path
    ) -> None:
        target = ["workspace/a.py"]
        d, pdp = self._mutating_dispatcher(constitution, permit_all, sink, target, tmp_path)
        with pdp:
            d.dispatch(AGENT, "many", {"paths": target})
        assert target == ["evaluator/x.py"]
        assert sink.calls == [["workspace/a.py"]]

    async def test_argument_mutated_during_async_authorisation(
        self, constitution: Constitution, permit_all: PolicySet, sink: Sink, tmp_path: Path
    ) -> None:
        target = ["workspace/a.py"]
        d, pdp = self._mutating_dispatcher(constitution, permit_all, sink, target, tmp_path)
        with pdp:
            await d.adispatch(AGENT, "many", {"paths": target})
        assert sink.calls == [["workspace/a.py"]]

    def test_frozen_tool_spec_ignores_later_mutation(
        self, dispatcher: GovernedToolDispatcher, sink: Sink
    ) -> None:
        dispatcher._read_only_tools = frozenset({"write"})
        dispatcher._tool_tiers["write"] = ActionTier.T0
        _denied(dispatcher, "write", {"path": "evaluator/x.py"}, sink)


class TestMedium4ParentDirectories:
    @pytest.mark.parametrize("path", ["examples", "app", "tests/fixtures", "examples/"])
    def test_parent_of_unanchored_core_pattern_denied(
        self, dispatcher: GovernedToolDispatcher, sink: Sink, path: str
    ) -> None:
        denial = _denied(dispatcher, "rm", {"path": path}, sink)
        assert "directory-like" in denial.decision.reason

    def test_existing_directory_with_dot_denied(
        self, constitution: Constitution, permit_all: PolicySet, tmp_path: Path, sink: Sink
    ) -> None:
        (tmp_path / "app" / "v1.2").mkdir(parents=True)
        (tmp_path / "app" / "notes.txt").write_text("ordinary file")
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        perms = RepositoryPermissions(
            registry, [WriteGrant("agent-1", PrincipalKind.AGENT, ("app/**",))]
        )
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, registry=registry
        ) as pdp:
            d = GovernedToolDispatcher(pdp, permissions=perms, tool_tiers={"rm": ActionTier.T1})

            def rm(path: str) -> str:
                return sink.record(path)

            d.register("rm", rm, path_params={"path"})
            with pytest.raises(ToolDenied):
                d.dispatch(AGENT, "rm", {"path": "app/v1.2"})
            d.dispatch(AGENT, "rm", {"path": "app/notes.txt"})
        assert sink.calls == ["app/notes.txt"]

    def test_scratch_directories_allowed(
        self, dispatcher: GovernedToolDispatcher, sink: Sink
    ) -> None:
        dispatcher.dispatch(AGENT, "rm", {"path": "workspace/build"})
        with pytest.raises(ToolDenied, match="may contain core files"):
            dispatcher.dispatch(AGENT, "rm", {"path": "examples/demo.py"})
        assert sink.calls == ["workspace/build"]


class TestMedium5PrincipalIds:
    @pytest.mark.parametrize(
        "bad", ["Alice ", " alice", "al\nice", "ａlice", "\u0430lice", "al ice", "alice/x", "é"]
    )
    def test_non_canonical_ids_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError, match="canonical"):
            Principal(bad, PrincipalKind.HUMAN)

    @pytest.mark.parametrize(
        ("requester", "approver_ids"),
        [("bob", ("alice", "Alice")), ("bob", ("BOB", "carol")), ("Bob", ("bob", "carol"))],
    )
    def test_t3_compares_canonical_ids(
        self, pdp: PolicyDecisionPoint, requester: str, approver_ids: tuple[str, str]
    ) -> None:
        approvers = tuple(Principal(i, PrincipalKind.HUMAN) for i in approver_ids)
        request = DecisionRequest(
            Principal(requester, PrincipalKind.HUMAN), "db.drop", "prod", ActionTier.T3, approvers
        )
        decision = pdp.decide(request)
        assert not decision.allowed
        assert "INV-T3-TWO-PERSON" in decision.determining_policies


class TestMedium6SensitiveRead:
    @pytest.mark.parametrize(
        ("action", "resource"),
        [
            ("file.read", "secrets/prod.key"),
            ("file.read", "heldout/test.jsonl"),
            ("file.stat", "svc/.env"),
        ],
    )
    def test_agent_read_denied(self, pdp: PolicyDecisionPoint, action: str, resource: str) -> None:
        decision = pdp.decide(DecisionRequest(AGENT, action, resource, ActionTier.T0))
        assert not decision.allowed
        assert "INV-CORE-SENSITIVE-READ" in decision.determining_policies

    def test_human_read_and_agent_policy_read_allowed(self, pdp: PolicyDecisionPoint) -> None:
        assert pdp.decide(
            DecisionRequest(HUMAN, "file.read", "secrets/prod.key", ActionTier.T0)
        ).allowed
        assert pdp.decide(
            DecisionRequest(AGENT, "file.read", "policies/main.yaml", ActionTier.T0)
        ).allowed

    @pytest.mark.parametrize("resource", ["evaluator/score.py", "evals/x.yaml", "eval_suites/a.py"])
    def test_agent_cannot_read_the_grader(self, pdp: PolicyDecisionPoint, resource: str) -> None:
        decision = pdp.decide(DecisionRequest(AGENT, "file.read", resource, ActionTier.T0))
        assert not decision.allowed
        assert "INV-CORE-SENSITIVE-READ" in decision.determining_policies


class TestLow8ExactReadAllowlist:
    @pytest.mark.parametrize(
        "action", ["file.delete.list", "file.get", "x.read", "file.read.write"]
    )
    def test_smuggled_verbs_are_writes(self, pdp: PolicyDecisionPoint, action: str) -> None:
        assert is_write_action(action)
        decision = pdp.decide(DecisionRequest(AGENT, action, "evaluator/x.py", ActionTier.T1))
        assert not decision.allowed
        assert "INV-CORE-WRITE" in decision.determining_policies


class TestLow9McpReference:
    async def test_mcp_denial_hides_reason_but_audit_keeps_it(
        self, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        pytest.importorskip("mcp")
        from mcp import Client, types
        from mcp.server import Server

        from acgs_lite.integrations.control_plane_mcp import make_mcp_call_tool_handler

        log = AuditLog()
        with PolicyDecisionPoint.for_constitution(constitution, permit_all, audit_log=log) as pdp:
            d = GovernedToolDispatcher(
                pdp, permissions=_permissions(), tool_tiers={"w": ActionTier.T1}
            )

            def w(path: str) -> str:
                return path

            d.register("w", w, path_params={"path"})

            async def list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
                tool = types.Tool(name="w", description="w", input_schema={"type": "object"})
                return types.ListToolsResult(tools=[tool])

            server = Server(
                "t",
                on_list_tools=list_tools,
                on_call_tool=make_mcp_call_tool_handler(d, lambda c: AGENT),
            )
            async with Client(server) as client:
                result = await client.call_tool("w", {"path": "evaluator/x.py"})
        text = result.content[0].text
        match = re.fullmatch(r"denied \(ref ([0-9a-f]{12})\)", text)
        assert match is not None
        assert "INV" not in text and "evaluator" not in text
        denied = [e for e in log.entries if not e.valid]
        assert any(
            e.metadata["decision_id"].startswith(match.group(1)) and "INV-" in e.metadata["reason"]
            for e in denied
        )


class TestLow10Normalisation:
    @pytest.mark.parametrize(
        "path",
        [
            "evaluator%2fx",
            "ｅvaluator/x",
            "evaluator./x",
            "evaluator /x",
            "evaluator.../x",
            "évaluator/x",
        ],
    )
    def test_lookalike_and_encoded_paths_are_core(self, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.is_core(path)


class TestReviewExtras:
    def test_condition_exception_text_not_in_reason(self, constitution: Constitution) -> None:
        def boom(ctx: DecisionContext) -> bool:
            raise RuntimeError("SECRET=hunter2 at /etc/x")

        policy = PolicySet.from_statements(
            [PolicyStatement("b", PolicyEffect.PERMIT, None, ("*",), ("**",), condition=boom)]
        )
        with PolicyDecisionPoint.for_constitution(constitution, policy) as pdp:
            decision = pdp.decide(DecisionRequest(AGENT, "x.run", "ok", ActionTier.T1))
        assert not decision.allowed
        assert "hunter2" not in decision.reason
        assert "RuntimeError" in decision.reason

    def test_backstop_decisions_get_distinct_ids(
        self, pdp: PolicyDecisionPoint, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(*args: Any) -> Any:
            raise RuntimeError("x")

        monkeypatch.setattr(pdp, "_get_executor", explode)
        first = pdp.decide(DecisionRequest(AGENT, "x.run", "ok", ActionTier.T1))
        second = pdp.decide(DecisionRequest(AGENT, "x.run", "ok", ActionTier.T1))
        assert first.error == second.error == "fail_closed"
        assert first.decision_id != second.decision_id

    def test_saturated_executor_denies_quickly(self, constitution: Constitution) -> None:
        def slow(ctx: DecisionContext) -> bool:
            time.sleep(0.5)
            return False

        policy = PolicySet.from_statements(
            [PolicyStatement("s", PolicyEffect.FORBID, None, ("*",), ("**",), condition=slow)]
        )
        with PolicyDecisionPoint.for_constitution(
            constitution, policy, max_workers=1, timeout_s=0.05
        ) as pdp:
            decisions = [
                pdp.decide(DecisionRequest(AGENT, "x.run", "ok", ActionTier.T1)) for _ in range(3)
            ]
        assert all(not d.allowed and d.error == "timeout" for d in decisions)
