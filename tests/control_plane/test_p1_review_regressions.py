"""Regression tests for the PR #237 (phase 1) review threads.

Each test names the thread it pins. Before the fix every "denied" case below
was allowed (or the configuration was silently accepted).
"""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    CoreCategory,
    DecisionRequest,
    GovernedToolDispatcher,
    IAMGrantRejected,
    PolicyDecisionPoint,
    PolicyEffect,
    PolicySet,
    PolicyStatement,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
    render_codeowners,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

AGENT = Principal("agent-1", PrincipalKind.AGENT)
HUMAN = Principal("alice", PrincipalKind.HUMAN)
SCOPED_HUMAN = Principal("bob", PrincipalKind.HUMAN)


def _permissions() -> RepositoryPermissions:
    return RepositoryPermissions(
        DEFAULT_IMMUTABLE_CORE,
        [
            WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**", "app/**")),
            WriteGrant("alice", PrincipalKind.HUMAN, ("**",)),
            WriteGrant("bob", PrincipalKind.HUMAN, ("workspace/**",)),
        ],
    )


class _Sink:
    def __init__(self) -> None:
        self.calls: list[Any] = []


@pytest.fixture()
def pdp(gated_pdp: PolicyDecisionPoint) -> PolicyDecisionPoint:
    # The shell tool is T2, which needs an ApprovalGate on the PDP (Phase 3).
    return gated_pdp


def _dispatcher(pdp: PolicyDecisionPoint) -> tuple[GovernedToolDispatcher, _Sink]:
    sink = _Sink()
    d = GovernedToolDispatcher(
        pdp,
        permissions=_permissions(),
        tool_tiers={
            "write_default": ActionTier.T1,
            "read_default": ActionTier.T1,
            "write": ActionTier.T1,
            "read": ActionTier.T1,
            "shell": ActionTier.T2,
        },
        read_only_tools=frozenset({"read_default", "read"}),
    )

    def write_default(path: str = "evaluator/score.py", content: str = "x") -> None:
        sink.calls.append(("write_default", path, content))

    def read_default(path: str = "secrets/token.txt") -> None:
        sink.calls.append(("read_default", path))

    def write(path: str, content: str = "", output_file: str = "") -> None:
        sink.calls.append(("write", path, content, output_file))

    def read(path: str) -> None:
        sink.calls.append(("read", path))

    def shell(command: str, cwd: str | None = None) -> None:
        sink.calls.append(("shell", command, cwd))

    d.register(
        "write_default",
        write_default,
        path_params={"path"},
        opaque_params={"content"},
        merge_capable=False,
    )
    d.register("read_default", read_default, path_params={"path"}, merge_capable=False)
    d.register(
        "write",
        write,
        path_params={"path"},
        opaque_params={"content", "output_file"},
        merge_capable=False,
    )
    d.register("read", read, path_params={"path"}, merge_capable=False)
    d.register("shell", shell, path_params={"cwd"}, command_param="command", merge_capable=False)
    return d, sink


class TestSignatureDefaultsAreAuthorised:
    """237.1 / 237.5: omitted arguments with core defaults skipped the PDP."""

    def test_defaulted_core_write_path_is_denied(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(AGENT, "write_default", {})
        assert sink.calls == []
        assert not excinfo.value.decision.allowed

    def test_defaulted_sensitive_read_path_is_denied(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(AGENT, "read_default", {})
        assert sink.calls == []

    def test_defaults_are_in_the_authorised_decisions(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, sink = _dispatcher(pdp)
        # The explicit override is fine; the decision set names the real path.
        result = dispatcher.dispatch(AGENT, "write_default", {"path": "workspace/a.py"})
        assert sink.calls == [("write_default", "workspace/a.py", "x")]
        assert any(d.resource == "workspace/a.py" for d in result.decisions)


class TestOverlappingCategories:
    """237.2 / 237.7: credentials that also match an earlier category."""

    @pytest.mark.parametrize("path", ["policies/.env", "policies/.env.production", "sandbox/.env"])
    def test_agent_read_of_overlapping_credential_denied(
        self, pdp: PolicyDecisionPoint, path: str
    ) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(AGENT, "read", {"path": path})
        assert sink.calls == []
        assert "INV-CORE-SENSITIVE-READ" in excinfo.value.decision.determining_policies

    def test_categories_reports_every_match(self) -> None:
        assert DEFAULT_IMMUTABLE_CORE.categories("policies/.env") == frozenset(
            {CoreCategory.POLICY, CoreCategory.CREDENTIALS}
        )
        # Display precedence is unchanged.
        assert DEFAULT_IMMUTABLE_CORE.classify("policies/.env") is CoreCategory.POLICY

    def test_human_only_floor_applies_to_any_matching_category(
        self, pdp: PolicyDecisionPoint
    ) -> None:
        # sandbox/constitution.yaml is SANDBOX_CONFIG first but also POLICY,
        # which needs tier >= T2 even for humans.
        decision = pdp.decide(
            DecisionRequest(HUMAN, "file.write", "sandbox/constitution.yaml", ActionTier.T1)
        )
        assert not decision.allowed
        assert "INV-CORE-HUMAN-ONLY-CHANGE" in decision.determining_policies


class TestShellNeedsUnrestrictedGrant:
    """237.3: a path-scoped human grant cannot be enforced on shell commands."""

    def test_scoped_human_shell_denied(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied) as excinfo:
            dispatcher.dispatch(
                SCOPED_HUMAN, "shell", {"command": "touch app/x.txt", "cwd": "workspace"}
            )
        assert sink.calls == []
        assert "unrestricted" in excinfo.value.decision.reason

    def test_unrestricted_human_shell_allowed(
        self, pdp: PolicyDecisionPoint, approver_factory: Any
    ) -> None:
        pytest.importorskip("cryptography")
        dispatcher, sink = _dispatcher(pdp)
        args = {"command": "ls -la", "cwd": "workspace"}
        approval = approver_factory("bob")(dispatcher.action_hash_for(HUMAN, "shell", args))
        dispatcher.dispatch(HUMAN, "shell", args, approvals=[approval])
        assert sink.calls == [("shell", "ls -la", "workspace")]

    def test_has_unrestricted_write_matches_id_and_kind(self) -> None:
        perms = _permissions()
        assert perms.has_unrestricted_write(HUMAN)
        assert not perms.has_unrestricted_write(SCOPED_HUMAN)
        assert not perms.has_unrestricted_write(Principal("alice", PrincipalKind.AGENT))


class TestRequestAttributesAreOwned:
    """237.4: nested attribute values were shared with the caller."""

    def test_caller_mutation_after_construction_does_not_change_request(self) -> None:
        nested = {"paths": ["workspace/a.py"]}
        request = DecisionRequest(AGENT, "tool.call", "write", ActionTier.T1, attributes=nested)
        before = request.inputs_digest()
        nested["paths"].append("evaluator/x.py")
        assert request.attributes["paths"] == ["workspace/a.py"]
        assert request.inputs_digest() == before

    def test_pdp_evaluates_its_own_snapshot(
        self, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        seen: list[Any] = []
        gate = threading.Event()
        release = threading.Event()

        def condition(ctx: Any) -> bool:
            gate.set()
            release.wait(5)
            seen.append(list(ctx.request.attributes["paths"]))
            return True

        policy = PolicySet(
            (
                *permit_all.statements,
                PolicyStatement(
                    id="observe",
                    effect=PolicyEffect.PERMIT,
                    principal_kinds=None,
                    actions=("*",),
                    resources=("**",),
                    condition=condition,
                ),
            ),
            source_digest="test-observe",
        )
        request = DecisionRequest(
            AGENT, "tool.call", "write", ActionTier.T1, attributes={"paths": ["workspace/a.py"]}
        )
        with PolicyDecisionPoint.for_constitution(constitution, policy) as pdp:
            result: list[Any] = []
            worker = threading.Thread(target=lambda: result.append(pdp.decide(request)))
            worker.start()
            assert gate.wait(5)
            # Mutating the caller's request mid-evaluation must not reach the PDP.
            request.attributes["paths"].append("evaluator/x.py")
            release.set()
            worker.join(5)
        assert seen == [["workspace/a.py"]]
        assert result and result[0].allowed


class TestModuleShadowsAreCore:
    """237.6 / 237.13: package dirs / extensions shadowing trusted modules."""

    @pytest.mark.parametrize(
        "path",
        [
            "src/acgs_lite/fail_closed/__init__.py",
            "src/acgs_lite/fail_closed",
            "src/acgs_lite/fail_closed.so",
            "src/acgs_lite/fail_closed.cpython-311-x86_64-linux-gnu.so",
            "src/acgs_lite/__pycache__/fail_closed.cpython-311.pyc",
            "src/acgs_lite/audit/__init__.py",
            "src/acgs_lite/__init__.cpython-311-x86_64-linux-gnu.so",
        ],
    )
    def test_shadow_paths_classify_core(self, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify(path) is CoreCategory.CONTROL_PLANE

    def test_unrelated_sibling_is_not_core(self) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify("src/acgs_lite/unrelated.py") is None

    @pytest.mark.parametrize(
        "glob",
        ["src/acgs_lite/fail_closed/**", "src/acgs_lite/fail_closed.so", "src/acgs_lite/audit*"],
    )
    def test_agent_grant_on_shadow_rejected(self, glob: str) -> None:
        with pytest.raises(IAMGrantRejected):
            RepositoryPermissions(
                DEFAULT_IMMUTABLE_CORE, [WriteGrant("a", PrincipalKind.AGENT, (glob,))]
            )

    def test_agent_write_to_shadow_denied_at_dispatch(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(AGENT, "write", {"path": "src/acgs_lite/fail_closed/__init__.py"})
        assert sink.calls == []

    def test_codeowners_lists_shadows(self) -> None:
        text = render_codeowners(DEFAULT_IMMUTABLE_CORE, ["@o"])
        assert "/src/acgs_lite/fail_closed/** @o" in text
        assert "/src/acgs_lite/fail_closed.* @o" in text

    def test_shadows_are_not_in_the_manifest(self) -> None:
        mapping = DEFAULT_IMMUTABLE_CORE.to_mapping()
        flat = {p for pats in mapping["categories"].values() for p in pats}
        assert "src/acgs_lite/fail_closed/**" not in flat


class TestLeafScanner:
    """237.9 / 237.11: empty content and whitespace-padded core paths."""

    def test_empty_content_is_not_a_core_path(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, sink = _dispatcher(pdp)
        dispatcher.dispatch(AGENT, "write", {"path": "workspace/x.py", "content": ""})
        assert sink.calls == [("write", "workspace/x.py", "", "")]

    def test_empty_declared_path_still_denied(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(AGENT, "write", {"path": ""})
        assert sink.calls == []

    @pytest.mark.parametrize(
        "padded", [" evaluator/x.py", "evaluator/x.py ", " policies/p.yaml", "\tsecrets/k\n"]
    )
    def test_padded_core_path_in_opaque_arg_denied(
        self, pdp: PolicyDecisionPoint, padded: str
    ) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(AGENT, "write", {"path": "workspace/x.py", "output_file": padded})
        assert sink.calls == []

    def test_padded_non_core_text_allowed(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, sink = _dispatcher(pdp)
        dispatcher.dispatch(
            AGENT, "write", {"path": "workspace/x.py", "content": " hello world \n"}
        )
        assert len(sink.calls) == 1


class TestDurableAuditNeedsLog:
    """237.10: durable_audit=True without an audit log returned allows."""

    def test_construction_rejected(self, constitution: Constitution, permit_all: PolicySet) -> None:
        with pytest.raises(ValueError, match="durable_audit"):
            PolicyDecisionPoint.for_constitution(constitution, permit_all, durable_audit=True)


class TestImportPathShadows:
    """Security re-review (MEDIUM): import-root shadows of the TCB / stdlib."""

    @pytest.mark.parametrize(
        "path",
        [
            "src/sitecustomize.py",
            "src/json.py",
            "src/json/__init__.py",
            "src/yaml",
            "workspace/usercustomize.py",
            "workspace/sitecustomize/__init__.py",
            "src/evil.pth",
            "workspace/lib/extra.pth",
        ],
    )
    def test_import_shadows_are_core(self, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify(path) is CoreCategory.CONTROL_PLANE

    @pytest.mark.parametrize("path", ["workspace/x.py", "src/acgs_lite/unrelated.py", "app/m.py"])
    def test_ordinary_paths_stay_routine(self, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify(path) is None

    def test_agent_write_denied_at_dispatch(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(AGENT, "write", {"path": "workspace/sitecustomize.py"})
        assert sink.calls == []

    def test_registry_without_src_modules_is_unaffected(self) -> None:
        from acgs_lite.control_plane import ImmutableCoreRegistry

        registry = ImmutableCoreRegistry({CoreCategory.EVALUATOR: ["evaluator/**"]})
        assert registry.classify("src/json.py") is None

    def test_codeowners_lists_import_shadows(self) -> None:
        text = render_codeowners(DEFAULT_IMMUTABLE_CORE, ["@o"])
        assert "/src/*.py @o" in text and "**/*.pth @o" in text


class TestRepoRootImportShadows:
    """Round-2 re-review (MEDIUM): repo-root modules and conftest files."""

    @pytest.mark.parametrize("path", ["json.py", "conftest.py", "pkg/tests/conftest.py"])
    def test_core(self, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify(path) is CoreCategory.CONTROL_PLANE

    def test_ordinary_module_unchanged(self) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify("src/acgs_lite/foo.py") is None

    @pytest.mark.parametrize(
        "path",
        [
            "json/__init__.py",
            "yaml/__init__.pyc",
            "json/__init__.cpython-310-x86_64-linux-gnu.so",
            "json/__init__.pyd",
            "json.cpython-310-x86_64-linux-gnu.so",
            "json.pyd",
            "json.pyc",
        ],
    )
    def test_package_and_native_shadows_denied(self, pdp: PolicyDecisionPoint, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify(path) is CoreCategory.CONTROL_PLANE
        decision = pdp.decide(DecisionRequest(AGENT, "file.write", path, ActionTier.T1))
        assert not decision.allowed

    def test_path_subclass_cannot_redirect_normalization(self, pdp: PolicyDecisionPoint) -> None:
        class PathText(str):
            def replace(self, old: str, new: str, count: int = -1) -> str:
                return "workspace/ok.txt"

        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(AGENT, "write", {"path": PathText("evaluator/score.py")})
        assert sink.calls == []


class TestOpaqueSubclassBoundary:
    @pytest.mark.parametrize("base", [str, bytes, dict, list, tuple, set, frozenset])
    @pytest.mark.parametrize("use_default", [False, True])
    def test_rejects_before_overridden_methods(
        self, pdp: PolicyDecisionPoint, base: type, use_default: bool
    ) -> None:
        invoked: list[str] = []

        def disguised(self: Any, *args: Any, **kwargs: Any) -> Any:
            invoked.append("override")
            return self

        deceptive = type(
            "Deceptive",
            (base,),
            {
                "__deepcopy__": disguised,
                "strip": disguised,
                "decode": disguised,
                "items": disguised,
                "__iter__": disguised,
            },
        )
        if base is bytes:
            value = deceptive(b"evaluator/score.py")
        elif base is dict:
            value = deceptive({"path": "evaluator/score.py"})
        elif base is str:
            value = deceptive("evaluator/score.py")
        else:
            value = deceptive(["evaluator/score.py"])
        calls: list[Any] = []

        def opaque(payload: Any = value) -> None:
            calls.append(payload)

        dispatcher = GovernedToolDispatcher(
            pdp, permissions=_permissions(), tool_tiers={"opaque": ActionTier.T1}
        )
        dispatcher.register("opaque", opaque, opaque_params={"payload"}, merge_capable=False)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(AGENT, "opaque", {} if use_default else {"payload": value})
        assert invoked == []
        assert calls == []

    def test_opaque_string_cannot_hide_core_path(self, pdp: PolicyDecisionPoint) -> None:
        class Deceptive(str):
            def strip(self, chars: str | None = None) -> str:
                return ""

        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(
                AGENT,
                "write",
                {"path": "workspace/ok.txt", "content": Deceptive("evaluator/score.py")},
            )
        assert sink.calls == []


class TestFinalReviewBoundaries:
    def test_workflow_and_make_gate_scripts_are_protected(self) -> None:
        root = Path(__file__).resolve().parents[2]
        callers = [root / "Makefile", *(root / ".github/workflows").glob("*.yml")]
        scripts = {
            path
            for caller in callers
            for path in re.findall(r"scripts/[A-Za-z0-9_/-]+\.py", caller.read_text())
        }
        assert scripts
        assert all(DEFAULT_IMMUTABLE_CORE.is_core(path) for path in scripts)

    def test_policy_read_permit_does_not_fold_path_case(self, constitution: Constitution) -> None:
        policy = PolicySet.from_mapping(
            {
                "version": 1,
                "statements": [
                    {
                        "id": "read",
                        "effect": "permit",
                        "actions": ["file.read"],
                        "resources": ["workspace/alice/**"],
                    }
                ],
            }
        )
        with PolicyDecisionPoint.for_constitution(constitution, policy) as pdp:
            assert pdp.decide(
                DecisionRequest(AGENT, "file.read", "workspace/alice/file.txt", ActionTier.T0)
            ).allowed
            assert not pdp.decide(
                DecisionRequest(AGENT, "file.read", "workspace/ALICE/file.txt", ActionTier.T0)
            ).allowed

    @pytest.mark.parametrize("character_class", ["[!0-9]", "[.-0]"])
    def test_negated_glob_class_cannot_cross_directory(self, character_class: str) -> None:
        permissions = RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE,
            [
                WriteGrant(
                    AGENT.id, PrincipalKind.AGENT, (f"workspace/report{character_class}*.txt",)
                )
            ],
        )
        assert permissions.can_write(AGENT, "workspace/report.final.txt")
        assert not permissions.can_write(AGENT, "workspace/report/private.txt")

    @pytest.mark.parametrize("directory", ["workspace", "policies", "workspace/sub.txt"])
    def test_recursive_reads_cannot_reach_sensitive_children(
        self, constitution: Constitution, permit_all: PolicySet, tmp_path: Path, directory: str
    ) -> None:
        target = tmp_path / directory
        target.mkdir(parents=True)
        (target / ".env").write_text("secret")
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        calls: list[str] = []

        def read_tree(path: str) -> list[str]:
            calls.append(path)
            return [p.read_text() for p in (tmp_path / path).rglob("*") if p.is_file()]

        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, registry=registry
        ) as pdp:
            dispatcher = GovernedToolDispatcher(
                pdp,
                permissions=RepositoryPermissions(registry),
                tool_tiers={"read_tree": ActionTier.T0},
                read_only_tools=frozenset({"read_tree"}),
            )
            dispatcher.register("read_tree", read_tree, path_params={"path"}, merge_capable=False)
            with pytest.raises(ToolDenied):
                dispatcher.dispatch(AGENT, "read_tree", {"path": directory})
        assert calls == []

    @pytest.mark.parametrize("absolute", [False, True])
    def test_parent_segments_cannot_create_outside_grant(
        self, constitution: Constitution, permit_all: PolicySet, tmp_path: Path, absolute: bool
    ) -> None:
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        permissions = RepositoryPermissions(
            registry, [WriteGrant(AGENT.id, PrincipalKind.AGENT, ("workspace/**",))]
        )
        raw = "outside/../workspace/file.txt"
        if absolute:
            raw = str(tmp_path / raw)

        def write(path: str) -> None:
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("written")

        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, registry=registry
        ) as pdp:
            dispatcher = GovernedToolDispatcher(
                pdp, permissions=permissions, tool_tiers={"write": ActionTier.T1}
            )
            dispatcher.register("write", write, path_params={"path"}, merge_capable=False)
            with pytest.raises(ToolDenied):
                dispatcher.dispatch(AGENT, "write", {"path": raw})
        assert not (tmp_path / "outside").exists()
        assert not (tmp_path / "workspace").exists()

    def test_grants_preserve_case_but_core_classification_remains_conservative(self) -> None:
        permissions = RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE,
            [WriteGrant(AGENT.id, PrincipalKind.AGENT, ("Workspace/**",))],
        )
        assert permissions.can_write(AGENT, "Workspace/file.txt")
        assert not permissions.can_write(AGENT, "workspace/file.txt")
        assert not permissions.can_write(AGENT, "Workspace/.ENV")
        assert DEFAULT_IMMUTABLE_CORE.is_core("EVALUATOR/score.py")

    @pytest.mark.parametrize(
        "path",
        [
            "src/acgs_lite/evals/runner.py",
            "src/acgs_lite/evals/schema.py",
            "src/acgs_lite/evals/report.py",
            "scripts/check_critical_coverage.py",
            "scripts/release_candidate.py",
            "scripts/qualify_wheel.py",
            "scripts/run_governance_regression.py",
            "scripts/check_links.py",
            "tests/red_team/governance_fail_closed_cases.py",
            "Makefile",
        ],
    )
    def test_real_grader_and_gate_files_are_core(self, pdp: PolicyDecisionPoint, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.is_core(path)
        assert not pdp.decide(DecisionRequest(AGENT, "file.write", path, ActionTier.T1)).allowed
        with pytest.raises(IAMGrantRejected):
            RepositoryPermissions(
                DEFAULT_IMMUTABLE_CORE, [WriteGrant(AGENT.id, PrincipalKind.AGENT, (path,))]
            )

    @pytest.mark.parametrize(
        "path",
        [
            "workspace./x.py",
            "workspace../x.py",
            "workspace\\x.py",
            "Workspace/x.py",
            "WORKSPACE/x.py",
        ],
    )
    def test_nonportable_alias_cannot_escape_workspace_grant(
        self, pdp: PolicyDecisionPoint, path: str
    ) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(AGENT, "write", {"path": path})
        assert sink.calls == []

    def test_namespaced_read_retains_sensitive_path_category(
        self, pdp: PolicyDecisionPoint
    ) -> None:
        decision = pdp.decide(DecisionRequest(AGENT, "policy.read", "policies/.env", ActionTier.T0))
        assert not decision.allowed

    def test_undecodable_opaque_bytes_denied(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied):
            dispatcher.dispatch(
                AGENT,
                "write",
                {"path": "workspace/ok.txt", "output_file": b"evaluator/grader\xff.py"},
            )
        assert sink.calls == []

    @pytest.mark.parametrize("directory", ["sub", "sub.txt", "link.txt"])
    def test_existing_scratch_directory_denied(
        self, constitution: Constitution, permit_all: PolicySet, tmp_path: Path, directory: str
    ) -> None:
        target = tmp_path / "workspace" / directory
        target.mkdir(parents=True)
        (target / ".env").write_text("protected")
        if directory == "link.txt":
            (tmp_path / "workspace" / "link.txt").rename(tmp_path / "protected")
            target.symlink_to(tmp_path / "protected", target_is_directory=True)
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        permissions = RepositoryPermissions(
            registry, [WriteGrant(AGENT.id, PrincipalKind.AGENT, ("workspace/**",))]
        )
        calls: list[str] = []
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, registry=registry
        ) as pdp:
            dispatcher = GovernedToolDispatcher(
                pdp, permissions=permissions, tool_tiers={"remove": ActionTier.T1}
            )

            def remove(path: str) -> None:
                calls.append(path)

            dispatcher.register("remove", remove, path_params={"path"}, merge_capable=False)
            with pytest.raises(ToolDenied):
                dispatcher.dispatch(AGENT, "remove", {"path": f"workspace/{directory}"})
            (tmp_path / "workspace" / "ordinary.txt").write_text("ordinary")
            dispatcher.dispatch(AGENT, "remove", {"path": "workspace/ordinary.txt"})
            dispatcher.dispatch(AGENT, "remove", {"path": "workspace/new.txt"})
        assert calls == ["workspace/ordinary.txt", "workspace/new.txt"]
        assert (target / ".env").read_text() == "protected"

    async def test_sync_async_dispatch_uses_worker_thread(self, pdp: PolicyDecisionPoint) -> None:
        dispatcher = GovernedToolDispatcher(
            pdp, permissions=_permissions(), tool_tiers={"thread_id": ActionTier.T1}
        )

        def thread_id() -> int:
            return threading.get_ident()

        dispatcher.register("thread_id", thread_id, merge_capable=False)
        result = await dispatcher.adispatch(AGENT, "thread_id", {})
        assert result.value != threading.get_ident()


class TestDottedDirectoryTargets:
    @pytest.mark.parametrize("path", ["app/v1.2", "app/v1.2/", "app/report.txt"])
    def test_unknown_target_kind_outside_scratch_is_denied(
        self, pdp: PolicyDecisionPoint, path: str
    ) -> None:
        dispatcher, sink = _dispatcher(pdp)
        with pytest.raises(ToolDenied, match="may contain core files"):
            dispatcher.dispatch(AGENT, "write", {"path": path})
        assert sink.calls == []
