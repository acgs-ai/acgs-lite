"""Immutable-core registry: glob semantics, fail-closed normalisation, manifest."""

from __future__ import annotations

from pathlib import Path

import pytest

from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    CoreCategory,
    ImmutableCoreError,
    ImmutableCoreRegistry,
    normalize_path,
)
from acgs_lite.control_plane.immutable_core import compile_glob, literal_prefix

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "control-plane" / "immutable-core.yaml"


class TestGlob:
    @pytest.mark.parametrize(
        ("pattern", "path", "expected"),
        [
            ("evaluator/**", "evaluator/x.py", True),
            ("evaluator/**", "evaluator/a/b/c.py", True),
            ("evaluator/**", "evaluator", True),
            ("evaluator/**", "evaluatorx/a.py", False),
            ("evaluator/**", "src/evaluator/a.py", False),
            ("**/.env*", ".env", True),
            ("**/.env*", "a/b/.env.local", True),
            ("**/.env*", "a/b/env", False),
            ("config/sandbox*", "config/sandbox.yaml", True),
            ("config/sandbox*", "config/sandbox/x.yaml", False),
            ("*.py", "a.py", True),
            ("*.py", "dir/a.py", False),
            ("a/**/b.py", "a/b.py", True),
            ("a/**/b.py", "a/x/y/b.py", True),
            ("a/?.py", "a/x.py", True),
            ("a/?.py", "a/xy.py", False),
            ("a/[bc].py", "a/c.py", True),
            ("a/[!bc].py", "a/c.py", False),
            ("a/[!bc].py", "a/d.py", True),
            ("a/[unclosed", "a/[unclosed", True),
            ("**", "anything/at/all", True),
            ("CODEOWNERS", "codeowners", True),
            ("CODEOWNERS", "docs/CODEOWNERS", False),
        ],
    )
    def test_compile_glob(self, pattern: str, path: str, expected: bool) -> None:
        assert bool(compile_glob(pattern).fullmatch(path)) is expected

    def test_literal_prefix(self) -> None:
        assert literal_prefix("Evaluator/**") == "evaluator/"
        assert literal_prefix("**/.env*") == ""
        assert literal_prefix("config/sandbox*") == "config/sandbox"
        assert literal_prefix("CODEOWNERS") == "codeowners"


class TestNormalize:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("./evaluator/x.py", "evaluator/x.py"),
            ("ok/../evaluator/x.py", None),
            ("a//b/./c", "a/b/c"),
            ("evaluator\\x.py", None),
            ("workspace./x.py", None),
            ("workspace../x.py", None),
            (".", "."),
            ("", None),
            ("../outside", None),
            ("a/../../outside", None),
            ("/etc/passwd", None),
            ("evil\x00.py", None),
            ("tab\there", None),
            (" leading", None),
            ("trailing ", None),
            ("~/x", None),
            ("C:/x", None),
            ("file:///etc/passwd", None),
            (None, None),
            (42, None),
        ],
    )
    def test_normalize_without_root(self, raw: object, expected: str | None) -> None:
        assert normalize_path(raw) == expected

    def test_absolute_inside_root_is_relativised(self) -> None:
        assert normalize_path("/repo/evaluator/x.py", "/repo") == "evaluator/x.py"
        assert normalize_path("/repo", "/repo") == "."
        assert normalize_path("/repo/../repo/a", "/repo") is None

    def test_absolute_outside_root_is_unresolvable(self) -> None:
        assert normalize_path("/repository/a", "/repo") is None
        assert normalize_path("/etc/passwd", "/repo") is None


class TestClassify:
    @pytest.mark.parametrize(
        ("path", "category"),
        [
            ("evaluator/score.py", CoreCategory.EVALUATOR),
            ("evals/suite.yaml", CoreCategory.EVALUATOR),
            ("eval_suites/a.py", CoreCategory.TEST_SUITE),
            ("data/heldout/x.jsonl", CoreCategory.HELDOUT_DATA),
            ("heldout/x.jsonl", CoreCategory.HELDOUT_DATA),
            ("config/sandbox.yaml", CoreCategory.SANDBOX_CONFIG),
            ("sandbox/profile.json", CoreCategory.SANDBOX_CONFIG),
            ("policies/main.yaml", CoreCategory.POLICY),
            ("deep/constitution_v2.yaml", CoreCategory.POLICY),
            ("cfg/tool_allowlist.json", CoreCategory.TOOL_ALLOWLIST),
            ("secrets/x", CoreCategory.CREDENTIALS),
            ("svc/.env.production", CoreCategory.CREDENTIALS),
            ("promotion/gate.py", CoreCategory.PROMOTION_GATE),
            ("audit/log.jsonl", CoreCategory.AUDIT_LOG),
            ("iam/roles.yaml", CoreCategory.IAM),
            ("CODEOWNERS", CoreCategory.IAM),
            (".github/workflows/x.yml", CoreCategory.CI_RULES),
            ("src/acgs_lite/control_plane/pdp.py", CoreCategory.CONTROL_PLANE),
            ("control-plane/immutable-core.yaml", CoreCategory.CONTROL_PLANE),
            ("Evaluator/Score.PY", CoreCategory.EVALUATOR),
            ("ok/../evaluator/x.py", CoreCategory.CONTROL_PLANE),
        ],
    )
    def test_core_paths(self, path: str, category: CoreCategory) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify(path) is category
        assert DEFAULT_IMMUTABLE_CORE.is_core(path)

    @pytest.mark.parametrize(
        "path",
        ["workspace/x.py", "src/acgs_lite/compliance/report.py", "tests/test_core.py", "README.md"],
    )
    def test_non_core_paths(self, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify(path) is None
        assert not DEFAULT_IMMUTABLE_CORE.is_core(path)

    def test_overlap_precedence_is_enum_order(self) -> None:
        # .github/CODEOWNERS matches IAM and CI_RULES (.github/**); IAM is first.
        assert DEFAULT_IMMUTABLE_CORE.classify(".github/CODEOWNERS") is CoreCategory.IAM

    @pytest.mark.parametrize(
        "path", ["", "../x", "/abs/path", "a\x00b", "~/.ssh/id_rsa", " evaluator/x"]
    )
    def test_unresolvable_paths_are_core(self, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.classify(path) is CoreCategory.CONTROL_PLANE

    @pytest.mark.parametrize("path", [".", "src", "src/acgs_lite", "data", "config", "tests"])
    def test_directories_containing_core_are_core(self, path: str) -> None:
        assert DEFAULT_IMMUTABLE_CORE.is_core(path)

    def test_repo_root_relativises_absolute_paths(self) -> None:
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root("/srv/repo")
        assert registry.repo_root == "/srv/repo"
        assert registry.classify("/srv/repo/evaluator/x.py") is CoreCategory.EVALUATOR
        assert registry.classify("/srv/repo/workspace/x.py") is None
        assert registry.classify("/srv/other/x.py") is CoreCategory.CONTROL_PLANE

    def test_empty_registry_root_is_not_core(self) -> None:
        empty = ImmutableCoreRegistry({})
        assert empty.classify(".") is None
        assert empty.classify("anything") is None


class TestRegistryObject:
    def test_registry_is_immutable(self) -> None:
        with pytest.raises(AttributeError):
            DEFAULT_IMMUTABLE_CORE._entries = ()  # type: ignore[misc]
        view = DEFAULT_IMMUTABLE_CORE.patterns()
        with pytest.raises(TypeError):
            view[CoreCategory.EVALUATOR] = ()  # type: ignore[index]

    def test_equality_ignores_pattern_order_and_duplicates(self) -> None:
        a = ImmutableCoreRegistry({CoreCategory.EVALUATOR: ["b/**", "a/**", "a/**"]})
        b = ImmutableCoreRegistry({"evaluator": ("a/**", "b/**")})
        assert a == b
        assert hash(a) == hash(b)
        assert a != DEFAULT_IMMUTABLE_CORE
        assert a != "not a registry"
        assert "patterns=2" in repr(a)

    @pytest.mark.parametrize(
        "patterns",
        [
            {"nope": ["a/**"]},
            {CoreCategory.EVALUATOR: "a/**"},
            {CoreCategory.EVALUATOR: [""]},
            {CoreCategory.EVALUATOR: ["/abs/**"]},
            {CoreCategory.EVALUATOR: ["a/../b"]},
            {CoreCategory.EVALUATOR: ["a\\b"]},
            {CoreCategory.EVALUATOR: [" a"]},
            {CoreCategory.EVALUATOR: [3]},
        ],
    )
    def test_invalid_patterns_raise(self, patterns: dict[object, object]) -> None:
        with pytest.raises(ImmutableCoreError):
            ImmutableCoreRegistry(patterns)  # type: ignore[arg-type]

    def test_relative_repo_root_rejected(self) -> None:
        with pytest.raises(ImmutableCoreError):
            ImmutableCoreRegistry({}, repo_root="relative")

    def test_dot_slash_pattern_prefix_is_stripped(self) -> None:
        registry = ImmutableCoreRegistry({CoreCategory.POLICY: ["./policies/**"]})
        assert registry.patterns()[CoreCategory.POLICY] == ("policies/**",)


class TestManifest:
    def test_yaml_manifest_equals_default(self) -> None:
        assert ImmutableCoreRegistry.from_yaml(MANIFEST) == DEFAULT_IMMUTABLE_CORE

    def test_round_trip_mapping(self) -> None:
        mapping = DEFAULT_IMMUTABLE_CORE.to_mapping()
        assert ImmutableCoreRegistry.from_mapping(mapping) == DEFAULT_IMMUTABLE_CORE

    @pytest.mark.parametrize(
        "data",
        [
            [],
            {"version": 1, "categories": {}, "extra": 1},
            {"version": 2, "categories": {}},
            {"version": 1, "categories": []},
            {"version": 1, "categories": {"evaluator": ["a/**"]}},
        ],
    )
    def test_strict_manifest_errors(self, data: object) -> None:
        with pytest.raises(ImmutableCoreError):
            ImmutableCoreRegistry.from_mapping(data)  # type: ignore[arg-type]

    def test_category_value_must_be_list(self) -> None:
        mapping = DEFAULT_IMMUTABLE_CORE.to_mapping()
        mapping["categories"]["evaluator"] = "evaluator/**"
        with pytest.raises(ImmutableCoreError):
            ImmutableCoreRegistry.from_mapping(mapping)

    def test_invalid_yaml(self) -> None:
        with pytest.raises(ImmutableCoreError):
            ImmutableCoreRegistry.from_yaml_str("version: [unclosed")


@pytest.mark.parametrize("leaf", ["leaf.py", "__init__.py", "nested/leaf.py"])
@pytest.mark.parametrize("suffix", [".py", ".pyc", ".cpython-310-x86_64-linux-gnu.so", ".pyd"])
def test_protected_leaf_closes_ancestor_module_shadows(leaf: str, suffix: str) -> None:
    registry = ImmutableCoreRegistry({CoreCategory.CONTROL_PLANE: [f"src/pkg/namespace/{leaf}"]})
    assert registry.is_core("src/pkg/namespace" + suffix)
    assert registry.is_core("src/pkg" + suffix)
    assert not registry.is_core("src/pkg/unrelated" + suffix)
