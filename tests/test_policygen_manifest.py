"""Tests for the manifest capability adapter (policygen.manifest).

Covers each manifest parser individually and combined, matched/unknown
correctness, self-name exclusion, normalization, determinism, malformed-input
error handling, and the zero-gaps invariant: every CAPABILITY_MAP value must be
a risk-area key the PolicyResearcher knowledge base actually knows.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acgs_lite.policygen import CAPABILITY_MAP, ManifestScanResult, scan_manifests
from acgs_lite.policygen.context import PreContext, PreContextBuilder
from acgs_lite.policygen.research import PolicyResearcher

# -- CAPABILITY_MAP zero-gaps invariant --------------------------------------------


class TestCapabilityMapZeroGaps:
    def test_every_capability_map_value_has_zero_research_gaps(self) -> None:
        areas = sorted(set(CAPABILITY_MAP.values()))
        assert areas, "CAPABILITY_MAP must not be empty"
        pc = PreContext(domain="X", risk_areas=tuple(areas))
        report = PolicyResearcher().research(pc)
        assert report.gaps == (), f"KB gaps for mapped areas: {report.gaps}"
        # Every mapped area must have produced at least one requirement.
        sources = {r.source for r in report.requirements}
        for area in areas:
            assert f"risk-area:{area}" in sources, area

    def test_capability_map_is_immutable(self) -> None:
        with pytest.raises(TypeError):
            CAPABILITY_MAP["new-package"] = "financial"  # type: ignore[index]

    def test_capability_map_keys_are_normalized(self) -> None:
        for key in CAPABILITY_MAP:
            assert key == key.strip().lower().replace("_", "-"), key


# -- pyproject.toml -----------------------------------------------------------------


class TestPyprojectParsing:
    def test_dependencies_and_optional_dependencies_matched(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            """
            [project]
            name = "my-app"
            dependencies = ["stripe>=5.0", "requests[socks]==2.31.0"]

            [project.optional-dependencies]
            dev = ["pytest>=7.0"]
            """
        )
        result = scan_manifests(tmp_path)
        assert result.manifests == ("pyproject.toml",)
        assert ("requests", "network-egress") in result.matched
        assert ("stripe", "financial") in result.matched
        assert "pytest" in result.unknown

    def test_self_name_excluded_from_matching(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            """
            [project]
            name = "Stripe"
            dependencies = ["stripe"]
            """
        )
        result = scan_manifests(tmp_path)
        # The project is literally named "Stripe" (case-insensitive match to its own
        # dependency "stripe") -- must be excluded entirely, not matched or unknown.
        assert result.matched == ()
        assert result.unknown == ()

    def test_missing_tomllib_and_tomli_raises_runtime_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')

        real_import = builtins.__import__

        def fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name in ("tomllib", "tomli"):
                raise ImportError(f"no module named {name}")
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(RuntimeError, match="tomli"):
            scan_manifests(tmp_path)

    def test_malformed_pyproject_raises_clear_value_error(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("this = is [ not valid toml")
        with pytest.raises(ValueError, match="Malformed pyproject.toml"):
            scan_manifests(tmp_path)

    def test_dependencies_not_a_list_raises(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            """
            [project]
            name = "x"
            dependencies = "stripe"
            """
        )
        with pytest.raises(ValueError, match="dependencies"):
            scan_manifests(tmp_path)

    def test_unparsable_dependency_spec_reported_as_unknown_not_dropped(
        self, tmp_path: Path
    ) -> None:
        # A non-standard, name-less direct-URL reference: _extract_name cannot
        # resolve a leading name token from it (starts with "@"). It must be
        # reported in `unknown` with its raw form -- never silently dropped --
        # while the normal dependency alongside it is still matched normally.
        garbage = "@ https://example.com/pkg-1.0-py3-none-any.whl"
        (tmp_path / "pyproject.toml").write_text(
            f"""
            [project]
            name = "x"
            dependencies = ["httpx", "{garbage}"]
            """
        )
        result = scan_manifests(tmp_path)
        assert ("httpx", "network-egress") in result.matched
        assert garbage in result.unknown

    def test_unparsable_optional_dependency_spec_reported_as_unknown(
        self, tmp_path: Path
    ) -> None:
        garbage = "@ https://example.com/pkg-1.0-py3-none-any.whl"
        (tmp_path / "pyproject.toml").write_text(
            f"""
            [project]
            name = "x"

            [project.optional-dependencies]
            dev = ["stripe", "{garbage}"]
            """
        )
        result = scan_manifests(tmp_path)
        assert ("stripe", "financial") in result.matched
        assert garbage in result.unknown


# -- requirements.txt ----------------------------------------------------------------


class TestRequirementsParsing:
    def test_comments_blank_lines_and_options_handled(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text(
            "\n".join(
                [
                    "# a comment",
                    "",
                    "stripe==5.0  # inline comment",
                    "boto3",
                    "-r other-requirements.txt",
                    "-e git+https://example.com/pkg.git#egg=pkg",
                    "https://example.com/some.whl",
                    "unknown-thing>=1.0",
                ]
            )
        )
        result = scan_manifests(tmp_path)
        assert result.manifests == ("requirements.txt",)
        assert ("boto3", "production-deploy") in result.matched
        assert ("stripe", "financial") in result.matched
        assert "unknown-thing" in result.unknown
        assert "-r other-requirements.txt" in result.unknown
        assert "-e git+https://example.com/pkg.git#egg=pkg" in result.unknown
        assert "https://example.com/some.whl" in result.unknown

    def test_normalization_underscore_and_case(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("Google_Cloud_Storage==2.0\n")
        result = scan_manifests(tmp_path)
        assert ("google-cloud-storage", "production-deploy") in result.matched


# -- package.json ---------------------------------------------------------------------


class TestPackageJsonParsing:
    def test_dependencies_and_dev_dependencies_matched(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "my-frontend",
                    "dependencies": {"langchain-core": "^1.0.0", "left-pad": "^1.0.0"},
                    "devDependencies": {"openai": "^4.0.0"},
                }
            )
        )
        result = scan_manifests(tmp_path)
        assert result.manifests == ("package.json",)
        assert ("langchain-core", "transparency") in result.matched
        assert ("openai", "transparency") in result.matched
        assert "left-pad" in result.unknown

    def test_self_name_excluded(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "openai", "dependencies": {"openai": "^4.0.0"}})
        )
        result = scan_manifests(tmp_path)
        assert result.matched == ()
        assert result.unknown == ()

    def test_malformed_json_raises_clear_value_error(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text("{not valid json")
        with pytest.raises(ValueError, match="Malformed package.json"):
            scan_manifests(tmp_path)

    def test_deeply_nested_json_raises_value_error_not_recursion_error(
        self, tmp_path: Path
    ) -> None:
        # Adversarial payload: json.loads recurses per nesting level and raises
        # RecursionError well before the 5 MiB manifest size guard triggers. This
        # must be converted to the module's ValueError contract, never crash
        # through as an unrelated exception.
        depth = 100_000
        payload = '{"dependencies": ' + ("[" * depth) + ("]" * depth) + "}"
        (tmp_path / "package.json").write_text(payload)
        with pytest.raises(ValueError, match="Malformed package.json"):
            scan_manifests(tmp_path)

    def test_dependencies_not_an_object_raises(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": ["stripe"]}))
        with pytest.raises(ValueError, match="dependencies"):
            scan_manifests(tmp_path)

    def test_package_json_only_scan_never_imports_toml_parser(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"stripe": "^1.0"}}))

        real_import = builtins.__import__

        def fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name in ("tomllib", "tomli"):
                raise AssertionError(f"{name} must not be imported for a package.json-only scan")
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(builtins, "__import__", fake_import)
        result = scan_manifests(tmp_path)
        assert ("stripe", "financial") in result.matched


# -- combined scan + PreContext wiring ------------------------------------------------


class TestCombinedScan:
    def test_all_three_manifests_combined(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "combo"\ndependencies = ["httpx"]\n'
        )
        (tmp_path / "requirements.txt").write_text("cryptography\n")
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"pymongo": "^4.0"}}))
        result = scan_manifests(tmp_path)
        assert result.manifests == ("package.json", "pyproject.toml", "requirements.txt")
        assert ("httpx", "network-egress") in result.matched
        assert ("cryptography", "secrets") in result.matched
        assert ("pymongo", "data-deletion") in result.matched
        assert result.precontext.risk_areas == ("data-deletion", "network-egress", "secrets")

    def test_no_manifests_found_returns_empty_result(self, tmp_path: Path) -> None:
        result = scan_manifests(tmp_path)
        assert result.manifests == ()
        assert result.matched == ()
        assert result.unknown == ()
        assert result.precontext.risk_areas == ()

    def test_scan_root_must_be_a_directory(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"
        with pytest.raises(ValueError, match="not a directory"):
            scan_manifests(missing)

    def test_default_domain_and_description(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("stripe\n")
        result = scan_manifests(tmp_path)
        assert result.precontext.domain == "scanned-project"
        assert "requirements.txt" in result.precontext.description

    def test_caller_supplied_domain_and_description(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("stripe\n")
        result = scan_manifests(tmp_path, domain="Checkout Service", description="custom brief")
        assert result.precontext.domain == "Checkout Service"
        assert result.precontext.description == "custom brief"

    def test_risk_level_left_to_builder_classification(self, tmp_path: Path) -> None:
        # Two distinct high-impact-adjacent risk areas (financial + secrets) should
        # trigger the *existing* PreContextBuilder classification -- the adapter
        # never hand-sets risk_level.
        (tmp_path / "requirements.txt").write_text("stripe\ncryptography\n")
        result = scan_manifests(tmp_path)
        expected = PreContextBuilder(
            domain=result.precontext.domain, description=result.precontext.description
        )
        expected.add_risk_area(*result.precontext.risk_areas)
        expected.infer()
        assert result.precontext.risk_level == expected.build().risk_level

    def test_result_to_dict_serializes(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("stripe\n")
        result = scan_manifests(tmp_path)
        data = result.to_dict()
        assert data["manifests"] == ["requirements.txt"]
        assert data["matched"] == [["stripe", "financial"]]
        assert data["unknown"] == []
        assert data["precontext"]["domain"] == "scanned-project"

    def test_manifest_scan_result_is_frozen(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("stripe\n")
        result = scan_manifests(tmp_path)
        with pytest.raises(AttributeError):
            result.matched = ()  # type: ignore[misc]

    def test_determinism_two_runs_identical(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\ndependencies = ["httpx", "boto3", "unmapped-pkg"]\n'
        )
        (tmp_path / "requirements.txt").write_text("stripe\ncryptography\nzzz-unmapped\n")
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"pymongo": "^4.0", "another-unmapped": "^1.0"}})
        )
        first = scan_manifests(tmp_path)
        second = scan_manifests(tmp_path)
        assert first.to_dict() == second.to_dict()
        assert first == second

    def test_matched_and_unknown_are_sorted(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text(
            "zzz-unmapped\naaa-unmapped\nstripe\nboto3\ncryptography\n"
        )
        result = scan_manifests(tmp_path)
        assert list(result.unknown) == sorted(result.unknown)
        assert list(result.matched) == sorted(result.matched)


class TestGovernanceInvariants:
    """Evidence-only, no-import, no-activation constraints named in the brief."""

    def test_module_docstring_states_evidence_only(self) -> None:
        from acgs_lite.policygen import manifest as manifest_module

        assert manifest_module.__doc__ is not None
        assert "evidence" in manifest_module.__doc__.lower()

    def test_scanning_never_imports_lifecycle_or_activation_modules(self) -> None:
        import ast

        from acgs_lite.policygen import manifest as manifest_module

        source = Path(manifest_module.__file__).read_text()
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not any("lifecycle" in m.lower() or "activat" in m.lower() for m in imported)

    def test_matched_and_unknown_never_overlap(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("stripe\nunmapped-thing\n")
        result = scan_manifests(tmp_path)
        matched_names = {name for name, _ in result.matched}
        assert matched_names.isdisjoint(result.unknown)


class TestFileSizeGuard:
    def test_oversized_manifest_rejected(self, tmp_path: Path) -> None:
        from acgs_lite.policygen.manifest import _MAX_MANIFEST_BYTES

        big = tmp_path / "requirements.txt"
        big.write_text("x" * (_MAX_MANIFEST_BYTES + 1))
        with pytest.raises(ValueError, match="too large"):
            scan_manifests(tmp_path)


class TestPublicExport:
    def test_top_level_policygen_exports(self) -> None:
        import acgs_lite.policygen as policygen_module

        for name in ("CAPABILITY_MAP", "ManifestScanResult", "scan_manifests"):
            assert hasattr(policygen_module, name), name
        assert isinstance(ManifestScanResult, type)
