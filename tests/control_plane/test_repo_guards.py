"""Repository-permission artefacts: CODEOWNERS, CI diff guard, coverage set."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType

import pytest
import yaml

from acgs_lite.control_plane import DEFAULT_IMMUTABLE_CORE, render_codeowners

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"control_plane_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RENDER = _load("render_codeowners")
GUARD = _load("check_immutable_core_diff")
COVERAGE = _load("check_critical_coverage")


class TestCodeowners:
    def test_checked_in_codeowners_matches_render(self) -> None:
        checked_in = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        assert checked_in == RENDER.render()
        assert checked_in.startswith(
            "# GENERATED — do not hand edit; regenerate with scripts/render_codeowners.py"
        )

    def test_every_core_pattern_is_owned(self) -> None:
        text = render_codeowners(DEFAULT_IMMUTABLE_CORE, ["@org/team", "owner@example.com"])
        for patterns in DEFAULT_IMMUTABLE_CORE.patterns().values():
            for pattern in patterns:
                anchored = pattern if pattern.startswith("**/") else "/" + pattern
                assert f"\n{anchored} @org/team owner@example.com\n" in text

    @pytest.mark.parametrize("owners", [[], [""], ["has space"], ["noatsign"]])
    def test_invalid_owners(self, owners: list[str]) -> None:
        with pytest.raises(ValueError):
            render_codeowners(DEFAULT_IMMUTABLE_CORE, owners)

    def test_single_string_owner(self) -> None:
        assert "@solo" in render_codeowners(DEFAULT_IMMUTABLE_CORE, "@solo")

    def test_check_mode(self, tmp_path: Path) -> None:
        target = tmp_path / "CODEOWNERS"
        assert RENDER.main(["--check", "--output", str(target)]) == 1
        assert RENDER.main(["--output", str(target)]) == 0
        assert RENDER.main(["--check", "--output", str(target)]) == 0
        target.write_text("stale\n", encoding="utf-8")
        assert RENDER.main(["--check", "--output", str(target)]) == 1


class TestDiffGuard:
    @pytest.mark.parametrize("author", ["dependabot[bot]", "claude-agent[bot]"])
    def test_bot_author_touching_core_blocked(self, author: str) -> None:
        assert GUARD.main(["--files", "evaluator/x.py", "--author", author]) == 1

    def test_agent_branch_blocked(self) -> None:
        argv = [
            "--files",
            ".github/workflows/ci.yml",
            "--author",
            "alice",
            "--head-ref",
            "agent/fix",
        ]
        assert GUARD.main(argv) == 1

    def test_agent_trailer_blocked(self, tmp_path: Path) -> None:
        messages = tmp_path / "msgs.txt"
        messages.write_text("fix\n\nCo-Authored-By: Claude Opus <noreply@anthropic.com>\n")
        argv = [
            "--files",
            "src/acgs_lite/control_plane/pdp.py",
            "--author",
            "alice",
            "--commit-messages-file",
            str(messages),
        ]
        assert GUARD.main(argv) == 1

    def test_agent_outside_core_allowed(self) -> None:
        assert GUARD.main(["--files", "workspace/x.py", "--author", "bot[bot]"]) == 0

    def test_optional_ci_dependency_input_blocks_agent_changes(self) -> None:
        assert (
            GUARD.main(["--files", "requirements-test-optional.txt", "--author", "bot[bot]"]) == 1
        )

    @pytest.mark.parametrize(
        "path",
        [
            "rust/pyo3/src/lib.rs",
            "rust/core/src/validator.rs",
            "rust/core/Cargo.toml",
            "rust/pyo3/Cargo.toml",
            "rust/pyo3/pyproject.toml",
            "rust/Cargo.toml",
            "rust/Cargo.lock",
            "rust/core/build.rs",
            "rust/.cargo/config.toml",
            ".cargo/config.toml",
            "rust-toolchain",
            "rust-toolchain.toml",
        ],
    )
    def test_native_governance_build_inputs_block_agent_changes(self, path: str) -> None:
        assert GUARD.main(["--files", path, "--author", "test[bot]"]) == 1

    def test_human_core_change_allowed_by_guard(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert GUARD.main(["--files", "policies/p.yaml", "--author", "alice"]) == 0
        assert "review required" in capsys.readouterr().out

    def test_custom_patterns_replace_defaults(self) -> None:
        argv = [
            "--files",
            "evaluator/x.py",
            "--author",
            "robo-1",
            "--agent-patterns",
            "author:^robo-",
        ]
        assert GUARD.main(argv) == 1
        argv = [
            "--files",
            "evaluator/x.py",
            "--author",
            "x[bot]",
            "--agent-patterns",
            "author:^robo-",
        ]
        assert GUARD.main(argv) == 0

    @pytest.mark.parametrize("pattern", ["nokind", "colour:x", "author:", "author:(unclosed"])
    def test_bad_patterns_fail_closed(self, pattern: str) -> None:
        argv = ["--files", "x", "--author", "a", "--agent-patterns", pattern]
        assert GUARD.main(argv) == 1

    def test_unreadable_messages_file_fails_closed(self, tmp_path: Path) -> None:
        argv = [
            "--files",
            "x",
            "--author",
            "a",
            "--commit-messages-file",
            str(tmp_path / "missing.txt"),
        ]
        assert GUARD.main(argv) == 1

    def test_manifest_option(self, tmp_path: Path) -> None:
        manifest = tmp_path / "core.yaml"
        data = DEFAULT_IMMUTABLE_CORE.to_mapping()
        data["categories"]["evaluator"] = ["custom/**"]
        manifest.write_text(yaml.safe_dump(data), encoding="utf-8")
        base = ["--manifest", str(manifest), "--author", "x[bot]", "--files"]
        assert GUARD.main([*base, "custom/a.py"]) == 1
        assert GUARD.main([*base, "evaluator/a.py"]) == 0
        manifest.write_text("version: 9\n", encoding="utf-8")
        assert GUARD.main([*base, "workspace/a.py"]) == 1

    def test_git_error_fails_closed(self, tmp_path: Path) -> None:
        argv = ["--repo", str(tmp_path), "--base", "nope", "--head", "nada", "--author", "alice"]
        assert GUARD.main(argv) == 1

    def test_base_requires_head(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            GUARD.main(["--base", "x", "--author", "a"])
        assert excinfo.value.code == 2

    def test_git_diff_mode_catches_renames(self, tmp_path: Path) -> None:
        def git(*args: str) -> str:
            completed = subprocess.run(
                ["git", "-C", str(tmp_path), *args],
                check=True,
                capture_output=True,
                text=True,
                env={
                    "GIT_AUTHOR_NAME": "t",
                    "GIT_AUTHOR_EMAIL": "t@example.com",
                    "GIT_COMMITTER_NAME": "t",
                    "GIT_COMMITTER_EMAIL": "t@example.com",
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(tmp_path),
                },
            )
            return completed.stdout.strip()

        git("init", "-q")
        (tmp_path / "evaluator").mkdir()
        (tmp_path / "evaluator" / "score.py").write_text("x = 1\n")
        (tmp_path / "notes.md").write_text("hi\n")
        git("add", ".")
        git("commit", "-qm", "base")
        base = git("rev-parse", "HEAD")
        git("mv", "evaluator/score.py", "moved.py")
        git("commit", "-qm", "move evaluator away")
        head = git("rev-parse", "HEAD")
        assert GUARD.changed_files(tmp_path, base, head) == ["evaluator/score.py", "moved.py"]
        argv = ["--repo", str(tmp_path), "--base", base, "--head", head, "--author", "a[bot]"]
        assert GUARD.main(argv) == 1
        argv = ["--repo", str(tmp_path), "--base", base, "--head", head, "--author", "alice"]
        assert GUARD.main(argv) == 0


class TestCiWiring:
    def test_workflow_runs_base_guard_with_env_inputs(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / "immutable-core-guard.yml").read_text()
        )
        assert "pull_request" in workflow[True]  # PyYAML parses the `on:` key as True
        steps = workflow["jobs"]["guard"]["steps"]
        guard = steps[-1]
        assert "_guard/scripts/check_immutable_core_diff.py" in guard["run"]
        assert guard["env"]["PR_AUTHOR"] == "${{ github.event.pull_request.user.login }}"
        assert "${{" not in guard["run"]
        assert steps[0]["with"]["fetch-depth"] == 0
        assert steps[1]["with"]["ref"] == "${{ github.event.pull_request.base.sha }}"

    def test_control_plane_is_critical_coverage(self) -> None:
        control_plane = {
            path.relative_to(ROOT / "src" / "acgs_lite").as_posix()
            for path in (ROOT / "src" / "acgs_lite" / "control_plane").glob("*.py")
        }
        assert control_plane
        assert control_plane <= COVERAGE.CRITICAL_FILES
