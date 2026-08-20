"""Guards for documented developer tooling entry points."""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility.
    import tomli as tomllib

_PYPROJECT_PATH = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _dev_extra_names() -> set[str]:
    data = tomllib.loads(_PYPROJECT_PATH.read_text(encoding="utf-8"))
    dependencies = data["project"]["optional-dependencies"]["dev"]
    return {dependency.split("[", 1)[0].split(">=", 1)[0] for dependency in dependencies}


def test_dev_extra_installs_make_build_and_publish_tooling() -> None:
    names = _dev_extra_names()

    assert {"build", "twine"} <= names


def test_z3_extra_is_declared_and_included_in_all() -> None:
    """The advertised z3 capability must be an installable extra, not a keyword."""
    data = tomllib.loads(_PYPROJECT_PATH.read_text(encoding="utf-8"))
    extras = data["project"]["optional-dependencies"]
    z3 = extras["z3"]
    assert any(dep.startswith("z3-solver") and ">=4.12" in dep for dep in z3), z3
    all_extra = extras["all"]
    assert any(",z3]" in item or "[z3]" in item or ",z3," in item for item in all_extra), all_extra


def test_ci_solver_lanes_install_the_z3_extra() -> None:
    """Verification CI must install the published extra, not a bare undeclared package.

    The python-fallback job is the exception: it is the lane that proves
    UNAVAILABLE blocks, so it must not pull z3 in by any path.
    """
    ci_path = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
    text = ci_path.read_text(encoding="utf-8")
    extra_install = '".[dev,autonoma,anthropic,mcp,otel,z3]"'
    assert extra_install in text
    assert text.count(extra_install) >= 3

    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if "pip install" in stripped and "z3-solver" in stripped:
            raise AssertionError(f"CI still installs bare z3-solver at line {line_no}: {stripped}")

    fallback_start = text.index("python-fallback:")
    fallback = text[fallback_start:]
    next_job = fallback.find("\n  docs:")
    fallback_job = fallback if next_job < 0 else fallback[:next_job]
    assert "[z3]" not in fallback_job
    assert "z3-solver" not in fallback_job.split("Install without Rust companion", 1)[-1]
