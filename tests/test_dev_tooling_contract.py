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
