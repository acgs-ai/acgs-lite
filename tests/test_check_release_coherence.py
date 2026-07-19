"""Tests for the release-coherence guard (scripts/check_release_coherence.py).

The guard enforces: a version presented as *released* in CHANGELOG.md (a dated
``## [X.Y.Z] - DATE`` heading) must have a matching ``vX.Y.Z`` git tag. By default
only ``pyproject.toml``'s current version is enforced; ``--strict-history`` widens
enforcement to all dated-but-untagged versions.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_release_coherence.py"
_spec = importlib.util.spec_from_file_location("check_release_coherence", _SCRIPT)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


def _patch(monkeypatch, *, version: str, changelog: str, tags: set[str]) -> None:
    def fake_read(path: Path) -> str:
        if path == guard.PYPROJECT:
            return f'[project]\nname = "acgs-lite"\nversion = "{version}"\n'
        if path == guard.CHANGELOG:
            return changelog
        raise AssertionError(f"unexpected read: {path}")

    monkeypatch.setattr(guard, "_read", fake_read)
    monkeypatch.setattr(guard, "_existing_tags", lambda: set(tags))


def test_current_version_dated_but_untagged_fails(monkeypatch):
    _patch(
        monkeypatch,
        version="2.11.0",
        changelog="## [Unreleased]\n\n## [2.11.0] - 2026-05-31\n- stuff\n",
        tags={"v2.10.1"},
    )
    assert guard.main([]) == 1


def test_current_version_tagged_passes(monkeypatch):
    _patch(
        monkeypatch,
        version="2.11.0",
        changelog="## [2.11.0] - 2026-05-31\n- stuff\n",
        tags={"v2.11.0", "v2.10.1"},
    )
    assert guard.main([]) == 0


def test_bare_tag_convention_accepted(monkeypatch):
    _patch(
        monkeypatch,
        version="2.11.0",
        changelog="## [2.11.0] - 2026-05-31\n",
        tags={"2.11.0"},
    )
    assert guard.main([]) == 0


def test_unreleased_current_version_passes(monkeypatch):
    _patch(
        monkeypatch,
        version="2.11.0",
        changelog="## [2.11.0] - Unreleased\n- pending\n",
        tags=set(),
    )
    assert guard.main([]) == 0


def test_default_scope_ignores_old_untagged_history(monkeypatch):
    changelog = (
        "## [2.11.0] - 2026-05-31\n"
        "## [2.0.0] - 2025-10-15\n"  # ancient, never tagged
    )
    _patch(monkeypatch, version="2.11.0", changelog=changelog, tags={"v2.11.0"})
    # Current (2.11.0) is tagged; the old untagged 2.0.0 is out of default scope.
    assert guard.main([]) == 0
    # strict-history surfaces the historical gap.
    assert guard.main(["--strict-history"]) == 1


def test_no_require_current_tag_override(monkeypatch):
    _patch(
        monkeypatch,
        version="2.11.0",
        changelog="## [2.11.0] - 2026-05-31\n",
        tags=set(),
    )
    assert guard.main(["--no-require-current-tag"]) == 0


def test_json_output_is_emitted(monkeypatch, capsys):
    import json

    _patch(
        monkeypatch,
        version="2.11.0",
        changelog="## [2.11.0] - 2026-05-31\n",
        tags=set(),
    )
    guard.main(["--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["current_version"] == "2.11.0"
    assert payload["current_dated_as_released"] is True
    assert payload["current_tagged"] is False
    assert payload["coherent"] is False
