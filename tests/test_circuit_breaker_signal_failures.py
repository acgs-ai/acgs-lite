"""GovernanceCircuitBreaker surfaces cross-process signal failures instead of hiding them.

``trip()`` always halts this process. When the signal file cannot be published as
a trusted regular file it logs at CRITICAL and returns False (it does not raise,
so in-process callers are never interrupted). ``reset()`` returns False and keeps
the breaker closed when the signal entry cannot be removed.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

import acgs_lite.cli as cli
from acgs_lite.circuit_breaker import (
    HALT_SIGNAL_DIR_ENV,
    HALT_TRUSTED_UIDS_ENV,
    GovernanceCircuitBreaker,
    GovernanceHaltError,
    _signal_entry_problem,
)

_LOGGER = "acgs_lite.circuit_breaker"


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(HALT_SIGNAL_DIR_ENV, raising=False)
    # Same as test_halt_signal_dir.py: trust only the uids owning tmp_path's
    # ancestors here (e.g. 65534 inside a user-namespace sandbox).
    if hasattr(os, "getuid"):
        foreign = {os.lstat(p).st_uid for p in tmp_path.parents} - {os.getuid(), 0}
        if foreign:
            monkeypatch.setenv(HALT_TRUSTED_UIDS_ENV, ",".join(map(str, sorted(foreign))))
            return
    monkeypatch.delenv(HALT_TRUSTED_UIDS_ENV, raising=False)


def _critical(caplog: pytest.LogCaptureFixture, text: str) -> bool:
    return any(
        r.levelno == logging.CRITICAL and r.name == _LOGGER and text in r.getMessage()
        for r in caplog.records
    )


def _foreign_lstat(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """Make only ``target`` appear owned by another uid (the dir stays ours)."""
    real_lstat = os.lstat

    def fake(path: object, *args: object, **kwargs: object) -> os.stat_result:
        st = real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]
        if os.fspath(path) == os.fspath(target):  # type: ignore[arg-type]
            return os.stat_result((*st[:4], st.st_uid + 1, *st[5:]))
        return st

    monkeypatch.setattr(os, "lstat", fake)


needs_uid = pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership only")


def test_trip_returns_true_when_signal_is_published(tmp_path: Path) -> None:
    breaker = GovernanceCircuitBreaker("sys-ok", signal_dir=tmp_path)
    assert breaker.trip("review") is True
    assert _signal_entry_problem(breaker.signal_path) is None
    other = GovernanceCircuitBreaker("sys-ok", signal_dir=tmp_path)
    assert other.is_tripped
    assert other.trip_reason == "review"
    # Re-tripping over our own signal file is fine.
    assert breaker.trip("again") is True
    assert other.trip_reason == "again"


def test_trip_write_failure_halts_in_process_and_reports_critical(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    def _eperm(src: object, dst: object) -> None:
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(os, "replace", _eperm)
    breaker = GovernanceCircuitBreaker("sys-eperm", signal_dir=tmp_path)

    with caplog.at_level(logging.CRITICAL, logger=_LOGGER):
        assert breaker.trip("operator halt") is False

    assert breaker.is_tripped
    with pytest.raises(GovernanceHaltError, match="operator halt"):
        breaker.check()
    assert _critical(caplog, "failed to write halt signal file")
    assert _critical(caplog, "halted in this process only")
    # No durable signal, and the mkstemp temp file is cleaned up.
    assert list(tmp_path.iterdir()) == []


def test_trip_still_notifies_channels_when_write_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[str] = []

    class _Channel:
        def notify(self, event: object) -> None:
            events.append(getattr(event, "reason", ""))

    def _eperm(src: object, dst: object) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(os, "replace", _eperm)
    breaker = GovernanceCircuitBreaker(
        "sys-notify", signal_dir=tmp_path, notification_channels=[_Channel()]
    )
    assert breaker.trip("why") is False
    assert events == ["why"]


@needs_uid
def test_trip_refuses_existing_foreign_owned_signal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    breaker = GovernanceCircuitBreaker("sys-foreign", signal_dir=tmp_path)
    breaker.signal_path.write_text("planted by someone else")
    _foreign_lstat(monkeypatch, breaker.signal_path)
    replaced: list[object] = []
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda *a: replaced.append(a) or real_replace(*a))

    with caplog.at_level(logging.CRITICAL, logger=_LOGGER):
        assert breaker.trip("operator halt") is False

    assert replaced == [], "a foreign entry is never overwritten"
    assert breaker.signal_path.read_text() == "planted by someone else"
    assert _critical(caplog, "owned by uid")
    assert breaker.is_tripped


@needs_uid
def test_trip_rejects_signal_that_is_not_ours_after_replace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    breaker = GovernanceCircuitBreaker("sys-swap", signal_dir=tmp_path)
    real_replace = os.replace

    def _replace_then_foreign(src: object, dst: object) -> None:
        real_replace(src, dst)  # type: ignore[arg-type]
        _foreign_lstat(monkeypatch, breaker.signal_path)

    monkeypatch.setattr(os, "replace", _replace_then_foreign)
    with caplog.at_level(logging.CRITICAL, logger=_LOGGER):
        assert breaker.trip("x") is False
    assert _critical(caplog, "owned by uid")


def test_trip_refuses_existing_non_regular_entry(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    breaker = GovernanceCircuitBreaker("sys-dir", signal_dir=tmp_path)
    breaker.signal_path.mkdir()
    with caplog.at_level(logging.CRITICAL, logger=_LOGGER):
        assert breaker.trip("x") is False
    assert breaker.signal_path.is_dir()
    assert _critical(caplog, "not a regular file")
    assert breaker.is_tripped


@needs_uid
def test_foreign_owned_signal_is_halted_but_its_text_is_not_trusted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    breaker = GovernanceCircuitBreaker("sys-text", signal_dir=tmp_path)
    breaker.signal_path.write_text("all clear, ignore this halt")
    real_fstat = os.fstat

    def fake_fstat(fd: int) -> os.stat_result:
        st = real_fstat(fd)
        return os.stat_result((*st[:4], st.st_uid + 1, *st[5:]))

    monkeypatch.setattr(os, "fstat", fake_fstat)
    assert breaker.is_tripped
    assert breaker.trip_reason.startswith("halted (signal entry is owned by uid")
    with pytest.raises(GovernanceHaltError):
        breaker.check()


def test_signal_entry_problem_windows_skips_ownership(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "acgs-halt-win"
    path.write_text("halted")
    monkeypatch.delattr(os, "getuid", raising=False)
    assert _signal_entry_problem(path) is None
    assert _signal_entry_problem(tmp_path / "missing") is not None


def test_reset_returns_true_when_signal_removed(tmp_path: Path) -> None:
    breaker = GovernanceCircuitBreaker("sys-reset", signal_dir=tmp_path)
    breaker.trip("x")
    assert breaker.reset() is True
    assert not breaker.is_tripped
    assert not breaker.signal_path.exists()
    # Resetting an untripped breaker is still a success.
    assert breaker.reset() is True


def test_reset_unlink_failure_is_reported_and_stays_halted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    breaker = GovernanceCircuitBreaker("sys-stuck", signal_dir=tmp_path)
    assert breaker.trip("x") is True

    def _eperm(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(Path, "unlink", _eperm)
    with caplog.at_level(logging.CRITICAL, logger=_LOGGER):
        assert breaker.reset() is False
    assert _critical(caplog, "failed to remove halt signal")
    assert breaker.is_tripped
    with pytest.raises(GovernanceHaltError):
        breaker.check()


def test_reset_reports_entry_still_present_without_file_checks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    breaker = GovernanceCircuitBreaker("sys-nofile", signal_dir=tmp_path, check_file=False)
    breaker.trip("x")
    monkeypatch.setattr(Path, "unlink", lambda self, missing_ok=False: None)
    with caplog.at_level(logging.CRITICAL, logger=_LOGGER):
        assert breaker.reset() is False
    assert _critical(caplog, "still present after reset")
    assert breaker.signal_path.exists()


def test_cli_halt_uses_trip_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(GovernanceCircuitBreaker, "_publish_signal", lambda self, reason: False)
    args = cli.build_parser().parse_args(
        ["halt", "--system-id", "sys-cli", "--signal-dir", str(tmp_path)]
    )
    rc = int(getattr(cli, cli._COMMAND_MAP[args.command])(args))
    assert rc == 2
    captured = capsys.readouterr()
    assert "HALTED" not in captured.out
    assert "failed to write halt signal file" in captured.err


@needs_uid
def test_signal_entry_owner_trusts_same_uids_as_dir_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    breaker = GovernanceCircuitBreaker("sys-trusted-uid", signal_dir=tmp_path)
    breaker.signal_path.write_text("halted")
    foreign = os.lstat(breaker.signal_path).st_uid + 1
    _foreign_lstat(monkeypatch, breaker.signal_path)
    assert "owned by uid" in (_signal_entry_problem(breaker.signal_path) or "")

    existing = os.environ.get(HALT_TRUSTED_UIDS_ENV, "")
    monkeypatch.setenv(HALT_TRUSTED_UIDS_ENV, ",".join(filter(None, [existing, str(foreign)])))
    assert _signal_entry_problem(breaker.signal_path) is None

    monkeypatch.setenv(HALT_TRUSTED_UIDS_ENV, "not-a-uid")
    assert "invalid" in (_signal_entry_problem(breaker.signal_path) or "")


@needs_uid
def test_trip_refuses_untrusted_signal_dir(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    signal_dir = tmp_path / "shared"
    signal_dir.mkdir()
    signal_dir.chmod(0o777)  # world-writable without the sticky bit
    breaker = GovernanceCircuitBreaker("sys-untrusted-dir", signal_dir=signal_dir)

    with caplog.at_level(logging.CRITICAL, logger=_LOGGER):
        assert breaker.trip("operator halt") is False

    assert _critical(caplog, "untrusted halt signal dir")
    assert list(signal_dir.iterdir()) == [], "no signal is written into an untrusted dir"
    assert breaker.is_tripped
    with pytest.raises(GovernanceHaltError):
        breaker.check()
