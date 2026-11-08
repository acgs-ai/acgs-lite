"""Tests for halt signal-dir resolution and the halt/resume/breaker-status CLI."""

from __future__ import annotations

import asyncio
import logging
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import acgs_lite.cli as cli
from acgs_lite.circuit_breaker import (
    HALT_SIGNAL_DIR_ENV,
    HALT_TRUSTED_UIDS_ENV,
    GovernanceCircuitBreaker,
    GovernanceHaltError,
    WebhookNotificationChannel,
    _signal_dir_ancestors_problem,
)
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.governed import GovernedAgent, GovernedCallable
from acgs_lite.legitimacy import AuthorizationProfile
from acgs_lite.maci import MACIRole

_WORKTREE_SRC = Path(__file__).resolve().parents[1] / "src"


def _run_cli(argv: list[str]) -> int:
    """Dispatch through the real parser and command map, like ``acgs``."""
    args = cli.build_parser().parse_args(argv)
    handler = getattr(cli, cli._COMMAND_MAP[args.command])
    return int(handler(args))


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(HALT_SIGNAL_DIR_ENV, raising=False)
    # Opt in only the uids that own tmp_path's ancestors in *this* environment
    # (e.g. 65534 for /tmp inside a user-namespace sandbox). Empty on a normal
    # host, where those ancestors are owned by root or the current user.
    if hasattr(os, "getuid"):
        foreign = {os.lstat(p).st_uid for p in tmp_path.parents} - {os.getuid(), 0}
        if foreign:
            monkeypatch.setenv(HALT_TRUSTED_UIDS_ENV, ",".join(map(str, sorted(foreign))))
            return
    monkeypatch.delenv(HALT_TRUSTED_UIDS_ENV, raising=False)


# ── Resolution precedence ────────────────────────────────────────────────────


def test_env_var_sets_signal_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(tmp_path))
    breaker = GovernanceCircuitBreaker(system_id="s")
    assert breaker.signal_dir == tmp_path
    assert breaker.signal_dir_source == "env"


def test_env_var_resolved_at_construction_not_import(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = GovernanceCircuitBreaker(system_id="s")
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(tmp_path / "later"))
    second = GovernanceCircuitBreaker(system_id="s")
    assert first.signal_dir_source == "tempdir"
    assert second.signal_dir == tmp_path / "later"


def test_explicit_arg_beats_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(tmp_path / "env"))
    breaker = GovernanceCircuitBreaker(system_id="s", signal_dir=tmp_path / "arg")
    assert breaker.signal_dir == tmp_path / "arg"
    assert breaker.signal_dir_source == "explicit"


def test_empty_env_falls_back_to_tempdir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, "   ")
    breaker = GovernanceCircuitBreaker(system_id="s")
    assert breaker.signal_dir == Path(tempfile.gettempdir())
    assert breaker.signal_dir_source == "tempdir"


def test_tilde_is_expanded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, "~/halts")
    assert GovernanceCircuitBreaker(system_id="s").signal_dir == tmp_path / "halts"
    explicit = GovernanceCircuitBreaker(system_id="s", signal_dir=Path("~/x"))
    assert explicit.signal_dir == tmp_path / "x"


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_flag_beats_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env_dir = tmp_path / "env"
    flag_dir = tmp_path / "flag"
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(env_dir))

    rc = _run_cli(["halt", "--system-id", "sys-flag", "--signal-dir", str(flag_dir)])

    assert rc == 0
    assert (flag_dir / "acgs-halt-sys-flag").is_file()
    assert not (env_dir / "acgs-halt-sys-flag").exists()
    out = capsys.readouterr().out
    assert f"Signal dir: {flag_dir} (from --signal-dir)" in out

    # An existing env directory has no signal; the flag directory does.
    env_dir.mkdir()
    assert _run_cli(["breaker-status", "--system-id", "sys-flag"]) == 0
    assert (
        _run_cli(["breaker-status", "--system-id", "sys-flag", "--signal-dir", str(flag_dir)]) == 1
    )
    assert _run_cli(["resume", "--system-id", "sys-flag", "--signal-dir", str(flag_dir)]) == 0
    assert not (flag_dir / "acgs-halt-sys-flag").exists()


def test_cli_halt_creates_missing_signal_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    signal_dir = tmp_path / "a" / "b" / "c"
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(signal_dir))

    assert _run_cli(["halt", "--system-id", "sys-mk", "--reason", "r"]) == 0

    assert (signal_dir / "acgs-halt-sys-mk").read_text() == "r"
    captured = capsys.readouterr()
    assert "HALTED system 'sys-mk'" in captured.out
    assert f"(from {HALT_SIGNAL_DIR_ENV})" in captured.out
    assert "TMPDIR" not in captured.err


def test_cli_fallback_warning_without_env_or_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    assert _run_cli(["breaker-status", "--system-id", "sys-fallback"]) == 0
    captured = capsys.readouterr()
    assert f"Signal dir: {tmp_path} (from system temp directory)" in captured.out
    assert "different TMPDIR will not see this halt" in captured.err
    assert HALT_SIGNAL_DIR_ENV in captured.err
    assert "--signal-dir" in captured.err

    assert _run_cli(["halt", "--system-id", "sys-fallback"]) == 0
    captured = capsys.readouterr()
    assert "HALTED system 'sys-fallback'" in captured.out
    assert "different TMPDIR will not see this halt" in captured.err
    assert (tmp_path / "acgs-halt-sys-fallback").is_file()


def test_cli_halt_fails_closed_when_dir_cannot_be_created(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "afile"
    blocker.write_text("not a directory")

    rc = _run_cli(["halt", "--system-id", "sys-bad", "--signal-dir", str(blocker / "sub")])

    assert rc != 0
    captured = capsys.readouterr()
    assert "HALTED" not in captured.out
    assert "was NOT halted" in captured.err


def test_cli_halt_fails_closed_when_signal_write_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def _boom(src: object, dst: object) -> None:
        raise PermissionError("read-only")

    monkeypatch.setattr(os, "replace", _boom)

    rc = _run_cli(["halt", "--system-id", "sys-ro", "--signal-dir", str(tmp_path)])

    assert rc != 0
    captured = capsys.readouterr()
    assert "HALTED" not in captured.out
    assert "failed to write halt signal file" in captured.err
    assert not (tmp_path / "acgs-halt-sys-ro").exists()
    # The mkstemp temp file is cleaned up on failure.
    assert list(tmp_path.iterdir()) == []


def _skip_if_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("running as root: file permissions are not enforced")


def test_cli_halt_fails_closed_on_unwritable_dir(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _skip_if_root()
    signal_dir = tmp_path / "ro"
    signal_dir.mkdir()
    signal_dir.chmod(0o500)
    try:
        rc = _run_cli(["halt", "--system-id", "sys-perm", "--signal-dir", str(signal_dir)])
    finally:
        signal_dir.chmod(0o700)

    assert rc != 0
    assert "HALTED" not in capsys.readouterr().out


# ── Fail-closed signal inspection ────────────────────────────────────────────


def test_unreadable_signal_dir_counts_as_tripped(tmp_path: Path) -> None:
    _skip_if_root()
    signal_dir = tmp_path / "locked"
    signal_dir.mkdir()
    breaker = GovernanceCircuitBreaker(system_id="sys-locked", signal_dir=signal_dir)
    signal_dir.chmod(0o000)
    try:
        assert breaker.is_tripped is True
        with pytest.raises(GovernanceHaltError, match="halt signal unreadable"):
            breaker.check()
    finally:
        signal_dir.chmod(0o700)
    assert breaker.is_tripped is False


def test_directory_at_signal_path_counts_as_tripped(tmp_path: Path) -> None:
    (tmp_path / "acgs-halt-sys-dir").mkdir()
    breaker = GovernanceCircuitBreaker(system_id="sys-dir", signal_dir=tmp_path)
    assert breaker.is_tripped is True
    with pytest.raises(GovernanceHaltError, match="not a regular file"):
        breaker.check()


def test_dangling_symlink_at_signal_path_counts_as_tripped(tmp_path: Path) -> None:
    (tmp_path / "acgs-halt-sys-link").symlink_to(tmp_path / "does-not-exist")
    breaker = GovernanceCircuitBreaker(system_id="sys-link", signal_dir=tmp_path)
    assert breaker.is_tripped is True
    with pytest.raises(GovernanceHaltError):
        breaker.check()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs required")
def test_fifo_at_signal_path_is_tripped_without_hanging(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "acgs-halt-sys-fifo")
    breaker = GovernanceCircuitBreaker(system_id="sys-fifo", signal_dir=tmp_path)
    assert breaker.is_tripped is True
    assert breaker.trip_reason == "halted (signal entry is not a regular file)"


def test_unreadable_signal_file_has_fallback_reason(tmp_path: Path) -> None:
    _skip_if_root()
    signal = tmp_path / "acgs-halt-sys-noread"
    signal.write_text("secret reason")
    signal.chmod(0o000)
    try:
        breaker = GovernanceCircuitBreaker(system_id="sys-noread", signal_dir=tmp_path)
        assert breaker.is_tripped is True
        assert breaker.trip_reason == "halted (reason unavailable)"
    finally:
        signal.chmod(0o600)


def test_cli_status_reports_halted_when_signal_unreadable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _skip_if_root()
    signal_dir = tmp_path / "locked"
    signal_dir.mkdir()
    signal_dir.chmod(0o000)
    try:
        status = _run_cli(
            ["breaker-status", "--system-id", "sys-u", "--signal-dir", str(signal_dir)]
        )
        halt = _run_cli(["halt", "--system-id", "sys-u", "--signal-dir", str(signal_dir)])
    finally:
        signal_dir.chmod(0o700)
    assert status == 1
    assert halt == 2
    out = capsys.readouterr().out
    assert "HALTED system" not in out


# ── Signal dir trust ─────────────────────────────────────────────────────────


def test_cli_halt_refuses_world_writable_dir_without_sticky(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    signal_dir = tmp_path / "open"
    signal_dir.mkdir()
    signal_dir.chmod(0o777)

    rc = _run_cli(["halt", "--system-id", "sys-open", "--signal-dir", str(signal_dir)])

    assert rc == 2
    captured = capsys.readouterr()
    assert "HALTED" not in captured.out
    assert "group/world-writable" in captured.err
    assert "was NOT halted" in captured.err
    assert not (signal_dir / "acgs-halt-sys-open").exists()


def test_cli_halt_accepts_sticky_world_writable_dir(tmp_path: Path) -> None:
    signal_dir = tmp_path / "sticky"
    signal_dir.mkdir()
    signal_dir.chmod(0o1777)
    assert _run_cli(["halt", "--system-id", "sys-sticky", "--signal-dir", str(signal_dir)]) == 0
    assert (signal_dir / "acgs-halt-sys-sticky").is_file()


def test_cli_halt_refuses_symlinked_signal_dir(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)

    rc = _run_cli(["halt", "--system-id", "sys-sym", "--signal-dir", str(link)])

    assert rc == 2
    assert "is a symlink" in capsys.readouterr().err
    assert not (real / "acgs-halt-sys-sym").exists()


def test_cli_halt_creates_dir_with_mode_0700(tmp_path: Path) -> None:
    signal_dir = tmp_path / "new"
    assert _run_cli(["halt", "--system-id", "sys-mode", "--signal-dir", str(signal_dir)]) == 0
    assert stat.S_IMODE(signal_dir.stat().st_mode) == 0o700


def test_untrusted_env_dir_logs_critical_on_construction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    signal_dir = tmp_path / "open"
    signal_dir.mkdir()
    signal_dir.chmod(0o777)
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(signal_dir))
    with caplog.at_level(logging.CRITICAL, logger="acgs_lite.circuit_breaker"):
        GovernanceCircuitBreaker(system_id="sys-crit")
    assert any(
        r.levelno == logging.CRITICAL and "untrusted halt signal dir" in r.getMessage()
        for r in caplog.records
    )


def test_relative_env_path_resolved_absolute(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, "rel/halts")
    breaker = GovernanceCircuitBreaker(system_id="sys-rel")
    assert breaker.signal_dir.is_absolute()
    assert breaker.signal_dir == tmp_path / "rel" / "halts"

    assert _run_cli(["halt", "--system-id", "sys-rel"]) == 0
    assert f"Signal dir: {tmp_path / 'rel' / 'halts'} (from" in capsys.readouterr().out


# ── Resume / atomic write / system_id ────────────────────────────────────────


def test_cli_resume_fails_when_unlink_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    signal = tmp_path / "acgs-halt-sys-stuck"
    signal.write_text("halt")

    def _boom(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError("busy")

    monkeypatch.setattr(Path, "unlink", _boom)

    rc = _run_cli(["resume", "--system-id", "sys-stuck", "--signal-dir", str(tmp_path)])

    assert rc == 2
    captured = capsys.readouterr()
    assert "RESUMED" not in captured.out
    assert "still HALTED" in captured.err
    assert signal.exists()


def test_dotted_system_ids_do_not_interfere(tmp_path: Path) -> None:
    a_v1 = GovernanceCircuitBreaker(system_id="a.v1", signal_dir=tmp_path)
    a_v2 = GovernanceCircuitBreaker(system_id="a.v2", signal_dir=tmp_path)
    a_tmp = GovernanceCircuitBreaker(system_id="a.tmp", signal_dir=tmp_path)
    a_plain = GovernanceCircuitBreaker(system_id="a", signal_dir=tmp_path)

    a_v1.trip("one")
    a_v2.trip("two")

    fresh = {
        sid: GovernanceCircuitBreaker(system_id=sid, signal_dir=tmp_path)
        for sid in ("a.v1", "a.v2", "a.tmp", "a")
    }
    assert fresh["a.v1"].trip_reason == "one"
    assert fresh["a.v2"].trip_reason == "two"
    assert fresh["a.tmp"].is_tripped is False
    assert fresh["a"].is_tripped is False
    assert not a_tmp.is_tripped and not a_plain.is_tripped
    assert sorted(p.name for p in tmp_path.iterdir()) == ["acgs-halt-a.v1", "acgs-halt-a.v2"]


def test_trip_does_not_follow_planted_tmp_symlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("original")
    signal_dir = tmp_path / "sig"
    signal_dir.mkdir()
    # The old implementation wrote to "<signal>.tmp" and would follow this link.
    (signal_dir / "acgs-halt-sys-plant.tmp").symlink_to(victim)

    GovernanceCircuitBreaker(system_id="sys-plant", signal_dir=signal_dir).trip("halt")

    assert victim.read_text() == "original"
    assert (signal_dir / "acgs-halt-sys-plant").read_text() == "halt"


@pytest.mark.parametrize("bad", ["", ".", "..", "a/b", "../x", "a\x00b"])
def test_invalid_system_id_rejected(bad: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        GovernanceCircuitBreaker(system_id=bad, signal_dir=tmp_path)


def test_cli_rejects_system_id_with_separator(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _run_cli(["halt", "--system-id", "../escape", "--signal-dir", str(tmp_path)])
    assert rc == 2
    assert "invalid --system-id" in capsys.readouterr().err
    assert not (tmp_path.parent / "acgs-halt-escape").exists()


def test_signal_path_is_public(tmp_path: Path) -> None:
    breaker = GovernanceCircuitBreaker(system_id="pub", signal_dir=tmp_path)
    assert breaker.signal_path == tmp_path / "acgs-halt-pub"


def test_cross_process_halt_with_different_tmpdir(tmp_path: Path) -> None:
    tmp_a = tmp_path / "tmp-a"
    tmp_b = tmp_path / "tmp-b"
    shared = tmp_path / "shared-signal"
    tmp_a.mkdir()
    tmp_b.mkdir()
    pythonpath = os.pathsep.join(
        [str(_WORKTREE_SRC), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    base_env = {k: v for k, v in os.environ.items() if k != HALT_SIGNAL_DIR_ENV}
    base_env["PYTHONPATH"] = pythonpath

    def run(tmpdir: Path, *argv: str, signal_env: bool = True) -> subprocess.CompletedProcess[str]:
        env = {**base_env, "TMPDIR": str(tmpdir)}
        if signal_env:
            env[HALT_SIGNAL_DIR_ENV] = str(shared)
        return subprocess.run(
            [sys.executable, *argv], env=env, capture_output=True, text=True, timeout=60
        )

    # Prove the subprocess imports this checkout's code, not another install.
    probe = run(tmp_a, "-c", "import acgs_lite.circuit_breaker as m; print(m.__file__)")
    assert probe.returncode == 0, probe.stderr
    assert Path(probe.stdout.strip()).resolve().is_relative_to(_WORKTREE_SRC)

    halt = run(tmp_a, "-m", "acgs_lite.cli", "halt", "--system-id", "xproc", "--reason", "stop")
    assert halt.returncode == 0, halt.stderr
    assert "HALTED system 'xproc'" in halt.stdout
    assert (shared / "acgs-halt-xproc").is_file()

    status = run(tmp_b, "-m", "acgs_lite.cli", "breaker-status", "--system-id", "xproc")
    assert status.returncode == 1, status.stdout + status.stderr
    assert "HALTED" in status.stdout
    assert "stop" in status.stdout

    # Without the shared env var, the TMPDIR=B process cannot see the halt
    # and is warned about it — the original bug, now surfaced.
    blind = run(
        tmp_b, "-m", "acgs_lite.cli", "breaker-status", "--system-id", "xproc", signal_env=False
    )
    assert blind.returncode == 0
    assert "different TMPDIR will not see this halt" in blind.stderr


# ── GovernedAgent ────────────────────────────────────────────────────────────


@pytest.fixture
def _no_halt_webhook(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACGS_HALT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ACGS_HALT_WEBHOOK_SECRET", raising=False)


@pytest.mark.usefixtures("_no_halt_webhook")
def test_governed_agent_breaker_from_signal_dir_env_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(tmp_path))
    agent = GovernedAgent(lambda prompt: prompt, agent_id="ga-env", maci_role=MACIRole.EXECUTOR)

    breaker = agent._circuit_breaker
    assert breaker is not None
    assert breaker.signal_dir == tmp_path
    assert breaker.signal_dir_source == "env"
    assert breaker._notification_channels == []
    assert agent.run("hello", governance_action="execute") == "hello"

    # Halt from the CLI (separate breaker, same env-resolved dir).
    assert _run_cli(["halt", "--system-id", "ga-env", "--reason", "operator halt"]) == 0
    assert "honor this halt only if" in capsys.readouterr().out
    with pytest.raises(GovernanceHaltError, match="operator halt"):
        agent.run("hello", governance_action="execute")

    assert _run_cli(["resume", "--system-id", "ga-env"]) == 0
    assert agent.run("hello", governance_action="execute") == "hello"


@pytest.mark.usefixtures("_no_halt_webhook")
def test_governed_agent_webhook_and_signal_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(tmp_path))
    monkeypatch.setenv("ACGS_HALT_WEBHOOK_URL", "http://127.0.0.1:9/unused")
    agent = GovernedAgent(lambda prompt: prompt, agent_id="ga-both")

    breaker = agent._circuit_breaker
    assert breaker is not None
    assert breaker.signal_dir == tmp_path
    assert len(breaker._notification_channels) == 1
    assert isinstance(breaker._notification_channels[0], WebhookNotificationChannel)


@pytest.mark.usefixtures("_no_halt_webhook")
def test_governed_agent_explicit_breaker_wins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(tmp_path / "env"))
    explicit = GovernanceCircuitBreaker(system_id="ga-x", signal_dir=tmp_path / "arg")
    agent = GovernedAgent(lambda prompt: prompt, agent_id="ga-x", circuit_breaker=explicit)
    assert agent._circuit_breaker is explicit


@pytest.mark.usefixtures("_no_halt_webhook")
def test_governed_agent_has_no_default_breaker_without_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Documents the unchanged default: no webhook, no signal-dir env -> no breaker.
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, "  ")
    assert GovernedAgent(lambda prompt: prompt, agent_id="ga-none")._circuit_breaker is None
    monkeypatch.delenv(HALT_SIGNAL_DIR_ENV)
    assert GovernedAgent(lambda prompt: prompt, agent_id="ga-none")._circuit_breaker is None


# ── PR 236 review follow-ups ─────────────────────────────────────────────────


def test_non_directory_signal_dir_parent_counts_as_tripped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A regular file where the signal dir should be makes the signal path
    # uninspectable (ENOTDIR); that must fail closed, not read as "absent".
    blocker = tmp_path / "afile"
    blocker.write_text("not a directory")
    signal_dir = blocker / "sub"

    breaker = GovernanceCircuitBreaker(system_id="sys-notdir", signal_dir=signal_dir)
    assert breaker.is_tripped is True
    with pytest.raises(GovernanceHaltError, match="halt signal unreadable"):
        breaker.check()
    status = _run_cli(
        ["breaker-status", "--system-id", "sys-notdir", "--signal-dir", str(signal_dir)]
    )
    assert status == 1
    assert "HALTED" in capsys.readouterr().out


def test_cli_halt_already_halted_in_untrusted_dir_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    signal_dir = tmp_path / "open"
    signal_dir.mkdir()
    (signal_dir / "acgs-halt-sys-pre").write_text("earlier")
    signal_dir.chmod(0o777)

    rc = _run_cli(["halt", "--system-id", "sys-pre", "--signal-dir", str(signal_dir)])

    assert rc == 2
    err = capsys.readouterr().err
    assert "group/world-writable" in err
    assert "already halted" not in err


def test_cli_halt_refuses_world_writable_ancestor(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    signal_dir = shared / "mine"

    rc = _run_cli(["halt", "--system-id", "sys-anc", "--signal-dir", str(signal_dir)])

    assert rc == 2
    err = capsys.readouterr().err
    assert f"ancestor {shared} is group/world-writable" in err
    assert "was NOT halted" in err
    assert not (signal_dir / "acgs-halt-sys-anc").exists()


def test_cli_halt_refuses_symlinked_ancestor_into_world_writable_dir(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    link = tmp_path / "link"
    link.symlink_to(shared)
    signal_dir = link / "mine"

    rc = _run_cli(["halt", "--system-id", "sys-symanc", "--signal-dir", str(signal_dir)])

    assert rc == 2
    assert f"ancestor {shared} is group/world-writable" in capsys.readouterr().err
    assert not (shared / "mine" / "acgs-halt-sys-symanc").exists()


def test_cli_halt_accepts_symlinked_ancestor_into_trusted_dir(tmp_path: Path) -> None:
    # Like macOS /var -> /private/var: a trusted symlink ancestor is fine.
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    signal_dir = link / "mine"

    assert _run_cli(["halt", "--system-id", "sys-okanc", "--signal-dir", str(signal_dir)]) == 0
    assert (real / "mine" / "acgs-halt-sys-okanc").is_file()


@pytest.mark.parametrize("relative", [False, True])
def test_intermediate_symlink_target_cannot_redirect_halt(tmp_path: Path, relative: bool) -> None:
    shared = tmp_path / "writable"
    shared.mkdir(mode=0o777)
    shared.chmod(0o777)
    first = tmp_path / "first"
    second = tmp_path / "second"
    for tree in (first, second):
        (tree / "signals").mkdir(parents=True)
    pivot = shared / "pivot"
    pivot.symlink_to(Path("../first") if relative else first)
    link = tmp_path / "operator-link"
    link.symlink_to(pivot.relative_to(tmp_path) if relative else pivot)
    (first / "signals" / "acgs-halt-pivot").write_text("halted")
    breaker = GovernanceCircuitBreaker(system_id="pivot", signal_dir=link / "signals")
    assert breaker.is_tripped
    pivot.unlink()
    pivot.symlink_to(Path("../second") if relative else second)
    assert breaker.is_tripped
    with pytest.raises(GovernanceHaltError):
        breaker.check()


def test_cli_halt_creates_intermediate_dirs_0700_under_loose_umask(tmp_path: Path) -> None:
    signal_dir = tmp_path / "a" / "b" / "c"
    old = os.umask(0o002)
    try:
        rc = _run_cli(["halt", "--system-id", "sys-umask", "--signal-dir", str(signal_dir)])
    finally:
        os.umask(old)
    assert rc == 0
    for directory in (tmp_path / "a", tmp_path / "a" / "b", signal_dir):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_trip_works_for_system_id_near_name_max(tmp_path: Path) -> None:
    name_max = os.pathconf(tmp_path, "PC_NAME_MAX")
    system_id = "x" * (name_max - len("acgs-halt-"))
    breaker = GovernanceCircuitBreaker(system_id=system_id, signal_dir=tmp_path)

    breaker.trip("long")

    assert breaker.signal_path.read_text() == "long"
    assert [p.name for p in tmp_path.iterdir()] == [breaker.signal_path.name]


# ── Security review of c495619c ──────────────────────────────────────────────


def _fake_owner(monkeypatch: pytest.MonkeyPatch, target: Path, uid: int) -> None:
    """Make os.lstat/os.stat report ``uid`` as the owner of ``target``."""

    def wrap(real):  # type: ignore[no-untyped-def]
        def fake(path, *args, **kwargs):  # type: ignore[no-untyped-def]
            st = real(path, *args, **kwargs)
            if isinstance(path, (str, os.PathLike)) and Path(path) == target:
                fields = list(st[:10])
                fields[4] = uid
                return os.stat_result(fields)
            return st

        return fake

    monkeypatch.setattr(os, "lstat", wrap(os.lstat))
    monkeypatch.setattr(os, "stat", wrap(os.stat))


_FOREIGN_UID = 4242


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership required")
def test_cli_halt_refuses_foreign_owned_ancestor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    _fake_owner(monkeypatch, shared, _FOREIGN_UID)

    rc = _run_cli(["halt", "--system-id", "sys-foreign", "--signal-dir", str(shared / "mine")])

    assert rc == 2
    err = capsys.readouterr().err
    assert f"ancestor {shared} is owned by uid {_FOREIGN_UID}" in err
    assert "was NOT halted" in err


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership required")
def test_overflow_uid_ancestor_untrusted_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # 65534 is the user-namespace overflow uid; it must not be trusted
    # implicitly (it also stands in for every unmapped host user).
    monkeypatch.delenv(HALT_TRUSTED_UIDS_ENV, raising=False)
    shared = tmp_path / "shared"
    (shared / "mine").mkdir(parents=True)
    _fake_owner(monkeypatch, shared, 65534)

    problem = _signal_dir_ancestors_problem(shared / "mine", os.getuid())

    assert problem is not None
    assert "owned by uid 65534" in problem


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership required")
def test_trusted_uids_env_opt_in_allows_ancestor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    existing = os.environ.get(HALT_TRUSTED_UIDS_ENV, "")
    monkeypatch.setenv(HALT_TRUSTED_UIDS_ENV, ",".join(filter(None, [existing, str(_FOREIGN_UID)])))
    shared = tmp_path / "shared"
    shared.mkdir()
    _fake_owner(monkeypatch, shared, _FOREIGN_UID)

    signal_dir = shared / "mine"
    assert _run_cli(["halt", "--system-id", "sys-optin", "--signal-dir", str(signal_dir)]) == 0
    assert (signal_dir / "acgs-halt-sys-optin").is_file()


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership required")
def test_cli_halt_invalid_trusted_uids_env_fails_closed_without_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(HALT_TRUSTED_UIDS_ENV, "root")

    rc = _run_cli(["halt", "--system-id", "sys-badenv", "--signal-dir", str(tmp_path / "s")])

    assert rc == 2
    err = capsys.readouterr().err
    assert f"invalid {HALT_TRUSTED_UIDS_ENV} value" in err
    assert "was NOT halted" in err


def test_untrusted_env_signal_dir_counts_as_tripped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    signal_dir = tmp_path / "open"
    signal_dir.mkdir()
    signal_dir.chmod(0o777)
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(signal_dir))

    breaker = GovernanceCircuitBreaker(system_id="sys-untrusted")
    assert breaker.is_tripped is True
    with pytest.raises(GovernanceHaltError, match="untrusted signal dir"):
        breaker.check()

    assert _run_cli(["breaker-status", "--system-id", "sys-untrusted"]) == 1
    assert _run_cli(["resume", "--system-id", "sys-untrusted"]) == 2
    out = capsys.readouterr()
    assert "RESUMED" not in out.out
    assert "still HALTED" in out.err

    signal_dir.chmod(0o700)
    assert breaker.is_tripped is False


def test_missing_explicit_signal_dir_fails_closed(tmp_path: Path) -> None:
    # A configured kill switch must be inspectable before execution.
    breaker = GovernanceCircuitBreaker(system_id="sys-later", signal_dir=tmp_path / "later")
    assert breaker.is_tripped is True


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership required")
def test_cli_halt_rejects_foreign_signal_in_sticky_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o1777)
    signal = tmp_path / "acgs-halt-planted"
    signal.write_text("planted")
    _fake_owner(monkeypatch, signal, _FOREIGN_UID)

    assert _run_cli(["halt", "--system-id", "planted", "--signal-dir", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert "already halted" not in captured.err
    assert "NOT halted" in captured.err


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership required")
def test_cli_halt_rejects_foreign_signal_after_failed_publication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o1777)
    signal = tmp_path / "acgs-halt-race"
    _fake_owner(monkeypatch, signal, _FOREIGN_UID)

    def replace_fails(*args: object) -> None:
        signal.write_text("planted during publication")
        raise PermissionError("sticky directory protects foreign inode")

    monkeypatch.setattr(os, "replace", replace_fails)
    assert _run_cli(["halt", "--system-id", "race", "--signal-dir", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert "HALTED system" not in captured.out
    assert "NOT halted" in captured.err


def test_fallback_signal_directory_trust_rechecked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    breaker = GovernanceCircuitBreaker(system_id="fallback")
    assert not breaker.is_tripped
    tmp_path.chmod(0o777)
    assert breaker.is_tripped


@pytest.mark.usefixtures("_no_halt_webhook")
def test_async_agent_honors_shared_halt_before_side_effect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(tmp_path))
    calls: list[str] = []

    async def action(prompt: str) -> str:
        calls.append(prompt)
        return prompt

    agent = GovernedAgent(action, agent_id="async-agent", maci_role=MACIRole.EXECUTOR)
    assert _run_cli(["halt", "--system-id", "async-agent"]) == 0
    with pytest.raises(GovernanceHaltError):
        asyncio.run(agent.arun("hello", governance_action="execute"))
    assert calls == []


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("production", [False, True])
def test_governed_callable_honors_shared_halt_before_side_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    asynchronous: bool,
    explicit: bool,
    production: bool,
) -> None:
    monkeypatch.setenv(HALT_SIGNAL_DIR_ENV, str(tmp_path))
    calls: list[str] = []
    breaker = (
        GovernanceCircuitBreaker(system_id="halt-callable", signal_dir=tmp_path)
        if explicit
        else None
    )
    if production:
        pytest.importorskip("cryptography")
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)), key_id="halt-test")
        guard = GovernedCallable(
            agent_id="halt-callable",
            circuit_breaker=breaker,
            authorization_profile=AuthorizationProfile.PRODUCTION,
            receipt_signer=signer,
            trusted_execution_keys={signer.key_id: signer.public_key_hex()},
        )
    else:
        guard = GovernedCallable(agent_id="halt-callable", circuit_breaker=breaker)
    if explicit:
        assert guard._circuit_breaker is breaker

    async def async_action(prompt: str) -> str:
        calls.append(prompt)
        return prompt

    def sync_action(prompt: str) -> str:
        calls.append(prompt)
        return prompt

    target = guard(async_action if asynchronous else sync_action)
    grant = guard.issue_grant(target, "hello")
    assert _run_cli(["halt", "--system-id", "halt-callable"]) == 0
    with pytest.raises(GovernanceHaltError):
        if asynchronous:
            asyncio.run(target("hello", execution_grant=grant))
        else:
            target("hello", execution_grant=grant)
    assert calls == []

    # A refused call must not consume the authorization; resume can use it once.
    assert _run_cli(["resume", "--system-id", "halt-callable"]) == 0
    if asynchronous:
        assert asyncio.run(target("hello", execution_grant=grant)) == "hello"
    else:
        assert target("hello", execution_grant=grant) == "hello"
    assert calls == ["hello"]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_agent_rechecks_halt_before_output_retry(tmp_path: Path, asynchronous: bool) -> None:
    breaker = GovernanceCircuitBreaker(system_id="retry-agent", signal_dir=tmp_path)
    calls: list[str] = []
    constitution = Constitution.from_rules(
        [
            Rule(
                id="RETRY-DENY",
                text="No forbiddenword",
                keywords=["forbiddenword"],
                severity=Severity.CRITICAL,
            )
        ]
    )

    def action(prompt: str) -> str:
        calls.append(prompt)
        breaker.trip("stop before retry")
        return "forbiddenword"

    async def async_action(prompt: str) -> str:
        return action(prompt)

    agent = GovernedAgent(
        async_action if asynchronous else action,
        constitution=constitution,
        agent_id="retry-agent",
        maci_role=MACIRole.EXECUTOR,
        circuit_breaker=breaker,
        max_retries=1,
    )
    with pytest.raises(GovernanceHaltError, match="stop before retry"):
        if asynchronous:
            asyncio.run(agent.arun("hello", governance_action="execute"))
        else:
            agent.run("hello", governance_action="execute")
    assert calls == ["hello"]
