# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs halt / acgs resume — EU AI Act Article 14 kill-switch.

Immediately halt or resume all governed agents for a given system.
Uses the GovernanceCircuitBreaker's cross-process file signaling.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import argparse
import contextlib
import os
import stat
import sys
from pathlib import Path

from acgs_lite.circuit_breaker import (
    HALT_SIGNAL_DIR_ENV,
    HALT_TRUSTED_UIDS_ENV,
    GovernanceCircuitBreaker,
    _signal_dir_problem,
    _signal_entry_problem,
    _signal_entry_state,
)

_SIGNAL_DIR_HELP = (
    f"Directory for the cross-process halt signal file "
    f"(default: ${HALT_SIGNAL_DIR_ENV}, else the system temp directory). "
    "Pre-create directories beneath symlink prefixes; automatic creation refuses symlinks."
)

_SOURCE_LABELS = {
    "explicit": "--signal-dir",
    "env": HALT_SIGNAL_DIR_ENV,
    "tempdir": "system temp directory",
}


def _make_breaker(args: argparse.Namespace) -> GovernanceCircuitBreaker | None:
    signal_dir: Path | None = getattr(args, "signal_dir", None)
    try:
        return GovernanceCircuitBreaker(system_id=args.system_id, signal_dir=signal_dir)
    except ValueError as exc:
        print(f"error: invalid --system-id: {exc}", file=sys.stderr)
        return None


def _is_regular_signal_file(path: Path) -> bool:
    return _signal_entry_problem(path) is None


def _print_signal_dir(breaker: GovernanceCircuitBreaker) -> None:
    source = _SOURCE_LABELS[breaker.signal_dir_source]
    print(f"  Signal dir: {breaker.signal_dir} (from {source})")
    if breaker.signal_dir_source == "tempdir":
        print(
            "warning: signal dir is the TMPDIR fallback; processes with a different "
            f"TMPDIR will not see this halt. Set {HALT_SIGNAL_DIR_ENV} or pass --signal-dir.",
            file=sys.stderr,
        )


def add_parser(sub: argparse._SubParsersAction) -> None:
    """Register halt and resume subcommands."""
    p_halt = sub.add_parser(
        "halt",
        help="Halt all governed agents for a system (Article 14 kill-switch)",
    )
    p_halt.add_argument(
        "--signal-dir",
        type=Path,
        default=None,
        help=_SIGNAL_DIR_HELP,
    )
    p_halt.add_argument(
        "--system-id",
        required=True,
        help="System identifier to halt",
    )
    p_halt.add_argument(
        "--reason",
        default="Manual halt via CLI",
        help="Reason for the halt (logged in signal file)",
    )

    p_resume = sub.add_parser(
        "resume",
        help="Resume governed agents after a halt",
    )
    p_resume.add_argument(
        "--signal-dir",
        type=Path,
        default=None,
        help=_SIGNAL_DIR_HELP,
    )
    p_resume.add_argument(
        "--system-id",
        required=True,
        help="System identifier to resume",
    )

    p_breaker_status = sub.add_parser(
        "breaker-status",
        help="Check circuit breaker status for a system",
    )
    p_breaker_status.add_argument(
        "--signal-dir",
        type=Path,
        default=None,
        help=_SIGNAL_DIR_HELP,
    )
    p_breaker_status.add_argument(
        "--system-id",
        required=True,
        help="System identifier to check",
    )


def _create_signal_dir(path: Path) -> None:
    """Create missing directories only through opened, trusted parents.

    Existing paths retain the normal symlink-ancestor trust checks. Creation
    deliberately refuses symlink prefixes: provision those paths separately.
    """
    if os.path.lexists(path):
        return
    if (
        os.open not in os.supports_dir_fd
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise OSError("secure directory creation unavailable; pre-create the signal directory")
    extra = os.environ.get(HALT_TRUSTED_UIDS_ENV, "")
    try:
        trusted = {os.getuid(), 0, *(int(value) for value in extra.split(",") if value.strip())}
    except ValueError as exc:
        raise OSError(f"invalid {HALT_TRUSTED_UIDS_ENV} value: {extra!r}") from exc
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = Path(path.anchor)
    descriptor = os.open(parent, flags)
    try:
        for component in path.parts[1:]:
            info = os.fstat(descriptor)
            if info.st_uid not in trusted:
                raise OSError(f"signal dir ancestor {parent} is owned by uid {info.st_uid}")
            if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                raise OSError(
                    f"signal dir ancestor {parent} is group/world-writable without the sticky bit"
                )
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                # A concurrent creator still must pass O_NOFOLLOW below.
                with contextlib.suppress(FileExistsError):
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            parent /= component
    finally:
        os.close(descriptor)


def cmd_halt(args: argparse.Namespace) -> int:
    """Halt all governed agents for a system."""
    system_id: str = args.system_id
    reason: str = args.reason

    breaker = _make_breaker(args)
    if breaker is None:
        return 2

    present, entry_error = _signal_entry_state(breaker.signal_path)
    if entry_error:
        print(
            f"error: {entry_error} ({breaker.signal_path}). "
            f"Cannot confirm a halt signal; System '{system_id}' was NOT halted by this command.",
            file=sys.stderr,
        )
        return 2

    if present:
        # An existing signal in an untrusted dir can be removed by another user.
        problem = _signal_dir_problem(breaker.signal_dir)
        if problem:
            print(
                f"error: untrusted halt signal dir: {problem}. "
                f"System '{system_id}' was NOT halted by this command.",
                file=sys.stderr,
            )
            return 2
        if not _is_regular_signal_file(breaker.signal_path):
            print(
                f"error: halt signal {breaker.signal_path} is not a trusted regular file. "
                f"System '{system_id}' was NOT halted by this command.",
                file=sys.stderr,
            )
            return 2
        existing_reason = breaker.trip_reason
        print(
            f"System '{system_id}' is already halted: {existing_reason}",
            file=sys.stderr,
        )
        _print_signal_dir(breaker)
        return 0

    try:
        _create_signal_dir(breaker.signal_dir)
    except OSError as exc:
        print(
            f"error: cannot create halt signal dir {breaker.signal_dir}: {exc}. "
            f"System '{system_id}' was NOT halted.",
            file=sys.stderr,
        )
        return 2

    problem = _signal_dir_problem(breaker.signal_dir)
    if problem:
        print(
            f"error: untrusted halt signal dir: {problem}. System '{system_id}' was NOT halted.",
            file=sys.stderr,
        )
        return 2

    # trip() halts this process even when the file write fails; its result
    # confirms the cross-process signal on disk before reporting success.
    if not breaker.trip(reason=reason):
        print(
            f"error: failed to write halt signal file {breaker.signal_path}. "
            f"System '{system_id}' was NOT halted for other processes.",
            file=sys.stderr,
        )
        return 2

    print(f"HALTED system '{system_id}'")
    print(f"  Reason: {reason}")
    print(f"  Signal: {breaker.signal_path}")
    _print_signal_dir(breaker)
    print()
    print(
        f"GovernedAgent instances for system id '{system_id}' honor this halt only if "
        f"they were created with {HALT_SIGNAL_DIR_ENV} (same dir) or "
        "ACGS_HALT_WEBHOOK_URL set, or with an explicit circuit_breaker resolving "
        "the same signal dir."
    )
    print(f"To resume: acgs resume --system-id {system_id}")
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    """Resume governed agents after a halt."""
    system_id: str = args.system_id

    breaker = _make_breaker(args)
    if breaker is None:
        return 2

    if not breaker.is_tripped:
        print(
            f"System '{system_id}' is not halted (signal dir: {breaker.signal_dir}).",
            file=sys.stderr,
        )
        return 0

    breaker.reset()
    # is_tripped also covers an untrusted signal dir, which reset() cannot clear.
    if breaker.is_tripped:
        _present, entry_error = _signal_entry_state(breaker.signal_path)
        detail = entry_error or breaker.trip_reason or "signal file still present"
        print(
            f"error: failed to remove halt signal {breaker.signal_path}: {detail}. "
            f"System '{system_id}' is still HALTED.",
            file=sys.stderr,
        )
        return 2
    print(f"RESUMED system '{system_id}'")
    print("Governed agents can now process requests.")
    return 0


def cmd_breaker_status(args: argparse.Namespace) -> int:
    """Check circuit breaker status."""
    system_id: str = args.system_id

    breaker = _make_breaker(args)
    if breaker is None:
        return 2

    if breaker.is_tripped:
        reason = breaker.trip_reason
        print(f"System '{system_id}': HALTED")
        print(f"  Reason: {reason}")
        print(f"  Signal: {breaker.signal_path}")
        _print_signal_dir(breaker)
        return 1
    else:
        print(f"System '{system_id}': OK")
        _print_signal_dir(breaker)
        return 0
