# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Global governance circuit breaker — EU AI Act Article 14 kill-switch.

Article 14 requires that high-risk AI systems allow natural persons to
intervene, halt, or override the system. This module provides a
thread-safe, cross-process mechanism to halt all governed agents.

Usage::

    from acgs_lite import GovernanceCircuitBreaker

    breaker = GovernanceCircuitBreaker(system_id="cv-screener")

    # Trip the breaker (halt all governed agents for this system)
    breaker.trip(reason="Human oversight review required")

    # Check status
    if breaker.is_tripped:
        print(f"HALTED: {breaker.trip_reason}")

    # Resume operations
    breaker.reset()

Cross-process signaling uses a file-based mechanism:
    {signal_dir}/acgs-halt-{system_id}

The signal directory is resolved when the breaker is constructed: an explicit
``signal_dir`` argument wins, then the ``ACGS_HALT_SIGNAL_DIR`` environment
variable, then the system temp directory. Processes that halt and check must
resolve the same directory; set ``ACGS_HALT_SIGNAL_DIR`` when they may run
with different ``TMPDIR`` values. A relative directory is made absolute against
the current working directory once, at construction (without following
symlinks, so a symlinked signal dir is still detected by the trust check).

Fail closed: any entry at the signal path (file, directory, dangling symlink)
counts as tripped, and a signal path that cannot be inspected for any reason
other than "does not exist" also counts as tripped.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import contextlib
import hmac
import json
import logging
import os
import stat
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_DEFAULT_SIGNAL_DIR = Path(tempfile.gettempdir())

HALT_SIGNAL_DIR_ENV = "ACGS_HALT_SIGNAL_DIR"

# Opt-in: comma-separated extra uids trusted to own signal dir *ancestors*
# (e.g. the overflow uid 65534 that stands in for root inside a user
# namespace). Never applies to the signal dir itself. Default: none.
HALT_TRUSTED_UIDS_ENV = "ACGS_HALT_TRUSTED_UIDS"

SignalDirSource = Literal["explicit", "env", "tempdir"]


_SIGNAL_READ_LIMIT = 4096


def _absolute(path: Path) -> Path:
    # abspath (not Path.resolve) so a symlinked final component is preserved
    # and can be rejected by _signal_dir_problem().
    return Path(os.path.abspath(path.expanduser()))


def _resolve_signal_dir(signal_dir: Path | None) -> tuple[Path, SignalDirSource]:
    """Resolve the halt signal directory and report where it came from.

    Precedence: explicit argument > ``ACGS_HALT_SIGNAL_DIR`` (if non-empty)
    > ``tempfile.gettempdir()``. Resolved per call, not at import time.
    ``~`` is expanded and relative paths are made absolute against the cwd.
    """
    if signal_dir is not None:
        return _absolute(Path(signal_dir)), "explicit"
    env_value = os.environ.get(HALT_SIGNAL_DIR_ENV, "").strip()
    if env_value:
        return _absolute(Path(env_value)), "env"
    return _absolute(Path(tempfile.gettempdir())), "tempdir"


def _signal_dir_problem(path: Path) -> str | None:
    """Return why ``path`` is not a trustworthy signal dir, or None if it is.

    Trusted means: a real directory (not a symlink), owned by the current
    user or root, and not group/world-writable unless the sticky bit is set.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return f"signal dir {path} does not exist"
    except OSError as exc:
        return f"cannot inspect signal dir {path}: {exc}"
    if stat.S_ISLNK(st.st_mode):
        return f"signal dir {path} is a symlink"
    if not stat.S_ISDIR(st.st_mode):
        return f"signal dir {path} is not a directory"
    getuid = getattr(os, "getuid", None)
    if getuid is not None:
        uid = getuid()
        if st.st_uid not in (uid, 0):
            return f"signal dir {path} is owned by uid {st.st_uid}, not {uid} or root"
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not st.st_mode & stat.S_ISVTX:
            return f"signal dir {path} is group/world-writable without the sticky bit"
        return _signal_dir_ancestors_problem(path, uid)
    return None


def _trusted_uids(uid: int) -> set[int]:
    """Our uid, root and the ``ACGS_HALT_TRUSTED_UIDS`` opt-ins; ValueError if invalid."""
    extra = os.environ.get(HALT_TRUSTED_UIDS_ENV, "")
    return {uid, 0, *(int(v) for v in extra.split(",") if v.strip())}


def _signal_dir_ancestors_problem(path: Path, uid: int) -> str | None:
    """Check that no other user can rename or replace an ancestor of ``path``.

    Inspect spelled and resolved ancestors, including every intermediate
    symlink target. Directories must have trusted owners and cannot be
    group/world-writable without the sticky bit.
    """
    try:
        trusted = _trusted_uids(uid)
    except ValueError:
        return f"invalid {HALT_TRUSTED_UIDS_ENV} value: {os.environ.get(HALT_TRUSTED_UIDS_ENV)!r}"
    try:
        resolved = Path(os.path.realpath(path, strict=True))
        pending = [*path.parents, *resolved.parents]
        visited: set[Path] = set()
        while pending:
            ancestor = pending.pop()
            if ancestor in visited:
                continue
            visited.add(ancestor)
            if len(visited) > 256:
                return f"too many ancestors or symlink targets for signal dir {path}"
            st = os.lstat(ancestor)
            if st.st_uid not in trusted:
                return f"signal dir ancestor {ancestor} is owned by uid {st.st_uid}"
            if stat.S_ISLNK(st.st_mode):
                target = Path(os.readlink(ancestor))
                if not target.is_absolute():
                    target = ancestor.parent / target
                # realpath() alone hides mutable intermediate pivots. Inspect
                # each link destination and all its parents before following
                # the next link, preserving relative '..' path components.
                pending.extend((target, *target.parents))
                continue
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not st.st_mode & stat.S_ISVTX:
                return (
                    f"signal dir ancestor {ancestor} is group/world-writable without the sticky bit"
                )
    except OSError as exc:
        return f"cannot inspect ancestors of signal dir {path}: {exc}"
    return None


def _signal_entry_state(path: Path) -> tuple[bool, str | None]:
    """Inspect the signal path without following symlinks.

    Returns ``(present, error)``. Missing is the only "not present" outcome;
    any other failure (including a non-directory parent) is reported as
    present with an error message so callers fail closed.
    """
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False, None
    except OSError as exc:
        return True, f"halt signal unreadable: {exc}"
    return True, None


def _entry_owner_problem(owner_uid: int) -> str | None:
    """Return why a signal entry owned by ``owner_uid`` is untrusted, or None.

    Trusts the same uids as the signal dir ancestor check (our uid, root and
    ``ACGS_HALT_TRUSTED_UIDS``). Skipped where ``os.getuid`` is unavailable.
    """
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        return None
    try:
        trusted = _trusted_uids(getuid())
    except ValueError:
        return f"invalid {HALT_TRUSTED_UIDS_ENV} value: {os.environ.get(HALT_TRUSTED_UIDS_ENV)!r}"
    if owner_uid not in trusted:
        return f"owned by uid {owner_uid}, not a trusted uid"
    return None


def _signal_entry_problem(path: Path) -> str | None:
    """Return why ``path`` is not a trusted halt signal file, or None if it is.

    Trusted means: a regular file (not followed through a symlink) owned by a
    trusted uid (see :func:`_entry_owner_problem`).
    """
    try:
        entry = os.lstat(path)
    except OSError as exc:
        return f"cannot inspect halt signal {path}: {exc}"
    if not stat.S_ISREG(entry.st_mode):
        return f"halt signal {path} is not a regular file"
    owner_problem = _entry_owner_problem(entry.st_uid)
    if owner_problem:
        return f"halt signal {path} is {owner_problem}"
    return None


def _validate_system_id(system_id: str) -> None:
    if not isinstance(system_id, str) or not system_id:
        raise ValueError("system_id must be a non-empty string")
    if system_id in (".", ".."):
        raise ValueError(f"system_id must not be {system_id!r}")
    forbidden = [os.sep, "\0"]
    if os.altsep:
        forbidden.append(os.altsep)
    if any(ch in system_id for ch in forbidden):
        raise ValueError("system_id must not contain path separators or NUL")


class GovernanceHaltError(Exception):
    """Raised when a governed operation is attempted while the circuit breaker is tripped."""

    def __init__(self, system_id: str, reason: str = "") -> None:
        self.system_id = system_id
        self.reason = reason
        msg = f"Governance halted for system '{system_id}'"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


@dataclass(slots=True)
class HaltEvent:
    system_id: str
    reason: str
    timestamp: str
    signal_path: str

    def to_dict(self) -> dict[str, str]:
        return {
            "system_id": self.system_id,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "signal_path": self.signal_path,
        }


class NotificationChannel(Protocol):
    def notify(self, event: HaltEvent) -> None: ...


class WebhookNotificationChannel:
    def __init__(self, url: str, secret: str | None = None) -> None:
        self._url = url
        self._secret = secret
        self._logger = logging.getLogger("acgs.halt.webhook")

    def notify(self, event: HaltEvent) -> None:
        try:
            parsed = urlparse(self._url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError("Webhook URL must use http or https scheme")
            body = json.dumps(event.to_dict()).encode()
            headers = {"Content-Type": "application/json"}
            if self._secret:
                digest = hmac.new(self._secret.encode(), body, "sha256").hexdigest()
                headers["X-ACGS-Signature"] = f"sha256={digest}"
            request = urllib.request.Request(
                self._url,
                data=body,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5):  # nosec B310 — scheme validated above
                return
        except Exception as exc:
            self._logger.warning("halt webhook notification failed: %s", exc, exc_info=True)


class StructuredLogNotificationChannel:
    def notify(self, event: HaltEvent) -> None:
        logging.getLogger("acgs.halt").critical(json.dumps(event.to_dict()))


class GovernanceCircuitBreaker:
    """Thread-safe, cross-process governance halt mechanism.

    Supports two modes:
    - **In-process**: Uses a threading.Event for immediate signaling
      within the same process.
    - **Cross-process**: Uses an atomic file signal that other processes
      can detect when calling ``check()``.

    Args:
        system_id: Identifier for the AI system this breaker controls. Must be
            non-empty, not ``.``/``..``, and free of path separators and NUL.
        signal_dir: Directory for cross-process signal files.
            Defaults to ``$ACGS_HALT_SIGNAL_DIR`` if set, else the system
            temp directory.
        check_file: If True, also check the file signal on ``is_tripped``
            and ``check()``. Enables cross-process detection.
    """

    def __init__(
        self,
        system_id: str,
        signal_dir: Path | None = None,
        check_file: bool = True,
        notification_channels: list[NotificationChannel] | None = None,
    ) -> None:
        _validate_system_id(system_id)
        self.system_id = system_id
        self._signal_dir, self.signal_dir_source = _resolve_signal_dir(signal_dir)
        if self.signal_dir_source != "tempdir" and os.path.lexists(self._signal_dir):
            problem = _signal_dir_problem(self._signal_dir)
            if problem:
                logger.critical("untrusted halt signal dir: %s", problem)
        self._check_file = check_file
        self._notification_channels = list(notification_channels or [])
        self._event = threading.Event()  # set = tripped
        self._reason = ""
        self._tripped_at: float | None = None
        self._lock = threading.Lock()

    @property
    def signal_dir(self) -> Path:
        """Directory holding the cross-process signal file."""
        return self._signal_dir

    @property
    def signal_path(self) -> Path:
        """Path to the cross-process signal file."""
        return self._signal_dir / f"acgs-halt-{self.system_id}"

    @property
    def _signal_path(self) -> Path:
        return self.signal_path

    def trip(self, reason: str = "") -> bool:
        """Trip the circuit breaker, halting all governed operations.

        This process is always halted, even when the cross-process signal fails.
        A failure to publish a trusted signal file (write error, or an existing
        entry that is not a regular file owned by this user or root) is logged
        at CRITICAL and reported by the return value rather than raised, so a
        caller relying on the in-process halt is never interrupted.

        Args:
            reason: Human-readable reason for the halt.

        Returns:
            True if the cross-process signal file is confirmed on disk; False if
            only this process is halted.
        """
        with self._lock:
            self._reason = reason
            self._tripped_at = time.time()
            self._event.set()

        published = self._publish_signal(reason)

        event = HaltEvent(
            system_id=self.system_id,
            reason=reason,
            timestamp=datetime.now(timezone.utc).isoformat(),
            signal_path=str(self.signal_path),
        )
        for channel in self._notification_channels:
            try:
                channel.notify(event)
            except Exception as exc:
                logger.warning("halt notification channel failed: %s", exc, exc_info=True)
        return published

    def _publish_signal(self, reason: str) -> bool:
        """Atomically write the cross-process signal file; False (CRITICAL) on failure."""
        # A signal in an untrusted dir can be removed by another user, so it is
        # never a durable halt; this process stays halted in memory.
        problem = self._untrusted_dir()
        if problem:
            problem = f"untrusted halt signal dir: {problem}"
        else:
            present, entry_error = _signal_entry_state(self.signal_path)
            problem = entry_error or (_signal_entry_problem(self.signal_path) if present else None)
        if problem:
            # A planted entry may be removed by its owner at any time, so it is
            # not a durable halt, and it is never overwritten or trusted.
            logger.critical(
                "failed to write halt signal file: %s; system=%s is halted in this process only",
                problem,
                self.system_id,
            )
            return False
        # Unique temp file in the signal dir (O_EXCL, never follows a planted
        # symlink), fsync, replace.
        try:
            # Fixed short prefix: embedding system_id could exceed NAME_MAX for
            # IDs whose final signal filename still fits.
            fd, tmp_name = tempfile.mkstemp(dir=self._signal_dir, prefix=".acgs-halt.")
            replaced = False
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(reason or "halted")
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_name, self.signal_path)
                replaced = True
            finally:
                if not replaced:
                    with contextlib.suppress(OSError):
                        os.unlink(tmp_name)
        except Exception as exc:
            logger.critical(
                "failed to write halt signal file: %s; system=%s is halted in this process only",
                exc,
                self.system_id,
                exc_info=True,
            )
            return False
        problem = _signal_entry_problem(self.signal_path)
        if problem:
            logger.critical(
                "failed to write halt signal file: %s; system=%s is halted in this process only",
                problem,
                self.system_id,
            )
            return False
        logger.warning("circuit breaker tripped: system=%s reason=%s", self.system_id, reason)
        return True

    def reset(self) -> bool:
        """Reset the circuit breaker, allowing operations to resume.

        The in-process halt is always cleared. If the cross-process signal entry
        cannot be removed, the failure is logged at CRITICAL and False is
        returned; ``is_tripped`` then still reports the halt (when file checks
        are enabled), so the breaker stays closed.

        Returns:
            True if no signal entry remains; False if one could not be removed.
        """
        with self._lock:
            self._event.clear()
            self._reason = ""
            self._tripped_at = None

        try:
            self.signal_path.unlink(missing_ok=True)
        except Exception as exc:
            logger.critical(
                "failed to remove halt signal %s: %s; system=%s is still halted for "
                "other processes",
                self.signal_path,
                exc,
                self.system_id,
                exc_info=True,
            )
            return False
        present, entry_error = _signal_entry_state(self.signal_path)
        if present:
            logger.critical(
                "halt signal %s still present after reset: %s; system=%s is still halted",
                self.signal_path,
                entry_error or "entry reappeared",
                self.system_id,
            )
            return False
        logger.info("circuit breaker reset: system=%s", self.system_id)
        return True

    @property
    def is_tripped(self) -> bool:
        """Check if the breaker is tripped (in-process or cross-process)."""
        if self._event.is_set():
            return True
        if not self._check_file:
            return False
        return _signal_entry_state(self.signal_path)[0] or self._untrusted_dir() is not None

    def _untrusted_dir(self) -> str | None:
        """Fail closed when the configured signal directory cannot be trusted.

        A missing directory also counts as untrusted (the halt could not be read
        from it, and another user could create it), and even the tempdir
        fallback may become writable by another user after construction.
        """
        return _signal_dir_problem(self._signal_dir)

    @property
    def trip_reason(self) -> str:
        """Return the reason the breaker was tripped, or empty string."""
        if self._reason:
            return self._reason
        if not self._check_file:
            return ""
        present, error = _signal_entry_state(self.signal_path)
        if error:
            return error
        if not present:
            problem = self._untrusted_dir()
            return f"halted (untrusted signal dir: {problem})" if problem else ""
        try:
            # O_NOFOLLOW: never read through a planted symlink.
            # O_NONBLOCK: a planted FIFO must not hang the check.
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(self.signal_path, flags)
            entry = os.fstat(fd)
            if not stat.S_ISREG(entry.st_mode):
                os.close(fd)
                return "halted (signal entry is not a regular file)"
            owner_problem = _entry_owner_problem(entry.st_uid)
            if owner_problem:
                # Still halted (fail closed), but a foreign entry's text is not trusted.
                os.close(fd)
                return f"halted (signal entry is {owner_problem})"
            with os.fdopen(fd, "rb") as fh:
                text = fh.read(_SIGNAL_READ_LIMIT).decode("utf-8", "replace").strip()
            return text or "halted"
        except Exception as exc:
            logger.debug("failed to read signal file: %s", exc, exc_info=True)
            return "halted (reason unavailable)"

    def check(self) -> None:
        """Check the breaker and raise GovernanceHaltError if tripped.

        Call this at the start of every governed operation.
        """
        if self.is_tripped:
            raise GovernanceHaltError(self.system_id, self.trip_reason)

    def __repr__(self) -> str:
        status = "TRIPPED" if self.is_tripped else "OK"
        return f"GovernanceCircuitBreaker(system={self.system_id!r}, status={status})"
