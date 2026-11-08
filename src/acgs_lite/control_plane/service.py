"""Out-of-process control-plane boundary: a Unix-socket JSON-lines server.

Phase 6b. The :class:`ControlPlaneService` runs in the harness process and
hosts the :class:`~.facade.ControlPlane` and its registered tools; agent code
runs in another process (another uid) and holds only a socket path and a
credential (see the stdlib-only ``acgs_cp_client`` package). In-process PDP
state is therefore out of the agent's reach.

Per connection:

* the peer is identified with ``SO_PEERCRED`` (pid, uid, gid); a uid not in
  ``uid_kinds``, or over its connection cap, is closed without a reply;
* each request is one UTF-8 JSON object per line, at most
  ``max_frame_bytes`` and arriving within the timeout; NaN/Infinity, duplicate keys and any key outside
  :data:`REQUEST_KEYS` are refused. A request carries no principal: the
  server authenticates the credential (P6a), takes kind, system_id and roles
  from the identity directory, and requires that kind to be allowed for the
  peer uid before the dispatcher sees the call;
* replies are ``{"id", "ok": true, "result"}`` (strict JSON; a result that
  does not serialise is an error, never a ``repr``) or, on any denial,
  ``{"id", "ok": false, "ref"}`` with the same opaque ref the MCP adapter
  returns. The full reason, the credential id, the attested kind and the
  peer uid/pid go to a hash-chained audit log in the core ``AUDIT_LOG`` area:
  an ``intent`` line before the tool runs, then ``completed``/``failed``
  (or ``denied``); the PDP receipt itself carries the ``credential_id``.

No object serialisation format other than JSON is used anywhere here.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import json
import logging
import os
import socket
import stat
import struct
import threading
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from acgs_lite.audit import AuditEntry, AuditLog, JSONLAuditBackend
from acgs_lite.control_plane.credentials import CredentialInvalid
from acgs_lite.control_plane.dispatcher import ToolDenied, opaque_ref
from acgs_lite.control_plane.evidence import require_audit_store_path
from acgs_lite.control_plane.facade import ControlPlane
from acgs_lite.control_plane.pdp import Decision
from acgs_lite.control_plane.principal import Principal, PrincipalKind

__all__ = [
    "DEFAULT_CONNECTION_TIMEOUT_S",
    "DEFAULT_DENIAL_WINDOW_S",
    "DEFAULT_MAX_CONNECTIONS",
    "DEFAULT_MAX_CONNECTIONS_PER_UID",
    "DEFAULT_MAX_DENIALS_PER_UID",
    "DEFAULT_RESERVED_HUMAN_SLOTS",
    "DEFAULT_MAX_FRAME_BYTES",
    "DEFAULT_MAX_REPLY_BYTES",
    "RESULT_TOO_LARGE",
    "REQUEST_KEYS",
    "SERVICE_AUDIT_PATH",
    "ControlPlaneService",
    "ControlPlaneServiceError",
    "ProtocolError",
    "parse_frame",
]

# TODO(control-plane-gap): frame size, the timeout (per recv *and* per whole
# frame), the global and per-uid connection caps and the per-uid denial-receipt
# budget and the HUMAN-only reserved slots are design inference (a tool call
# is small; an idle or trickling agent must not pin a thread; one uid must not
# starve another; agents must not lock humans out); tune them.
DEFAULT_MAX_FRAME_BYTES = 64 * 1024
# A reply larger than this is replaced by RESULT_TOO_LARGE (the tool ran).
DEFAULT_MAX_REPLY_BYTES = DEFAULT_MAX_FRAME_BYTES
RESULT_TOO_LARGE = "result too large (the tool ran)"
DEFAULT_CONNECTION_TIMEOUT_S = 30.0
DEFAULT_MAX_CONNECTIONS = 64
DEFAULT_MAX_CONNECTIONS_PER_UID = 16
DEFAULT_MAX_DENIALS_PER_UID = 32
DEFAULT_DENIAL_WINDOW_S = 60.0
DEFAULT_RESERVED_HUMAN_SLOTS = 4
_MAX_ID = 2**63
SERVICE_AUDIT_PATH = "audit/control-plane-service.jsonl"
# TODO(control-plane-gap): the wire carries no change_id, runbook or approval
# fields yet, so T1+ calls that need them are denied over the socket.
REQUEST_KEYS = frozenset({"op", "credential", "tool", "arguments", "requested_by", "id"})
_CALL_KEYS = frozenset({"op", "credential", "tool"})
_PING_KEYS = frozenset({"op", "id"})
_PEERCRED = struct.Struct("3i")
_UNIX_PATH_MAX = 107

logger = logging.getLogger(__name__)


class ControlPlaneServiceError(RuntimeError):
    """The service refused its configuration or could not start safely."""


class ProtocolError(ValueError):
    """A malformed request frame (reported to the client as ``error``)."""


def _reject_constant(name: str) -> Any:
    raise ProtocolError(f"non-finite number {name}")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ProtocolError("duplicate key")
        out[key] = value
    return out


def parse_frame(raw: bytes) -> dict[str, Any]:
    """Strictly parse one request line into a dict with :data:`REQUEST_KEYS` only."""
    try:
        data = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_no_duplicates,
        )
    except ProtocolError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProtocolError("malformed frame") from exc
    if not isinstance(data, dict):
        raise ProtocolError("request must be a JSON object")
    if not set(data) <= REQUEST_KEYS:
        raise ProtocolError("unknown request keys")
    op = data.get("op")
    request_id = data.get("id")
    if request_id is not None and (
        isinstance(request_id, bool)
        or not isinstance(request_id, (str, int))
        or (isinstance(request_id, int) and abs(request_id) >= _MAX_ID)
        or (isinstance(request_id, str) and len(request_id) > 128)
    ):
        raise ProtocolError("id must be a short string or a 64-bit integer")
    if op == "ping":
        if not set(data) <= _PING_KEYS:
            raise ProtocolError("ping takes only op and id")
    elif op == "call":
        if not set(data) >= _CALL_KEYS:
            raise ProtocolError("call needs credential and tool")
        for key in ("credential", "tool"):
            if not isinstance(data[key], str) or not data[key]:
                raise ProtocolError(f"{key} must be a non-empty string")
        if not isinstance(data.get("arguments", {}), dict):
            raise ProtocolError("arguments must be an object")
        requested_by = data.get("requested_by")
        if requested_by is not None and not isinstance(requested_by, str):
            raise ProtocolError("requested_by must be a string")
    else:
        raise ProtocolError("op must be 'call' or 'ping'")
    return data


def _checked_uid_kinds(
    uid_kinds: Mapping[int, frozenset[PrincipalKind]],
) -> dict[int, frozenset[PrincipalKind]]:
    # TODO(control-plane-gap): there is deliberately no default uid map; which
    # uid runs agents and which runs humans is deployment configuration.
    if not isinstance(uid_kinds, Mapping) or not uid_kinds:
        raise ControlPlaneServiceError("uid_kinds must be a non-empty mapping")
    out: dict[int, frozenset[PrincipalKind]] = {}
    for uid, kinds in uid_kinds.items():
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
            raise ControlPlaneServiceError("uid_kinds keys must be uids (ints >= 0)")
        if not isinstance(kinds, frozenset) or not kinds:
            raise ControlPlaneServiceError("uid_kinds values must be non-empty frozensets")
        if not all(isinstance(kind, PrincipalKind) for kind in kinds):
            raise ControlPlaneServiceError("uid_kinds values must hold PrincipalKind members")
        # Human uids are dedicated: a uid that may run an agent can never
        # present a HUMAN credential, even one it somehow obtained.
        if PrincipalKind.HUMAN in kinds and len(kinds) > 1:
            raise ControlPlaneServiceError(
                f"uid {uid} may not mix HUMAN with other kinds (human uids are dedicated)"
            )
        out[uid] = kinds
    return out


def _positive(value: object, label: str, *, integral: bool) -> float:
    kinds: tuple[type, ...] = (int,) if integral else (int, float)
    if isinstance(value, bool) or not isinstance(value, kinds):
        raise ControlPlaneServiceError(f"{label} must be a positive number")
    number = float(value)  # type: ignore[arg-type]
    if not number > 0:
        raise ControlPlaneServiceError(f"{label} must be a positive number")
    return number


def _safe_ancestor(info: os.stat_result) -> bool:
    """A sticky root-owned directory (``/tmp``), or one owned by root or the
    service uid that group/other cannot write. The owner of any other
    ancestor could rename the socket directory and plant its own listener."""
    if info.st_mode & stat.S_ISVTX and info.st_uid == 0:
        return True
    if info.st_mode & 0o022:
        return False
    return info.st_uid in (0, os.getuid())


def _trusted_symlink(link: Path, info: os.stat_result) -> bool:
    """A root-owned symlink in a root-owned directory nobody else can write
    (``/var/run -> /run`` style): only root could repoint it."""
    if info.st_uid != 0:
        return False
    parent = os.lstat(link.parent)
    return parent.st_uid == 0 and not parent.st_mode & 0o022


def _check_path_components(path: Path) -> None:
    """lstat every existing component of the *unresolved* absolute path, which
    is the one bind() and clients use. A symlink component is refused unless
    :func:`_trusted_symlink`: otherwise whoever controls the link (or its
    directory) could repoint it at their own socket and harvest credentials.
    ``..`` is refused outright."""
    if ".." in path.parts:
        raise ControlPlaneServiceError("socket path must not contain '..'")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return  # the rest is created below, component by component
        if stat.S_ISLNK(info.st_mode) and not _trusted_symlink(current, info):
            raise ControlPlaneServiceError(f"socket path component {str(current)!r} is a symlink")


def _prepare_directory(directory: Path, group: int | None) -> None:
    """Create *directory* (and missing parents) mode 0700 one level at a time,
    or require an existing one to be ours and not group/world writable.

    Two checks, so nobody else can substitute the directory or the socket:
    every component of the unresolved path (:func:`_check_path_components`),
    and every ancestor of the resolved path (writable only by us, or sticky
    and root-owned, like ``/tmp``; this covers the targets of trusted system
    symlinks). With *group* the directory becomes 0710 and is chgrp'd (group
    members may traverse only). The unresolved path is used throughout."""
    _check_path_components(directory)
    missing: list[Path] = []
    probe = directory
    while True:
        try:
            os.lstat(probe)
        except FileNotFoundError:
            missing.append(probe)
            probe = probe.parent
            continue
        break
    real = Path(os.path.realpath(probe))
    for ancestor in [real, *real.parents] if missing else list(real.parents):
        if not _safe_ancestor(os.lstat(ancestor)):
            raise ControlPlaneServiceError(
                f"socket directory ancestor {str(ancestor)!r} is writable or owned by others"
            )
    for path in reversed(missing):
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)  # explicitly: the umask must not decide
        if group is not None:
            # Every created level must be traversable by the socket group,
            # not only the last one.
            os.chown(path, -1, group)
            os.chmod(path, 0o710)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode):
        raise ControlPlaneServiceError(f"socket directory {str(directory)!r} is not a directory")
    if info.st_uid != os.getuid():  # pragma: no cover - needs a foreign-owned directory
        raise ControlPlaneServiceError("socket directory is not owned by the service uid")
    if info.st_mode & 0o022:
        raise ControlPlaneServiceError("socket directory is group- or world-writable")
    if group is not None:
        os.chown(directory, -1, group)
        os.chmod(directory, 0o710)


class _FrameTooLarge(Exception):
    pass


class _FrameTimeout(Exception):
    pass


class _FrameReader:
    """Bounded line reader: at most *max_frame* bytes per frame, and the whole
    frame (from the moment we start waiting for it) must arrive within
    *deadline_s*, so one byte per almost-timeout (slowloris) cannot pin a
    connection; each ``recv`` is also bounded by the remaining time."""

    def __init__(self, conn: socket.socket, max_frame: int, deadline_s: float) -> None:
        self._conn = conn
        self._max = max_frame
        self._deadline_s = deadline_s
        self._buffer = b""

    def read_frame(self) -> bytes | None:
        """One frame without its newline; ``None`` at a clean EOF."""
        deadline = time.monotonic() + self._deadline_s
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                if newline > self._max:
                    raise _FrameTooLarge
                frame, self._buffer = self._buffer[:newline], self._buffer[newline + 1 :]
                return frame
            if len(self._buffer) > self._max:
                raise _FrameTooLarge
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _FrameTimeout
            self._conn.settimeout(remaining)
            try:
                chunk = self._conn.recv(4096)
            except TimeoutError as exc:  # socket.timeout on 3.10 is an alias
                raise _FrameTimeout from exc
            if not chunk:
                if self._buffer:
                    raise _FrameTooLarge  # an unterminated final fragment
                return None
            self._buffer += chunk


class ControlPlaneService:
    """Serve :class:`~.facade.ControlPlane` tool calls over a Unix socket.

    Use as a context manager (binds on entry) and call :meth:`serve_forever`
    on any thread; :meth:`shutdown` stops it from another thread.

    **Deployment (read this).** By default the directory is 0700 and the
    socket 0600, so only the service's *own* uid can even connect -- an agent
    running under a different uid gets ``EACCES``. For the intended cross-uid
    deployment pass ``socket_group`` (a gid the agent uid belongs to): the
    directory becomes 0710 and the socket 0660, both chgrp'd to it.
    ``SO_PEERCRED`` against ``uid_kinds`` stays the authorisation gate either
    way; the file modes only decide who may knock.
    TODO(control-plane-gap): the group-based cross-uid layout is design
    inference (an alternative is a socket-activated per-agent socket).
    """

    def __init__(
        self,
        control_plane: ControlPlane,
        socket_path: str | os.PathLike[str],
        uid_kinds: Mapping[int, frozenset[PrincipalKind]],
        *,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_reply_bytes: int = DEFAULT_MAX_REPLY_BYTES,
        connection_timeout_s: float = DEFAULT_CONNECTION_TIMEOUT_S,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        max_connections_per_uid: int = DEFAULT_MAX_CONNECTIONS_PER_UID,
        max_denials_per_uid: int = DEFAULT_MAX_DENIALS_PER_UID,
        denial_window_s: float = DEFAULT_DENIAL_WINDOW_S,
        socket_group: int | None = None,
        reserved_human_slots: int = DEFAULT_RESERVED_HUMAN_SLOTS,
        audit_path: str = SERVICE_AUDIT_PATH,
    ) -> None:
        if not hasattr(socket, "SO_PEERCRED"):  # pragma: no cover - non-Linux
            raise ControlPlaneServiceError("ControlPlaneService needs SO_PEERCRED (Linux)")
        if type(control_plane) is not ControlPlane:
            raise ControlPlaneServiceError("control_plane must be a ControlPlane")
        if control_plane.credentials.identity is None:  # pragma: no cover - facade sets it
            raise ControlPlaneServiceError("the credential issuer needs an identity directory")
        self._cp = control_plane
        self._uid_kinds = _checked_uid_kinds(uid_kinds)
        self._max_frame = int(_positive(max_frame_bytes, "max_frame_bytes", integral=True))
        self._max_reply = int(_positive(max_reply_bytes, "max_reply_bytes", integral=True))
        self._timeout = _positive(connection_timeout_s, "connection_timeout_s", integral=False)
        self._max_connections = int(_positive(max_connections, "max_connections", integral=True))
        self._max_per_uid = int(
            _positive(max_connections_per_uid, "max_connections_per_uid", integral=True)
        )
        self._max_denials = int(
            _positive(max_denials_per_uid, "max_denials_per_uid", integral=True)
        )
        self._denial_window = _positive(denial_window_s, "denial_window_s", integral=False)
        if socket_group is not None and (
            isinstance(socket_group, bool) or not isinstance(socket_group, int) or socket_group < 0
        ):
            raise ControlPlaneServiceError("socket_group must be a gid (int >= 0) or None")
        self._group = socket_group
        if (
            isinstance(reserved_human_slots, bool)
            or not isinstance(reserved_human_slots, int)
            or not 0 <= reserved_human_slots < self._max_connections
        ):
            raise ControlPlaneServiceError(
                "reserved_human_slots must be an int in [0, max_connections)"
            )
        self._reserved_human = reserved_human_slots
        path = Path(os.fspath(socket_path)).absolute()
        if len(os.fsencode(path)) > _UNIX_PATH_MAX:
            raise ControlPlaneServiceError("socket path is too long for AF_UNIX")
        registry = control_plane.registry
        # Outside the repository normalize() is None (acceptable); inside it,
        # the socket must not sit on an immutable-core path.
        normalized = registry.normalize(str(path))
        if normalized is not None and registry.is_core(normalized):
            raise ControlPlaneServiceError("socket path is on an immutable-core path")
        self._path = path
        try:
            audit_file = require_audit_store_path(audit_path, registry)
        except PermissionError as exc:
            raise ControlPlaneServiceError(str(exc)) from exc
        backend = JSONLAuditBackend(audit_file)
        self._audit = AuditLog.from_backend(backend)
        self._audit_backend = backend
        self._audit_path = audit_file
        self._listener: socket.socket | None = None
        self._inode: tuple[int, int] | None = None
        self._lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._per_uid: dict[int, int] = {}
        self._denials: dict[int, collections.deque[float]] = {}
        self._threads: set[threading.Thread] = set()
        self._stopping = threading.Event()

    @property
    def socket_path(self) -> Path:
        return self._path

    @property
    def audit_path(self) -> Path:
        return self._audit_path

    # -- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        """Create the directory and bind the socket (idempotent)."""
        if self._listener is not None:
            return
        if self._stopping.is_set():
            raise ControlPlaneServiceError("the service was shut down")
        _prepare_directory(self._path.parent, self._group)
        try:
            existing = os.lstat(self._path)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.getuid():
                raise ControlPlaneServiceError(
                    "socket path exists and is not a socket owned by the service uid"
                )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                try:
                    probe.connect(str(self._path))
                except OSError:
                    pass  # nobody listening: a stale socket of ours
                else:
                    raise ControlPlaneServiceError("another service is listening on the socket")
            os.unlink(self._path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # umask is process-global, but this is safe: the socket is born 0600
        # (never wider), the old umask is restored immediately, and anything a
        # concurrent thread creates meanwhile only gets *narrower* modes.
        old_umask = os.umask(0o177)
        try:
            listener.bind(str(self._path))
        except OSError as exc:
            listener.close()
            raise ControlPlaneServiceError(f"cannot bind the socket: {exc}") from exc
        finally:
            os.umask(old_umask)
        mode = 0o600
        if self._group is not None:
            os.chown(self._path, -1, self._group)
            mode = 0o660
        os.chmod(self._path, mode)
        info = os.lstat(self._path)
        if (
            stat.S_IMODE(info.st_mode) != mode or info.st_uid != os.getuid()
        ):  # pragma: no cover - chmod just set it
            listener.close()
            raise ControlPlaneServiceError(f"socket mode is not {mode:o}")
        listener.listen(self._max_connections)
        self._listener = listener
        self._inode = (info.st_dev, info.st_ino)

    def __enter__(self) -> ControlPlaneService:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.shutdown()

    @staticmethod
    def _peer_credentials(conn: socket.socket) -> tuple[int, int, int]:
        """(pid, uid, gid) of the connected peer, from the kernel."""
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size)
        pid, uid, gid = _PEERCRED.unpack(raw)
        return pid, uid, gid

    def _admit(self, uid: int) -> bool:
        """Reserve a connection slot for *uid*: the global cap and the per-uid
        cap, so one uid cannot starve another's slots, and the last
        ``reserved_human_slots`` of the global cap only for HUMAN uids, so
        agent uids together can never lock the humans out."""
        human = self._uid_kinds.get(uid) == frozenset({PrincipalKind.HUMAN})
        cap = self._max_connections if human else self._max_connections - self._reserved_human
        with self._lock:
            if self._stopping.is_set() or sum(self._per_uid.values()) >= cap:
                return False
            if self._per_uid.get(uid, 0) >= self._max_per_uid:
                return False
            self._per_uid[uid] = self._per_uid.get(uid, 0) + 1
            return True

    def _release(self, uid: int) -> None:
        with self._lock:
            left = self._per_uid.get(uid, 0) - 1
            if left > 0:
                self._per_uid[uid] = left
            else:
                self._per_uid.pop(uid, None)

    def serve_forever(self) -> None:
        """Accept connections until :meth:`shutdown`; one thread per connection."""
        self.start()
        listener = self._listener
        assert listener is not None
        while not self._stopping.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                if self._stopping.is_set():
                    break
                raise  # pragma: no cover - accept failing while serving
            try:
                pid, uid, _gid = self._peer_credentials(conn)
            except OSError:  # pragma: no cover - the peer vanished
                conn.close()
                continue
            if uid not in self._uid_kinds:
                logger.warning("control-plane service: refused peer uid %d (pid %d)", uid, pid)
                conn.close()
                continue
            if not self._admit(uid):
                conn.close()
                continue
            thread = threading.Thread(
                target=self._serve_connection, args=(conn, pid, uid), daemon=True
            )
            with self._lock:
                self._connections.add(conn)
                self._threads.add(thread)
            try:
                thread.start()
            except Exception as exc:  # e.g. RuntimeError: can't start new thread
                logger.error("control-plane service: thread start failed: %s", type(exc).__name__)
                with self._lock:
                    self._connections.discard(conn)
                    self._threads.discard(thread)
                self._release(uid)
                conn.close()

    def shutdown(self) -> None:
        """Stop accepting, close every connection, remove our socket file."""
        self._stopping.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            with contextlib.suppress(OSError):
                listener.shutdown(socket.SHUT_RDWR)
            listener.close()
            try:
                info = os.lstat(self._path)
                if (info.st_dev, info.st_ino) == self._inode:
                    os.unlink(self._path)
            except FileNotFoundError:  # pragma: no cover - removed externally
                pass
        with self._lock:
            connections = list(self._connections)
            threads = list(self._threads)
        for conn in connections:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=self._timeout)
        self._audit_backend.close()

    # -- one connection --------------------------------------------------------

    def _serve_connection(self, conn: socket.socket, pid: int, uid: int) -> None:
        allowed = self._uid_kinds[uid]
        reader = _FrameReader(conn, self._max_frame, self._timeout)
        try:
            while not self._stopping.is_set():
                reply, close = self._handle_frame(reader, pid, uid, allowed)
                if reply is not None:
                    conn.settimeout(self._timeout)
                    conn.sendall(reply)
                if close:
                    return
        except OSError:
            return  # reset or shutdown
        except Exception as exc:
            # Never let a bug kill the thread silently: log, audit, close.
            logger.error("control-plane service connection failed: %s", type(exc).__name__)
            self._audit_record(
                {"peer_uid": uid, "peer_pid": pid},
                phase="connection_error",
                ok=False,
                reason=f"connection error: {type(exc).__name__}",
            )
        finally:
            with self._lock:
                self._connections.discard(conn)
                self._threads.discard(threading.current_thread())
            self._release(uid)
            conn.close()

    def _handle_frame(
        self, reader: _FrameReader, pid: int, uid: int, allowed: frozenset[PrincipalKind]
    ) -> tuple[bytes | None, bool]:
        try:
            frame = reader.read_frame()
        except _FrameTooLarge:
            return _encode({"id": None, "ok": False, "error": "frame too large"}), True
        except _FrameTimeout:
            return None, True
        if frame is None:
            return None, True
        try:
            request = parse_frame(frame)
        except ProtocolError as exc:
            return _encode({"id": None, "ok": False, "error": str(exc)}), False
        request_id = request.get("id")
        if request["op"] == "ping":
            return _encode({"id": request_id, "ok": True, "result": "pong"}), False
        return self._call(request, request_id, pid, uid, allowed)

    def _attested_principal(
        self, token: str, allowed: frozenset[PrincipalKind]
    ) -> tuple[Principal, str]:
        """(directory principal, credential id); raises PermissionError."""
        issuer = self._cp.credentials
        try:
            credential = issuer.authenticate(token)
        except CredentialInvalid as exc:
            raise PermissionError(f"credential rejected: {exc}") from exc
        except Exception as exc:  # fail closed on any verifier bug: type only
            raise PermissionError(f"credential rejected: {type(exc).__name__}") from exc
        identity = issuer.identity
        entry = None if identity is None else identity.lookup(credential.principal_id)
        if entry is None or entry.kind is not credential.kind:
            raise PermissionError("credential principal is not in the identity directory")
        if entry.system_id != credential.system_id:
            raise PermissionError("credential system_id differs from the directory")
        if entry.kind not in allowed:
            raise PermissionError(f"peer uid may not act as kind {entry.kind.value!r} (uid_kinds)")
        return entry.principal(), credential.credential_id

    def _denial_budget_exhausted(self, uid: int) -> bool:
        """Peek (without spending) whether *uid* has used its denial budget."""
        now = time.monotonic()
        with self._lock:
            window = self._denials.get(uid)
            if window is None:
                return False
            while window and window[0] <= now - self._denial_window:
                window.popleft()
            return len(window) >= self._max_denials

    def _denial_allowed(self, uid: int) -> bool:
        """Sliding-window budget of receipted authentication denials per uid,
        so one uid cannot spam fsyncs or crowd out other uids' receipts."""
        now = time.monotonic()
        with self._lock:
            window = self._denials.setdefault(uid, collections.deque())
            while window and window[0] <= now - self._denial_window:
                window.popleft()
            if len(window) >= self._max_denials:
                return False
            window.append(now)
            return True

    def _call(
        self,
        request: dict[str, Any],
        request_id: str | int | None,
        pid: int,
        uid: int,
        allowed: frozenset[PrincipalKind],
    ) -> tuple[bytes, bool]:
        tool: str = request["tool"]
        record: dict[str, Any] = {"peer_uid": uid, "peer_pid": pid, "tool": tool}
        try:
            principal, credential_id = self._attested_principal(request["credential"], allowed)
        except PermissionError as exc:
            if not self._denial_allowed(uid):
                # Over budget: refuse and hang up without another fsync.
                return _encode({"id": request_id, "ok": False, "error": "rate limited"}), True
            decision = self._cp.pdp.record_denial(
                str(exc),
                action="tool.call",
                resource=tool,
                error="service_denied",
                limit_key=f"uid:{uid}",
            )
            return self._deny(request_id, record, decision), False
        record.update(
            credential_id=credential_id,
            principal_id=principal.id,
            principal_kind=principal.kind.value,
            system_id=principal.system_id,
        )

        if self._denial_budget_exhausted(uid):
            # Checked *before* dispatch: an exhausted uid must not cause more
            # PDP decisions, receipts, audit fsyncs or telemetry.
            return _encode({"id": request_id, "ok": False, "error": "rate limited"}), True

        def intent(decisions: tuple[Decision, ...]) -> None:
            # Attribution is durable *before* the tool runs; a failure here
            # denies the call (the dispatcher never invokes the tool).
            decision_id = decisions[0].decision_id if decisions else ""
            if not self._audit_record(record, phase="intent", ok=True, decision_id=decision_id):
                raise OSError("intent record not written")

        try:
            call = (
                principal,
                tool,
                request.get("arguments", {}),
            )
            options: dict[str, Any] = {
                "credential": request["credential"],
                "requested_by": request.get("requested_by"),
                "on_authorized": intent,
            }
            if self._cp.dispatcher.is_async(tool):
                # Decided before authorization, so nothing is consumed twice.
                result = asyncio.run(self._cp.dispatcher.adispatch(*call, **options))
            else:
                result = self._cp.dispatcher.dispatch(*call, **options)
        except ToolDenied as exc:
            if not self._denial_allowed(uid):
                # Over the per-uid denial budget: the PDP receipt exists, but
                # no further audit fsync; refuse and hang up (no reason text).
                return _encode({"id": request_id, "ok": False, "error": "rate limited"}), True
            return self._deny(request_id, record, exc.decision), False
        except Exception as exc:
            self._audit_record(
                record, phase="failed", ok=False, reason=f"tool error: {type(exc).__name__}"
            )
            return _encode({"id": request_id, "ok": False, "error": "tool error"}), False
        decision_id = result.decisions[0].decision_id if result.decisions else ""
        try:
            reply = _encode({"id": request_id, "ok": True, "result": result.value})
        except (TypeError, ValueError):
            if not self._audit_record(
                record,
                phase="failed",
                ok=False,
                reason="result not JSON-serialisable",
                decision_id=decision_id,
            ):
                return _encode(
                    {"id": request_id, "ok": False, "error": "executed_unaudited"}
                ), False
            return _encode(
                {"id": request_id, "ok": False, "error": "result not serialisable"}
            ), False
        if len(reply) > self._max_reply:
            # The stock client drops frames over its limit and would report a
            # connection failure for a call that DID run: say so instead.
            if not self._audit_record(
                record,
                phase="failed",
                ok=False,
                reason="result too large for the client frame limit",
                decision_id=decision_id,
            ):
                return _encode(
                    {"id": request_id, "ok": False, "error": "executed_unaudited"}
                ), False
            return _encode({"id": request_id, "ok": False, "error": RESULT_TOO_LARGE}), False
        if not self._audit_record(record, phase="completed", ok=True, decision_id=decision_id):
            # The tool ran (the intent line attributes it); tell the client
            # not to retry blindly.
            return _encode({"id": request_id, "ok": False, "error": "executed_unaudited"}), False
        return reply, False

    def _deny(
        self, request_id: str | int | None, record: dict[str, Any], decision: Decision
    ) -> bytes:
        # The reason goes to the audit log (and the receipt); the agent gets
        # only the opaque ref, exactly as over MCP.
        self._audit_record(
            record,
            phase="denied",
            ok=False,
            reason=decision.reason,
            decision_id=decision.decision_id,
        )
        return _encode({"id": request_id, "ok": False, "ref": opaque_ref(decision)})

    def _audit_record(
        self,
        record: Mapping[str, Any],
        *,
        phase: str,
        ok: bool,
        reason: str = "",
        decision_id: str = "",
    ) -> bool:
        """Durably append one audit line; ``False`` (and a log line) on failure."""
        metadata = dict(record)
        metadata["decision_id"] = decision_id
        metadata["phase"] = phase
        entry = AuditEntry(
            id=uuid.uuid4().hex,
            type="control_plane_service",
            agent_id=str(record.get("principal_id", "")),
            action=f"tool.call:{record.get('tool', '')}",
            valid=ok,
            violations=[reason] if reason else [],
            metadata=metadata,
        )
        try:
            self._audit.record_durable(entry)
        except Exception as exc:
            logger.error("control-plane service audit write failed: %s", type(exc).__name__)
            return False
        return True


def _encode(message: Mapping[str, Any]) -> bytes:
    return (json.dumps(message, allow_nan=False, sort_keys=True) + "\n").encode("utf-8")
