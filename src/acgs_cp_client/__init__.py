"""Agent-side client for the ACGS control-plane socket (Phase 6b).

Stdlib only, on purpose. It lives outside the ``acgs_lite`` package because
``import acgs_lite`` (and so any ``acgs_lite.*`` submodule) loads the signing
and governance modules; an agent process holding this client must import
none of the credential issuer, approvals, roles, kill switch, core writer,
PDP, receipt ledger, facade, identity or signing code. The server
(``acgs_lite.control_plane.service``) owns the protocol; the constants here
mirror it and are never read by the server.

Usage::

    with ControlPlaneClient("/run/acgs/cp.sock", token) as cp:
        text = cp.call("read_file", {"path": "workspace/notes.md"})
"""

from __future__ import annotations

import itertools
import json
import socket
from typing import Any

__all__ = [
    "DEFAULT_MAX_FRAME_BYTES",
    "DEFAULT_TIMEOUT_S",
    "EXECUTED_UNAUDITED",
    "ControlPlaneClient",
    "ControlPlaneDenied",
    "ControlPlaneError",
]

DEFAULT_MAX_FRAME_BYTES = 64 * 1024
DEFAULT_TIMEOUT_S = 30.0
_REPLY_KEYS = (
    frozenset({"id", "ok", "result"}),
    frozenset({"id", "ok", "ref"}),
    frozenset({"id", "ok", "error"}),
)


EXECUTED_UNAUDITED = "executed_unaudited"


class ControlPlaneError(Exception):
    """The service refused the request or the connection failed.

    :attr:`code` is the service's error string when it sent one (else
    ``None``). Codes: ``"tool error"``, ``"result not serialisable"``,
    ``"rate limited"``, ``"frame too large"``, protocol messages, and
    :data:`EXECUTED_UNAUDITED` -- **the tool
    DID run** but its completion record could not be written: do not retry
    blindly (a write would happen twice); ask the harness operator.
    """

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class ControlPlaneDenied(ControlPlaneError):
    """The control plane denied the call; :attr:`ref` is the opaque reference
    the harness can look up in its audit log (the reason is never sent)."""

    def __init__(self, ref: str) -> None:
        super().__init__(f"denied (ref {ref})")
        self.ref = ref


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


class ControlPlaneClient:
    """One connection to the control-plane service, authenticated per call by
    *credential* (a harness-issued token; the client never names a principal)."""

    def __init__(
        self,
        socket_path: str,
        credential: str,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
    ) -> None:
        if not isinstance(credential, str) or not credential:
            raise ValueError("credential must be a non-empty string")
        self._path = str(socket_path)
        self._credential = credential
        self._timeout = float(timeout_s)
        self._max_frame = int(max_frame_bytes)
        self._ids = itertools.count(1)
        self._sock: socket.socket | None = None
        self._reader: Any = None

    def __enter__(self) -> ControlPlaneClient:
        self._connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _connect(self) -> socket.socket:
        if self._sock is None:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            try:
                sock.connect(self._path)
            except OSError as exc:
                sock.close()
                raise ControlPlaneError(f"cannot connect: {exc}") from exc
            self._sock = sock
            self._reader = sock.makefile("rb")
        return self._sock

    def _request(self, message: dict[str, Any]) -> Any:
        request_id = next(self._ids)
        message["id"] = request_id
        frame = (json.dumps(message, allow_nan=False) + "\n").encode("utf-8")
        if len(frame) > self._max_frame:
            raise ControlPlaneError("request frame too large")
        sock = self._connect()
        try:
            sock.sendall(frame)
            line = self._reader.readline(self._max_frame + 1)
        except OSError as exc:
            self.close()
            raise ControlPlaneError(f"connection failed: {exc}") from exc
        if not line or not line.endswith(b"\n") or len(line) > self._max_frame:
            self.close()
            raise ControlPlaneError("connection closed by the service")
        try:
            reply = json.loads(
                line.decode("utf-8"),
                parse_constant=_reject_constant,
                object_pairs_hook=_no_duplicates,
            )
        except ValueError as exc:
            self.close()
            raise ControlPlaneError("malformed reply") from exc
        if not isinstance(reply, dict) or frozenset(reply) not in _REPLY_KEYS:
            self.close()
            raise ControlPlaneError("malformed reply")
        if reply["id"] not in (request_id, None):
            self.close()
            raise ControlPlaneError("reply does not match the request")
        if reply["ok"] is True and "result" in reply:
            return reply["result"]
        if "ref" in reply and isinstance(reply["ref"], str):
            raise ControlPlaneDenied(reply["ref"])
        code = str(reply.get("error", "malformed reply"))
        raise ControlPlaneError(code, code=code)

    def call(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        requested_by: str | None = None,
    ) -> Any:
        """Run *tool* through the control plane; return its JSON result or
        raise :class:`ControlPlaneDenied` / :class:`ControlPlaneError`."""
        message: dict[str, Any] = {
            "op": "call",
            "credential": self._credential,
            "tool": tool,
            "arguments": {} if arguments is None else arguments,
        }
        if requested_by is not None:
            message["requested_by"] = requested_by
        return self._request(message)

    def ping(self) -> bool:
        """``True`` when the service answers (no credential is sent)."""
        return bool(self._request({"op": "ping"}) == "pong")
