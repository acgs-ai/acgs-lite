"""Phase 6b: the out-of-process control-plane boundary (Unix socket + client)."""

from __future__ import annotations

import ast
import asyncio
import contextlib
import dataclasses
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from acgs_cp_client import (
    EXECUTED_UNAUDITED,
    ControlPlaneClient,
    ControlPlaneDenied,
    ControlPlaneError,
)  # noqa: E402
from acgs_lite.control_plane import (  # noqa: E402
    DEFAULT_IMMUTABLE_CORE,
    ControlPlaneReceipt,
    ControlPlaneService,
    ControlPlaneServiceError,
    CoreCategory,
    CredentialInvalid,
    PrincipalKind,
    ToolDenied,
)
from acgs_lite.control_plane import service as service_module  # noqa: E402
from acgs_lite.control_plane.demo_loop import (  # noqa: E402
    ADMIN,
    AGENT,
    ARTIFACT_FILES,
    REQUESTER,
    SUITE_PATH,
    TRIGGER_ID,
    DemoEnvironment,
    build_demo_environment,
)
from acgs_lite.control_plane.service import (  # noqa: E402
    SERVICE_AUDIT_PATH,
    ProtocolError,
    _check_path_components,
    parse_frame,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform != "linux", reason="SO_PEERCRED is Linux-only"),
]

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
UID = os.getuid()
AGENT_ONLY = {UID: frozenset({PrincipalKind.AGENT})}
PROMPT = ARTIFACT_FILES["prompt"]
FORBIDDEN_IN_CLIENT = (
    "credentials",
    "approvals",
    "roles",
    "killswitch",
    "core_write",
    "pdp",
    "receipt_ledger",
    "facade",
    "identity",
    "signing",
)


@pytest.fixture()
def env(tmp_path: Path) -> Iterator[DemoEnvironment]:
    environment = build_demo_environment(tmp_path / "repo")
    yield environment
    environment.close()


@pytest.fixture()
def sock_dir() -> Iterator[Path]:
    # Short and outside the repo: AF_UNIX paths are limited to ~107 bytes.
    directory = Path(tempfile.mkdtemp(prefix="cps-"))
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


def _agent_token(env: DemoEnvironment, *tools: str) -> str:
    scopes = [f"tool:{t}" for t in tools or ("read_file", "write_file")]
    return env.cp.credentials.issue(
        AGENT, scopes=scopes, on_behalf_of=REQUESTER.id, trigger_id=TRIGGER_ID
    ).token


class _Running:
    """A service serving on a background thread for one test."""

    def __init__(self, service: ControlPlaneService) -> None:
        self.service = service
        service.start()
        self.thread = threading.Thread(target=service.serve_forever, daemon=True)
        self.thread.start()

    @property
    def path(self) -> str:
        return str(self.service.socket_path)

    def stop(self) -> None:
        self.service.shutdown()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()


@pytest.fixture()
def serve(env: DemoEnvironment, sock_dir: Path) -> Iterator[Any]:
    running: list[_Running] = []

    def start(uid_kinds: Any = None, **kwargs: Any) -> _Running:
        service = ControlPlaneService(
            env.cp, sock_dir / "cp.sock", AGENT_ONLY if uid_kinds is None else uid_kinds, **kwargs
        )
        running.append(_Running(service))
        return running[-1]

    yield start
    for item in running:
        item.stop()


def _audit_lines(root: Path) -> list[dict[str, Any]]:
    path = root / SERVICE_AUDIT_PATH
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _receipts(root: Path) -> dict[str, dict[str, Any]]:
    lines = (root / "audit" / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
    receipts = [json.loads(line)["receipt"] for line in lines if line]
    return {r["decision_id"]: r for r in receipts}


def _raw(path: str, payload: bytes) -> list[dict[str, Any]]:
    """Send raw bytes; return every reply line until the server closes."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(path)
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        data = b""
        with contextlib.suppress(ConnectionResetError):  # a close with unread data
            while chunk := sock.recv(65536):
                data += chunk
    return [json.loads(line) for line in data.splitlines()]


# -- B2: client import closure -------------------------------------------------


def test_client_import_closure_excludes_the_control_plane(tmp_path: Path) -> None:
    code = "import acgs_cp_client, json, sys; print(json.dumps(sorted(sys.modules)))"
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env["PYTHONPATH"] = str(SRC)
    out = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    modules = set(json.loads(out.stdout))
    assert "acgs_cp_client" in modules
    assert not {m for m in modules if m == "acgs_lite" or m.startswith(("acgs_lite.", "acgs."))}
    leaked = {m for m in modules if m.rsplit(".", 1)[-1] in FORBIDDEN_IN_CLIENT}
    assert leaked == set()


@pytest.mark.parametrize(
    "path",
    [SRC / "acgs_lite" / "control_plane" / "service.py", SRC / "acgs_cp_client" / "__init__.py"],
)
def test_no_object_serialisation_or_dynamic_code(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert "pickle" not in text and "marshal" not in text and "shelve" not in text
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile", "__import__"}


def test_service_is_core_and_client_is_stdlib_only() -> None:
    assert (
        DEFAULT_IMMUTABLE_CORE.classify("src/acgs_lite/control_plane/service.py")
        is CoreCategory.CONTROL_PLANE
    )
    tree = ast.parse((SRC / "acgs_cp_client" / "__init__.py").read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported <= set(sys.stdlib_module_names) | {"__future__"}


# -- B3: a separate harness process ---------------------------------------------


def test_subprocess_denied_and_allowed_calls_are_receipted(tmp_path: Path, sock_dir: Path) -> None:
    root = tmp_path / "repo"
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{REPO}"
    child = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("service_child.py")),
            str(root),
            str(sock_dir / "cp.sock"),
        ],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None and child.stdin is not None
        ready = json.loads(child.stdout.readline())
        assert stat.S_IMODE(os.lstat(ready["socket"]).st_mode) == 0o600
        with ControlPlaneClient(ready["socket"], ready["credential"]) as client:
            assert client.ping()
            with pytest.raises(ControlPlaneDenied) as denied:
                client.call("read_file", {"path": SUITE_PATH})
            assert client.call("read_file", {"path": PROMPT}) == "You are a helpful assistant.\n"
        child.stdin.close()
        assert child.wait(timeout=10) == 0
    finally:
        if child.poll() is None:  # pragma: no cover - only on failure
            child.kill()
            child.wait()
    ref = denied.value.ref
    assert (
        len(ref) == 12 and "INV" not in str(denied.value) and "sensitive" not in str(denied.value)
    )
    audit = [line for line in _audit_lines(root) if line["type"] == "control_plane_service"]
    assert [line["metadata"]["phase"] for line in audit] == ["denied", "intent", "completed"]
    receipts = _receipts(root)
    cid = ready["credential_id"]
    for line, allowed in zip(audit, (False, True, True), strict=True):
        meta = line["metadata"]
        assert meta["principal_kind"] == "agent" and meta["principal_id"] == AGENT.id
        assert meta["credential_id"] == cid and meta["peer_uid"] == UID
        receipt = receipts[meta["decision_id"]]
        # B3: the signed receipt itself names the credential and the kind.
        assert receipt["allowed"] is allowed and receipt["principal_kind"] == "agent"
        assert receipt["credential_id"] == cid
    assert audit[0]["metadata"]["decision_id"].startswith(ref)
    assert "INV-CORE-SENSITIVE-READ" in audit[0]["violations"][0]


# -- B1: in-process server, real socket -----------------------------------------


class TestPeerAndKind:
    def test_allowed_call_and_socket_modes(self, env: DemoEnvironment, serve: Any) -> None:
        running = serve()
        assert stat.S_IMODE(os.lstat(running.path).st_mode) == 0o600
        assert stat.S_IMODE(os.lstat(Path(running.path).parent).st_mode) == 0o700
        with ControlPlaneClient(running.path, _agent_token(env)) as client:
            assert client.call("read_file", {"path": PROMPT}).startswith("You are")
        line = _audit_lines(env.root)[-1]
        assert line["valid"] is True and line["metadata"]["principal_kind"] == "agent"

    def test_uid_not_in_map_is_closed(self, env: DemoEnvironment, serve: Any) -> None:
        running = serve({UID + 1: frozenset({PrincipalKind.AGENT})})
        with (
            ControlPlaneClient(running.path, _agent_token(env)) as client,
            pytest.raises(ControlPlaneError, match="connection"),
        ):
            client.ping()

    def test_kind_not_allowed_for_uid_is_denied(self, env: DemoEnvironment, serve: Any) -> None:
        running = serve({UID: frozenset({PrincipalKind.SERVICE})})
        with (
            ControlPlaneClient(running.path, _agent_token(env)) as client,
            pytest.raises(ControlPlaneDenied) as denied,
        ):
            client.call("read_file", {"path": PROMPT})
        assert "kind" not in str(denied.value)
        line = _audit_lines(env.root)[-1]
        assert line["valid"] is False and "uid_kinds" in line["violations"][0]
        assert line["metadata"]["decision_id"].startswith(denied.value.ref)

    def test_human_credential_from_agent_uid_is_denied(
        self, env: DemoEnvironment, serve: Any
    ) -> None:
        running = serve()
        token = env.human_credential(REQUESTER, ("tool:read_file",))
        with ControlPlaneClient(running.path, token) as client, pytest.raises(ControlPlaneDenied):
            client.call("read_file", {"path": PROMPT})
        assert "'human'" in _audit_lines(env.root)[-1]["violations"][0]

    def test_bad_credential_is_denied_with_receipt(self, env: DemoEnvironment, serve: Any) -> None:
        running = serve()
        with (
            ControlPlaneClient(running.path, "not.a-token") as client,
            pytest.raises(ControlPlaneDenied) as denied,
        ):
            client.call("read_file", {"path": PROMPT})
        decision_id = _audit_lines(env.root)[-1]["metadata"]["decision_id"]
        assert decision_id.startswith(denied.value.ref)
        assert _receipts(env.root)[decision_id]["allowed"] is False

    def test_dispatcher_denial_and_requested_by(self, env: DemoEnvironment, serve: Any) -> None:
        running = serve()
        with ControlPlaneClient(running.path, _agent_token(env)) as client:
            with pytest.raises(ControlPlaneDenied):  # noqa: SIM117 - the next call is outside
                client.call("read_file", {"path": PROMPT}, requested_by="someone-else")
            assert client.call("read_file", {"path": PROMPT}, requested_by=REQUESTER.id)

    def test_tool_error_and_unserialisable_result(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tools = env.cp.dispatcher._tools
        spec = tools["read_file"]

        def boom(path: str) -> str:
            raise RuntimeError("secret detail")

        running = serve()
        with ControlPlaneClient(running.path, _agent_token(env)) as client:
            monkeypatch.setitem(tools, "read_file", dataclasses.replace(spec, fn=boom))
            with pytest.raises(ControlPlaneError, match="^tool error$"):
                client.call("read_file", {"path": PROMPT})
            opaque = dataclasses.replace(spec, fn=lambda path: object())
            monkeypatch.setitem(tools, "read_file", opaque)
            with pytest.raises(ControlPlaneError, match="not serialisable"):
                client.call("read_file", {"path": PROMPT})
        failed = [x for x in _audit_lines(env.root) if x["metadata"].get("phase") == "failed"]
        assert [x["violations"] for x in failed] == [
            ["tool error: RuntimeError"],
            ["result not JSON-serialisable"],
        ]

    def test_intent_record_failure_denies_before_the_tool_runs(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        running = serve()

        def fail(entry: Any) -> str:
            raise OSError("disk full")

        monkeypatch.setattr(running.service._audit, "record_durable", fail)
        with (
            ControlPlaneClient(running.path, _agent_token(env)) as client,
            pytest.raises(ControlPlaneDenied),
        ):
            client.call("read_file", {"path": PROMPT})
        assert env.tool_calls == []  # never executed

    def test_completion_record_failure_is_executed_unaudited(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        running = serve()
        audit = running.service._audit
        real = audit.record_durable

        def fail_completion(entry: Any) -> str:
            if entry.metadata.get("phase") == "completed":
                raise OSError("disk full")
            return real(entry)

        monkeypatch.setattr(audit, "record_durable", fail_completion)
        with (
            ControlPlaneClient(running.path, _agent_token(env)) as client,
            pytest.raises(ControlPlaneError) as error,
        ):
            client.call("read_file", {"path": PROMPT})
        assert error.value.code == EXECUTED_UNAUDITED
        assert env.tool_calls == [("read_file", PROMPT)]
        assert _audit_lines(env.root)[-1]["metadata"]["phase"] == "intent"


class TestProtocol:
    @pytest.mark.parametrize(
        ("frame", "match"),
        [
            (b'{"op": "call", "principal": "x", "credential": "t", "tool": "r"}', "unknown"),
            (b'{"op": "call", "kind": "human", "credential": "t", "tool": "r"}', "unknown"),
            (b'{"op": "ping", "id": NaN}', "non-finite"),
            (b'{"op": "ping", "op": "ping"}', "duplicate"),
            (b"[1]", "JSON object"),
            (b"\xff", "malformed"),
            (b"{", "malformed"),
            (b'{"op": "delete"}', "op must be"),
            (b'{"op": "ping", "tool": "x"}', "ping takes"),
            (b'{"op": "ping", "id": true}', "id must be"),
            (b'{"op": "call", "tool": "r"}', "needs credential"),
            (b'{"op": "call", "credential": "", "tool": "r"}', "credential must"),
            (b'{"op": "call", "credential": "t", "tool": "r", "arguments": []}', "arguments"),
            (b'{"op": "call", "credential": "t", "tool": "r", "requested_by": 1}', "requested_by"),
        ],
    )
    def test_parse_frame_is_strict(self, frame: bytes, match: str) -> None:
        with pytest.raises(ProtocolError, match=match):
            parse_frame(frame)

    def test_principal_key_is_an_error_and_the_connection_survives(self, serve: Any) -> None:
        running = serve()
        replies = _raw(
            running.path,
            b'{"op": "call", "principal": "root-admin", "credential": "t", "tool": "r", "id": 7}\n'
            b'{"op": "ping", "id": 8}\n',
        )
        assert replies == [
            {"id": None, "ok": False, "error": "unknown request keys"},
            {"id": 8, "ok": True, "result": "pong"},
        ]

    def test_oversized_frame_is_an_error_and_closes(self, serve: Any) -> None:
        running = serve(max_frame_bytes=128)
        replies = _raw(
            running.path, b'{"op": "ping", "id": "' + b"x" * 200 + b'"}\n{"op": "ping"}\n'
        )
        assert replies == [{"id": None, "ok": False, "error": "frame too large"}]

    def test_unterminated_final_fragment_is_never_parsed(self, serve: Any) -> None:
        running = serve()
        assert _raw(running.path, b'{"op": "ping"}') == [
            {"id": None, "ok": False, "error": "frame too large"}
        ]

    def test_idle_connection_times_out(self, serve: Any) -> None:
        running = serve(connection_timeout_s=0.05)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(running.path)
            assert sock.recv(1) == b""

    def test_connection_cap(self, env: DemoEnvironment, serve: Any) -> None:
        running = serve(max_connections=1, reserved_human_slots=0)
        with ControlPlaneClient(running.path, _agent_token(env)) as first:
            assert first.ping()
            with (
                ControlPlaneClient(running.path, _agent_token(env)) as second,
                pytest.raises(ControlPlaneError),
            ):
                second.ping()


class TestStartup:
    def test_refuses_writable_socket_directory(self, env: DemoEnvironment, sock_dir: Path) -> None:
        os.chmod(sock_dir, 0o777)
        service = ControlPlaneService(env.cp, sock_dir / "cp.sock", AGENT_ONLY)
        with pytest.raises(ControlPlaneServiceError, match="writable"):
            service.start()
        service.shutdown()

    def test_refuses_non_directory_parent(self, env: DemoEnvironment, sock_dir: Path) -> None:
        (sock_dir / "file").write_text("x")
        service = ControlPlaneService(env.cp, sock_dir / "file" / "cp.sock", AGENT_ONLY)
        with pytest.raises(ControlPlaneServiceError, match="not a directory"):
            service.start()
        service.shutdown()

    def test_creates_missing_directory_0700(self, env: DemoEnvironment, sock_dir: Path) -> None:
        with ControlPlaneService(env.cp, sock_dir / "new" / "cp.sock", AGENT_ONLY) as service:
            assert stat.S_IMODE(os.lstat(sock_dir / "new").st_mode) == 0o700
            service.start()  # idempotent
        assert not (sock_dir / "new" / "cp.sock").exists()
        with pytest.raises(ControlPlaneServiceError, match="shut down"):
            service.start()

    def test_refuses_existing_non_socket_and_replaces_stale_socket(
        self, env: DemoEnvironment, sock_dir: Path
    ) -> None:
        target = sock_dir / "cp.sock"
        target.write_text("not a socket")
        service = ControlPlaneService(env.cp, target, AGENT_ONLY)
        with pytest.raises(ControlPlaneServiceError, match="not a socket"):
            service.start()
        service.shutdown()
        target.unlink()
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(str(target))
        stale.close()
        with ControlPlaneService(env.cp, target, AGENT_ONLY):
            assert stat.S_IMODE(os.lstat(target).st_mode) == 0o600
            # A live socket (another running service) is never taken over.
            rival = ControlPlaneService(env.cp, target, AGENT_ONLY)
            with pytest.raises(ControlPlaneServiceError, match="listening"):
                rival.start()
            rival.shutdown()

    @pytest.mark.parametrize(
        ("uid_kinds", "match"),
        [
            ({UID: frozenset({PrincipalKind.HUMAN, PrincipalKind.AGENT})}, "dedicated"),
            ({}, "non-empty mapping"),
            ({-1: frozenset({PrincipalKind.AGENT})}, "uids"),
            ({True: frozenset({PrincipalKind.AGENT})}, "uids"),
            ({UID: {PrincipalKind.AGENT}}, "frozensets"),
            ({UID: frozenset()}, "frozensets"),
            ({UID: frozenset({"agent"})}, "PrincipalKind"),
        ],
    )
    def test_uid_map_validation(
        self, env: DemoEnvironment, sock_dir: Path, uid_kinds: Any, match: str
    ) -> None:
        with pytest.raises(ControlPlaneServiceError, match=match):
            ControlPlaneService(env.cp, sock_dir / "cp.sock", uid_kinds)

    def test_dedicated_human_uid_is_accepted(self, env: DemoEnvironment, sock_dir: Path) -> None:
        ControlPlaneService(env.cp, sock_dir / "cp.sock", {UID: frozenset({PrincipalKind.HUMAN})})

    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"max_frame_bytes": 0}, "max_frame_bytes"),
            ({"max_frame_bytes": 1.5}, "max_frame_bytes"),
            ({"connection_timeout_s": True}, "connection_timeout_s"),
            ({"max_connections": -1}, "max_connections"),
            ({"audit_path": "workspace/audit.jsonl"}, "AUDIT_LOG"),
        ],
    )
    def test_knob_validation(
        self, env: DemoEnvironment, sock_dir: Path, kwargs: Any, match: str
    ) -> None:
        with pytest.raises(ControlPlaneServiceError, match=match):
            ControlPlaneService(env.cp, sock_dir / "cp.sock", AGENT_ONLY, **kwargs)

    def test_refuses_bad_control_plane_and_paths(
        self, env: DemoEnvironment, sock_dir: Path
    ) -> None:
        with pytest.raises(ControlPlaneServiceError, match="ControlPlane"):
            ControlPlaneService(env.cp.dispatcher, sock_dir / "cp.sock", AGENT_ONLY)  # type: ignore[arg-type]
        with pytest.raises(ControlPlaneServiceError, match="too long"):
            ControlPlaneService(env.cp, sock_dir / ("x" * 120), AGENT_ONLY)
        with pytest.raises(ControlPlaneServiceError, match="immutable-core"):
            ControlPlaneService(env.cp, env.root / "control-plane" / "cp.sock", AGENT_ONLY)


class TestClient:
    def test_client_errors(self, sock_dir: Path) -> None:
        with pytest.raises(ValueError, match="credential"):
            ControlPlaneClient(str(sock_dir / "cp.sock"), "")
        with pytest.raises(ControlPlaneError, match="cannot connect"):
            ControlPlaneClient(str(sock_dir / "missing.sock"), "t").ping()
        client = ControlPlaneClient(str(sock_dir / "cp.sock"), "t", max_frame_bytes=16)
        with pytest.raises(ControlPlaneError, match="too large"):
            client.call("read_file", {"path": "x" * 32})


# -- fix round 1 ------------------------------------------------------------------


class TestMalformedCredentials:
    @pytest.mark.parametrize(
        "token",
        [
            "",
            "YWJj.éé",
            "é" * 10 + "." + "0" * 64,
            "a" * 20_000 + "." + "0" * 64,
            "YWJj." + "0" * 63,
            "YWJj." + "G" * 64,
            "." + "0" * 64,
        ],
    )
    def test_authenticate_raises_only_credential_invalid(
        self, env: DemoEnvironment, token: str
    ) -> None:
        with pytest.raises(CredentialInvalid, match="malformed"):
            env.cp.credentials.authenticate(token)

    @pytest.mark.parametrize("token", ["YWJj.éé", "a" * 20_000 + "." + "0" * 64])
    def test_malformed_token_over_the_socket_is_denied_and_audited(
        self, env: DemoEnvironment, serve: Any, token: str
    ) -> None:
        running = serve()
        with ControlPlaneClient(running.path, token) as client:
            with pytest.raises(ControlPlaneDenied):  # noqa: SIM117
                client.call("read_file", {"path": PROMPT})
            assert client.ping()  # the connection thread survived
        line = _audit_lines(env.root)[-1]
        assert line["metadata"]["phase"] == "denied"
        assert line["violations"] == ["credential rejected: malformed token"]

    def test_verifier_bug_is_a_denial_with_type_only(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken(token: object) -> Any:
            raise RuntimeError("secret internals")

        monkeypatch.setattr(env.cp.credentials, "authenticate", broken)
        running = serve()
        with (
            ControlPlaneClient(running.path, _agent_token(env)) as client,
            pytest.raises(ControlPlaneDenied),
        ):
            client.call("read_file", {"path": PROMPT})
        assert _audit_lines(env.root)[-1]["violations"] == ["credential rejected: RuntimeError"]

    def test_connection_bug_is_logged_audited_and_closed(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        running = serve()

        def broken(*args: Any) -> Any:
            raise ValueError("bug")

        monkeypatch.setattr(running.service, "_handle_frame", broken)
        assert _raw(running.path, b'{"op": "ping"}\n') == []
        line = _audit_lines(env.root)[-1]
        assert line["metadata"]["phase"] == "connection_error"
        assert line["violations"] == ["connection error: ValueError"]

    def test_denial_receipts_are_rate_limited_per_uid(
        self, env: DemoEnvironment, serve: Any
    ) -> None:
        running = serve(max_denials_per_uid=2)
        before = len(_receipts(env.root))
        with ControlPlaneClient(running.path, "not.a-token") as client:
            for _ in range(2):
                with pytest.raises(ControlPlaneDenied):
                    client.call("read_file", {"path": PROMPT})
            with pytest.raises(ControlPlaneError) as error:
                client.call("read_file", {"path": PROMPT})
        assert error.value.code == "rate limited"
        assert len(_receipts(env.root)) == before + 2


class TestSlowlorisAndCaps:
    def test_trickled_frame_hits_the_whole_frame_deadline(self, serve: Any) -> None:
        running = serve(connection_timeout_s=2.0)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(running.path)
            sock.settimeout(1.5)
            started = time.monotonic()
            closed_at = None
            for byte in b'{"op": "ping"}':
                sock.sendall(bytes([byte]))
                try:
                    if sock.recv(1) == b"":  # the server hung up
                        closed_at = time.monotonic() - started
                        break
                except TimeoutError:
                    continue  # one byte per 1.5 s: each recv alone is under 2 s
        assert closed_at is not None and 1.9 <= closed_at < 3.5

    def test_per_uid_cap_cannot_starve_another_uid(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        other = UID + 4242
        uids = {UID: frozenset({PrincipalKind.AGENT}), other: frozenset({PrincipalKind.AGENT})}
        running = serve(uids, max_connections=4, max_connections_per_uid=1, reserved_human_slots=0)
        peers = iter([other, other, UID])
        monkeypatch.setattr(running.service, "_peer_credentials", lambda conn: (1, next(peers), 1))
        token = _agent_token(env)
        with ControlPlaneClient(running.path, token) as first:
            assert first.ping()  # the fake uid holds its one slot
            with (
                ControlPlaneClient(running.path, token) as second,
                pytest.raises(ControlPlaneError),
            ):
                second.ping()  # the fake uid is over its cap
            with ControlPlaneClient(running.path, token) as third:
                assert third.ping()  # the real uid still gets a slot

    def test_admit_and_release_accounting(self, env: DemoEnvironment, sock_dir: Path) -> None:
        service = ControlPlaneService(
            env.cp, sock_dir / "cp.sock", AGENT_ONLY, max_connections_per_uid=2
        )
        assert service._admit(5) and service._admit(5) and not service._admit(5)
        assert service._admit(6)
        service._release(5)
        assert service._admit(5)
        for _ in range(3):
            service._release(5)
        assert service._per_uid == {6: 1}
        service.shutdown()
        assert not service._admit(7)  # stopping

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_connections_per_uid": 0},
            {"max_denials_per_uid": 0},
            {"denial_window_s": 0},
            {"socket_group": -1},
            {"socket_group": True},
        ],
    )
    def test_new_knob_validation(self, env: DemoEnvironment, sock_dir: Path, kwargs: Any) -> None:
        with pytest.raises(ControlPlaneServiceError):
            ControlPlaneService(env.cp, sock_dir / "cp.sock", AGENT_ONLY, **kwargs)

    def test_id_bounds(self) -> None:
        with pytest.raises(ProtocolError, match="64-bit"):
            parse_frame(b'{"op": "ping", "id": ' + b"9" * 30 + b"}")
        with pytest.raises(ProtocolError, match="short string"):
            parse_frame(b'{"op": "ping", "id": "' + b"x" * 200 + b'"}')


class TestDeploymentModes:
    def test_socket_group_layout(self, env: DemoEnvironment, sock_dir: Path) -> None:
        gid = os.getgid()
        path = sock_dir / "grp" / "cp.sock"
        service = ControlPlaneService(env.cp, path, AGENT_ONLY, socket_group=gid)
        running = _Running(service)
        try:
            dir_info, sock_info = os.lstat(path.parent), os.lstat(path)
            assert stat.S_IMODE(dir_info.st_mode) == 0o710 and dir_info.st_gid == gid
            assert stat.S_IMODE(sock_info.st_mode) == 0o660 and sock_info.st_gid == gid
            with ControlPlaneClient(str(path), _agent_token(env)) as client:
                assert client.call("read_file", {"path": PROMPT}).startswith("You are")
        finally:
            running.stop()

    def test_refuses_writable_ancestor(self, env: DemoEnvironment, sock_dir: Path) -> None:
        os.chmod(sock_dir, 0o777)
        service = ControlPlaneService(env.cp, sock_dir / "sub" / "cp.sock", AGENT_ONLY)
        with pytest.raises(ControlPlaneServiceError, match="ancestor"):
            service.start()
        service.shutdown()
        assert not (sock_dir / "sub").exists()

    def test_missing_parents_are_created_0700(self, env: DemoEnvironment, sock_dir: Path) -> None:
        old = os.umask(0o022)  # a permissive umask must not leak into the modes
        try:
            with ControlPlaneService(env.cp, sock_dir / "a" / "b" / "cp.sock", AGENT_ONLY):
                for rel in ("a", "a/b"):
                    assert stat.S_IMODE(os.lstat(sock_dir / rel).st_mode) == 0o700
        finally:
            os.umask(old)


class TestReceiptCredentialId:
    def test_plain_dispatch_receipts_carry_the_credential_id(self, env: DemoEnvironment) -> None:
        credential = env.cp.credentials.issue(
            AGENT, scopes=["tool:read_file"], on_behalf_of=REQUESTER.id, trigger_id=TRIGGER_ID
        )
        result = env.cp.dispatcher.dispatch(
            AGENT, "read_file", {"path": PROMPT}, credential=credential.token
        )
        receipts = _receipts(env.root)
        assert receipts[result.decisions[0].decision_id]["credential_id"] == (
            credential.credential_id
        )
        with pytest.raises(ToolDenied) as denied:
            env.cp.dispatcher.dispatch(
                AGENT, "read_file", {"path": SUITE_PATH}, credential=credential.token
            )
        assert _receipts(env.root)[denied.value.decision.decision_id]["credential_id"] == (
            credential.credential_id
        )
        with pytest.raises(ToolDenied) as anonymous:
            env.cp.dispatcher.dispatch(AGENT, "read_file", {"path": PROMPT})
        assert _receipts(env.root)[anonymous.value.decision.decision_id]["credential_id"] is None
        assert env.cp.verify_receipts().valid

    def test_credential_id_is_hashed_only_when_set(self, env: DemoEnvironment) -> None:
        env.cp.dispatcher.dispatch(
            AGENT, "read_file", {"path": PROMPT}, credential=_agent_token(env)
        )
        with_id = next(r.receipt for r in env.cp.ledger.receipts() if r.receipt.credential_id)
        without = env.cp.ledger.receipts()[0].receipt
        assert without.credential_id is None and "credential_id" not in without._payload()
        assert with_id._payload()["credential_id"] == with_id.credential_id
        assert ControlPlaneReceipt.from_dict(with_id.to_dict()) == with_id
        legacy = {k: v for k, v in without.to_dict().items() if k != "credential_id"}
        assert ControlPlaneReceipt.from_dict(legacy).verify_hash()
        tampered = dataclasses.replace(with_id, credential_id="0" * 32)
        assert not tampered.verify_hash()
        with pytest.raises(ValueError, match="credential_id"):
            dataclasses.replace(with_id, credential_id="not-hex")

    def test_hook_failure_denies_in_adispatch(self, env: DemoEnvironment) -> None:
        def hook(decisions: Any) -> None:
            raise OSError("no")

        async def run() -> None:
            await env.cp.dispatcher.adispatch(
                AGENT,
                "read_file",
                {"path": PROMPT},
                credential=_agent_token(env),
                on_authorized=hook,
            )

        with pytest.raises(ToolDenied, match="pre-execution hook failed: OSError"):
            asyncio.run(run())
        assert env.tool_calls == []


# -- fix round 2 ------------------------------------------------------------------


class TestRound2:
    @pytest.mark.parametrize("missing", [False, True])
    def test_trusted_symlink_does_not_hide_untrusted_ancestor(
        self, sock_dir: Path, monkeypatch: pytest.MonkeyPatch, missing: bool
    ) -> None:
        untrusted = sock_dir / "untrusted"
        root_owned = untrusted / "root-owned"
        root_owned.mkdir(parents=True)
        safe = sock_dir / "safe"
        safe.mkdir(mode=0o700)
        link = root_owned / "link"
        link.symlink_to(safe)
        directory = link / "sockets" if missing else link / "existing"
        if not missing:
            directory.mkdir(mode=0o700)
        original_lstat = os.lstat

        def ownership(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            info = original_lstat(path, *args, **kwargs)
            values = list(info)
            if Path(path) == untrusted:
                values[4] = os.getuid() + 1
            elif Path(path) in (root_owned, link):
                values[4] = 0
            return os.stat_result(values)

        monkeypatch.setattr(os, "lstat", ownership)
        with pytest.raises(ControlPlaneServiceError, match="ancestor.*owned by others"):
            service_module._prepare_directory(directory, None)
        assert not (safe / "sockets").exists()

    @pytest.mark.parametrize("relative", [False, True])
    @pytest.mark.parametrize("missing", [False, True])
    def test_trusted_link_target_chain_cannot_hide_untrusted_ancestor(
        self, sock_dir: Path, monkeypatch: pytest.MonkeyPatch, relative: bool, missing: bool
    ) -> None:
        untrusted = sock_dir / "untrusted"
        hidden = untrusted / "root-owned"
        hidden.mkdir(parents=True)
        safe = sock_dir / "safe"
        safe.mkdir(mode=0o700)
        inner = hidden / "inner"
        inner.symlink_to(safe)
        outer = sock_dir / "outer"
        outer.symlink_to(inner.relative_to(sock_dir) if relative else inner)
        if not missing:
            (safe / "sockets").mkdir(mode=0o700)
        original_lstat = os.lstat

        def ownership(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            info = original_lstat(path, *args, **kwargs)
            values = list(info)
            if Path(path) == untrusted:
                values[4] = os.getuid() + 1
            elif Path(path) in (sock_dir, hidden, inner, outer):
                values[4] = 0
            return os.stat_result(values)

        monkeypatch.setattr(os, "lstat", ownership)
        with pytest.raises(ControlPlaneServiceError, match="ancestor.*owned by others"):
            service_module._prepare_directory(outer / "sockets", None)
        assert (safe / "sockets").exists() is not missing

    def test_trusted_link_loop_is_refused(
        self, sock_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        link = sock_dir / "loop"
        link.symlink_to("loop")
        monkeypatch.setattr(service_module, "_trusted_symlink", lambda *_: True)
        with pytest.raises(ControlPlaneServiceError, match="symlink limit"):
            _check_path_components(link / "sockets")

    def test_trusted_target_parent_segments_do_not_hide_unsafe_directory(
        self, sock_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        unsafe = sock_dir / "unsafe"
        unsafe.mkdir()
        os.chmod(unsafe, 0o777)
        safe = sock_dir / "safe"
        safe.mkdir(mode=0o700)
        link = sock_dir / "link"
        link.symlink_to("unsafe/../safe")
        monkeypatch.setattr(service_module, "_trusted_symlink", lambda *_: True)
        with pytest.raises(ControlPlaneServiceError, match="ancestor.*writable"):
            _check_path_components(link / "sockets")

    def test_symlink_component_is_refused(self, env: DemoEnvironment, sock_dir: Path) -> None:
        safe = sock_dir / "safe"
        safe.mkdir(mode=0o700)
        evil = sock_dir / "evil"
        evil.mkdir()
        os.chmod(evil, 0o777)  # anyone could repoint a link in here
        (evil / "link").symlink_to(safe)
        service = ControlPlaneService(env.cp, evil / "link" / "x.sock", AGENT_ONLY)
        with pytest.raises(ControlPlaneServiceError, match="ancestor.*writable"):
            service.start()
        service.shutdown()
        assert list(safe.iterdir()) == []
        # Even our own link in our own 0700 directory: one path everywhere.
        (sock_dir / "mine").symlink_to(safe)
        service = ControlPlaneService(env.cp, sock_dir / "mine" / "x.sock", AGENT_ONLY)
        with pytest.raises(ControlPlaneServiceError, match="symlink"):
            service.start()
        service.shutdown()
        with pytest.raises(ControlPlaneServiceError, match=r"'\.\.'"):
            _check_path_components(sock_dir / "safe" / ".." / "x")

    def test_root_owned_system_symlink_is_trusted(self) -> None:
        link = Path("/var/run")
        if not link.is_symlink() or link.lstat().st_uid != 0:
            pytest.skip("no root-owned /var/run symlink on this host")
        _check_path_components(link / "acgs" / "cp.sock")

    def test_kill_switch_engaged_in_the_hook_stops_the_tool(self, env: DemoEnvironment) -> None:
        admin_token = env.admin_credential

        def hook(decisions: Any) -> None:
            env.cp.kill_switch.engage(ADMIN, "halt mid-call", admin_credential=admin_token)

        before = len(env.cp.ledger.receipts())
        with pytest.raises(ToolDenied, match="kill switch engaged") as denied:
            env.cp.dispatcher.dispatch(
                AGENT,
                "read_file",
                {"path": PROMPT},
                credential=_agent_token(env),
                on_authorized=hook,
            )
        assert env.tool_calls == []
        assert len(env.cp.ledger.receipts()) > before
        receipt = _receipts(env.root)[denied.value.decision.decision_id]
        assert receipt["allowed"] is False

    def test_kill_switch_engaged_in_the_hook_stops_adispatch(self, env: DemoEnvironment) -> None:
        admin_token = env.admin_credential

        def hook(decisions: Any) -> None:
            env.cp.kill_switch.engage(ADMIN, "halt mid-call", admin_credential=admin_token)

        async def run() -> None:
            await env.cp.dispatcher.adispatch(
                AGENT,
                "read_file",
                {"path": PROMPT},
                credential=_agent_token(env),
                on_authorized=hook,
            )

        with pytest.raises(ToolDenied, match="kill switch engaged"):
            asyncio.run(run())
        assert env.tool_calls == []

    def test_human_slots_are_reserved(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        human_uid = UID + 777
        uids = {UID: frozenset({PrincipalKind.AGENT}), human_uid: frozenset({PrincipalKind.HUMAN})}
        running = serve(uids, max_connections=3, reserved_human_slots=1)
        peers = iter([UID, UID, UID, human_uid])
        monkeypatch.setattr(running.service, "_peer_credentials", lambda conn: (1, next(peers), 1))
        token = _agent_token(env)
        with (
            ControlPlaneClient(running.path, token) as a,
            ControlPlaneClient(running.path, token) as b,
        ):
            assert a.ping() and b.ping()  # the two non-reserved slots
            with ControlPlaneClient(running.path, token) as c, pytest.raises(ControlPlaneError):
                c.ping()  # an agent uid may not take the reserved slot
            with ControlPlaneClient(running.path, token) as human:
                assert human.ping()  # the human uid still gets in

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_connections": 4, "reserved_human_slots": 4},
            {"reserved_human_slots": -1},
            {"reserved_human_slots": True},
        ],
    )
    def test_reserved_slot_validation(
        self, env: DemoEnvironment, sock_dir: Path, kwargs: Any
    ) -> None:
        with pytest.raises(ControlPlaneServiceError, match="reserved_human_slots"):
            ControlPlaneService(env.cp, sock_dir / "cp.sock", AGENT_ONLY, **kwargs)

    def test_dispatcher_denials_share_the_per_uid_budget(
        self, env: DemoEnvironment, serve: Any
    ) -> None:
        running = serve(max_denials_per_uid=1)
        with ControlPlaneClient(running.path, _agent_token(env)) as client:
            with pytest.raises(ControlPlaneDenied):
                client.call("read_file", {"path": SUITE_PATH})
            with pytest.raises(ControlPlaneError) as error:
                client.call("read_file", {"path": SUITE_PATH})
        assert error.value.code == "rate limited"
        assert "INV" not in str(error.value)
        denied = [x for x in _audit_lines(env.root) if x["metadata"]["phase"] == "denied"]
        assert len(denied) == 1

    def test_thread_start_failure_releases_the_slot(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        running = serve()
        failures = [RuntimeError("can't start new thread")]

        class Flaky(threading.Thread):
            def start(self) -> None:
                if failures:
                    raise failures.pop()
                super().start()

        monkeypatch.setattr(service_module.threading, "Thread", Flaky)
        with (
            ControlPlaneClient(running.path, _agent_token(env)) as first,
            pytest.raises(ControlPlaneError),
        ):
            first.ping()
        with ControlPlaneClient(running.path, _agent_token(env)) as second:
            assert second.ping()  # serve_forever survived
        assert running.service._per_uid in ({}, {UID: 1})
