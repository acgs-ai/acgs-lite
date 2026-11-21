"""Regression tests for the PR #242 (phase 6) review threads."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import shutil
import stat
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from acgs_cp_client import ControlPlaneClient, ControlPlaneError  # noqa: E402
from acgs_lite.control_plane import ActionTier, Principal, PrincipalKind, ToolDenied  # noqa: E402
from acgs_lite.control_plane.credentials import CredentialIssuanceRefused
from acgs_lite.control_plane.demo_loop import (
    AGENT,
    ARTIFACT_FILES,
    REQUESTER,
    TRIGGER_ID,
    DemoEnvironment,
    build_demo_environment,
)
from acgs_lite.control_plane.dispatcher import GovernedToolDispatcher, _Denied
from acgs_lite.control_plane.service import (
    RESULT_TOO_LARGE,
    SERVICE_AUDIT_PATH,
    ControlPlaneService,
    _prepare_directory,
    _safe_ancestor,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

UID = os.getuid()
AGENT_ONLY = {UID: frozenset({PrincipalKind.AGENT})}
PROMPT = ARTIFACT_FILES["prompt"]


@pytest.fixture()
def env(tmp_path: Path) -> Iterator[DemoEnvironment]:
    environment = build_demo_environment(tmp_path / "repo")
    yield environment
    environment.close()


@pytest.fixture()
def sock_dir() -> Iterator[Path]:
    directory = Path(tempfile.mkdtemp(prefix="cpr-"))
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


def _token(env: DemoEnvironment) -> str:
    return env.cp.credentials.issue(
        AGENT, scopes=["tool:read_file"], on_behalf_of=REQUESTER.id, trigger_id=TRIGGER_ID
    ).token


@pytest.fixture()
def serve(env: DemoEnvironment, sock_dir: Path) -> Iterator[Any]:
    running: list[tuple[ControlPlaneService, threading.Thread]] = []

    def start(**kwargs: Any) -> ControlPlaneService:
        service = ControlPlaneService(env.cp, sock_dir / "cp.sock", AGENT_ONLY, **kwargs)
        service.start()
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        running.append((service, thread))
        return service

    yield start
    for service, thread in running:
        service.shutdown()
        thread.join(timeout=5)


def _stat(mode: int, uid: int) -> os.stat_result:
    return os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))


class TestSocketDirectory:
    """242.1 / 242.6 / 242.2 / 242.10."""

    def test_ancestor_owner_must_be_root_or_service(self) -> None:
        directory = stat.S_IFDIR
        assert _safe_ancestor(_stat(directory | 0o755, 0))
        assert _safe_ancestor(_stat(directory | 0o755, UID))
        assert not _safe_ancestor(_stat(directory | 0o755, UID + 4242))
        assert _safe_ancestor(_stat(directory | 0o1777, 0))  # /tmp
        assert not _safe_ancestor(_stat(directory | 0o1777, UID + 4242))
        assert not _safe_ancestor(_stat(directory | 0o775, UID))

    def test_every_created_parent_gets_the_socket_group(self, sock_dir: Path) -> None:
        target = sock_dir / "a" / "b"
        _prepare_directory(target, os.getgid())
        for level in (sock_dir / "a", target):
            info = os.stat(level)
            assert stat.S_IMODE(info.st_mode) == 0o710, level
            assert info.st_gid == os.getgid()


class TestServiceCalls:
    """242.3 / 242.7 / 242.4 / 242.11 / 242.8 / 242.12."""

    @pytest.mark.parametrize("kind", ["sync", "async", "async_callable", "returns_coroutine"])
    def test_all_callable_forms_execute_once(
        self,
        env: DemoEnvironment,
        serve: Any,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
    ) -> None:
        calls: list[str] = []
        authorizations: list[str] = []

        def read_sync(path: str) -> str:
            calls.append(path)
            return "read-ok"

        async def read_async(path: str) -> str:
            await asyncio.sleep(0)
            return read_sync(path)

        class AsyncReader:
            async def __call__(self, path: str) -> str:
                return await read_async(path)

        def read_wrapper(path: str) -> Any:
            return read_async(path)

        fn = {
            "sync": read_sync,
            "async": read_async,
            "async_callable": AsyncReader(),
            "returns_coroutine": read_wrapper,
        }[kind]
        tools = env.cp.dispatcher._tools
        monkeypatch.setitem(tools, "read_file", dataclasses.replace(tools["read_file"], fn=fn))
        original = env.cp.dispatcher._authorize

        def counting(*args: Any, **kwargs: Any) -> Any:
            authorizations.append(args[1])
            return original(*args, **kwargs)

        monkeypatch.setattr(env.cp.dispatcher, "_authorize", counting)
        service = serve()
        with ControlPlaneClient(str(service.socket_path), _token(env)) as client:
            assert client.call("read_file", {"path": PROMPT}) == "read-ok"
        assert calls == [PROMPT]
        assert authorizations == ["read_file"]
        lines = (env.root / SERVICE_AUDIT_PATH).read_text(encoding="utf-8").splitlines()
        phases = [json.loads(line)["metadata"].get("phase") for line in lines if line]
        assert phases == ["intent", "completed"]

    def test_exhausted_uid_is_refused_before_dispatch(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service = serve(max_denials_per_uid=1)
        dispatched: list[str] = []
        original = env.cp.dispatcher._authorize

        def counting(*args: Any, **kwargs: Any) -> Any:
            dispatched.append(args[1])
            return original(*args, **kwargs)

        monkeypatch.setattr(env.cp.dispatcher, "_authorize", counting)
        with (
            ControlPlaneClient(str(service.socket_path), _token(env)) as client,
            pytest.raises(ControlPlaneError),
        ):
            client.call("read_file", {"path": "heldout/demo-suite.json"})
        with (
            ControlPlaneClient(str(service.socket_path), _token(env)) as client,
            pytest.raises(ControlPlaneError, match="rate limited"),
        ):
            client.call("read_file", {"path": "heldout/demo-suite.json"})
        assert dispatched == ["read_file"]  # the second call never reached the PDP

    def test_async_tool_runs(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tools = env.cp.dispatcher._tools

        async def read_async(path: str) -> str:
            return "async-ok"

        monkeypatch.setitem(
            tools, "read_file", dataclasses.replace(tools["read_file"], fn=read_async)
        )
        service = serve()
        with ControlPlaneClient(str(service.socket_path), _token(env)) as client:
            assert client.call("read_file", {"path": PROMPT}) == "async-ok"
        # Attribution before execution holds on the async path too.
        lines = (env.root / SERVICE_AUDIT_PATH).read_text(encoding="utf-8").splitlines()
        phases = [json.loads(line)["metadata"].get("phase") for line in lines if line]
        assert phases[-2:] == ["intent", "completed"]

    def test_oversized_result_is_bounded(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tools = env.cp.dispatcher._tools
        big = dataclasses.replace(tools["read_file"], fn=lambda path: "x" * (70 * 1024))
        monkeypatch.setitem(tools, "read_file", big)
        service = serve()
        with (
            ControlPlaneClient(str(service.socket_path), _token(env)) as client,
            pytest.raises(ControlPlaneError) as excinfo,
        ):
            client.call("read_file", {"path": PROMPT})
        assert excinfo.value.code == RESULT_TOO_LARGE

    def test_unaudited_failed_phase_is_executed_unaudited(
        self, env: DemoEnvironment, serve: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tools = env.cp.dispatcher._tools
        opaque = dataclasses.replace(tools["read_file"], fn=lambda path: object())
        monkeypatch.setitem(tools, "read_file", opaque)
        service = serve()
        original = service._audit_record

        def no_failed_record(record: Any, *, phase: str, **kw: Any) -> bool:
            if phase == "failed":
                return False
            return original(record, phase=phase, **kw)

        monkeypatch.setattr(service, "_audit_record", no_failed_record)
        with (
            ControlPlaneClient(str(service.socket_path), _token(env)) as client,
            pytest.raises(ControlPlaneError) as excinfo,
        ):
            client.call("read_file", {"path": PROMPT})
        assert excinfo.value.code == "executed_unaudited"


class TestCredentialBinding:
    """242.5 / 242.9."""

    def test_authenticated_requester_is_bound_without_obo(self, env: DemoEnvironment) -> None:
        cred = env.cp.credentials.issue(
            AGENT,
            scopes=["tool:read_file"],
            trigger_id=TRIGGER_ID,
            requester=REQUESTER,
            requester_credential=env.requester_credential,
        )
        assert cred.on_behalf_of == REQUESTER.canonical_id

    def test_unbound_credential_cannot_carry_a_t2_agent_call(self, env: DemoEnvironment) -> None:
        session = env.cp.credentials.issue(AGENT, scopes=["tool:read_file"])
        assert session.on_behalf_of is None
        with pytest.raises(_Denied, match="not bound"):
            GovernedToolDispatcher._resolve_requested_by(AGENT, ActionTier.T2, "anyone", session)

    def test_oversized_token_refused_at_issuance(self, env: DemoEnvironment) -> None:
        scopes = [f"tool:{'a' * 240}{index:03d}" for index in range(80)]
        with pytest.raises(CredentialIssuanceRefused, match="exceed"):
            env.cp.credentials.issue(AGENT, scopes=scopes)


class TestRunbookOutcomeWiring:
    """241.2 / 241.15 at the dispatcher: a predicate-failing return is counted."""

    @pytest.mark.parametrize(("exit_status", "second_allowed"), [(1, False), (0, True)])
    def test_exit_code_feeds_stop_conditions(
        self,
        p5: Any,
        runbook_data: Any,
        monkeypatch: pytest.MonkeyPatch,
        exit_status: int,
        second_allowed: bool,
    ) -> None:
        agent = Principal("agent-1", PrincipalKind.AGENT, "sys-a")
        digest = p5.approve_runbook(
            runbook_data(stop_conditions=[{"kind": "max_failures", "count": 1}])
        )
        tools = p5.dispatcher._tools
        returning = dataclasses.replace(tools["write_file"], fn=lambda path, content: exit_status)
        monkeypatch.setitem(tools, "write_file", returning)

        def call(name: str) -> Any:
            return p5.dispatcher.dispatch(
                agent,
                "write_file",
                {"path": f"{p5.worktree}/{name}", "content": "x"},
                change_id="c1",
                runbook_id="rb-restart-cache",
                runbook_hash=digest,
            )

        call("a")  # the tool ran and returned exit_status
        if second_allowed:
            call("b")
        else:
            with pytest.raises(ToolDenied, match="runbook rejected"):
                call("b")
