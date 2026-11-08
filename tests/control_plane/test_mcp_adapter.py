"""MCP adapter end-to-end through a real in-memory mcp Server/Client session."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

pytest.importorskip("mcp")

from mcp import Client, types  # noqa: E402
from mcp.server import Server  # noqa: E402

from acgs_lite.control_plane import (  # noqa: E402
    ActionTier,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    WriteGrant,
)
from acgs_lite.integrations.control_plane_mcp import (  # noqa: E402
    CONTROL_PLANE_MCP_AVAILABLE,
    make_mcp_call_tool_handler,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

AGENT = Principal("mcp-agent", PrincipalKind.AGENT)
TOOLS = [
    types.Tool(
        name=name,
        description=name,
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    )
    for name in ("write_file", "explode", "stats")
]


def _server(
    pdp: PolicyDecisionPoint, resolver: Any = lambda ctx: AGENT
) -> tuple[Server, list[Any]]:
    calls: list[Any] = []
    permissions = RepositoryPermissions(
        pdp.registry,
        [WriteGrant("mcp-agent", PrincipalKind.AGENT, ("workspace/**",))],
    )
    dispatcher = GovernedToolDispatcher(
        pdp,
        permissions=permissions,
        tool_tiers={"write_file": ActionTier.T1, "explode": ActionTier.T1, "stats": ActionTier.T0},
        read_only_tools=frozenset({"stats"}),
    )

    def write_file(path: str, content: str = "") -> str:
        calls.append(path)
        return f"wrote {path}"

    def explode(path: str) -> str:
        raise RuntimeError("tool crashed")

    def stats() -> dict[str, int]:
        return {"files": 3}

    dispatcher.register(
        "write_file",
        write_file,
        path_params={"path"},
        opaque_params={"content"},
        merge_capable=False,
    )
    dispatcher.register("explode", explode, path_params={"path"}, merge_capable=False)
    dispatcher.register("stats", stats, merge_capable=False)

    async def list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=TOOLS)

    handler = make_mcp_call_tool_handler(dispatcher, resolver)
    return Server("governed-tools", on_list_tools=list_tools, on_call_tool=handler), calls


async def _call(server: Server, name: str, arguments: dict[str, Any] | None) -> Any:
    async with Client(server) as client:
        return await client.call_tool(name, arguments)


def _text(result: Any) -> str:
    return result.content[0].text


def test_adapter_available() -> None:
    assert CONTROL_PLANE_MCP_AVAILABLE


@pytest.mark.parametrize(
    "target",
    [
        "evaluator/score.py",
        "policies/main.yaml",
        "config/tool_allowlist.json",
        ".github/workflows/x.yml",
        "audit/log.jsonl",
        "src/acgs_lite/control_plane/pdp.py",
        "data/heldout/x.jsonl",
        "secrets/x",
        "ok/../evaluator/x.py",
        "/etc/passwd",
    ],
)
async def test_core_write_denied_over_mcp(pdp: PolicyDecisionPoint, target: str) -> None:
    server, calls = _server(pdp)
    result = await _call(server, "write_file", {"path": target})
    assert result.is_error
    assert re.fullmatch(r"denied \(ref [0-9a-f]{12}\)", _text(result))
    assert calls == []


async def test_permitted_write_runs(pdp: PolicyDecisionPoint) -> None:
    server, calls = _server(pdp)
    result = await _call(server, "write_file", {"path": "workspace/x.py"})
    assert not result.is_error
    assert _text(result) == "wrote workspace/x.py"
    assert calls == ["workspace/x.py"]


async def test_non_string_result_rendered_as_json(pdp: PolicyDecisionPoint) -> None:
    server, _ = _server(pdp)
    result = await _call(server, "stats", None)
    assert not result.is_error
    assert json.loads(_text(result)) == {"files": 3}


async def test_unregistered_tool_denied(pdp: PolicyDecisionPoint) -> None:
    server, _ = _server(pdp)
    result = await _call(server, "rm_rf", {"path": "workspace"})
    assert result.is_error
    assert re.fullmatch(r"denied \(ref [0-9a-f]{12}\)", _text(result))


async def test_tool_exception_reported_as_error(pdp: PolicyDecisionPoint) -> None:
    server, _ = _server(pdp)
    result = await _call(server, "explode", {"path": "workspace/x.py"})
    assert result.is_error
    assert _text(result) == "tool error: RuntimeError"


@pytest.mark.parametrize("resolver", [lambda ctx: 1 / 0, lambda ctx: "mcp-agent"])
async def test_principal_resolution_failure_denies(pdp: PolicyDecisionPoint, resolver: Any) -> None:
    server, calls = _server(pdp, resolver)
    result = await _call(server, "write_file", {"path": "workspace/x.py"})
    assert result.is_error
    assert _text(result) == "denied: principal could not be resolved"
    assert calls == []


def test_factory_rejects_non_dispatcher() -> None:
    with pytest.raises(TypeError):
        make_mcp_call_tool_handler("dispatcher", lambda ctx: AGENT)  # type: ignore[arg-type]
