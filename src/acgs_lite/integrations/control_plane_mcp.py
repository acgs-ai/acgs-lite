"""MCP adapter for the control-plane tool dispatcher.

Routes an MCP ``call_tool`` request through
:class:`acgs_lite.control_plane.GovernedToolDispatcher`, so every tool an
agent reaches over MCP passes the PDP and the immutable-core invariants.

Usage::

    from mcp.server import Server
    from acgs_lite.integrations.control_plane_mcp import make_mcp_call_tool_handler

    handler = make_mcp_call_tool_handler(dispatcher, resolve_principal)
    server = Server("governed-tools", on_list_tools=list_tools, on_call_tool=handler)

The handler signature matches the ``mcp`` low-level server used by
:mod:`acgs_lite.integrations.mcp_server`. A denial, an unresolvable principal
or a tool error is returned as ``CallToolResult(is_error=True)``; the tool is
never invoked on a denial, and the agent receives only
``denied (ref <decision_id[:12]>)``; the full reason is audited. MCP carries no approvers, so T3 tools are always
denied over this path.

Phase 6a: :func:`credential_principal_resolver` is the default resolver. It
reads the harness-issued credential from the request ``_meta`` (never from
tool arguments), verifies it, and derives the Principal from the verified
credential plus the identity directory; the handler then passes the same
credential to the dispatcher::

    resolver = credential_principal_resolver(control_plane.credentials)
    handler = make_mcp_call_tool_handler(control_plane.dispatcher, resolver)
    # client: await session.call_tool(name, args, meta={"acgs-credential": token})
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from acgs_lite.control_plane.credentials import CredentialIssuer
from acgs_lite.control_plane.dispatcher import GovernedToolDispatcher, ToolDenied
from acgs_lite.control_plane.principal import Principal

try:
    from mcp import types

    CONTROL_PLANE_MCP_AVAILABLE = True
except ImportError:
    CONTROL_PLANE_MCP_AVAILABLE = False

__all__ = [
    "CONTROL_PLANE_MCP_AVAILABLE",
    "DEFAULT_CREDENTIAL_META_KEY",
    "CredentialPrincipalResolver",
    "credential_principal_resolver",
    "make_mcp_call_tool_handler",
]

DEFAULT_CREDENTIAL_META_KEY = "acgs-credential"

logger = logging.getLogger(__name__)


def _error(text: str) -> Any:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


def _render(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, default=str, sort_keys=True)


class CredentialPrincipalResolver:
    """Resolve the Principal from a verified credential in the request meta."""

    def __init__(self, issuer: CredentialIssuer, meta_key: str) -> None:
        if type(issuer) is not CredentialIssuer or issuer.identity is None:
            raise TypeError("issuer must be a CredentialIssuer with an identity provider")
        if not isinstance(meta_key, str) or not meta_key:
            raise ValueError("meta_key must be a non-empty string")
        self._issuer = issuer
        self.meta_key = meta_key

    def token(self, ctx: Any) -> str:
        """The raw credential from ``ctx.meta`` (request ``_meta``)."""
        meta = getattr(ctx, "meta", None)
        token = meta.get(self.meta_key) if isinstance(meta, dict) else None
        if not isinstance(token, str):
            raise PermissionError("no credential in the request meta")
        return token

    def __call__(self, ctx: Any) -> Principal:
        credential = self._issuer.authenticate(self.token(ctx))
        identity = self._issuer.identity
        entry = None if identity is None else identity.lookup(credential.principal_id)
        if entry is None or entry.kind is not credential.kind:
            raise PermissionError("credential principal is not in the identity directory")
        if entry.system_id != credential.system_id:
            raise PermissionError("credential system_id differs from the directory")
        return entry.principal()


def credential_principal_resolver(
    issuer: CredentialIssuer, meta_key: str = DEFAULT_CREDENTIAL_META_KEY
) -> CredentialPrincipalResolver:
    """The default resolver: Principal from the verified credential in
    ``_meta[meta_key]`` plus the issuer's identity directory."""
    return CredentialPrincipalResolver(issuer, meta_key)


def make_mcp_call_tool_handler(
    dispatcher: GovernedToolDispatcher,
    principal_resolver: Callable[[Any], Principal],
) -> Callable[[Any, Any], Awaitable[Any]]:
    """Return an ``on_call_tool`` handler that dispatches through *dispatcher*.

    *principal_resolver* receives the MCP ``ServerRequestContext`` and must
    return a :class:`Principal` minted from the authenticated session -- never
    from tool arguments or other agent-controlled input. Any exception or
    other return value denies. With a :class:`CredentialPrincipalResolver`
    the same meta credential is also passed to the dispatcher.
    """
    if not CONTROL_PLANE_MCP_AVAILABLE:
        raise ImportError("mcp package is required. Install with: pip install acgs-lite[mcp]")
    if not isinstance(dispatcher, GovernedToolDispatcher):
        raise TypeError("dispatcher must be a GovernedToolDispatcher")

    async def call_tool(ctx: Any, params: Any) -> Any:
        try:
            principal = principal_resolver(ctx)
        except Exception as exc:
            logger.warning("control-plane MCP principal resolution failed: %s", type(exc).__name__)
            return _error("denied: principal could not be resolved")
        if not isinstance(principal, Principal):
            return _error("denied: principal could not be resolved")
        credential: str | None = None
        if isinstance(principal_resolver, CredentialPrincipalResolver):
            credential = principal_resolver.token(ctx)
        arguments = params.arguments if params.arguments is not None else {}
        try:
            result = await dispatcher.adispatch(
                principal, params.name, arguments, credential=credential
            )
        except ToolDenied as exc:
            # The agent learns only that it was denied and a reference; the
            # reason (which policy, which core path) goes to the audit log, so
            # the agent cannot probe the policy by reading denial texts.
            return _error(f"denied (ref {exc.ref})")
        except Exception as exc:
            logger.warning("control-plane MCP tool failed: %s", type(exc).__name__)
            return _error(f"tool error: {type(exc).__name__}")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=_render(result.value))],
            is_error=False,
        )

    return call_tool
