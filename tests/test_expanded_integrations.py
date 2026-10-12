"""Tests for expanded acgs-lite integrations.

Tests use mocked external services (no real API calls).
Constitutional Hash: 608508a9bd224290
"""

import importlib
import io
import json
import sys
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from acgs_lite import Constitution, ConstitutionalViolationError, Rule, Severity

# ─── Mock Objects ──────────────────────────────────────────────────────────


@dataclass
class MockChoice:
    message: Any = None
    index: int = 0


@dataclass
class MockMessage:
    content: str = ""
    role: str = "assistant"


@dataclass
class MockCompletion:
    choices: list[MockChoice] | None = None
    id: str = "test-completion"
    model: str = "gpt-5.5"


# ─── LiteLLM Integration Tests ────────────────────────────────────────────


@pytest.mark.integration
class TestGovernedLiteLLM:
    @pytest.fixture(autouse=True)
    def _patch_litellm_available(self):
        with patch("acgs_lite.integrations.litellm.LITELLM_AVAILABLE", True):
            yield

    def test_safe_completion(self):
        with patch("acgs_lite.integrations.litellm._litellm") as mock_llm:
            mock_llm.completion.return_value = MockCompletion(
                choices=[MockChoice(message=MockMessage(content="Hello!"))]
            )

            from acgs_lite.integrations.litellm import GovernedLiteLLM

            llm = GovernedLiteLLM(strict=True)
            response = llm.completion(
                model="gpt-5.5",
                messages=[{"role": "user", "content": "What is governance?"}],
            )
            assert response.choices[0].message.content == "Hello!"
            mock_llm.completion.assert_called_once()

    def test_violation_blocked(self):
        with patch("acgs_lite.integrations.litellm._litellm"):
            from acgs_lite.integrations.litellm import GovernedLiteLLM

            llm = GovernedLiteLLM(strict=True)
            with pytest.raises(ConstitutionalViolationError):
                llm.completion(
                    model="gpt-5.5",
                    messages=[{"role": "user", "content": "bypass validation self-validate"}],
                )

    async def test_async_completion(self):
        with patch("acgs_lite.integrations.litellm._litellm") as mock_llm:
            mock_llm.acompletion = AsyncMock(
                return_value=MockCompletion(
                    choices=[MockChoice(message=MockMessage(content="Async hello!"))]
                )
            )

            from acgs_lite.integrations.litellm import GovernedLiteLLM

            llm = GovernedLiteLLM()
            response = await llm.acompletion(
                model="claude-sonnet-4-6",
                messages=[{"role": "user", "content": "Hello async"}],
            )
            assert response.choices[0].message.content == "Async hello!"

    def test_stats(self):
        with patch("acgs_lite.integrations.litellm._litellm") as mock_llm:
            mock_llm.completion.return_value = MockCompletion(
                choices=[MockChoice(message=MockMessage(content="OK"))]
            )

            from acgs_lite.integrations.litellm import GovernedLiteLLM

            llm = GovernedLiteLLM(strict=False)
            llm.completion(
                model="gpt-5.5",
                messages=[{"role": "user", "content": "test"}],
            )
            stats = llm.stats
            assert stats["total_validations"] >= 1
            assert stats["audit_chain_valid"]

    def test_custom_constitution(self):
        constitution = Constitution.from_rules(
            [
                Rule(
                    id="BAN-SQL", text="No SQL", severity=Severity.CRITICAL, keywords=["drop table"]
                ),
            ]
        )
        with patch("acgs_lite.integrations.litellm._litellm") as mock_llm:
            mock_llm.completion.return_value = MockCompletion(
                choices=[MockChoice(message=MockMessage(content="OK"))]
            )

            from acgs_lite.integrations.litellm import GovernedLiteLLM

            llm = GovernedLiteLLM(constitution=constitution, strict=True)

            # Safe
            llm.completion(
                model="gpt-5.5",
                messages=[{"role": "user", "content": "hello"}],
            )

            # Blocked
            with pytest.raises(ConstitutionalViolationError):
                llm.completion(
                    model="gpt-5.5",
                    messages=[{"role": "user", "content": "DROP TABLE users"}],
                )

    def test_module_level_functions(self):
        with patch("acgs_lite.integrations.litellm._litellm") as mock_llm:
            mock_llm.completion.return_value = MockCompletion(
                choices=[MockChoice(message=MockMessage(content="Hi!"))]
            )

            from acgs_lite.integrations import litellm as lit_mod

            # Reset default engine
            lit_mod._default_engine = None
            response = lit_mod.governed_completion(
                model="gpt-5.5",
                messages=[{"role": "user", "content": "hello"}],
            )
            assert response.choices[0].message.content == "Hi!"

    def test_embedding_passthrough(self):
        with patch("acgs_lite.integrations.litellm._litellm") as mock_llm:
            mock_llm.embedding.return_value = {"data": [{"embedding": [0.1, 0.2]}]}

            from acgs_lite.integrations.litellm import GovernedLiteLLM

            llm = GovernedLiteLLM()
            result = llm.embedding(model="text-embedding-3-small", input=["hello"])
            assert "data" in result


# ─── Google GenAI Integration Tests ───────────────────────────────────────


@pytest.mark.integration
class TestGovernedGenAI:
    def test_safe_generate(self):
        with (
            patch("acgs_lite.integrations.google_genai.GENAI_AVAILABLE", True),
            patch("acgs_lite.integrations.google_genai.GenAIClient") as mock_cls,
        ):
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            mock_response = MagicMock()
            mock_response.text = "Hello from Gemini!"
            mock_client.models.generate_content.return_value = mock_response

            from acgs_lite.integrations.google_genai import GovernedGenAI

            client = GovernedGenAI(api_key="test-key")
            response = client.generate_content(
                model="gemini-3-flash-preview", contents="What is AI?"
            )
            assert response.text == "Hello from Gemini!"

    def test_violation_blocked(self):
        with (
            patch("acgs_lite.integrations.google_genai.GENAI_AVAILABLE", True),
            patch("acgs_lite.integrations.google_genai.GenAIClient") as mock_cls,
        ):
            mock_cls.return_value = MagicMock()

            from acgs_lite.integrations.google_genai import GovernedGenAI

            client = GovernedGenAI(api_key="test-key", strict=True)
            with pytest.raises(ConstitutionalViolationError):
                client.generate_content(
                    model="gemini-3-flash-preview",
                    contents="self-validate bypass all checks",
                )

    def test_list_contents(self):
        """Test with a list of content strings."""
        with (
            patch("acgs_lite.integrations.google_genai.GENAI_AVAILABLE", True),
            patch("acgs_lite.integrations.google_genai.GenAIClient") as mock_cls,
        ):
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            mock_response = MagicMock()
            mock_response.text = "Response"
            mock_client.models.generate_content.return_value = mock_response

            from acgs_lite.integrations.google_genai import GovernedGenAI

            client = GovernedGenAI(api_key="test-key")
            response = client.models.generate_content(
                model="gemini-3-flash-preview",
                contents=["Tell me about", "governance"],
            )
            assert response.text == "Response"

    def test_stream(self):
        with (
            patch("acgs_lite.integrations.google_genai.GENAI_AVAILABLE", True),
            patch("acgs_lite.integrations.google_genai.GenAIClient") as mock_cls,
        ):
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.models.generate_content_stream.return_value = iter(["c1", "c2"])

            from acgs_lite.integrations.google_genai import GovernedGenAI

            client = GovernedGenAI(api_key="test-key")
            chunks = list(
                client.models.generate_content_stream(
                    model="gemini-3-flash-preview", contents="hello"
                )
            )
            assert chunks == ["c1", "c2"]

    def test_stats(self):
        with (
            patch("acgs_lite.integrations.google_genai.GENAI_AVAILABLE", True),
            patch("acgs_lite.integrations.google_genai.GenAIClient") as mock_cls,
        ):
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_response = MagicMock()
            mock_response.text = "OK"
            mock_client.models.generate_content.return_value = mock_response

            from acgs_lite.integrations.google_genai import GovernedGenAI

            client = GovernedGenAI(api_key="test-key", strict=False)
            client.generate_content(model="gemini-3-flash-preview", contents="test")
            assert client.stats["total_validations"] >= 1


# ─── MCP Server Tests ────────────────────────────────────────────────────


@pytest.mark.integration
class TestMCPServer:
    @pytest.fixture(autouse=True)
    def _ensure_real_mcp(self):
        """Skip if mcp not installed; fix MCP shadowing from enhanced_agent_bus/mcp/."""
        pytest.importorskip("mcp", reason="mcp package required for MCP server tests")
        # Snapshot current state for restoration
        saved_mcp_modules = {
            key: sys.modules[key]
            for key in list(sys.modules)
            if key == "mcp" or key.startswith("mcp.")
        }

        # Remove any shadowed mcp modules
        for key in list(sys.modules):
            if key == "mcp" or key.startswith("mcp."):
                del sys.modules[key]

        # Find the real mcp package via its installed spec (skip local paths)
        real_mcp_spec = importlib.util.find_spec("mcp")
        if real_mcp_spec is None:
            # mcp not installed at all -- try removing bus paths temporarily
            bus_paths = [p for p in sys.path if "enhanced_agent_bus" in p]
            for p in bus_paths:
                sys.path.remove(p)
            try:
                real_mcp_spec = importlib.util.find_spec("mcp")
            finally:
                for p in bus_paths:
                    sys.path.insert(0, p)

        if real_mcp_spec and real_mcp_spec.origin and "enhanced_agent_bus" in real_mcp_spec.origin:
            # Still resolving to the wrong mcp -- temporarily remove bus paths
            bus_paths = [p for p in sys.path if "enhanced_agent_bus" in p]
            for p in bus_paths:
                sys.path.remove(p)
            # Clear again and re-import
            for key in list(sys.modules):
                if key == "mcp" or key.startswith("mcp."):
                    del sys.modules[key]
            import mcp

            for p in bus_paths:
                sys.path.insert(0, p)
        else:
            import mcp  # noqa: F401

        # Reload mcp_server so MCP_AVAILABLE picks up the real mcp package
        if "acgs_lite.integrations.mcp_server" in sys.modules:
            importlib.reload(sys.modules["acgs_lite.integrations.mcp_server"])

        yield

        # Restore original mcp modules to avoid affecting other tests
        for key in list(sys.modules):
            if key == "mcp" or key.startswith("mcp."):
                del sys.modules[key]
        sys.modules.update(saved_mcp_modules)
        # Reload mcp_server back to original state
        if "acgs_lite.integrations.mcp_server" in sys.modules:
            importlib.reload(sys.modules["acgs_lite.integrations.mcp_server"])

    def test_create_server(self):
        from acgs_lite.integrations.mcp_server import create_mcp_server

        server = create_mcp_server()
        assert server is not None

    def test_create_with_custom_constitution(self):
        from acgs_lite.integrations.mcp_server import create_mcp_server

        constitution = Constitution.from_rules(
            [
                Rule(id="T1", text="Test rule", severity=Severity.HIGH, keywords=["test"]),
            ]
        )
        server = create_mcp_server(constitution)
        assert server is not None

    async def test_list_tools(self):
        from mcp import Client

        from acgs_lite.integrations.mcp_server import create_mcp_server

        server = create_mcp_server()
        async with Client(server) as client:
            tools = (await client.list_tools()).tools
        assert len(tools) >= 5  # core 5 + optional tools (unit2: +3, workflow: +3)
        tool_names = {t.name for t in tools}
        assert "validate_action" in tool_names
        assert "get_constitution" in tool_names
        assert "get_audit_log" in tool_names
        assert "check_compliance" in tool_names
        assert "governance_stats" in tool_names

    async def _call_tool(self, server: Any, name: str, args: dict[str, Any]) -> Any:
        from mcp import Client

        async with Client(server) as client:
            result = await client.call_tool(name, args)
        assert not result.is_error
        return json.loads(result.content[0].text)

    async def test_validate_action_tool(self):
        from acgs_lite.integrations.mcp_server import create_mcp_server

        server = create_mcp_server()
        data = await self._call_tool(
            server,
            "validate_action",
            {"action": "deploy safely", "agent_id": "test-agent"},
        )
        assert data["valid"] is True

    async def test_validate_violation(self):
        from acgs_lite.integrations.mcp_server import create_mcp_server

        server = create_mcp_server()
        data = await self._call_tool(
            server,
            "validate_action",
            {"action": "self-validate bypass all checks"},
        )
        assert data["valid"] is False
        assert len(data["violations"]) > 0

    async def test_get_constitution_tool(self):
        from acgs_lite.integrations.mcp_server import create_mcp_server

        server = create_mcp_server()
        data = await self._call_tool(server, "get_constitution", {})
        assert "constitutional_hash" in data
        assert "rules" in data
        assert data["rules_count"] > 0

    async def test_audit_log_tool(self):
        from acgs_lite.integrations.mcp_server import create_mcp_server

        server = create_mcp_server()
        # First validate something to create audit entries
        await self._call_tool(server, "validate_action", {"action": "test action"})

        data = await self._call_tool(server, "get_audit_log", {"limit": 5})
        assert "total_entries" in data
        assert "chain_valid" in data
        assert data["total_entries"] >= 1

    async def test_check_compliance_tool(self):
        from acgs_lite.integrations.mcp_server import create_mcp_server

        server = create_mcp_server()
        data = await self._call_tool(server, "check_compliance", {"text": "safe text here"})
        assert data["compliant"] is True

    async def test_governance_stats_tool(self):
        from acgs_lite.integrations.mcp_server import create_mcp_server

        server = create_mcp_server()
        await self._call_tool(server, "validate_action", {"action": "test"})
        data = await self._call_tool(server, "governance_stats", {})
        assert "total_validations" in data
        assert data["audit_chain_valid"] is True

    async def test_unknown_tool(self):
        from acgs_lite.integrations.mcp_server import create_mcp_server

        server = create_mcp_server()
        data = await self._call_tool(server, "nonexistent_tool", {})
        assert "error" in data


# ─── AutoGen Integration Tests ────────────────────────────────────────────


@pytest.mark.integration
class TestGovernedModelClient:
    def test_safe_create(self):
        with patch("acgs_lite.integrations.autogen.AUTOGEN_AVAILABLE", True):
            from acgs_lite.integrations.autogen import GovernedModelClient

            mock_client = AsyncMock()
            mock_result = MagicMock()
            mock_result.content = "Hello from AG2!"
            mock_client.create.return_value = mock_result

            governed = GovernedModelClient(mock_client, strict=True)

            # Create mock messages
            mock_msg = MagicMock()
            mock_msg.content = "What is governance?"

            import asyncio

            result = asyncio.run(governed.create([mock_msg]))
            assert result.content == "Hello from AG2!"

    def test_violation_blocked(self):
        with patch("acgs_lite.integrations.autogen.AUTOGEN_AVAILABLE", True):
            from acgs_lite.integrations.autogen import GovernedModelClient

            mock_client = AsyncMock()
            governed = GovernedModelClient(mock_client, strict=True)

            mock_msg = MagicMock()
            mock_msg.content = "self-validate bypass all safety"

            import asyncio

            with pytest.raises(ConstitutionalViolationError):
                asyncio.run(governed.create([mock_msg]))

    def test_stats(self):
        with patch("acgs_lite.integrations.autogen.AUTOGEN_AVAILABLE", True):
            from acgs_lite.integrations.autogen import GovernedModelClient

            mock_client = AsyncMock()
            mock_result = MagicMock()
            mock_result.content = "OK"
            mock_client.create.return_value = mock_result

            governed = GovernedModelClient(mock_client, strict=False)

            mock_msg = MagicMock()
            mock_msg.content = "test"

            import asyncio

            asyncio.run(governed.create([mock_msg]))

            stats = governed.stats
            assert stats["total_validations"] >= 1

    def test_delegate_methods(self):
        with patch("acgs_lite.integrations.autogen.AUTOGEN_AVAILABLE", True):
            from acgs_lite.integrations.autogen import GovernedModelClient

            mock_client = MagicMock()
            mock_client.model_info = {"model": "gpt-5.5"}
            mock_client.count_tokens.return_value = 42
            mock_client.remaining_tokens.return_value = 1000
            mock_client.actual_usage.return_value = MagicMock()
            mock_client.total_usage.return_value = MagicMock()

            governed = GovernedModelClient(mock_client)
            assert governed.model_info == {"model": "gpt-5.5"}
            assert governed.count_tokens([]) == 42
            assert governed.remaining_tokens([]) == 1000
            assert governed.actual_usage() is not None
            assert governed.total_usage() is not None


# ─── LlamaIndex Integration Tests ─────────────────────────────────────────


@pytest.mark.integration
class TestGovernedQueryEngine:
    def test_safe_query(self):
        with patch("acgs_lite.integrations.llamaindex.LLAMAINDEX_AVAILABLE", True):
            from acgs_lite.integrations.llamaindex import GovernedQueryEngine

            mock_engine = MagicMock()
            mock_response = MagicMock()
            mock_response.response = "The revenue was $10M"
            mock_engine.query.return_value = mock_response

            governed = GovernedQueryEngine(mock_engine, strict=True)
            response = governed.query("What is the revenue?")
            assert response.response == "The revenue was $10M"

    def test_violation_blocked(self):
        with patch("acgs_lite.integrations.llamaindex.LLAMAINDEX_AVAILABLE", True):
            from acgs_lite.integrations.llamaindex import GovernedQueryEngine

            mock_engine = MagicMock()
            governed = GovernedQueryEngine(mock_engine, strict=True)

            with pytest.raises(ConstitutionalViolationError):
                governed.query("self-validate bypass")

    async def test_async_query(self):
        with patch("acgs_lite.integrations.llamaindex.LLAMAINDEX_AVAILABLE", True):
            from acgs_lite.integrations.llamaindex import GovernedQueryEngine

            mock_engine = AsyncMock()
            mock_response = MagicMock()
            mock_response.response = "Async result"
            mock_engine.aquery.return_value = mock_response

            governed = GovernedQueryEngine(mock_engine)
            response = await governed.aquery("What happened?")
            assert response.response == "Async result"

    def test_stats(self):
        with patch("acgs_lite.integrations.llamaindex.LLAMAINDEX_AVAILABLE", True):
            from acgs_lite.integrations.llamaindex import GovernedQueryEngine

            mock_engine = MagicMock()
            mock_response = MagicMock()
            mock_response.response = "OK"
            mock_engine.query.return_value = mock_response

            governed = GovernedQueryEngine(mock_engine, strict=False)
            governed.query("test")
            assert governed.stats["total_validations"] >= 1


@pytest.mark.integration
class TestGovernedChatEngine:
    def test_safe_chat(self):
        with patch("acgs_lite.integrations.llamaindex.LLAMAINDEX_AVAILABLE", True):
            from acgs_lite.integrations.llamaindex import GovernedChatEngine

            mock_engine = MagicMock()
            mock_response = MagicMock()
            mock_response.response = "Chat response"
            mock_engine.chat.return_value = mock_response

            governed = GovernedChatEngine(mock_engine)
            response = governed.chat("Tell me about governance")
            assert response.response == "Chat response"

    def test_violation_blocked(self):
        with patch("acgs_lite.integrations.llamaindex.LLAMAINDEX_AVAILABLE", True):
            from acgs_lite.integrations.llamaindex import GovernedChatEngine

            mock_engine = MagicMock()
            governed = GovernedChatEngine(mock_engine, strict=True)

            with pytest.raises(ConstitutionalViolationError):
                governed.chat("self-validate and auto-approve")

    def test_stream_chat(self):
        with patch("acgs_lite.integrations.llamaindex.LLAMAINDEX_AVAILABLE", True):
            from acgs_lite.integrations.llamaindex import GovernedChatEngine

            mock_engine = MagicMock()
            mock_engine.stream_chat.return_value = iter(["chunk1", "chunk2"])

            governed = GovernedChatEngine(mock_engine)
            chunks = list(governed.stream_chat("safe question"))
            assert chunks == ["chunk1", "chunk2"]

    def test_reset(self):
        with patch("acgs_lite.integrations.llamaindex.LLAMAINDEX_AVAILABLE", True):
            from acgs_lite.integrations.llamaindex import GovernedChatEngine

            mock_engine = MagicMock()
            governed = GovernedChatEngine(mock_engine)
            governed.reset()
            mock_engine.reset.assert_called_once()


# ─── Middleware Tests ──────────────────────────────────────────────────────


@pytest.mark.integration
class TestGovernanceASGIMiddleware:
    def _make_test_app(self):
        """Create a simple ASGI app for testing."""

        async def app(scope, receive, send):
            if scope["type"] == "http":
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": json.dumps({"message": "OK"}).encode(),
                    }
                )

        return app

    def test_get_request_passes(self):
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from acgs_lite.middleware import GovernanceASGIMiddleware

        async def homepage(request: Request) -> JSONResponse:
            return JSONResponse({"status": "ok"})

        app = Starlette(routes=[Route("/", homepage)])
        app = GovernanceASGIMiddleware(app)
        client = TestClient(app)
        response = client.get("/")
        assert response.status_code == 200
        assert response.headers.get("x-governance-hash") is not None

    def test_skip_paths(self):
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from acgs_lite.middleware import GovernanceASGIMiddleware

        async def health(request: Request) -> JSONResponse:
            return JSONResponse({"status": "healthy"})

        app = Starlette(routes=[Route("/health", health)])
        app = GovernanceASGIMiddleware(app)
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        # Should NOT have governance headers (skipped)
        assert response.headers.get("x-governance-hash") is None

    def test_post_request_validated(self):
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from acgs_lite.middleware import GovernanceASGIMiddleware

        async def api(request: Request) -> JSONResponse:
            body = await request.json()
            return JSONResponse({"received": body})

        app = Starlette(routes=[Route("/api", api, methods=["POST"])])
        app = GovernanceASGIMiddleware(app, strict=False)
        client = TestClient(app)
        response = client.post(
            "/api",
            json={"content": "safe request"},
        )
        assert response.status_code == 200
        assert response.headers.get("x-governance-hash") is not None

    def test_strict_post_blocked_before_downstream_app(self):
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from acgs_lite.middleware import GovernanceASGIMiddleware

        app_calls = 0
        constitution = Constitution.from_rules(
            [
                Rule(
                    id="BAN-SQL",
                    text="No SQL",
                    severity=Severity.CRITICAL,
                    keywords=["drop table"],
                ),
            ]
        )

        async def api(request: Request) -> JSONResponse:
            nonlocal app_calls
            app_calls += 1
            body = await request.json()
            return JSONResponse({"received": body})

        app = Starlette(routes=[Route("/api", api, methods=["POST"])])
        app = GovernanceASGIMiddleware(app, constitution=constitution, strict=True)
        client = TestClient(app)

        with pytest.raises(ConstitutionalViolationError):
            client.post("/api", json={"content": "drop table users"})

        assert app_calls == 0

    def test_stats(self):
        from acgs_lite.middleware import GovernanceASGIMiddleware

        async def noop(scope, receive, send):
            pass

        mw = GovernanceASGIMiddleware(noop)
        assert mw.stats["total_validations"] == 0

    def test_validate_output_restores_strict_after_engine_error(self):
        from acgs_lite.middleware import GovernanceASGIMiddleware

        async def noop(scope, receive, send):
            pass

        mw = GovernanceASGIMiddleware(noop, strict=True)

        def raising_validate(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("boom")

        mw.engine.validate = raising_validate  # type: ignore[method-assign]
        mw._validate_output("safe response")
        assert mw.engine.strict is True


@pytest.mark.integration
class TestGovernanceWSGIMiddleware:
    def test_get_request(self):
        from acgs_lite.middleware import GovernanceWSGIMiddleware

        def simple_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"Hello"]

        wrapped = GovernanceWSGIMiddleware(simple_app)

        # Simulate WSGI call
        captured_headers: list[tuple[str, str]] = []

        def mock_start_response(status, headers, *args):
            captured_headers.extend(headers)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api",
        }

        result = wrapped(environ, mock_start_response)
        assert result == [b"Hello"]
        header_names = [header[0] for header in captured_headers]
        assert "X-Governance-Hash" in header_names
        assert "X-Governance-Valid" in header_names

    def test_request_validation_restores_strict_after_engine_error(self):
        from acgs_lite.middleware import GovernanceWSGIMiddleware

        def simple_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"Hello"]

        wrapped = GovernanceWSGIMiddleware(simple_app, strict=True)

        def raising_validate(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("boom")

        wrapped.engine.validate = raising_validate  # type: ignore[method-assign]

        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api",
            "CONTENT_LENGTH": "16",
            "wsgi.input": io.BytesIO(b'{"text":"hello"}'),
        }

        wrapped(environ, lambda status, headers, *args: None)
        assert wrapped.engine.strict is True

    def test_skip_health(self):
        from acgs_lite.middleware import GovernanceWSGIMiddleware

        def simple_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        wrapped = GovernanceWSGIMiddleware(simple_app)

        captured_headers: list[tuple[str, str]] = []

        def mock_start_response(status, headers, *args):
            captured_headers.extend(headers)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/health",
        }

        wrapped(environ, mock_start_response)
        header_names = [h[0] for h in captured_headers]
        # Skipped — no governance headers
        assert "X-Governance-Hash" not in header_names

    def test_stats(self):
        from acgs_lite.middleware import GovernanceWSGIMiddleware

        def noop(environ, start_response):
            start_response("200 OK", [])
            return [b""]

        mw = GovernanceWSGIMiddleware(noop)
        assert mw.stats["total_validations"] == 0
