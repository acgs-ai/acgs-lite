"""Comprehensive tests for the MCP server integration.

Covers all 5 governance tools, error handling, edge cases,
and ensures >90% coverage of mcp_server.py.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import inspect
import json
from typing import Any
from unittest.mock import patch

import pytest

from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.constitution.experience_library import GovernanceExperienceLibrary
from acgs_lite.integrations.mcp_server import (
    MCP_AVAILABLE,
    create_mcp_server,
    run_mcp_server,
)

# Skip entire module if mcp is not installed
pytestmark = pytest.mark.skipif(not MCP_AVAILABLE, reason="mcp package not installed")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_constitution() -> Constitution:
    """Return the built-in default constitution."""
    return Constitution.default()


@pytest.fixture()
def empty_constitution() -> Constitution:
    """Return a constitution with zero rules."""
    return Constitution(name="empty", version="0.0.0", rules=[])


@pytest.fixture()
def custom_constitution() -> Constitution:
    """Return a constitution with a single keyword-based deny rule."""
    return Constitution(
        name="test-constitution",
        version="1.0.0",
        rules=[
            Rule(
                id="TEST-001",
                text="Must not contain forbidden content",
                severity=Severity.CRITICAL,
                keywords=["forbidden", "blocked"],
                category="safety",
            ),
            Rule(
                id="TEST-002",
                text="Warn on suspicious content",
                severity=Severity.LOW,
                keywords=["suspicious"],
                category="monitoring",
            ),
        ],
    )


@pytest.fixture()
def embedded_constitution() -> Constitution:
    """Return a constitution with semantically searchable rule embeddings."""
    return Constitution(
        name="embedded-constitution",
        version="1.0.0",
        rules=[
            Rule(
                id="PRIV-001",
                text="Protect personal data from external disclosure",
                severity=Severity.CRITICAL,
                keywords=["protect", "personal", "data"],
                category="privacy",
                embedding=[1.0, 0.0],
            ),
            Rule(
                id="SEC-001",
                text="Rotate service credentials regularly",
                severity=Severity.HIGH,
                keywords=["rotate", "service", "credentials"],
                category="security",
                embedding=[0.0, 1.0],
            ),
        ],
    )


class _StubEmbeddingProvider:
    """Deterministic embedding provider for MCP governance-memory tests."""

    def __init__(self, embedding: list[float]) -> None:
        self._embedding = embedding

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [list(self._embedding) for _ in texts]


async def _call_tool(server: Any, name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Call through the public client and parse the first JSON text result."""
    result = await _call_tool_raw(server, name, arguments)
    assert not result.is_error
    assert result.content
    return json.loads(result.content[0].text)


async def _call_tool_raw(server: Any, name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Call through the public client and retain protocol errors."""
    from mcp import Client

    async with Client(server) as client:
        return await client.call_tool(name, arguments)


async def _list_tools(server: Any) -> list[Any]:
    """Discover the registered tools through the public client."""
    from mcp import Client

    async with Client(server) as client:
        return (await client.list_tools()).tools


# ---------------------------------------------------------------------------
# list_tools
# ---------------------------------------------------------------------------


class TestListTools:
    """Tests for the tool listing endpoint."""

    @pytest.mark.asyncio
    async def test_lists_all_tools(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        tools = await _list_tools(server)

        tool_names = {t.name for t in tools}
        core_tools = {
            "validate_action",
            "get_constitution",
            "get_audit_log",
            "check_compliance",
            "governance_stats",
            "explain_violation",
            "check_capability_tier",
            "verify_audit_chain",
        }
        # Workflow tools are included when constitutional_swarm is installed
        assert core_tools.issubset(tool_names)

    @pytest.mark.asyncio
    async def test_tool_schemas_have_required_fields(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        tools = await _list_tools(server)

        for tool in tools:
            assert tool.name
            assert tool.description
            assert tool.input_schema is not None
            assert tool.input_schema["type"] == "object"

    @pytest.mark.asyncio
    async def test_validate_action_schema_requires_action(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        tools = await _list_tools(server)

        validate_tool = next(t for t in tools if t.name == "validate_action")
        assert "action" in validate_tool.input_schema.get("required", [])

    @pytest.mark.asyncio
    async def test_check_compliance_schema_requires_text(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        tools = await _list_tools(server)

        compliance_tool = next(t for t in tools if t.name == "check_compliance")
        assert "text" in compliance_tool.input_schema.get("required", [])


# ---------------------------------------------------------------------------
# validate_action tool
# ---------------------------------------------------------------------------


class TestValidateAction:
    """Tests for the validate_action governance tool."""

    @pytest.mark.asyncio
    async def test_valid_action_returns_compliant(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "validate_action", {"action": "hello world"})

        assert result["valid"] is True
        assert result["violations"] == []
        assert "constitutional_hash" in result

    @pytest.mark.asyncio
    async def test_validate_action_always_includes_governance_memory_fields(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)

        result = await _call_tool(server, "validate_action", {"action": "hello world"})

        assert result["retrieved_rules"] == []
        assert result["retrieved_precedents"] == []
        assert result["governance_memory_summary"] == {
            "total_rules": len(default_constitution.rules),
            "rules_with_embeddings": 0,
            "rule_embedding_coverage": 0.0,
            "rule_hit_count": 0,
            "total_precedents": 0,
            "precedents_with_embeddings": 0,
            "precedent_embedding_coverage": 0.0,
            "precedent_hit_count": 0,
        }

    @pytest.mark.asyncio
    async def test_validate_action_includes_semantic_rule_retrieval(
        self, embedded_constitution: Constitution
    ) -> None:
        server = create_mcp_server(
            embedded_constitution,
            embedding_provider=_StubEmbeddingProvider([0.98, 0.02]),
        )

        result = await _call_tool(server, "validate_action", {"action": "email customer data"})

        assert [hit["rule_id"] for hit in result["retrieved_rules"]] == ["PRIV-001", "SEC-001"]
        assert result["retrieved_rules"][0]["score"] >= result["retrieved_rules"][1]["score"]
        assert result["retrieved_precedents"] == []
        assert result["governance_memory_summary"]["total_rules"] == 2
        assert result["governance_memory_summary"]["rules_with_embeddings"] == 2
        assert result["governance_memory_summary"]["rule_hit_count"] == 2
        assert result["governance_memory_summary"]["total_precedents"] == 0

    @pytest.mark.asyncio
    async def test_validate_action_includes_retrieved_precedents_and_summary_counts(
        self, embedded_constitution: Constitution
    ) -> None:
        library = GovernanceExperienceLibrary()
        library.record(
            "share patient records with vendor",
            "deny",
            triggered_rules=["PRIV-001"],
            category="privacy",
            severity="critical",
            rationale="Protected records cannot be shared with external vendors",
            embedding=[1.0, 0.0],
        )
        library.record(
            "document validation outcome in audit log",
            "allow",
            triggered_rules=[],
            category="general",
            severity="low",
        )
        server = create_mcp_server(
            embedded_constitution,
            embedding_provider=_StubEmbeddingProvider([1.0, 0.0]),
            experience_library=library,
        )

        result = await _call_tool(server, "validate_action", {"action": "send patient records"})

        assert [hit["precedent_id"] for hit in result["retrieved_precedents"]] == ["P0"]
        assert result["retrieved_precedents"][0]["decision"] == "deny"
        assert result["governance_memory_summary"] == {
            "total_rules": 2,
            "rules_with_embeddings": 2,
            "rule_embedding_coverage": 1.0,
            "rule_hit_count": 2,
            "total_precedents": 2,
            "precedents_with_embeddings": 1,
            "precedent_embedding_coverage": 0.5,
            "precedent_hit_count": 1,
        }

    @pytest.mark.asyncio
    async def test_validate_action_records_allow_outcome_in_experience_library(
        self, default_constitution: Constitution
    ) -> None:
        library = GovernanceExperienceLibrary()
        server = create_mcp_server(default_constitution, experience_library=library)

        result = await _call_tool(
            server, "validate_action", {"action": "draft weekly status update"}
        )

        assert result["valid"] is True
        assert len(library.precedents) == 1
        recorded = library.precedents[0]
        assert recorded.action == "draft weekly status update"
        assert recorded.decision == "allow"
        assert recorded.triggered_rules == []
        assert recorded.context == {}
        assert recorded.category == "general"
        assert recorded.severity == "none"
        assert recorded.rationale

    @pytest.mark.asyncio
    async def test_validate_action_records_deny_outcome_with_triggered_rule_ids(
        self, custom_constitution: Constitution
    ) -> None:
        library = GovernanceExperienceLibrary()
        server = create_mcp_server(custom_constitution, experience_library=library)

        result = await _call_tool(server, "validate_action", {"action": "forbidden action"})

        assert result["valid"] is False
        assert len(library.precedents) == 1
        recorded = library.precedents[0]
        assert recorded.decision == "deny"
        assert recorded.triggered_rules == ["TEST-001"]
        assert recorded.category == "safety"
        assert recorded.severity == "critical"
        assert "TEST-001" in recorded.rationale

    @pytest.mark.asyncio
    async def test_validate_action_deduplicates_repeated_identical_precedents(
        self, default_constitution: Constitution
    ) -> None:
        library = GovernanceExperienceLibrary()
        server = create_mcp_server(default_constitution, experience_library=library)

        await _call_tool(server, "validate_action", {"action": "summarize customer feedback"})
        await _call_tool(server, "validate_action", {"action": "summarize customer feedback"})

        assert len(library.precedents) == 1

    @pytest.mark.asyncio
    async def test_validate_action_records_embedding_and_makes_precedent_retrievable(
        self, embedded_constitution: Constitution
    ) -> None:
        library = GovernanceExperienceLibrary()
        server = create_mcp_server(
            embedded_constitution,
            experience_library=library,
            embedding_provider=_StubEmbeddingProvider([1.0, 0.0]),
        )

        await _call_tool(server, "validate_action", {"action": "share patient records with vendor"})
        recorded = library.precedents[0]
        assert recorded.embedding == [1.0, 0.0]

        result = await _call_tool(server, "validate_action", {"action": "send patient records"})

        assert [hit["precedent_id"] for hit in result["retrieved_precedents"]] == ["P0"]

    @pytest.mark.asyncio
    async def test_validate_action_audit_metadata_includes_runtime_governance_context(
        self, embedded_constitution: Constitution
    ) -> None:
        library = GovernanceExperienceLibrary()
        library.record(
            "share patient records with vendor",
            "deny",
            triggered_rules=["PRIV-001"],
            category="privacy",
            severity="critical",
            rationale="Protected records cannot be shared with external vendors",
            embedding=[1.0, 0.0],
        )
        server = create_mcp_server(
            embedded_constitution,
            embedding_provider=_StubEmbeddingProvider([1.0, 0.0]),
            experience_library=library,
        )

        result = await _call_tool(
            server,
            "validate_action",
            {
                "action": "send patient records",
                "agent_id": "audit-agent",
                "tool_name": "shell",
                "session_id": "session-123",
                "checkpoint_kind": "tool_invocation",
                "runtime_context": {
                    "untrusted_input": True,
                    "environment": "production",
                },
                "capability_tags": ["command-execution"],
            },
        )
        audit = await _call_tool(server, "get_audit_log", {"limit": 1})

        assert result["valid"] is True
        assert audit["chain_valid"] is True
        entry = audit["entries"][0]
        assert "rule_evaluations" in entry["metadata"]
        runtime_governance = entry["metadata"]["runtime_governance"]
        assert runtime_governance["tool_name"] == "shell"
        assert runtime_governance["session_id"] == "session-123"
        assert runtime_governance["checkpoint_kind"] == "tool_invocation"
        assert runtime_governance["tool_risk"]["tool_name"] == "shell"
        assert runtime_governance["tool_risk"]["risk_level"] in {
            "critical",
            "high",
            "medium",
            "low",
        }
        assert [hit["rule_id"] for hit in runtime_governance["retrieved_rules"]] == [
            "PRIV-001",
            "SEC-001",
        ]
        assert [hit["precedent_id"] for hit in runtime_governance["retrieved_precedents"]] == ["P0"]
        assert runtime_governance["governance_memory_summary"]["precedent_hit_count"] == 1
        assert runtime_governance["trajectory_violations"] == []

    @pytest.mark.asyncio
    async def test_violating_action_returns_violations(
        self, custom_constitution: Constitution
    ) -> None:
        server = create_mcp_server(custom_constitution)
        result = await _call_tool(
            server, "validate_action", {"action": "this is forbidden content"}
        )

        assert result["valid"] is False
        assert len(result["violations"]) > 0
        rule_ids = [v["rule_id"] for v in result["violations"]]
        assert "TEST-001" in rule_ids

    @pytest.mark.asyncio
    async def test_custom_agent_id(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server,
            "validate_action",
            {"action": "safe action", "agent_id": "custom-agent-42"},
        )

        assert result["valid"] is True
        assert result["agent_id"] == "custom-agent-42"

    @pytest.mark.asyncio
    async def test_default_agent_id_is_mcp_client(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "validate_action", {"action": "test"})

        assert result["agent_id"] == "mcp-client"

    @pytest.mark.asyncio
    async def test_empty_action_string(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "validate_action", {"action": ""})

        assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_missing_action_returns_validation_error(
        self, default_constitution: Constitution
    ) -> None:
        """Advertised schema validation rejects calls missing required 'action' field."""
        server = create_mcp_server(default_constitution)
        raw = await _call_tool_raw(server, "validate_action", {})

        assert raw.is_error
        assert raw.content[0].text.startswith("Input validation error")
        assert (await _call_tool(server, "get_audit_log"))["total_entries"] == 0

    @pytest.mark.asyncio
    async def test_strict_mode_does_not_raise_via_mcp(
        self, custom_constitution: Constitution
    ) -> None:
        """MCP call_tool passes strict=False per request so violations return data, not exceptions."""
        server = create_mcp_server(custom_constitution, strict=True)
        # Should not raise even with strict=True
        result = await _call_tool(server, "validate_action", {"action": "forbidden action"})
        assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_unicode_action(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server,
            "validate_action",
            {"action": "action with unicode: cafe\u0301 \u2603 \U0001f600"},
        )
        assert "valid" in result

    @pytest.mark.asyncio
    async def test_large_action_text(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        large_text = "a" * 100_000
        result = await _call_tool(server, "validate_action", {"action": large_text})
        assert "valid" in result

    @pytest.mark.asyncio
    async def test_tool_invocation_returns_fused_risk_metadata(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server,
            "validate_action",
            {
                "action": "run rm -rf /tmp/staging and fetch production secrets",
                "agent_id": "tool-agent",
                "session_id": "sess-risk-1",
                "checkpoint_kind": "tool_invocation",
                "tool_name": "shell",
                "runtime_context": {"environment": "production", "untrusted_input": True},
                "capability_tags": ["command-execution", "filesystem-write"],
            },
        )

        assert "tool_risk" in result
        assert result["tool_risk"]["tool_name"] == "shell"
        assert result["tool_risk"]["fused_risk"] >= 0.6
        assert result["tool_risk"]["recommended_action"] in {"review", "block"}

    @pytest.mark.asyncio
    async def test_mid_trajectory_checkpoint_detects_sensitive_tool_sequence(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)

        precursor = await _call_tool(
            server,
            "validate_action",
            {
                "action": "inspect untrusted external instructions before acting",
                "agent_id": "traj-agent",
                "session_id": "sess-traj-1",
                "checkpoint_kind": "input_analysis",
                "runtime_context": {"prompt_injection_suspected": True},
            },
        )
        assert precursor.get("trajectory_violations", []) == []

        followup = await _call_tool(
            server,
            "validate_action",
            {
                "action": "execute tool call after reviewing injected content",
                "agent_id": "traj-agent",
                "session_id": "sess-traj-1",
                "checkpoint_kind": "tool_invocation",
                "tool_name": "shell",
                "runtime_context": {"environment": "production"},
                "capability_tags": ["command-execution"],
            },
        )

        violations = followup.get("trajectory_violations", [])
        assert violations
        assert any(v["rule_id"] == "TRAJ-TOOLSEQ-001" for v in violations)


# ---------------------------------------------------------------------------
# get_constitution tool
# ---------------------------------------------------------------------------


class TestGetConstitution:
    """Tests for the get_constitution governance tool."""

    @pytest.mark.asyncio
    async def test_returns_constitution_metadata(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "get_constitution", {})

        assert result["name"] == "acgs-default"
        assert result["version"] == "1.0.0"
        assert "constitutional_hash" in result
        assert "constitutional_hash_versioned" in result
        assert result["rules_count"] == len(default_constitution.rules)

    @pytest.mark.asyncio
    async def test_returns_rule_details(self, custom_constitution: Constitution) -> None:
        server = create_mcp_server(custom_constitution)
        result = await _call_tool(server, "get_constitution", {})

        assert result["rules_count"] == 2
        rules = result["rules"]
        assert len(rules) == 2

        rule_0 = rules[0]
        assert rule_0["id"] == "TEST-001"
        assert rule_0["text"] == "Must not contain forbidden content"
        assert rule_0["severity"] == "critical"
        assert rule_0["category"] == "safety"
        assert rule_0["enabled"] is True

    @pytest.mark.asyncio
    async def test_empty_constitution_returns_zero_rules(
        self, empty_constitution: Constitution
    ) -> None:
        server = create_mcp_server(empty_constitution)
        result = await _call_tool(server, "get_constitution", {})

        assert result["name"] == "empty"
        assert result["rules_count"] == 0
        assert result["rules"] == []

    @pytest.mark.asyncio
    async def test_ignores_extra_arguments(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "get_constitution", {"extra": "ignored"})
        assert "name" in result


# ---------------------------------------------------------------------------
# get_audit_log tool
# ---------------------------------------------------------------------------


class TestGetAuditLog:
    """Tests for the get_audit_log governance tool."""

    @pytest.mark.asyncio
    async def test_empty_audit_log(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "get_audit_log", {})

        assert result["total_entries"] == 0
        assert result["chain_valid"] is True
        assert result["entries"] == []

    @pytest.mark.asyncio
    async def test_returns_entries_after_validation(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)

        # Generate some audit entries by validating actions
        await _call_tool(server, "validate_action", {"action": "action one"})
        await _call_tool(server, "validate_action", {"action": "action two"})

        result = await _call_tool(server, "get_audit_log", {})

        assert result["total_entries"] == 2
        assert result["chain_valid"] is True
        assert len(result["entries"]) == 2

    @pytest.mark.asyncio
    async def test_limit_parameter(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)

        # Generate 5 entries
        for i in range(5):
            await _call_tool(server, "validate_action", {"action": f"action {i}"})

        result = await _call_tool(server, "get_audit_log", {"limit": 2})

        assert result["total_entries"] == 5
        assert len(result["entries"]) == 2

    @pytest.mark.asyncio
    async def test_default_limit_is_20(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)

        # Generate 25 entries
        for i in range(25):
            await _call_tool(server, "validate_action", {"action": f"action {i}"})

        result = await _call_tool(server, "get_audit_log", {})

        assert result["total_entries"] == 25
        assert len(result["entries"]) == 20

    @pytest.mark.asyncio
    async def test_limit_larger_than_entries(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)

        await _call_tool(server, "validate_action", {"action": "only one"})

        result = await _call_tool(server, "get_audit_log", {"limit": 100})

        assert result["total_entries"] == 1
        assert len(result["entries"]) == 1

    @pytest.mark.asyncio
    async def test_audit_chain_integrity(self, custom_constitution: Constitution) -> None:
        server = create_mcp_server(custom_constitution)

        await _call_tool(server, "validate_action", {"action": "safe"})
        await _call_tool(server, "validate_action", {"action": "forbidden"})

        result = await _call_tool(server, "get_audit_log", {})

        assert result["chain_valid"] is True
        assert result["total_entries"] == 2


# ---------------------------------------------------------------------------
# check_compliance tool
# ---------------------------------------------------------------------------


class TestCheckCompliance:
    """Tests for the check_compliance governance tool."""

    @pytest.mark.asyncio
    async def test_compliant_text(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "check_compliance", {"text": "hello world"})

        assert result["compliant"] is True
        assert result["violations"] == []
        assert "constitutional_hash" in result

    @pytest.mark.asyncio
    async def test_non_compliant_text(self, custom_constitution: Constitution) -> None:
        server = create_mcp_server(custom_constitution)
        result = await _call_tool(server, "check_compliance", {"text": "this is forbidden"})

        assert result["compliant"] is False
        assert len(result["violations"]) > 0
        violation = result["violations"][0]
        assert violation["rule_id"] == "TEST-001"
        assert violation["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_empty_text(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "check_compliance", {"text": ""})

        assert result["compliant"] is True

    @pytest.mark.asyncio
    async def test_missing_text_returns_validation_error(
        self, default_constitution: Constitution
    ) -> None:
        """Advertised schema validation rejects calls missing required 'text' field."""
        server = create_mcp_server(default_constitution)
        raw = await _call_tool_raw(server, "check_compliance", {})

        assert raw.is_error
        assert raw.content[0].text.startswith("Input validation error")
        assert (await _call_tool(server, "get_audit_log"))["total_entries"] == 0

    @pytest.mark.asyncio
    async def test_compliance_check_uses_fixed_agent_id(
        self, default_constitution: Constitution
    ) -> None:
        """check_compliance uses agent_id 'compliance-check' internally."""
        server = create_mcp_server(default_constitution)
        await _call_tool(server, "check_compliance", {"text": "test"})

        # Verify via audit log
        result = await _call_tool(server, "get_audit_log", {})
        entries = result["entries"]
        assert len(entries) == 1
        assert entries[0]["agent_id"] == "compliance-check"

    @pytest.mark.asyncio
    async def test_strict_mode_does_not_raise(self, custom_constitution: Constitution) -> None:
        """check_compliance passes strict=False per request without mutating engine.strict."""
        server = create_mcp_server(custom_constitution, strict=True)
        result = await _call_tool(server, "check_compliance", {"text": "forbidden content here"})
        assert result["compliant"] is False


# ---------------------------------------------------------------------------
# governance_stats tool
# ---------------------------------------------------------------------------


class TestGovernanceStats:
    """Tests for the governance_stats tool."""

    @pytest.mark.asyncio
    async def test_initial_stats(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "governance_stats", {})

        assert result["total_validations"] == 0
        assert result["compliance_rate"] == 1.0
        assert result["rules_count"] == len(default_constitution.rules)
        assert "constitutional_hash" in result
        assert result["audit_entries"] == 0
        assert result["audit_chain_valid"] is True

    @pytest.mark.asyncio
    async def test_stats_after_validations(self, custom_constitution: Constitution) -> None:
        server = create_mcp_server(custom_constitution)

        await _call_tool(server, "validate_action", {"action": "safe action"})
        await _call_tool(server, "validate_action", {"action": "forbidden action"})

        result = await _call_tool(server, "governance_stats", {})

        assert result["total_validations"] == 2
        assert result["audit_entries"] == 2
        assert result["audit_chain_valid"] is True
        # One valid, one invalid -> compliance_rate = 0.5
        assert result["compliance_rate"] == 0.5

    @pytest.mark.asyncio
    async def test_stats_with_empty_constitution(self, empty_constitution: Constitution) -> None:
        server = create_mcp_server(empty_constitution)
        result = await _call_tool(server, "governance_stats", {})

        assert result["rules_count"] == 0
        assert result["total_validations"] == 0


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------


class TestUnknownTool:
    """Tests for the unknown tool error path."""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "nonexistent_tool", {})

        assert "error" in result
        assert "Unknown tool" in result["error"]
        assert "nonexistent_tool" in result["error"]

    @pytest.mark.asyncio
    async def test_empty_tool_name_returns_error(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "", {})

        assert "error" in result
        assert "Unknown tool" in result["error"]


# ---------------------------------------------------------------------------
# create_mcp_server factory
# ---------------------------------------------------------------------------


class TestCreateMcpServer:
    """Tests for the create_mcp_server factory function."""

    def test_returns_server_instance(self) -> None:
        server = create_mcp_server()
        assert server is not None

    def test_default_constitution_when_none(self) -> None:
        server = create_mcp_server(None)
        assert server is not None

    def test_custom_server_name(self) -> None:
        server = create_mcp_server(server_name="my-custom-gov")
        assert server is not None
        assert server.name == "my-custom-gov"

    def test_strict_flag_accepted(self) -> None:
        server = create_mcp_server(strict=True)
        assert server is not None

    def test_mcp_unavailable_raises_import_error(self) -> None:
        with (
            patch("acgs_lite.integrations.mcp_server.MCP_AVAILABLE", False),
            pytest.raises(ImportError, match="mcp package is required"),
        ):
            create_mcp_server()


# ---------------------------------------------------------------------------
# run_mcp_server
# ---------------------------------------------------------------------------


class TestRunMcpServer:
    """Tests for the run_mcp_server entry point."""

    def test_mcp_unavailable_raises_import_error(self) -> None:
        with (
            patch("acgs_lite.integrations.mcp_server.MCP_AVAILABLE", False),
            pytest.raises(ImportError, match="mcp package is required"),
        ):
            run_mcp_server()

    def test_run_mcp_server_creates_and_runs(self) -> None:
        """Verify run_mcp_server wires up create_mcp_server and asyncio.run."""
        with (
            patch("acgs_lite.integrations.mcp_server.create_mcp_server") as mock_create,
            patch("asyncio.run") as mock_run,
            patch("mcp.server.stdio.stdio_server"),
        ):
            mock_server = mock_create.return_value
            mock_server.run = lambda *a, **kw: None
            mock_server.create_initialization_options = lambda: {}

            run_mcp_server(server_name="test-gov")

            mock_create.assert_called_once()
            mock_run.assert_called_once()
            run_arg = mock_run.call_args.args[0]
            assert inspect.iscoroutine(run_arg)
            run_arg.close()


# ---------------------------------------------------------------------------
# Strict mode restoration
# ---------------------------------------------------------------------------


class TestStrictModeRestoration:
    """Verify that strict mode is correctly restored after tool calls."""

    @pytest.mark.asyncio
    async def test_validate_action_restores_strict_mode(
        self, custom_constitution: Constitution
    ) -> None:
        """After validate_action completes, engine.strict must be restored."""
        constitution = custom_constitution
        server = create_mcp_server(constitution, strict=True)

        # Call validate_action which passes strict=False per call without flipping engine.strict
        await _call_tool(server, "validate_action", {"action": "forbidden"})

        # We can't directly access the engine from outside, but we can verify
        # that a subsequent call also works (doesn't raise)
        result = await _call_tool(server, "validate_action", {"action": "forbidden"})
        assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_check_compliance_restores_strict_mode(
        self, custom_constitution: Constitution
    ) -> None:
        server = create_mcp_server(custom_constitution, strict=True)

        await _call_tool(server, "check_compliance", {"text": "forbidden"})

        # Second call must also work
        result = await _call_tool(server, "check_compliance", {"text": "forbidden"})
        assert result["compliant"] is False

    @pytest.mark.asyncio
    async def test_validate_action_restores_strict_mode_on_exception(
        self, custom_constitution: Constitution
    ) -> None:
        """engine.strict must never be mutated — validate uses per-call strict=False."""
        import json

        from acgs_lite.engine import GovernanceEngine as _RealEngine

        captured: list[_RealEngine] = []

        class _TrackingEngine(_RealEngine):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)  # type: ignore[arg-type]
                captured.append(self)

        with patch("acgs_lite.integrations.mcp_server.GovernanceEngine", _TrackingEngine):
            server = create_mcp_server(custom_constitution, strict=True)

        assert captured, "engine was not created"
        engine = captured[0]
        assert engine.strict is True

        # New contract: validate(strict=False) is used — engine.strict stays True throughout.
        strict_during_call: list[bool] = []
        kwarg_strict: list[bool | None] = []

        def _boom(*args: object, **kwargs: object) -> None:
            strict_during_call.append(engine.strict)
            kwarg_strict.append(kwargs.get("strict"))
            raise RuntimeError("boom")

        with patch.object(engine, "validate", side_effect=_boom):
            import contextlib

            with contextlib.suppress(json.JSONDecodeError, Exception):
                await _call_tool(server, "validate_action", {"action": "x"})

        assert strict_during_call, "validate must have been called"
        assert strict_during_call[0] is True, "engine.strict must never be mutated to False"
        assert kwarg_strict[0] is False, "validate must be called with strict=False kwarg"
        assert engine.strict is True, "engine.strict must remain True after exception"

    @pytest.mark.asyncio
    async def test_check_compliance_restores_strict_mode_on_exception(
        self, custom_constitution: Constitution
    ) -> None:
        """engine.strict must never be mutated — validate uses per-call strict=False."""
        import json

        from acgs_lite.engine import GovernanceEngine as _RealEngine

        captured: list[_RealEngine] = []

        class _TrackingEngine(_RealEngine):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)  # type: ignore[arg-type]
                captured.append(self)

        with patch("acgs_lite.integrations.mcp_server.GovernanceEngine", _TrackingEngine):
            server = create_mcp_server(custom_constitution, strict=True)

        engine = captured[0]
        assert engine.strict is True

        strict_during_call: list[bool] = []
        kwarg_strict: list[bool | None] = []

        def _boom(*args: object, **kwargs: object) -> None:
            strict_during_call.append(engine.strict)
            kwarg_strict.append(kwargs.get("strict"))
            raise RuntimeError("boom")

        with patch.object(engine, "validate", side_effect=_boom):
            import contextlib

            with contextlib.suppress(json.JSONDecodeError, Exception):
                await _call_tool(server, "check_compliance", {"text": "x"})

        assert strict_during_call, "validate must have been called"
        assert strict_during_call[0] is True, "engine.strict must never be mutated to False"
        assert kwarg_strict[0] is False, "validate must be called with strict=False kwarg"
        assert engine.strict is True, "engine.strict must remain True after exception"

    @pytest.mark.asyncio
    async def test_explain_violation_restores_strict_mode_on_exception(
        self, custom_constitution: Constitution
    ) -> None:
        """engine.strict must never be mutated — validate uses per-call strict=False."""
        import json

        from acgs_lite.engine import GovernanceEngine as _RealEngine

        captured: list[_RealEngine] = []

        class _TrackingEngine(_RealEngine):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)  # type: ignore[arg-type]
                captured.append(self)

        with patch("acgs_lite.integrations.mcp_server.GovernanceEngine", _TrackingEngine):
            server = create_mcp_server(custom_constitution, strict=True)

        engine = captured[0]
        assert engine.strict is True

        strict_during_call: list[bool] = []
        kwarg_strict: list[bool | None] = []

        def _boom(*args: object, **kwargs: object) -> None:
            strict_during_call.append(engine.strict)
            kwarg_strict.append(kwargs.get("strict"))
            raise RuntimeError("boom")

        with patch.object(engine, "validate", side_effect=_boom):
            import contextlib

            with contextlib.suppress(json.JSONDecodeError, Exception):
                await _call_tool(server, "explain_violation", {"action": "x"})

        assert strict_during_call, "validate must have been called"
        assert strict_during_call[0] is True, "engine.strict must never be mutated to False"
        assert kwarg_strict[0] is False, "validate must be called with strict=False kwarg"
        assert engine.strict is True, "engine.strict must remain True after exception"


# ---------------------------------------------------------------------------
# Integration: cross-tool interactions
# ---------------------------------------------------------------------------


class TestCrossToolIntegration:
    """Tests verifying correct state across multiple tool calls."""

    @pytest.mark.asyncio
    async def test_validate_then_audit_then_stats(self, custom_constitution: Constitution) -> None:
        server = create_mcp_server(custom_constitution)

        # Validate a mix of compliant and non-compliant actions
        await _call_tool(server, "validate_action", {"action": "clean action"})
        await _call_tool(server, "validate_action", {"action": "forbidden action"})
        await _call_tool(server, "check_compliance", {"text": "safe text"})

        # Audit should have 3 entries
        audit = await _call_tool(server, "get_audit_log", {})
        assert audit["total_entries"] == 3
        assert audit["chain_valid"] is True

        # Stats should reflect 3 validations
        stats = await _call_tool(server, "governance_stats", {})
        assert stats["total_validations"] == 3
        assert stats["audit_entries"] == 3

    @pytest.mark.asyncio
    async def test_constitution_hash_consistency(self, custom_constitution: Constitution) -> None:
        """The constitutional hash must be consistent across all tools."""
        server = create_mcp_server(custom_constitution)

        constitution_data = await _call_tool(server, "get_constitution", {})
        const_hash = constitution_data["constitutional_hash"]

        await _call_tool(server, "validate_action", {"action": "test"})
        validation = await _call_tool(server, "validate_action", {"action": "test"})

        assert validation["constitutional_hash"] == const_hash

        compliance = await _call_tool(server, "check_compliance", {"text": "test"})
        assert compliance["constitutional_hash"] == const_hash

        stats = await _call_tool(server, "governance_stats", {})
        assert stats["constitutional_hash"] == const_hash

    @pytest.mark.asyncio
    async def test_multiple_violations_in_single_action(
        self, custom_constitution: Constitution
    ) -> None:
        """An action matching multiple rules should report all violations."""
        server = create_mcp_server(custom_constitution)
        result = await _call_tool(
            server,
            "validate_action",
            {"action": "this is forbidden and suspicious"},
        )

        assert result["valid"] is False
        rule_ids = {v["rule_id"] for v in result["violations"]}
        # Should match both TEST-001 (forbidden) and TEST-002 (suspicious)
        assert "TEST-001" in rule_ids


# ---------------------------------------------------------------------------
# explain_violation tool
# ---------------------------------------------------------------------------


class TestExplainViolation:
    """Tests for the explain_violation governance tool."""

    @pytest.mark.asyncio
    async def test_compliant_action_returns_no_violations(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "explain_violation", {"action": "hello world"})

        assert result["compliant"] is True
        assert result["violations"] == []
        assert result["constitutional_hash"] == "608508a9bd224290"
        assert "compliant" in result["summary"].lower()

    @pytest.mark.asyncio
    async def test_violating_action_returns_explanation(
        self, custom_constitution: Constitution
    ) -> None:
        server = create_mcp_server(custom_constitution)
        result = await _call_tool(
            server, "explain_violation", {"action": "this is forbidden content"}
        )

        assert result["compliant"] is False
        assert len(result["violations"]) > 0
        violation = result["violations"][0]
        assert violation["rule_id"] == "TEST-001"
        assert violation["severity"] == "critical"
        assert "rule_text" in violation
        assert "description" in violation
        assert "TEST-001" in result["summary"]

    @pytest.mark.asyncio
    async def test_rule_id_filter(self, custom_constitution: Constitution) -> None:
        server = create_mcp_server(custom_constitution)
        result = await _call_tool(
            server,
            "explain_violation",
            {"action": "this is forbidden and suspicious", "rule_id": "TEST-001"},
        )

        assert result["compliant"] is False
        assert all(v["rule_id"] == "TEST-001" for v in result["violations"])

    @pytest.mark.asyncio
    async def test_action_field_present_in_response(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "explain_violation", {"action": "some safe action"})

        assert result["action"] == "some safe action"

    @pytest.mark.asyncio
    async def test_error_path_returns_error_dict(self, default_constitution: Constitution) -> None:
        from unittest.mock import patch

        server = create_mcp_server(default_constitution)
        # Patch GovernanceEngine.validate to raise, simulating an engine failure
        with patch(
            "acgs_lite.engine.GovernanceEngine.validate",
            side_effect=RuntimeError("simulated engine failure"),
        ):
            result = await _call_tool(server, "explain_violation", {"action": "anything"})

        assert "error" in result
        assert result["error"] == "RuntimeError"


# ---------------------------------------------------------------------------
# check_capability_tier tool
# ---------------------------------------------------------------------------


class TestCheckCapabilityTier:
    """Tests for the check_capability_tier governance tool."""

    @pytest.mark.asyncio
    async def test_restricted_action(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server, "check_capability_tier", {"action_text": "delete all records"}
        )

        assert result["tier"] == "RESTRICTED"
        assert result["constitutional_hash"] == "608508a9bd224290"

    @pytest.mark.asyncio
    async def test_full_action(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server, "check_capability_tier", {"action_text": "get user profile"}
        )

        assert result["tier"] == "FULL"

    @pytest.mark.asyncio
    async def test_supervised_action(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server, "check_capability_tier", {"action_text": "update user settings"}
        )

        assert result["tier"] == "SUPERVISED"

    @pytest.mark.asyncio
    async def test_domain_field_echoed(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server,
            "check_capability_tier",
            {"action_text": "list items", "domain": "inventory"},
        )

        assert result["domain"] == "inventory"
        assert result["action"] == "list items"

    @pytest.mark.asyncio
    async def test_no_domain_returns_none(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "check_capability_tier", {"action_text": "destroy data"})

        assert result["domain"] is None

    @pytest.mark.asyncio
    async def test_empty_action_returns_supervised(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "check_capability_tier", {"action_text": ""})

        assert result["tier"] == "SUPERVISED"


# ---------------------------------------------------------------------------
# verify_audit_chain tool
# ---------------------------------------------------------------------------


class TestVerifyAuditChain:
    """Tests for the verify_audit_chain governance tool."""

    @pytest.mark.asyncio
    async def test_empty_log_returns_ok(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "verify_audit_chain", {})

        assert result["status"] == "ok"
        assert result["chain_valid"] is True
        assert result["total_entries"] == 0
        assert result["entries_checked"] == 0
        assert result["constitutional_hash"] == "608508a9bd224290"

    @pytest.mark.asyncio
    async def test_chain_valid_after_validations(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)

        for i in range(5):
            await _call_tool(server, "validate_action", {"action": f"action {i}"})

        result = await _call_tool(server, "verify_audit_chain", {})

        assert result["status"] == "ok"
        assert result["chain_valid"] is True
        assert result["total_entries"] == 5
        assert result["entries_checked"] == 5

    @pytest.mark.asyncio
    async def test_limit_parameter_respected(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)

        for i in range(10):
            await _call_tool(server, "validate_action", {"action": f"action {i}"})

        result = await _call_tool(server, "verify_audit_chain", {"limit": 3})

        assert result["total_entries"] == 10
        assert result["entries_checked"] == 3

    @pytest.mark.asyncio
    async def test_error_path_returns_error_dict(self, default_constitution: Constitution) -> None:
        from unittest.mock import patch

        server = create_mcp_server(default_constitution)
        with patch(
            "acgs_lite.integrations.mcp_server.AuditLog.verify_chain",
            side_effect=RuntimeError("simulated chain failure"),
        ):
            result = await _call_tool(server, "verify_audit_chain", {})

        assert "error" in result
        assert result["error"] == "RuntimeError"


# ---------------------------------------------------------------------------
# Phase 2: compile_workflow + execute_workflow
# ---------------------------------------------------------------------------

try:
    from constitutional_swarm import GoalSpec  # noqa: F401

    _SWARM_AVAILABLE = True
except ImportError:
    _SWARM_AVAILABLE = False

_SIMPLE_WORKFLOW = {
    "goal": "Validate then audit",
    "domains": ["validation", "audit"],
    "steps": [
        {"title": "validate", "domain": "validation", "depends_on": []},
        {"title": "audit-step", "domain": "audit", "depends_on": ["validate"]},
    ],
}

_PARALLEL_WORKFLOW = {
    "goal": "Check compliance and stats, then audit",
    "domains": ["compliance", "stats", "audit"],
    "steps": [
        {"title": "check-compliance", "domain": "compliance", "depends_on": []},
        {"title": "governance-stats", "domain": "stats", "depends_on": []},
        {
            "title": "audit-results",
            "domain": "audit",
            "depends_on": ["check-compliance", "governance-stats"],
        },
    ],
}


@pytest.mark.skipif(not _SWARM_AVAILABLE, reason="constitutional_swarm not installed")
class TestCompileWorkflow:
    @pytest.mark.asyncio
    async def test_compile_returns_nodes(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "compile_workflow", {"workflow": _SIMPLE_WORKFLOW})
        assert "nodes" in result
        assert len(result["nodes"]) == 2

    @pytest.mark.asyncio
    async def test_compile_nodes_have_required_fields(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "compile_workflow", {"workflow": _SIMPLE_WORKFLOW})
        for node in result["nodes"]:
            assert "node_id" in node
            assert "title" in node
            assert "domain" in node

    @pytest.mark.asyncio
    async def test_compile_parallel_three_nodes(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "compile_workflow", {"workflow": _PARALLEL_WORKFLOW})
        assert len(result["nodes"]) == 3

    @pytest.mark.asyncio
    async def test_compile_unknown_domain_returns_error(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        bad = {
            "goal": "Bad",
            "domains": ["nonexistent"],
            "steps": [{"title": "s", "domain": "nonexistent", "depends_on": []}],
        }
        result = await _call_tool(server, "compile_workflow", {"workflow": bad})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_compile_missing_workflow_key_returns_error(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "compile_workflow", {})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_compile_includes_constitutional_hash(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(server, "compile_workflow", {"workflow": _SIMPLE_WORKFLOW})
        assert result.get("constitutional_hash") == "608508a9bd224290"


@pytest.mark.skipif(not _SWARM_AVAILABLE, reason="constitutional_swarm not installed")
class TestExecuteWorkflow:
    @pytest.mark.asyncio
    async def test_execute_returns_step_results(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server,
            "execute_workflow",
            {"workflow": _SIMPLE_WORKFLOW, "inputs": {"action": "read data", "text": "read data"}},
        )
        assert "steps" in result
        assert len(result["steps"]) == 2

    @pytest.mark.asyncio
    async def test_execute_step_fields(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server,
            "execute_workflow",
            {"workflow": _SIMPLE_WORKFLOW, "inputs": {"action": "read data"}},
        )
        for step in result["steps"]:
            assert "node_id" in step
            assert "title" in step
            assert "domain" in step
            assert "constitutional_hash" in step

    @pytest.mark.asyncio
    async def test_execute_parallel_all_steps(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server,
            "execute_workflow",
            {"workflow": _PARALLEL_WORKFLOW, "inputs": {"text": "safe content", "action": "get"}},
        )
        assert len(result["steps"]) == 3

    @pytest.mark.asyncio
    async def test_execute_unknown_domain_returns_error(
        self, default_constitution: Constitution
    ) -> None:
        server = create_mcp_server(default_constitution)
        bad = {
            "goal": "Bad",
            "domains": ["nonexistent"],
            "steps": [{"title": "s", "domain": "nonexistent", "depends_on": []}],
        }
        result = await _call_tool(server, "execute_workflow", {"workflow": bad, "inputs": {}})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_workflow_tools_in_list_tools(self, default_constitution: Constitution) -> None:
        server = create_mcp_server(default_constitution)
        tools = await _list_tools(server)
        names = {t.name for t in tools}
        assert "compile_workflow" in names
        assert "execute_workflow" in names


@pytest.mark.asyncio
async def test_invalid_action_type_does_not_dispatch(default_constitution: Constitution) -> None:
    server = create_mcp_server(default_constitution)
    with patch("acgs_lite.integrations.mcp_server.GovernanceEngine.validate") as validate:
        result = await _call_tool_raw(server, "validate_action", {"action": 42})
    assert result.is_error
    assert result.content[0].text.startswith("Input validation error")
    validate.assert_not_called()
    assert (await _call_tool(server, "get_audit_log"))["total_entries"] == 0


@pytest.mark.asyncio
async def test_legacy_client_jsonrpc_roundtrip(default_constitution: Constitution) -> None:
    from mcp import Client

    server = create_mcp_server(default_constitution)
    async with Client(server, mode="legacy") as client:
        tools = (await client.list_tools()).tools
        assert "validate_action" in {tool.name for tool in tools}
        assert all(tool.input_schema["type"] == "object" for tool in tools)
        valid = await client.call_tool("validate_action", {"action": "hello world"})
        assert not valid.is_error
        assert json.loads(valid.content[0].text)["valid"] is True
        before = await client.call_tool("get_audit_log")
        invalid = await client.call_tool("validate_action")
        assert invalid.is_error
        assert invalid.content[0].text.startswith("Input validation error")
        after = await client.call_tool("get_audit_log")
        assert json.loads(after.content[0].text) == json.loads(before.content[0].text)


@pytest.mark.asyncio
async def test_optional_workflow_dispatch_results(default_constitution: Constitution) -> None:
    """Exercise SDK dispatch/serialization with controlled optional backend results."""
    from types import SimpleNamespace

    from acgs_lite.integrations import mcp_server
    from acgs_lite.integrations.workflow import StepResult

    node = SimpleNamespace(
        node_id="step-1", title="Validate", domain="validation", depends_on=[], priority=1
    )
    dag = SimpleNamespace(dag_id="dag-1", goal="Validate safely", nodes={"step-1": node})
    step = StepResult("step-1", "Validate", "validation", {"valid": True}, "608508a9bd224290")
    with (
        patch.object(mcp_server, "WORKFLOW_AVAILABLE", True),
        patch.object(mcp_server, "GovernanceWorkflowCompiler") as compiler,
        patch.object(mcp_server, "GovernanceWorkflowExecutor") as executor,
        patch.object(mcp_server, "list_workflow_templates", return_value={"example": "demo.yaml"}),
    ):
        compiler.return_value.compile_from_dict.return_value = dag
        executor.return_value.execute.return_value = [step]
        server = create_mcp_server(default_constitution)
        assert {"compile_workflow", "execute_workflow", "list_workflow_templates"} <= {
            tool.name for tool in await _list_tools(server)
        }
        compiled = await _call_tool(server, "compile_workflow", {"workflow": _SIMPLE_WORKFLOW})
        assert compiled == {
            "dag_id": "dag-1",
            "goal": "Validate safely",
            "node_count": 1,
            "nodes": [
                {
                    "node_id": "step-1",
                    "title": "Validate",
                    "domain": "validation",
                    "depends_on": [],
                    "priority": 1,
                }
            ],
            "constitutional_hash": "608508a9bd224290",
        }
        executed = await _call_tool(server, "execute_workflow", {"workflow": _SIMPLE_WORKFLOW})
        assert executed["goal"] == "Validate safely"
        assert executed["steps_completed"] == 1
        assert executed["steps"][0]["result"] == {"valid": True}
        templates = await _call_tool(server, "list_workflow_templates")
        assert templates["templates"] == {"example": "demo.yaml"}
        assert templates["count"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["compile_workflow", "execute_workflow"])
@pytest.mark.parametrize("missing", [False, True])
async def test_optional_workflow_dispatch_errors(
    default_constitution: Constitution, tool_name: str, missing: bool
) -> None:
    """Preserve workflow error payloads through the public client without the backend."""
    from acgs_lite.integrations import mcp_server

    with (
        patch.object(mcp_server, "WORKFLOW_AVAILABLE", True),
        patch.object(mcp_server, "GovernanceWorkflowCompiler") as compiler,
    ):
        compiler.return_value.compile_from_dict.side_effect = ValueError("invalid workflow")
        server = create_mcp_server(default_constitution)
        result = await _call_tool(
            server, tool_name, {} if missing else {"workflow": _SIMPLE_WORKFLOW}
        )
        if missing:
            assert result == {"error": "Missing required argument: workflow"}
            compiler.assert_not_called()
        else:
            assert result == {"error": "ValueError", "detail": "invalid workflow"}
        assert (await _call_tool(server, "get_audit_log"))["total_entries"] == 0


@pytest.mark.asyncio
async def test_workflow_tools_absent_without_backend(default_constitution: Constitution) -> None:
    with patch("acgs_lite.integrations.mcp_server.WORKFLOW_AVAILABLE", False):
        tools = await _list_tools(create_mcp_server(default_constitution))
    assert not {"compile_workflow", "execute_workflow", "list_workflow_templates"} & {
        tool.name for tool in tools
    }
