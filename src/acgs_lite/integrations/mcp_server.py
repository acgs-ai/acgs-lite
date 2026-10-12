"""ACGS-Lite MCP Server Integration.

Exposes constitutional governance as an MCP (Model Context Protocol) server.
Any MCP-compatible client (Claude Desktop, VS Code, Cursor, etc.) can call
these tools to validate actions, inspect constitutions, and query audit logs.

Usage::

    # Run from command line:
    python -m acgs_lite.integrations.mcp_server

    # Or programmatically:
    from acgs_lite.integrations.mcp_server import create_mcp_server, run_mcp_server
    run_mcp_server()

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

import structlog

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.constitution.experience_library import GovernanceExperienceLibrary
from acgs_lite.constitution.governance_memory import GovernanceMemoryRetriever
from acgs_lite.constitution.semantic_search import EmbeddingProvider
from acgs_lite.engine import GovernanceEngine
from acgs_lite.integrations._runtime_governance import (
    build_runtime_governance_observability,
    record_validation_precedent,
)
from acgs_lite.integrations.workflow import (
    WORKFLOW_AVAILABLE,
    GovernanceWorkflowCompiler,
    GovernanceWorkflowExecutor,
    list_workflow_templates,
)
from acgs_lite.scoring import ConstitutionalImpactScorer
from acgs_lite.trajectory import (
    InMemoryTrajectoryStore,
    SensitiveToolSequenceRule,
    TrajectoryMonitor,
)

logger = structlog.get_logger(__name__)

CONSTITUTIONAL_HASH = "608508a9bd224290"

# Keywords used by check_capability_tier heuristic (no CapabilityPassport available)
_RESTRICTED_KEYWORDS = frozenset({"delete", "destroy", "admin", "override", "drop", "truncate"})
_FULL_KEYWORDS = frozenset({"read", "list", "get", "fetch", "view", "show", "describe"})

try:
    from mcp import types
    from mcp.server import Server, ServerRequestContext

    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    Server = None  # type: ignore[assignment,misc]


def create_mcp_server(
    constitution: Constitution | None = None,
    *,
    server_name: str = "acgs-governance",
    strict: bool = False,
    embedding_provider: EmbeddingProvider | None = None,
    experience_library: GovernanceExperienceLibrary | None = None,
) -> Any:
    """Create an MCP server exposing governance tools.

    Args:
        constitution: Rules to enforce. Defaults to built-in rules.
        server_name: Name of the MCP server.
        strict: Baseline strict mode for the underlying engine. The MCP tools
            (``validate_action``, ``check_compliance``, ``explain_violation``)
            always operate non-strictly by passing ``validate(strict=False)`` per
            call. They do not mutate ``engine.strict`` and return structured
            results instead of raising. This parameter therefore affects only
            direct non-tool engine access.
        embedding_provider: Optional embedding provider for governance-memory retrieval.
        experience_library: Optional precedent library for governance-memory retrieval.

    Returns:
        MCP Server instance.
    """
    if not MCP_AVAILABLE:
        raise ImportError("mcp package is required. Install with: pip install acgs-lite[mcp]")

    from jsonschema import ValidationError
    from jsonschema.validators import validator_for

    constitution = constitution if constitution is not None else Constitution.default()
    audit_log = AuditLog()
    engine = GovernanceEngine(constitution, audit_log=audit_log, strict=strict, audit_mode="full")
    impact_scorer = ConstitutionalImpactScorer()
    trajectory_monitor = TrajectoryMonitor(
        rules=[SensitiveToolSequenceRule(sensitive_tools={"shell", "terminal", "bash", "exec"})],
        store=InMemoryTrajectoryStore(),
    )
    governance_memory = GovernanceMemoryRetriever(
        constitution,
        experience_library=experience_library,
        embedding_provider=embedding_provider,
    )

    tools = [
        types.Tool(
            name="validate_action",
            description=(
                "Validate an agent action against constitutional governance rules. "
                "Returns whether the action is compliant and any violations found."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "The action text to validate",
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "ID of the agent performing the action",
                        "default": "mcp-client",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session identifier for mid-trajectory checkpoint tracking",
                    },
                    "checkpoint_kind": {
                        "type": "string",
                        "description": "Optional checkpoint kind such as input_analysis or tool_invocation",
                    },
                    "tool_name": {
                        "type": "string",
                        "description": "Optional tool name when validating a tool invocation",
                    },
                    "runtime_context": {
                        "type": "object",
                        "description": "Optional runtime risk signals (e.g. untrusted_input, prompt_injection_suspected)",
                        "default": {},
                    },
                    "capability_tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional capability tags used for static tool prior scoring",
                        "default": [],
                    },
                },
                "required": ["action"],
            },
        ),
        types.Tool(
            name="get_constitution",
            description=(
                "Get the current constitution: name, version, hash, and the full list of rules."
            ),
            input_schema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="get_audit_log",
            description=("Get recent audit log entries showing governance decisions."),
            input_schema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum entries to return",
                        "default": 20,
                    },
                },
            },
        ),
        types.Tool(
            name="check_compliance",
            description=(
                "Quick compliance check — returns whether text contains "
                "any constitutional violations."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to check for compliance",
                    },
                },
                "required": ["text"],
            },
        ),
        types.Tool(
            name="governance_stats",
            description=(
                "Get governance statistics: total validations, compliance rate, "
                "average latency, and audit chain integrity."
            ),
            input_schema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="explain_violation",
            description=(
                "Explain a constitutional violation in human-readable form. "
                "Validates the action and returns detailed violation information "
                "including rule text, severity, and description."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "The action text to explain violations for",
                    },
                    "rule_id": {
                        "type": "string",
                        "description": "Optional rule ID to filter explanation to a specific rule",
                    },
                },
                "required": ["action"],
            },
        ),
        types.Tool(
            name="check_capability_tier",
            description=(
                "Check the autonomy capability tier for an action. "
                "Returns RESTRICTED, SUPERVISED, or FULL based on the action content."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "action_text": {
                        "type": "string",
                        "description": "The action text to check the capability tier for",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Optional domain context for tier determination",
                    },
                },
                "required": ["action_text"],
            },
        ),
        types.Tool(
            name="verify_audit_chain",
            description=(
                "Verify the integrity of the audit chain. "
                "Checks hash chain consistency across recent audit entries."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of recent entries to check",
                        "default": 100,
                    },
                },
            },
        ),
        *(
            [
                types.Tool(
                    name="compile_workflow",
                    description=(
                        "Compile a governance workflow GoalSpec into an executable TaskDAG. "
                        "Validates step domains against known governance domains and returns "
                        "node list with IDs, titles, domains, and dependency edges."
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "workflow": {
                                "type": "object",
                                "description": (
                                    "GoalSpec dict with keys: goal (str), "
                                    "domains (list[str]), steps (list[dict])"
                                ),
                            },
                        },
                    },
                ),
                types.Tool(
                    name="execute_workflow",
                    description=(
                        "Compile and execute a governance workflow. Each step is dispatched "
                        "to the matching acgs-lite governance function. Returns per-step results "
                        "with constitutional proof."
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "workflow": {
                                "type": "object",
                                "description": "GoalSpec dict (same as compile_workflow)",
                            },
                            "inputs": {
                                "type": "object",
                                "description": (
                                    "Shared inputs for steps: action (str), text (str), limit (int)"
                                ),
                                "default": {},
                            },
                        },
                    },
                ),
                types.Tool(
                    name="list_workflow_templates",
                    description=(
                        "List pre-built governance workflow templates. "
                        "Returns template names and YAML file paths for common patterns: "
                        "action_validation, compliance_assessment, agent_onboarding."
                    ),
                    input_schema={"type": "object", "properties": {}},
                ),
            ]
            if WORKFLOW_AVAILABLE
            else []
        ),
    ]

    tools_by_name = {tool.name: tool for tool in tools}
    validators = {
        name: validator_for(tool.input_schema)(tool.input_schema)
        for name, tool in tools_by_name.items()
    }

    async def list_tools(
        ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        """Return the schemas used to validate every governance call."""
        return types.ListToolsResult(tools=tools)

    async def call_tool(
        ctx: ServerRequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        """Validate the advertised schema before dispatching a governance call."""
        name = params.name
        arguments = params.arguments or {}
        validator = validators.get(name)
        if validator is not None:
            try:
                validator.validate(arguments)
            except ValidationError as exc:
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text", text=f"Input validation error: {exc.message}"
                        )
                    ],
                    is_error=True,
                )
        if name == "validate_action":
            action = arguments.get("action", "")
            agent_id = arguments.get("agent_id", "mcp-client")
            session_id = arguments.get("session_id")
            checkpoint_kind = arguments.get("checkpoint_kind")
            tool_name = arguments.get("tool_name")
            runtime_context = arguments.get("runtime_context", {})
            capability_tags = arguments.get("capability_tags", [])
            if not isinstance(runtime_context, dict):
                runtime_context = {}
            if not isinstance(capability_tags, list):
                capability_tags = []

            engine_context = dict(runtime_context)
            if checkpoint_kind:
                engine_context["checkpoint_kind"] = checkpoint_kind
            if tool_name:
                engine_context["tool_name"] = tool_name
            if capability_tags:
                engine_context["capability_tags"] = capability_tags

            governance_memory_report = governance_memory.retrieve(action)
            tool_risk = (
                impact_scorer.score_tool_invocation(
                    tool_name=tool_name,
                    request=action,
                    runtime_context=runtime_context,
                    capability_tags=capability_tags,
                )
                if tool_name
                else None
            )
            trajectory_violations = (
                trajectory_monitor.check_checkpoint(
                    session_id=session_id,
                    agent_id=agent_id,
                    decision={
                        "action_type": checkpoint_kind,
                        "agent_id": agent_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "metadata": {
                            **engine_context,
                            "tool_name": tool_name,
                        },
                    },
                )
                if session_id and checkpoint_kind
                else []
            )
            audit_metadata = build_runtime_governance_observability(
                governance_memory_report=governance_memory_report,
                tool_risk=tool_risk,
                trajectory_violations=trajectory_violations,
                tool_name=tool_name,
                session_id=session_id,
                checkpoint_kind=checkpoint_kind,
            )

            result = engine.validate(
                action,
                agent_id=agent_id,
                context=engine_context or None,
                audit_metadata=audit_metadata or None,
                strict=False,
            )

            response = result.to_dict()
            response["retrieved_rules"] = [
                asdict(hit) for hit in governance_memory_report.rule_hits
            ]
            response["retrieved_precedents"] = [
                asdict(hit) for hit in governance_memory_report.precedent_hits
            ]
            response["governance_memory_summary"] = asdict(governance_memory_report.summary)

            if tool_name:
                response["tool_risk"] = tool_risk

            if session_id and checkpoint_kind:
                response["trajectory_violations"] = [
                    {
                        "rule_id": v.rule_id,
                        "evidence": v.evidence,
                        "severity": v.severity,
                        "agent_id": v.agent_id,
                        "timestamp": v.timestamp,
                    }
                    for v in trajectory_violations
                ]
            else:
                response["trajectory_violations"] = []

            try:
                record_validation_precedent(
                    experience_library=experience_library,
                    embedding_provider=embedding_provider,
                    action=action,
                    result=result,
                    context=engine_context,
                )
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.warning("validate_action_precedent_record_failed", error=str(exc))

            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps(response, indent=2),
                    )
                ]
            )

        elif name == "get_constitution":
            data = {
                "name": constitution.name,
                "version": constitution.version,
                "constitutional_hash": constitution.hash,
                "constitutional_hash_versioned": constitution.hash_versioned,
                "rules_count": len(constitution.rules),
                "rules": [
                    {
                        "id": r.id,
                        "text": r.text,
                        "severity": r.severity.value,
                        "category": r.category,
                        "enabled": r.enabled,
                    }
                    for r in constitution.rules
                ],
            }
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps(data, indent=2),
                    )
                ]
            )

        elif name == "get_audit_log":
            limit = arguments.get("limit", 20)
            entries = audit_log.export_dicts()[-limit:]
            data = {
                "total_entries": len(audit_log),
                "chain_valid": audit_log.verify_chain(),
                "entries": entries,
            }
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps(data, indent=2, default=str),
                    )
                ]
            )

        elif name == "check_compliance":
            text = arguments.get("text", "")
            result = engine.validate(text, agent_id="compliance-check", strict=False)

            data = {
                "compliant": result.valid,
                "constitutional_hash": result.constitutional_hash,
                "violations": [
                    {"rule_id": v.rule_id, "severity": v.severity.value} for v in result.violations
                ],
            }
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps(data, indent=2),
                    )
                ]
            )

        elif name == "governance_stats":
            stats = {
                **engine.stats,
                "audit_entries": len(audit_log),
                "audit_chain_valid": audit_log.verify_chain(),
            }
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps(stats, indent=2),
                    )
                ]
            )

        elif name == "explain_violation":
            action = arguments.get("action", "")
            rule_id_filter: str | None = arguments.get("rule_id")

            try:
                result = engine.validate(action, agent_id="explain-tool", strict=False)
            except Exception as exc:
                logger.warning(
                    "explain_violation_error",
                    error_type=type(exc).__name__,
                    constitutional_hash=CONSTITUTIONAL_HASH,
                )
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=json.dumps({"error": type(exc).__name__, "action": action}),
                        )
                    ]
                )

            violations = result.violations
            if rule_id_filter:
                violations = [v for v in violations if v.rule_id == rule_id_filter]

            explanation: dict[str, Any] = {
                "action": action,
                "compliant": result.valid,
                "constitutional_hash": CONSTITUTIONAL_HASH,
                "violations": [
                    {
                        "rule_id": v.rule_id,
                        "severity": v.severity.value,
                        "rule_text": v.rule_text,
                        "description": getattr(v, "description", v.rule_text),
                    }
                    for v in violations
                ],
                "summary": (
                    "Action is compliant — no violations found."
                    if result.valid
                    else (
                        f"Action violates {len(violations)} rule(s): "
                        + ", ".join(v.rule_id for v in violations)
                    )
                ),
            }
            logger.info(
                "explain_violation",
                action_length=len(action),
                violations_count=len(violations),
                constitutional_hash=CONSTITUTIONAL_HASH,
            )
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps(explanation, indent=2),
                    )
                ]
            )

        elif name == "check_capability_tier":
            action_text = arguments.get("action_text", "")
            domain: str | None = arguments.get("domain")

            try:
                lower = action_text.lower()
                words = set(lower.split())

                if words & _RESTRICTED_KEYWORDS:
                    tier = "RESTRICTED"
                elif words & _FULL_KEYWORDS:
                    tier = "FULL"
                else:
                    tier = "SUPERVISED"

                tier_data: dict[str, Any] = {
                    "tier": tier,
                    "action": action_text,
                    "domain": domain,
                    "constitutional_hash": CONSTITUTIONAL_HASH,
                }
                logger.info(
                    "check_capability_tier",
                    tier=tier,
                    domain=domain,
                    constitutional_hash=CONSTITUTIONAL_HASH,
                )
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=json.dumps(tier_data, indent=2),
                        )
                    ]
                )
            except Exception as exc:
                logger.warning(
                    "check_capability_tier_error",
                    error_type=type(exc).__name__,
                    constitutional_hash=CONSTITUTIONAL_HASH,
                )
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=json.dumps(
                                {"error": type(exc).__name__, "action_text": action_text}
                            ),
                        )
                    ]
                )

        elif name == "verify_audit_chain":
            limit = arguments.get("limit", 100)

            try:
                chain_valid = audit_log.verify_chain()
                entries = audit_log.export_dicts()
                recent = entries[-limit:] if len(entries) > limit else entries

                result_data: dict[str, Any] = {
                    "status": "ok" if chain_valid else "chain_broken",
                    "chain_valid": chain_valid,
                    "total_entries": len(entries),
                    "entries_checked": len(recent),
                    "constitutional_hash": CONSTITUTIONAL_HASH,
                }
                logger.info(
                    "verify_audit_chain",
                    chain_valid=chain_valid,
                    entries_checked=len(recent),
                    constitutional_hash=CONSTITUTIONAL_HASH,
                )
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=json.dumps(result_data, indent=2),
                        )
                    ]
                )
            except Exception as exc:
                logger.warning(
                    "verify_audit_chain_error",
                    error_type=type(exc).__name__,
                    constitutional_hash=CONSTITUTIONAL_HASH,
                )
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=json.dumps({"error": type(exc).__name__}),
                        )
                    ]
                )

        elif name == "compile_workflow" and WORKFLOW_AVAILABLE:
            workflow_spec = arguments.get("workflow") if arguments else None
            if not workflow_spec:
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=json.dumps({"error": "Missing required argument: workflow"}),
                        )
                    ]
                )
            try:
                compiler = GovernanceWorkflowCompiler(CONSTITUTIONAL_HASH)
                dag = compiler.compile_from_dict(workflow_spec)
                nodes = [
                    {
                        "node_id": node.node_id,
                        "title": node.title,
                        "domain": node.domain,
                        "depends_on": list(node.depends_on),
                        "priority": node.priority,
                    }
                    for node in dag.nodes.values()
                ]
                data = {
                    "dag_id": dag.dag_id,
                    "goal": dag.goal,
                    "node_count": len(nodes),
                    "nodes": nodes,
                    "constitutional_hash": CONSTITUTIONAL_HASH,
                }
                logger.info(
                    "compile_workflow",
                    node_count=len(nodes),
                    constitutional_hash=CONSTITUTIONAL_HASH,
                )
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=json.dumps(data, indent=2))]
                )
            except Exception as exc:
                logger.warning(
                    "compile_workflow_error",
                    error_type=type(exc).__name__,
                    constitutional_hash=CONSTITUTIONAL_HASH,
                )
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=json.dumps({"error": type(exc).__name__, "detail": str(exc)}),
                        )
                    ]
                )

        elif name == "execute_workflow" and WORKFLOW_AVAILABLE:
            workflow_spec = arguments.get("workflow") if arguments else None
            if not workflow_spec:
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=json.dumps({"error": "Missing required argument: workflow"}),
                        )
                    ]
                )
            inputs: dict[str, Any] = (arguments.get("inputs") or {}) if arguments else {}
            try:
                compiler = GovernanceWorkflowCompiler(CONSTITUTIONAL_HASH)
                dag = compiler.compile_from_dict(workflow_spec)
                executor = GovernanceWorkflowExecutor(
                    engine=engine,
                    constitution=constitution,
                    audit_log=audit_log,
                    constitutional_hash=CONSTITUTIONAL_HASH,
                )
                step_results = executor.execute(dag, inputs)
                data = {
                    "goal": dag.goal,
                    "steps_completed": len(step_results),
                    "constitutional_hash": CONSTITUTIONAL_HASH,
                    "steps": [sr.to_dict() for sr in step_results],
                }
                logger.info(
                    "execute_workflow",
                    steps_completed=len(step_results),
                    constitutional_hash=CONSTITUTIONAL_HASH,
                )
                return types.CallToolResult(
                    content=[
                        types.TextContent(type="text", text=json.dumps(data, indent=2, default=str))
                    ]
                )
            except Exception as exc:
                logger.warning(
                    "execute_workflow_error",
                    error_type=type(exc).__name__,
                    constitutional_hash=CONSTITUTIONAL_HASH,
                )
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=json.dumps({"error": type(exc).__name__, "detail": str(exc)}),
                        )
                    ]
                )

        elif name == "list_workflow_templates" and WORKFLOW_AVAILABLE:
            templates = list_workflow_templates()
            data = {
                "templates": templates,
                "count": len(templates),
                "constitutional_hash": CONSTITUTIONAL_HASH,
            }
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=json.dumps(data, indent=2))]
            )

        else:
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Unknown tool: {name}"}),
                    )
                ]
            )

    return Server(server_name, on_list_tools=list_tools, on_call_tool=call_tool)


def run_mcp_server(
    constitution: Constitution | None = None,
    *,
    server_name: str = "acgs-governance",
) -> None:
    """Run the governance MCP server over stdio.

    Usage::

        python -m acgs_lite.integrations.mcp_server
    """
    if not MCP_AVAILABLE:
        raise ImportError("mcp package is required. Install with: pip install acgs-lite[mcp]")

    from mcp.server.stdio import stdio_server

    server = create_mcp_server(constitution, server_name=server_name)

    async def _run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    asyncio.run(_run())


if __name__ == "__main__":
    run_mcp_server()
