"""ACGS-Lite Anthropic Integration.

Wraps Anthropic's Messages API with constitutional governance.

Usage::

    from acgs_lite.integrations.anthropic import GovernedAnthropic

    client = GovernedAnthropic(api_key="sk-ant-...")
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello!"}],
    )

Constitutional Hash: 608508a9bd224290\n\nPublic integration clients use `audit_mode="full"` so exported stats and audit APIs reflect the durable `AuditLog`.\n"""

from __future__ import annotations

import copy
import json
import logging
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any

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
from acgs_lite.scoring import ConstitutionalImpactScorer
from acgs_lite.trajectory import (
    InMemoryTrajectoryStore,
    SensitiveToolSequenceRule,
    TrajectoryMonitor,
    TrajectoryViolation,
)

logger = logging.getLogger(__name__)

try:
    from anthropic import Anthropic

    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    Anthropic = object  # type: ignore[assignment,misc]


# Tool definitions for ACGS governance tools (Anthropic tool_use format).
# These mirror what the MCP server exposes, allowing Claude to call
# governance tools on itself via tool_use.
_GOVERNANCE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "validate_action",
        "description": (
            "Validate text against constitutional governance rules. "
            "Returns detailed validation result with any violations found."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text or action to validate.",
                },
                "agent_id": {
                    "type": "string",
                    "description": ("Identifier for the agent performing the action."),
                    "default": "self",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "check_compliance",
        "description": (
            "Quick boolean compliance check. Returns true if the text "
            "passes all constitutional rules, false otherwise."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to check for compliance.",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "get_constitution",
        "description": (
            "Get the active constitutional rules. Returns all enabled "
            "rules with their IDs, text, severity, and categories."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "get_audit_log",
        "description": (
            "Get recent governance decisions from the audit log. "
            "Returns the most recent validation entries."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": ("Maximum number of entries to return."),
                    "default": 20,
                },
                "agent_id": {
                    "type": "string",
                    "description": ("Filter entries by agent ID. Omit to return all agents."),
                },
            },
        },
    },
    {
        "name": "governance_stats",
        "description": (
            "Get validation statistics including total checks, "
            "violation counts, and compliance rate."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
]

_GOVERNANCE_TOOL_NAMES: frozenset[str] = frozenset(t["name"] for t in _GOVERNANCE_TOOLS)
_AGENT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")
_TOOL_GOVERNANCE_META_KEYS = frozenset(
    {"runtime_context", "capability_tags", "session_id", "checkpoint_kind"}
)


def _struct_to_dict(value: Any) -> dict[str, Any]:
    """Convert dataclass-like or object-like values into plain dictionaries."""
    if isinstance(value, dict):
        return dict(value)
    if is_dataclass(value):
        if isinstance(value, type):
            # A dataclass class (not an instance); keeps the TypeError asdict() raises.
            raise TypeError("asdict() should be called on dataclass instances")
        return asdict(value)
    if hasattr(value, "__dict__"):
        return dict(vars(value))
    return {}


def _serialize_tool_request(tool_input: Any) -> tuple[str, str]:
    """Serialize full tool input and a request-only payload for auxiliary analysis."""
    serialized = json.dumps(tool_input, sort_keys=True)
    if isinstance(tool_input, dict):
        request_payload = {
            key: value for key, value in tool_input.items() if key not in _TOOL_GOVERNANCE_META_KEYS
        }
        request_serialized = json.dumps(request_payload, sort_keys=True)
        return serialized, request_serialized
    return serialized, serialized


def _trajectory_violation_to_dict(violation: TrajectoryViolation | Any) -> dict[str, Any]:
    """Normalize a trajectory violation into a serializable dict."""
    if isinstance(violation, dict):
        return dict(violation)
    return {
        "rule_id": getattr(violation, "rule_id", ""),
        "evidence": getattr(violation, "evidence", ""),
        "severity": getattr(violation, "severity", ""),
        "agent_id": getattr(violation, "agent_id", ""),
        "timestamp": getattr(violation, "timestamp", ""),
    }


class GovernedMessages:
    """Governed wrapper around Anthropic's messages API."""

    def __init__(
        self,
        client: Any,
        engine: GovernanceEngine,
        agent_id: str,
        *,
        embedding_provider: EmbeddingProvider | None = None,
        experience_library: GovernanceExperienceLibrary | None = None,
        governance_memory: GovernanceMemoryRetriever | Any | None = None,
        tool_risk_scorer: ConstitutionalImpactScorer | Any | None = None,
        trajectory_monitor: TrajectoryMonitor | Any | None = None,
    ) -> None:
        self._client = client
        self._engine = engine
        self._agent_id = agent_id
        self._embedding_provider = embedding_provider
        self._experience_library = experience_library
        self._governance_memory = governance_memory
        self._tool_risk_scorer = tool_risk_scorer
        self._trajectory_monitor = trajectory_monitor
        self.last_tool_use_governance: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> Any:
        """Create a message with governance."""
        messages = kwargs.get("messages", [])

        # Validate last user message
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    self._engine.validate(content, agent_id=self._agent_id)
                elif isinstance(content, list):
                    # Anthropic supports content blocks
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            self._engine.validate(
                                block["text"],
                                agent_id=self._agent_id,
                            )
                break

        # Also validate system prompt if present
        system = kwargs.get("system", "")
        if isinstance(system, str) and system:
            self._validate_non_strict(system, agent_id=f"{self._agent_id}:system")

        # Call Anthropic
        response = self._client.messages.create(**kwargs)

        # Validate output
        if hasattr(response, "content") and response.content:
            for block in response.content:
                if hasattr(block, "text") and block.text:
                    self._validate_output_text(block.text)
                elif (
                    hasattr(block, "type") and block.type == "tool_use" and hasattr(block, "input")
                ):
                    self._validate_tool_use(block)

        return response

    def _validate_output_text(self, text: str) -> None:
        """Validate a text output block against the constitution."""
        result = self._validate_non_strict(text, agent_id=f"{self._agent_id}:output")

        if not result.valid:
            logger.warning(
                "Anthropic response violations: %s",
                [v.rule_id for v in result.violations],
            )

    def _validate_non_strict(
        self,
        text: str,
        *,
        agent_id: str,
        context: dict[str, Any] | None = None,
        audit_metadata: dict[str, Any] | None = None,
    ) -> Any:
        """Run engine validation with per-call strict=False (no instance mutation)."""
        validate_kwargs: dict[str, Any] = {
            "agent_id": agent_id,
            "context": context,
            "strict": False,
        }
        if audit_metadata:
            validate_kwargs["audit_metadata"] = audit_metadata
        # Retry with problematic kwargs dropped if the underlying validate() rejects them
        # (covers older engines / test mocks that pin a narrower signature).
        for _ in range(3):
            try:
                return self._engine.validate(text, **validate_kwargs)
            except TypeError as exc:
                msg = str(exc)
                dropped = False
                for key in ("strict", "audit_metadata"):
                    if key in msg and key in validate_kwargs:
                        validate_kwargs.pop(key)
                        dropped = True
                if not dropped:
                    raise
        return self._engine.validate(text, **validate_kwargs)

    def _validate_tool_use(self, block: Any) -> None:
        """Validate a tool_use output block.

        Tool use inputs can contain malicious content (SQL injection,
        secrets exfiltration, prompt injection, etc.) that needs
        governance checking. The block.input dict is serialized to
        JSON for validation.
        """
        tool_input = getattr(block, "input", None)
        if tool_input is None:
            return

        tool_name = getattr(block, "name", "unknown_tool")
        serialized, request_serialized = _serialize_tool_request(tool_input)
        runtime_context = (
            dict(tool_input.get("runtime_context", {}))
            if isinstance(tool_input, dict) and isinstance(tool_input.get("runtime_context"), dict)
            else {}
        )
        capability_tags = (
            list(tool_input.get("capability_tags", []))
            if isinstance(tool_input, dict) and isinstance(tool_input.get("capability_tags"), list)
            else []
        )
        checkpoint_kind = (
            str(tool_input.get("checkpoint_kind", "")).strip()
            if isinstance(tool_input, dict) and tool_input.get("checkpoint_kind")
            else "tool_invocation"
        )
        session_id = (
            str(tool_input.get("session_id", "")).strip()
            if isinstance(tool_input, dict) and tool_input.get("session_id")
            else self._agent_id
        )
        engine_context = dict(runtime_context)
        engine_context["tool_name"] = tool_name
        if capability_tags:
            engine_context["capability_tags"] = capability_tags
        if checkpoint_kind:
            engine_context["checkpoint_kind"] = checkpoint_kind

        governance_memory_report = None
        if self._governance_memory is not None:
            try:
                governance_memory_report = self._governance_memory.retrieve(request_serialized)
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.warning("anthropic_tool_use_governance_memory_failed: %s", exc)

        tool_risk = None
        if self._tool_risk_scorer is not None:
            try:
                tool_risk = self._tool_risk_scorer.score_tool_invocation(
                    tool_name=tool_name,
                    request=request_serialized,
                    runtime_context=runtime_context,
                    capability_tags=capability_tags,
                )
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.warning("anthropic_tool_use_risk_scoring_failed: %s", exc)

        trajectory_violations: list[dict[str, Any]] = []
        if self._trajectory_monitor is not None:
            try:
                raw_violations = self._trajectory_monitor.check_checkpoint(
                    session_id=session_id,
                    agent_id=self._agent_id,
                    decision={
                        "action_type": checkpoint_kind,
                        "agent_id": self._agent_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "metadata": engine_context,
                    },
                )
                trajectory_violations = [
                    _trajectory_violation_to_dict(violation) for violation in raw_violations
                ]
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.warning("anthropic_tool_use_trajectory_failed: %s", exc)

        audit_metadata = build_runtime_governance_observability(
            governance_memory_report=governance_memory_report,
            tool_risk=tool_risk,
            trajectory_violations=trajectory_violations,
            tool_name=tool_name,
            session_id=session_id,
            checkpoint_kind=checkpoint_kind,
        )
        result = self._validate_non_strict(
            serialized,
            agent_id=f"{self._agent_id}:tool_use:{tool_name}",
            context=engine_context,
            audit_metadata=audit_metadata or None,
        )

        governance_context: dict[str, Any] = {
            "tool_name": tool_name,
            "request": request_serialized,
            "runtime_context": runtime_context,
            "capability_tags": capability_tags,
            "session_id": session_id,
            "checkpoint_kind": checkpoint_kind,
            "validation": {
                "valid": bool(getattr(result, "valid", False)),
                "violation_rule_ids": [
                    violation.rule_id for violation in getattr(result, "violations", [])
                ],
            },
            "tool_risk": None,
            "retrieved_rules": [],
            "retrieved_precedents": [],
            "governance_memory_summary": {},
            "trajectory_violations": [],
        }

        if governance_memory_report is not None:
            governance_context["retrieved_rules"] = [
                _struct_to_dict(hit) for hit in getattr(governance_memory_report, "rule_hits", [])
            ]
            governance_context["retrieved_precedents"] = [
                _struct_to_dict(hit)
                for hit in getattr(governance_memory_report, "precedent_hits", [])
            ]
            governance_context["governance_memory_summary"] = _struct_to_dict(
                getattr(governance_memory_report, "summary", {})
            )

        governance_context["tool_risk"] = tool_risk
        governance_context["trajectory_violations"] = trajectory_violations

        if self._experience_library is not None:
            try:
                record_validation_precedent(
                    experience_library=self._experience_library,
                    embedding_provider=self._embedding_provider,
                    action=request_serialized,
                    result=result,
                    context=engine_context,
                )
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.warning("anthropic_tool_use_precedent_record_failed: %s", exc)

        self.last_tool_use_governance = governance_context

        if not result.valid:
            logger.warning(
                "Tool use '%s' violations: %s",
                tool_name,
                [v.rule_id for v in result.violations],
            )
        if governance_context["trajectory_violations"]:
            logger.warning(
                "Tool use '%s' trajectory violations: %s",
                tool_name,
                [violation["rule_id"] for violation in governance_context["trajectory_violations"]],
            )


class GovernedAnthropic:
    """Drop-in replacement for Anthropic() with constitutional governance.

    Usage::

        from acgs_lite.integrations.anthropic import GovernedAnthropic

        client = GovernedAnthropic()
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello!"}],
        )

    Governance tools (for tool_use self-governance)::

        client = GovernedAnthropic()
        tools = client.governance_tools()
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            tools=tools,
            messages=[{"role": "user", "content": "Check yourself"}],
        )

        # Process governance tool calls from the response
        for block in response.content:
            if block.type == "tool_use" and block.name in tools_by_name:
                result = client.handle_governance_tool(
                    block.name, block.input
                )
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        constitution: Constitution | None = None,
        agent_id: str = "anthropic-agent",
        strict: bool = True,
        embedding_provider: EmbeddingProvider | None = None,
        experience_library: GovernanceExperienceLibrary | None = None,
        governance_memory: GovernanceMemoryRetriever | None = None,
        tool_risk_scorer: ConstitutionalImpactScorer | None = None,
        trajectory_monitor: TrajectoryMonitor | None = None,
        **anthropic_kwargs: Any,
    ) -> None:
        if not ANTHROPIC_AVAILABLE:
            raise ImportError(
                "The 'anthropic' package is required. Install with: pip install acgs-lite[anthropic]"
            )

        self._client = Anthropic(api_key=api_key, **anthropic_kwargs)
        self.constitution = constitution or Constitution.default()
        self.audit_log = AuditLog()
        self.engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict,
            audit_mode="full",
        )
        self.agent_id = agent_id
        self.embedding_provider = embedding_provider
        self.experience_library = experience_library
        self.governance_memory = governance_memory or GovernanceMemoryRetriever(
            self.constitution,
            experience_library=self.experience_library,
            embedding_provider=self.embedding_provider,
        )
        self.tool_risk_scorer = tool_risk_scorer or ConstitutionalImpactScorer()
        self.trajectory_monitor = trajectory_monitor or TrajectoryMonitor(
            rules=[
                SensitiveToolSequenceRule(sensitive_tools={"shell", "terminal", "bash", "exec"})
            ],
            store=InMemoryTrajectoryStore(),
        )
        self.messages = GovernedMessages(
            self._client,
            self.engine,
            agent_id,
            embedding_provider=self.embedding_provider,
            experience_library=self.experience_library,
            governance_memory=self.governance_memory,
            tool_risk_scorer=self.tool_risk_scorer,
            trajectory_monitor=self.trajectory_monitor,
        )

    @classmethod
    def governance_tools(cls) -> list[dict[str, Any]]:
        """Return Anthropic-format tool definitions for governance tools.

        These let Claude call governance tools on itself via tool_use,
        matching what the ACGS MCP server exposes. Include these in
        the ``tools`` parameter of ``messages.create()`` to enable
        self-governance.

        Returns:
            List of tool definitions in Anthropic tool_use format.
        """
        # Return a deep copy so callers cannot mutate the canonical defs
        return copy.deepcopy(_GOVERNANCE_TOOLS)

    def handle_governance_tool(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
    ) -> dict[str, Any]:
        """Process a governance tool_use call and return the result.

        This handles calls to the 5 ACGS governance tools that Claude
        may invoke via tool_use. The caller feeds the result back as a
        ``tool_result`` message.

        Args:
            tool_name: Name of the governance tool being called.
            tool_input: The input dict from the tool_use block.

        Returns:
            Result dict suitable for serialization into a tool_result.

        Raises:
            ValueError: If tool_name is not a known governance tool.
        """
        if tool_name not in _GOVERNANCE_TOOL_NAMES:
            raise ValueError(
                f"Unknown governance tool: {tool_name!r}. "
                f"Known tools: {sorted(_GOVERNANCE_TOOL_NAMES)}"
            )

        if tool_name == "validate_action":
            return self._handle_validate_action(tool_input)
        if tool_name == "check_compliance":
            return self._handle_check_compliance(tool_input)
        if tool_name == "get_constitution":
            return self._handle_get_constitution()
        if tool_name == "get_audit_log":
            return self._handle_get_audit_log(tool_input)
        if tool_name == "governance_stats":
            return self._handle_governance_stats()

        # Unreachable due to the membership check above, but satisfies
        # exhaustiveness for static analysis.
        raise ValueError(f"Unhandled governance tool: {tool_name!r}")

    def _handle_validate_action(self, tool_input: dict[str, Any]) -> dict[str, Any]:
        """Handle the validate_action governance tool."""
        text = tool_input.get("text", "")
        if not text or not text.strip():
            return {"error": "text parameter is required and must not be empty"}

        agent_id = tool_input.get("agent_id", "self")
        if not isinstance(agent_id, str) or not _AGENT_ID_PATTERN.match(agent_id):
            return {"error": f"Invalid agent_id format: {agent_id!r}"}

        governance_memory_report = self.governance_memory.retrieve(text)
        audit_metadata = build_runtime_governance_observability(
            governance_memory_report=governance_memory_report,
        )
        validate_kwargs: dict[str, Any] = {
            "agent_id": f"{self.agent_id}:{agent_id}",
            "strict": False,
        }
        if audit_metadata:
            validate_kwargs["audit_metadata"] = audit_metadata
        result = None
        for _ in range(3):
            try:
                result = self.engine.validate(text, **validate_kwargs)
                break
            except TypeError as exc:
                msg = str(exc)
                dropped = False
                for key in ("strict", "audit_metadata"):
                    if key in msg and key in validate_kwargs:
                        validate_kwargs.pop(key)
                        dropped = True
                if not dropped:
                    raise
        if result is None:
            result = self.engine.validate(text, **validate_kwargs)
        response = {
            "valid": result.valid,
            "violations": [
                {
                    "rule_id": v.rule_id,
                    "rule_text": v.rule_text,
                    "severity": str(v.severity),
                    "matched_content": v.matched_content,
                    "category": v.category,
                }
                for v in result.violations
            ],
            "rules_checked": result.rules_checked,
            "constitutional_hash": result.constitutional_hash,
            "retrieved_rules": [asdict(hit) for hit in governance_memory_report.rule_hits],
            "retrieved_precedents": [
                asdict(hit) for hit in governance_memory_report.precedent_hits
            ],
            "governance_memory_summary": asdict(governance_memory_report.summary),
        }

        try:
            record_validation_precedent(
                experience_library=self.experience_library,
                embedding_provider=self.embedding_provider,
                action=text,
                result=result,
                context={},
            )
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("anthropic_validate_action_precedent_record_failed: %s", exc)

        return response

    def _handle_check_compliance(self, tool_input: dict[str, Any]) -> dict[str, Any]:
        """Handle the check_compliance governance tool."""
        text = tool_input.get("text", "")
        if not text or not text.strip():
            return {"error": "text parameter is required and must not be empty"}

        result = self.engine.validate(
            text,
            agent_id=f"{self.agent_id}:compliance_check",
            strict=False,
        )

        return {
            "compliant": result.valid,
            "violation_count": len(result.violations),
        }

    def _handle_get_constitution(self) -> dict[str, Any]:
        """Handle the get_constitution governance tool."""
        rules = [
            {
                "id": rule.id,
                "text": rule.text,
                "severity": str(rule.severity),
                "category": rule.category,
                "keywords": rule.keywords,
                "enabled": rule.enabled,
            }
            for rule in self.constitution.rules
            if rule.enabled
        ]
        return {
            "rules": rules,
            "rule_count": len(rules),
            "constitutional_hash": self.constitution.hash,
        }

    def _handle_get_audit_log(self, tool_input: dict[str, Any]) -> dict[str, Any]:
        """Handle the get_audit_log governance tool."""
        raw_limit = tool_input.get("limit", 20)
        limit = max(1, min(int(raw_limit), 1000))
        agent_id = tool_input.get("agent_id")
        if agent_id is not None and (
            not isinstance(agent_id, str) or not _AGENT_ID_PATTERN.match(agent_id)
        ):
            return {"error": f"Invalid agent_id format: {agent_id!r}"}

        entries = self.audit_log.query(
            agent_id=agent_id,
            limit=limit,
        )
        return {
            "entries": [entry.to_dict() for entry in entries],
            "count": len(entries),
            "chain_valid": self.audit_log.verify_chain(),
        }

    def _handle_governance_stats(self) -> dict[str, Any]:
        """Handle the governance_stats governance tool."""
        return {
            **self.engine.stats,
            "agent_id": self.agent_id,
            "audit_chain_valid": self.audit_log.verify_chain(),
            "compliance_rate": self.audit_log.compliance_rate,
        }

    @property
    def stats(self) -> dict[str, Any]:
        """Return governance statistics for this client."""
        return {
            **self.engine.stats,
            "agent_id": self.agent_id,
            "audit_chain_valid": self.audit_log.verify_chain(),
        }
