"""Governance workflow compilation using constitutional_swarm.DAGCompiler.

Wraps DAGCompiler with governance-specific domain validation and provides
a convenience API for compiling governance workflows from dicts or GoalSpecs.

Usage::

    from acgs_lite.integrations.workflow import GovernanceWorkflowCompiler

    compiler = GovernanceWorkflowCompiler("608508a9bd224290")
    dag = compiler.compile_from_dict({
        "goal": "Validate then audit",
        "domains": ["validation", "audit"],
        "steps": [
            {"title": "validate", "domain": "validation", "depends_on": []},
            {"title": "audit",    "domain": "audit",       "depends_on": ["validate"]},
        ],
    })

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Domains map 1:1 to the MCP tools exposed by mcp_server.py
GOVERNANCE_DOMAINS: frozenset[str] = frozenset(
    {
        "validation",
        "constitution",
        "audit",
        "compliance",
        "stats",
        "explain",
        "capability",
    }
)

try:
    from constitutional_swarm import DAGCompiler, GoalSpec
    from constitutional_swarm.artifact import Artifact, ArtifactStore
    from constitutional_swarm.execution import WorkReceipt
    from constitutional_swarm.swarm import ExecutionStatus, TaskDAG, TaskNode

    WORKFLOW_AVAILABLE = True
except ImportError:  # pragma: no cover
    WORKFLOW_AVAILABLE = False
    DAGCompiler = None  # type: ignore[assignment,misc]
    GoalSpec = None  # type: ignore[assignment]
    TaskDAG = None  # type: ignore[assignment]
    TaskNode = None  # type: ignore[assignment]
    ExecutionStatus = None  # type: ignore[assignment]
    Artifact = None  # type: ignore[assignment]
    ArtifactStore = None  # type: ignore[assignment]
    WorkReceipt = None  # type: ignore[assignment]


class StepResult:
    """Immutable result of executing one workflow step."""

    __slots__ = ("node_id", "title", "domain", "result", "constitutional_hash")

    def __init__(
        self,
        node_id: str,
        title: str,
        domain: str,
        result: dict[str, Any],
        constitutional_hash: str,
    ) -> None:
        self.node_id = node_id
        self.title = title
        self.domain = domain
        self.result = result
        self.constitutional_hash = constitutional_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "title": self.title,
            "domain": self.domain,
            "result": self.result,
            "constitutional_hash": self.constitutional_hash,
        }


class GovernanceWorkflowExecutor:
    """Executes a compiled TaskDAG by dispatching each step to an acgs-lite function.

    Domain-to-function dispatch:
    - ``"validation"``   → ``engine.validate(action)``
    - ``"compliance"``   → ``engine.validate(text, agent_id="compliance-check")``
    - ``"constitution"`` → ``constitution.to_dict()`` equivalent
    - ``"audit"``        → ``audit_log.export_dicts()``
    - ``"stats"``        → ``engine.stats``
    - ``"explain"``      → validate + format violation explanations
    - ``"capability"``   → keyword-based tier heuristic

    Args:
        engine: Governance engine (non-strict; violations are returned not raised).
        constitution: Active constitution.
        audit_log: Audit log for the session.
        constitutional_hash: Constitutional hash embedded in each result.
    """

    _RESTRICTED_KEYWORDS = frozenset({"delete", "destroy", "admin", "override", "drop", "truncate"})
    _FULL_KEYWORDS = frozenset({"read", "list", "get", "fetch", "view", "show", "describe"})

    def __init__(
        self,
        engine: Any,
        constitution: Any,
        audit_log: Any,
        constitutional_hash: str,
    ) -> None:
        self._engine = engine
        self._constitution = constitution
        self._audit_log = audit_log
        self._constitutional_hash = constitutional_hash

    def _dispatch(self, domain: str, inputs: dict[str, Any]) -> dict[str, Any]:
        """Execute one step by domain, returning a result dict."""
        action = inputs.get("action", "")
        text = inputs.get("text", action)
        limit = int(inputs.get("limit", 20))

        if domain == "validation":
            result = self._engine.validate(action, agent_id="workflow", strict=False)
            payload: dict[str, Any] = result.to_dict()
            return payload

        if domain == "compliance":
            result = self._engine.validate(text, agent_id="compliance-check", strict=False)
            return {
                "compliant": result.valid,
                "constitutional_hash": self._constitutional_hash,
                "violations": [
                    {"rule_id": v.rule_id, "severity": v.severity.value} for v in result.violations
                ],
            }

        if domain == "constitution":
            return {
                "name": self._constitution.name,
                "version": self._constitution.version,
                "constitutional_hash": self._constitution.hash,
                "rules_count": len(self._constitution.rules),
            }

        if domain == "audit":
            entries = self._audit_log.export_dicts()
            return {
                "total_entries": len(self._audit_log),
                "chain_valid": self._audit_log.verify_chain(),
                "entries": entries[-limit:],
            }

        if domain == "stats":
            return {
                **self._engine.stats,
                "audit_entries": len(self._audit_log),
            }

        if domain == "explain":
            result = self._engine.validate(action, agent_id="explain-workflow", strict=False)
            return {
                "action": action,
                "compliant": result.valid,
                "violations": [
                    {
                        "rule_id": v.rule_id,
                        "severity": v.severity.value,
                        "rule_text": v.rule_text,
                    }
                    for v in result.violations
                ],
            }

        if domain == "capability":
            words = set(action.lower().split())
            if words & self._RESTRICTED_KEYWORDS:
                tier = "RESTRICTED"
            elif words & self._FULL_KEYWORDS:
                tier = "FULL"
            else:
                tier = "SUPERVISED"
            return {"tier": tier, "action": action}

        return {"error": f"Unhandled domain: {domain}"}

    def execute(
        self,
        dag: TaskDAG,  # type: ignore[name-defined]
        inputs: dict[str, Any],
    ) -> list[StepResult]:
        """Execute a compiled TaskDAG step-by-step.

        Processes ``ready_nodes()`` in priority order, dispatches each to the
        domain handler, marks the node complete, then re-evaluates ready nodes
        until ``dag.is_complete``.

        Returns:
            List of StepResult in execution order.
        """
        results: list[StepResult] = []
        max_iterations = len(dag.nodes) * 2 + 1  # safety cap
        executor_id = "workflow-executor"

        for _ in range(max_iterations):
            # Transition all eligible BLOCKED → READY before querying
            dag = dag.mark_ready()
            ready = sorted(
                [n for n in dag.nodes.values() if n.status == ExecutionStatus.READY],
                key=lambda n: -n.priority,
            )
            if not ready:
                break
            for node in ready:
                # Immutable DAG: claim then complete
                dag = dag.claim_node(node.node_id, executor_id)
                step_result = self._dispatch(node.domain, inputs)
                sr = StepResult(
                    node_id=node.node_id,
                    title=node.title,
                    domain=node.domain,
                    result=step_result,
                    constitutional_hash=self._constitutional_hash,
                )
                results.append(sr)
                artifact_id = f"wf-{node.node_id}"
                dag = dag.complete_node(node.node_id, artifact_id)

            if dag.is_complete:
                break

        logger.debug(
            "governance_workflow_executed",
            steps_completed=len(results),
            constitutional_hash=self._constitutional_hash,
        )
        return results


def list_workflow_templates() -> dict[str, str]:
    """Return a dict of built-in workflow template names → YAML file paths.

    Requires ``WORKFLOW_AVAILABLE`` (constitutional_swarm installed).
    Returns an empty dict if templates directory is not found.
    """
    try:
        from acgs_lite.workflows import list_workflow_templates as _list

        return {name: str(path) for name, path in _list().items()}
    except ImportError:  # pragma: no cover
        return {}


class GovernanceWorkflowCompiler:
    """Compiles governance workflows into executable TaskDAGs.

    Wraps ``constitutional_swarm.DAGCompiler`` with domain validation:
    only steps whose ``domain`` is in ``GOVERNANCE_DOMAINS`` are accepted.

    Args:
        constitutional_hash: Hash of the active constitution.
            Must be ``608508a9bd224290`` for the default constitution.
    """

    def __init__(self, constitutional_hash: str) -> None:
        if not WORKFLOW_AVAILABLE:
            raise ImportError(
                "constitutional_swarm is required. Install with: pip install constitutional-swarm"
            )
        self.constitutional_hash = constitutional_hash
        self._compiler = DAGCompiler()

    def compile(self, spec: GoalSpec) -> TaskDAG:  # type: ignore[name-defined]
        """Compile a GoalSpec into a TaskDAG.

        Validates that every step declares a non-empty ``domain`` and that the
        domain is in ``GOVERNANCE_DOMAINS`` before delegating to
        ``DAGCompiler.compile()``.

        Raises:
            ValueError: If any step is missing a domain, uses an empty domain,
                or uses an unrecognised governance domain, or if
                ``DAGCompiler`` rejects the spec (cycles, missing deps…).
        """
        for step in spec.steps:
            title = step.get("title", "?")
            domain = step.get("domain", "")
            if not domain:
                raise ValueError(
                    f"Step {title!r} is missing a domain. "
                    f"Each step must declare one of: {sorted(GOVERNANCE_DOMAINS)}"
                )
            if domain not in GOVERNANCE_DOMAINS:
                raise ValueError(
                    f"Step {title!r} uses domain {domain!r}, "
                    f"which is not a governance domain. "
                    f"Allowed: {sorted(GOVERNANCE_DOMAINS)}"
                )
        dag = self._compiler.compile(spec)
        logger.debug(
            "governance_workflow_compiled",
            goal=spec.goal,
            node_count=len(dag.nodes),
            constitutional_hash=self.constitutional_hash,
        )
        return dag

    def compile_from_dict(self, data: dict[str, Any]) -> TaskDAG:  # type: ignore[name-defined]
        """Compile a workflow from a plain dict (e.g. from MCP tool input).

        Expected keys: ``goal`` (str), ``domains`` (list[str]),
        ``steps`` (list[dict]).  Missing keys default to empty values.

        Raises:
            ValueError: Same as ``compile()``.
        """
        spec = GoalSpec(
            goal=data.get("goal", ""),
            domains=data.get("domains", []),
            steps=data.get("steps", []),
        )
        return self.compile(spec)
