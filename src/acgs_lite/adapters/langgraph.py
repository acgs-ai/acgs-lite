"""LangGraph tool-call wrappers built on ACGS-lite adapter contracts."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import import_module
from typing import Any
from uuid import uuid4

from acgs_lite.adapters.contracts import (
    AdapterPolicyDecision,
    DecisionState,
    ExecutionReceipt,
    ExecutionReceiptSink,
    ToolCallContext,
)
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.engine.core import GovernanceEngine
from acgs_lite.engine.models import ValidationResult
from acgs_lite.errors import ConstitutionalViolationError, PolicyDeniedError
from acgs_lite.serialization import serialize_for_governance

ContextBuilder = Callable[[ToolCallContext, Any], dict[str, Any]]
SyncToolExecutor = Callable[[Any], Any]
AsyncToolExecutor = Callable[[Any], Awaitable[Any]]


@dataclass(slots=True)
class _EvaluatedCall:
    context: ToolCallContext
    action_id: str
    decision: AdapterPolicyDecision
    policy_hash: str | None
    denial_error: PolicyDeniedError | None = None
    force_raise: bool = False


def make_wrap_tool_call(
    engine: GovernanceEngine,
    *,
    sink: ExecutionReceiptSink | None = None,
    fail_closed: bool = True,
    agent_id: str = "langgraph-tool",
    context_builder: ContextBuilder | None = None,
) -> Callable[[Any, SyncToolExecutor], Any]:
    """Build a LangGraph-compatible synchronous tool-call wrapper."""

    def _wrap(request: Any, execute: SyncToolExecutor) -> Any:
        evaluated = _evaluate_request(
            engine,
            request,
            fallback_agent_id=agent_id,
            fail_closed=fail_closed,
            context_builder=context_builder,
        )
        if not evaluated.decision.allowed:
            _emit_receipt(
                sink,
                evaluated,
                execution_status="blocked",
            )
            if evaluated.force_raise:
                raise evaluated.denial_error or _policy_error_from_decision(
                    evaluated.context,
                    evaluated.decision,
                    policy_hash=evaluated.policy_hash,
                )
            return _deny_with_tool_message(evaluated)

        try:
            result = execute(request)
        except Exception as exc:
            _emit_receipt(
                sink,
                evaluated,
                execution_status="error",
                execution_error=type(exc).__name__,
            )
            raise
        _emit_receipt(sink, evaluated, execution_status="success")
        return result

    return _wrap


def make_awrap_tool_call(
    engine: GovernanceEngine,
    *,
    sink: ExecutionReceiptSink | None = None,
    fail_closed: bool = True,
    agent_id: str = "langgraph-tool",
    context_builder: ContextBuilder | None = None,
) -> Callable[[Any, AsyncToolExecutor], Awaitable[Any]]:
    """Build a LangGraph-compatible asynchronous tool-call wrapper."""

    async def _wrap(request: Any, execute: AsyncToolExecutor) -> Any:
        evaluated = _evaluate_request(
            engine,
            request,
            fallback_agent_id=agent_id,
            fail_closed=fail_closed,
            context_builder=context_builder,
        )
        if not evaluated.decision.allowed:
            _emit_receipt(
                sink,
                evaluated,
                execution_status="blocked",
            )
            if evaluated.force_raise:
                raise evaluated.denial_error or _policy_error_from_decision(
                    evaluated.context,
                    evaluated.decision,
                    policy_hash=evaluated.policy_hash,
                )
            return _deny_with_tool_message(evaluated)

        try:
            result = await execute(request)
        except Exception as exc:
            _emit_receipt(
                sink,
                evaluated,
                execution_status="error",
                execution_error=type(exc).__name__,
            )
            raise
        _emit_receipt(sink, evaluated, execution_status="success")
        return result

    return _wrap


def _evaluate_request(
    engine: GovernanceEngine,
    request: Any,
    *,
    fallback_agent_id: str,
    fail_closed: bool,
    context_builder: ContextBuilder | None,
) -> _EvaluatedCall:
    context, action_id = _extract_tool_context(request, fallback_agent_id=fallback_agent_id)
    validation_context = _build_validation_context(
        context, request, context_builder=context_builder
    )
    effective_agent_id = context.actor_id or fallback_agent_id

    try:
        result = engine.validate(
            context.tool_name,
            agent_id=effective_agent_id,
            context=validation_context,
            strict=False,
        )
    except ConstitutionalViolationError as exc:
        denial_error = _policy_error_from_exception(
            exc,
            action=context.tool_name,
            policy_hash=_engine_policy_hash(engine),
        )
        return _EvaluatedCall(
            context=context,
            action_id=action_id,
            decision=_decision_from_exception(denial_error),
            policy_hash=denial_error.policy_hash,
            denial_error=denial_error,
            force_raise=denial_error.enforcement_action is ViolationAction.HALT,
        )
    except Exception as exc:
        if fail_closed:
            denial_error = PolicyDeniedError(
                "Policy validation unavailable; fail-closed block applied.",
                policy_id="policy-engine",
                policy_hash=_engine_policy_hash(engine),
                severity="critical",
                action=context.tool_name,
            )
            return _EvaluatedCall(
                context=context,
                action_id=action_id,
                decision=AdapterPolicyDecision(
                    allowed=False,
                    state="HARD_DENY",
                    reason=str(denial_error),
                    metadata={
                        "validation_error": type(exc).__name__,
                        "fail_closed": True,
                    },
                ),
                policy_hash=denial_error.policy_hash,
                denial_error=denial_error,
                force_raise=True,
            )
        return _EvaluatedCall(
            context=context,
            action_id=action_id,
            decision=AdapterPolicyDecision(
                allowed=True,
                state="ALLOW_WITH_CONTROLS",
                reason="Policy validation unavailable; fail-open path enabled.",
                metadata={
                    "validation_error": type(exc).__name__,
                    "fail_open": True,
                },
            ),
            policy_hash=_engine_policy_hash(engine),
        )

    decision = _decision_from_result(result)
    policy_error: PolicyDeniedError | None = None
    if not decision.allowed:
        policy_error = _policy_error_from_result(result, context, decision)
    return _EvaluatedCall(
        context=context,
        action_id=action_id,
        decision=decision,
        policy_hash=result.constitutional_hash,
        denial_error=policy_error,
    )


def _extract_tool_context(
    request: Any,
    *,
    fallback_agent_id: str,
) -> tuple[ToolCallContext, str]:
    tool_call = _coerce_mapping(_get_value(request, "tool_call"))
    runtime = _get_value(request, "runtime")
    config = _coerce_mapping(_get_value(runtime, "config"))
    configurable = _coerce_mapping(config.get("configurable"))

    raw_args = _get_value(tool_call, "args")
    tool_args = _coerce_mapping(raw_args)
    if not tool_args and raw_args not in (None, {}):
        tool_args = {"value": raw_args}

    tool_name = str(
        _first_non_empty(
            _get_value(tool_call, "name"),
            _get_value(_get_value(request, "tool"), "name"),
            "tool",
        )
    )
    action_id = str(
        _first_non_empty(
            _get_value(tool_call, "id"),
            configurable.get("tool_call_id"),
            config.get("run_id"),
            uuid4().hex,
        )
    )
    session_id = str(
        _first_non_empty(
            configurable.get("thread_id"),
            configurable.get("session_id"),
            config.get("thread_id"),
            config.get("session_id"),
            "",
        )
    )
    actor_id = str(
        _first_non_empty(
            configurable.get("agent_id"),
            configurable.get("assistant_id"),
            configurable.get("user_id"),
            fallback_agent_id,
        )
    )
    tool_args_preview = serialize_for_governance(tool_args)
    metadata: dict[str, Any] = {"tool_call_id": action_id}
    if tool_args_preview:
        metadata["tool_args_preview"] = tool_args_preview

    return (
        ToolCallContext(
            tool_name=tool_name,
            tool_args=tool_args,
            framework="langgraph",
            session_id=session_id,
            actor_id=actor_id,
            metadata=metadata,
        ),
        action_id,
    )


def _build_validation_context(
    context: ToolCallContext,
    request: Any,
    *,
    context_builder: ContextBuilder | None,
) -> dict[str, Any]:
    preview = serialize_for_governance(context.tool_args)
    validation_context: dict[str, Any] = {
        "framework": context.framework,
        "tool_name": context.tool_name,
        "tool_args": dict(context.tool_args),
        "session_id": context.session_id,
        "tool_call_id": context.metadata.get("tool_call_id", ""),
    }
    if preview:
        validation_context["action_description"] = (
            f"execute tool {context.tool_name} with args {preview}"
        )
        validation_context["action_detail"] = preview

    if context_builder is not None:
        extra_context = context_builder(context, request)
        if not isinstance(extra_context, dict):
            raise TypeError("context_builder must return a dict[str, Any]")
        validation_context.update(extra_context)
    return validation_context


def _decision_from_result(result: ValidationResult) -> AdapterPolicyDecision:
    metadata = _decision_metadata_from_result(result)
    rule_ids = metadata["rule_ids"]
    action_taken = metadata["action_taken"]

    if result.valid:
        if metadata["warning_count"] > 0:
            return AdapterPolicyDecision(
                allowed=True,
                state="ALLOW_WITH_CONTROLS",
                reason=_reason_for_state("ALLOW_WITH_CONTROLS", rule_ids),
                metadata=metadata,
            )
        return AdapterPolicyDecision.allow()

    state: DecisionState
    if action_taken == ViolationAction.HALT.value:
        state = "HARD_DENY"
    elif (
        action_taken
        in {
            ViolationAction.REQUIRE_HUMAN_REVIEW.value,
            ViolationAction.ESCALATE.value,
        }
        or metadata["review_count"] > 0
        or metadata["escalation_count"] > 0
    ):
        state = "STRUCTURED_REVIEW_REQUIRED"
    else:
        state = "DENY_GOAL"

    return AdapterPolicyDecision(
        allowed=False,
        state=state,
        reason=_reason_for_state(state, rule_ids),
        metadata=metadata,
    )


def _decision_from_exception(error: PolicyDeniedError) -> AdapterPolicyDecision:
    action_taken = (
        error.enforcement_action.value
        if error.enforcement_action is not None
        else ViolationAction.BLOCK.value
    )
    state: DecisionState = "DENY_GOAL"
    if error.enforcement_action is ViolationAction.HALT:
        state = "HARD_DENY"
    elif error.enforcement_action in {
        ViolationAction.REQUIRE_HUMAN_REVIEW,
        ViolationAction.ESCALATE,
    }:
        state = "STRUCTURED_REVIEW_REQUIRED"
    return AdapterPolicyDecision(
        allowed=False,
        state=state,
        reason=str(error),
        metadata={
            "rule_ids": [error.rule_id] if error.rule_id else [],
            "action_taken": action_taken,
            "exception_type": type(error).__name__,
        },
    )


def _decision_metadata_from_result(result: ValidationResult) -> dict[str, Any]:
    rule_ids = _unique_rule_ids(result)
    action_taken = result.action_taken.value if result.action_taken is not None else None
    return {
        "rule_ids": rule_ids,
        "action_taken": action_taken,
        "warning_count": len(result.warnings),
        "review_count": len(result.review_requests),
        "escalation_count": len(result.escalations),
        "incident_count": len(result.incident_alerts),
    }


def _unique_rule_ids(result: ValidationResult) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def _push(rule_id: str) -> None:
        if rule_id and rule_id not in seen:
            seen.add(rule_id)
            ordered.append(rule_id)

    for violation in result.violations:
        _push(violation.rule_id)
    for warning in result.warnings:
        _push(warning.rule_id)
    for review in result.review_requests:
        _push(review.rule_id)
    for escalation in result.escalations:
        _push(escalation.rule_id)
    for incident in result.incident_alerts:
        _push(incident.rule_id)
    return ordered


def _reason_for_state(state: str, rule_ids: list[str]) -> str:
    joined = ", ".join(rule_ids) if rule_ids else "policy"
    if state == "ALLOW_WITH_CONTROLS":
        return f"Allowed with controls from rules: {joined}."
    if state == "STRUCTURED_REVIEW_REQUIRED":
        return f"Review required by rules: {joined}."
    if state == "HARD_DENY":
        return f"Hard deny by rules: {joined}."
    return f"Blocked by rules: {joined}."


def _policy_error_from_result(
    result: ValidationResult,
    context: ToolCallContext,
    decision: AdapterPolicyDecision,
) -> PolicyDeniedError:
    policy_id = next(iter(decision.metadata.get("rule_ids", [])), None)
    enforcement_action = result.action_taken
    return PolicyDeniedError(
        decision.reason or "Denied by policy.",
        policy_id=policy_id,
        rule_id=policy_id,
        policy_hash=result.constitutional_hash,
        severity=_primary_severity(result),
        action=context.tool_name,
        enforcement_action=enforcement_action,
    )


def _policy_error_from_exception(
    error: ConstitutionalViolationError,
    *,
    action: str,
    policy_hash: str | None,
) -> PolicyDeniedError:
    if isinstance(error, PolicyDeniedError):
        return error
    return PolicyDeniedError(
        str(error),
        policy_id=error.rule_id,
        rule_id=error.rule_id,
        policy_hash=policy_hash,
        severity=error.severity,
        action=action,
        enforcement_action=error.enforcement_action,
    )


def _policy_error_from_decision(
    context: ToolCallContext,
    decision: AdapterPolicyDecision,
    *,
    policy_hash: str | None,
) -> PolicyDeniedError:
    policy_id = next(iter(decision.metadata.get("rule_ids", [])), None)
    return PolicyDeniedError(
        decision.reason or "Denied by policy.",
        policy_id=policy_id,
        rule_id=policy_id,
        policy_hash=policy_hash,
        action=context.tool_name,
    )


def _primary_severity(result: ValidationResult) -> str:
    if result.violations:
        return result.violations[0].severity.value
    if result.warnings:
        return result.warnings[0].severity.value
    return "high"


def _emit_receipt(
    sink: ExecutionReceiptSink | None,
    evaluated: _EvaluatedCall,
    *,
    execution_status: str,
    execution_error: str | None = None,
) -> None:
    if sink is None:
        return

    metadata: dict[str, Any] = {
        "tool_name": evaluated.context.tool_name,
        "framework": evaluated.context.framework,
        "session_id": evaluated.context.session_id,
        "actor_id": evaluated.context.actor_id,
        "execution_status": execution_status,
        **evaluated.context.metadata,
        **evaluated.decision.metadata,
    }
    if execution_error is not None:
        metadata["execution_error"] = execution_error

    sink.write(
        ExecutionReceipt(
            action_id=evaluated.action_id,
            action_type="tool_call",
            decision=evaluated.decision.state,
            reason=evaluated.decision.reason,
            policy_hash=evaluated.policy_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata,
        )
    )


def _deny_with_tool_message(evaluated: _EvaluatedCall) -> Any:
    denial_error = evaluated.denial_error or _policy_error_from_decision(
        evaluated.context,
        evaluated.decision,
        policy_hash=evaluated.policy_hash,
    )
    try:
        messages_module = import_module("langchain_core.messages")
        tool_message_cls = messages_module.ToolMessage
    except ModuleNotFoundError as exc:
        raise denial_error from exc

    return tool_message_cls(
        content=denial_error.args[0] if denial_error.args else "Denied by policy.",
        tool_call_id=evaluated.action_id,
        name=evaluated.context.tool_name,
        status="error",
        artifact={
            "policy_hash": denial_error.policy_hash,
            "rule_id": denial_error.rule_id,
            "decision_state": evaluated.decision.state,
        },
    )


def _engine_policy_hash(engine: GovernanceEngine) -> str | None:
    constitution = getattr(engine, "constitution", None)
    return getattr(constitution, "hash", None)


def _get_value(source: Any, key: str) -> Any:
    if isinstance(source, Mapping):
        return source.get(key)
    return getattr(source, key, None)


def _coerce_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    return {}


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return ""


__all__ = ["make_awrap_tool_call", "make_wrap_tool_call"]
