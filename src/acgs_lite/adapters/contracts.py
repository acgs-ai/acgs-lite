"""Neutral adapter contracts with no optional framework dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from acgs_lite.legitimacy.decide import DecisionState as DecisionState

__all__ = [
    "AdapterPolicyDecision",
    "DecisionState",
    "ExecutionReceipt",
    "ExecutionReceiptSink",
    "ToolCallContext",
]


@dataclass(slots=True)
class AdapterPolicyDecision:
    """Adapter-facing policy decision."""

    allowed: bool
    state: DecisionState
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def allow(cls) -> AdapterPolicyDecision:
        return cls(allowed=True, state="ALLOW")

    @classmethod
    def deny(cls, reason: str | None = None, **metadata: Any) -> AdapterPolicyDecision:
        return cls(
            allowed=False,
            state="DENY_GOAL",
            reason=reason,
            metadata=dict(metadata),
        )

    @classmethod
    def require_review(
        cls,
        reason: str | None = None,
        **metadata: Any,
    ) -> AdapterPolicyDecision:
        return cls(
            allowed=False,
            state="STRUCTURED_REVIEW_REQUIRED",
            reason=reason,
            metadata=dict(metadata),
        )


@dataclass(slots=True)
class ToolCallContext:
    """Framework-neutral tool call context for adapter policy checks."""

    tool_name: str
    tool_args: dict[str, Any]
    framework: str
    session_id: str = ""
    actor_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ExecutionReceipt:
    """Framework-neutral execution receipt emitted by adapters."""

    action_id: str
    action_type: str
    decision: DecisionState
    reason: str | None = None
    policy_hash: str | None = None
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ExecutionReceiptSink(Protocol):
    """Receives adapter execution receipts."""

    def write(self, receipt: ExecutionReceipt) -> None:
        """Persist or forward an execution receipt."""
