# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Errors raised by governed agent selection.

Selection fails closed: every denial path raises a typed error rather than
returning ``None`` or a best-effort pick (CK-002, "validation failures raise").
Each error carries the denied :class:`~acgs_lite.legitimacy.receipt.DecisionReceipt`
so the refusal is itself auditable.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from acgs_lite.errors import ConstitutionalViolationError, GovernanceError

if TYPE_CHECKING:
    from acgs_lite.constitution.rule import ViolationAction
    from acgs_lite.legitimacy.receipt import DecisionReceipt


class SelectionDeniedError(ConstitutionalViolationError):
    """Raised when governance refuses to authorize any agent selection.

    Covers a missing governance state, a constitutional violation in the task, or
    a required MACI role with no enforcer configured.
    """

    __slots__ = ("receipt",)

    def __init__(
        self,
        message: str,
        *,
        rule_id: str = "agent-selection",
        receipt: DecisionReceipt | None = None,
        severity: str = "high",
        action: str = "",
        enforcement_action: ViolationAction | None = None,
    ) -> None:
        self.receipt = receipt
        super().__init__(
            message,
            rule_id=rule_id,
            severity=severity,
            action=action,
            enforcement_action=enforcement_action,
        )


class NoEligibleAgentError(GovernanceError):
    """Raised when no registered agent is both suitable and MACI-eligible.

    This is the fail-closed outcome when the registry is empty, no profile matches
    the task, or every match is filtered out by MACI checks -- never a silent
    fallback to an unsuitable agent.
    """

    __slots__ = ("receipt",)

    def __init__(
        self,
        message: str,
        *,
        receipt: DecisionReceipt | None = None,
        rule_id: str = "agent-selection",
    ) -> None:
        self.receipt = receipt
        super().__init__(message, rule_id=rule_id)


__all__ = ["NoEligibleAgentError", "SelectionDeniedError"]
