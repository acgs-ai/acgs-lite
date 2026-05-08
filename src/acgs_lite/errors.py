# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""ACGS-Lite error types."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acgs_lite.constitution.rule import ViolationAction


class GovernanceError(Exception):
    """Base error for all ACGS-Lite governance failures."""

    __slots__ = ("rule_id",)

    def __init__(self, message: str, *, rule_id: str | None = None) -> None:
        self.rule_id = rule_id
        super().__init__(message)


class ConstitutionalViolationError(GovernanceError):
    """Raised when an action violates a constitutional rule."""

    __slots__ = ("severity", "action", "enforcement_action")

    def __init__(
        self,
        message: str,
        *,
        rule_id: str,
        severity: str = "high",
        action: str = "",
        enforcement_action: ViolationAction | None = None,
    ) -> None:
        # Bypass GovernanceError.__init__ to save one Python call frame:
        # set the GovernanceError slot directly, then call Exception.__init__.
        from acgs_lite.constitution.rule import ViolationAction as _VA  # noqa: PLC0415

        self.rule_id = rule_id
        self.severity = severity
        self.action = action
        self.enforcement_action = (
            enforcement_action if enforcement_action is not None else _VA.BLOCK
        )
        Exception.__init__(self, message)


class PolicyDeniedError(ConstitutionalViolationError):
    """Raised when a policy denies an action through an adapter-facing contract."""

    __slots__ = ("policy_id", "policy_hash")

    def __init__(
        self,
        message: str,
        *,
        policy_id: str | None = None,
        rule_id: str | None = None,
        policy_hash: str | None = None,
        severity: str = "high",
        action: str = "",
        enforcement_action: ViolationAction | None = None,
    ) -> None:
        effective_rule_id = rule_id or policy_id or "policy"
        self.policy_id = policy_id
        self.policy_hash = policy_hash
        super().__init__(
            message,
            rule_id=effective_rule_id,
            severity=severity,
            action=action,
            enforcement_action=enforcement_action,
        )


class MACIViolationError(GovernanceError):
    """Raised when MACI separation of powers is violated.

    Example: A Proposer trying to validate their own proposal.
    """

    __slots__ = ("actor_role", "attempted_action")

    def __init__(
        self,
        message: str,
        *,
        actor_role: str,
        attempted_action: str,
    ) -> None:
        self.actor_role = actor_role
        self.attempted_action = attempted_action
        super().__init__(message, rule_id="MACI")
