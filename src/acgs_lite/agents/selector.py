# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Governed task-to-agent selection.

:class:`GovernedAgentSelector` answers "which agent should take this task?" as a
*governed* decision, reusing the Runtime Legitimacy Kernel rather than forking a
parallel decision path:

* **Fail-closed** -- a missing governance state, an empty/non-matching registry, a
  constitutional violation, or a required MACI role with no enforcer each raise a
  typed error carrying the denied receipt. There is no silent "best guess".
* **Receipted** -- an authorized selection returns a :class:`DecisionReceipt` bound
  to the chosen agent via an :class:`ExecutionBoundary`, optionally Ed25519-signed
  and replay-verifiable.
* **MACI-respecting** -- the chosen agent's role must permit the required action,
  and a requester can never be selected as its own validator. MACI is never
  bypassed: a required role with no enforcer fails closed.

This module does not import or alter the governance hot-path
``engine/matcher.py`` -- ranking is independent, pure-Python lexical scoring.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from acgs_lite.agents.errors import NoEligibleAgentError, SelectionDeniedError
from acgs_lite.agents.registry import AgentRegistry
from acgs_lite.errors import ConstitutionalViolationError, MACIViolationError
from acgs_lite.legitimacy.decide import DecisionState
from acgs_lite.legitimacy.receipt import (
    BASELINE_CONSTRAINT_MARKER,
    DecisionReceipt,
    ExecutionBoundary,
)
from acgs_lite.maci.roles import MACIRole

if TYPE_CHECKING:
    from acgs_lite.agents.capability import AgentCapabilityProfile
    from acgs_lite.engine.core import GovernanceEngine
    from acgs_lite.legitimacy.signing import ReceiptSigner, SignedReceipt
    from acgs_lite.maci.enforcer import MACIEnforcer

# The canonical MACI action verb a candidate's role must permit for each filled role.
_ROLE_ACTION: dict[MACIRole, str] = {
    MACIRole.PROPOSER: "propose",
    MACIRole.VALIDATOR: "validate",
    MACIRole.EXECUTOR: "execute",
    MACIRole.OBSERVER: "read",
}


@dataclass(slots=True, frozen=True)
class AgentSelection:
    """The governed outcome of selecting an agent for a task."""

    selected_agent_id: str
    decision: Literal["ALLOW"]  # AgentSelection is only ever an authorized outcome
    receipt: DecisionReceipt
    signed_receipt: SignedReceipt | None
    candidates: tuple[tuple[str, float], ...]
    rationale: str


class GovernedAgentSelector:
    """Select the most suitable agent for a task under constitutional governance."""

    def __init__(
        self,
        *,
        registry: AgentRegistry,
        engine: GovernanceEngine | None,
        maci_enforcer: MACIEnforcer | None = None,
        signer: ReceiptSigner | None = None,
        policy_version: str | None = None,
    ) -> None:
        self._registry = registry
        self._engine = engine
        self._maci = maci_enforcer
        self._signer = signer
        constitution = getattr(engine, "constitution", None) if engine is not None else None
        resolved_version = policy_version or (
            str(getattr(constitution, "version", "")) if constitution is not None else ""
        )
        self._policy_version = resolved_version
        self._authority_basis = (
            f"constitution:{getattr(constitution, 'name', 'unknown')}@{resolved_version}"
            if constitution is not None
            else "UNCONFIGURED"
        )

    def select(
        self,
        task: str,
        *,
        requester_id: str = "anonymous",
        required_role: MACIRole | None = None,
        domain: str | None = None,
        candidates: list[AgentCapabilityProfile] | None = None,
    ) -> AgentSelection:
        """Return an :class:`AgentSelection` for ``task`` or fail closed.

        Raises :class:`SelectionDeniedError` when governance refuses the task and
        :class:`NoEligibleAgentError` when no suitable, MACI-eligible agent exists.
        Both errors carry the denied receipt.
        """
        # 0. Reject an empty/blank task up front, failing closed with a typed error
        #    and receipt. A blank goal would otherwise crash DecisionReceipt.create
        #    (it requires a non-empty goal), turning a denial into a raw ValueError.
        if not task or not task.strip():
            raise SelectionDeniedError(
                "agent selection requires a non-empty task description",
                rule_id="empty-task",
                receipt=self._denied_receipt(
                    "<empty-task>",
                    decision="HARD_DENY",
                    constraints=("EMPTY_TASK",),
                    rationale="An empty or whitespace-only task cannot be governed or routed.",
                    domain=domain,
                    policy_version=self._policy_version or "UNVERSIONED_POLICY",
                ),
            )

        # 1. Fail-closed governance-state guard.
        if self._engine is None or not self._policy_version:
            raise SelectionDeniedError(
                "agent selection requires a configured governance engine and policy version",
                rule_id="governance-state-missing",
                receipt=self._denied_receipt(
                    task,
                    decision="HARD_DENY",
                    constraints=("GOVERNANCE_STATE_MISSING",),
                    rationale="No constitution / policy version available for the selector.",
                    domain=domain,
                    policy_version=self._policy_version or "UNVERSIONED_POLICY",
                ),
            )

        # 2. Constitutional check on the task itself, before any agent is considered
        #    (raise-on-violation, CK-002). An unconstitutional task is denied even
        #    when a matching agent exists -- the task is governed first.
        #
        #    `strict=True` is forced on the call so a non-strict engine (a supported
        #    per-instance mode where validate() returns valid=False instead of
        #    raising) cannot fail open. The returned result is *also* inspected as
        #    defense in depth -- the selector never trusts the engine's instance
        #    strict flag, and never relies on the exception side-effect alone.
        try:
            result = self._engine.validate(
                task,
                agent_id=requester_id,
                context={"domain": domain} if domain else None,
                strict=True,
            )
        except ConstitutionalViolationError as exc:
            receipt = self._denied_receipt(
                task,
                decision="HARD_DENY",
                constraints=(exc.rule_id or BASELINE_CONSTRAINT_MARKER,),
                rationale=f"Task violates constitutional rule {exc.rule_id}: {exc}",
                domain=domain,
            )
            raise SelectionDeniedError(
                f"task denied by constitution before agent selection: {exc}",
                rule_id=exc.rule_id or "agent-selection",
                receipt=receipt,
                severity=getattr(exc, "severity", "high"),
            ) from exc
        if result is not None and getattr(result, "valid", True) is False:
            blocking = list(getattr(result, "blocking_violations", None) or [])
            denied_rule = blocking[0].rule_id if blocking else "constitutional-violation"
            receipt = self._denied_receipt(
                task,
                decision="HARD_DENY",
                constraints=(denied_rule,),
                rationale="Task failed constitutional validation (engine returned an invalid result).",
                domain=domain,
            )
            raise SelectionDeniedError(
                "task denied by constitution before agent selection",
                rule_id=denied_rule,
                receipt=receipt,
            )

        # 3. Rank candidates (pure-Python lexical scoring).
        ranked = self._rank(task, domain=domain, candidates=candidates)
        if not ranked:
            raise NoEligibleAgentError(
                f"no registered agent matches task: {task!r}",
                receipt=self._denied_receipt(
                    task,
                    decision="DENY_OPERATION_WITH_ALTERNATIVE",
                    constraints=("NO_MATCHING_AGENT",),
                    rationale="The registry held no agent whose capabilities match the task.",
                    domain=domain,
                ),
            )

        # 4. MACI gating. A required role with no enforcer fails closed (never bypass).
        if required_role is not None and self._maci is None:
            raise SelectionDeniedError(
                f"selecting a {required_role.value} requires a MACI enforcer; refusing to bypass",
                rule_id="MACI",
                receipt=self._denied_receipt(
                    task,
                    decision="STRUCTURED_REVIEW_REQUIRED",
                    constraints=("MACI_ENFORCER_REQUIRED",),
                    rationale="A MACI role was required but no enforcer was configured.",
                    domain=domain,
                ),
            )

        selected = self._first_eligible(
            ranked, requester_id=requester_id, required_role=required_role
        )
        if selected is None:
            raise NoEligibleAgentError(
                "no candidate satisfied MACI role and separation-of-powers checks",
                receipt=self._denied_receipt(
                    task,
                    decision="DENY_OPERATION_WITH_ALTERNATIVE",
                    constraints=("NO_MACI_ELIGIBLE_AGENT",),
                    rationale="Every ranked candidate was filtered out by MACI checks.",
                    domain=domain,
                ),
            )

        # 5. Authorized selection -> bound receipt.
        agent_id = selected.agent_id
        receipt = DecisionReceipt.create(
            request_id=uuid.uuid4().hex,
            goal=task,
            proposed_method=f"delegate:{agent_id}",
            decision_type="ALLOW",
            authority_basis=self._authority_basis,
            matched_constraints=(BASELINE_CONSTRAINT_MARKER,),
            policy_version=self._policy_version,
            execution_boundary=ExecutionBoundary(
                allowed_method=f"delegate:{agent_id}",
                allowed_scope=domain,
                allowed_subjects=(agent_id,),
                expires_at=None,
                single_use=False,
            ),
        )
        signed: SignedReceipt | None = None
        if self._signer is not None:
            # Lazy: only import the signing surface when a signer is actually used.
            from acgs_lite.legitimacy.signing import sign_receipt

            signed = sign_receipt(receipt, self._signer)
        role_note = f" as {required_role.value}" if required_role is not None else ""
        return AgentSelection(
            selected_agent_id=agent_id,
            decision="ALLOW",
            receipt=receipt,
            signed_receipt=signed,
            candidates=tuple((profile.agent_id, score) for profile, score in ranked),
            rationale=f"Selected {agent_id}{role_note} (top governed candidate of {len(ranked)}).",
        )

    # -- internals ---------------------------------------------------------------

    def _rank(
        self,
        task: str,
        *,
        domain: str | None,
        candidates: list[AgentCapabilityProfile] | None,
    ) -> list[tuple[AgentCapabilityProfile, float]]:
        if candidates is None:
            return self._registry.candidates_for(task, domain=domain)
        # Caller-supplied candidates: apply the same active-only filter the registry
        # path applies, then defer to the shared ranking core (no duplicated loop).
        active = [profile for profile in candidates if profile.is_active]
        return AgentRegistry.rank_profiles(active, task, domain=domain)

    def _first_eligible(
        self,
        ranked: list[tuple[AgentCapabilityProfile, float]],
        *,
        requester_id: str,
        required_role: MACIRole | None,
    ) -> AgentCapabilityProfile | None:
        if required_role is None or self._maci is None:
            return ranked[0][0]
        action_verb = _ROLE_ACTION[required_role]
        for profile, _score in ranked:
            try:
                self._maci.check(profile.agent_id, action_verb)
            except MACIViolationError:
                continue
            if required_role is MACIRole.VALIDATOR:
                try:
                    self._maci.check_no_self_validation(requester_id, profile.agent_id)
                except MACIViolationError:
                    continue
            return profile
        return None

    def _denied_receipt(
        self,
        task: str,
        *,
        decision: DecisionState,
        constraints: tuple[str, ...],
        rationale: str,
        domain: str | None,
        policy_version: str | None = None,
    ) -> DecisionReceipt:
        return DecisionReceipt.create(
            request_id=uuid.uuid4().hex,
            goal=task,
            proposed_method="select_agent",
            decision_type=decision,
            authority_basis=self._authority_basis,
            matched_constraints=constraints,
            policy_version=policy_version or self._policy_version or "UNVERSIONED_POLICY",
            denial_or_review_rationale=rationale,
            execution_boundary=ExecutionBoundary(
                allowed_method=None,
                allowed_scope=domain,
                allowed_subjects=(),
                expires_at=None,
                single_use=True,
            ),
        )


__all__ = ["AgentSelection", "GovernedAgentSelector"]
