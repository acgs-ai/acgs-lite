"""ACGS-lite engine for AMD GAIA's optional governance layer.

GAIA documents ``PolicyEngine`` as a Protocol and names ACGS-lite as the
intended production swap for the in-repo ``RuleBasedPolicyEngine`` stub.
This module implements that Protocol (and the three companion seams)
without importing ``gaia`` — the types are duck-typed so GAIA can stay
an optional, AMD-owned dependency.

Usage with GAIA::

    from acgs_lite.integrations.gaia import build_gaia_components
    from gaia.governance import GaiaGovernanceAdapter, GovernedAgentMixin

    engine, checkpoints, receipts, binding = build_gaia_components()
    adapter = GaiaGovernanceAdapter(engine, checkpoints, receipts, binding)

GAIA's ``@govern(risk=...)`` tags remain a floor: a constitution may only
tighten a decision (ALLOW → REVIEW/BLOCK). ``GAIA_AUTO_APPROVE_TOOLS`` is
never consulted.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.engine import GovernanceEngine
from acgs_lite.engine.models import ValidationResult
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.serialization import serialize_for_governance

logger = logging.getLogger(__name__)

CONSTITUTIONAL_HASH = "608508a9bd224290"

DecisionType = Literal["ALLOW", "REVIEW", "BLOCK"]
CheckpointStatus = Literal["OPEN", "APPROVED", "REJECTED", "ESCALATED", "TIMEOUT_REJECTED"]
TransitionStatus = Literal["CONTINUE", "CHECKPOINT_OPEN", "TERMINATED", "RESUMED"]
ResolutionType = Literal["APPROVE", "REJECT", "ESCALATE", "TIMEOUT_REJECT"]

_BLOCKING_ACTIONS = {
    ViolationAction.BLOCK,
    ViolationAction.BLOCK_AND_NOTIFY,
    ViolationAction.HALT,
}
_REVIEW_ACTIONS = {
    ViolationAction.REQUIRE_HUMAN_REVIEW,
    ViolationAction.ESCALATE,
}

# AMD's confirmation UX is welcome; this env var is not a policy bypass.
_AUTO_APPROVE_ENV = "GAIA_AUTO_APPROVE_TOOLS"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


@dataclass(frozen=True, slots=True)
class GovernanceDecision:
    """Duck-typed match for ``gaia.governance.schemas.GovernanceDecision``."""

    decision: DecisionType
    reason: str
    policy_version: str
    rule_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CheckpointRecord:
    checkpoint_id: str
    workflow_id: str
    transition_id: str
    status: CheckpointStatus
    created_at: str
    decision_context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TransitionOutcome:
    status: TransitionStatus
    reason: str
    checkpoint_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PolicyVersionRef:
    version: str
    constitution_hash: str
    activated_at: str


@dataclass(frozen=True, slots=True)
class ReceiptRecord:
    receipt_id: str
    workflow_id: str
    checkpoint_id: str | None
    decision: str
    policy_version: str
    actor_id: str | None
    validator_set_id: str | None
    created_at: str
    payload_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)


def _as_mapping(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return dict(value)
    return None


def _action_text(request: Any) -> str:
    tool_name = str(getattr(request, "tool_name", "") or "")
    action_type = str(getattr(request, "action_type", "") or "")
    actor_id = str(getattr(request, "actor_id", "") or "")
    tags = list(getattr(request, "risk_tags", []) or [])
    args = _as_mapping(getattr(request, "args", None)) or {}
    payload = serialize_for_governance(
        {
            "tool_name": tool_name,
            "action_type": action_type,
            "actor_id": actor_id,
            "risk_tags": tags,
            "args": args,
        }
    )
    return f"gaia tool={tool_name} type={action_type} actor={actor_id} {payload}"


def _rule_ids_from_result(result: ValidationResult) -> list[str]:
    seen: list[str] = []
    for group in (result.violations, result.warnings):
        for item in group:
            rule_id = getattr(item, "rule_id", "")
            if rule_id and rule_id not in seen:
                seen.append(rule_id)
    return seen


def _decision_from_result(
    result: ValidationResult,
    *,
    policy_version: str,
    extra_rule_ids: list[str] | None = None,
) -> GovernanceDecision:
    rule_ids = _rule_ids_from_result(result)
    for extra in extra_rule_ids or []:
        if extra not in rule_ids:
            rule_ids.append(extra)

    metadata = {
        "constitutional_hash": result.constitutional_hash,
        "valid": result.valid,
        "action_taken": (result.action_taken.value if result.action_taken is not None else None),
        "request_id": result.request_id,
    }

    if result.action_taken in _BLOCKING_ACTIONS or (
        not result.valid and result.blocking_violations
    ):
        reason = result.violations[0].rule_text if result.violations else "blocked by constitution"
        return GovernanceDecision(
            decision="BLOCK",
            reason=reason,
            policy_version=policy_version,
            rule_ids=rule_ids,
            metadata=metadata,
        )

    if result.action_taken in _REVIEW_ACTIONS or result.review_requests or result.escalations:
        reason = "requires operator review"
        if result.review_requests:
            reason = getattr(result.review_requests[0], "reason", reason) or reason
        elif result.escalations:
            reason = getattr(result.escalations[0], "reason", reason) or reason
        return GovernanceDecision(
            decision="REVIEW",
            reason=str(reason),
            policy_version=policy_version,
            rule_ids=rule_ids,
            metadata=metadata,
        )

    return GovernanceDecision(
        decision="ALLOW",
        reason="allowed by constitution",
        policy_version=policy_version,
        rule_ids=rule_ids,
        metadata=metadata,
    )


def _apply_risk_tag_floor(
    decision: GovernanceDecision,
    request: Any,
    *,
    policy_version: str,
) -> GovernanceDecision:
    """Honor GAIA decorator/dict tags as a floor; never loosen a BLOCK."""

    tags = {str(tag).lower() for tag in (getattr(request, "risk_tags", []) or [])}
    if decision.decision == "BLOCK":
        return decision
    if "blocked" in tags:
        rule_ids = list(decision.rule_ids)
        if "gaia:risk-tag:blocked" not in rule_ids:
            rule_ids.append("gaia:risk-tag:blocked")
        return GovernanceDecision(
            decision="BLOCK",
            reason="blocked by GAIA risk tag",
            policy_version=policy_version,
            rule_ids=rule_ids,
            metadata={**decision.metadata, "risk_tag_floor": "blocked"},
        )
    if decision.decision == "REVIEW":
        return decision
    if "review" in tags:
        rule_ids = list(decision.rule_ids)
        if "gaia:risk-tag:review" not in rule_ids:
            rule_ids.append("gaia:risk-tag:review")
        return GovernanceDecision(
            decision="REVIEW",
            reason="requires operator review (GAIA risk tag)",
            policy_version=policy_version,
            rule_ids=rule_ids,
            metadata={**decision.metadata, "risk_tag_floor": "review"},
        )
    return decision


class AcgsLitePolicyEngine:
    """Production-shaped ``PolicyEngine`` for AMD GAIA.

    Fail-closed: malformed requests, engine exceptions, and missing tool
    names become ``BLOCK``. Auto-approve environment variables are ignored.
    """

    def __init__(
        self,
        constitution: Constitution | None = None,
        *,
        engine: GovernanceEngine | None = None,
        audit_log: AuditLog | None = None,
        agent_id: str = "gaia-agent",
    ) -> None:
        if engine is not None:
            self.engine = engine
            self.constitution = engine.constitution
        else:
            self.constitution = constitution or Constitution.default()
            self.engine = GovernanceEngine(
                self.constitution,
                audit_log=audit_log if audit_log is not None else AuditLog(),
                strict=True,
            )
        self.agent_id = agent_id

    @property
    def policy_version(self) -> str:
        version = getattr(self.constitution, "version", None) or "1.0.0"
        return str(version)

    def evaluate_action(self, action_request: Any) -> GovernanceDecision:
        if os.environ.get(_AUTO_APPROVE_ENV):
            logger.info(
                "ignoring %s; ACGS-lite does not treat auto-approve as policy",
                _AUTO_APPROVE_ENV,
            )

        try:
            return self._evaluate_action(action_request)
        except ConstitutionalViolationError as exc:
            return _apply_risk_tag_floor(
                self._decision_from_violation(exc),
                action_request,
                policy_version=self.policy_version,
            )
        except Exception:
            logger.exception("GAIA policy evaluation failed closed")
            return GovernanceDecision(
                decision="BLOCK",
                reason="policy evaluation failed closed",
                policy_version=self.policy_version,
                rule_ids=["acgs:fail-closed"],
                metadata={"fail_closed": True},
            )

    def _decision_from_violation(self, exc: ConstitutionalViolationError) -> GovernanceDecision:
        rule_ids = [exc.rule_id] if exc.rule_id else []
        enforcement = exc.enforcement_action
        rule = None
        if exc.rule_id:
            rule = next(
                (item for item in self.constitution.rules if item.id == exc.rule_id),
                None,
            )
        if rule is not None:
            enforcement = rule.workflow_action
        if enforcement in _REVIEW_ACTIONS:
            return GovernanceDecision(
                decision="REVIEW",
                reason=str(exc),
                policy_version=self.policy_version,
                rule_ids=rule_ids,
                metadata={"enforcement_action": getattr(enforcement, "value", None)},
            )
        return GovernanceDecision(
            decision="BLOCK",
            reason=str(exc),
            policy_version=self.policy_version,
            rule_ids=rule_ids,
            metadata={"enforcement_action": getattr(enforcement, "value", None)},
        )

    def _evaluate_action(self, action_request: Any) -> GovernanceDecision:
        tool_name = str(getattr(action_request, "tool_name", "") or "").strip()
        if not tool_name:
            return GovernanceDecision(
                decision="BLOCK",
                reason="missing tool_name",
                policy_version=self.policy_version,
                rule_ids=["acgs:malformed-request"],
                metadata={"fail_closed": True},
            )

        args = _as_mapping(getattr(action_request, "args", None))
        if args is None:
            return GovernanceDecision(
                decision="BLOCK",
                reason="tool args must be a mapping",
                policy_version=self.policy_version,
                rule_ids=["acgs:malformed-request"],
                metadata={"fail_closed": True},
            )

        actor_id = str(getattr(action_request, "actor_id", "") or self.agent_id)
        context = {
            "action_description": tool_name,
            "action_detail": serialize_for_governance(args),
            "tool_name": tool_name,
            "tool_args": args,
            "actor_id": actor_id,
            "action_id": str(getattr(action_request, "action_id", "") or ""),
            "action_type": str(getattr(action_request, "action_type", "") or ""),
            "risk_tags": list(getattr(action_request, "risk_tags", []) or []),
            "workflow_id": getattr(action_request, "workflow_id", None),
            "source": str(getattr(action_request, "source", "gaia") or "gaia"),
        }
        result = self.engine.validate(
            _action_text(action_request),
            agent_id=actor_id,
            context=context,
            audit_metadata={
                "source": "amd-gaia",
                "tool_name": tool_name,
                "action_id": context["action_id"],
            },
            strict=True,
        )
        decision = _decision_from_result(result, policy_version=self.policy_version)
        return _apply_risk_tag_floor(decision, action_request, policy_version=self.policy_version)


class AcgsLitePolicyBinding:
    """Stamp receipts with the live constitution hash."""

    def __init__(self, constitution: Constitution) -> None:
        self._constitution = constitution
        self._activated_at = _utc_now_iso()

    def current_version(self) -> PolicyVersionRef:
        return PolicyVersionRef(
            version=str(getattr(self._constitution, "version", None) or "1.0.0"),
            constitution_hash=str(self._constitution.hash),
            activated_at=self._activated_at,
        )


class AcgsLiteCheckpointRuntime:
    """In-process checkpoints with workflow binding.

    ``get_checkpoint`` is the duck-typed hook GAIA uses to refuse a
    resolution under the wrong ``workflow_id``.
    """

    def __init__(self) -> None:
        self._records: dict[str, CheckpointRecord] = {}

    def create_checkpoint(self, transition: Any, decision: Any) -> CheckpointRecord:
        workflow_id = str(getattr(transition, "workflow_id", "") or "")
        if not workflow_id:
            raise ValueError("checkpoint requires workflow_id")
        record = CheckpointRecord(
            checkpoint_id=_new_id("cp"),
            workflow_id=workflow_id,
            transition_id=str(getattr(transition, "transition_id", "") or ""),
            status="OPEN",
            created_at=_utc_now_iso(),
            decision_context={
                "decision": getattr(decision, "decision", ""),
                "reason": getattr(decision, "reason", ""),
                "related_action_id": getattr(transition, "related_action_id", None),
            },
        )
        self._records[record.checkpoint_id] = record
        return record

    def get_checkpoint(self, checkpoint_id: str) -> CheckpointRecord | None:
        return self._records.get(checkpoint_id)

    def resolve_checkpoint(self, checkpoint_id: str, resolution: Any) -> TransitionOutcome:
        record = self._records.get(checkpoint_id)
        if record is None:
            return TransitionOutcome(
                status="TERMINATED",
                reason=f"unknown checkpoint {checkpoint_id}",
                checkpoint_id=checkpoint_id,
                metadata={"fail_closed": True},
            )
        if record.status != "OPEN":
            return TransitionOutcome(
                status="TERMINATED",
                reason=f"checkpoint {checkpoint_id} already {record.status}",
                checkpoint_id=checkpoint_id,
                metadata={"fail_closed": True},
            )

        label = str(getattr(resolution, "resolution", "") or "")
        if label == "APPROVE":
            self._records[checkpoint_id] = CheckpointRecord(
                checkpoint_id=record.checkpoint_id,
                workflow_id=record.workflow_id,
                transition_id=record.transition_id,
                status="APPROVED",
                created_at=record.created_at,
                decision_context=record.decision_context,
            )
            return TransitionOutcome(
                status="RESUMED",
                reason=str(getattr(resolution, "reason", "") or "reviewer approved"),
                checkpoint_id=checkpoint_id,
            )
        if label in {"REJECT", "TIMEOUT_REJECT"}:
            status: CheckpointStatus = (
                "TIMEOUT_REJECTED" if label == "TIMEOUT_REJECT" else "REJECTED"
            )
            self._records[checkpoint_id] = CheckpointRecord(
                checkpoint_id=record.checkpoint_id,
                workflow_id=record.workflow_id,
                transition_id=record.transition_id,
                status=status,
                created_at=record.created_at,
                decision_context=record.decision_context,
            )
            return TransitionOutcome(
                status="TERMINATED",
                reason=str(getattr(resolution, "reason", "") or "reviewer rejected"),
                checkpoint_id=checkpoint_id,
            )

        # ESCALATE and anything unknown: do not execute.
        return TransitionOutcome(
            status="TERMINATED",
            reason=f"unsupported resolution {label!r}; failing closed",
            checkpoint_id=checkpoint_id,
            metadata={"fail_closed": True},
        )


class AcgsLiteReceiptService:
    """Stores GAIA receipt records and mirrors them onto an ACGS audit log."""

    def __init__(self, audit_log: AuditLog | None = None) -> None:
        self.audit_log = audit_log if audit_log is not None else AuditLog()
        self._records: dict[str, Any] = {}

    def issue_receipt(self, record: Any) -> str:
        receipt_id = str(getattr(record, "receipt_id", "") or _new_id("rcpt"))
        self._records[receipt_id] = record
        payload = {
            "receipt_id": receipt_id,
            "workflow_id": getattr(record, "workflow_id", None),
            "checkpoint_id": getattr(record, "checkpoint_id", None),
            "decision": getattr(record, "decision", None),
            "policy_version": getattr(record, "policy_version", None),
            "actor_id": getattr(record, "actor_id", None),
            "payload_hash": getattr(record, "payload_hash", None),
            "created_at": getattr(record, "created_at", None),
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        try:
            self.audit_log.record(
                AuditEntry(
                    id=receipt_id,
                    type="gaia_receipt",
                    agent_id=str(payload["actor_id"] or "gaia"),
                    action=str(payload["decision"] or ""),
                    valid=str(payload["decision"] or "") in {"ALLOW", "APPROVE"},
                    constitutional_hash=str(
                        getattr(record, "metadata", {}).get("constitution_hash", "")
                        if isinstance(getattr(record, "metadata", None), dict)
                        else ""
                    ),
                    metadata={
                        "source": "amd-gaia",
                        "receipt_id": receipt_id,
                        "payload_hash": payload["payload_hash"],
                        "digest": digest,
                        "workflow_id": payload["workflow_id"],
                    },
                )
            )
        except Exception:
            logger.exception("failed to append GAIA receipt to ACGS audit log")
        return receipt_id

    def get_receipt(self, receipt_id: str) -> Any:
        record = self._records.get(receipt_id)
        if record is None:
            raise KeyError(receipt_id)
        return record


def build_gaia_components(
    constitution: Constitution | None = None,
    *,
    audit_log: AuditLog | None = None,
    agent_id: str = "gaia-agent",
) -> tuple[
    AcgsLitePolicyEngine,
    AcgsLiteCheckpointRuntime,
    AcgsLiteReceiptService,
    AcgsLitePolicyBinding,
]:
    """Return the four objects ``GaiaGovernanceAdapter`` composes."""

    log = audit_log if audit_log is not None else AuditLog()
    engine = AcgsLitePolicyEngine(
        constitution,
        audit_log=log,
        agent_id=agent_id,
    )
    return (
        engine,
        AcgsLiteCheckpointRuntime(),
        AcgsLiteReceiptService(log),
        AcgsLitePolicyBinding(engine.constitution),
    )


__all__ = [
    "AcgsLiteCheckpointRuntime",
    "AcgsLitePolicyBinding",
    "AcgsLitePolicyEngine",
    "AcgsLiteReceiptService",
    "CheckpointRecord",
    "GovernanceDecision",
    "PolicyVersionRef",
    "ReceiptRecord",
    "TransitionOutcome",
    "build_gaia_components",
]
