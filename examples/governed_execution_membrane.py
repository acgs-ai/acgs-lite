"""Governed execution membrane example.

This example keeps side effects in memory, but treats them like real tool calls:
an agent proposes an action, ACGS checks the action under a versioned
constitution, a receipt is issued, and the executor refuses to run without a
valid receipt.

Run:
    python examples/governed_execution_membrane.py
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from acgs_lite import Constitution, Rule, Severity
from acgs_lite.audit import AuditLog
from acgs_lite.engine import GovernanceEngine
from acgs_lite.legitimacy import (
    ActualCall,
    DecisionReceipt,
    ExecutionBoundary,
    LegitimacyInvariantError,
    validate_receipt_for_execution,
)

DecisionState = Literal["ALLOW", "DENY", "TRANSFORM"]

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


@dataclass(frozen=True)
class ProposedAction:
    """A framework-neutral side-effect proposal from an agent runtime."""

    method: str
    tenant: str
    subject: str
    body: str

    def policy_text(self) -> str:
        return (
            f"method={self.method}; tenant={self.tenant}; subject={self.subject}; body={self.body}"
        )


@dataclass(frozen=True)
class RuntimeDecision:
    """The membrane's decision plus the receipt an executor must verify."""

    state: DecisionState
    action: ProposedAction
    receipt: DecisionReceipt


class ConstitutionalMembrane:
    """Tiny framework-neutral authorization layer around GovernanceEngine."""

    def __init__(self, constitution: Constitution, audit_log: AuditLog) -> None:
        self.constitution = constitution
        self.audit_log = audit_log
        self.engine = GovernanceEngine(
            constitution,
            audit_log=audit_log,
            strict=False,
            audit_mode="full",
        )
        self.policy_version = f"{constitution.version}:{constitution.hash}"

    def authorize(self, action: ProposedAction) -> RuntimeDecision:
        result = self.engine.validate(action.policy_text(), agent_id="runtime")
        if result.valid:
            return RuntimeDecision("ALLOW", action, self._receipt("ALLOW", action, ("matched",)))

        rule_ids = tuple(v.rule_id for v in result.violations) or ("denied",)
        if "no-raw-ssn" in rule_ids:
            transformed = ProposedAction(
                method=action.method,
                tenant=action.tenant,
                subject=action.subject,
                body=SSN_RE.sub("[REDACTED-SSN]", action.body),
            )
            transformed_result = self.engine.validate(
                transformed.policy_text(),
                agent_id="runtime:transform",
            )
            if transformed_result.valid:
                return RuntimeDecision(
                    "TRANSFORM",
                    transformed,
                    self._receipt(
                        "ALLOW",
                        transformed,
                        rule_ids,
                        transformation_applied="redacted SSN before execution",
                    ),
                )

        return RuntimeDecision(
            "DENY",
            action,
            self._receipt(
                "DENY_GOAL",
                action,
                rule_ids,
                rationale="constitutional policy denied the proposed side effect",
            ),
        )

    def _receipt(
        self,
        decision_type: str,
        action: ProposedAction,
        matched_constraints: tuple[str, ...],
        *,
        transformation_applied: str | None = None,
        rationale: str | None = None,
    ) -> DecisionReceipt:
        return DecisionReceipt.create(
            request_id=f"{action.method}:{action.subject}:{decision_type}",
            goal="govern a side-effectful tool call",
            proposed_method=action.method,
            decision_type=decision_type,
            authority_basis="demo:versioned-constitution",
            matched_constraints=matched_constraints,
            policy_version=self.policy_version,
            transformation_applied=transformation_applied,
            denial_or_review_rationale=rationale,
            execution_boundary=ExecutionBoundary(
                allowed_method=action.method,
                allowed_scope=action.tenant,
                allowed_subjects=(action.subject,),
                expires_at=None,
                single_use=True,
            ),
        )


class ReceiptCheckingExecutor:
    """Executor that performs no side effect until receipt validation passes."""

    def __init__(self) -> None:
        self.outbox: list[ProposedAction] = []

    def execute(self, action: ProposedAction, receipt: DecisionReceipt | None) -> str:
        validate_receipt_for_execution(
            receipt,
            actual_call=ActualCall(
                method=action.method,
                scope=action.tenant,
                subjects=(action.subject,),
            ),
        )
        self.outbox.append(action)
        return "executed"


def make_constitution() -> Constitution:
    return Constitution(
        name="agent-tool-membrane",
        version="2026.05",
        rules=[
            Rule(
                id="no-raw-ssn",
                text="Raw SSNs must not be sent to tools",
                severity=Severity.HIGH,
                patterns=[SSN_RE.pattern],
            ),
            Rule(
                id="no-wire-transfer",
                text="Wire transfers require a separate approval workflow",
                severity=Severity.CRITICAL,
                keywords=["wire transfer"],
            ),
        ],
    )


def run_demo() -> dict[str, object]:
    audit_log = AuditLog()
    membrane = ConstitutionalMembrane(make_constitution(), audit_log)
    executor = ReceiptCheckingExecutor()

    proposals = [
        ProposedAction("send_email", "tenant-a", "customer-1", "Your invoice is ready."),
        ProposedAction("send_email", "tenant-a", "customer-2", "SSN 123-45-6789 is on file."),
        ProposedAction("wire_transfer", "tenant-a", "account-7", "wire transfer $1000"),
    ]

    decisions = [membrane.authorize(action) for action in proposals]
    denied_blocked = False
    for decision in decisions:
        try:
            executor.execute(decision.action, decision.receipt)
        except LegitimacyInvariantError:
            if decision.state == "DENY":
                denied_blocked = True

    receiptless_blocked = False
    try:
        executor.execute(proposals[0], None)
    except LegitimacyInvariantError:
        receiptless_blocked = True

    audit_entries = audit_log.entries
    return {
        "decisions": [decision.state for decision in decisions],
        "outbox": [action.policy_text() for action in executor.outbox],
        "denied_blocked": denied_blocked,
        "receiptless_blocked": receiptless_blocked,
        "audit_entries": len(audit_entries),
        "first_audit_entry": audit_entries[0].to_dict() if audit_entries else {},
        "audit_chain_valid": audit_log.verify_chain(),
    }


def main() -> int:
    result = run_demo()
    print("Governed execution membrane")
    print("Flow: LLM reasoning -> constitutional check -> decision receipt -> governed execution")
    print(f"Decisions: {', '.join(result['decisions'])}")
    print(f"Executed side effects: {len(result['outbox'])}")
    print(f"Denied execution blocked: {result['denied_blocked']}")
    print(f"Receiptless execution blocked: {result['receiptless_blocked']}")
    print(f"Audit entries: {result['audit_entries']}")
    print(f"Audit chain valid: {result['audit_chain_valid']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
