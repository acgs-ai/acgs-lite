"""Pip-only 5-minute membrane proof.

This is the script documented in docs/guides/five-minute-membrane.md.
It requires only the published package surface:

    pip install acgs-lite==2.12.0
    python examples/membrane_5min.py   # from a clone
    # or paste the same file after pip install — no repo paths needed

The only side effect is an in-memory string. The executor never runs without a
valid ALLOW receipt bound to method / tenant / subject.
"""

from __future__ import annotations

import re

from acgs_lite import (
    AuditLog,
    Constitution,
    GovernanceEngine,
    MACIEnforcer,
    MACIRole,
    Rule,
    Severity,
)
from acgs_lite.legitimacy import (
    BASELINE_CONSTRAINT_MARKER,
    ActualCall,
    DecisionReceipt,
    ExecutionBoundary,
    LegitimacyInvariantError,
    validate_receipt_for_execution,
)

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def authorize(engine, constitution, text, *, method, tenant, subject):
    # strict=False only so DENY/TRANSFORM come back as values we can receipt.
    # The executor below is the fail-closed gate. Default GovernanceEngine raises.
    result = engine.validate(text, agent_id="runtime", strict=False)
    policy_version = f"{constitution.version}:{constitution.hash}"
    body, state, decision_type = text, "DENY", "DENY_GOAL"
    transform = rationale = None
    constraints = tuple(v.rule_id for v in result.violations) or (BASELINE_CONSTRAINT_MARKER,)

    if result.valid:
        state, decision_type, constraints = "ALLOW", "ALLOW", (BASELINE_CONSTRAINT_MARKER,)
    elif any(v.rule_id == "no-raw-ssn" for v in result.violations):
        redacted = SSN_RE.sub("[REDACTED-SSN]", text)
        if engine.validate(redacted, agent_id="runtime:transform", strict=False).valid:
            body, state, decision_type = redacted, "TRANSFORM", "ALLOW"
            transform = "redacted SSN before execution"

    if state == "DENY":
        rationale = "constitutional policy denied the proposed side effect"

    receipt = DecisionReceipt.create(
        request_id=f"{method}:{subject}:{decision_type}",
        goal="govern a side-effectful tool call",
        proposed_method=method,
        decision_type=decision_type,
        authority_basis="demo:versioned-constitution",
        matched_constraints=constraints,
        policy_version=policy_version,
        transformation_applied=transform,
        denial_or_review_rationale=rationale,
        execution_boundary=ExecutionBoundary(
            allowed_method=method,
            allowed_scope=tenant,
            allowed_subjects=(subject,),
            expires_at=None,
            single_use=True,
        ),
    )
    return state, body, receipt


def execute(maci, agent_id, method, tenant, subject, body, receipt):
    maci.check(agent_id, "execute")
    validate_receipt_for_execution(
        receipt,
        actual_call=ActualCall(method=method, scope=tenant, subjects=(subject,)),
    )
    return f"executed:{body}"


def run_demo() -> dict[str, object]:
    constitution = Constitution(
        name="agent-tool-membrane",
        version="2026.08",
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
    audit = AuditLog()
    engine = GovernanceEngine(constitution, audit_log=audit, audit_mode="full")
    maci = MACIEnforcer()
    maci.assign_role("tool-executor", MACIRole.EXECUTOR)
    outbox: list[str] = []

    allow_state, allow_body, allow_receipt = authorize(
        engine,
        constitution,
        "Your invoice is ready.",
        method="send_email",
        tenant="tenant-a",
        subject="customer-1",
    )
    allow_out = execute(
        maci, "tool-executor", "send_email", "tenant-a", "customer-1", allow_body, allow_receipt
    )
    outbox.append(allow_out)

    transform_state, transform_body, transform_receipt = authorize(
        engine,
        constitution,
        "SSN 123-45-6789 is on file.",
        method="send_email",
        tenant="tenant-a",
        subject="customer-2",
    )
    transform_out = execute(
        maci,
        "tool-executor",
        "send_email",
        "tenant-a",
        "customer-2",
        transform_body,
        transform_receipt,
    )
    outbox.append(transform_out)

    deny_state, deny_body, deny_receipt = authorize(
        engine,
        constitution,
        "wire transfer $1000",
        method="wire_transfer",
        tenant="tenant-a",
        subject="account-7",
    )
    deny_blocked = False
    deny_message = ""
    try:
        execute(
            maci,
            "tool-executor",
            "wire_transfer",
            "tenant-a",
            "account-7",
            deny_body,
            deny_receipt,
        )
    except LegitimacyInvariantError as exc:
        deny_blocked = True
        deny_message = str(exc)

    receiptless_blocked = False
    receiptless_message = ""
    try:
        execute(
            maci,
            "tool-executor",
            "send_email",
            "tenant-a",
            "customer-1",
            "Your invoice is ready.",
            None,
        )
    except LegitimacyInvariantError as exc:
        receiptless_blocked = True
        receiptless_message = str(exc)

    first = audit.entries[0].to_dict() if audit.entries else {}
    return {
        "decisions": [allow_state, transform_state, deny_state],
        "outbox": outbox,
        "denied_blocked": deny_blocked,
        "deny_message": deny_message,
        "receiptless_blocked": receiptless_blocked,
        "receiptless_message": receiptless_message,
        "allow_receipt_ok": allow_receipt.verify_hash(),
        "allow_decision": allow_receipt.decision_type,
        "transformed_body": transform_body,
        "transformation_applied": transform_receipt.transformation_applied,
        "audit_entries": len(audit.entries),
        "audit_chain_valid": audit.verify_chain(),
        "first_audit_entry": first,
    }


def main() -> int:
    result = run_demo()
    print("ALLOW", result["decisions"][0], result["outbox"][0])
    print(
        "  receipt",
        result["allow_decision"],
        "hash_ok",
        result["allow_receipt_ok"],
    )
    print("TRANSFORM", result["decisions"][1], result["outbox"][1])
    print("  transformed_body", result["transformed_body"])
    print("  transformation_applied", result["transformation_applied"])
    print("DENY", result["decisions"][2], "blocked:", result["deny_message"])
    print("RECEIPTLESS blocked:", result["receiptless_message"])
    print("AUDIT entries", result["audit_entries"], "chain_ok", result["audit_chain_valid"])
    first = result["first_audit_entry"]
    print(
        "FIRST_AUDIT type",
        first.get("type"),
        "valid",
        first.get("valid"),
        "hash",
        first.get("constitutional_hash"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
