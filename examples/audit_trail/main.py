"""
Example: Tamper-Evident Audit Trail
=====================================
Every governance decision is recorded in a cryptographically-chained
audit log. Chain integrity is verifiable at any time.

Run:
    python examples/audit_trail/main.py
"""

import json
import tempfile
from pathlib import Path

from acgs_lite import Constitution, ConstitutionalViolationError, GovernedCallable, Rule, Severity
from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.legitimacy import (
    BASELINE_CONSTRAINT_MARKER,
    DecisionReceipt,
    ExecutionBoundary,
)


def _allow_receipt(*, method: str, policy_version: str, goal: str) -> DecisionReceipt:
    """Build an ALLOW receipt so the governed call reaches the constitutional check."""
    return DecisionReceipt.create(
        request_id=f"demo-{method}",
        goal=goal,
        proposed_method=method,
        decision_type="ALLOW",
        authority_basis="demo:audit_trail",
        matched_constraints=(BASELINE_CONSTRAINT_MARKER,),
        policy_version=policy_version,
        execution_boundary=ExecutionBoundary(
            allowed_method=method,
            allowed_scope=None,
            allowed_subjects=(),
            expires_at=None,
            single_use=False,
        ),
    )


def demo_manual_audit() -> None:
    """Record and verify a manually-built audit chain."""
    print("\n── 1. Manual Audit Chain ─────────────────────────────────────")
    log = AuditLog()

    entries = [
        AuditEntry(
            id="ev-001", type="validation", agent_id="agent-A", action="review_proposal", valid=True
        ),
        AuditEntry(
            id="ev-002",
            type="maci_check",
            agent_id="agent-B",
            action="validate_proposal",
            valid=True,
        ),
        AuditEntry(
            id="ev-003",
            type="validation",
            agent_id="agent-C",
            action="execute_deployment",
            valid=True,
        ),
        AuditEntry(
            id="ev-004",
            type="validation",
            agent_id="agent-A",
            action="harmful_request",
            valid=False,
            violations=["no-harmful-content"],
        ),
    ]

    for entry in entries:
        chain_hash = log.record(entry)
        icon = "✅" if entry.valid else "🚫"
        print(
            f"  {icon}  {entry.id}  agent={entry.agent_id}  "
            f"action={entry.action}  chain={chain_hash}"
        )

    # Verify chain integrity
    intact = log.verify_chain()
    print(f"\n  Chain intact: {intact} ({'✅ no tampering' if intact else '❌ TAMPERED'})")


def demo_query_and_export() -> None:
    """Query entries by agent/type and export to JSON."""
    print("\n── 2. Query + Export ─────────────────────────────────────────")
    log = AuditLog()

    for i in range(5):
        log.record(
            AuditEntry(
                id=f"ev-{i:03d}",
                type="validation",
                agent_id="agent-A" if i % 2 == 0 else "agent-B",
                action=f"action-{i}",
                valid=(i != 2),
            )
        )

    # Filter by agent
    agent_a_entries = log.query(agent_id="agent-A")
    print(f"  agent-A entries : {len(agent_a_entries)}")

    # Filter by validity
    violations = log.query(valid=False)
    print(f"  Violation entries: {len(violations)}")
    for v in violations:
        print(f"    • {v.id}  {v.agent_id}  {v.action}")

    # Export to JSON
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        path = Path(f.name)
        json.dump([e.to_dict() for e in log.entries], f, indent=2)

    print(f"\n  Exported {len(log.entries)} entries → {path.name}")
    path.unlink()


def demo_governed_with_audit() -> None:
    """Record governance decisions from a GovernedCallable into an AuditLog."""
    print("\n── 3. Governed Callable → Audit Log ──────────────────────────")

    log = AuditLog()
    constitution = Constitution(
        name="demo-policy",
        version="1.0",
        rules=[
            Rule(
                id="no-pii",
                text="Prevent SSN patterns",
                patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
                severity=Severity.HIGH,
            ),
        ],
    )
    governed_fn = GovernedCallable(constitution=constitution)(lambda prompt: f"answer: {prompt}")
    method = "<lambda>"
    policy_version = constitution.hash

    # Allowed call → record success
    result = governed_fn(
        "What is 2+2?",
        decision_receipt=_allow_receipt(
            method=method, policy_version=policy_version, goal="answer math question"
        ),
    )
    log.record(
        AuditEntry(
            id="g-001", type="validation", agent_id="ai_fn", action="math_question", valid=True
        )
    )
    print(f"  Allowed call: {result}")

    # Blocked call → record violation
    try:
        governed_fn(
            "My SSN is 123-45-6789",
            decision_receipt=_allow_receipt(
                method=method, policy_version=policy_version, goal="share personal info"
            ),
        )
    except ConstitutionalViolationError as exc:
        log.record(
            AuditEntry(
                id="g-002",
                type="validation",
                agent_id="ai_fn",
                action="pii_request",
                valid=False,
                violations=[exc.rule_id],
            )
        )
        print(f"  Blocked: {exc.rule_id}")

    print(f"  Log entries : {len(log.entries)}")
    print(f"  Chain intact: {log.verify_chain()}")
    for entry in log.entries:
        icon = "✅" if entry.valid else "🚫"
        print(f"    {icon}  {entry.id}  valid={entry.valid}")


if __name__ == "__main__":
    print("=" * 55)
    print("  Tamper-Evident Audit Trail Demo")
    print("=" * 55)

    demo_manual_audit()
    demo_query_and_export()
    demo_governed_with_audit()

    print("\nDone. Every governance decision recorded and chain-verified.")
