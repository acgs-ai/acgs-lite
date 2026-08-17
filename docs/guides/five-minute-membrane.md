# 5-minute membrane: from `pip install` to a governed side effect

Copy this page into a file. You do not need the git repo. You do not need API keys.

`examples/` is **not** shipped on PyPI. After `pip install acgs-lite`, run the
script below (or clone the repo and run
[`examples/membrane_5min.py`](https://github.com/acgs-ai/acgs-lite/blob/main/examples/membrane_5min.py)).

```bash
python -m venv .venv && source .venv/bin/activate
pip install "acgs-lite==2.12.0"
python membrane_5min.py
```

Core invariant:

> No valid Decision Receipt, no side effect.

Save the script as `membrane_5min.py`.

```python
"""Governed side-effect membrane. Requires only: pip install acgs-lite==2.12.0"""
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
    constraints = tuple(v.rule_id for v in result.violations) or ("denied",)

    if result.valid:
        state, decision_type, constraints = "ALLOW", "ALLOW", ("matched",)
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
    return f"executed:{body}"  # the only side effect in this demo: a string


def main() -> None:
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
    engine = GovernanceEngine(constitution, audit_log=audit, strict=False, audit_mode="full")
    maci = MACIEnforcer()
    maci.assign_role("tool-executor", MACIRole.EXECUTOR)

    # ALLOW
    state, body, receipt = authorize(
        engine,
        constitution,
        "Your invoice is ready.",
        method="send_email",
        tenant="tenant-a",
        subject="customer-1",
    )
    print(
        "ALLOW",
        state,
        execute(maci, "tool-executor", "send_email", "tenant-a", "customer-1", body, receipt),
    )
    print(
        "  receipt",
        receipt.decision_type,
        "hash_ok",
        receipt.verify_hash(),
        receipt.receipt_hash[:16] + "…",
    )

    # TRANSFORM (PII)
    state, body, receipt = authorize(
        engine,
        constitution,
        "SSN 123-45-6789 is on file.",
        method="send_email",
        tenant="tenant-a",
        subject="customer-2",
    )
    print(
        "TRANSFORM",
        state,
        execute(maci, "tool-executor", "send_email", "tenant-a", "customer-2", body, receipt),
    )
    print("  transformed_body", body)
    print("  transformation_applied", receipt.transformation_applied)

    # DENY (financial / policy)
    state, body, receipt = authorize(
        engine,
        constitution,
        "wire transfer $1000",
        method="wire_transfer",
        tenant="tenant-a",
        subject="account-7",
    )
    try:
        execute(
            maci,
            "tool-executor",
            "wire_transfer",
            "tenant-a",
            "account-7",
            body,
            receipt,
        )
        print("DENY unexpected execution")
    except LegitimacyInvariantError as exc:
        print("DENY", state, "blocked:", exc)

    # Missing receipt
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
        print("RECEIPTLESS unexpected execution")
    except LegitimacyInvariantError as exc:
        print("RECEIPTLESS blocked:", exc)

    print("AUDIT entries", len(audit.entries), "chain_ok", audit.verify_chain())
    first = audit.entries[0].to_dict()
    print("FIRST_AUDIT type", first["type"], "valid", first["valid"], "hash", first["constitutional_hash"])


if __name__ == "__main__":
    main()
```

## Expected output

Recorded against **acgs-lite 2.12.0**. Receipt hashes include `issued_at`, so the
hex prefix will change. The decisions and the two refusal strings must not.

```text
ALLOW ALLOW executed:Your invoice is ready.
  receipt ALLOW hash_ok True <16 hex>…
TRANSFORM TRANSFORM executed:SSN [REDACTED-SSN] is on file.
  transformed_body SSN [REDACTED-SSN] is on file.
  transformation_applied redacted SSN before execution
DENY DENY blocked: Decision DENY_GOAL does not permit execution
RECEIPTLESS blocked: No legitimacy receipt, no execution
AUDIT entries 4 chain_ok True
FIRST_AUDIT type validation valid True hash <constitution.hash>
```

If a DENY or missing receipt prints `executed:…`, the membrane is not in the
path. Stop.

## How to read the two gates

| Gate | What it decides | Fail-closed signal |
|---|---|---|
| `GovernanceEngine.validate` | Does this text match the constitution? | Default `strict=True` raises `ConstitutionalViolationError`. This demo uses `strict=False` **only** to receipt DENY/TRANSFORM as values. |
| `validate_receipt_for_execution` | May this executor run **this** call? | Raises `LegitimacyInvariantError`. DENY receipts are not executable. `None` is not executable. Bound method / tenant / subject must match. |

The side effect is the `return f"executed:{body}"` line. It is unreachable
unless the receipt is an executable ALLOW (or ALLOW after TRANSFORM) for that
exact call.

## What this proves

- A versioned constitution can ALLOW a benign email and execute it only after a receipt.
- A PII pattern can TRANSFORM the payload; the executor runs the redacted body, not the raw SSN.
- A financial keyword produces `DENY_GOAL`; the executor refuses: **Decision DENY_GOAL does not permit execution**.
- The same executor refuses a missing receipt: **No legitimacy receipt, no execution**.
- `AuditLog.verify_chain()` returns `True` on the in-memory chain written by those checks.
- `DecisionReceipt.verify_hash()` returns `True` on the issued ALLOW receipt.

## What this does not claim

- This is an in-process demo. The “side effect” is a string. It does not send
  email, move money, or write your filesystem.
- In-memory `AuditLog` is tamper-evident in process. It is not a durable,
  independently hosted audit store.
- Unsigned receipts prove integrity of the payload, not *who* signed them.
  Ed25519 signing is an optional `crypto` extra and is not used here.
- `strict=False` on the engine is a demo inspection mode. Do not copy it into a
  production executor path.
- This does not prove production hardening, multi-tenant isolation,
  certification, or that any third party runs acgs-lite.
- Keyword / regex constitutions are exact-match policy, not semantic
  understanding. A rephrased wire transfer that avoids the keyword is a
  different proposed action — write a better rule, do not assume the engine
  “knows finance.”
