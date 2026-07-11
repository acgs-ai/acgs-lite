"""End-to-end conformance: a real acgs-lite constitution verdict travels the
full signed gove-zone chain — ConstitutionPolicy -> ChainHashAuditStore ->
signed DecisionReceipt -> execute_with_receipt. Proves the ALLOW leg reaches
the tool and that a DENY receipt can never authorize execution.

Wiring mirrors packages/gove-zone/examples/receipt-gated-execution/demo.py
scenarios [1] (ALLOW -> execute) and [2]/[8] (DENY blocked / signed receipt),
substituting acgs_lite.gove.policy.ConstitutionPolicy backed by a REAL
GovernanceEngine (acgs_lite.Constitution.default()) for the demo's
RuleSetPolicy/TenantPolicyStore path.
"""

from __future__ import annotations

import pytest

pytest.importorskip("gove_zone")
pytest.importorskip("cryptography")

from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision
from gove_zone.errors import ReceiptRejectionReason, ReceiptValidationError
from gove_zone.executor import execute_with_receipt
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.signing import Ed25519Signer
from gove_zone.tool import ToolCall

from acgs_lite import Constitution, GovernanceEngine
from acgs_lite.gove.policy import ConstitutionPolicy

TENANT = "tenant-conformance"
BOUNDARY = "local-sandbox"
POLICY_BUNDLE_ID = "acgs-lite-constitution-bundle"
AUTHORITY = "tenant-conformance/write-grant"
# The invoking principal's identity, supplied to the gate as expected_actor —
# the same non-circular trust-boundary pattern as the demo's CALLER_IDENTITY:
# it comes from runtime context, never from the receipt/request body.
CALLER_IDENTITY = "agent-1"
# A distinct MACI validating principal — never the proposer (CALLER_IDENTITY).
VALIDATOR = Validator("constitutional-council")


def _real_constitution_policy() -> ConstitutionPolicy:
    """A REAL GovernanceEngine over a non-empty constitution (ACGS-001..),
    wrapped as a gove-zone Policy via the Task 3 adapter.
    """
    engine = GovernanceEngine(Constitution.default(), strict=False)
    return ConstitutionPolicy(engine, version="1.0.0")


def test_allow_travels_full_signed_chain(tmp_path):
    # 1. Real GovernanceEngine, benign action -> ConstitutionPolicy ALLOW.
    policy = _real_constitution_policy()
    call = ToolCall(
        name="deploy_feature",
        args={"env": "staging", "version": "1.2.3"},
        goal="deploy new feature to staging",
        actor=CALLER_IDENTITY,
    )
    record = policy.evaluate(call)
    assert record.decision is Decision.ALLOW, record.reason

    # 2. Append the DecisionRecord to the tamper-evident audit chain.
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    event = audit.append(record)

    # 3. Mint a signed DecisionReceipt — validator distinct from the actor
    #    (fail-closed at from_record: validator == proposer would raise).
    signing_key = Ed25519Signer.generate()
    verify_key = Ed25519Signer.from_public_bytes(signing_key.public_bytes())
    receipt = DecisionReceipt.from_record(
        record,
        event["event_hash"],
        event["previous_hash"],
        TENANT,
        BOUNDARY,
        POLICY_BUNDLE_ID,
        policy.version,
        "req-allow-1",
        validator=VALIDATOR,
        authority=AUTHORITY,
        signer=signing_key,
    )
    assert receipt.decision == "allow"
    assert receipt.validator_id != receipt.actor
    assert receipt.signature_algorithm == "ed25519"

    # 4. execute_with_receipt, signed + require_signature=True, returns the
    #    tool result — the production-profile default posture.
    def tool_fn(**kwargs):
        return {"deployed": True, **kwargs}

    result = execute_with_receipt(
        tool_fn=tool_fn,
        args=dict(call.args),
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=call.name,
        expected_actor=CALLER_IDENTITY,
        verifier=verify_key,
        require_signature=True,
    )
    assert result == {"deployed": True, "env": "staging", "version": "1.2.3"}

    # 5. The audit chain is internally consistent end to end.
    chain = audit.verify_chain()
    assert chain["valid"] is True


def test_deny_never_executes(tmp_path):
    executed: list[dict] = []

    def tool_fn(**kwargs):
        executed.append(kwargs)

    # Forbidden action -> REAL engine returns valid=False (ACGS-001,
    # "self-validate" keyword) -> ConstitutionPolicy DENY. This exercises the
    # adapter's non-exception DENY path (engine.validate returns a result
    # object with valid=False), not the fail-closed exception-catch path.
    policy = _real_constitution_policy()
    call = ToolCall(
        name="review_output",
        args={"target": "output"},
        goal="self-validate its output",
        actor=CALLER_IDENTITY,
    )
    record = policy.evaluate(call)
    assert record.decision is Decision.DENY
    assert record.matched_rules == ("ACGS-001",)

    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    event = audit.append(record)

    # DENY receipts are mintable (the audit trail must record what was
    # denied) but are never executable — verified below.
    receipt = DecisionReceipt.from_record(
        record,
        event["event_hash"],
        event["previous_hash"],
        TENANT,
        BOUNDARY,
        POLICY_BUNDLE_ID,
        policy.version,
        "req-deny-1",
        validator=VALIDATOR,
        authority=AUTHORITY,
    )
    assert receipt.decision == "deny"

    with pytest.raises(ReceiptValidationError) as excinfo:
        execute_with_receipt(
            tool_fn=tool_fn,
            args=dict(call.args),
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=call.name,
            expected_actor=CALLER_IDENTITY,
            require_signature=False,  # dev-mode; DENY is rejected regardless
        )
    assert excinfo.value.reason_code == ReceiptRejectionReason.DENIED_RECEIPT
    assert executed == []

    # The audit chain still verifies — a DENY leaves tamper-evident evidence.
    assert audit.verify_chain()["valid"] is True
