"""Tests for Phase 1 adapter contracts and adapter-facing serializers."""

from __future__ import annotations

import sys

from acgs_lite.adapters.contracts import (
    AdapterPolicyDecision,
    ExecutionReceipt,
    ExecutionReceiptSink,
    ToolCallContext,
)
from acgs_lite.audit import AuditEntry
from acgs_lite.constitution import Constitution
from acgs_lite.constitution.bundle import ConstitutionBundle
from acgs_lite.engine.decision_record import GovernanceDecisionRecord
from acgs_lite.engine.models import ValidationResult


def test_adapter_contracts_import_without_optional_frameworks() -> None:
    before = set(sys.modules)
    import acgs_lite.adapters.contracts as contracts

    new_modules = set(sys.modules) - before
    deny_fragments = ["z3", "openshell", "postgres", "sqlite", "bundle_store"]
    violations = sorted(
        name for name in new_modules if any(fragment in name.lower() for fragment in deny_fragments)
    )

    assert not violations
    assert hasattr(contracts, "AdapterPolicyDecision")
    assert hasattr(contracts, "ExecutionReceipt")
    assert hasattr(contracts, "ToolCallContext")


def test_policy_decision_factories_use_adapter_states() -> None:
    assert AdapterPolicyDecision.allow() == AdapterPolicyDecision(allowed=True, state="ALLOW")
    assert AdapterPolicyDecision.deny("blocked", rule="PII") == AdapterPolicyDecision(
        allowed=False,
        state="DENY_GOAL",
        reason="blocked",
        metadata={"rule": "PII"},
    )


def test_tool_context_receipt_and_sink_protocol_contracts() -> None:
    context = ToolCallContext(tool_name="search", tool_args={"q": "x"}, framework="mcp")
    receipt = ExecutionReceipt(
        action_id="act-1",
        action_type="tool_call",
        decision="ALLOW_WITH_CONTROLS",
        policy_hash="hash-1",
    )

    class MemorySink:
        def __init__(self) -> None:
            self.receipts: list[ExecutionReceipt] = []

        def write(self, receipt: ExecutionReceipt) -> None:
            self.receipts.append(receipt)

    sink: ExecutionReceiptSink = MemorySink()
    sink.write(receipt)

    assert context.session_id == ""
    assert context.metadata == {}
    assert receipt.policy_hash == "hash-1"
    assert isinstance(sink, MemorySink)
    assert sink.receipts == [receipt]


def test_validation_result_adapter_dict_renames_hash_without_mutating_to_dict() -> None:
    result = ValidationResult(valid=True, constitutional_hash="hash-1", rules_checked=2)

    adapter_payload = result.to_adapter_dict()
    original_payload = result.to_dict()

    assert adapter_payload["policy_hash"] == "hash-1"
    assert "constitutional_hash" not in adapter_payload
    assert original_payload["constitutional_hash"] == "hash-1"
    assert result.constitutional_hash == "hash-1"


def test_decision_record_adapter_dict_renames_hash_without_mutating_to_dict() -> None:
    record = GovernanceDecisionRecord(decision="deny", constitutional_hash="hash-2")

    adapter_payload = record.to_adapter_dict()
    original_payload = record.to_dict()

    assert adapter_payload["policy_hash"] == "hash-2"
    assert "constitutional_hash" not in adapter_payload
    assert original_payload["constitutional_hash"] == "hash-2"
    assert record.constitutional_hash == "hash-2"


def test_constitution_bundle_adapter_dict_renames_hash_without_mutating_model_dump() -> None:
    bundle = ConstitutionBundle(
        tenant_id="tenant-a",
        constitution=Constitution.default(),
        proposed_by="proposer-1",
    )

    adapter_payload = bundle.to_adapter_dict()
    original_payload = bundle.model_dump(mode="json")

    assert adapter_payload["policy_hash"] == bundle.constitutional_hash
    assert "constitutional_hash" not in adapter_payload
    assert original_payload["constitutional_hash"] == bundle.constitutional_hash
    assert bundle.constitutional_hash == bundle.constitution.hash


def test_audit_entry_adapter_dict_renames_hash_without_mutating_to_dict() -> None:
    entry = AuditEntry(id="audit-1", type="validation", constitutional_hash="hash-3")

    adapter_payload = entry.to_adapter_dict()
    original_payload = entry.to_dict()

    assert adapter_payload["policy_hash"] == "hash-3"
    assert "constitutional_hash" not in adapter_payload
    assert original_payload["constitutional_hash"] == "hash-3"
    assert entry.constitutional_hash == "hash-3"
