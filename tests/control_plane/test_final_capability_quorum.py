"""Privileged operations must use the final, still-valid approval set."""

from typing import Any

import pytest

from acgs_lite.control_plane import (
    ActionTier,
    DecisionRequest,
    EvidenceSource,
    ExternalRunRef,
    PolicyDecisionPoint,
    Principal,
    PrincipalKind,
    PromotionGate,
    PromotionRejected,
    ReceiptKind,
    TrustedRunRegistry,
    action_hash,
)
from acgs_lite.control_plane.incident import IncidentLockError, IncidentMutationLock
from acgs_lite.control_plane.runbook import RunbookRegistry, RunbookRejected

pytestmark = pytest.mark.unit
ADMIN = Principal("root-admin", PrincipalKind.HUMAN)
REQUESTER = Principal("requester", PrincipalKind.HUMAN)
QUALIFIED = Principal("qualified", PrincipalKind.HUMAN)


@pytest.mark.parametrize("invalidation", ["revocation", "expiry"])
@pytest.mark.parametrize("operation", ["runbook", "promotion", "takeover"])
def test_final_quorum_must_retain_required_capability(
    operation: str,
    invalidation: str,
    ledger_pdp: Any,
    roles: Any,
    approver_factory: Any,
    approval_authority: Any,
    runbook_data: Any,
    monkeypatch: Any,
) -> None:
    qualified_sign = approver_factory("qualified")
    ordinary_sign = approver_factory("ordinary")
    now = [1000.0]
    registry = None
    promotion = None
    ref = None
    lock = None
    data = None
    digest = None
    if operation == "runbook":
        roles.grant_capability(ADMIN, "sre", QUALIFIED)
        registry = RunbookRegistry(pdp=ledger_pdp, roles=roles, registry=ledger_pdp.registry)
        data = runbook_data()
        request = registry.approval_request(REQUESTER, data)
        error = RunbookRejected
    elif operation == "promotion":
        roles.grant_capability(ADMIN, "promotion.approve", QUALIFIED)
        digest = "sha256:" + "d" * 64
        ref = ExternalRunRef("ci", "run", EvidenceSource.CI_SYSTEM, artifact_digest=digest)
        runs = TrustedRunRegistry()
        runs.register_run(Principal("ci", PrincipalKind.SERVICE), ref, conclusion="success")
        promotion = PromotionGate(ledger_pdp.receipt_ledger, runs, pdp=ledger_pdp, roles=roles)
        request = DecisionRequest(
            principal=REQUESTER,
            action="promotion.promote",
            resource="candidate",
            tier=ActionTier.T2,
            attributes={"candidate_digest": digest, "external_runs": [ref.to_dict()]},
        )
        error = PromotionRejected
    else:
        commander = Principal("commander", PrincipalKind.HUMAN)
        roles.grant_capability(ADMIN, "incident_commander", commander)
        roles.grant_capability(ADMIN, "incident_admin", REQUESTER)
        roles.grant_capability(ADMIN, "incident_admin", QUALIFIED)
        lock = IncidentMutationLock(
            registry=ledger_pdp.registry,
            roles=roles,
            pdp=ledger_pdp,
            clock=lambda: now[0],
            stale_after_s=60,
        )
        lock.declare_incident(commander, "inc-1")
        now[0] += 120
        request = lock.takeover_request(REQUESTER, "stale commander")
        error = IncidentLockError
    approval_now = [2000.0]
    monkeypatch.setattr(ledger_pdp.approval_gate, "_clock", lambda: approval_now[0])
    approvals = [
        qualified_sign(action_hash(request), now=2000, ttl_s=10),
        ordinary_sign(action_hash(request), now=2000, ttl_s=100),
    ]
    original = PolicyDecisionPoint._decide_attested
    final_approvers = []

    def decide(self: Any, req: Any) -> Any:
        # The preliminary check saw both signatures. Revoke only the privileged
        # signer before the real PDP recomputes an otherwise sufficient quorum.
        if invalidation == "revocation":
            approval_authority.revoke_approver(ADMIN, "key-qualified")
        else:
            approval_now[0] = 2011.0
        decision, attested = original(self, req)
        assert decision.allowed and attested is not None
        final_approvers.extend(a.canonical_id for a in attested.approvers)
        return decision, attested

    monkeypatch.setattr(PolicyDecisionPoint, "_decide_attested", decide)
    with pytest.raises(error, match="final.*approval|final.*approver"):
        if operation == "runbook":
            assert registry is not None and data is not None
            registry.approve(REQUESTER, data, approvals=approvals)
        elif operation == "promotion":
            assert promotion is not None and ref is not None and digest is not None
            promotion.promote(
                REQUESTER, "candidate", candidate_digest=digest, evidence=[ref], approvals=approvals
            )
        else:
            assert lock is not None
            lock.take_over(REQUESTER, "stale commander", approvals=approvals)
    assert final_approvers == ["ordinary"]
    if operation == "runbook":
        assert registry is not None and data is not None
        assert registry.approved(data["runbook_id"]) is None
    elif operation == "promotion":
        assert all(
            r.receipt.kind is not ReceiptKind.PROMOTION
            for r in ledger_pdp.receipt_ledger.receipts()
        )
    else:
        assert lock is not None
        assert lock.state().commander_id == "commander"
        assert all(event["event"] != "takeover" for event in lock.history())
