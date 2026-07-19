"""EU AI Act Article 14 — fail-closed human oversight for high-risk side effects.

A mock payment side effect is gated behind two independent layers: a
constitutional rule that blocks unapproved payment actions outright
(``CK-002``), and a ``HumanOversightGateway`` that requires human approval
before a ``GatedExecutor`` will perform the side effect. The deny path runs
first to show the system fails closed by default; only after explicit human
approval does the side effect execute.

Run:
    python examples/eu_ai_act_runtime/art14_human_oversight.py

No external services required — all oversight routing runs in-process.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from acgs_lite import Constitution, GovernanceEngine, Rule, Severity
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.eu_ai_act import HumanOversightGateway, OversightOutcome

CONSTITUTIONAL_HASH = "608508a9bd224290"

SYSTEM_ID = "payment-agent-v1"

CK_002_RULE_ID = "CK-002"


def make_constitution() -> Constitution:
    return Constitution(
        name="payment-oversight-policy",
        version="1.0",
        rules=[
            Rule(
                id=CK_002_RULE_ID,
                text="Payments must not execute without prior human approval on record",
                severity=Severity.CRITICAL,
                keywords=["unapproved payment"],
            ),
        ],
    )


class GatedExecutor:
    """Mirrors the membrane's receipt-checking executor for oversight decisions.

    Performs the mock side effect only when the oversight decision it is
    handed is ``APPROVED`` — never on ``PENDING``, ``REJECTED``, or any other
    outcome.
    """

    def __init__(self) -> None:
        self.side_effects: list[str] = []

    def execute_if_approved(self, outcome: OversightOutcome, action_text: str) -> bool:
        if outcome != OversightOutcome.APPROVED:
            return False
        self.side_effects.append(action_text)
        return True


def run_demo() -> dict[str, object]:
    engine = GovernanceEngine(make_constitution())  # strict=True by default
    gateway = HumanOversightGateway(system_id=SYSTEM_ID, oversight_threshold=0.8)
    executor = GatedExecutor()

    unapproved_action_text = "unapproved payment of $5000 to vendor-9"

    # Deny path first: Layer 1 constitutional check blocks the raw action text.
    ck002_raised = False
    try:
        engine.validate(unapproved_action_text, agent_id=SYSTEM_ID)
    except ConstitutionalViolationError:
        ck002_raised = True

    # Layer 2: even if Layer 1 were bypassed, the executor still refuses without
    # an APPROVED human oversight decision.
    decision = gateway.submit(
        operation="execute_payment",
        ai_output=unapproved_action_text,
        impact_score=0.95,
        context={"vendor": "vendor-9", "amount_usd": 5000},
    )
    deny_path_blocked = not executor.execute_if_approved(decision.outcome, unapproved_action_text)
    side_effects_before_approval = len(executor.side_effects)

    # Human reviewer approves after out-of-band verification.
    approved_decision = gateway.approve(
        decision.decision_id,
        reviewer_id="finance-controller-1",
        notes="Vendor invoice verified against PO-4471.",
    )
    executor.execute_if_approved(approved_decision.outcome, unapproved_action_text)
    side_effects_after_approval = len(executor.side_effects)

    compliant = bool(gateway.compliance_summary()["compliant"])

    return {
        "deny_path_blocked": deny_path_blocked,
        "side_effects_before_approval": side_effects_before_approval,
        "ck002_raised": ck002_raised,
        "approved_outcome": approved_decision.outcome.value,
        "side_effects_after_approval": side_effects_after_approval,
        "compliant": compliant,
    }


def main() -> int:
    result = run_demo()
    print("EU AI Act Article 14 — fail-closed human oversight")
    print(f"Deny path blocked before approval: {result['deny_path_blocked']}")
    print(f"CK-002 constitutional violation raised: {result['ck002_raised']}")
    print(f"Side effects before approval: {result['side_effects_before_approval']}")
    print(f"Outcome after human approval: {result['approved_outcome']}")
    print(f"Side effects after approval: {result['side_effects_after_approval']}")
    print(f"Article 14 compliant: {result['compliant']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
