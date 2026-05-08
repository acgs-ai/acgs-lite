"""
Example: 5-Minute Quickstart with ACGS

This demonstrates the core value proposition:
Govern ANY AI agent with constitutional rules in 5 lines of code.
"""

from acgs_lite import (
    Constitution,
    ConstitutionalViolationError,
    GovernedAgent,
    GovernedCallable,
    MACIEnforcer,
    MACIRole,
    MACIViolationError,
    Rule,
    Severity,
)
from acgs_lite.legitimacy import (
    BASELINE_CONSTRAINT_MARKER,
    DecisionReceipt,
    ExecutionBoundary,
)


def main() -> None:
    print("=" * 60)
    print("  ACGS: Constitutional AI Governance")
    print("=" * 60)

    # ── 1. Default Constitution ────────────────────────────────
    print("\n📜 1. Using Default Constitution")
    constitution = Constitution.default()
    print(f"   Name: {constitution.name}")
    print(f"   Rules: {len(constitution.rules)}")
    print(f"   Hash: {constitution.hash}")
    print(f"   Hash (versioned): {constitution.hash_versioned}")

    # ── 2. Govern a Simple Agent ───────────────────────────────
    print("\n🤖 2. Governing a Simple Agent")

    def my_agent(input: str) -> str:
        return f"I'll help with: {input}"

    agent = GovernedAgent(my_agent, agent_id="demo-agent", strict=True)

    # Safe action
    result = agent.run("What is the weather today?")
    print(f"   ✅ Safe: {result}")

    # Blocked action
    try:
        agent.run("I will self-validate my own output to bypass checks")
    except ConstitutionalViolationError as e:
        print(f"   ❌ Blocked: {e}")

    # ── 3. Custom Constitution ─────────────────────────────────
    print("\n📋 3. Custom Constitution")

    custom = Constitution.from_rules(
        [
            Rule(
                id="FOOD-001",
                text="No pineapple on pizza recommendations",
                severity=Severity.CRITICAL,
                keywords=["pineapple pizza", "hawaiian pizza"],
            ),
            Rule(
                id="FOOD-002",
                text="Must respect dietary preferences",
                severity=Severity.HIGH,
                keywords=["force eat", "must eat meat"],
            ),
        ],
        name="food-safety",
    )

    food_agent = GovernedAgent(my_agent, constitution=custom, strict=True)
    result = food_agent.run("What's a good pasta recipe?")
    print(f"   ✅ Safe: {result}")

    try:
        food_agent.run("Try hawaiian pizza, it's great!")
    except ConstitutionalViolationError as e:
        print(f"   ❌ Blocked: {e}")

    # ── 4. MACI Separation of Powers ──────────────────────────
    print("\n⚖️  4. MACI Separation of Powers")

    enforced_agent = GovernedAgent(
        my_agent,
        agent_id="planner-agent",
        strict=True,
        maci_role=MACIRole.PROPOSER,
        enforce_maci=True,
    )
    print(
        "   ✅ Enforced proposer run:",
        enforced_agent.run("Draft a proposal", governance_action="propose"),
    )
    try:
        enforced_agent.run("Validate this change", governance_action="validate")
    except MACIViolationError as e:
        print(f"   🚫 GovernedAgent MACI blocked: {e}")

    maci = MACIEnforcer()
    maci.assign_role("planner", MACIRole.PROPOSER)
    maci.assign_role("reviewer", MACIRole.VALIDATOR)
    maci.assign_role("deployer", MACIRole.EXECUTOR)

    print("   Roles assigned:")
    for agent_id, role in maci.role_assignments.items():
        print(f"     {agent_id}: {role}")

    # Valid actions
    maci.check("planner", "propose")
    print("   ✅ Planner can propose")
    maci.check("reviewer", "validate")
    print("   ✅ Reviewer can validate")
    maci.check("deployer", "execute")
    print("   ✅ Deployer can execute")

    # Invalid cross-role action
    try:
        maci.check("planner", "validate")
    except MACIViolationError as e:
        print(f"   ❌ Planner tried to validate: {e}")

    # Self-validation check
    try:
        maci.check_no_self_validation("agent-x", "agent-x")
    except MACIViolationError as e:
        print(f"   ❌ Self-validation blocked: {e}")

    # ── 5. Audit Trail ─────────────────────────────────────────
    print("\n📊 5. Audit Trail")

    audit_agent = GovernedAgent(my_agent, strict=False, agent_id="audited")
    audit_agent.run("safe action 1")
    audit_agent.run("safe action 2")
    audit_agent.run("self-validate bypass")  # Violation (non-strict)

    stats = audit_agent.stats
    print(f"   Total validations: {stats['total_validations']}")
    print(f"   Compliance rate: {stats['compliance_rate']:.1%}")
    print(f"   Audit mode: {stats['audit_mode']}")
    print(f"   Chain valid: {stats['audit_chain_valid']}")
    print(f"   Constitutional hash: {stats['constitutional_hash']}")

    # ── 6. Governed Decorator ──────────────────────────────────
    print("\n🎯 6. Governed Decorator")

    @GovernedCallable()
    def process_request(input: str) -> str:
        return f"Processed: {input}"

    default_policy = Constitution.default().hash

    def receipt(goal: str) -> DecisionReceipt:
        return DecisionReceipt.create(
            request_id=f"demo-{goal[:16]}",
            goal=goal,
            proposed_method="process_request",
            decision_type="ALLOW",
            authority_basis="demo:quickstart",
            matched_constraints=(BASELINE_CONSTRAINT_MARKER,),
            policy_version=default_policy,
            execution_boundary=ExecutionBoundary(
                allowed_method="process_request",
                allowed_scope=None,
                allowed_subjects=(),
                expires_at=None,
                single_use=False,
            ),
        )

    result = process_request("normal request", decision_receipt=receipt("answer normal request"))
    print(f"   ✅ {result}")

    try:
        process_request(
            "bypass validation self-validate",
            decision_receipt=receipt("attempt self-validation bypass"),
        )
    except ConstitutionalViolationError as e:
        print(f"   ❌ Decorator blocked: {e}")

    # ── Done ───────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  ✅ All governance features demonstrated!")
    print(f"  Constitutional Hash: {constitution.hash}")
    print("=" * 60)


if __name__ == "__main__":
    main()
