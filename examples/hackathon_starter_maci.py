"""
ACGS Hackathon Starter: Multi-Agent MACI Governance
====================================================
Demonstrates the MACI (Multi-Agent Constitutional Infrastructure) pattern:
Proposer, Validator, and Executor are separate agents that cannot bypass
each other. An agent cannot validate its own proposals.

Usage:
    python hackathon_starter_maci.py

No API keys required.
"""

from acgs_lite import Constitution, GovernedAgent, MACIRole

# --- Step 1: Define rules for a code deployment pipeline ---
DEPLOYMENT_RULES = """
rules:
  - id: NO_PROD_WITHOUT_TESTS
    text: Production deployments require passing test suite
    severity: critical
    keywords: ["deploy to production", "push to prod"]

  - id: NO_FORCE_PUSH
    text: Force pushing to protected branches is not allowed
    severity: critical
    keywords: ["force push", "git push -f", "git push --force"]

  - id: NO_SECRET_IN_CODE
    text: Source code must not contain hardcoded secrets
    severity: critical
    keywords: ["api_key=", "password=", "secret=", "AWS_SECRET"]
    patterns: ["['\\\"]sk-[a-zA-Z0-9]{20,}['\\\"]"]

  - id: REQUIRE_REVIEW
    text: Changes require peer review before merge
    severity: low
    keywords: ["merge without review", "skip review", "self-approve"]
"""


def proposer_agent(action: str) -> str:
    """Proposes an action. Cannot validate or execute."""
    return f"PROPOSAL: {action}"


def validator_agent(proposal: str) -> str:
    """Validates a proposal against rules. Cannot propose or execute."""
    return f"VALIDATED: {proposal}"


def executor_agent(validated_action: str) -> str:
    """Executes a validated action. Cannot propose or validate."""
    return f"EXECUTED: {validated_action}"


def main() -> None:
    constitution = Constitution.from_yaml_str(DEPLOYMENT_RULES)

    # --- Step 2: Create governed agents with MACI roles ---
    proposer = GovernedAgent(
        proposer_agent,
        constitution=constitution,
        agent_id="proposer",
        maci_role=MACIRole.PROPOSER,
    )

    validator = GovernedAgent(
        validator_agent,
        constitution=constitution,
        agent_id="validator",
        maci_role=MACIRole.VALIDATOR,
    )

    executor = GovernedAgent(
        executor_agent,
        constitution=constitution,
        agent_id="executor",
        maci_role=MACIRole.EXECUTOR,
    )

    print("=== MACI Governance Demo ===\n")

    # --- Step 3: Run the pipeline ---
    test_actions = [
        "deploy feature-branch to staging after tests pass",
        "deploy to production without running tests",
        "force push to main branch",
        "merge PR #42 after code review approval",
        "add config with api_key='sk-proj-abc123def456' to .env",
        "self-approve and merge without review",
    ]

    for action in test_actions:
        print(f'Action: "{action}"')

        # Phase 1: Propose
        try:
            proposal = proposer.run(action, governance_action="propose")
            print(f"  Proposer:  {proposal}")
        except Exception as e:
            print(f"  Proposer:  [BLOCKED] {type(e).__name__}")
            print("             Rule violated at proposal stage")
            print()
            continue

        # Phase 2: Validate
        try:
            validated = validator.run(proposal, governance_action="validate")
            print(f"  Validator: {validated}")
        except Exception as e:
            print(f"  Validator: [BLOCKED] {type(e).__name__}")
            print("             Constitutional violation detected")
            print()
            continue

        # Phase 3: Execute
        try:
            result = executor.run(validated, governance_action="execute")
            print(f"  Executor:  {result}")
        except Exception as e:
            print(f"  Executor:  [BLOCKED] {type(e).__name__}")
            print()
            continue

        print()

    # --- Step 4: Audit trail ---
    print("=== Audit Summary ===")
    all_entries = (
        proposer.audit_log.entries + validator.audit_log.entries + executor.audit_log.entries
    )
    print(f"Total audit entries: {len(all_entries)}")
    print(f"Proposer entries:  {len(proposer.audit_log.entries)}")
    print(f"Validator entries: {len(validator.audit_log.entries)}")
    print(f"Executor entries:  {len(executor.audit_log.entries)}")

    blocked = sum(
        1
        for e in all_entries
        if "block" in str(e.action).lower() or "violation" in str(e.action).lower()
    )
    print(f"Blocked actions: {blocked}")


if __name__ == "__main__":
    main()
