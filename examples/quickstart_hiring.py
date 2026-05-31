"""Quickstart: AI Hiring Governance

Demonstrates constitutional governance for AI-assisted hiring decisions.
Rules prevent bias, protect candidates from discrimination, and enforce
fair evaluation practices. No external API keys required.
"""

from acgs_lite import (
    Constitution,
    ConstitutionalViolationError,
    GovernedAgent,
    MACIRole,
    Rule,
    Severity,
)


def main() -> None:
    print("=" * 60)
    print("  ACGS Hiring Governance")
    print("=" * 60)

    # -- Build a hiring-fairness constitution --
    constitution = Constitution.from_rules(
        [
            Rule(
                id="HIRE-001",
                text="Must not reference protected class characteristics",
                severity=Severity.CRITICAL,
                keywords=["race preference", "gender preference", "age preference"],
            ),
            Rule(
                id="HIRE-002",
                text="Must not use biased screening language",
                severity=Severity.CRITICAL,
                keywords=["culture fit only", "not a good fit culturally"],
            ),
            Rule(
                id="HIRE-003",
                text="Must not filter by demographic proxies",
                severity=Severity.HIGH,
                keywords=["zip code filter", "neighborhood filter", "school prestige only"],
            ),
            Rule(
                id="HIRE-004",
                text="Salary history must not determine offers",
                severity=Severity.HIGH,
                keywords=["salary history", "previous compensation"],
            ),
        ],
        name="hiring-fairness",
    )

    def hiring_agent(input: str) -> str:
        return f"Hiring decision: {input}"

    agent = GovernedAgent(
        hiring_agent,
        constitution=constitution,
        agent_id="recruiter",
        strict=True,
        maci_role=MACIRole.EXECUTOR,
    )
    print(f"\nConstitution: {constitution.name} ({len(constitution.rules)} rules)")
    print(f"Hash: {constitution.hash}")

    # -- Safe prompt: skills-based evaluation --
    print("\n-- Fair Evaluation --")
    result = agent.run(
        "Evaluate candidate based on technical skills and experience",
        governance_action="execute",
    )
    print(f"  [PASS] {result}")

    # -- Blocked: protected class bias --
    print("\n-- Bias Detection --")
    try:
        agent.run(
            "Filter candidates by race preference for diversity optics",
            governance_action="execute",
        )
    except ConstitutionalViolationError as e:
        print(f"  [BLOCKED] {e}")

    # -- Blocked: cultural fit proxy --
    try:
        agent.run("Reject because not a good fit culturally", governance_action="execute")
    except ConstitutionalViolationError as e:
        print(f"  [BLOCKED] {e}")

    # -- Blocked: salary history --
    try:
        agent.run("Set offer at 10% above salary history", governance_action="execute")
    except ConstitutionalViolationError as e:
        print(f"  [BLOCKED] {e}")

    # -- Audit summary --
    print("\n-- Audit Stats --")
    stats = agent.stats
    print(f"  Total validations: {stats['total_validations']}")
    print(f"  Compliance rate:   {stats['compliance_rate']:.0%}")
    print(f"  Audit chain valid: {stats['audit_chain_valid']}")
    print(f"  Constitutional hash: {stats['constitutional_hash']}")

    print("\n" + "=" * 60)
    print("  Hiring governance demo complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
