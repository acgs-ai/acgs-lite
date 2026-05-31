"""Quickstart: Content Moderation Governance

Demonstrates constitutional governance for content moderation AI.
Uses non-strict mode (strict=False) to flag violations without blocking,
enabling a review workflow with full audit trail. No external API keys required.
"""

from acgs_lite import (
    Constitution,
    GovernedAgent,
    MACIRole,
    Rule,
    Severity,
)


def main() -> None:
    print("=" * 60)
    print("  ACGS Content Moderation Governance")
    print("=" * 60)

    # -- Build a content moderation constitution --
    constitution = Constitution.from_rules(
        [
            Rule(
                id="CM-001",
                text="Must not produce hate speech targeting protected groups",
                severity=Severity.CRITICAL,
                keywords=["racial slur", "ethnic slur", "hate group propaganda"],
            ),
            Rule(
                id="CM-002",
                text="Must not generate health misinformation",
                severity=Severity.HIGH,
                keywords=[
                    "vaccines cause autism",
                    "reject medical consensus",
                    "miracle cure proven",
                ],
            ),
            Rule(
                id="CM-003",
                text="Must not enable targeted harassment",
                severity=Severity.HIGH,
                keywords=["dox this person", "harass them online", "organize brigading"],
            ),
            Rule(
                id="CM-004",
                text="Must flag manipulated media claims",
                severity=Severity.MEDIUM,
                keywords=["deepfake undetectable", "fake video real", "fabricated evidence"],
            ),
        ],
        name="content-moderation",
    )

    def content_bot(input: str) -> str:
        return f"Generated: {input}"

    # -- Non-strict mode: flag but do not block --
    agent = GovernedAgent(
        content_bot,
        constitution=constitution,
        agent_id="content-mod",
        strict=False,
        maci_role=MACIRole.EXECUTOR,
    )
    print(f"\nConstitution: {constitution.name} ({len(constitution.rules)} rules)")
    print("Mode: non-strict (flag, do not block)")

    # -- Clean content passes --
    print("\n-- Safe Content --")
    result = agent.run(
        "Here is a factual summary of today's weather forecast",
        governance_action="execute",
    )
    print(f"  [PASS] {result}")

    # -- Flagged: misinformation (HIGH - would block in strict mode) --
    print("\n-- Flagged: Misinformation --")
    result = agent.run(
        "Studies show vaccines cause autism in children",
        governance_action="execute",
    )
    print(f"  [FLAGGED] {result}")

    # -- Flagged: harassment (HIGH) --
    print("\n-- Flagged: Harassment --")
    result = agent.run(
        "We should dox this person and share their address",
        governance_action="execute",
    )
    print(f"  [FLAGGED] {result}")

    # -- Flagged: manipulated media (MEDIUM - warning only) --
    print("\n-- Flagged: Manipulated Media --")
    result = agent.run(
        "This deepfake undetectable video proves the conspiracy",
        governance_action="execute",
    )
    print(f"  [FLAGGED] {result}")

    # -- Audit trail with violation details --
    print("\n-- Audit Trail --")
    stats = agent.stats
    print(f"  Total validations: {stats['total_validations']}")
    print(f"  Compliance rate:   {stats['compliance_rate']:.0%}")
    print(f"  Audit chain valid: {stats['audit_chain_valid']}")

    print("\n-- Violation Details --")
    flagged = agent.audit_log.query(valid=False)
    for entry in flagged:
        rules = ", ".join(entry.violations)
        print(f"  - action: {entry.action[:60]}...")
        print(f"    violated: [{rules}]")

    print("\n" + "=" * 60)
    print("  Content moderation governance demo complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
