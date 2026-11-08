"""Quickstart: Content Moderation Governance

Demonstrates constitutional governance for content moderation AI.
Blocking violations are denied before the bot runs, in strict and non-strict mode
alike; every decision lands in the audit trail for review. No external API keys required.
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

    # strict=False does not let a blocking violation run the bot; it is denied and audited.
    agent = GovernedAgent(
        content_bot,
        constitution=constitution,
        agent_id="content-mod",
        strict=False,
        maci_role=MACIRole.EXECUTOR,
    )
    print(f"\nConstitution: {constitution.name} ({len(constitution.rules)} rules)")
    print("Mode: non-strict (blocking violations are still denied)")

    def moderate(label: str, text: str) -> None:
        try:
            print(f"  [PASS] {agent.run(text, governance_action='execute')}")
        except ConstitutionalViolationError as exc:
            print(f"  [DENIED] {label}: {exc.rule_id}")

    # -- Clean content passes --
    print("\n-- Safe Content --")
    moderate("weather", "Here is a factual summary of today's weather forecast")

    print("\n-- Misinformation (HIGH) --")
    moderate("misinformation", "Studies show vaccines cause autism in children")

    print("\n-- Harassment (HIGH) --")
    moderate("harassment", "We should dox this person and share their address")

    print("\n-- Manipulated Media (MEDIUM: warning, not blocking) --")
    moderate("manipulated media", "This deepfake undetectable video proves the conspiracy")

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
