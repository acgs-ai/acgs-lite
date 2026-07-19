"""EU AI Act Compliance Quickstart — acgs-lite

Demonstrates how to achieve Article 12 (Record-Keeping), Article 13
(Transparency), and Article 14 (Human Oversight) compliance in ~50 lines.

Run:
    python examples/eu_ai_act_quickstart.py

No external services required — all compliance infrastructure runs in-process.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from acgs_lite.eu_ai_act import (
    Article12Logger,
    ComplianceChecklist,
    HumanOversightGateway,
    RiskClassifier,
    SystemDescription,
    TransparencyDisclosure,
)

# ---------------------------------------------------------------------------
# Simulated LLM responses (replace with your actual LLM calls)
# ---------------------------------------------------------------------------


def _simulate_cv_screen(cv_text: str) -> str:
    """Simulated LLM screening response."""
    if "python" in cv_text.lower():
        return "SHORTLIST: Strong Python background, meets requirements."
    return "REJECT: Candidate does not meet minimum technical requirements."


def _compute_impact(response: str) -> float:
    """Simple impact score — rejections have higher impact."""
    return 0.9 if response.startswith("REJECT") else 0.3


# ---------------------------------------------------------------------------
# Step 1: Classify your system's risk level
# ---------------------------------------------------------------------------


def classify_system() -> None:
    print("\n=== Step 1: Risk Classification ===")
    classifier = RiskClassifier()
    result = classifier.classify(
        SystemDescription(
            system_id="cv-screener-v1",
            purpose="Automated first-pass screening of job applications",
            domain="employment",
            autonomy_level=3,
            human_oversight=True,
            employment=True,  # Annex III, point 4
        )
    )
    print(f"Risk Level:  {result.level.value.upper()}")
    print(f"Legal Basis: {result.article_basis}")
    print(f"Deadline:    {result.high_risk_deadline}")
    print(f"Requires Article 12 logging: {result.requires_article12_logging}")
    print(f"Requires human oversight:    {result.requires_human_oversight}")
    print("Obligations:")
    for obligation in result.obligations[:4]:
        print(f"  - {obligation}")


# ---------------------------------------------------------------------------
# Step 2: Article 12 — automatic tamper-evident logging
# ---------------------------------------------------------------------------


def article12_demo() -> Article12Logger:
    print("\n=== Step 2: Article 12 Record-Keeping ===")
    log = Article12Logger(system_id="cv-screener-v1", risk_level="high_risk")

    cv_samples = [
        "Experienced Python developer with 5 years Django.",
        "Junior designer with Photoshop and Figma skills.",
        "Full-stack engineer: Python, Go, Kubernetes.",
    ]

    for cv in cv_samples:
        result = log.log_call(
            operation="screen_candidate",
            call=lambda cv=cv: _simulate_cv_screen(cv),
            input_text=cv,
            human_oversight_applied=False,
        )
        print(f"  Screened → {result[:60]}")

    print(f"\nRecords logged: {log.record_count}")
    print(f"Chain valid:    {log.verify_chain()}")

    summary = log.compliance_summary()
    print(f"Article 12 compliant: {summary['compliant']}")

    # Export append-only JSONL
    log.export_jsonl("/tmp/cv_screener_audit.jsonl")
    print("Exported: /tmp/cv_screener_audit.jsonl")

    return log  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Step 3: Article 14 — human oversight for high-impact decisions
# ---------------------------------------------------------------------------


def article14_demo() -> None:
    print("\n=== Step 3: Article 14 Human Oversight ===")

    review_requests: list[str] = []

    def notify_reviewer(decision: object) -> None:
        review_requests.append(getattr(decision, "decision_id", ""))
        print(f"  [NOTIFICATION] Human review requested: {getattr(decision, 'decision_id', '')}")

    gateway = HumanOversightGateway(
        system_id="cv-screener-v1",
        oversight_threshold=0.8,
        on_review_required=notify_reviewer,
    )

    # High-impact rejection → requires human review
    rejection = gateway.submit(
        operation="reject_candidate",
        ai_output="REJECT: Candidate does not meet minimum technical requirements.",
        impact_score=0.9,
        context={"candidate_id": "cand-001", "role": "Senior Python Engineer"},
    )
    print(f"  Rejection outcome: {rejection.outcome.value}")  # pending
    print(f"  Requires review:   {rejection.requires_human_review}")

    # Human reviews and approves
    approved = gateway.approve(
        rejection.decision_id,
        reviewer_id="hr-manager-jane",
        notes="Confirmed — candidate lacks Go experience required for the role.",
    )
    print(f"  After review:      {approved.outcome.value}")  # approved

    # Low-impact formatting → auto-approved
    auto = gateway.submit(
        operation="format_cv_header",
        ai_output="Reformatted header section.",
        impact_score=0.1,
    )
    print(f"  Low-impact auto:   {auto.outcome.value}")  # auto_approved

    summary = gateway.compliance_summary()
    print(f"Article 14 compliant: {summary['compliant']}")


# ---------------------------------------------------------------------------
# Step 4: Article 13 — transparency disclosure
# ---------------------------------------------------------------------------


def article13_demo() -> None:
    print("\n=== Step 4: Article 13 Transparency ===")
    disclosure = TransparencyDisclosure(
        system_id="cv-screener-v1",
        system_name="CV Screening Assistant",
        provider="Acme Corp",
        intended_purpose=(
            "Automated first-pass screening of job applications for software engineering roles"
        ),
        capabilities=[
            "Classifies CVs as shortlist / review / reject",
            "Scores technical skills against job description requirements",
            "Flags missing mandatory qualifications",
        ],
        limitations=[
            "Validated for English-language CVs only",
            "Accuracy below 85% for candidates from non-OECD universities",
            "Not validated for creative, management, or leadership roles",
        ],
        human_oversight_measures=[
            "All 'reject' decisions reviewed by HR coordinator within 48 hours",
            "Monthly accuracy audits by platform team",
            "Hiring managers can override any AI decision",
        ],
        known_biases=[
            "Trained on historical hiring data which may reflect past biases",
            "Name-based bias mitigation applied but not fully validated",
        ],
        performance_metrics={
            "precision": "0.87",
            "recall": "0.91",
            "validation_set": "50,000 CVs",
        },
        contact_email="ai-compliance@acme.com",
        ai_system_disclosure=(
            "Your application is being reviewed by an AI system. "
            "A human HR coordinator will review all AI-generated rejections."
        ),
    )

    missing = disclosure.validate()
    print(f"Required fields populated: {len(missing) == 0}")
    if missing:
        print(f"Missing: {missing}")

    card = disclosure.to_system_card()
    print(f"System card generated: {len(card)} fields")
    print(f"Validation status:     {card['validation_status']}")


# ---------------------------------------------------------------------------
# Step 5: Compliance checklist
# ---------------------------------------------------------------------------


def compliance_checklist_demo() -> None:
    print("\n=== Step 5: Compliance Checklist ===")
    checklist = ComplianceChecklist(system_id="cv-screener-v1", risk_level="high_risk")

    # Auto-populate items that acgs-lite directly satisfies
    checklist.auto_populate_acgs_lite()

    # Mark remaining items (in real usage: attach your evidence)
    checklist.mark_complete(
        "Article 10",
        evidence="Bias audit report 2025-Q4 at docs/bias-audit.pdf",
    )
    checklist.mark_complete(
        "Article 11",
        evidence="Annex IV documentation at docs/annex-iv.md v2.1",
    )
    checklist.mark_complete(
        "Article 15",
        evidence="Accuracy validation 2025-11, precision=0.87, recall=0.91",
    )
    checklist.mark_not_applicable(
        "Article 16",
        reason="CE marking handled by legal team",
    )

    print(f"Compliance score: {checklist.compliance_score:.0%}")
    print(f"Gate clear:       {checklist.is_gate_clear}")

    if not checklist.is_gate_clear:
        print("Blocking gaps:")
        for gap in checklist.blocking_gaps:
            print(f"  - {gap}")

    # Print item-by-item status
    print("\nChecklist summary:")
    for item in checklist.items:
        icon = (
            "✅"
            if item.status.value == "compliant"
            else ("➖" if item.status.value == "not_applicable" else "⏳")
        )
        print(f"  {icon} {item.article_ref:<15} {item.status.value}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("EU AI Act Compliance Demo — acgs-lite")
    print("=" * 50)
    print(
        "High-risk provisions deadline: 2027-12-02 "
        "(Annex III stand-alone; deferred by 2026 Digital Omnibus)"
    )

    classify_system()
    article12_demo()
    article14_demo()
    article13_demo()
    compliance_checklist_demo()

    print("\n=== Done ===")
    print("Your AI system now has:")
    print("  ✅ Article 12 — Tamper-evident automatic logging")
    print("  ✅ Article 13 — Transparency system card")
    print("  ✅ Article 14 — Human oversight gateway")
    print("  ✅ Risk classification per Article 6 + Annex III")
    print("  ✅ Conformity assessment checklist")
    print()
    print("pip install acgs   # Get started in 5 minutes")


if __name__ == "__main__":
    main()
