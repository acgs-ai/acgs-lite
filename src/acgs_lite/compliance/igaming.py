"""iGaming Compliance (UKGC LCCP + Responsible Gambling) framework module.

Implements compliance obligations for AI systems operating in iGaming contexts
under the UK Gambling Commission's Licence Conditions and Codes of Practice (LCCP):

- SR-S1: Self-exclusion and cool-off mechanisms
- SR-S2: Reality check notifications
- SR-S3: Deposit, loss, and wager limits
- SR-S4: Problem gambling detection and flagging
- SR-S5: Links to support organisations (GamCare / BeGambleAware)
- ORG-3: Age verification and KYC
- AML-1/2: Anti-money laundering and source of funds verification
- TEC-1/2: RNG certification and RTP disclosure
- AI-1/2/3: AI-specific obligations for personalised offers, risk scoring,
  and prohibition on targeting vulnerable / self-excluded players

Risk tiers:
  HIGH    → gambling, betting, casino, sports_betting domains
  MEDIUM  → generic igaming
  LOW     → unrelated domains

Status: proposed — pending SME review against current LCCP version.
Enforcement date: None (proposed; UKGC enforcement ongoing for licensed operators)

Penalties: UKGC may suspend or revoke operating licence; unlimited fines under
the Gambling Act 2005 for breaches of licence conditions.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from acgs_lite.compliance.base import (
    ChecklistItem,
    ChecklistStatus,
    FrameworkAssessment,
)

# ---------------------------------------------------------------------------
# Checklist: (ref, requirement, legal_citation, acgs_lite_feature, blocking)
# ---------------------------------------------------------------------------
_IGAMING_ITEMS: list[tuple[str, str, str, str | None, bool]] = [
    # ── Responsible Gambling: Self-exclusion & cool-off ─────────────────────
    (
        "IGAMING-RG-1.1",
        "Self-exclusion mechanism must be available and immediately enforced. "
        "AI systems must not contact, target, or facilitate gameplay for any "
        "player who has self-excluded. Exclusion must propagate across all "
        "product lines within 24 hours.",
        "UKGC LCCP SR-S1.1",
        "GovernanceEngine — constitutional rules block self-excluded/vulnerable player targeting",
        True,
    ),
    (
        "IGAMING-RG-1.2",
        "Cool-off period of at least 24 hours must be available and enforced "
        "before a player may resume after requesting a break. AI-driven "
        "reactivation flows must respect and enforce the cooling-off window.",
        "UKGC LCCP SR-S1.2",
        "GovernanceEngine — constitutional rules block self-excluded/vulnerable player targeting",
        True,
    ),
    (
        "IGAMING-RG-1.3",
        "Deposit limit setting must be available to all players and enforced "
        "in real time. AI payment processing must reject deposits that would "
        "breach a player's active deposit limit. Limit reductions must take "
        "immediate effect; increases require a 24-hour cooling-off period.",
        "UKGC LCCP SR-S3.1",
        None,
        True,
    ),
    (
        "IGAMING-RG-1.4",
        "Loss limit setting must be available and enforced in real time. "
        "AI-driven game recommendations must cease when a player has reached "
        "their loss limit for the applicable period.",
        "UKGC LCCP SR-S3.2",
        None,
        True,
    ),
    (
        "IGAMING-RG-1.5",
        "Wager and stake limits must be enforced by the platform. AI systems "
        "that generate bet suggestions or automated wagers must respect the "
        "player's active stake-limit configuration and reject any bet that "
        "exceeds the limit.",
        "UKGC LCCP SR-S3.3",
        None,
        True,
    ),
    (
        "IGAMING-RG-1.6",
        "Reality check notifications must be displayed at configurable intervals "
        "(minimum every 60 minutes) to remind players of time and money spent. "
        "AI must not suppress or defer reality check popups.",
        "UKGC LCCP SR-S2.1",
        None,
        False,
    ),
    (
        "IGAMING-RG-1.7",
        "Problem gambling warning signs (e.g. rapid bet escalation, extended "
        "sessions, chasing losses) must be detected and flagged by AI monitoring "
        "systems. Flagged players must be referred to the safer gambling team "
        "within 24 hours.",
        "UKGC LCCP SR-S4.1",
        "GovernanceEngine — constitutional rules block self-excluded/vulnerable player targeting",
        False,
    ),
    (
        "IGAMING-RG-1.8",
        "Links to GamCare and BeGambleAware (or equivalent UKGC-approved bodies) "
        "must be prominently displayed. AI-generated communications to players "
        "must include a responsible gambling footer with current support links.",
        "UKGC LCCP SR-S5.1",
        None,
        False,
    ),
    # ── KYC / AML ────────────────────────────────────────────────────────────
    (
        "IGAMING-KYC-2.1",
        "Age verification (18+) must be completed and confirmed before a player "
        "may make a deposit or participate in real-money gameplay. AI onboarding "
        "flows must block progression until age verification is approved.",
        "UKGC LCCP ORG-3.1",
        None,
        True,
    ),
    (
        "IGAMING-KYC-2.2",
        "Full identity verification (KYC) must be completed before any withdrawal "
        "is processed. AI-driven payout systems must verify that KYC status is "
        "'approved' before initiating a withdrawal transaction.",
        "UKGC LCCP AML-1.1",
        "AuditLog — tamper-evident audit trail for all governance decisions",
        True,
    ),
    (
        "IGAMING-KYC-2.3",
        "Source of funds verification must be completed for high-value customers "
        "(typically those depositing or losing above operator-defined thresholds). "
        "AI risk-scoring must trigger enhanced due diligence workflows when "
        "thresholds are breached.",
        "UKGC LCCP AML-1.3",
        None,
        False,
    ),
    (
        "IGAMING-KYC-2.4",
        "Automated transaction monitoring must be in place to detect and report "
        "suspicious activity. AI models used for AML screening must produce "
        "auditable outputs and be reviewed at least annually for bias and drift.",
        "UKGC LCCP AML-2.1",
        "AuditLog — tamper-evident audit trail for all governance decisions",
        False,
    ),
    (
        "IGAMING-KYC-2.5",
        "Affordability checks must be conducted for high-spend players to assess "
        "whether gambling expenditure is within their financial means. AI systems "
        "using affordability data must document the data sources and inference "
        "logic used in each determination.",
        "UKGC LCCP AML-1.4",
        None,
        False,
    ),
    # ── Fair Outcomes & RNG ───────────────────────────────────────────────────
    (
        "IGAMING-FAIR-3.1",
        "Random number generators (RNGs) used in games must be certified by a "
        "UKGC-approved test house (e.g. eCOGRA, BMM, iTech Labs, NMi). "
        "AI-augmented game logic must not override or bias certified RNG outputs.",
        "UKGC LCCP TEC-1.1",
        None,
        True,
    ),
    (
        "IGAMING-FAIR-3.2",
        "Game odds and return-to-player (RTP) percentages must be disclosed "
        "transparently in a location accessible before gameplay. AI-generated "
        "or dynamic game variants must have their RTPs calculated and disclosed "
        "with the same rigour as standard games.",
        "UKGC LCCP TEC-2.1",
        None,
        False,
    ),
    (
        "IGAMING-FAIR-3.3",
        "Algorithmic personalisation of offers, promotions, and game recommendations "
        "must not systematically disadvantage specific player cohorts or exploit "
        "cognitive biases. Fairness testing across demographic groups must be "
        "documented and reviewed at least annually.",
        "UKGC LCCP AI-1.1",
        None,
        False,
    ),
    # ── AI-Specific ───────────────────────────────────────────────────────────
    (
        "IGAMING-AI-4.1",
        "AI-driven personalised offers (bonuses, free spins, tailored promotions) "
        "must be reviewed against constitutional governance rules before delivery. "
        "Offer generation pipelines must verify that the recipient is not "
        "self-excluded, is KYC-verified, and has not breached safer gambling limits.",
        "UKGC LCCP AI-2.1",
        "GovernedAgent — MACI enforcement prevents unauthorized AI actions",
        True,
    ),
    (
        "IGAMING-AI-4.2",
        "Where AI produces automated risk scores for players (e.g. problem gambling "
        "risk, AML risk, fraud risk), the scoring logic must be documented and "
        "players must have a mechanism to request an explanation and challenge "
        "decisions that significantly affect their account.",
        "UKGC LCCP AI-2.2",
        "AuditLog — tamper-evident audit trail for all governance decisions",
        False,
    ),
    (
        "IGAMING-AI-4.3",
        "AI systems must not target, contact, or send promotional material to "
        "players who are self-excluded, within a cool-off period, or flagged as "
        "vulnerable. Constitutional rule verification must be performed before "
        "any AI-initiated player communication.",
        "UKGC LCCP AI-3.1",
        "GovernanceEngine — constitutional rules block self-excluded/vulnerable player targeting",
        True,
    ),
]

# ---------------------------------------------------------------------------
# acgs-lite auto-population map: ref → evidence string
# ---------------------------------------------------------------------------
_ACGS_LITE_MAP: dict[str, str] = {
    "IGAMING-RG-1.1": (
        "acgs-lite GovernanceEngine — constitutional rule set enforces self-exclusion "
        "status checks at the governance layer, blocking any action that would "
        "contact or facilitate gameplay for self-excluded players"
    ),
    "IGAMING-RG-1.2": (
        "acgs-lite GovernanceEngine — cool-off enforcement rules prevent AI from "
        "initiating any reactivation or promotional contact within the mandated "
        "cooling-off window"
    ),
    "IGAMING-RG-1.7": (
        "acgs-lite GovernanceEngine — constitutional monitoring rules flag rapid "
        "bet escalation and session anomalies, routing at-risk players to the "
        "safer gambling team"
    ),
    "IGAMING-KYC-2.2": (
        "acgs-lite AuditLog — tamper-evident JSONL logging with cryptographic hash "
        "chaining records every KYC status change and withdrawal event, providing "
        "an tamper-evident audit trail for LCCP AML compliance"
    ),
    "IGAMING-KYC-2.4": (
        "acgs-lite AuditLog — all transaction monitoring outputs are logged with "
        "SHA-256 hash chaining, enabling replay and audit review for AML screening "
        "decisions"
    ),
    "IGAMING-AI-4.1": (
        "acgs-lite GovernedAgent — MACI role separation ensures personalised offer "
        "generation (Proposer) is independently reviewed (Validator) before delivery "
        "(Executor), with GovernanceEngine pre-flight checks against self-exclusion "
        "and limit breaches"
    ),
    "IGAMING-AI-4.2": (
        "acgs-lite AuditLog — automated risk score decisions are logged with full "
        "input/output provenance, enabling player-facing explanation and challenge "
        "workflows"
    ),
    "IGAMING-AI-4.3": (
        "acgs-lite GovernanceEngine — constitutional rules execute a mandatory "
        "vulnerability and self-exclusion check before any AI-initiated player "
        "communication is permitted"
    ),
}


class IGamingFramework:
    """iGaming Compliance (UKGC LCCP + Responsible Gambling) assessor.

    Covers responsible gambling obligations (self-exclusion, limits, reality checks,
    problem gambling detection), KYC/AML requirements, RNG certification, and
    AI-specific obligations under the UKGC Licence Conditions and Codes of Practice.

    Status: proposed — pending SME review against current LCCP version.
    Enforcement date: None (UKGC enforcement ongoing for licensed operators).

    Penalties:
    - Licence suspension or revocation under Gambling Act 2005 s.116/119
    - Unlimited financial penalties for breach of licence conditions
    - Criminal prosecution for operation without a valid licence

    Usage::

        from acgs_lite.compliance.igaming import IGamingFramework

        framework = IGamingFramework()
        assessment = framework.assess({
            "system_id": "player-ai-v2",
            "domain": "sports_betting",
            "jurisdiction": "united_kingdom",
        })
    """

    framework_id: str = "igaming"
    framework_name: str = "iGaming Compliance (UKGC LCCP + Responsible Gambling)"
    jurisdiction: str = "united_kingdom"
    status: str = "proposed"
    enforcement_date: str | None = None

    def get_checklist(self, system_description: dict[str, Any]) -> list[ChecklistItem]:
        """Generate iGaming compliance checklist items.

        All 19 checklist items are returned regardless of system_description,
        as the LCCP applies to all AI systems operating within a UKGC-licensed
        environment.

        Args:
            system_description: Dict describing the AI system. The ``domain``
                key may be used for informational risk-tier inference but does
                not filter checklist items.

        Returns:
            List of :class:`~acgs_lite.compliance.base.ChecklistItem` instances,
            one per LCCP obligation.
        """
        items: list[ChecklistItem] = []
        for ref, requirement, legal_citation, acgs_lite_feature, blocking in _IGAMING_ITEMS:
            items.append(
                ChecklistItem(
                    ref=ref,
                    requirement=requirement,
                    legal_citation=legal_citation,
                    acgs_lite_feature=acgs_lite_feature,
                    blocking=blocking,
                )
            )
        return items

    def auto_populate_acgs_lite(self, checklist: list[ChecklistItem]) -> None:
        """Mark items that acgs-lite directly satisfies as COMPLIANT.

        Items whose ``ref`` appears in ``_ACGS_LITE_MAP`` are marked compliant
        with structured evidence text describing which acgs-lite feature
        satisfies the obligation.

        Args:
            checklist: List of ChecklistItem instances (mutated in place).
        """
        for item in checklist:
            if item.ref in _ACGS_LITE_MAP:
                item.mark_complete(_ACGS_LITE_MAP[item.ref])

    def assess(self, system_description: dict[str, Any]) -> FrameworkAssessment:
        """Run full iGaming LCCP compliance assessment.

        Generates the checklist, auto-populates items satisfied by acgs-lite,
        computes the compliance score, identifies blocking gaps, and returns
        an immutable :class:`~acgs_lite.compliance.base.FrameworkAssessment`.

        Args:
            system_description: Dict describing the AI system. Expected keys:
                - system_id: str (required)
                - domain: str (optional, used to populate risk_tier hint)
                - jurisdiction: str (optional)
                - Additional framework-specific keys.

        Returns:
            Frozen FrameworkAssessment with score, items, gaps, and recommendations.
        """
        checklist = self.get_checklist(system_description)
        self.auto_populate_acgs_lite(checklist)

        total = len(checklist) or 1
        compliant = sum(1 for i in checklist if i.status == ChecklistStatus.COMPLIANT)
        acgs_auto = sum(1 for i in checklist if i.ref in _ACGS_LITE_MAP)

        gaps = tuple(
            f"{item.ref}: {item.requirement[:120]}"
            for item in checklist
            if item.status in (ChecklistStatus.PENDING, ChecklistStatus.NON_COMPLIANT)
            and item.blocking
        )

        recommendations = tuple(
            f"Address: {item.ref} — {item.requirement[:100]}"
            for item in checklist
            if item.status in (ChecklistStatus.PENDING, ChecklistStatus.NON_COMPLIANT)
            and item.blocking
        )[:5]

        return FrameworkAssessment(
            framework_id=self.framework_id,
            framework_name=self.framework_name,
            compliance_score=round(compliant / total, 4),
            items=tuple(i.to_dict() for i in checklist),
            gaps=gaps,
            acgs_lite_coverage=round(acgs_auto / total, 4),
            recommendations=recommendations,
            assessed_at=datetime.now(timezone.utc).isoformat(),
        )


def infer_risk_tier(system_description: dict[str, Any]) -> str:
    """Infer the iGaming risk tier from system_description fields.

    Returns one of: ``"HIGH"`` | ``"MEDIUM"`` | ``"LOW"``.

    Priority order:
    1. ``domain`` matched against high-risk gambling domains → ``"HIGH"``
    2. ``domain`` == ``"igaming"`` → ``"MEDIUM"``
    3. Default: ``"LOW"``

    Usage::

        tier = infer_risk_tier({"domain": "sports_betting"})  # → "HIGH"
        tier = infer_risk_tier({"domain": "igaming"})         # → "MEDIUM"
        tier = infer_risk_tier({"domain": "saas"})            # → "LOW"
    """
    domain: str = (system_description.get("domain") or "").lower().replace(" ", "_")

    _high_risk_domains: frozenset[str] = frozenset(
        {"gambling", "betting", "casino", "sports_betting"}
    )

    if domain in _high_risk_domains:
        return "HIGH"
    if domain == "igaming":
        return "MEDIUM"
    return "LOW"
