"""Runtime compliance checker — extracts obligations from decision context.

Given a decision context dict (frameworks applied, article refs, verdict),
produces the list of RuntimeObligation instances that apply to this decision.

Constitutional Hash: 608508a9bd224290

Usage::

    from acgs_lite.compliance.runtime_checker import RuntimeComplianceChecker

    checker = RuntimeComplianceChecker()
    obligations = checker.check({
        "compliance_frameworks": ["eu_ai_act", "hipaa_ai"],
        "matched_rules": ["EU-AIA Art.14(1)", "HIPAA §164.502"],
        "verdict": "allow",
        "risk_score": 0.9,
    })
    blocking = [o for o in obligations if o.is_blocking and not o.satisfied]
"""

from __future__ import annotations

from acgs_lite.compliance.obligation_mappings import get_obligations_for_refs
from acgs_lite.compliance.runtime_obligations import (
    ObligationType,
    RuntimeObligation,
)

# Article refs emitted by each framework that always imply a HITL obligation
# when the risk tier is HIGH or UNACCEPTABLE.
_HIGH_RISK_HITL_REFS: frozenset[str] = frozenset(
    [
        "EU-AIA Art.14(1)",
        "EU-AIA Art.14(4)",
        "EU-AIA Art.14(5)",
        "GDPR Art.22(1)",
        "GDPR Art.22(3)",
    ]
)

# Article refs from assessment checklist items that imply PHI_GUARD
_PHI_REFS: frozenset[str] = frozenset(
    [
        "HIPAA §164.502",
        "HIPAA §164.312",
    ]
)


class RuntimeComplianceChecker:
    """Extract runtime obligations applicable to a governance decision.

    This class is stateless and safe for reuse across decisions.

    The ``check()`` method accepts a flexible dict describing the decision
    context — the same shape used inside CDP records and GovernedAgent.
    """

    def check(self, decision_context: dict) -> list[RuntimeObligation]:
        """Derive runtime obligations from a decision context dictionary.

        The dict may contain any subset of these keys:
        - ``compliance_frameworks``: list[str] — e.g. ["eu_ai_act", "hipaa_ai"]
        - ``matched_rules``: list[str] — article refs matched by the engine
        - ``violated_rules``: list[str] — article refs violated
        - ``verdict``: str — "allow" | "deny" | "conditional" | ...
        - ``risk_score``: float — 0.0–1.0
        - ``human_approval``: bool | None — whether human approval was given
        - ``domain``: str — e.g. "healthcare", "legal", "gambling"

        Returns:
            List of RuntimeObligation instances relevant to this decision.
            Items are not yet satisfied — callers update `.satisfied` as needed.
        """
        all_refs: list[str] = []
        all_refs.extend(decision_context.get("matched_rules") or [])
        all_refs.extend(decision_context.get("violated_rules") or [])

        # Also synthesize refs from high-level framework presence + risk score
        risk_score = decision_context.get("risk_score", 0.0) or 0.0
        frameworks = set(decision_context.get("compliance_frameworks") or [])
        domain = (decision_context.get("domain") or "").lower()

        # Infer refs from framework presence when not already in matched_rules
        inferred = self._infer_refs(frameworks, risk_score, domain)
        for ref in inferred:
            if ref not in all_refs:
                all_refs.append(ref)

        obligations = get_obligations_for_refs(all_refs)

        # Mark satisfied obligations based on context signals
        human_approval = decision_context.get("human_approval")
        obligations = self._apply_satisfaction(obligations, human_approval=human_approval)

        return obligations

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _infer_refs(self, frameworks: set[str], risk_score: float, domain: str) -> list[str]:
        """Infer article refs from framework presence and risk signals."""
        refs: list[str] = []

        # EU AI Act: high risk_score triggers HITL and AUDIT obligations
        if "eu_ai_act" in frameworks and risk_score >= 0.7:
            refs.extend(["EU-AIA Art.14(1)", "EU-AIA Art.12(1)"])

        # HIPAA: always triggers PHI_GUARD
        if "hipaa_ai" in frameworks:
            refs.extend(["HIPAA §164.502", "HIPAA §164.530"])

        # GDPR: automated decision-making triggers HITL + CONSENT
        if "gdpr" in frameworks:
            refs.extend(["GDPR Art.22(1)", "GDPR Art.6(1)"])

        # SOC2: always audit-required
        if "soc2_ai" in frameworks:
            refs.append("SOC2 CC7.1")

        # Domain-level inference
        if domain in ("healthcare", "medical", "clinical") and "HIPAA §164.502" not in refs:
            refs.append("HIPAA §164.502")

        return refs

    def _apply_satisfaction(
        self,
        obligations: list[RuntimeObligation],
        *,
        human_approval: bool | None,
    ) -> list[RuntimeObligation]:
        """Mark obligations satisfied based on decision context signals."""
        result: list[RuntimeObligation] = []
        for ob in obligations:
            if ob.obligation_type == ObligationType.HITL_REQUIRED and human_approval is True:
                result.append(ob.satisfy(evidence="human_approval=True in decision context"))
            else:
                result.append(ob)
        return result
