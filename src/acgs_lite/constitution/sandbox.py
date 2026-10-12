"""exp193: PolicySandbox — isolated rule testing environment.

Safe experimentation space for constitution changes.  Runs candidate rule
sets against sample traffic, compares outcomes to the production constitution,
and produces compatibility reports before deployment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from acgs_lite.errors import ConstitutionalViolationError


@dataclass(frozen=True)
class SandboxOutcome:
    action: str
    production_decision: str
    sandbox_decision: str
    changed: bool
    production_violations: list[str]
    sandbox_violations: list[str]
    new_violations: list[str]
    removed_violations: list[str]


@dataclass
class SandboxReport:
    total_actions: int = 0
    changed_decisions: int = 0
    newly_blocked: int = 0
    newly_allowed: int = 0
    unchanged: int = 0
    outcomes: list[SandboxOutcome] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def compatibility_score(self) -> float:
        if self.total_actions == 0:
            return 1.0
        return self.unchanged / self.total_actions

    @property
    def risk_score(self) -> float:
        if self.total_actions == 0:
            return 0.0
        return (self.newly_allowed * 3 + self.newly_blocked) / (self.total_actions * 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_actions": self.total_actions,
            "changed_decisions": self.changed_decisions,
            "newly_blocked": self.newly_blocked,
            "newly_allowed": self.newly_allowed,
            "unchanged": self.unchanged,
            "compatibility_score": round(self.compatibility_score, 4),
            "risk_score": round(self.risk_score, 4),
            "generated_at": self.generated_at.isoformat(),
            "outcomes": [
                {
                    "action": o.action,
                    "production_decision": o.production_decision,
                    "sandbox_decision": o.sandbox_decision,
                    "changed": o.changed,
                    "new_violations": o.new_violations,
                    "removed_violations": o.removed_violations,
                }
                for o in self.outcomes
                if o.changed
            ],
        }


class PolicySandbox:
    """Isolated testing environment for governance rule changes.

    Example::

        from acgs_lite import Constitution, GovernanceEngine
        prod = GovernanceEngine(production_constitution)
        sandbox = PolicySandbox(prod)
        report = sandbox.test_constitution(
            candidate_constitution,
            sample_actions=["deploy to prod", "read user data", "delete logs"],
        )
        print(report.compatibility_score)
    """

    def __init__(self, production_engine: Any) -> None:
        self._production = production_engine
        self._history: list[SandboxReport] = []

    def test_constitution(
        self,
        candidate_constitution: Any,
        sample_actions: list[str],
        *,
        context: dict[str, Any] | None = None,
    ) -> SandboxReport:
        """Run sample actions against both production and candidate constitutions."""
        from acgs_lite import GovernanceEngine

        candidate_engine = GovernanceEngine(candidate_constitution)
        report = SandboxReport()

        for action in sample_actions:
            prod_result = self._safe_validate(self._production, action, context)
            cand_result = self._safe_validate(candidate_engine, action, context)

            prod_decision = prod_result.get("decision", "allow")
            cand_decision = cand_result.get("decision", "allow")
            prod_violations = prod_result.get("violations", [])
            cand_violations = cand_result.get("violations", [])

            prod_viol_ids = set(prod_violations)
            cand_viol_ids = set(cand_violations)

            changed = prod_decision != cand_decision
            outcome = SandboxOutcome(
                action=action,
                production_decision=prod_decision,
                sandbox_decision=cand_decision,
                changed=changed,
                production_violations=prod_violations,
                sandbox_violations=cand_violations,
                new_violations=sorted(cand_viol_ids - prod_viol_ids),
                removed_violations=sorted(prod_viol_ids - cand_viol_ids),
            )
            report.outcomes.append(outcome)
            report.total_actions += 1

            if changed:
                report.changed_decisions += 1
                if cand_decision in ("deny", "escalate") and prod_decision == "allow":
                    report.newly_blocked += 1
                elif cand_decision == "allow" and prod_decision in ("deny", "escalate"):
                    report.newly_allowed += 1
            else:
                report.unchanged += 1

        self._history.append(report)
        return report

    def test_rule_addition(
        self,
        new_rules: list[dict[str, Any]],
        sample_actions: list[str],
        *,
        context: dict[str, Any] | None = None,
    ) -> SandboxReport:
        """Test adding rules to the production constitution."""
        prod_constitution = self._production.constitution
        existing_rules = [r.model_dump(mode="json") for r in prod_constitution.rules]
        combined = existing_rules + new_rules

        from acgs_lite import Constitution

        candidate = Constitution(rules=combined, name=f"{prod_constitution.name}-sandbox")
        return self.test_constitution(candidate, sample_actions, context=context)

    def test_rule_removal(
        self,
        rule_ids_to_remove: list[str],
        sample_actions: list[str],
        *,
        context: dict[str, Any] | None = None,
    ) -> SandboxReport:
        """Test removing rules from the production constitution."""
        prod_constitution = self._production.constitution
        remaining = [
            r.model_dump(mode="json")
            for r in prod_constitution.rules
            if r.id not in rule_ids_to_remove
        ]

        from acgs_lite import Constitution

        candidate = Constitution(rules=remaining, name=f"{prod_constitution.name}-sandbox")
        return self.test_constitution(candidate, sample_actions, context=context)

    def history(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._history]

    def summary(self) -> dict[str, Any]:
        return {
            "total_runs": len(self._history),
            "avg_compatibility": (
                sum(r.compatibility_score for r in self._history) / len(self._history)
                if self._history
                else 0.0
            ),
            "avg_risk": (
                sum(r.risk_score for r in self._history) / len(self._history)
                if self._history
                else 0.0
            ),
        }

    @staticmethod
    def _safe_validate(engine: Any, action: str, context: dict[str, Any] | None) -> dict[str, Any]:
        try:
            result = engine.validate(action, context=context or {})
            decision = "allow"
            violations: list[str] = []
            if hasattr(result, "violations") and result.violations:
                violations = [
                    v.rule_id if hasattr(v, "rule_id") else str(v) for v in result.violations
                ]
                decision = "deny"
            if hasattr(result, "decision"):
                decision = result.decision
            return {"decision": decision, "violations": violations}
        except (ValueError, TypeError, RuntimeError, AttributeError, ConstitutionalViolationError):
            return {"decision": "deny", "violations": ["EXCEPTION"]}
