"""Governance validation engine.

The engine evaluates actions against constitutional rules and produces
structured validation results with full audit trails.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from acgs_lite.constitution import Severity
from acgs_lite.constitution.rule import ViolationAction

if TYPE_CHECKING:
    from .models import ValidationResult

_SEVERITY_VALUES: frozenset[str] = frozenset(s.value for s in Severity)


@dataclass(frozen=True)
class BatchValidationResult:
    """exp107: Aggregate result of a batch governance validation.

    Returned by ``GovernanceEngine.validate_batch_report()``. Provides per-action
    results alongside aggregate statistics for orchestrators that need to assess
    the overall compliance posture of a batch of agent actions — e.g., before
    committing a pipeline stage, processing a queue of messages, or running a
    multi-step workflow.

    Attributes:
        results: Individual ``ValidationResult`` for each action (same order as input).
        total: Total number of actions validated.
        allowed: Count of actions that passed all rules.
        denied: Count of actions that were blocked (had critical/high violations).
        escalated: Count of actions that have medium/low violations (warn only).
        compliance_rate: Fraction of clean actions (allowed / total).
        critical_rule_ids: Rule IDs that triggered at least one critical violation.
        summary: Human-readable one-line summary of the batch result.
    """

    results: tuple[ValidationResult, ...]  # frozen
    total: int
    allowed: int
    denied: int
    escalated: int
    compliance_rate: float
    critical_rule_ids: tuple[str, ...]
    summary: str

    def to_dict(self) -> dict[str, object]:
        """Serialise batch result to a JSON-compatible dict."""
        return {
            "total": self.total,
            "allowed": self.allowed,
            "denied": self.denied,
            "escalated": self.escalated,
            "compliance_rate": self.compliance_rate,
            "critical_rule_ids": list(self.critical_rule_ids),
            "summary": self.summary,
            "results": [
                {
                    "action": r.action,
                    "valid": r.valid,
                    "violations": [
                        {"rule_id": v.rule_id, "severity": v.severity.value} for v in r.violations
                    ],
                }
                for r in self.results
            ],
        }


class BatchValidationMixin:
    """Mixin providing batch validation methods for GovernanceEngine."""

    # Type stubs for attributes provided by GovernanceEngine (the concrete host class).
    strict: bool
    _const_hash: str
    _rule_id_to_wa: dict[str, ViolationAction]

    def validate(
        self,
        action: str,
        *,
        agent_id: str = "anonymous",
        context: dict[str, Any] | None = None,
        strict: bool | None = None,
    ) -> ValidationResult:
        raise NotImplementedError  # pragma: no cover

    def validate_batch(
        self,
        actions: list[str],
        *,
        agent_id: str = "anonymous",
    ) -> list[ValidationResult]:
        """Validate multiple actions without raising in strict mode.

        Uses the per-call ``strict=False`` override instead of mutating
        ``self.strict``, so concurrent calls on a shared engine remain
        thread-safe and never observe a fail-open strictness window.
        """
        return [self.validate(a, agent_id=agent_id, strict=False) for a in actions]

    def validate_batch_report(
        self,
        actions: list[str | tuple[str, dict[str, Any]]],
        *,
        agent_id: str = "anonymous",
    ) -> BatchValidationResult:
        """exp107: Validate a batch of actions and return aggregate statistics.

        Accepts plain action strings or (action, context) pairs. Never raises
        in strict mode — all violations are captured in the returned result.
        Useful for orchestrators that need to assess a batch of agent outputs
        before routing them to downstream systems.

        Args:
            actions: List of action strings OR (action, context_dict) tuples.
                     Plain strings use empty context ``{}``.
            agent_id: Agent performing the actions.

        Returns:
            ``BatchValidationResult`` with per-action results and aggregate stats.

        Example::

            report = engine.validate_batch_report([
                "deploy to staging",
                ("deploy to production", {"environment": "prod"}),
                "auto-approve merge request",
            ])
            print(report.compliance_rate)   # 0.666...
            print(report.critical_rule_ids) # ('ACGS-004',)
            print(report.summary)
        """
        from acgs_lite.errors import ConstitutionalViolationError

        from .models import ValidationResult, Violation

        individual: list[ValidationResult] = []
        for item in actions:
            if isinstance(item, tuple):
                action, ctx = item[0], item[1]
            else:
                action, ctx = item, None
            try:
                individual.append(
                    self.validate(action, agent_id=agent_id, context=ctx, strict=False)
                )
            except ConstitutionalViolationError as exc:
                # HALT workflow actions raise regardless of strict mode;
                # construct a synthetic ValidationResult so the batch never raises.
                _sev = (
                    Severity(exc.severity)
                    if exc.severity in _SEVERITY_VALUES
                    else Severity.CRITICAL
                )
                _viol = Violation(
                    rule_id=exc.rule_id or "UNKNOWN",
                    rule_text=str(exc),
                    severity=_sev,
                    matched_content=action[:200],
                    category="constitutional",
                )
                individual.append(
                    ValidationResult(
                        valid=False,
                        constitutional_hash=self._const_hash,
                        violations=[_viol],
                        action=action,
                        agent_id=agent_id,
                    )
                )

        total = len(individual)
        allowed = 0
        denied = 0
        escalated = 0
        critical_ids: set[str] = set()

        wa_lookup = getattr(self, "_rule_id_to_wa", {})
        for r in individual:
            if r.valid and not r.violations and not r.warnings:
                allowed += 1
            elif not r.valid or any(v.severity.blocks() for v in r.violations):
                denied += 1
                blocking_ids = [
                    v.rule_id
                    for v in r.violations
                    if v.severity.blocks()
                    or wa_lookup.get(v.rule_id, ViolationAction.WARN) is not ViolationAction.WARN
                ]
                if blocking_ids:
                    critical_ids.update(blocking_ids)
                elif not r.valid:
                    critical_ids.update(v.rule_id for v in r.violations)
            else:
                escalated += 1

        compliance_rate = allowed / total if total > 0 else 1.0

        if denied == 0 and escalated == 0:
            summary = f"PASS: all {total} actions compliant"
        elif denied > 0:
            summary = (
                f"FAIL: {denied}/{total} actions blocked, "
                f"{escalated} warnings, "
                f"compliance={compliance_rate:.1%}"
            )
        else:
            summary = (
                f"WARN: {escalated}/{total} actions have warnings, compliance={compliance_rate:.1%}"
            )

        return BatchValidationResult(
            results=tuple(individual),
            total=total,
            allowed=allowed,
            denied=denied,
            escalated=escalated,
            compliance_rate=compliance_rate,
            critical_rule_ids=tuple(sorted(critical_ids)),
            summary=summary,
        )
