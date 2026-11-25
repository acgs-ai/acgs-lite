"""Self-evolution system for safe, governed policy improvement.

The engine in this module does **not** mutate a constitution directly. It turns
runtime decision feedback into scored evolution candidates, then optionally
submits those candidates to :class:`AmendmentProtocol` so MACI separation,
quorum, voting, ratification, and audit trails still control every change.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .amendments import Amendment, AmendmentProtocol, AmendmentType
from .rule import Severity, ViolationAction

if TYPE_CHECKING:
    from acgs_lite.engine.decision_record import GovernanceDecisionRecord

    from .constitution import Constitution


_RE_WORD = re.compile(r"[a-z0-9][a-z0-9_\-]{2,}")
_STOP_WORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "that",
    "this",
    "must",
    "should",
    "would",
    "could",
    "into",
    "action",
    "agent",
    "request",
    "user",
}


@dataclass(frozen=True, slots=True)
class SelfEvolutionConfig:
    """Tunable controls for governance self-evolution.

    Args:
        min_support: Minimum repeated evidence count before a candidate is emitted.
        min_fitness: Minimum fitness score for amendment drafting.
        low_confidence_threshold: Allowed decisions below this confidence become
            review candidates.
        max_candidates: Maximum candidates returned per evaluation pass.
        proposer_id: Identity used when drafting amendments. Validators/executors
            must be separate actors in the amendment protocol.
    """

    min_support: int = 2
    min_fitness: float = 0.55
    low_confidence_threshold: float = 0.6
    max_candidates: int = 10
    proposer_id: str = "self-evolution-agent"
    max_blast_radius: float = 0.25
    max_weighted_risk: float = 0.35
    allow_regressions: bool = False

    def __post_init__(self) -> None:
        if self.min_support < 1:
            raise ValueError("min_support must be >= 1")
        if not 0.0 <= self.min_fitness <= 1.0:
            raise ValueError("min_fitness must be between 0 and 1")
        if not 0.0 <= self.low_confidence_threshold <= 1.0:
            raise ValueError("low_confidence_threshold must be between 0 and 1")
        if self.max_candidates < 1:
            raise ValueError("max_candidates must be >= 1")
        if not 0.0 <= self.max_blast_radius <= 1.0:
            raise ValueError("max_blast_radius must be between 0 and 1")
        if not 0.0 <= self.max_weighted_risk <= 1.0:
            raise ValueError("max_weighted_risk must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class EvolutionEvidence:
    """A compact evidence item supporting an evolution candidate."""

    audit_entry_id: str = ""
    decision: str = ""
    action: str = ""
    rule_ids: tuple[str, ...] = ()
    confidence: float = 1.0
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_entry_id": self.audit_entry_id,
            "decision": self.decision,
            "action": self.action,
            "rule_ids": list(self.rule_ids),
            "confidence": self.confidence,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class EvolutionCandidate:
    """A scored constitutional change candidate."""

    candidate_id: str
    amendment_type: AmendmentType
    title: str
    description: str
    changes: dict[str, Any]
    fitness: float
    risk: str
    support: int
    evidence: tuple[EvolutionEvidence, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "amendment_type": self.amendment_type.value,
            "title": self.title,
            "description": self.description,
            "changes": self.changes,
            "fitness": round(self.fitness, 4),
            "risk": self.risk,
            "support": self.support,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class CandidateGateResult:
    """Pre-amendment simulation gate result for one candidate."""

    candidate: EvolutionCandidate
    passed: bool
    recommendation: str
    blast_radius: float
    weighted_risk: float
    regressions: int
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate.to_dict(),
            "passed": self.passed,
            "recommendation": self.recommendation,
            "blast_radius": round(self.blast_radius, 4),
            "weighted_risk": round(self.weighted_risk, 4),
            "regressions": self.regressions,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class SelfEvolutionReport:
    """Result of one self-evolution evaluation pass."""

    input_records: int
    candidates: tuple[EvolutionCandidate, ...]
    skipped: dict[str, int] = field(default_factory=dict)

    @property
    def actionable_candidates(self) -> tuple[EvolutionCandidate, ...]:
        return self.candidates

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_records": self.input_records,
            "candidate_count": len(self.candidates),
            "skipped": dict(self.skipped),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


@dataclass(frozen=True, slots=True)
class EvolutionGateReport:
    """Aggregate pre-amendment safety gate report."""

    evaluated: int
    passed: tuple[CandidateGateResult, ...]
    failed: tuple[CandidateGateResult, ...]

    @property
    def approved_candidates(self) -> tuple[EvolutionCandidate, ...]:
        return tuple(result.candidate for result in self.passed)

    def to_evolution_report(
        self,
        *,
        input_records: int = 0,
        skipped: Mapping[str, int] | None = None,
    ) -> SelfEvolutionReport:
        """Return an amendment-ready report containing only gate-approved candidates."""

        return SelfEvolutionReport(
            input_records=input_records,
            candidates=self.approved_candidates,
            skipped=dict(skipped or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluated": self.evaluated,
            "passed": [result.to_dict() for result in self.passed],
            "failed": [result.to_dict() for result in self.failed],
        }


class SelfEvolutionEngine:
    """Generate safe constitutional evolution proposals from runtime feedback.

    The engine currently detects three practical improvement classes:

    * uncovered denials: denied actions with violations but no active rule hit,
      producing an ``add_rule`` proposal;
    * repeated hot rules: frequently triggered rules, producing a bounded
      priority/severity tuning proposal;
    * low-confidence allows: allowed actions under the confidence threshold,
      producing a human-review rule proposal.
    """

    def __init__(self, config: SelfEvolutionConfig | None = None) -> None:
        self.config = config or SelfEvolutionConfig()

    def evaluate(
        self,
        records: Iterable[GovernanceDecisionRecord | Mapping[str, Any]],
        constitution: Constitution,
    ) -> SelfEvolutionReport:
        normalized = [_record_to_mapping(record) for record in records]
        existing_rule_ids = {rule.id for rule in constitution.rules}
        skipped: Counter[str] = Counter()
        candidates: list[EvolutionCandidate] = []

        candidates.extend(self._uncovered_denial_candidates(normalized, existing_rule_ids, skipped))
        candidates.extend(self._hot_rule_candidates(normalized, constitution, skipped))
        candidates.extend(self._low_confidence_allow_candidates(normalized, skipped))

        filtered = [
            candidate for candidate in candidates if candidate.fitness >= self.config.min_fitness
        ]
        filtered.sort(key=lambda c: (c.fitness, c.support, c.candidate_id), reverse=True)
        return SelfEvolutionReport(
            input_records=len(normalized),
            candidates=tuple(filtered[: self.config.max_candidates]),
            skipped=dict(skipped),
        )

    def draft_amendments(
        self,
        report: SelfEvolutionReport,
        protocol: AmendmentProtocol,
        *,
        proposer_id: str | None = None,
        open_voting: bool = False,
        gate_report: EvolutionGateReport | None = None,
    ) -> list[Amendment]:
        """Draft candidates as formal amendments.

        If ``open_voting`` is true, each draft is also moved through
        ``proposed`` to ``voting``. Ratification/enforcement are intentionally
        left to distinct executor actors.
        """

        actor = proposer_id or self.config.proposer_id
        gate_by_candidate = {
            result.candidate.candidate_id: result
            for result in (gate_report.passed if gate_report else ())
        }
        gate_report_hash = _canonical_hash(gate_report.to_dict()) if gate_report is not None else ""
        if gate_report is not None:
            unapproved = [
                candidate.candidate_id
                for candidate in report.actionable_candidates
                if candidate.candidate_id not in gate_by_candidate
                or _canonical_hash(candidate.to_dict())
                != _canonical_hash(gate_by_candidate[candidate.candidate_id].candidate.to_dict())
            ]
            if unapproved:
                msg = (
                    "Candidates were not approved by the supplied gate_report: "
                    f"{', '.join(repr(candidate_id) for candidate_id in unapproved)}; "
                    "pass gate_report.to_evolution_report() or omit failed candidates"
                )
                raise ValueError(msg)
        amendments: list[Amendment] = []
        for candidate in report.actionable_candidates:
            gate_result = gate_by_candidate.get(candidate.candidate_id)
            metadata = {
                "source": "self_evolution",
                "candidate_id": candidate.candidate_id,
                "fitness": candidate.fitness,
                "risk": candidate.risk,
                "support": candidate.support,
                "evidence": [item.to_dict() for item in candidate.evidence],
            }
            if gate_result is not None:
                metadata["gate_result"] = gate_result.to_dict()
                metadata["gate_report_hash"] = gate_report_hash
            amd = protocol.draft(
                proposer_id=actor,
                amendment_type=candidate.amendment_type.value,
                title=candidate.title,
                description=candidate.description,
                changes=candidate.changes,
                metadata=metadata,
            )
            if open_voting:
                protocol.propose(amd.amendment_id, proposer_id=actor)
                protocol.open_voting(amd.amendment_id, proposer_id=actor)
            amendments.append(amd)
        return amendments

    def action_corpus_from_records(
        self,
        records: Iterable[GovernanceDecisionRecord | Mapping[str, Any]],
        *,
        include_evidence_actions: bool = True,
        max_actions: int | None = None,
    ) -> tuple[str, ...]:
        """Build a stable, de-duplicated simulation corpus from decision records.

        The corpus starts with observed ``action`` strings. When
        ``include_evidence_actions`` is enabled, compact violation messages are
        included too, which helps proposed uncovered-risk rules get simulated
        against the actual text that caused the governance signal.
        """

        corpus: list[str] = []
        seen: set[str] = set()

        def _add(text: str) -> None:
            normalized = " ".join(text.split())
            if not normalized or normalized in seen:
                return
            seen.add(normalized)
            corpus.append(normalized)

        for record in records:
            item = _record_to_mapping(record)
            _add(str(item.get("action", "")))
            if include_evidence_actions:
                for violation in item.get("violations") or []:
                    if isinstance(violation, Mapping):
                        _add(str(violation.get("message") or violation.get("reason") or ""))
                    else:
                        _add(str(violation))
            if max_actions is not None and len(corpus) >= max_actions:
                return tuple(corpus[:max_actions])
        return tuple(corpus)

    def gate_candidates(
        self,
        report: SelfEvolutionReport,
        constitution: Constitution,
        action_corpus: Iterable[str],
    ) -> EvolutionGateReport:
        """Simulate candidates before drafting formal amendments.

        This is the self-evolution safety valve: every candidate is converted to
        a candidate constitution and compared against the current constitution on
        a representative action corpus. Candidates that create regressions,
        exceed blast-radius limits, or exceed weighted-risk limits are rejected
        before they enter the amendment workflow.
        """

        actions = [action for action in action_corpus if action]
        if not actions:
            failed = tuple(
                CandidateGateResult(
                    candidate=candidate,
                    passed=False,
                    recommendation="no-go",
                    blast_radius=0.0,
                    weighted_risk=1.0,
                    regressions=0,
                    reasons=("empty action corpus",),
                )
                for candidate in report.actionable_candidates
            )
            return EvolutionGateReport(evaluated=len(failed), passed=(), failed=failed)

        passed: list[CandidateGateResult] = []
        failed_results: list[CandidateGateResult] = []

        for candidate in report.actionable_candidates:
            try:
                candidate_constitution = _candidate_constitution(constitution, candidate)
                deltas = [
                    (
                        _decision_for(constitution, action),
                        _decision_for(candidate_constitution, action),
                    )
                    for action in actions
                ]
            except Exception as exc:
                failed_results.append(
                    CandidateGateResult(
                        candidate=candidate,
                        passed=False,
                        recommendation="no-go",
                        blast_radius=1.0,
                        weighted_risk=1.0,
                        regressions=0,
                        reasons=(f"candidate simulation failed: {type(exc).__name__}: {exc}",),
                    )
                )
                continue
            changed = sum(1 for before, after in deltas if before != after)
            regressions = sum(
                1 for before, after in deltas if before == "deny" and after == "allow"
            )
            blast_radius = changed / len(actions)
            weighted_risk = sum(_transition_risk(before, after) for before, after in deltas) / len(
                actions
            )
            reasons: list[str] = []
            if not self.config.allow_regressions and regressions > 0:
                reasons.append(f"{regressions} deny-to-allow regression(s)")
            if blast_radius > self.config.max_blast_radius:
                reasons.append(
                    f"blast radius {blast_radius:.1%} exceeds {self.config.max_blast_radius:.1%}"
                )
            if weighted_risk > self.config.max_weighted_risk:
                reasons.append(
                    f"weighted risk {weighted_risk:.3f} exceeds {self.config.max_weighted_risk:.3f}"
                )
            if reasons:
                recommendation = "no-go"
            elif weighted_risk == 0:
                recommendation = "go"
            else:
                recommendation = "review"
            passed_gate = not reasons
            gate_result = CandidateGateResult(
                candidate=candidate,
                passed=passed_gate,
                recommendation=recommendation,
                blast_radius=blast_radius,
                weighted_risk=weighted_risk,
                regressions=regressions,
                reasons=tuple(reasons),
            )
            if passed_gate:
                passed.append(gate_result)
            else:
                failed_results.append(gate_result)

        return EvolutionGateReport(
            evaluated=len(passed) + len(failed_results),
            passed=tuple(passed),
            failed=tuple(failed_results),
        )

    def _uncovered_denial_candidates(
        self,
        records: list[Mapping[str, Any]],
        existing_rule_ids: set[str],
        skipped: Counter[str],
    ) -> list[EvolutionCandidate]:
        buckets: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for record in records:
            decision = str(record.get("decision", "")).lower()
            if decision != "deny":
                continue
            rule_ids = _record_rule_ids(record)
            known_hits = [rid for rid in rule_ids if rid in existing_rule_ids]
            violations = record.get("violations") or []
            if known_hits or not violations:
                skipped["covered_or_without_violation_denials"] += 1
                continue
            key = _topic_key(str(record.get("action", "")), violations)
            buckets[key].append(record)

        candidates: list[EvolutionCandidate] = []
        for key, items in buckets.items():
            if len(items) < self.config.min_support:
                skipped["uncovered_denial_below_support"] += len(items)
                continue
            keywords = _keywords(key)
            rule_id = _stable_rule_id("EVO", key)
            support = len(items)
            fitness = _bounded(0.45 + min(0.4, support / 10) + 0.1 * bool(keywords))
            evidence = tuple(
                _evidence(item, "denied with no active rule coverage") for item in items[:5]
            )
            candidates.append(
                EvolutionCandidate(
                    candidate_id=_stable_rule_id("CAND", f"uncovered:{key}"),
                    amendment_type=AmendmentType.add_rule,
                    title=f"Add coverage for repeated uncovered denial: {key[:60]}",
                    description=(
                        "Runtime feedback repeatedly denied actions with violation evidence, "
                        "but no active constitutional rule was triggered. Add explicit coverage "
                        "so future enforcement is deterministic and auditable."
                    ),
                    changes={
                        "rule": {
                            "id": rule_id,
                            "text": f"Agents must not perform actions matching repeated risk pattern: {key}",
                            "severity": Severity.HIGH.value,
                            "keywords": keywords,
                            "category": "self-evolution",
                            "workflow_action": ViolationAction.BLOCK.value,
                            "tags": ["self-evolution", "runtime-feedback"],
                            "metadata": {"generated_by": "SelfEvolutionEngine", "support": support},
                        }
                    },
                    fitness=fitness,
                    risk="medium",
                    support=support,
                    evidence=evidence,
                )
            )
        return candidates

    def _hot_rule_candidates(
        self,
        records: list[Mapping[str, Any]],
        constitution: Constitution,
        skipped: Counter[str],
    ) -> list[EvolutionCandidate]:
        rule_counts: Counter[str] = Counter()
        for record in records:
            if str(record.get("decision", "")).lower() == "deny":
                rule_counts.update(_record_rule_ids(record))

        by_id = {rule.id: rule for rule in constitution.rules}
        candidates: list[EvolutionCandidate] = []
        for rule_id, support in rule_counts.items():
            rule = by_id.get(rule_id)
            if rule is None or support < self.config.min_support:
                skipped["hot_rule_unknown_or_below_support"] += 1
                continue
            changes: dict[str, Any] = {
                "rule_id": rule_id,
                "priority": min(rule.priority + support, 100),
            }
            amendment_type = AmendmentType.modify_rule
            risk = "low"
            if rule.severity in {Severity.LOW, Severity.MEDIUM}:
                changes["severity"] = Severity.HIGH.value
                changes["workflow_action"] = ViolationAction.BLOCK.value
                risk = "medium"
            candidates.append(
                EvolutionCandidate(
                    candidate_id=_stable_rule_id("CAND", f"hot:{rule_id}:{support}"),
                    amendment_type=amendment_type,
                    title=f"Tune frequently triggered rule {rule_id}",
                    description=(
                        f"Rule {rule_id} triggered {support} denied decisions. Increase priority"
                        " and, for non-blocking severities, escalate to high so repeated risk is handled earlier."
                    ),
                    changes=changes,
                    fitness=_bounded(0.4 + min(0.5, support / 12)),
                    risk=risk,
                    support=support,
                    evidence=tuple(
                        _evidence(item, f"triggered hot rule {rule_id}")
                        for item in records
                        if rule_id in _record_rule_ids(item)
                    )[:5],
                )
            )
        return candidates

    def _low_confidence_allow_candidates(
        self, records: list[Mapping[str, Any]], skipped: Counter[str]
    ) -> list[EvolutionCandidate]:
        items = [
            record
            for record in records
            if str(record.get("decision", "")).lower() == "allow"
            and float(record.get("confidence", 1.0) or 0.0) < self.config.low_confidence_threshold
        ]
        if len(items) < self.config.min_support:
            skipped["low_confidence_allow_below_support"] += len(items)
            return []
        topic = _topic_key(" ".join(str(item.get("action", "")) for item in items), [])
        rule_id = _stable_rule_id("EVO-REVIEW", topic)
        return [
            EvolutionCandidate(
                candidate_id=_stable_rule_id("CAND", f"low-confidence:{topic}"),
                amendment_type=AmendmentType.add_rule,
                title="Require review for repeated low-confidence allow decisions",
                description=(
                    "Multiple actions were allowed with confidence below the configured threshold. "
                    "Route matching future actions to human review instead of silent allow."
                ),
                changes={
                    "rule": {
                        "id": rule_id,
                        "text": f"Actions matching low-confidence allow pattern require human review: {topic}",
                        "severity": Severity.HIGH.value,
                        "keywords": _keywords(topic),
                        "category": "self-evolution",
                        "workflow_action": ViolationAction.REQUIRE_HUMAN_REVIEW.value,
                        "tags": ["self-evolution", "low-confidence", "human-review"],
                        "metadata": {"generated_by": "SelfEvolutionEngine", "support": len(items)},
                    }
                },
                fitness=_bounded(0.5 + min(0.35, len(items) / 12)),
                risk="medium",
                support=len(items),
                evidence=tuple(
                    _evidence(item, "allowed below confidence threshold") for item in items[:5]
                ),
            )
        ]


def _record_to_mapping(record: GovernanceDecisionRecord | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(record, Mapping):
        return record
    to_dict = getattr(record, "to_dict", None)
    if callable(to_dict):
        mapped = to_dict()
        if isinstance(mapped, Mapping):
            return mapped
    msg = f"Unsupported decision record type: {type(record)!r}"
    raise TypeError(msg)


def _candidate_constitution(
    constitution: Constitution, candidate: EvolutionCandidate
) -> Constitution:
    bundle = constitution.to_bundle()
    rules = list(bundle.get("rules", []))

    if candidate.amendment_type == AmendmentType.add_rule:
        rules.append(dict(candidate.changes.get("rule", {})))
    elif candidate.amendment_type in {
        AmendmentType.modify_rule,
        AmendmentType.modify_severity,
        AmendmentType.modify_workflow,
    }:
        rule_id = str(candidate.changes.get("rule_id", ""))
        patch = {key: value for key, value in candidate.changes.items() if key != "rule_id"}
        rules = [
            dict(rule, **patch) if str(rule.get("id", "")) == rule_id else rule for rule in rules
        ]
    elif candidate.amendment_type == AmendmentType.remove_rule:
        rule_id = str(candidate.changes.get("rule_id", ""))
        rules = [rule for rule in rules if str(rule.get("id", "")) != rule_id]

    bundle["rules"] = rules
    return constitution.__class__.from_bundle(bundle)


def _decision_for(constitution: Constitution, action: str) -> str:
    from acgs_lite.engine import GovernanceEngine

    try:
        result = GovernanceEngine(constitution, strict=False).validate(action)
    except Exception:
        return "deny"
    if result.valid:
        return "allow"
    if any(
        getattr(violation.severity, "blocks", lambda: True)() for violation in result.violations
    ):
        return "deny"
    return "escalate"


def _transition_risk(before: str, after: str) -> float:
    weights = {
        ("deny", "allow"): 1.0,
        ("deny", "escalate"): 0.8,
        ("allow", "deny"): 0.5,
        ("allow", "escalate"): 0.2,
        ("escalate", "allow"): 0.2,
        ("escalate", "deny"): 0.5,
    }
    return weights.get((before, after), 0.0)


def _record_rule_ids(record: Mapping[str, Any]) -> tuple[str, ...]:
    ids: list[str] = []
    for rule in record.get("triggered_rules") or []:
        if isinstance(rule, Mapping) and rule.get("id"):
            ids.append(str(rule["id"]))
        elif hasattr(rule, "id"):
            ids.append(str(rule.id))
    for violation in record.get("violations") or []:
        if isinstance(violation, Mapping):
            rid = violation.get("rule_id") or violation.get("rule") or violation.get("id")
            if rid:
                ids.append(str(rid))
    return tuple(dict.fromkeys(ids))


def _topic_key(action: str, violations: Any) -> str:
    parts = [action]
    if isinstance(violations, list):
        for violation in violations[:3]:
            if isinstance(violation, Mapping):
                parts.append(str(violation.get("message") or violation.get("reason") or ""))
            else:
                parts.append(str(violation))
    text = " ".join(parts).strip().lower()
    words = _keywords(text, max_keywords=8)
    return " ".join(words) if words else "general runtime risk"


def _keywords(text: str, *, max_keywords: int = 6) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for token in _RE_WORD.findall(text.lower()):
        if token in _STOP_WORDS or token in seen:
            continue
        seen.add(token)
        result.append(token)
        if len(result) >= max_keywords:
            break
    return result


def _stable_rule_id(prefix: str, text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, value))


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _evidence(record: Mapping[str, Any], reason: str) -> EvolutionEvidence:
    return EvolutionEvidence(
        audit_entry_id=str(record.get("audit_entry_id", "")),
        decision=str(record.get("decision", "")),
        action=str(record.get("action", "")),
        rule_ids=_record_rule_ids(record),
        confidence=float(record.get("confidence", 1.0) or 0.0),
        reason=reason,
    )


__all__ = [
    "EvolutionCandidate",
    "EvolutionEvidence",
    "CandidateGateResult",
    "EvolutionGateReport",
    "SelfEvolutionConfig",
    "SelfEvolutionEngine",
    "SelfEvolutionReport",
]
