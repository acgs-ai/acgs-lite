"""Condition evaluators for intervention rules.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from typing import Any


def evaluate_condition(condition: dict[str, Any], cdp_record: dict[str, Any]) -> bool:
    """Evaluate a condition dict against a CDP record dict.

    Condition types:
    - {"verdict": "deny"} — matches if verdict equals value
    - {"verdict_in": ["deny", "conditional"]} — matches if verdict in list
    - {"risk_score_gte": 0.8} — matches if risk_score >= threshold
    - {"has_violated_rule": "PHI_GUARD"} — matches if rule in violated_rules
    - {"has_obligation_type": "hitl_required"} — matches if obligation type present
    - {"has_blocking_unsatisfied": true} — matches if any blocking obligation unsatisfied
    - {"framework_in": ["igaming"]} — matches if framework in compliance_frameworks
    - {"and": [cond1, cond2]} — all conditions true
    - {"or": [cond1, cond2]} — any condition true
    - {"not": cond} — negation

    Unknown condition types return False (fail-safe).

    Returns True if the condition matches, False otherwise.
    """
    if not condition:
        return False

    # Logical combinators
    if "and" in condition:
        sub_conditions = condition["and"]
        return all(evaluate_condition(c, cdp_record) for c in sub_conditions)

    if "or" in condition:
        sub_conditions = condition["or"]
        return any(evaluate_condition(c, cdp_record) for c in sub_conditions)

    if "not" in condition:
        return not evaluate_condition(condition["not"], cdp_record)

    # Verdict checks
    if "verdict" in condition:
        return bool(cdp_record.get("verdict") == condition["verdict"])

    if "verdict_in" in condition:
        return cdp_record.get("verdict") in condition["verdict_in"]

    # Risk score threshold
    if "risk_score_gte" in condition:
        threshold = condition["risk_score_gte"]
        return float(cdp_record.get("risk_score", 0.0)) >= float(threshold)

    # Violated rule membership
    if "has_violated_rule" in condition:
        violated_rules = cdp_record.get("violated_rules", [])
        return condition["has_violated_rule"] in violated_rules

    # Obligation type presence
    if "has_obligation_type" in condition:
        target_type = condition["has_obligation_type"]
        obligations = cdp_record.get("runtime_obligations", [])
        return any(ob.get("obligation_type") == target_type for ob in obligations)

    # Blocking unsatisfied obligations
    if "has_blocking_unsatisfied" in condition:
        if not condition["has_blocking_unsatisfied"]:
            return False
        obligations = cdp_record.get("runtime_obligations", [])
        return any(
            ob.get("severity") == "blocking" and not ob.get("satisfied", True) for ob in obligations
        )

    # Compliance framework membership
    if "framework_in" in condition:
        frameworks = cdp_record.get("compliance_frameworks", [])
        return any(fw in frameworks for fw in condition["framework_in"])

    # Unknown condition type — fail-safe: do not trigger
    return False
