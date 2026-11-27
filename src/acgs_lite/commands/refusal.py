# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs refusal — explain governance denials and suggest alternatives."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the refusal subcommand."""
    p = sub.add_parser("refusal", help="Explain governance denials and suggest alternatives")
    p.add_argument("action_text", help='The action text to analyze (e.g. "invest in tech stocks")')
    p.add_argument("--rules", default="rules.yaml", help="Path to rules YAML (default: rules.yaml)")
    p.add_argument("--json", dest="json_out", action="store_true", help="JSON output")


def handler(args: argparse.Namespace) -> int:
    """Explain why a governance action was denied and suggest alternatives."""
    from acgs_lite.constitution import Constitution
    from acgs_lite.constitution.refusal_reasoning import RefusalReasoningEngine
    from acgs_lite.engine.core import GovernanceEngine

    rules_path = Path(getattr(args, "rules", "rules.yaml"))
    action_text: str = getattr(args, "action_text", "")

    if not rules_path.exists():
        print(f"  ❌ {rules_path} not found. Run 'acgs init' first.", file=sys.stderr)
        return 1

    if not action_text:
        print(
            '  ❌ Provide an action to analyze. Usage: acgs refusal "action text"', file=sys.stderr
        )
        return 1

    constitution = Constitution.from_yaml(str(rules_path))
    engine = GovernanceEngine(constitution, strict=False)
    refusal_engine = RefusalReasoningEngine(constitution)

    result = engine.validate(action_text)
    json_out = getattr(args, "json_out", False)

    if result.valid:
        if json_out:
            print(
                json.dumps(
                    {
                        "action": action_text,
                        "decision": "allow",
                        "message": "Action is allowed -- no refusal to explain.",
                    }
                )
            )
        else:
            print()
            print(f'  ✅ Action ALLOWED: "{action_text}"')
            print("  No refusal to explain -- this action passes all governance rules.")
            print()
        return 0

    rule_ids: list[str] = [v.rule_id for v in result.violations]
    refusal = refusal_engine.reason_refusal(action_text, rule_ids)

    if json_out:
        print(json.dumps(refusal.to_dict(), indent=2))
        return 0

    print()
    print("  ACGS Refusal Analysis")
    print("  " + "=" * 50)
    print(f'  Action:   "{action_text}"')
    print("  Decision: ❌ DENIED")
    print(f"  Severity: {refusal.refusal_severity}")
    print(f"  Rules:    {refusal.rule_count}")
    print()

    if refusal.reasons:
        print("  Why it was blocked:")
        for reason in refusal.reasons:
            print(f"    ❌ {reason.explanation}")
            if reason.matched_keywords:
                print(f"       Keywords: {', '.join(reason.matched_keywords)}")
        print()

    if refusal.suggestions:
        print("  Suggested alternatives:")
        for i, sug in enumerate(refusal.suggestions, 1):
            conf_bar = "●" * int(sug.confidence * 5) + "○" * (5 - int(sug.confidence * 5))
            print(f'    {i}. "{sug.alternative_action}"')
            print(f"       Confidence: {conf_bar} ({sug.confidence:.0%})")
            print(f"       Rationale:  {sug.rationale}")
        print()

    if refusal.can_retry:
        print("  💡 This action can be retried with the suggested modifications.")
    else:
        print("  🚫 No safe alternatives found. Escalate to a human reviewer.")
    print()

    return 0
