# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs lifecycle — manage policy promotion lifecycle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_LIFECYCLE_ACTIONS = {
    "register",
    "review",
    "stage",
    "activate",
    "deprecate",
    "archive",
    "approve",
    "lint-gate",
    "test-gate",
    "status",
    "audit",
    "summary",
}


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the lifecycle subcommand."""
    p = sub.add_parser(
        "lifecycle", help="Manage policy promotion lifecycle (draft→review→staged→active)"
    )
    p.add_argument(
        "action",
        nargs="?",
        default="summary",
        help="Action: register, review, stage, activate, deprecate, archive, "
        "approve, lint-gate, test-gate, status, audit, summary",
    )
    p.add_argument("policy_id", nargs="?", default="", help="Policy identifier")
    p.add_argument("--actor", default=None, help="Actor identifier for approvals")
    p.add_argument("--force", action="store_true", help="Force transition (bypass gates)")
    p.add_argument(
        "--supersedes",
        action="append",
        default=None,
        help="Policy IDs superseded by this activation (repeatable)",
    )
    p.add_argument(
        "--state-file",
        default=".acgs_lifecycle.json",
        help="Path to lifecycle state file (default: .acgs_lifecycle.json)",
    )
    p.add_argument("--json", dest="json_out", action="store_true", help="JSON output")


def handler(args: argparse.Namespace) -> int:
    """Manage policy promotion lifecycle."""
    from acgs_lite.constitution.policy_lifecycle import (
        PolicyLifecycleOrchestrator,
        PolicyState,
        RolloutPlan,
    )

    action: str = getattr(args, "action", "summary")
    policy_id: str = getattr(args, "policy_id", "")
    state_file = Path(getattr(args, "state_file", ".acgs_lifecycle.json"))

    orch = PolicyLifecycleOrchestrator()
    _lifecycle_load(orch, state_file)

    json_out = getattr(args, "json_out", False)

    if action == "summary":
        s = orch.summary()
        if json_out:
            print(json.dumps(s, indent=2))
        else:
            print()
            print("  ACGS Policy Lifecycle")
            print("  " + "=" * 50)
            print(f"  Total policies:     {s['total_policies']}")
            print(f"  Gates configured:   {s['gates_configured']}")
            print(f"  Audit trail:        {s['audit_trail_length']} transitions")
            print()
            if s["state_counts"]:
                for state, count in sorted(s["state_counts"].items()):
                    print(f"    {state:15s}  {count}")
            else:
                print("  No policies registered. Run: acgs lifecycle register <policy-id>")
            print()
        _lifecycle_save(orch, state_file)
        return 0

    if not policy_id and action != "summary":
        print(
            "  ❌ Policy ID required. Usage: acgs lifecycle <action> <policy-id>", file=sys.stderr
        )
        return 1

    if action == "register":
        existing = orch.get(policy_id)
        if existing is not None:
            print(f"  ℹ️  Policy '{policy_id}' already registered in state: {existing.state.value}")
        else:
            p = orch.register(policy_id)
            print(f"  ✅ Registered policy '{policy_id}' in state: {p.state.value}")

    elif action == "approve":
        actor = getattr(args, "actor", None) or "cli-user"
        ok = orch.record_approval(policy_id, actor)
        if ok:
            policy = orch.get(policy_id)
            count = len(policy.approvals) if policy else 0
            print(f"  ✅ Approval recorded for '{policy_id}' by {actor} ({count} total)")
        else:
            print(f"  ❌ Policy '{policy_id}' not found.", file=sys.stderr)
            return 1

    elif action == "lint-gate":
        ok = orch.set_lint_clean(policy_id, True)
        if ok:
            print(f"  ✅ Lint gate cleared for '{policy_id}'")
        else:
            print(f"  ❌ Policy '{policy_id}' not found.", file=sys.stderr)
            return 1

    elif action == "test-gate":
        ok = orch.set_test_suite_passed(policy_id, True)
        if ok:
            print(f"  ✅ Test gate cleared for '{policy_id}'")
        else:
            print(f"  ❌ Policy '{policy_id}' not found.", file=sys.stderr)
            return 1

    elif action in ("review", "stage", "activate", "deprecate", "archive"):
        state_map = {
            "review": PolicyState.REVIEW,
            "stage": PolicyState.STAGED,
            "activate": PolicyState.ACTIVE,
            "deprecate": PolicyState.DEPRECATED,
            "archive": PolicyState.ARCHIVED,
        }
        target = state_map[action]
        force = getattr(args, "force", False)
        supersedes_raw: list[str] | None = getattr(args, "supersedes", None)

        if action == "stage":
            policy = orch.get(policy_id)
            if policy and not policy.rollout_plan:
                orch.set_rollout_plan(policy_id, RolloutPlan.canary([10.0, 50.0, 100.0]))

        if action == "activate":
            policy = orch.get(policy_id)
            if policy and policy.blast_radius_pct is None:
                orch.set_blast_radius(policy_id, 10.0)

        result = orch.transition(
            policy_id,
            target,
            actor="cli-user",
            force=force,
            supersedes=supersedes_raw,
        )

        if result.succeeded:
            print(f"  ✅ {result.message}")
            if result.auto_deprecated:
                for dep in result.auto_deprecated:
                    print(f"     ↳ Auto-deprecated: {dep}")
        else:
            print(f"  ❌ {result.message}")
            if result.gate_evaluations:
                for ge in result.gate_evaluations:
                    icon = "✅" if ge.passed else "❌"
                    print(f"     {icon} {ge.gate.gate_type.value}: {ge.reason or 'passed'}")
            return 1

    elif action == "status":
        policy = orch.get(policy_id)
        if not policy:
            print(f"  ❌ Policy '{policy_id}' not found.", file=sys.stderr)
            return 1
        if json_out:
            print(json.dumps(policy.to_dict(), indent=2))
        else:
            print()
            print(f"  Policy: {policy.policy_id}")
            print(f"  State:  {policy.state.value}")
            print(f"  Approvals: {', '.join(policy.approvals) if policy.approvals else 'none'}")
            print(f"  Lint clean: {'✅' if policy.lint_clean else '❌'}")
            print(f"  Tests pass: {'✅' if policy.test_suite_passed else '❌'}")
            if policy.blast_radius_pct is not None:
                print(f"  Blast radius: {policy.blast_radius_pct:.1f}%")
            if policy.rollout_plan:
                print(
                    f"  Rollout: stage {policy.rollout_plan.current_stage_index}"
                    f" ({policy.rollout_plan.current_percentage:.0f}%)"
                )
            if policy.supersedes:
                print(f"  Supersedes: {', '.join(policy.supersedes)}")
            print()

    elif action == "audit":
        trail = orch.audit_trail(policy_id=policy_id, limit=20)
        if json_out:
            print(json.dumps([t.to_dict() for t in trail], indent=2, default=str))
        else:
            print()
            print(f"  Audit Trail: {policy_id}")
            print("  " + "=" * 50)
            if not trail:
                print("  No transitions recorded.")
            for t in trail:
                from_s = t.from_state.value if t.from_state else "—"
                print(
                    f"  {from_s:12s} → {t.to_state.value:12s}  "
                    f"actor={t.actor or '—'}  gates={len(t.gate_evaluations)}"
                )
                if t.notes:
                    print(f"    note: {t.notes}")
            print()

    else:
        print(f"  ❌ Unknown action: {action}", file=sys.stderr)
        print(f"  Valid: {', '.join(sorted(_LIFECYCLE_ACTIONS))}", file=sys.stderr)
        return 1

    _lifecycle_save(orch, state_file)
    return 0


def _lifecycle_load(orch: Any, state_file: Path) -> None:
    """Load persisted lifecycle state from disk."""
    if not state_file.exists():
        return
    try:
        from acgs_lite.constitution.policy_lifecycle import (
            GateEvaluation,
            GateType,
            LifecycleGate,
            ManagedPolicy,
            PolicyState,
            RolloutPlan,
            RolloutStage,
            TransitionRecord,
        )

        with state_file.open(encoding="utf-8") as f:
            data = json.load(f)

        for p_data in data.get("policies", []):
            rollout_data = p_data.get("rollout_plan")
            rollout_plan = None
            if rollout_data:
                rollout_plan = RolloutPlan(
                    stages=[
                        RolloutStage(
                            percentage=float(stage["percentage"]),
                            duration_seconds=float(stage["duration_seconds"]),
                            auto_advance=bool(stage.get("auto_advance", True)),
                        )
                        for stage in rollout_data.get("stages", [])
                    ],
                    current_stage_index=int(rollout_data.get("current_stage_index", 0)),
                    started_at=rollout_data.get("started_at"),
                )

            policy = ManagedPolicy(
                policy_id=p_data["policy_id"],
                state=PolicyState(p_data.get("state", "draft")),
                approvals=list(p_data.get("approvals", [])),
                lint_clean=bool(p_data.get("lint_clean", False)),
                test_suite_passed=bool(p_data.get("test_suite_passed", False)),
                blast_radius_pct=p_data.get("blast_radius_pct"),
                attestation_present=bool(p_data.get("attestation_present", False)),
                rollout_plan=rollout_plan,
                supersedes=list(p_data.get("supersedes", [])),
                metadata=dict(p_data.get("metadata", {})),
            )
            orch._policies[policy.policy_id] = policy

        audit_records = []
        for record_data in data.get("audit_trail", []):
            gate_evaluations = []
            for gate_data in record_data.get("gate_evaluations", []):
                gate = LifecycleGate(
                    gate_type=GateType(gate_data["gate"]["gate_type"]),
                    target_state=PolicyState(gate_data["gate"]["target_state"]),
                    threshold=gate_data["gate"].get("threshold"),
                    required=bool(gate_data["gate"].get("required", True)),
                )
                gate_evaluations.append(
                    GateEvaluation(
                        gate=gate,
                        passed=bool(gate_data.get("passed", False)),
                        reason=str(gate_data.get("reason", "")),
                    )
                )
            audit_records.append(
                TransitionRecord(
                    policy_id=record_data["policy_id"],
                    from_state=(
                        PolicyState(record_data["from_state"])
                        if record_data.get("from_state")
                        else None
                    ),
                    to_state=PolicyState(record_data["to_state"]),
                    timestamp=float(record_data.get("timestamp", 0.0)),
                    actor=record_data.get("actor"),
                    gate_evaluations=gate_evaluations,
                    notes=str(record_data.get("notes", "")),
                )
            )
        orch._audit_trail[:] = audit_records
    except (json.JSONDecodeError, ValueError, TypeError, KeyError, OSError):
        pass  # graceful degradation — start fresh on corrupt state


def _lifecycle_save(orch: Any, state_file: Path) -> None:
    """Persist lifecycle state to disk."""
    policies = []
    for policy in getattr(orch, "_policies", {}).values():
        policy_data = policy.to_dict()
        if policy.rollout_plan:
            policy_data["rollout_plan"] = {
                "current_stage_index": policy.rollout_plan.current_stage_index,
                "started_at": policy.rollout_plan.started_at,
                "stages": [
                    {
                        "percentage": stage.percentage,
                        "duration_seconds": stage.duration_seconds,
                        "auto_advance": stage.auto_advance,
                    }
                    for stage in policy.rollout_plan.stages
                ],
            }
        else:
            policy_data["rollout_plan"] = None
        policies.append(policy_data)

    audit_trail = []
    for record in getattr(orch, "_audit_trail", []):
        audit_trail.append(
            {
                "policy_id": record.policy_id,
                "from_state": record.from_state.value if record.from_state else None,
                "to_state": record.to_state.value,
                "timestamp": record.timestamp,
                "actor": record.actor,
                "notes": record.notes,
                "gate_evaluations": [
                    {
                        "gate": ge.gate.to_dict(),
                        "passed": ge.passed,
                        "reason": ge.reason,
                    }
                    for ge in record.gate_evaluations
                ],
            }
        )

    data = {"policies": policies, "audit_trail": audit_trail}
    state_file.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")
