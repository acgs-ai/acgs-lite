"""
Agent Quickstart — Self-Verifying ACGS-Lite Source-Candidate Demo
==================================================================
A single script that an AI coding agent (Claude Code, Codex CLI) can run
verbatim to confirm ACGS-Lite is correctly installed and working.

Covers three capabilities in sequence:
  1. Governed callable  — missing authorization and violations are blocked;
     a same-instance production grant allows one matching safe request
  2. MACI role separation — roles are enforced; cross-role actions are denied
  3. Audit trail        — governance decisions are chained and verifiable

No API keys required. Runs fully offline.

Run:
    python examples/agent_quickstart/run.py

Exit code 0 = all assertions passed (ACGS-Lite is correctly installed).
Exit code 1 = one or more assertions failed (investigate the output).
"""

import sys
from pathlib import Path

from acgs_lite import (
    AuthorizationProfile,
    Constitution,
    ConstitutionalViolationError,
    GovernedCallable,
    MACIEnforcer,
    MACIRole,
    MACIViolationError,
    Rule,
    Severity,
)
from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.legitimacy import LegitimacyInvariantError

_PASS = "✅"
_FAIL = "❌"
_BLOCK = "🚫"

_failures: list[str] = []


def _assert(condition: bool, label: str) -> None:
    if condition:
        print(f"  {_PASS}  {label}")
    else:
        print(f"  {_FAIL}  FAIL: {label}")
        _failures.append(label)


# ── Section 1: Governed Callable ──────────────────────────────────────────────


def section_governed_callable() -> None:
    print("\n" + "=" * 60)
    print("  Section 1: Governed Callable")
    print("=" * 60)

    # 1a. Inline constitution (fast, no file I/O)
    print("\n── 1a. Inline constitution ───────────────────────────────────")
    constitution = Constitution(
        name="quickstart-policy",
        version="1.0",
        rules=[
            Rule(
                id="no-pii",
                text="Block SSN patterns",
                keywords=["ssn", "social security"],
                patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
                severity=Severity.CRITICAL,
            ),
            Rule(
                id="no-destructive",
                text="Block destructive operations",
                keywords=["drop table", "rm -rf"],
                patterns=[r"(?i)\bdrop table\b", r"(?i)\brm -rf\b"],
                severity=Severity.HIGH,
            ),
        ],
    )

    calls: list[str] = []

    def my_agent(prompt: str) -> str:
        calls.append(prompt)
        return f"Response to: {prompt}"

    governed = GovernedCallable(
        constitution=constitution,
        authorization_profile=AuthorizationProfile.PRODUCTION,
    )(my_agent)

    # Missing authorization is denied before the callable runs.
    safe_prompt = "What is the capital of France?"
    try:
        governed(safe_prompt)
        _assert(False, "missing authorization must be blocked")
    except LegitimacyInvariantError:
        _assert(calls == [], "missing authorization causes zero callable invocations")

    # A same-instance production grant allows exactly the matching call.
    grant = governed.issue_grant(safe_prompt)  # type: ignore[attr-defined]
    result = governed(
        safe_prompt,
        execution_grant=grant,
        execution_attempt_id="quickstart-inline-safe",
    )
    if "Response to:" in result:
        print(f"  {_PASS}  Allowed:  {result}")
    _assert("Response to:" in result, "safe request passes through")

    # PII is blocked
    try:
        governed.issue_grant("My SSN is 123-45-6789")  # type: ignore[attr-defined]
        _assert(False, "PII request must be blocked")
    except ConstitutionalViolationError as exc:
        print(f"  {_BLOCK}  Blocked:  {exc.rule_id} — {exc}")
        _assert(exc.rule_id == "no-pii", f"PII blocked by rule 'no-pii' (got '{exc.rule_id}')")

    # Destructive operation is blocked
    try:
        governed.issue_grant("drop table users")  # type: ignore[attr-defined]
        _assert(False, "destructive request must be blocked")
    except ConstitutionalViolationError as exc:
        print(f"  {_BLOCK}  Blocked:  {exc.rule_id} — {exc}")
        _assert(
            exc.rule_id == "no-destructive",
            f"destructive op blocked by 'no-destructive' (got '{exc.rule_id}')",
        )

    # 1b. YAML constitution (production pattern)
    print("\n── 1b. YAML constitution (production pattern) ────────────────")
    yaml_path = Path(__file__).parent / "constitution.yaml"
    try:
        yaml_const = Constitution.from_yaml(str(yaml_path))
        yaml_governed = GovernedCallable(
            constitution=yaml_const,
            authorization_profile=AuthorizationProfile.PRODUCTION,
        )(my_agent)
        _assert(len(yaml_const.rules) == 3, f"YAML loads 3 rules (got {len(yaml_const.rules)})")

        yaml_prompt = "Tell me about Paris"
        yaml_grant = yaml_governed.issue_grant(yaml_prompt)  # type: ignore[attr-defined]
        yaml_result = yaml_governed(
            yaml_prompt,
            execution_grant=yaml_grant,
            execution_attempt_id="quickstart-yaml-safe",
        )
        if "Response to:" in yaml_result:
            print(f"  {_PASS}  YAML load OK — rules: {len(yaml_const.rules)}")
        _assert("Response to:" in yaml_result, "safe request passes via YAML constitution")

        try:
            yaml_governed.issue_grant(  # type: ignore[attr-defined]
                "My social security number is 999-88-7777"
            )
            _assert(False, "YAML PII rule must block")
        except ConstitutionalViolationError as exc:
            print(f"  {_BLOCK}  YAML block: {exc.rule_id} — still enforced from file")
            _assert(exc.rule_id == "no-pii", "YAML PII rule enforced")
    except FileNotFoundError:
        _assert(
            False,
            "constitution.yaml not found — expected at examples/agent_quickstart/constitution.yaml",
        )
    except ImportError as exc:
        _assert(False, f"pyyaml not installed — YAML constitution support broken: {exc}")


# ── Section 2: MACI Role Separation ──────────────────────────────────────────


def section_maci() -> None:
    print("\n" + "=" * 60)
    print("  Section 2: MACI Role Separation")
    print("=" * 60)

    enforcer = MACIEnforcer()
    enforcer.assign_role("agent-proposer", MACIRole.PROPOSER)
    enforcer.assign_role("agent-validator", MACIRole.VALIDATOR)
    enforcer.assign_role("agent-executor", MACIRole.EXECUTOR)
    enforcer.assign_role("agent-observer", MACIRole.OBSERVER)

    cases: list[tuple[str, str, bool, str]] = [
        ("agent-proposer", "propose", True, "Proposer can propose"),
        ("agent-proposer", "validate", False, "Proposer CANNOT self-validate"),
        ("agent-proposer", "execute", False, "Proposer CANNOT execute"),
        ("agent-validator", "validate", True, "Validator can validate"),
        ("agent-validator", "execute", False, "Validator CANNOT execute"),
        ("agent-executor", "execute", True, "Executor can execute"),
        ("agent-executor", "propose", False, "Executor CANNOT propose"),
        ("agent-observer", "read", True, "Observer can read"),
        ("agent-observer", "execute", False, "Observer CANNOT execute"),
    ]

    for agent_id, operation, should_pass, label in cases:
        try:
            enforcer.check(agent_id, operation)
            _assert(should_pass, label)
        except MACIViolationError:
            _assert(not should_pass, label)
            if not should_pass:
                print(f"  {_BLOCK}  Blocked: {label}")

    # Golden Rule: an agent cannot validate its own proposals (multi-agent check)
    print("\n── Golden Rule: no self-validation ──────────────────────────")
    try:
        enforcer.check_no_self_validation("agent-proposer", "agent-proposer")
        _assert(False, "Golden Rule must prevent self-validation")
    except MACIViolationError:
        _assert(True, "Golden Rule: same agent cannot propose and validate")


# ── Section 3: Audit Trail ────────────────────────────────────────────────────


def section_audit() -> None:
    print("\n" + "=" * 60)
    print("  Section 3: Audit Trail")
    print("=" * 60)

    log = AuditLog()

    entries = [
        AuditEntry(
            id="ev-001", type="validation", agent_id="agent-A", action="safe query", valid=True
        ),
        AuditEntry(
            id="ev-002",
            type="validation",
            agent_id="agent-B",
            action="pii attempt",
            valid=False,
            violations=["no-pii"],
        ),
        AuditEntry(
            id="ev-003",
            type="maci_check",
            agent_id="agent-C",
            action="approve proposal",
            valid=True,
        ),
    ]
    for entry in entries:
        log.record(entry)

    all_entries = list(log.entries)
    _assert(len(all_entries) == 3, f"audit log holds 3 entries (got {len(all_entries)})")

    # Chain verification
    chain_ok = log.verify_chain()
    _assert(chain_ok, "audit chain integrity verified")
    print(f"  {'✅' if chain_ok else '❌'}  Chain: {'verified' if chain_ok else 'BROKEN'}")

    # Query violations
    violations = [e for e in all_entries if not e.valid]
    _assert(len(violations) == 1, f"1 violation recorded (got {len(violations)})")
    _assert(violations[0].id == "ev-002", "violation entry is ev-002")
    print(f"  ✅  Violations in log: {[e.id for e in violations]}")

    # Tamper detection: mutating an internal entry breaks the chain
    print("\n── Tamper detection ─────────────────────────────────────────")
    original_action = log._entries[0].action
    log._entries[0].action = "TAMPERED"
    tampered_ok = log.verify_chain()
    _assert(not tampered_ok, "verify_chain detects internal entry mutation → returns False")
    print(f"  {_BLOCK}  Chain broken after mutation: verify_chain() = {tampered_ok}")
    log._entries[0].action = original_action  # restore


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    print("\n" + "=" * 60)
    print("  ACGS-Lite Agent Quickstart — Verification Suite")
    print("=" * 60)

    section_governed_callable()
    section_maci()
    section_audit()

    # Final report
    print("\n" + "=" * 60)
    if _failures:
        print(f"  {_FAIL}  {len(_failures)} assertion(s) FAILED:")
        for f in _failures:
            print(f"       • {f}")
        print("  Exit code: 1")
        return 1
    else:
        print(f"  {_PASS}  All assertions passed — ACGS-Lite is correctly installed.")
        print("  Exit code: 0")
        return 0


if __name__ == "__main__":
    sys.exit(main())
