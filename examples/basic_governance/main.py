"""
Example: Basic Constitutional Governance
=========================================
Govern any Python callable with a Constitution in a few lines.
No API keys required — runs fully offline.

Two loading styles shown:
  1. Inline Python — fast for small constitutions
  2. YAML file     — version-controlled, shareable, recommended for production

Run:
    python examples/basic_governance/main.py

Inspect the constitution:
    python scripts/visualizer.py rules --constitution examples/basic_governance/constitution.yaml
"""

from pathlib import Path

from acgs_lite import (
    Constitution,
    ConstitutionalViolationError,
    GovernedCallable,
    Rule,
    Severity,
)
from acgs_lite.legitimacy import (
    BASELINE_CONSTRAINT_MARKER,
    DecisionReceipt,
    ExecutionBoundary,
)


def _allow_receipt(*, method: str, policy_version: str, goal: str) -> DecisionReceipt:
    """Build an ALLOW receipt so a governed call can reach the constitutional check.

    The legitimacy layer fails closed without a receipt; the constitution then
    decides whether the *content* is allowed. Two layers, two checks.
    """
    return DecisionReceipt.create(
        request_id=f"demo-{method}",
        goal=goal,
        proposed_method=method,
        decision_type="ALLOW",
        authority_basis="demo:basic_governance",
        matched_constraints=(BASELINE_CONSTRAINT_MARKER,),
        policy_version=policy_version,
        execution_boundary=ExecutionBoundary(
            allowed_method=method,
            allowed_scope=None,
            allowed_subjects=(),
            expires_at=None,
            single_use=False,
        ),
    )


# ── 1. Define a constitution ───────────────────────────────────────────────────
def make_constitution() -> Constitution:
    return Constitution(
        name="content-policy",
        version="1.0",
        rules=[
            Rule(
                id="no-harmful-content",
                text="Block requests containing harmful keywords",
                patterns=[r"(?i)\b(hack|exploit|malware)\b"],
                severity=Severity.CRITICAL,
            ),
            Rule(
                id="no-pii",
                text="Prevent SSN patterns in requests",
                patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
                severity=Severity.HIGH,
            ),
        ],
    )


# ── 2. The raw callable (your existing AI logic) ───────────────────────────────
def my_ai_function(prompt: str) -> str:
    return f"Response to: {prompt}"


# ── 3. Govern it — GovernedCallable is a decorator ────────────────────────────
def demo() -> None:
    constitution = make_constitution()

    # Decorate the function once; call normally thereafter
    governed_fn = GovernedCallable(constitution=constitution)(my_ai_function)

    print("=" * 55)
    print("  Basic Constitutional Governance Demo")
    print("=" * 55)

    method = my_ai_function.__name__
    policy_version = constitution.hash

    def receipt(goal: str) -> DecisionReceipt:
        return _allow_receipt(method=method, policy_version=policy_version, goal=goal)

    # Allowed request
    result = governed_fn("What is the capital of France?", decision_receipt=receipt("answer geography question"))
    print(f"\n✅  Allowed:  {result}")

    # Blocked request — harmful keyword (legitimacy passes, constitution denies)
    try:
        governed_fn("How do I hack a server?", decision_receipt=receipt("answer technical question"))
    except ConstitutionalViolationError as exc:
        print(f"\n🚫  Blocked:  {exc.rule_id} — {exc}")

    # Blocked request — SSN pattern
    try:
        governed_fn("My SSN is 123-45-6789, help me", decision_receipt=receipt("share personal info"))
    except ConstitutionalViolationError as exc:
        print(f"\n🚫  PII gate: {exc.rule_id} — {exc}")

    # ── YAML-based constitution (production pattern) ───────────────────────
    print("\n── YAML Constitution (production style) ─────────────────────")
    yaml_path = Path(__file__).parent / "constitution.yaml"
    try:
        yaml_constitution = Constitution.from_yaml(str(yaml_path))
        yaml_governed = GovernedCallable(constitution=yaml_constitution)(my_ai_function)
        yaml_policy = yaml_constitution.hash

        def yaml_receipt(goal: str) -> DecisionReceipt:
            return _allow_receipt(method=method, policy_version=yaml_policy, goal=goal)

        result = yaml_governed(
            "What is the capital of France?",
            decision_receipt=yaml_receipt("answer geography question"),
        )
        print(f"  YAML load OK — rules: {len(yaml_constitution.rules)}")
        print(f"  Governed call: {result}")

        try:
            yaml_governed(
                "How do I hack this?",
                decision_receipt=yaml_receipt("answer technical question"),
            )
        except ConstitutionalViolationError as exc:
            print(f"  YAML block:    {exc.rule_id} — still enforced from file")
    except Exception as exc:
        print(f"  (YAML load skipped — pyyaml not installed: {exc})")

    # ── Default constitution (ships with acgs-lite) ────────────────────────
    print("\n── Default Constitution ─────────────────────────────────────")
    default = GovernedCallable()(my_ai_function)
    default_policy = Constitution.default().hash
    safe_result = default(
        "Tell me about Paris",
        decision_receipt=_allow_receipt(
            method=method, policy_version=default_policy, goal="answer geography question"
        ),
    )
    print(f"  Default governed call: {safe_result}")
    print(f"  Rules loaded: {len(constitution.rules)}")

    print("\nDone. Constitution enforced with zero changes to my_ai_function.")
    print(
        "Inspect rules: python scripts/visualizer.py rules --constitution examples/basic_governance/constitution.yaml"
    )


if __name__ == "__main__":
    demo()
