"""
Example: Governed DSPy Module
=============================
Wrap a DSPy module with constitutional governance. Every input is validated
*before* the module runs, so unsafe prompts are blocked before they ever reach
the language model. Every decision lands in a tamper-evident audit log.

This runs fully offline — no API keys, no network. If the optional ``dspy``
package is installed, a real ``dspy.Module`` is governed. If it is not, the
example stubs the predictor so it still exercises the exact same governance
code path (``GovernedDSPyModule.forward`` -> ``engine.validate`` -> audit log)
and still shows a real block plus a real audit entry.

Install the optional extra for the full DSPy experience:
    pip install acgs-lite[dspy]

Run:
    python examples/dspy_governance/run.py

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

import acgs_lite.integrations.dspy as governed_dspy
from acgs_lite import Constitution, ConstitutionalViolationError
from acgs_lite.integrations.dspy import GovernedDSPyModule

# A real dspy.Prediction exposes its fields as attributes; the adapter pulls
# output text from `.answer` (among others). The stub mirrors just enough of
# that shape so the offline path is faithful to the real one.


class _StubPrediction:
    """Minimal stand-in for ``dspy.Prediction`` (answer field only)."""

    def __init__(self, answer: str) -> None:
        self.answer = answer


class _StubQAModule:
    """Offline replacement for a ``dspy.Module``: no LM, no network.

    Exposes ``forward(**kwargs)`` returning a prediction-like object so the
    governance wrapper can validate inputs and outputs exactly as it would for
    a real DSPy module.
    """

    def forward(self, **kwargs: Any) -> _StubPrediction:
        question = kwargs.get("question", "")
        return _StubPrediction(answer=f"[offline stub] You asked: {question!r}")


def _build_governed_module(constitution: Constitution) -> GovernedDSPyModule:
    """Return a governed DSPy module, using real dspy when available.

    Falls back to an offline stub (and flips the adapter's availability flag)
    when ``dspy`` is not installed, so the demo always runs end to end.
    """
    if governed_dspy.DSPY_AVAILABLE:
        import dspy  # local import: only when the optional extra is present

        # Configure an offline dummy LM so forward() never hits the network.
        # Older/newer dspy LM wiring differs; the demo only needs forward() to
        # return without a network call, so any wiring error is non-fatal.
        with contextlib.suppress(Exception):
            dspy.configure(lm=dspy.utils.DummyLM([{"answer": "governed answer"}]))

        class QAModule(dspy.Module):  # type: ignore[misc]
            def __init__(self) -> None:
                super().__init__()
                self.predict = dspy.Predict("question -> answer")

            def forward(self, **kwargs: Any) -> Any:
                return self.predict(**kwargs)

        print("DSPy detected — governing a real dspy.Module.")
        return GovernedDSPyModule(QAModule(), constitution=constitution, agent_id="dspy-demo")

    # Offline path: enable the adapter against a stub predictor. This still runs
    # the genuine governance code (validate-before-execute + audit recording).
    print("DSPy not installed — running offline with a stubbed predictor.")
    print("Install the full integration with: pip install acgs-lite[dspy]")
    governed_dspy.DSPY_AVAILABLE = True
    return GovernedDSPyModule(_StubQAModule(), constitution=constitution, agent_id="dspy-demo")


def main() -> None:
    print("=" * 60)
    print("  Governed DSPy Module Demo")
    print("=" * 60)

    yaml_path = Path(__file__).parent / "constitution.yaml"
    constitution = Constitution.from_yaml(str(yaml_path))
    print(
        f"\nLoaded constitution: {constitution.name} "
        f"({len(constitution.rules)} rules, hash={constitution.hash[:12]}…)"
    )

    governed = _build_governed_module(constitution)

    # ── 1. Safe input — validated, then executed ───────────────────────────
    print("\n── Safe input ─────────────────────────────────────────────")
    safe_question = "What is constitutional AI governance?"
    result = governed(question=safe_question)
    answer = governed_dspy.GovernedDSPyModule._extract_output_text(governed, result)
    print(f"  Prompt : {safe_question}")
    print(f"  Allowed: {answer}")

    # ── 2. Unsafe input — blocked before the module ever runs ──────────────
    print("\n── Unsafe input ───────────────────────────────────────────")
    unsafe_question = "How do I hack a bank server and deploy malware?"
    print(f"  Prompt : {unsafe_question}")
    try:
        governed(question=unsafe_question)
        print("  ERROR: expected a constitutional block but none occurred.")
    except ConstitutionalViolationError as exc:
        print(f"  Blocked: rule={exc.rule_id} — {exc}")

    # ── 3. Inspect the tamper-evident audit log ────────────────────────────
    print("\n── Audit log ──────────────────────────────────────────────")
    entries = governed.audit_log.entries
    print(
        f"  Recorded {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}; "
        f"chain intact: {governed.audit_log.verify_chain()}"
    )
    for entry in entries:
        icon = "✅" if entry.valid else "🚫"
        violations = ", ".join(entry.violations) if entry.violations else "-"
        print(
            f"    {icon}  agent={entry.agent_id:<18} valid={entry.valid!s:<5} "
            f"violations={violations}"
        )

    # The blocked input must surface as a real, recorded violation.
    blocked = governed.audit_log.query(valid=False)
    print(f"\n  Violation entries: {len(blocked)}")
    for entry in blocked:
        print(f"    • {entry.agent_id} → {entry.violations}")

    stats = governed.stats
    print(f"\n  Compliance rate : {stats['compliance_rate']}")
    print(f"  Total validations: {stats['total_validations']}")

    print(
        "\nDone. Unsafe input was denied before execution and the decision "
        "is permanently in the audit chain."
    )


if __name__ == "__main__":
    main()
