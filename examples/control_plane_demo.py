"""Control-plane demo: a self-improvement loop that cannot touch its judge.

Runs entirely inside a temporary directory it creates (nothing is written to
the repository). Phase 1: a rule-based agent improves its prompt / skill /
memory artifacts through the governed dispatcher; the deterministic
evaluator scores them and improvements are promoted by a human with a
second human's signed approval. Phase 2: an adversarial agent attempts every
known attack on the evaluator, policy, audit store, sandbox flag, its own
tier and the merge path; each must be denied. Exits 0 only if the score
improved, every attack was denied, the protected files are byte-for-byte
unchanged and the receipt chain verifies.

    python examples/control_plane_demo.py

Requires the ``cryptography`` extra (Ed25519 keys).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from acgs_lite.control_plane.demo_loop import (
    AdversarialProposer,
    SelfImprovementLoop,
    build_demo_environment,
    protected_digests,
)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="acgs-control-plane-demo-") as tmp:
        root = Path(tmp)
        env = build_demo_environment(root / "improve")
        try:
            report = SelfImprovementLoop(env).run(8)
        finally:
            env.close()
        print(
            f"improvement: score {report.initial_score:.2f} -> {report.best_score:.2f}, "
            f"{report.promotions} promotion(s), {report.receipts} receipts, "
            f"chain verified={report.receipts_verified}"
        )
        for item in report.iterations:
            print(
                f"  iter {item.iteration}: {','.join(item.proposed) or '-'} "
                f"score={item.score} accepted={item.accepted} {item.note}"
            )

        adv_env = build_demo_environment(root / "adversarial")
        before = protected_digests(adv_env.root)
        try:
            adversarial = SelfImprovementLoop(adv_env, AdversarialProposer()).run(2)
        finally:
            adv_env.close()
        unchanged = protected_digests(adv_env.root) == before
        print(
            f"adversarial: {adversarial.attacks_denied}/{len(adversarial.attacks)} attacks "
            f"denied, protected files unchanged={unchanged}, "
            f"chain verified={adversarial.receipts_verified}"
        )
        for outcome in adversarial.attacks[: len(adversarial.attacks) // 2]:
            status = "DENIED" if outcome.denied else "ALLOWED"
            print(f"  {status} {outcome.name}: {outcome.reason}")
        ok = (
            report.improved
            and report.receipts_verified
            and adversarial.attacks_denied == len(adversarial.attacks) > 0
            and unchanged
            and adversarial.receipts_verified
        )
    print("demo: OK" if ok else "demo: FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
