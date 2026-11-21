"""Phase 5: independent verifier (different family/vendor, artifact-anchored)."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from acgs_lite.control_plane import (
    EvidenceSource,
    ExternalRunRef,
    InMemoryTelemetryStore,
    Principal,
    PrincipalKind,
    TelemetryRecorder,
    TrustedRunRegistry,
)
from acgs_lite.control_plane.telemetry import EventKind
from acgs_lite.control_plane.verifier import (
    IndependentVerifier,
    ReplayVerifier,
    VerdictOutcome,
    VerifierPolicy,
    VerifierRejected,
    VerifierVerdict,
)

pytestmark = [pytest.mark.unit]

SERVICE = Principal("evaluator-svc", PrincipalKind.SERVICE)
DIGEST = "sha256:" + "ab" * 32


@pytest.fixture()
def runs() -> TrustedRunRegistry:
    registry = TrustedRunRegistry()
    registry.register_run(
        SERVICE,
        ExternalRunRef("acgs-eval", "r1", EvidenceSource.EVALUATOR_SERVICE, artifact_digest=DIGEST),
        conclusion="success",
    )
    return registry


def eval_ref(run_id: str = "r1", digest: str = DIGEST) -> ExternalRunRef:
    return ExternalRunRef(
        "acgs-eval", run_id, EvidenceSource.EVALUATOR_SERVICE, artifact_digest=digest
    )


class SameVendor:
    verifier_id = "same"
    model_family = "Claude-5"
    vendor = "Anthropic"

    def verify(self, candidate_digest: str, artifacts: Sequence[ExternalRunRef]) -> VerifierVerdict:
        return VerifierVerdict(self.verifier_id, candidate_digest, VerdictOutcome.PASS, ())


class TestIndependence:
    def test_same_family_and_vendor_rejected(self, runs: TrustedRunRegistry) -> None:
        policy = VerifierPolicy(runs)
        assert isinstance(SameVendor(), IndependentVerifier)
        with pytest.raises(VerifierRejected, match="not independent"):
            policy.require_independent("claude-5", " anthropic ", SameVendor())

    def test_different_family_or_vendor_accepted(self, runs: TrustedRunRegistry) -> None:
        policy = VerifierPolicy(runs)
        policy.require_independent("claude-4", "anthropic", SameVendor())
        policy.require_independent("claude-5", "other-vendor", SameVendor())

    def test_vendor_rule_and_unnamed(self, runs: TrustedRunRegistry) -> None:
        strict = VerifierPolicy(runs, require_vendor_differs=True)
        with pytest.raises(VerifierRejected, match="different vendor"):
            strict.require_independent("claude-4", "anthropic", SameVendor())
        with pytest.raises(VerifierRejected, match="named"):
            strict.require_independent("", "anthropic", SameVendor())
        with pytest.raises(VerifierRejected, match="IndependentVerifier"):
            strict.require_independent("a", "b", object())

    def test_constructor_validation(self, runs: TrustedRunRegistry) -> None:
        with pytest.raises(TypeError):
            VerifierPolicy("runs")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            VerifierPolicy(runs, telemetry="t")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            ReplayVerifier("runs")  # type: ignore[arg-type]


class TestAnchoring:
    def test_prose_only_rejected(self, runs: TrustedRunRegistry) -> None:
        verdict = VerifierVerdict("v", DIGEST, "pass", (), rationale="looks great, tests pass")
        assert "not anchored" in " ".join(VerifierPolicy(runs).check_verdict(verdict, DIGEST))

    def test_agent_log_only_rejected(self, runs: TrustedRunRegistry) -> None:
        log = ExternalRunRef("agent", "l1", EvidenceSource.AGENT_LOG, artifact_digest=DIGEST)
        review = ExternalRunRef("hr", "h1", EvidenceSource.HUMAN_REVIEW, artifact_digest=DIGEST)
        verdict = VerifierVerdict("v", DIGEST, "pass", (log, review))
        assert VerifierPolicy(runs).check_verdict(verdict, DIGEST)

    @pytest.mark.parametrize(
        ("evidence", "candidate", "reason"),
        [
            ((eval_ref("unregistered"),), DIGEST, "not independently validated"),
            ((eval_ref(digest="sha256:" + "cd" * 32),), DIGEST, "not bound"),
            ((eval_ref(),), "sha256:" + "ef" * 32, "different candidate"),
            (("not-a-ref",), DIGEST, "ExternalRunRef"),
        ],
    )
    def test_bad_evidence(
        self, runs: TrustedRunRegistry, evidence: tuple[object, ...], candidate: str, reason: str
    ) -> None:
        verdict = VerifierVerdict("v", DIGEST, "pass", evidence)  # type: ignore[arg-type]
        assert reason in " ".join(VerifierPolicy(runs).check_verdict(verdict, candidate))

    def test_not_a_verdict(self, runs: TrustedRunRegistry) -> None:
        assert VerifierPolicy(runs).check_verdict("pass", DIGEST)

    def test_verifier_errors_are_rejections(self) -> None:
        class Boom:
            verifier_id = "boom"
            attests_artifact_digest = True

            def validate(self, ref: ExternalRunRef) -> object:
                raise RuntimeError("down")

        verdict = VerifierVerdict("v", DIGEST, "pass", (eval_ref(),))
        assert "verifier error" in " ".join(VerifierPolicy(Boom()).check_verdict(verdict, DIGEST))  # type: ignore[arg-type]

    def test_artifact_anchored_accepted_and_recorded(self, runs: TrustedRunRegistry) -> None:
        store = InMemoryTelemetryStore()
        policy = VerifierPolicy(runs, telemetry=TelemetryRecorder(store, SERVICE))
        verifier = ReplayVerifier(runs)
        verdict = verifier.verify(DIGEST, [eval_ref(), eval_ref("unregistered")])
        assert verdict.outcome is VerdictOutcome.PASS and verdict.evidence == (eval_ref(),)
        accepted = policy.accept(
            verifier, verdict, DIGEST, proposer_model_family="claude-5", proposer_vendor="anthropic"
        )
        assert accepted is verdict
        events = store.read_all()
        assert [e.kind for e in events] == [EventKind.VERIFIER_VERDICT]
        assert events[0].to_dict()["verifier_id"] == "replay-verifier"

    def test_accept_rejects_foreign_and_unanchored(self, runs: TrustedRunRegistry) -> None:
        policy = VerifierPolicy(runs)
        verifier = ReplayVerifier(runs)
        foreign = VerifierVerdict("someone-else", DIGEST, "pass", (eval_ref(),))
        with pytest.raises(VerifierRejected, match="not produced"):
            policy.accept(verifier, foreign, DIGEST, proposer_model_family="x", proposer_vendor="y")
        failing = verifier.verify(DIGEST, [])
        assert failing.outcome is VerdictOutcome.FAIL
        with pytest.raises(VerifierRejected, match="anchored"):
            policy.accept(verifier, failing, DIGEST, proposer_model_family="x", proposer_vendor="y")
