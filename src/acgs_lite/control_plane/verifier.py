"""Independent verifier: a different model tier or vendor, anchored on runs.

Evidence: METR (Mar 2026) -- the SWE-bench grader approved patches that
maintainers would not merge (~24pp gap), i.e. an automated grader from the
same pipeline over-approves; so the verifier must be independent of the
proposer (a different model family *or* vendor) and cannot merge. DGM -- the
agent faked "tests passed" logs; so a verdict counts only when it cites at
least one executable artifact (an ``ExternalRunRef`` from a CI system or the
evaluator service) that the harness's run verifier validates. Prose and
``AGENT_LOG`` evidence never count.

Verdicts are recorded as Phase-4 ``VERIFIER_VERDICT`` telemetry by a
SERVICE/HUMAN recorder (``TelemetryRecorder`` refuses agents).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from acgs_lite._compat import StrEnum
from acgs_lite.control_plane.evidence import (
    EvidenceSource,
    ExternalRunRef,
    ExternalRunVerifier,
    RunValidation,
)
from acgs_lite.control_plane.telemetry import TelemetryRecorder

__all__ = [
    "ANCHOR_SOURCES",
    "IndependentVerifier",
    "ReplayVerifier",
    "VerdictOutcome",
    "VerifierPolicy",
    "VerifierRejected",
    "VerifierVerdict",
]

# Sources that are *executable* artifacts (a human review is not a re-run).
ANCHOR_SOURCES = frozenset({EvidenceSource.CI_SYSTEM, EvidenceSource.EVALUATOR_SERVICE})


class VerifierRejected(PermissionError):
    """The verifier or its verdict is not acceptable."""


class VerdictOutcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"


@dataclass(frozen=True)
class VerifierVerdict:
    """An independent verifier's verdict on one candidate."""

    verifier_id: str
    candidate_digest: str
    outcome: VerdictOutcome
    evidence: tuple[ExternalRunRef, ...]
    rationale: str = ""
    """Free text; never counts as evidence."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", VerdictOutcome(self.outcome))
        object.__setattr__(self, "evidence", tuple(self.evidence))


@runtime_checkable
class IndependentVerifier(Protocol):
    verifier_id: str
    model_family: str
    vendor: str

    def verify(
        self, candidate_digest: str, artifacts: Sequence[ExternalRunRef]
    ) -> VerifierVerdict: ...


def _norm(value: object) -> str:
    return value.strip().casefold() if isinstance(value, str) else ""


class VerifierPolicy:
    """Independence + anchoring rules, and telemetry of accepted verdicts."""

    # TODO(control-plane-gap): "differs in model family or vendor" is a design
    # inference from METR (grader != maintainer); stricter rules (different
    # vendor *and* family, or N verifiers) are configurable per deployment.

    def __init__(
        self,
        run_verifier: ExternalRunVerifier,
        *,
        telemetry: TelemetryRecorder | None = None,
        require_vendor_differs: bool = False,
    ) -> None:
        if not isinstance(run_verifier, ExternalRunVerifier):
            raise TypeError("run_verifier must be an ExternalRunVerifier")
        if telemetry is not None and type(telemetry) is not TelemetryRecorder:
            raise TypeError("telemetry must be a TelemetryRecorder")
        self._runs = run_verifier
        self._telemetry = telemetry
        self._require_vendor = bool(require_vendor_differs)

    def require_independent(
        self, proposer_model_family: str, proposer_vendor: str, verifier: object
    ) -> None:
        """Raise unless *verifier* differs from the proposer in family or vendor."""
        if not isinstance(verifier, IndependentVerifier):
            raise VerifierRejected("verifier must implement IndependentVerifier")
        family, vendor = _norm(verifier.model_family), _norm(verifier.vendor)
        proposer_family, proposer_vendor_n = _norm(proposer_model_family), _norm(proposer_vendor)
        if not family or not vendor or not proposer_family or not proposer_vendor_n:
            raise VerifierRejected("model family and vendor must be named for both parties")
        if self._require_vendor and vendor == proposer_vendor_n:
            raise VerifierRejected("verifier must come from a different vendor")
        if family == proposer_family and vendor == proposer_vendor_n:
            raise VerifierRejected(
                "verifier shares the proposer's model family and vendor (not independent)"
            )

    def check_verdict(self, verdict: object, candidate_digest: str) -> tuple[str, ...]:
        """Rejection reasons (empty = the verdict is artifact-anchored)."""
        if not isinstance(verdict, VerifierVerdict):
            return ("verdict must be a VerifierVerdict",)
        reasons: list[str] = []
        if verdict.candidate_digest != candidate_digest:
            reasons.append("verdict is about a different candidate")
        anchored = 0
        for ref in verdict.evidence:
            if not isinstance(ref, ExternalRunRef):
                reasons.append("evidence must be ExternalRunRef objects")
                continue
            if ref.source not in ANCHOR_SOURCES:
                continue  # prose-like or agent-written context: never counts
            if ref.artifact_digest != candidate_digest:
                reasons.append(f"run {ref.label} is not bound to the candidate")
                continue
            try:
                result = self._runs.validate(ref)
            except Exception as exc:
                reasons.append(f"run {ref.label}: verifier error {type(exc).__name__}")
                continue
            if not isinstance(result, RunValidation) or result.valid is not True:
                reasons.append(f"run {ref.label} not independently validated")
                continue
            anchored += 1
        if anchored == 0:
            reasons.append("verdict is not anchored on a validated executable artifact")
        return tuple(reasons)

    def accept(
        self,
        verifier: IndependentVerifier,
        verdict: VerifierVerdict,
        candidate_digest: str,
        *,
        proposer_model_family: str,
        proposer_vendor: str,
    ) -> VerifierVerdict:
        """Independence + anchoring; on success record VERIFIER_VERDICT telemetry."""
        self.require_independent(proposer_model_family, proposer_vendor, verifier)
        if verdict.verifier_id != verifier.verifier_id:
            raise VerifierRejected("verdict was not produced by this verifier")
        reasons = self.check_verdict(verdict, candidate_digest)
        if reasons:
            raise VerifierRejected("; ".join(reasons))
        if self._telemetry is not None:
            self._telemetry.record_verifier_verdict(
                candidate_digest, verifier.verifier_id, verdict.outcome.value
            )
        return verdict


class ReplayVerifier:
    """Deterministic, network-free verifier (test double and demo default).

    It re-checks the cited runs through its own run verifier and passes only
    if a validated ``ANCHOR_SOURCES`` run is bound to the candidate.
    """

    def __init__(
        self,
        run_verifier: ExternalRunVerifier,
        *,
        verifier_id: str = "replay-verifier",
        model_family: str = "rule-based-replay",
        vendor: str = "acgs-independent-verifier",
    ) -> None:
        if not isinstance(run_verifier, ExternalRunVerifier):
            raise TypeError("run_verifier must be an ExternalRunVerifier")
        self._runs = run_verifier
        self.verifier_id = verifier_id
        self.model_family = model_family
        self.vendor = vendor

    def verify(self, candidate_digest: str, artifacts: Sequence[ExternalRunRef]) -> VerifierVerdict:
        valid = tuple(
            ref
            for ref in artifacts
            if isinstance(ref, ExternalRunRef)
            and ref.source in ANCHOR_SOURCES
            and ref.artifact_digest == candidate_digest
            and self._runs.validate(ref).valid is True
        )
        return VerifierVerdict(
            verifier_id=self.verifier_id,
            candidate_digest=candidate_digest,
            outcome=VerdictOutcome.PASS if valid else VerdictOutcome.FAIL,
            evidence=valid,
            rationale="replayed cited runs" if valid else "no validated run for the candidate",
        )
