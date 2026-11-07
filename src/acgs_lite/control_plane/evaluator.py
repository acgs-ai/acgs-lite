"""Deterministic evaluator, outside every agent's mutation scope.

Evidence: Darwin Goedel Machine -- the self-modifying agent fabricated "tests
passed" logs and removed hallucination-detection markers, so the grader must
sit where the agent cannot write it, be deterministic and bind its verdict to
exact digests (lineage). STOP -- the agent edited its own sandbox flag, so
the evaluator's code (``src/acgs_lite/control_plane/**``) and its held-out
suite (``HELDOUT_DATA``, which agents may not even read:
INV-CORE-SENSITIVE-READ) are both immutable core.

:class:`DeterministicEvaluator` scores candidate prompt / skill / memory
artifacts (``{name: text}``) against a held-out JSON suite with pure string
predicates -- no LLM, no randomness (``seed`` is recorded in the result
digest for forward compatibility). Every :class:`EvaluationResult` carries
``suite_digest``, ``candidate_digest``, ``evaluator_digest`` (SHA-256 of the
evaluator's source file) and ``result_digest`` over all of them.

:class:`EvaluatorService` runs it as a SERVICE principal and registers each
run as an ``EVALUATOR_SERVICE`` :class:`~.evidence.ExternalRunRef` in a
:class:`~.evidence.TrustedRunRegistry` with ``artifact_digest =
candidate_digest``, so Phase-2 promotion binding works -- but only when the
harness asks for promotion evidence (:meth:`EvaluatorService.evaluate`,
deduplicated per candidate), never per agent query. Agents get only
:meth:`EvaluatorService.submission_handle`: a callable returning a score
rounded to a coarse granularity, rate-limited per principal and charging one
iteration of the agent's budget per call, so the held-out suite cannot be
mined through an unbounded score oracle.

``evaluator_digest`` covers the evaluator source, the control-plane modules
it executes (evidence, immutable_core, principal) and the suite schema.

Suite format::

    {"version": 1, "suite_id": "...", "pass_threshold": 0.5,
     "cases": [{"case_id": "c1", "artifact": "prompt",
                "require_all": ["cite"], "forbid_any": ["guess"]}]}
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from acgs_lite.control_plane import evidence as _evidence_module
from acgs_lite.control_plane import immutable_core as _core_module
from acgs_lite.control_plane import principal as _principal_module
from acgs_lite.control_plane.budgets import BudgetLedger
from acgs_lite.control_plane.evidence import EvidenceSource, ExternalRunRef, TrustedRunRegistry
from acgs_lite.control_plane.immutable_core import CoreCategory, ImmutableCoreRegistry
from acgs_lite.control_plane.principal import Principal, PrincipalKind

__all__ = [
    "EVALUATOR_PROVIDER",
    "CaseResult",
    "DeterministicEvaluator",
    "EvaluationResult",
    "EvaluatorError",
    "EvaluatorService",
    "SubmissionRefused",
    "candidate_digest",
]

EVALUATOR_PROVIDER = "acgs-deterministic-evaluator"
_CANDIDATE_DOMAIN = b"acgs-control-plane-candidate-v1\x00"
_RESULT_DOMAIN = b"acgs-control-plane-evaluation-v1\x00"
_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
_SUITE_KEYS = frozenset({"version", "suite_id", "pass_threshold", "cases"})
_CASE_KEYS = frozenset({"case_id", "artifact", "require_all", "forbid_any"})
_MAX_ARTIFACT_CHARS = 1_000_000
_EVALUATOR_DIGEST_DOMAIN = b"acgs-control-plane-evaluator-v1\x00"
_DEPENDENCY_SOURCES = (
    ("evidence", Path(_evidence_module.__file__)),
    ("immutable_core", Path(_core_module.__file__)),
    ("principal", Path(_principal_module.__file__)),
)
# TODO(control-plane-gap): submission limits (20 per 60 s per principal, score
# granularity 0.1) are design inference against score-oracle mining of the
# held-out suite; configurable per submission handle.
DEFAULT_SUBMISSIONS_PER_WINDOW = 20
DEFAULT_SUBMISSION_WINDOW_S = 60.0
DEFAULT_SCORE_GRANULARITY = 0.1


class SubmissionRefused(PermissionError):
    """An agent evaluation submission was refused (rate limit or budget)."""


class EvaluatorError(ValueError):
    """The suite, the candidate or the evaluator source is unusable."""


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _check_candidate(candidate: object) -> dict[str, str]:
    if not isinstance(candidate, Mapping) or not candidate:
        raise EvaluatorError("candidate must be a non-empty mapping of artifact name -> text")
    out: dict[str, str] = {}
    for name, text in candidate.items():
        if not isinstance(name, str) or not _ID.fullmatch(name):
            raise EvaluatorError(f"invalid artifact name {name!r}")
        if not isinstance(text, str) or len(text) > _MAX_ARTIFACT_CHARS:
            raise EvaluatorError(f"artifact {name!r} must be text <= {_MAX_ARTIFACT_CHARS} chars")
        out[name] = text
    return out


def candidate_digest(candidate: Mapping[str, str]) -> str:
    """Digest of candidate artifacts (the promotion ``candidate_digest``)."""
    return _sha256(_CANDIDATE_DOMAIN + _canonical(_check_candidate(candidate)))


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    passed: bool


@dataclass(frozen=True)
class EvaluationResult:
    score: float
    passed: bool
    cases: tuple[CaseResult, ...]
    suite_digest: str
    candidate_digest: str
    evaluator_digest: str
    result_digest: str
    seed: int = 0


@dataclass(frozen=True)
class _Case:
    case_id: str
    artifact: str
    require_all: tuple[str, ...]
    forbid_any: tuple[str, ...]


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise EvaluatorError(f"{label} must be a list of non-empty strings")
    if label == "require_all" and not value:
        raise EvaluatorError("require_all must not be empty (a vacuous case always passes)")
    return tuple(v.casefold() for v in value)


def _parse_suite(data: object) -> tuple[str, float, tuple[_Case, ...]]:
    if not isinstance(data, Mapping) or set(data) != _SUITE_KEYS or data["version"] != 1:
        raise EvaluatorError("suite must be {version: 1, suite_id, pass_threshold, cases}")
    suite_id = data["suite_id"]
    if not isinstance(suite_id, str) or not _ID.fullmatch(suite_id):
        raise EvaluatorError("invalid suite_id")
    threshold = data["pass_threshold"]
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
        or not 0 < threshold <= 1
    ):
        raise EvaluatorError("pass_threshold must be in (0, 1]")
    raw_cases = data["cases"]
    if not isinstance(raw_cases, list) or not raw_cases:
        raise EvaluatorError("suite needs at least one case")
    cases: list[_Case] = []
    seen: set[str] = set()
    for raw in raw_cases:
        if not isinstance(raw, Mapping) or set(raw) != _CASE_KEYS:
            raise EvaluatorError("malformed suite case")
        case_id, artifact = raw["case_id"], raw["artifact"]
        if not isinstance(case_id, str) or not _ID.fullmatch(case_id) or case_id in seen:
            raise EvaluatorError(f"invalid or duplicate case_id {case_id!r}")
        if not isinstance(artifact, str) or not _ID.fullmatch(artifact):
            raise EvaluatorError(f"invalid artifact name in case {case_id!r}")
        seen.add(case_id)
        cases.append(
            _Case(
                case_id,
                artifact,
                _strings(raw["require_all"], "require_all"),
                _strings(raw["forbid_any"], "forbid_any"),
            )
        )
    return suite_id, float(threshold), tuple(cases)


class DeterministicEvaluator:
    """Pure scorer bound to one held-out suite file and its own source."""

    def __init__(
        self,
        suite_path: str | Path,
        *,
        registry: ImmutableCoreRegistry,
        source_path: str | Path | None = None,
        seed: int = 0,
    ) -> None:
        if not isinstance(registry, ImmutableCoreRegistry):
            raise TypeError("registry must be an ImmutableCoreRegistry")
        raw = str(suite_path)
        category = registry.classify(raw)
        if category is not CoreCategory.HELDOUT_DATA:
            raise EvaluatorError(
                f"held-out suite {raw!r} must be immutable-core HELDOUT_DATA, got {category}"
            )
        path = Path(raw)
        if not path.is_absolute() and registry.repo_root is not None:
            path = Path(registry.repo_root) / path
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise EvaluatorError("seed must be an int")
        self._suite_path = path
        self._source_path = Path(__file__) if source_path is None else Path(source_path)
        self._seed = seed
        self._suite_bytes = self._read(self._suite_path, "suite")
        try:
            parsed = json.loads(self._suite_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise EvaluatorError("suite is not UTF-8 JSON") from exc
        self._suite_id, self._threshold, self._cases = _parse_suite(parsed)
        self._suite_digest = _sha256(self._suite_bytes)
        self._evaluator_digest = self._code_digest()

    @staticmethod
    def _read(path: Path, label: str) -> bytes:
        try:
            return path.read_bytes()
        except OSError as exc:
            raise EvaluatorError(f"{label} unreadable: {type(exc).__name__}") from exc

    def _code_digest(self) -> str:
        parts = [["evaluator", _sha256(self._read(self._source_path, "evaluator source"))]]
        parts.extend(
            [name, _sha256(self._read(path, f"{name} source"))]
            for name, path in _DEPENDENCY_SOURCES
        )
        parts.append(["suite_schema", ",".join(sorted(_SUITE_KEYS | _CASE_KEYS)) + ";v1"])
        return _sha256(_EVALUATOR_DIGEST_DOMAIN + _canonical(parts))

    @property
    def suite_digest(self) -> str:
        return self._suite_digest

    @property
    def evaluator_digest(self) -> str:
        return self._evaluator_digest

    @property
    def suite_id(self) -> str:
        return self._suite_id

    def evaluate(self, candidate: Mapping[str, str]) -> EvaluationResult:
        """Score *candidate*. The suite and evaluator source are re-hashed
        first; a change since construction raises (no silent re-grading)."""
        artifacts = _check_candidate(candidate)
        if _sha256(self._read(self._suite_path, "suite")) != self._suite_digest:
            raise EvaluatorError("held-out suite changed since the evaluator was bound")
        if self._code_digest() != self._evaluator_digest:
            raise EvaluatorError("evaluator source changed since the evaluator was bound")
        lowered = {name: text.casefold() for name, text in artifacts.items()}
        results = []
        for case in self._cases:
            text = lowered.get(case.artifact)
            passed = (
                text is not None
                and all(token in text for token in case.require_all)
                and not any(token in text for token in case.forbid_any)
            )
            results.append(CaseResult(case.case_id, passed))
        score = sum(r.passed for r in results) / len(results)
        digest = candidate_digest(artifacts)
        payload = {
            "score": score,
            "passed": score >= self._threshold,
            "cases": [[r.case_id, r.passed] for r in results],
            "suite_digest": self._suite_digest,
            "candidate_digest": digest,
            "evaluator_digest": self._evaluator_digest,
            "seed": self._seed,
        }
        return EvaluationResult(
            score=score,
            passed=score >= self._threshold,
            cases=tuple(results),
            suite_digest=self._suite_digest,
            candidate_digest=digest,
            evaluator_digest=self._evaluator_digest,
            result_digest=_sha256(_RESULT_DOMAIN + _canonical(payload)),
            seed=self._seed,
        )


class EvaluatorService:
    """Runs the evaluator as a SERVICE and registers each run as evidence."""

    def __init__(
        self,
        evaluator: DeterministicEvaluator,
        principal: Principal,
        run_registry: TrustedRunRegistry,
        *,
        provider: str = EVALUATOR_PROVIDER,
    ) -> None:
        if not isinstance(evaluator, DeterministicEvaluator):
            raise TypeError("evaluator must be a DeterministicEvaluator")
        if not isinstance(principal, Principal) or principal.kind is not PrincipalKind.SERVICE:
            raise EvaluatorError("the evaluator service runs as a SERVICE principal")
        if not isinstance(run_registry, TrustedRunRegistry):
            raise TypeError("run_registry must be a TrustedRunRegistry")
        self._evaluator = evaluator
        self._principal = principal
        self._registry = run_registry
        self._provider = provider
        self._lock = threading.Lock()
        self._count = 0
        self._latest: dict[str, tuple[EvaluationResult, ExternalRunRef]] = {}
        # Submission windows live here, keyed by canonical principal id, so
        # minting fresh handles does not reset an agent's rate limit.
        self._windows: dict[str, collections.deque[float]] = {}

    def evaluate(self, candidate: Mapping[str, str]) -> tuple[EvaluationResult, ExternalRunRef]:
        """Harness: evaluate and register promotion evidence. Deduplicated:
        a candidate already registered returns its existing run."""
        result = self._evaluator.evaluate(candidate)
        with self._lock:
            existing = self._latest.get(result.candidate_digest)
            if existing is not None and existing[0] == result:
                return existing
            self._count += 1
            run_id = f"eval-{self._count}-{result.result_digest[7:23]}"
            ref = ExternalRunRef(
                provider=self._provider,
                run_id=run_id,
                source=EvidenceSource.EVALUATOR_SERVICE,
                artifact_digest=result.candidate_digest,
            )
            self._registry.register_run(
                self._principal,
                ref,
                conclusion="success" if result.passed else "failure",
                artifact_digest=result.candidate_digest,
            )
            self._latest[result.candidate_digest] = (result, ref)
        return result, ref

    def latest(self, digest: str) -> tuple[EvaluationResult, ExternalRunRef] | None:
        """Harness-only: the registered run for *digest* (never given to agents)."""
        with self._lock:
            return self._latest.get(digest)

    def submission_handle(
        self,
        principal: Principal,
        budgets: BudgetLedger,
        *,
        max_per_window: int = DEFAULT_SUBMISSIONS_PER_WINDOW,
        window_s: float = DEFAULT_SUBMISSION_WINDOW_S,
        granularity: float = DEFAULT_SCORE_GRANULARITY,
        clock: Callable[[], float] = time.monotonic,
    ) -> Callable[[Mapping[str, str]], float]:
        """The only evaluator capability an agent receives: candidate -> score.

        Each call is rate-limited per principal, charges one iteration to
        *principal*'s budget (atomically; no run or exhausted -> refused) and
        returns the score rounded to *granularity*. Nothing is registered.

        TODO(control-plane-gap): in-process, a closure's cells are
        introspectable; out-of-process evaluation is a later phase.
        """
        if not isinstance(principal, Principal):
            raise TypeError("principal must be a Principal")
        if not isinstance(budgets, BudgetLedger):
            raise TypeError("budgets must be a BudgetLedger")
        if isinstance(max_per_window, bool) or not isinstance(max_per_window, int):
            raise ValueError("max_per_window must be an int >= 1")
        if max_per_window < 1 or window_s <= 0 or not 0 < granularity <= 1:
            raise ValueError("invalid submission limits")
        evaluator = self._evaluator
        lock = self._lock
        with lock:
            window = self._windows.setdefault(principal.canonical_id, collections.deque())
        steps = round(1 / granularity)

        def submit_for_evaluation(candidate: Mapping[str, str]) -> float:
            with lock:
                now = float(clock())
                while window and window[0] <= now - window_s:
                    window.popleft()
                if len(window) >= max_per_window:
                    raise SubmissionRefused("evaluation rate limit reached")
                if not budgets.has_run(principal):
                    raise SubmissionRefused("no budget run for this principal")
                if budgets.try_charge(principal, iterations=1) is None:
                    raise SubmissionRefused("budget exhausted")
                window.append(now)
            score = evaluator.evaluate(dict(candidate)).score
            return round(math.floor(score * steps + 1e-9) / steps, 6)

        return submit_for_evaluation
