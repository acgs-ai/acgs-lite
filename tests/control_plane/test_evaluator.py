"""Phase 5: deterministic, digest-bound evaluator outside mutation scope."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    EvidenceSource,
    Principal,
    PrincipalKind,
    TrustedRunRegistry,
)
from acgs_lite.control_plane import evaluator as evaluator_module
from acgs_lite.control_plane.evaluator import (
    DeterministicEvaluator,
    EvaluatorError,
    EvaluatorService,
    candidate_digest,
)
from acgs_lite.control_plane.immutable_core import CoreCategory

pytestmark = [pytest.mark.unit]

SERVICE = Principal("evaluator-svc", PrincipalKind.SERVICE)
SUITE: dict[str, Any] = {
    "version": 1,
    "suite_id": "demo-heldout",
    "pass_threshold": 0.5,
    "cases": [
        {"case_id": "c1", "artifact": "prompt", "require_all": ["cite"], "forbid_any": []},
        {"case_id": "c2", "artifact": "skill", "require_all": ["retry"], "forbid_any": ["guess"]},
    ],
}


def write_suite(root: Path, suite: object = SUITE) -> str:
    path = root / "heldout" / "suite.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(suite), encoding="utf-8")
    return "heldout/suite.json"


@pytest.fixture()
def evaluator(tmp_path: Path) -> DeterministicEvaluator:
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    return DeterministicEvaluator(write_suite(tmp_path), registry=registry)


def test_deterministic_result_digest(evaluator: DeterministicEvaluator) -> None:
    candidate = {"prompt": "Always CITE sources.", "skill": "retry once"}
    first, second = evaluator.evaluate(candidate), evaluator.evaluate(dict(candidate))
    assert first == second
    assert first.score == 1.0 and first.passed
    assert first.candidate_digest == candidate_digest(candidate)
    assert first.evaluator_digest == evaluator.evaluator_digest
    assert first.suite_digest == evaluator.suite_digest
    assert evaluator.evaluate({"prompt": "x", "skill": "y"}).result_digest != first.result_digest


def test_scoring_rules(evaluator: DeterministicEvaluator) -> None:
    assert evaluator.evaluate({"prompt": "cite"}).score == 0.5  # missing artifact fails c2
    forbidden = evaluator.evaluate({"prompt": "nope", "skill": "retry or guess"})
    assert forbidden.score == 0.0 and not forbidden.passed
    assert evaluator.suite_id == "demo-heldout"


def test_evaluator_digest_covers_dependencies(tmp_path: Path, monkeypatch: Any) -> None:
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    suite = write_suite(tmp_path)
    base = DeterministicEvaluator(suite, registry=registry).evaluator_digest
    copy = tmp_path / "dep_copy.py"
    shutil.copy(evaluator_module._DEPENDENCY_SOURCES[0][1], copy)
    deps = (("evidence", copy), *evaluator_module._DEPENDENCY_SOURCES[1:])
    monkeypatch.setattr(evaluator_module, "_DEPENDENCY_SOURCES", deps)
    assert DeterministicEvaluator(suite, registry=registry).evaluator_digest == base
    copy.write_text(copy.read_text() + "\n# tampered dependency\n")
    assert DeterministicEvaluator(suite, registry=registry).evaluator_digest != base


def test_evaluator_digest_tracks_source(tmp_path: Path) -> None:
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    suite = write_suite(tmp_path)
    copy = tmp_path / "evaluator" / "copy.py"
    copy.parent.mkdir()
    shutil.copy(evaluator_module.__file__, copy)
    real = DeterministicEvaluator(suite, registry=registry)
    same = DeterministicEvaluator(suite, registry=registry, source_path=copy)
    assert same.evaluator_digest == real.evaluator_digest
    copy.write_text(copy.read_text() + "\n# edited\n")
    changed = DeterministicEvaluator(suite, registry=registry, source_path=copy)
    assert changed.evaluator_digest != real.evaluator_digest
    copy.write_text(copy.read_text() + "\n# edited again\n")
    with pytest.raises(EvaluatorError, match="source changed"):
        changed.evaluate({"prompt": "cite"})


def test_suite_tamper_detected(tmp_path: Path, evaluator: DeterministicEvaluator) -> None:
    write_suite(tmp_path, {**SUITE, "pass_threshold": 0.1})
    with pytest.raises(EvaluatorError, match="suite changed"):
        evaluator.evaluate({"prompt": "cite"})


def test_suite_must_be_heldout_core(tmp_path: Path) -> None:
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    assert registry.classify("heldout/suite.json") is CoreCategory.HELDOUT_DATA
    (tmp_path / "workspace").mkdir()
    (tmp_path / "workspace" / "suite.json").write_text(json.dumps(SUITE))
    with pytest.raises(EvaluatorError, match="HELDOUT_DATA"):
        DeterministicEvaluator("workspace/suite.json", registry=registry)
    with pytest.raises(TypeError):
        DeterministicEvaluator("heldout/suite.json", registry="x")  # type: ignore[arg-type]
    with pytest.raises(EvaluatorError, match="unreadable"):
        DeterministicEvaluator("heldout/missing.json", registry=registry)


@pytest.mark.parametrize(
    "suite",
    [
        {"version": 2},
        {**SUITE, "suite_id": "bad id"},
        {**SUITE, "pass_threshold": 0},
        {**SUITE, "pass_threshold": True},
        {**SUITE, "cases": []},
        {**SUITE, "cases": [{"case_id": "c1"}]},
        {**SUITE, "cases": [SUITE["cases"][0], SUITE["cases"][0]]},
        {**SUITE, "cases": [{**SUITE["cases"][0], "artifact": "bad name"}]},
        {**SUITE, "cases": [{**SUITE["cases"][0], "require_all": "cite"}]},
        {**SUITE, "cases": [{**SUITE["cases"][0], "require_all": [], "forbid_any": []}]},
        {**SUITE, "cases": [{**SUITE["cases"][0], "require_all": [], "forbid_any": ["x"]}]},
    ],
)
def test_malformed_suites(tmp_path: Path, suite: object) -> None:
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    with pytest.raises(EvaluatorError):
        DeterministicEvaluator(write_suite(tmp_path, suite), registry=registry)


def test_non_json_suite_and_bad_seed(tmp_path: Path) -> None:
    registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    rel = write_suite(tmp_path)
    with pytest.raises(EvaluatorError, match="seed"):
        DeterministicEvaluator(rel, registry=registry, seed=True)
    (tmp_path / rel).write_bytes(b"\xff\xfe")
    with pytest.raises(EvaluatorError, match="JSON"):
        DeterministicEvaluator(rel, registry=registry)


@pytest.mark.parametrize(
    "candidate", [{}, {"bad name": "x"}, {"prompt": 3}, "prompt", {"prompt": "x" * 1_000_001}]
)
def test_bad_candidates(evaluator: DeterministicEvaluator, candidate: Any) -> None:
    with pytest.raises(EvaluatorError):
        evaluator.evaluate(candidate)


class TestService:
    def test_registers_bound_evidence(self, evaluator: DeterministicEvaluator) -> None:
        runs = TrustedRunRegistry()
        service = EvaluatorService(evaluator, SERVICE, runs)
        candidate = {"prompt": "cite", "skill": "retry"}
        result, ref = service.evaluate(candidate)
        assert ref.source is EvidenceSource.EVALUATOR_SERVICE
        assert ref.artifact_digest == result.candidate_digest
        assert runs.validate(ref).valid
        assert service.latest(result.candidate_digest) == (result, ref)
        failing, failing_ref = service.evaluate({"prompt": "x"})
        assert not failing.passed and not runs.validate(failing_ref).valid
        assert service.latest("sha256:" + "0" * 64) is None

    def test_submission_handle_is_score_only(self, evaluator: DeterministicEvaluator) -> None:
        from acgs_lite.control_plane import BudgetLedger, BudgetLimits

        budgets = BudgetLedger()
        budgets.start_run(AGENT, BudgetLimits(iterations=1000))
        service = EvaluatorService(evaluator, SERVICE, TrustedRunRegistry())
        submit = service.submission_handle(AGENT, budgets)
        assert submit({"prompt": "cite", "skill": "retry"}) == 1.0
        assert not isinstance(submit, (DeterministicEvaluator, EvaluatorService))

    def test_oracle_flood_is_bounded(self, evaluator: DeterministicEvaluator) -> None:
        """300 queries: rate-limited, budget-charged, coarse, nothing registered."""
        from acgs_lite.control_plane import BudgetLedger, BudgetLimits
        from acgs_lite.control_plane.evaluator import SubmissionRefused

        runs = TrustedRunRegistry()
        budgets = BudgetLedger()
        budgets.start_run(AGENT, BudgetLimits(iterations=1000))
        now = [0.0]
        submit = EvaluatorService(evaluator, SERVICE, runs).submission_handle(
            AGENT,
            budgets,
            max_per_window=20,
            window_s=60,
            granularity=0.5,
            clock=lambda: now[0],
        )
        accepted = refused = 0
        scores = set()
        for i in range(300):
            now[0] = i * 0.1  # 300 queries in 30 s
            try:
                scores.add(submit({"prompt": f"probe {i} cite", "skill": "retry"}))
                accepted += 1
            except SubmissionRefused:
                refused += 1
        assert accepted == 20 and refused == 280
        assert budgets.state(AGENT).iterations == 20
        assert len(runs) == 0
        assert scores == {1.0}
        assert submit.__name__ == "submit_for_evaluation"
        # Granularity floors: 0.5 of the cases -> 0.5; 0.0 stays 0.0.
        now[0] = 1000.0
        assert submit({"prompt": "cite"}) == 0.5

    def test_submission_budget_and_validation(self, evaluator: DeterministicEvaluator) -> None:
        from acgs_lite.control_plane import BudgetLedger, BudgetLimits
        from acgs_lite.control_plane.evaluator import SubmissionRefused

        service = EvaluatorService(evaluator, SERVICE, TrustedRunRegistry())
        budgets = BudgetLedger()
        submit = service.submission_handle(AGENT, budgets)
        with pytest.raises(SubmissionRefused, match="no budget run"):
            submit({"prompt": "x"})
        budgets.start_run(AGENT, BudgetLimits(iterations=1))
        submit({"prompt": "x"})
        with pytest.raises(SubmissionRefused, match="budget exhausted"):
            submit({"prompt": "x"})
        for kw in (
            {"max_per_window": 0},
            {"window_s": 0},
            {"granularity": 2},
            {"max_per_window": True},
        ):
            with pytest.raises(ValueError):
                service.submission_handle(AGENT, budgets, **kw)
        with pytest.raises(TypeError):
            service.submission_handle("agent", budgets)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            service.submission_handle(AGENT, "b")  # type: ignore[arg-type]

    def test_registration_deduplicated(self, evaluator: DeterministicEvaluator) -> None:
        runs = TrustedRunRegistry()
        service = EvaluatorService(evaluator, SERVICE, runs)
        first = service.evaluate({"prompt": "cite", "skill": "retry"})
        assert service.evaluate({"prompt": "cite", "skill": "retry"}) == first
        assert len(runs) == 1

    def test_service_validation(self, evaluator: DeterministicEvaluator) -> None:
        runs = TrustedRunRegistry()
        with pytest.raises(EvaluatorError, match="SERVICE"):
            EvaluatorService(evaluator, Principal("agent-1", PrincipalKind.AGENT), runs)
        with pytest.raises(TypeError):
            EvaluatorService("e", SERVICE, runs)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            EvaluatorService(evaluator, SERVICE, "runs")  # type: ignore[arg-type]


# -- agents cannot reach the evaluator or its suite (dispatcher) --------------

from acgs_lite.control_plane import ToolDenied  # noqa: E402

AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")


class TestDispatcherIsolation:
    def test_agent_cannot_read_suite_or_write_evaluator(self, p5: Any) -> None:
        write_suite(p5.root)
        with pytest.raises(ToolDenied) as excinfo:
            p5.dispatcher.dispatch(AGENT, "read_file", {"path": "heldout/suite.json"})
        assert "INV-CORE-SENSITIVE-READ" in excinfo.value.decision.determining_policies
        for path in (
            "src/acgs_lite/control_plane/evaluator.py",
            "evaluator/score.py",
            "heldout/suite.json",
        ):
            with pytest.raises(ToolDenied):
                p5.dispatcher.dispatch(
                    AGENT,
                    "write_file",
                    {"path": path, "content": "x"},
                    change_id="c1",
                    requested_by="olivia",
                )
        assert p5.calls == []


def test_fresh_handles_share_the_principal_window(evaluator: DeterministicEvaluator) -> None:
    """R5: five fresh handles for one agent still get 20 submissions in total."""
    from acgs_lite.control_plane import BudgetLedger, BudgetLimits
    from acgs_lite.control_plane.evaluator import SubmissionRefused

    budgets = BudgetLedger()
    budgets.start_run(AGENT, BudgetLimits(iterations=1000))
    service = EvaluatorService(evaluator, SERVICE, TrustedRunRegistry())
    accepted = 0
    for _ in range(5):
        handle = service.submission_handle(AGENT, budgets, max_per_window=20, window_s=3600)
        for _ in range(25):
            try:
                handle({"prompt": "x"})
                accepted += 1
            except SubmissionRefused:
                pass
    assert accepted == 20
    other = Principal("agent-2", PrincipalKind.AGENT, system_id="sys-a")
    budgets.start_run(other, BudgetLimits(iterations=10))
    assert service.submission_handle(other, budgets)({"prompt": "x"}) == 0.0
