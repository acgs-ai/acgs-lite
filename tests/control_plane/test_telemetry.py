"""Phase 4: oversight telemetry -- events, stores, metrics and wiring.

Every metric is checked against a hand-computed fixture (counts in the
comments). Approval latency is measured through the real dispatcher +
ApprovalGate flow with a fake clock; the error-budget bridge is checked end
to end through the dispatcher.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    DecisionRequest,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    PolicySet,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.approvals import (
    ApprovalAuthority,
    ApprovalGate,
    QuorumPolicy,
    SignedApproval,
)
from acgs_lite.control_plane.autonomy import AutonomyController, AutonomyLevel, ErrorBudget
from acgs_lite.control_plane.evidence import EvidenceSource, ExternalRunRef
from acgs_lite.control_plane.telemetry import (
    DEFAULT_REWORK_WINDOW_S,
    AgentTelemetryRejected,
    ApprovalGranted,
    ApprovalRequested,
    DecisionObserved,
    GroundTruth,
    InMemoryTelemetryStore,
    JSONLTelemetryStore,
    OversightEvent,
    OversightMetrics,
    Rework,
    TelemetryAutonomyBridge,
    TelemetryRecorder,
    TelemetryStoreCorrupted,
    VerificationFailed,
    event_from_dict,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

CI = Principal("ci-bot", PrincipalKind.SERVICE)
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
ALICE = Principal("alice", PrincipalKind.HUMAN)
DAY = 86400.0
REQ = "requester-1"


def h(char: str) -> str:
    return "sha256:" + char * 64


class Clock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _recorder(clock: Clock | None = None) -> tuple[InMemoryTelemetryStore, TelemetryRecorder]:
    store = InMemoryTelemetryStore()
    return store, TelemetryRecorder(store, CI, clock=clock or Clock())


CI_RUN = ExternalRunRef("github", "run-1", EvidenceSource.CI_SYSTEM)


class TestOverrideRate:
    def _fixture(self) -> OversightMetrics:
        store, rec = _recorder()
        rec.record_decision("d1", PrincipalKind.AGENT, True, at=10)
        rec.record_decision("d2", PrincipalKind.AGENT, False, at=20)
        rec.record_decision("d3", PrincipalKind.HUMAN, True, at=30)
        rec.record_decision("d4", PrincipalKind.AGENT, True, at=40)
        rec.record_decision("d5", PrincipalKind.SERVICE, True, at=50)
        rec.record_override("d1", ALICE, "human_overrode_allow", at=11)
        rec.record_override("d1", ALICE, "human_overrode_allow", at=12)  # counted once
        rec.record_override("d3", ALICE, "human_overrode_allow", at=31)
        rec.record_override("dx", ALICE, "human_overrode_deny", at=60)  # never observed
        return OversightMetrics(store)

    def test_all_and_segments(self) -> None:
        metrics = self._fixture()
        everything = metrics.override_rate()
        assert (everything.numerator, everything.denominator) == (2, 5)
        assert everything.value == pytest.approx(0.4)
        assert everything.unmatched == 1
        agent = metrics.override_rate("agent")  # d1,d2,d4; d1 overridden
        assert (agent.numerator, agent.denominator) == (1, 3)
        assert agent.value == pytest.approx(1 / 3)
        human = metrics.override_rate("human")  # d3 overridden
        assert (human.numerator, human.denominator, human.value) == (1, 1, 1.0)

    def test_window(self) -> None:
        rate = self._fixture().override_rate(since=15, until=45)  # d2,d3,d4
        assert (rate.numerator, rate.denominator) == (1, 3)

    def test_zero_denominator_is_none(self) -> None:
        store, _ = _recorder()
        rate = OversightMetrics(store).override_rate("agent")
        assert (rate.numerator, rate.denominator, rate.value) == (0, 0, None)

    def test_bad_segment(self) -> None:
        store, _ = _recorder()
        with pytest.raises(ValueError):
            OversightMetrics(store).override_rate("robots")  # type: ignore[arg-type]

    def test_override_requires_a_human(self) -> None:
        _, rec = _recorder()
        for who in (AGENT, CI):
            with pytest.raises(AgentTelemetryRejected):
                rec.record_override("d1", who, "human_overrode_allow")


class TestApprovalLatency:
    def test_hand_computed(self) -> None:
        store, rec = _recorder()
        rec.record_approval_requested(h("1"), at=0)
        rec.record_approval_granted(h("1"), "bob", at=10)
        rec.record_approval_granted(h("1"), "carol", at=20)  # quorum completes here
        rec.record_approval_requested(h("2"), at=5)
        rec.record_approval_requested(h("2"), at=7)  # first request wins
        rec.record_approval_denied(h("2"), ALICE, at=65)
        rec.record_approval_requested(h("3"), at=100)  # pending
        rec.record_approval_granted(h("4"), "bob", at=1)  # never requested: ignored
        rec.record_approval_requested(h("5"), at=200)
        rec.record_approval_granted(h("5"), "bob", at=150)  # before request: ignored
        latency = OversightMetrics(store).approval_latency()
        # latencies [20, 60] (quorum completion); nearest-rank p50 -> 20, p90/p99 -> 60
        assert latency.count == 2
        assert (latency.p50_s, latency.p90_s, latency.p99_s, latency.max_s) == (20, 60, 60, 60)
        assert latency.pending == 2
        windowed = OversightMetrics(store).approval_latency(since=50)
        assert (windowed.count, windowed.p50_s, windowed.max_s, windowed.pending) == (
            0,
            None,
            None,
            2,
        )

    def test_denial_requires_a_human_approver(self) -> None:
        _, rec = _recorder()
        with pytest.raises(AgentTelemetryRejected):
            rec.record_approval_denied(h("1"), AGENT)

    def test_malformed_hash_rejected(self) -> None:
        _, rec = _recorder()
        with pytest.raises(ValueError):
            rec.record_approval_requested("not-a-hash")


class TestVerifierPrecisionRecall:
    def _fixture(self) -> OversightMetrics:
        store, rec = _recorder()
        truths = {"s1": "fail", "s3": "fail", "s4": "pass", "s6": "fail"}
        for subject, actual in truths.items():
            rec.record_ground_truth(subject, actual, run_ref=CI_RUN, at=1)
        rec.record_ground_truth("s2", "fail", run_ref=CI_RUN, at=1)
        rec.record_ground_truth("s2", "pass", reviewer=ALICE, at=5)  # latest truth wins
        rec.record_verifier_verdict("s1", "v1", "fail", at=2)  # tp
        rec.record_verifier_verdict("s2", "v1", "fail", at=2)  # fp
        rec.record_verifier_verdict("s3", "v1", "pass", at=2)  # fn
        rec.record_verifier_verdict("s4", "v1", "pass", at=2)  # tn
        rec.record_verifier_verdict("s5", "v1", "fail", at=2)  # unlabeled
        rec.record_verifier_verdict("s6", "v1", "pass", at=2)
        rec.record_verifier_verdict("s6", "v1", "fail", at=3)  # latest verdict: tp
        rec.record_verifier_verdict("s1", "v2", "pass", at=2)  # fn for v2
        rec.record_merge("s1", author_kind="agent", author_id="agent-1", at=0)
        rec.record_merge("s2", author_kind="agent", author_id="agent-1", at=0)
        rec.record_merge("s3", author_kind="human", author_id="alice", at=0)
        return OversightMetrics(store)

    def test_single_verifier(self) -> None:
        m = self._fixture().verifier_precision_recall("v1")
        assert (m.tp, m.fp, m.fn, m.tn, m.unlabeled) == (2, 1, 1, 1, 1)
        assert m.precision == pytest.approx(2 / 3)
        assert m.recall == pytest.approx(2 / 3)

    def test_all_verifiers(self) -> None:
        m = self._fixture().verifier_precision_recall()
        assert (m.tp, m.fp, m.fn, m.tn, m.unlabeled) == (2, 1, 2, 1, 1)
        assert m.precision == pytest.approx(2 / 3)
        assert m.recall == pytest.approx(0.5)

    def test_segments_join_merged_author(self) -> None:
        metrics = self._fixture()
        agent = metrics.verifier_precision_recall("v1", segment="agent")  # s1 tp, s2 fp
        assert (agent.tp, agent.fp, agent.precision, agent.recall) == (1, 1, 0.5, 1.0)
        human = metrics.verifier_precision_recall("v1", segment="human")  # s3 fn
        assert (human.fn, human.precision, human.recall) == (1, None, 0.0)

    def test_window_and_empty(self) -> None:
        metrics = self._fixture()
        late = metrics.verifier_precision_recall("v1", since=2.5)  # only s6@3
        assert (late.tp, late.fp, late.fn, late.tn) == (1, 0, 0, 0)
        store, _ = _recorder()
        empty = OversightMetrics(store).verifier_precision_recall()
        assert (empty.precision, empty.recall, empty.unlabeled) == (None, None, 0)
        assert metrics.verifier_ids() == ("v1", "v2")


class TestGroundTruthProvenance:
    def test_agent_log_and_agent_reviewer_rejected(self) -> None:
        _, rec = _recorder()
        agent_run = ExternalRunRef("agent", "log-1", EvidenceSource.AGENT_LOG)
        with pytest.raises(AgentTelemetryRejected):
            rec.record_ground_truth("s1", "pass", run_ref=agent_run)
        with pytest.raises(AgentTelemetryRejected):
            rec.record_ground_truth("s1", "pass", reviewer=AGENT)
        with pytest.raises(AgentTelemetryRejected):
            GroundTruth(
                subject_id="s1",
                actual="pass",  # type: ignore[arg-type]
                source=EvidenceSource.AGENT_LOG,
                reviewer_id="x",
                at=0,
                recorded_by="ci-bot",
                recorder_kind=PrincipalKind.SERVICE,
            )

    def test_missing_or_conflicting_provenance(self) -> None:
        _, rec = _recorder()
        with pytest.raises(ValueError):
            rec.record_ground_truth("s1", "pass")
        with pytest.raises(ValueError):
            rec.record_ground_truth("s1", "pass", run_ref=CI_RUN, reviewer=ALICE)
        common: dict[str, Any] = {
            "subject_id": "s1",
            "actual": "pass",
            "at": 0,
            "recorded_by": "ci-bot",
            "recorder_kind": PrincipalKind.SERVICE,
        }
        with pytest.raises(ValueError):  # external source without a run_ref
            GroundTruth(source=EvidenceSource.CI_SYSTEM, **common)
        with pytest.raises(ValueError):  # human review without a reviewer
            GroundTruth(source=EvidenceSource.HUMAN_REVIEW, **common)
        with pytest.raises(ValueError):  # run_ref source mismatch
            GroundTruth(source=EvidenceSource.EVALUATOR_SERVICE, run_ref=CI_RUN, **common)

    def test_rework_from_agent_log_rejected(self) -> None:
        _, rec = _recorder()
        with pytest.raises(AgentTelemetryRejected):
            rec.record_rework("c1", "revert", source=EvidenceSource.AGENT_LOG)


class TestReworkRate:
    def _fixture(self) -> OversightMetrics:
        clock = Clock(100 * DAY)
        store, rec = _recorder(clock)
        rec.record_merge("c1", author_kind="agent", author_id="agent-1", at=0)
        rec.record_rework("c1", "fixup", source="ci_system", at=3 * DAY)  # within 14d
        rec.record_merge("c2", author_kind="agent", author_id="agent-1", at=10 * DAY)
        rec.record_rework("c2", "revert", source="ci_system", at=30 * DAY)  # 20d later
        rec.record_merge("c3", author_kind="human", author_id="alice", at=20 * DAY)
        rec.record_rework("c3", "revert", source="human_review", at=21 * DAY)
        rec.record_merge("c4", author_kind="human", author_id="alice", at=50 * DAY)
        rec.record_merge("c5", author_kind="agent", author_id="agent-1", at=95 * DAY)
        rec.record_rework("c5", "hotfix", source="ci_system", at=96 * DAY)  # immature
        return OversightMetrics(store, clock=clock)

    def test_default_window_segmented(self) -> None:
        metrics = self._fixture()
        everything = metrics.post_merge_rework_rate()
        assert (everything.numerator, everything.denominator, everything.immature) == (2, 4, 1)
        assert everything.value == pytest.approx(0.5)
        agent = metrics.post_merge_rework_rate(segment="agent")  # c1 yes, c2 no; c5 immature
        assert (agent.numerator, agent.denominator, agent.immature) == (1, 2, 1)
        human = metrics.post_merge_rework_rate(segment="human")  # c3 yes, c4 no
        assert (human.numerator, human.denominator, human.immature) == (1, 2, 0)

    def test_window_is_configurable(self) -> None:
        rate = self._fixture().post_merge_rework_rate(window_s=30 * DAY)
        # c1, c2 (day 30 <= 10+30), c3 reworked; c4 not; c5 immature
        assert (rate.numerator, rate.denominator, rate.immature) == (3, 4, 1)
        windowed = self._fixture().post_merge_rework_rate(since=15 * DAY, until=60 * DAY)
        assert (windowed.numerator, windowed.denominator) == (1, 2)

    def test_only_immature_is_none(self) -> None:
        clock = Clock(DAY)
        store, rec = _recorder(clock)
        rec.record_merge("c1", author_kind="agent", author_id="agent-1", at=0)
        rate = OversightMetrics(store, clock=clock).post_merge_rework_rate()
        assert (rate.denominator, rate.value, rate.immature) == (0, None, 1)
        assert DEFAULT_REWORK_WINDOW_S == 14 * DAY

    @pytest.mark.parametrize("window", [0, -1, float("inf"), True])
    def test_bad_window(self, window: Any) -> None:
        store, _ = _recorder()
        with pytest.raises(ValueError):
            OversightMetrics(store).post_merge_rework_rate(window)


class TestSnapshot:
    def test_snapshot_is_json_serializable(self) -> None:
        clock = Clock(5.0)
        store, rec = _recorder(clock)
        rec.record_decision("d1", PrincipalKind.AGENT, True)
        rec.record_verifier_verdict("s1", "v1", "fail")
        snapshot = OversightMetrics(store, clock=clock).snapshot()
        assert snapshot["generated_at"] == 5.0
        assert set(snapshot) == {
            "generated_at",
            "override_rate",
            "approval_latency",
            "verifier",
            "post_merge_rework",
        }
        assert set(snapshot["override_rate"]) == {"all", "agent", "human"}
        assert snapshot["override_rate"]["agent"]["denominator"] == 1
        assert snapshot["verifier"]["positive_class"] == "fail"
        assert snapshot["verifier"]["by_verifier"]["v1"]["unlabeled"] == 1
        assert set(snapshot["post_merge_rework"]["segments"]) == {"all", "agent", "human"}
        json.dumps(snapshot)


class TestAgentsCannotRecord:
    def test_agent_recorder_refused(self) -> None:
        with pytest.raises(AgentTelemetryRejected):
            TelemetryRecorder(InMemoryTelemetryStore(), AGENT)

    def test_agent_event_refused(self) -> None:
        with pytest.raises(AgentTelemetryRejected):
            DecisionObserved(
                decision_id="d1",
                principal_kind=None,
                allowed=True,
                at=0,
                recorded_by="agent-1",
                recorder_kind=PrincipalKind.AGENT,
            )

    def test_store_rejects_non_events(self) -> None:
        store = InMemoryTelemetryStore()
        with pytest.raises(TypeError):
            store.append("decision")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            TelemetryRecorder("store", CI)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            TelemetryRecorder(store, "ci-bot")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            OversightMetrics("store")  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"at": float("nan")},
            {"at": True},
            {"recorded_by": "<script>"},
            {"event_id": ""},
        ],
    )
    def test_event_fields_validated(self, kwargs: dict[str, Any]) -> None:
        base: dict[str, Any] = {
            "decision_id": "d1",
            "principal_kind": None,
            "allowed": True,
            "at": 0,
            "recorded_by": "ci-bot",
            "recorder_kind": PrincipalKind.SERVICE,
        }
        with pytest.raises(ValueError):
            DecisionObserved(**{**base, **kwargs})

    def test_trigger_event_validation(self) -> None:
        _, rec = _recorder()
        with pytest.raises(ValueError):
            rec.record_rollback("<script>", "c1")
        with pytest.raises(ValueError):
            rec.record_verification_failed("loop-a", "s1", agent=ALICE)
        with pytest.raises(ValueError):
            VerificationFailed(
                trigger_id="loop-a",
                subject_id="s1",
                agent_system_id="sys-a",
                at=0,
                recorded_by="ci-bot",
                recorder_kind=PrincipalKind.SERVICE,
            )


def _every_kind(rec: TelemetryRecorder) -> list[OversightEvent]:
    return [
        rec.record_decision("d1", PrincipalKind.AGENT, True, at=1),
        rec.record_decision("d2", None, False, at=1),
        rec.record_approval_requested(h("a"), at=2),
        rec.record_approval_granted(h("a"), "bob", at=3),
        rec.record_approval_denied(h("b"), ALICE, at=3),
        rec.record_override("d1", ALICE, "human_overrode_allow", at=4),
        rec.record_verifier_verdict("s1", "v1", "fail", at=5),
        rec.record_ground_truth("s1", "fail", run_ref=CI_RUN, at=6),
        rec.record_ground_truth("s2", "pass", reviewer=ALICE, at=6),
        rec.record_merge("c1", author_kind="agent", author_id="agent-1", system_id="sys-a", at=7),
        rec.record_rework("c1", "revert", source="ci_system", at=8),
        rec.record_rollback("loop-a", "c1", agent=AGENT, at=9),
        rec.record_verification_failed("loop-a", "s1", at=10),
    ]


class TestDispatchGrouping:
    def test_m3_override_denominator_is_one_per_dispatch(self, pdp: PolicyDecisionPoint) -> None:
        store, rec = _recorder()
        with PolicyDecisionPoint.for_constitution(
            Constitution.default(),
            PolicySet.from_mapping(
                {
                    "version": 1,
                    "statements": [
                        {"id": "p", "effect": "permit", "actions": ["*"], "resources": ["**"]}
                    ],
                }
            ),
            telemetry=rec,
        ) as point:
            d = GovernedToolDispatcher(
                point,
                permissions=RepositoryPermissions(
                    DEFAULT_IMMUTABLE_CORE,
                    [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))],
                ),
                tool_tiers={"write": ActionTier.T1},
            )

            def write(paths: list[str]) -> str:
                return "ok"

            d.register("write", write, path_params={"paths"}, merge_capable=False)
            result = d.dispatch(AGENT, "write", {"paths": ["workspace/a", "workspace/b"]})
            d.authorize_without_consuming(AGENT, "write", {"paths": ["workspace/c"]})
        decisions = [e for e in store.read_all() if isinstance(e, DecisionObserved)]
        assert len(decisions) == 3  # tool.call + 2 paths; the dry run records nothing
        assert {e.group_id for e in decisions} == {result.decisions[0].decision_id}
        rec.record_override(result.decisions[2].decision_id, ALICE, "human_overrode_allow")
        rate = OversightMetrics(store).override_rate("agent")
        assert (rate.numerator, rate.denominator, rate.unmatched) == (1, 1, 0)


class TestJSONLStore:
    def test_l3_torn_tail_is_quarantined_and_truncated(self, tmp_path: Path) -> None:
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        store = JSONLTelemetryStore("audit/t.jsonl", registry=core)
        rec = TelemetryRecorder(store, CI)
        first = rec.record_rollback("t", "c1")
        with open(store.path, "a", encoding="utf-8") as handle:
            handle.write('{"kind":"rollback","at":1')  # writer crashed mid-append
        assert store.read_all() == (first,)  # live readers skip the torn tail
        reopened = JSONLTelemetryStore("audit/t.jsonl", registry=core)
        assert reopened.torn_tails == 1
        assert reopened.read_all() == (first,)
        quarantined = list((tmp_path / "audit").glob("t.jsonl.torn-*"))
        assert [q.read_text() for q in quarantined] == ['{"kind":"rollback","at":1']
        assert core.classify("audit/" + quarantined[0].name).value == "audit_log"
        # A torn tail appearing under a live store is healed before the append.
        with open(store.path, "a", encoding="utf-8") as handle:
            handle.write('{"kind":')
        second = rec.record_rollback("t", "c2")
        assert store.torn_tails == 1
        assert JSONLTelemetryStore("audit/t.jsonl", registry=core).read_all() == (first, second)
        assert store.path.read_bytes().endswith(b"\n")

    def test_round_trip_reopen(self, tmp_path: Path) -> None:
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        store = JSONLTelemetryStore("audit/telemetry.jsonl", registry=core)
        written = _every_kind(TelemetryRecorder(store, CI))
        assert store.path == tmp_path / "audit" / "telemetry.jsonl"
        assert store.read_all() == tuple(written)
        reopened = JSONLTelemetryStore("audit/telemetry.jsonl", registry=core)
        assert reopened.read_all() == tuple(written)
        assert isinstance(reopened.read_all()[3], ApprovalGranted)

    def test_refuses_non_core_path(self, tmp_path: Path) -> None:
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        for bad in ("workspace/telemetry.jsonl", "scratch/t.jsonl"):
            with pytest.raises(PermissionError):
                JSONLTelemetryStore(bad, registry=core)

    @pytest.mark.parametrize(
        "line",
        [
            "not json",
            json.dumps({"kind": "nope"}),
            json.dumps({"kind": "decision", "extra": 1}),
            json.dumps({"kind": "decision", "at": 0}),
            json.dumps(
                {
                    "kind": "decision",
                    "decision_id": "d1",
                    "principal_kind": None,
                    "allowed": True,
                    "at": 0,
                    "recorded_by": "agent-1",
                    "recorder_kind": "agent",
                }
            ),
        ],
    )
    def test_corrupt_line_fails_open(self, tmp_path: Path, line: str) -> None:
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        target = tmp_path / "audit" / "t.jsonl"
        target.parent.mkdir(parents=True)
        target.write_text(line + "\n\n", encoding="utf-8")
        with pytest.raises(TelemetryStoreCorrupted):
            JSONLTelemetryStore("audit/t.jsonl", registry=core)

    def test_event_from_dict_rejects_non_mapping(self) -> None:
        with pytest.raises(ValueError):
            event_from_dict(["decision"])


class TestListeners:
    def test_listener_failure_is_counted_not_raised(self) -> None:
        store = InMemoryTelemetryStore()
        seen: list[OversightEvent] = []

        def broken(event: OversightEvent) -> None:
            raise RuntimeError("boom")

        store.subscribe(broken)
        store.subscribe(seen.append)
        TelemetryRecorder(store, CI).record_decision("d1", None, True)
        assert len(seen) == 1
        assert store.listener_failures == 1
        with pytest.raises(TypeError):
            store.subscribe("nope")  # type: ignore[arg-type]


class _FailingStore(InMemoryTelemetryStore):
    def append(self, event: OversightEvent) -> None:
        raise OSError("disk full")


def _allow() -> DecisionRequest:
    return DecisionRequest(ALICE, "file.read", "README.md", ActionTier.T0)


def _deny() -> DecisionRequest:
    return DecisionRequest(AGENT, "file.write", "evaluator/score.py", ActionTier.T1)


class TestPdpTelemetry:
    def _pdp(
        self, constitution: Constitution, permit_all: PolicySet, recorder: TelemetryRecorder
    ) -> PolicyDecisionPoint:
        return PolicyDecisionPoint.for_constitution(constitution, permit_all, telemetry=recorder)

    def test_decision_recorded_per_decision(
        self, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        store, rec = _recorder()
        with self._pdp(constitution, permit_all, rec) as pdp:
            allowed = pdp.decide(_allow())
            denied = pdp.decide(_deny())
            pre = pdp.record_denial("pre-check", principal_id="agent-1")
            assert pdp.telemetry_failures == 0
        assert allowed.allowed and not denied.allowed
        events = [e for e in store.read_all() if isinstance(e, DecisionObserved)]
        assert [(e.decision_id, e.principal_kind, e.allowed) for e in events] == [
            (allowed.decision_id, PrincipalKind.HUMAN, True),
            (denied.decision_id, PrincipalKind.AGENT, False),
            (pre.decision_id, None, False),
        ]

    def test_store_failure_changes_no_decision(
        self, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        rec = TelemetryRecorder(_FailingStore(), CI)
        with self._pdp(constitution, permit_all, rec) as pdp:
            assert pdp.decide(_allow()).allowed is True
            assert pdp.decide(_deny()).allowed is False
            assert pdp.telemetry_failures == 2

    def test_telemetry_type_checked(
        self, constitution: Constitution, permit_all: PolicySet
    ) -> None:
        with pytest.raises(ValueError):
            PolicyDecisionPoint.for_constitution(
                constitution,
                permit_all,
                telemetry=InMemoryTelemetryStore(),  # type: ignore[arg-type]
            )


Sign = Callable[..., SignedApproval]


class Calls:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def tool(self, path: str, content: str = "") -> str:
        self.paths.append(path)
        return "ok"


@pytest.fixture()
def latency_setup(
    constitution: Constitution,
    permit_all: PolicySet,
    approval_authority: ApprovalAuthority,
    approver_factory: Callable[..., Sign],
) -> Iterator[tuple[GovernedToolDispatcher, Clock, InMemoryTelemetryStore, Sign, ApprovalGate]]:
    pytest.importorskip("cryptography")
    clock = Clock(1000.0)
    store, rec = _recorder(clock)
    gate = ApprovalGate(approval_authority, clock=clock, telemetry=rec)
    with PolicyDecisionPoint.for_constitution(
        constitution, permit_all, approval_gate=gate, telemetry=rec
    ) as pdp:
        permissions = RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE, [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))]
        )
        d = GovernedToolDispatcher(pdp, permissions=permissions, tool_tiers={"edit": ActionTier.T2})
        d.register(
            "edit",
            Calls().tool,
            path_params={"path"},
            opaque_params={"content"},
            merge_capable=False,
        )
        yield d, clock, store, approver_factory("bob"), gate


class TestApprovalLatencyThroughDispatcher:
    def test_requested_then_granted(
        self,
        latency_setup: tuple[
            GovernedToolDispatcher, Clock, InMemoryTelemetryStore, Sign, ApprovalGate
        ],
    ) -> None:
        d, clock, store, bob, gate = latency_setup
        args = {"path": "workspace/a", "content": "v1"}
        action = d.action_hash_for(AGENT, "edit", args, requested_by=REQ)  # requested @1000
        with pytest.raises(ToolDenied):  # no approval yet: still one REQUESTED (deduped)
            d.dispatch(AGENT, "edit", args, requested_by=REQ)
        clock.now = 1090.0
        d.dispatch(AGENT, "edit", args, requested_by=REQ, approvals=[bob(action, now=clock.now)])
        d.action_hash_for(AGENT, "edit", {"path": "workspace/b"}, requested_by=REQ)  # pending
        latency = OversightMetrics(store, clock=clock).approval_latency()
        assert (latency.count, latency.p50_s, latency.max_s, latency.pending) == (1, 90, 90, 1)
        granted = [e for e in store.read_all() if isinstance(e, ApprovalGranted)]
        assert [(e.action_hash, e.approver_id, e.at) for e in granted] == [(action, "bob", 1090)]
        assert gate.telemetry_failures == 0
        requested = [e for e in store.read_all() if isinstance(e, ApprovalRequested)]
        assert requested and all(e.principal_kind is PrincipalKind.AGENT for e in requested)
        metrics = OversightMetrics(store, clock=clock)
        assert metrics.approval_latency("agent") == latency
        assert metrics.approval_latency("human").count == 0
        decisions = [e for e in store.read_all() if isinstance(e, DecisionObserved)]
        assert decisions and all(e.principal_kind is PrincipalKind.AGENT for e in decisions)

    def test_m2_agent_sitting_on_an_approval_does_not_inflate_latency(
        self,
        latency_setup: tuple[
            GovernedToolDispatcher, Clock, InMemoryTelemetryStore, Sign, ApprovalGate
        ],
    ) -> None:
        d, clock, store, bob, _ = latency_setup
        args = {"path": "workspace/a", "content": "v1"}
        action = d.action_hash_for(AGENT, "edit", args, requested_by=REQ)  # @1000
        clock.now = 1010.0
        approval = bob(action, now=clock.now)  # human signs after 10 s
        clock.now = 1300.0  # agent holds the approval for 290 s
        d.dispatch(AGENT, "edit", args, requested_by=REQ, approvals=[approval])
        latency = OversightMetrics(store, clock=clock).approval_latency()
        assert (latency.count, latency.p50_s, latency.pre_approved) == (1, 10, 0)

    def test_m2_pre_collected_approval_counts_as_pre_approved(
        self,
        latency_setup: tuple[
            GovernedToolDispatcher, Clock, InMemoryTelemetryStore, Sign, ApprovalGate
        ],
    ) -> None:
        d, clock, store, bob, _ = latency_setup
        args = {"path": "workspace/z", "content": "v"}
        # Hash computed out of band (not via action_hash_for): the gate first
        # sees it on dispatch, already satisfied.
        from acgs_lite.control_plane.action_hash import action_hash, arguments_digest

        request = DecisionRequest(
            AGENT,
            "tool.call",
            "edit",
            ActionTier.T2,
            attributes={
                "paths": ["workspace/z"],
                "tool_read_only": False,
                "arguments_digest": arguments_digest(args),
                "requested_by": REQ,
            },
        )
        approval = bob(action_hash(request), now=clock.now - 50)
        d.dispatch(AGENT, "edit", args, requested_by=REQ, approvals=[approval])
        requested = [e for e in store.read_all() if isinstance(e, ApprovalRequested)]
        assert len(requested) == 1  # recorded although satisfied on first evaluate
        latency = OversightMetrics(store, clock=clock).approval_latency()
        assert (latency.count, latency.pre_approved, latency.pending) == (0, 1, 0)

    def test_m3_dry_runs_record_no_telemetry(
        self,
        latency_setup: tuple[
            GovernedToolDispatcher, Clock, InMemoryTelemetryStore, Sign, ApprovalGate
        ],
    ) -> None:
        d, _, store, _, _ = latency_setup
        for i in range(20):
            with pytest.raises(ToolDenied):  # unsatisfied quorum
                d.authorize_without_consuming(
                    AGENT, "edit", {"path": f"workspace/s{i}", "content": ""}, requested_by=REQ
                )
        with pytest.raises(ToolDenied):  # pre-denial (unknown tool) in a dry run
            d.authorize_without_consuming(AGENT, "nope", {}, requested_by=REQ)
        assert store.read_all() == ()

    def test_gate_telemetry_failure_does_not_block(
        self,
        approval_authority: ApprovalAuthority,
        approver_factory: Callable[..., Sign],
        constitution: Constitution,
        permit_all: PolicySet,
    ) -> None:
        pytest.importorskip("cryptography")
        clock = Clock(1000.0)
        gate = ApprovalGate(
            approval_authority, clock=clock, telemetry=TelemetryRecorder(_FailingStore(), CI)
        )
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, approval_gate=gate
        ) as pdp:
            permissions = RepositoryPermissions(
                DEFAULT_IMMUTABLE_CORE,
                [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))],
            )
            d = GovernedToolDispatcher(
                pdp, permissions=permissions, tool_tiers={"edit": ActionTier.T2}
            )
            calls = Calls()
            d.register(
                "edit",
                calls.tool,
                path_params={"path"},
                opaque_params={"content"},
                merge_capable=False,
            )
            args = {"path": "workspace/a", "content": "v1"}
            action = d.action_hash_for(AGENT, "edit", args, requested_by=REQ)
            bob = approver_factory("bob")
            d.dispatch(AGENT, "edit", args, requested_by=REQ, approvals=[bob(action, now=1000)])
        assert calls.paths == ["workspace/a"]
        assert gate.telemetry_failures == 2  # requested + granted

    def test_l3_eviction_keeps_pending_requests(
        self,
        latency_setup: tuple[
            GovernedToolDispatcher, Clock, InMemoryTelemetryStore, Sign, ApprovalGate
        ],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from acgs_lite.control_plane import approvals as approvals_module

        monkeypatch.setattr(approvals_module, "_MAX_REQUESTED_TRACKED", 2)
        d, clock, store, bob, gate = latency_setup
        pending_args = {"path": "workspace/p", "content": "v"}
        pending = d.action_hash_for(AGENT, "edit", pending_args, requested_by=REQ)  # @1000
        clock.now = 1001.0
        done_args = {"path": "workspace/d", "content": "v"}
        done = d.action_hash_for(AGENT, "edit", done_args, requested_by=REQ)
        d.dispatch(AGENT, "edit", done_args, requested_by=REQ, approvals=[bob(done, now=1001)])
        clock.now = 1002.0
        d.action_hash_for(AGENT, "edit", {"path": "workspace/n", "content": "v"}, requested_by=REQ)
        # The resolved hash was evicted, not the older pending one.
        clock.now = 1100.0
        d.dispatch(
            AGENT, "edit", pending_args, requested_by=REQ, approvals=[bob(pending, now=1100)]
        )
        requested = [e for e in store.read_all() if isinstance(e, ApprovalRequested)]
        assert len(requested) == 3  # the pending hash was not re-recorded
        latency = OversightMetrics(store, clock=clock).approval_latency()
        assert (latency.max_s, latency.pending) == (100, 1)
        assert gate.telemetry_failures == 0

    def test_gate_telemetry_type_checked(self, approval_authority: ApprovalAuthority) -> None:
        with pytest.raises(TypeError):
            ApprovalGate(approval_authority, telemetry=object())  # type: ignore[arg-type]


def _autonomy_dispatcher(
    pdp: PolicyDecisionPoint, autonomy: AutonomyController
) -> tuple[GovernedToolDispatcher, list[str]]:
    calls: list[str] = []
    d = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            DEFAULT_IMMUTABLE_CORE, [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))]
        ),
        tool_tiers={"read": ActionTier.T0, "write": ActionTier.T1},
        read_only_tools=frozenset({"read"}),
        autonomy=autonomy,
    )

    def read(path: str) -> str:
        calls.append("read:" + path)
        return "data"

    def write(path: str) -> str:
        calls.append("write:" + path)
        return "ok"

    d.register("read", read, path_params={"path"}, merge_capable=False)
    d.register("write", write, path_params={"path"}, merge_capable=False)
    return d, calls


class TestErrorBudgetBridge:
    def test_verification_failures_demote_end_to_end(self, pdp: PolicyDecisionPoint) -> None:
        clock = Clock()
        autonomy = AutonomyController(ErrorBudget(window_s=3600, max_failures=3), clock=clock)
        store, rec = _recorder(clock)
        TelemetryAutonomyBridge(autonomy).attach(store)
        d, calls = _autonomy_dispatcher(pdp, autonomy)
        d.dispatch(AGENT, "write", {"path": "workspace/a"})
        rec.record_verification_failed("loop-a", "s1", agent=AGENT)
        rec.record_verification_failed("loop-a", "s2")  # unattributed: ignored
        rec.record_verification_failed("loop-a", "s3", agent=AGENT)
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED
        rec.record_verification_failed("loop-a", "s4", agent=AGENT)
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY
        with pytest.raises(ToolDenied, match="P0_ONLY"):
            d.dispatch(AGENT, "write", {"path": "workspace/b"})
        d.dispatch(AGENT, "read", {"path": "workspace/b"})
        assert calls == ["write:workspace/a", "read:workspace/b"]

    def test_rollbacks_demote(self) -> None:
        autonomy = AutonomyController(ErrorBudget(max_rollbacks=2))
        store, rec = _recorder()
        TelemetryAutonomyBridge(autonomy).attach(store)
        rec.record_rollback("loop-a", "c1", agent=AGENT)
        assert autonomy.level(AGENT) is AutonomyLevel.T1_PREAUTHORIZED
        rec.record_merge("c2", author_kind="agent", author_id="agent-1")  # ignored kind
        rec.record_rollback("loop-a", "c2", agent=AGENT)
        assert autonomy.level(AGENT) is AutonomyLevel.P0_ONLY

    def test_bridge_type_checked(self) -> None:
        with pytest.raises(TypeError):
            TelemetryAutonomyBridge(object())  # type: ignore[arg-type]


def test_rework_event_kind_attribute() -> None:
    rework = Rework(
        change_id="c1",
        rework_kind="revert",  # type: ignore[arg-type]
        source="ci_system",  # type: ignore[arg-type]
        at=1,
        recorded_by="ci-bot",
        recorder_kind="service",  # type: ignore[arg-type]
    )
    assert rework.to_dict()["kind"] == "rework"
    assert event_from_dict(rework.to_dict()) == rework


@pytest.mark.parametrize("verifiers", [1, 12])
def test_snapshot_reads_one_immutable_jsonl_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verifiers: int
) -> None:
    core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    store = JSONLTelemetryStore("audit/snapshot.jsonl", registry=core)
    rec = TelemetryRecorder(store, CI, clock=Clock(100))
    rec.record_merge("s1", author_kind="agent", author_id="agent-1", at=0)
    rec.record_ground_truth("s1", "fail", run_ref=CI_RUN, at=1)
    for i in range(verifiers):
        rec.record_verifier_verdict("s1", f"v{i}", "fail", at=2)
    reads = 0
    read = store.read_all

    def counted_read() -> tuple[OversightEvent, ...]:
        nonlocal reads
        reads += 1
        batch = read()
        # Concurrently arriving data must not split a snapshot across versions.
        rec.record_verifier_verdict("s1", "late", "pass", at=3)
        return batch

    monkeypatch.setattr(store, "read_all", counted_read)
    snapshot = OversightMetrics(store, clock=Clock(100)).snapshot()
    assert reads == 1
    assert len(snapshot["verifier"]["by_verifier"]) == verifiers
    assert snapshot["verifier"]["segments"]["all"]["tp"] == verifiers
    assert snapshot["verifier"]["segments"]["agent"]["tp"] == verifiers
    assert snapshot["verifier"]["segments"]["human"]["tp"] == 0


def test_approval_latency_segments_follow_requester_and_roundtrip() -> None:
    store, rec = _recorder()
    for char, kind, start, end in (
        ("1", PrincipalKind.AGENT, 0, 10),
        ("2", PrincipalKind.HUMAN, 20, 50),
        ("3", PrincipalKind.SERVICE, 60, 100),
        ("4", None, 100, 150),
    ):
        event = rec.record_approval_requested(h(char), principal_kind=kind, at=start)
        assert event_from_dict(event.to_dict()) == event
        rec.record_approval_granted(h(char), "bob", at=end)
    # A later duplicate must not relabel the original request.
    rec.record_approval_requested(h("1"), principal_kind=PrincipalKind.HUMAN, at=1)
    rec.record_approval_requested(h("5"), principal_kind=PrincipalKind.AGENT, at=200)
    metrics = OversightMetrics(store)
    assert metrics.approval_latency().count == 4
    assert metrics.approval_latency("agent").p50_s == 10
    assert metrics.approval_latency("agent").pending == 1
    assert metrics.approval_latency("human").p50_s == 30
    assert metrics.approval_latency("agent", since=20).count == 0
    assert metrics.snapshot()["approval_latency"]["human"]["p50_s"] == 30
    with pytest.raises(ValueError, match="segment"):
        metrics.approval_latency("robot")
    # Old persisted requests without attribution remain in the combined metric.
    old = rec.record_approval_requested(h("6")).to_dict()
    old.pop("principal_kind")
    assert event_from_dict(old).principal_kind is None


@pytest.mark.parametrize(
    ("tier", "required", "roles", "expected"),
    [
        (ActionTier.T2, 1, frozenset(), 10),
        (ActionTier.T3, 2, frozenset(), 20),
        (ActionTier.T3, 2, frozenset({"ops"}), 90),
    ],
)
def test_latency_uses_earliest_role_satisfying_quorum(
    approval_authority: ApprovalAuthority,
    approver_factory: Callable[..., Sign],
    tier: ActionTier,
    required: int,
    roles: frozenset[str],
    expected: int,
) -> None:
    clock = Clock(1000)
    store, rec = _recorder(clock)
    gate = ApprovalGate(
        approval_authority,
        policies={tier: QuorumPolicy(required, required_roles=roles)},
        clock=clock,
        telemetry=rec,
    )
    request = DecisionRequest(AGENT, "tool.call", "deploy", tier, attributes={"requested_by": REQ})
    pending = gate.evaluate(request, [])
    signers = [
        approver_factory("bob"),
        approver_factory("carol"),
        approver_factory("dora", roles=frozenset({"ops"})),
        approver_factory("eric"),
    ]
    approvals = [
        sign(pending.action_hash, now=at)
        for sign, at in zip(signers, [1010, 1020, 1090, 1095], strict=True)
    ]
    clock.now = 1100
    result = gate.evaluate(request, reversed(approvals))
    assert result.satisfied
    assert len(result.counted_approvals) == 4  # authorization semantics unchanged
    assert gate.consume(result)
    assert all(gate.is_consumed(approval) for approval in approvals)
    metrics = OversightMetrics(store, clock=clock)
    assert metrics.approval_latency("agent").max_s == expected
    assert metrics.approval_latency("human").count == 0
