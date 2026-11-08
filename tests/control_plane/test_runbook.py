"""Phase 5: machine-readable runbook schema, hash, approval and T1 validation."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.control_plane import DEFAULT_IMMUTABLE_CORE, Principal, PrincipalKind
from acgs_lite.control_plane.immutable_core import CoreCategory
from acgs_lite.control_plane.runbook import (
    Runbook,
    RunbookDenied,
    RunbookRegistry,
    RunbookRejected,
    StopSignals,
    check_runbook_scope,
    is_stale,
    load_runbook_file,
    parse_runbook,
    runbook_hash,
    runbook_json_schema,
)

pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parents[2]
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
REQUIRED_FIELDS = {
    "runbook_id",
    "version",
    "action_tier",
    "scope_selector",
    "max_blast_radius",
    "rate_limit",
    "required_approver_role",
    "rollback_command",
    "success_predicate",
    "stop_conditions",
    "owner",
    "last_tested",
}

RunbookData = Callable[..., dict[str, Any]]


def _check(
    registry: RunbookRegistry, digest: str, *, rb_id: str = "rb-restart-cache", **kw: Any
) -> Runbook:
    args: dict[str, Any] = {
        "tool_name": "write_file",
        "paths": ["workspace/a.txt"],
        "principal": AGENT,
        "blast_radius": 1,
    }
    args.update(kw)
    return registry.check_execution(rb_id, digest, **args)


class TestSchema:
    def test_exact_field_set(self) -> None:
        assert set(Runbook.model_fields) == REQUIRED_FIELDS

    @pytest.mark.parametrize("field", sorted(REQUIRED_FIELDS))
    def test_every_field_required(self, runbook_data: RunbookData, field: str) -> None:
        data = runbook_data()
        del data[field]
        with pytest.raises(RunbookRejected):
            parse_runbook(data)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("version", "1"),
            ("version", 0),
            ("max_blast_radius", 0),
            ("max_blast_radius", True),
            ("rollback_command", "git revert HEAD"),
            ("rollback_command", []),
            ("stop_conditions", []),
            ("stop_conditions", [{"kind": "eval", "code": "True"}]),
            ("success_predicate", {"kind": "python", "expr": "1"}),
            ("rate_limit", {"max_executions": 0, "per_seconds": 60}),
            ("owner", "bad owner"),
            ("last_tested", "not-a-date"),
            ("action_tier", 7),
            ("runbook_id", ""),
        ],
    )
    def test_types_enforced(self, runbook_data: RunbookData, field: str, value: Any) -> None:
        with pytest.raises(RunbookRejected):
            parse_runbook(runbook_data(**{field: value}))

    def test_unknown_field_rejected(self, runbook_data: RunbookData) -> None:
        with pytest.raises(RunbookRejected):
            parse_runbook(runbook_data(shell="rm -rf /"))

    def test_non_mapping_rejected(self) -> None:
        with pytest.raises(RunbookRejected):
            parse_runbook(["not", "a", "mapping"])

    def test_parse_passthrough(self, runbook_data: RunbookData) -> None:
        runbook = parse_runbook(runbook_data())
        assert parse_runbook(runbook) is runbook

    def test_all_predicates_and_stops_parse(self, runbook_data: RunbookData) -> None:
        runbook = parse_runbook(
            runbook_data(
                success_predicate={
                    "kind": "external_run",
                    "provider": "github-actions",
                    "workflow": ".github/workflows/ci.yml",
                },
                stop_conditions=[
                    {"kind": "max_failures", "count": 1},
                    {"kind": "error_rate", "max_rate": 0.5, "min_samples": 2},
                    {"kind": "budget_fraction", "max_fraction": 0.8},
                    {"kind": "breaker_open"},
                ],
            )
        )
        assert len(runbook.stop_conditions) == 4

    def test_json_schema_file_matches(self) -> None:
        checked_in = json.loads((ROOT / "control-plane" / "runbook.schema.json").read_text())
        assert checked_in == runbook_json_schema()
        assert set(checked_in["required"]) == REQUIRED_FIELDS

    def test_hash_is_stable_and_content_bound(self, runbook_data: RunbookData) -> None:
        a = parse_runbook(runbook_data())
        b = parse_runbook(runbook_data())
        assert runbook_hash(a) == runbook_hash(b)
        assert runbook_hash(a).startswith("sha256:")
        assert runbook_hash(parse_runbook(runbook_data(max_blast_radius=4))) != runbook_hash(a)
        with pytest.raises(TypeError):
            runbook_hash(runbook_data())  # type: ignore[arg-type]


class TestScope:
    @pytest.mark.parametrize(
        "glob",
        [
            "**",
            "*",
            "evaluator/**",
            "heldout/x.json",
            "policy/*.yaml",
            "control-plane/**",
            "src/**",
            "../x",
            "/abs/**",
            "audit/receipts.jsonl",
        ],
    )
    def test_scope_touching_core_rejected(self, runbook_data: RunbookData, glob: str) -> None:
        data = runbook_data()
        data["scope_selector"] = {**data["scope_selector"], "paths": [glob]}
        with pytest.raises(RunbookRejected):
            check_runbook_scope(parse_runbook(data), DEFAULT_IMMUTABLE_CORE)

    def test_scope_needs_principal_selector(self, runbook_data: RunbookData) -> None:
        data = runbook_data()
        data["scope_selector"] = {**data["scope_selector"], "principals": [], "system_ids": []}
        with pytest.raises(RunbookRejected, match="principals or system_ids"):
            check_runbook_scope(parse_runbook(data), DEFAULT_IMMUTABLE_CORE)

    def test_workspace_scope_accepted(self, runbook_data: RunbookData) -> None:
        check_runbook_scope(parse_runbook(runbook_data()), DEFAULT_IMMUTABLE_CORE)

    def test_runbook_files_are_policy_core(self) -> None:
        assert (
            DEFAULT_IMMUTABLE_CORE.classify("control-plane/runbooks/restart.json")
            is CoreCategory.POLICY
        )


class TestStaleness:
    def test_stale(self, runbook_data: RunbookData) -> None:
        old = (date.today() - timedelta(days=91)).isoformat()
        assert is_stale(parse_runbook(runbook_data(last_tested=old)), date.today())
        assert not is_stale(parse_runbook(runbook_data()), date.today())
        future = (date.today() + timedelta(days=2)).isoformat()
        assert is_stale(parse_runbook(runbook_data(last_tested=future)), date.today())


class TestApproval:
    def test_agent_cannot_request(self, rb: Any, runbook_data: RunbookData) -> None:
        registry = rb.make()
        with pytest.raises(RunbookRejected, match="HUMAN"):
            registry.approve(AGENT, runbook_data(), approvals=[])

    def test_self_asserted_role_cannot_approve(
        self, rb: Any, runbook_data: RunbookData, approver_factory: Any
    ) -> None:
        """mallory claims ``sre`` in Principal.roles: without a signed approval
        from a registered key whose holder has the sre *capability*, refused."""
        registry = rb.make()
        mallory = Principal("mallory", PrincipalKind.HUMAN, roles=frozenset({"sre"}))
        with pytest.raises(RunbookRejected, match="signed approval"):
            registry.approve(mallory, runbook_data(), approvals=[])
        # Registered key but no capability grant: still refused.
        sign = approver_factory("mallory", roles=frozenset({"sre"}))
        requester = Principal("sam", PrincipalKind.HUMAN)
        digest = registry.approval_hash(requester, runbook_data())
        with pytest.raises(RunbookRejected, match="role 'sre'"):
            registry.approve(requester, runbook_data(), approvals=[sign(digest)])
        assert registry.approved("rb-restart-cache") is None

    def test_owner_cannot_approve(self, rb: Any, runbook_data: RunbookData) -> None:
        with pytest.raises(RunbookRejected):
            rb.approve(rb.make(), runbook_data(owner="rita"))

    def test_approval_bound_to_runbook_hash(self, rb: Any, runbook_data: RunbookData) -> None:
        registry = rb.make()
        requester = Principal("sam", PrincipalKind.HUMAN)
        signed = rb.signer(registry.approval_hash(requester, runbook_data()))
        with pytest.raises(RunbookRejected):
            registry.approve(requester, runbook_data(max_blast_radius=9), approvals=[signed])

    def test_approval_is_receipted_and_verifiable(
        self,
        runbook_data: RunbookData,
        constitution: Any,
        permit_all: Any,
        approval_gate: Any,
        rb: Any,
    ) -> None:
        from acgs_lite.control_plane import (
            InMemoryReceiptStore,
            PolicyDecisionPoint,
            ReceiptLedger,
            TrustedRunRegistry,
            verify_chain,
        )
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        ledger = ReceiptLedger(
            Ed25519ReceiptSigner.from_seed(b"k" * 32, key_id="l"), store=InMemoryReceiptStore()
        )
        with PolicyDecisionPoint.for_constitution(
            constitution, permit_all, approval_gate=approval_gate, receipt_ledger=ledger
        ) as pdp:
            registry = RunbookRegistry(DEFAULT_IMMUTABLE_CORE, pdp=pdp, roles=rb.roles)
            digest = rb.approve(registry, runbook_data())
            (receipt,) = ledger.receipts()
            assert receipt.receipt.action == "runbook.approve"
            assert receipt.receipt.allowed
            result = verify_chain(
                ledger.receipts(),
                trusted_public_keys={ledger.key_id: ledger.public_key_hex},
                run_verifier=TrustedRunRegistry(),
            )
            assert result.valid, result.reasons
            assert registry.approved("rb-restart-cache") == (parse_runbook(runbook_data()), digest)
            # Replaying the consumed approval for a re-approval is refused.

    def test_approve_and_revoke(self, rb: Any, runbook_data: RunbookData, sre: Principal) -> None:
        registry = rb.make()
        digest = rb.approve(registry, runbook_data())
        assert registry.approved("rb-restart-cache") == (parse_runbook(runbook_data()), digest)
        assert registry.revoke(sre, "rb-restart-cache") is True
        assert registry.revoke(sre, "rb-restart-cache") is False
        with pytest.raises(RunbookRejected):
            registry.revoke(AGENT, "x")
        assert registry.approved("rb-restart-cache") is None

    def test_constructor_validation(self, rb: Any, gated_pdp: Any, pdp: Any) -> None:
        with pytest.raises(TypeError):
            RunbookRegistry("core", pdp=gated_pdp, roles=rb.roles)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="ApprovalGate"):
            RunbookRegistry(DEFAULT_IMMUTABLE_CORE, pdp=pdp, roles=rb.roles)
        with pytest.raises(TypeError, match="roles"):
            RunbookRegistry(DEFAULT_IMMUTABLE_CORE, pdp=gated_pdp, roles="r")  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="same immutable-core"):
            RunbookRegistry(
                DEFAULT_IMMUTABLE_CORE.with_repo_root("/x"), pdp=gated_pdp, roles=rb.roles
            )
        with pytest.raises(ValueError):
            rb.make(max_runbook_age_days=-1)
        assert rb.make().registry is DEFAULT_IMMUTABLE_CORE


class TestFiles:
    def _write(self, root: Path, data: dict[str, Any]) -> Path:
        path = root / "control-plane" / "runbooks" / "restart.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_load_requires_policy_path(self, tmp_path: Path, runbook_data: RunbookData) -> None:
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        other = tmp_path / "workspace" / "rb.json"
        other.parent.mkdir(parents=True)
        other.write_text(json.dumps(runbook_data()))
        with pytest.raises(RunbookRejected, match="POLICY"):
            load_runbook_file("workspace/rb.json", registry)

    def test_load_yaml_and_unreadable(self, tmp_path: Path, runbook_data: RunbookData) -> None:
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        path = tmp_path / "control-plane" / "runbooks" / "r.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(runbook_data()))  # JSON is valid YAML
        assert load_runbook_file("control-plane/runbooks/r.yaml", registry).version == 1
        with pytest.raises(RunbookRejected, match="unreadable"):
            load_runbook_file("control-plane/runbooks/missing.json", registry)

    def test_file_tamper_detected(self, tmp_path: Path, runbook_data: RunbookData, rb: Any) -> None:
        registry_core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        path = self._write(tmp_path, runbook_data())
        registry = rb.make(registry_core)
        rel = "control-plane/runbooks/restart.json"
        digest = rb.approve(registry, load_runbook_file(rel, registry_core), source_path=rel)
        assert _check(registry, digest).runbook_id == "rb-restart-cache"
        path.write_text(json.dumps(runbook_data(max_blast_radius=50)))
        with pytest.raises(RunbookDenied, match="changed since approval"):
            _check(registry, digest)
        path.write_text("{not json")
        with pytest.raises(RunbookDenied, match="re-validation"):
            _check(registry, digest)

    def test_source_must_match(self, tmp_path: Path, runbook_data: RunbookData, rb: Any) -> None:
        registry_core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        self._write(tmp_path, runbook_data(max_blast_radius=2))
        with pytest.raises(RunbookRejected, match="source file"):
            rb.approve(
                rb.make(registry_core),
                runbook_data(),
                source_path="control-plane/runbooks/restart.json",
            )


class TestExecution:
    @pytest.fixture()
    def approved(self, runbook_data: RunbookData, rb: Any) -> tuple[RunbookRegistry, str]:
        registry = rb.make(DEFAULT_IMMUTABLE_CORE)
        return registry, rb.approve(registry, runbook_data())

    def test_valid(self, approved: tuple[RunbookRegistry, str]) -> None:
        registry, digest = approved
        assert _check(registry, digest).max_blast_radius == 3

    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"tool_name": "delete_file"}, "tool"),
            ({"paths": ["other/a.txt"]}, "outside the runbook scope"),
            ({"paths": ["workspace/.env"]}, "immutable core"),
            ({"paths": ["../x"]}, "immutable core"),
            ({"principal": Principal("agent-2", PrincipalKind.AGENT)}, "principal"),
            ({"blast_radius": 4}, "blast radius"),
            ({"blast_radius": True}, "int"),
        ],
    )
    def test_scope_misses(
        self, approved: tuple[RunbookRegistry, str], kwargs: dict[str, Any], match: str
    ) -> None:
        registry, digest = approved
        with pytest.raises(RunbookDenied, match=match):
            _check(registry, digest, **kwargs)

    def test_missing_unapproved_and_tampered(self, approved: tuple[RunbookRegistry, str]) -> None:
        registry, digest = approved
        with pytest.raises(RunbookDenied, match="requires runbook_id"):
            registry.check_execution(
                None, None, tool_name="write_file", paths=[], principal=AGENT, blast_radius=1
            )
        with pytest.raises(RunbookDenied, match="not approved"):
            _check(registry, digest, rb_id="rb-other")
        with pytest.raises(RunbookDenied, match="tampered"):
            _check(registry, "sha256:" + "0" * 64)

    def test_system_selector(self, runbook_data: RunbookData, rb: Any) -> None:
        data = runbook_data()
        data["scope_selector"] = {
            **data["scope_selector"],
            "principals": [],
            "system_ids": ["SYS-A"],
        }
        registry = rb.make(DEFAULT_IMMUTABLE_CORE)
        digest = rb.approve(registry, data)
        assert _check(registry, digest)

    def test_non_t1_runbook_denied(self, runbook_data: RunbookData, rb: Any) -> None:
        registry = rb.make(DEFAULT_IMMUTABLE_CORE)
        digest = rb.approve(registry, runbook_data(action_tier=2))
        with pytest.raises(RunbookDenied, match="not a T1"):
            _check(registry, digest)

    def test_stale_denied(self, runbook_data: RunbookData, rb: Any) -> None:
        registry = rb.make(DEFAULT_IMMUTABLE_CORE)
        old = (date.today() - timedelta(days=200)).isoformat()
        digest = rb.approve(registry, runbook_data(last_tested=old))
        with pytest.raises(RunbookDenied, match="stale"):
            _check(registry, digest)

    def test_broken_clocks_deny(self, runbook_data: RunbookData, rb: Any) -> None:
        def boom() -> Any:
            raise RuntimeError("clock")

        registry = rb.make(DEFAULT_IMMUTABLE_CORE, today=boom)
        digest = rb.approve(registry, runbook_data())
        with pytest.raises(RunbookDenied, match="date unavailable"):
            _check(registry, digest)
        registry = rb.make(DEFAULT_IMMUTABLE_CORE, clock=boom)
        digest = rb.approve(registry, runbook_data())
        with pytest.raises(RunbookDenied, match="clock unavailable"):
            _check(registry, digest)

    def test_rate_limit_and_window(self, runbook_data: RunbookData, rb: Any) -> None:
        now = [0.0]
        registry = rb.make(DEFAULT_IMMUTABLE_CORE, clock=lambda: now[0])
        digest = rb.approve(
            registry, runbook_data(rate_limit={"max_executions": 2, "per_seconds": 10})
        )
        _check(registry, digest)
        _check(registry, digest, consume=False)  # dry run spends nothing
        _check(registry, digest)
        with pytest.raises(RunbookDenied, match="rate limit"):
            _check(registry, digest)
        now[0] = 11.0
        _check(registry, digest)

    def test_rate_limit_atomic_under_threads(self, runbook_data: RunbookData, rb: Any) -> None:
        registry = rb.make(DEFAULT_IMMUTABLE_CORE)
        digest = rb.approve(
            registry, runbook_data(rate_limit={"max_executions": 5, "per_seconds": 3600})
        )
        ok: list[int] = []
        barrier = threading.Barrier(32)

        def worker() -> None:
            barrier.wait()
            try:
                _check(registry, digest)
                ok.append(1)
            except RunbookDenied:
                pass

        threads = [threading.Thread(target=worker) for _ in range(32)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(ok) == 5

    def test_stop_conditions(self, runbook_data: RunbookData, rb: Any) -> None:
        registry = rb.make(DEFAULT_IMMUTABLE_CORE)
        digest = rb.approve(
            registry,
            runbook_data(
                stop_conditions=[
                    {"kind": "max_failures", "count": 2},
                    {"kind": "error_rate", "max_rate": 0.5, "min_samples": 4},
                    {"kind": "budget_fraction", "max_fraction": 0.8},
                    {"kind": "breaker_open"},
                ]
            ),
        )
        ok = StopSignals(budget_fraction=0.1)
        _check(registry, digest, signals=ok)
        with pytest.raises(RunbookDenied, match="breaker_open"):
            _check(registry, digest, signals=StopSignals(breaker_open=True, budget_fraction=0.1))
        with pytest.raises(RunbookDenied, match="budget_fraction"):
            _check(registry, digest, signals=StopSignals(budget_fraction=0.9))
        with pytest.raises(RunbookDenied, match="budget unknown"):
            _check(registry, digest, signals=StopSignals())
        registry.record_outcome("rb-restart-cache", success=True)
        registry.record_outcome("rb-restart-cache", success=True)
        registry.record_outcome("rb-restart-cache", success=True)
        registry.record_outcome("rb-restart-cache", success=False)
        registry.record_outcome("unknown", success=False)  # ignored
        _check(registry, digest, signals=ok)
        registry.record_outcome("rb-restart-cache", success=False)
        with pytest.raises(RunbookDenied, match="max_failures"):
            _check(registry, digest, signals=ok)

    def test_error_rate(self, runbook_data: RunbookData, rb: Any) -> None:
        registry = rb.make(DEFAULT_IMMUTABLE_CORE)
        digest = rb.approve(
            registry,
            runbook_data(
                stop_conditions=[{"kind": "error_rate", "max_rate": 0.5, "min_samples": 2}]
            ),
        )
        registry.record_outcome("rb-restart-cache", success=True)
        registry.record_outcome("rb-restart-cache", success=False)
        with pytest.raises(RunbookDenied, match="error_rate"):
            _check(registry, digest)


# -- T1 through the dispatcher -------------------------------------------------

from acgs_lite.control_plane import ActionTier, ToolDenied  # noqa: E402


class TestDispatchT1:
    def _approve(self, p5: Any, runbook_data: RunbookData, **kw: Any) -> str:
        data = runbook_data(**kw)
        data["scope_selector"] = {**data["scope_selector"], "tools": ["write_*", "legacy_*"]}
        return p5.approve_runbook(data)

    def _write(self, p5: Any, digest: str | None, *, path: str = "a.md", **kw: Any) -> Any:
        return p5.dispatcher.dispatch(
            AGENT,
            "write_file",
            {"path": f"{p5.worktree}/{path}", **kw.pop("args", {})},
            change_id="c1",
            runbook_id="rb-restart-cache" if digest is not None else None,
            runbook_hash=digest,
            **kw,
        )

    def test_allowed_and_reviewed(self, p5: Any, runbook_data: RunbookData, rb: Any) -> None:
        digest = self._approve(p5, runbook_data)
        result = self._write(p5, digest)
        assert result.decisions[0].tier is ActionTier.T1
        assert p5.calls == [("write_file", f"{p5.worktree}/a.md")]
        (item,) = p5.review.unresolved()
        assert item.decision_id == result.decisions[0].decision_id
        assert (item.runbook_id, item.runbook_hash) == ("rb-restart-cache", digest)
        assert (
            p5.dispatcher.tier_of_call(
                AGENT,
                "write_file",
                {"path": f"{p5.worktree}/a.md"},
                runbook_id="rb-restart-cache",
                runbook_hash=digest,
            )
            is ActionTier.T1
        )

    def test_no_runbook_denied(self, p5: Any, runbook_data: RunbookData, rb: Any) -> None:
        with pytest.raises(ToolDenied, match="requires runbook_id"):
            p5.dispatcher.dispatch(
                AGENT, "legacy_write", {"path": f"{p5.worktree}/a"}, change_id="c1"
            )
        with pytest.raises(ToolDenied):  # profile tool without runbook -> T2 -> approval
            self._write(p5, None, requested_by="olivia")
        assert p5.calls == [] and p5.review.items() == ()

    def test_legacy_static_t1_with_runbook(
        self, p5: Any, runbook_data: RunbookData, rb: Any
    ) -> None:
        digest = self._approve(p5, runbook_data)
        p5.dispatcher.dispatch(
            AGENT,
            "legacy_write",
            {"path": f"{p5.worktree}/a"},
            change_id="c1",
            runbook_id="rb-restart-cache",
            runbook_hash=digest,
        )
        assert len(p5.review.items()) == 1

    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"runbook_hash": "sha256:" + "1" * 64}, "tampered"),
            ({"runbook_id": "rb-unknown"}, "not approved"),
        ],
    )
    def test_unapproved_or_tampered(
        self, p5: Any, runbook_data: RunbookData, sre: Principal, kwargs: Any, match: str
    ) -> None:
        digest = self._approve(p5, runbook_data)
        call = {"runbook_id": "rb-restart-cache", "runbook_hash": digest, **kwargs}
        with pytest.raises(ToolDenied, match=match):
            p5.dispatcher.dispatch(
                AGENT, "write_file", {"path": f"{p5.worktree}/a"}, change_id="c1", **call
            )
        assert p5.calls == []

    def test_scope_misses(self, p5: Any, runbook_data: RunbookData, rb: Any) -> None:
        data = runbook_data()
        data["scope_selector"] = {**data["scope_selector"], "paths": [f"{p5.worktree}/ok/**"]}
        digest = p5.approve_runbook(data)
        with pytest.raises(ToolDenied, match="outside the runbook scope"):
            self._write(p5, digest, path="other.md")
        other = Principal("agent-2", PrincipalKind.AGENT, system_id="sys-b")
        with pytest.raises(ToolDenied, match="principal"):
            p5.dispatcher.dispatch(
                other,
                "write_file",
                {"path": f"{p5.worktree}/ok/a"},
                runbook_id="rb-restart-cache",
                runbook_hash=digest,
            )
        with pytest.raises(ToolDenied, match="tool"):
            p5.dispatcher.dispatch(
                AGENT,
                "git_commit",
                {"path": f"{p5.worktree}/ok/a", "branch": "agent/agent-1/c1"},
                change_id="c1",
                runbook_id="rb-restart-cache",
                runbook_hash=digest,
            )
        self._write(p5, digest, path="ok/a.md")

    def test_blast_radius_exceeded(self, p5: Any, runbook_data: RunbookData, rb: Any) -> None:
        digest = self._approve(p5, runbook_data)
        paths = [f"{p5.worktree}/{i}.md" for i in range(4)]
        with pytest.raises(ToolDenied, match="blast radius"):
            p5.dispatcher.dispatch(
                AGENT,
                "write_many",
                {"paths": paths},
                change_id="c1",
                runbook_id="rb-restart-cache",
                runbook_hash=digest,
            )
        p5.dispatcher.dispatch(
            AGENT,
            "write_many",
            {"paths": paths[:3]},
            change_id="c1",
            runbook_id="rb-restart-cache",
            runbook_hash=digest,
        )

    def test_rate_limit_and_dry_run(self, p5: Any, runbook_data: RunbookData, rb: Any) -> None:
        digest = self._approve(
            p5, runbook_data, rate_limit={"max_executions": 2, "per_seconds": 3600}
        )
        for _ in range(3):
            p5.dispatcher.authorize_without_consuming(
                AGENT,
                "write_file",
                {"path": f"{p5.worktree}/a"},
                change_id="c1",
                runbook_id="rb-restart-cache",
                runbook_hash=digest,
            )
        self._write(p5, digest)
        self._write(p5, digest)
        with pytest.raises(ToolDenied, match="rate limit"):
            self._write(p5, digest)
        assert len(p5.calls) == 2

    def test_stop_condition_tripped(self, p5: Any, runbook_data: RunbookData, rb: Any) -> None:
        digest = self._approve(
            p5, runbook_data, stop_conditions=[{"kind": "max_failures", "count": 1}]
        )
        with pytest.raises(RuntimeError):
            self._write(p5, digest, args={"content": "boom"})
        assert len(p5.review.items()) == 1  # failed executions are reviewed too
        with pytest.raises(ToolDenied, match="max_failures"):
            self._write(p5, digest)

    def test_stale_runbook_denied(self, p5: Any, runbook_data: RunbookData, rb: Any) -> None:
        old = (date.today() - timedelta(days=120)).isoformat()
        digest = self._approve(p5, runbook_data, last_tested=old)
        with pytest.raises(ToolDenied, match="stale"):
            self._write(p5, digest)

    def test_budget_and_breaker_stops(self, p5: Any) -> None:
        from acgs_lite.control_plane import BudgetLedger, BudgetLimits

        budgets = BudgetLedger()
        assert budgets.used_fraction(AGENT) is None
        budgets.start_run(AGENT, BudgetLimits())
        assert budgets.used_fraction(AGENT) is None
        budgets.start_run(AGENT, BudgetLimits(iterations=4, tokens=0))
        assert budgets.used_fraction(AGENT) == 1.0
        budgets.start_run(AGENT, BudgetLimits(iterations=4))
        budgets.charge(AGENT, iterations=1)
        assert budgets.used_fraction(AGENT) == 0.25
        signals = p5.dispatcher._stop_signals(AGENT, None, None)
        assert signals.breaker_open is False and signals.budget_fraction is None

    def test_runbook_without_registry_denied(self, gated_pdp: Any) -> None:
        from acgs_lite.control_plane import (
            DEFAULT_IMMUTABLE_CORE,
            GovernedToolDispatcher,
            RepositoryPermissions,
        )

        d = GovernedToolDispatcher(
            gated_pdp,
            permissions=RepositoryPermissions(DEFAULT_IMMUTABLE_CORE),
            tool_tiers={"r": ActionTier.T0},
            read_only_tools=frozenset({"r"}),
        )
        d.register("r", lambda path: path, path_params={"path"}, merge_capable=False)
        with pytest.raises(ToolDenied, match="no runbook registry"):
            d.dispatch(AGENT, "r", {"path": "x.txt"}, runbook_id="rb", runbook_hash="h")

    def test_constructor_requires_review_queue(self, gated_pdp: Any, rb: Any) -> None:
        from acgs_lite.control_plane import GovernedToolDispatcher, RepositoryPermissions
        from acgs_lite.control_plane.tier_policy import ReviewQueue

        perms = RepositoryPermissions(DEFAULT_IMMUTABLE_CORE)
        with pytest.raises(ValueError, match="review_queue"):
            GovernedToolDispatcher(
                gated_pdp,
                permissions=perms,
                tool_tiers={},
                runbooks=rb.make(DEFAULT_IMMUTABLE_CORE),
            )
        with pytest.raises(ValueError, match="same immutable-core"):
            GovernedToolDispatcher(
                gated_pdp,
                permissions=perms,
                tool_tiers={},
                review_queue=ReviewQueue(),
                runbooks=rb.make(DEFAULT_IMMUTABLE_CORE.with_repo_root("/x")),
            )
        for kw in (
            {"runbooks": "r"},
            {"review_queue": "q"},
            {"ownership": "o"},
            {"incident_lock": "i"},
            {"run_verifier": "v"},
        ):
            with pytest.raises(TypeError):
                GovernedToolDispatcher(gated_pdp, permissions=perms, tool_tiers={}, **kw)
        with pytest.raises(ValueError):
            GovernedToolDispatcher(
                gated_pdp, permissions=perms, tool_tiers={}, narrow_max_blast_radius=0
            )
