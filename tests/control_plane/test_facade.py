"""Phase 5: the facade wires every layer; a missing layer is a construction error."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from acgs_lite.constitution import Constitution  # noqa: E402
from acgs_lite.control_plane import (  # noqa: E402
    BreakerPolicy,
    BudgetLimits,
    ControlPlaneConfig,
    ControlPlaneConfigError,
    ErrorBudget,
    GovernedToolDispatcher,
    Principal,
    PrincipalKind,
    ReplayVerifier,
    ToolDenied,
    WriteGrant,
    build_control_plane,
)
from acgs_lite.control_plane.demo_loop import (  # noqa: E402
    POLICY_PATH,
    SUITE_PATH,
    _write_layout,
)
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = [pytest.mark.unit]

AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")


def _config(root: Path, **overrides: Any) -> ControlPlaneConfig:
    _write_layout(root)
    base: dict[str, Any] = {
        "repo_root": str(root),
        "system_id": "sys-a",
        "constitution": Constitution.default(),
        "policy_path": POLICY_PATH,
        "heldout_suite_path": SUITE_PATH,
        "admin": Principal("root-admin", PrincipalKind.HUMAN),
        "harness": Principal("harness", PrincipalKind.SERVICE),
        "ledger_signer": Ed25519ReceiptSigner.from_seed(b"l" * 32, key_id="ledger"),
        "run_registry_signer": Ed25519ReceiptSigner.from_seed(b"r" * 32, key_id="runs"),
        "verifier_factory": lambda runs: ReplayVerifier(runs),
        "proposer_model_family": "claude-5",
        "proposer_vendor": "anthropic",
        "write_grants": (WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",)),),
        "budget_limits": BudgetLimits(iterations=100),
        "error_budget": ErrorBudget(),
        "breaker_policy": BreakerPolicy(),
    }
    base.update(overrides)
    return ControlPlaneConfig(**base)


def test_builds_every_layer(tmp_path: Path) -> None:
    cp = build_control_plane(_config(tmp_path))
    try:
        assert isinstance(cp.dispatcher, GovernedToolDispatcher)
        assert cp.pdp.receipt_ledger is cp.ledger
        assert cp.pdp.approval_gate is cp.gate and cp.pdp.kill_switch is cp.kill_switch
        assert cp.registry.repo_root == str(tmp_path)
        for name in (
            "runbooks",
            "review_queue",
            "ownership",
            "incident_lock",
            "breaker",
            "budgets",
            "autonomy",
            "credentials",
            "evaluator_service",
            "promotion",
        ):
            assert getattr(cp, name) is not None
        assert (tmp_path / "control-plane" / "halt").is_dir()
        assert (tmp_path / "control-plane" / "incident").is_dir()
        cp.start_agent_run(AGENT)
        cp.dispatcher.register("noop", lambda path: path, path_params={"path"}, merge_capable=False)
        # Credentials are mandatory: an agent call without a token is denied.
        with pytest.raises(ToolDenied, match="credential"):
            cp.dispatcher.dispatch(AGENT, "noop", {"path": "workspace/x"})
        snapshot = cp.telemetry_snapshot()
        assert snapshot["post_hoc_review"] == {"total": 0, "unresolved": 0, "overdue": 0}
        assert "override_rate" in snapshot
        assert cp.verify_receipts().valid
        assert len(cp.ledger.receipts()) >= 1
    finally:
        cp.close()


@pytest.mark.parametrize(
    "workflow,valid,expected",
    [
        ("ci.yml", True, True),
        ("other.yml", True, False),
        ("ci.yml", False, False),
    ],
)
def test_configured_workflow_verifier_reaches_runbook_predicate(
    tmp_path: Path, workflow: str, valid: bool, expected: bool
) -> None:
    from acgs_lite.control_plane.evidence import ExternalRunRef, RunValidation
    from acgs_lite.control_plane.runbook import ExternalRunPredicate, predicate_satisfied

    class WorkflowVerifier:
        verifier_id = "trusted-workflow-verifier"
        attests_artifact_digest = False

        def validate(self, ref: ExternalRunRef) -> RunValidation:
            return RunValidation(
                valid, "independently checked", self.verifier_id, workflow=workflow
            )

    verifier = WorkflowVerifier()
    cp = build_control_plane(_config(tmp_path, run_verifier=verifier))
    try:
        predicate = ExternalRunPredicate(
            kind="external_run", provider="github-actions", workflow="ci.yml"
        )
        ref = ExternalRunRef(provider="github-actions", run_id="123", source="ci_system")
        assert predicate_satisfied(predicate, ref, cp.dispatcher._run_verifier) is expected
        assert cp.dispatcher._run_verifier is verifier
        assert cp.dispatcher._backup_consumption is cp.runs
        assert cp.runs.supports_durable_backup_consumption
    finally:
        cp.close()


def test_invalid_configured_run_verifier_rejected(tmp_path: Path) -> None:
    with pytest.raises(ControlPlaneConfigError, match="run_verifier"):
        build_control_plane(_config(tmp_path, run_verifier=object()))


@pytest.mark.parametrize("workflow", ["ci.yml", "wrong.yml"])
def test_dispatch_external_run_outcome_controls_runbook_stop(tmp_path: Path, workflow: str) -> None:
    from datetime import datetime, timezone

    from acgs_lite.control_plane.approvals import SignedApproval
    from acgs_lite.control_plane.demo_loop import _runbook
    from acgs_lite.control_plane.evidence import ExternalRunRef, RunValidation
    from acgs_lite.control_plane.tier_policy import ActionProfile

    class WorkflowVerifier:
        verifier_id = "trusted-ci"
        attests_artifact_digest = False

        def validate(self, ref: ExternalRunRef) -> RunValidation:
            return RunValidation(True, "checked CI", self.verifier_id, workflow=workflow)

    cp = build_control_plane(_config(tmp_path, run_verifier=WorkflowVerifier()))
    try:
        requester = Principal("requester", PrincipalKind.HUMAN)
        approver = Principal("approver", PrincipalKind.HUMAN)
        signer = Ed25519ReceiptSigner.from_seed(b"a" * 32, key_id="approver")
        cp.authority.register_approver(
            cp.config.admin, approver, signer.public_key_hex(), key_id="approver"
        )
        cp.roles.grant_capability(cp.config.admin, "sre", approver)
        book = _runbook(datetime.now(timezone.utc).date().isoformat())
        book["owner"] = requester.id
        book["scope_selector"]["principals"] = [AGENT.id]
        book["scope_selector"]["paths"] = ["workspace/test/**"]
        book["success_predicate"] = {
            "kind": "external_run",
            "provider": "github-actions",
            "workflow": "ci.yml",
        }
        book["stop_conditions"] = [{"kind": "max_failures", "count": 1}]
        approval = SignedApproval.create(
            signer, approver=approver, action_hash=cp.runbooks.approval_hash(requester, book)
        )
        digest = cp.runbooks.approve(requester, book, approvals=[approval])
        cp.ownership.assign(cp.config.admin, "change-1", AGENT, "workspace/test")
        cp.triggers.bind(cp.config.admin, "loop", principals=[AGENT])
        cp.start_agent_run(AGENT)
        calls: list[str] = []
        ref = ExternalRunRef("github-actions", "123", "ci_system")

        def write_file(path: str) -> ExternalRunRef:
            calls.append(path)
            return ref

        def profile(arguments: Any) -> ActionProfile:
            return ActionProfile(
                reversible=True, data_destroying=False, blast_radius=1, novel=False
            )

        cp.dispatcher.register(
            "write_file", write_file, path_params={"path"}, profile=profile, merge_capable=False
        )
        token = cp.credentials.issue(AGENT, scopes={"tool:write_file"}).token
        kwargs = dict(
            credential=token,
            trigger_id="loop",
            change_id="change-1",
            runbook_id=book["runbook_id"],
            runbook_hash=digest,
        )
        cp.dispatcher.dispatch(
            AGENT, "write_file", {"path": "workspace/test/prompts/x.md"}, **kwargs
        )
        if workflow == "ci.yml":
            cp.dispatcher.dispatch(
                AGENT, "write_file", {"path": "workspace/test/prompts/x.md"}, **kwargs
            )
            assert len(calls) == 2
        else:
            with pytest.raises(ToolDenied, match="max_failures"):
                cp.dispatcher.dispatch(
                    AGENT, "write_file", {"path": "workspace/test/prompts/x.md"}, **kwargs
                )
            assert len(calls) == 1
        assert cp.promotion._verifier is cp.runs
    finally:
        cp.close()


REQUIRED = [
    "repo_root",
    "system_id",
    "constitution",
    "policy_path",
    "heldout_suite_path",
    "admin",
    "harness",
    "ledger_signer",
    "run_registry_signer",
    "verifier_factory",
    "proposer_model_family",
    "proposer_vendor",
    "write_grants",
    "budget_limits",
    "error_budget",
    "breaker_policy",
    "core_registry",
]


@pytest.mark.parametrize("field", REQUIRED)
def test_missing_layer_is_a_construction_error(tmp_path: Path, field: str) -> None:
    with pytest.raises(ControlPlaneConfigError):
        build_control_plane(_config(tmp_path, **{field: None}))


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"admin": Principal("bot", PrincipalKind.AGENT)}, "admin"),
        ({"harness": Principal("h", PrincipalKind.HUMAN)}, "harness"),
        ({"repo_root": "relative/path"}, "absolute"),
        ({"policy_path": "workspace/policy.yaml"}, "policy"),
        ({"heldout_suite_path": "workspace/suite.json"}, "heldout"),
        ({"budget_limits": "lots"}, "wrong type"),
        (
            {
                "proposer_model_family": "rule-based-replay",
                "proposer_vendor": "acgs-independent-verifier",
            },
            "independent",
        ),
        (
            {"write_grants": (WriteGrant("agent-1", PrincipalKind.AGENT, ("**",)),)},
            "construction failed",
        ),
    ],
)
def test_misconfiguration_rejected(tmp_path: Path, overrides: Any, match: str) -> None:
    with pytest.raises(ControlPlaneConfigError, match=match):
        build_control_plane(_config(tmp_path, **overrides))


def test_shared_signing_key_rejected(tmp_path: Path) -> None:
    signer = Ed25519ReceiptSigner.from_seed(b"s" * 32, key_id="same")
    with pytest.raises(ControlPlaneConfigError, match="distinct"):
        build_control_plane(_config(tmp_path, ledger_signer=signer, run_registry_signer=signer))


def test_unloadable_policy_and_bad_config(tmp_path: Path) -> None:
    config = _config(tmp_path)
    (tmp_path / POLICY_PATH).write_text("statements: [", encoding="utf-8")
    with pytest.raises(ControlPlaneConfigError, match="policy set"):
        build_control_plane(config)
    with pytest.raises(ControlPlaneConfigError, match="ControlPlaneConfig"):
        build_control_plane("config")  # type: ignore[arg-type]
    assert dataclasses.is_dataclass(config)
