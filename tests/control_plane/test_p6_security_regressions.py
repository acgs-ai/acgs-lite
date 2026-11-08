"""Phase 6a red team: a HUMAN label is worthless without attested identity.

Every attack runs against the facade-built control plane (the demo
environment): through the dispatcher, through every human-only entry point
and through a real in-memory MCP session.
"""

from __future__ import annotations

import ast
import base64
import json
import re
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from acgs_lite.control_plane import (  # noqa: E402
    ADMIN_SCOPE,
    AgentTelemetryRejected,
    ApprovalRegistrationRejected,
    AutonomyRestoreRejected,
    BreakerResetRejected,
    CredentialInvalid,
    CredentialIssuanceRefused,
    IncidentLockError,
    KillSwitchOperationRejected,
    OwnershipDenied,
    Principal,
    PrincipalKind,
    PromotionRejected,
    Role,
    RoleConflict,
    RunbookRejected,
    ToolDenied,
)
from acgs_lite.control_plane.breaker import TriggerBindingRejected  # noqa: E402
from acgs_lite.control_plane.demo_loop import (  # noqa: E402
    ADMIN,
    AGENT,
    APPROVER,
    ARTIFACT_FILES,
    CHANGE_ID,
    HARNESS,
    POLICY_PATH,
    REQUESTER,
    RUNBOOK_ID,
    SUITE_PATH,
    TRIGGER_ID,
    DemoEnvironment,
    _runbook,
    build_demo_environment,
)
from acgs_lite.control_plane.identity import KILL_SWITCH_ENGAGE_SCOPE  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

IMPOSTOR = Principal(AGENT.id, PrincipalKind.HUMAN, system_id=AGENT.system_id)
PROMPT = ARTIFACT_FILES["prompt"]
CONTROL_PLANE = Path(__file__).resolve().parents[2] / "src" / "acgs_lite" / "control_plane"


@pytest.fixture()
def env(tmp_path: Path) -> Iterator[DemoEnvironment]:
    environment = build_demo_environment(tmp_path)
    try:
        yield environment
    finally:
        environment.close()


def _agent_token(env: DemoEnvironment, *tools: str) -> str:
    scopes = [f"tool:{name}" for name in tools or ("read_file", "write_file")]
    return env.cp.credentials.issue(AGENT, scopes=scopes, trigger_id=TRIGGER_ID).token


class TestDispatcherMislabel:
    def test_human_label_with_agent_credential_denied(self, env: DemoEnvironment) -> None:
        token = _agent_token(env)
        before = (env.root / POLICY_PATH).read_bytes()
        for tool, args in (
            ("write_file", {"path": POLICY_PATH, "content": "statements: []\n"}),
            ("read_file", {"path": SUITE_PATH}),  # human-only sensitive read
            ("read_file", {"path": PROMPT}),
        ):
            with pytest.raises(ToolDenied) as excinfo:
                env.cp.dispatcher.dispatch(IMPOSTOR, tool, args, credential=token)
            assert "another principal kind" in excinfo.value.decision.reason
        assert (env.root / POLICY_PATH).read_bytes() == before
        assert env.tool_calls == []
        # The same credential under its true label works.
        assert env.cp.dispatcher.dispatch(AGENT, "read_file", {"path": PROMPT}, credential=token)

    def test_system_id_relabel_denied(self, env: DemoEnvironment) -> None:
        token = _agent_token(env)
        shed = Principal(AGENT.id, PrincipalKind.AGENT, system_id="other-system")
        with pytest.raises(ToolDenied, match="system_id"):
            env.cp.dispatcher.dispatch(shed, "read_file", {"path": PROMPT}, credential=token)

    def test_human_label_without_credential_denied(self, env: DemoEnvironment) -> None:
        with pytest.raises(ToolDenied, match="credential"):
            env.cp.dispatcher.dispatch(IMPOSTOR, "read_file", {"path": SUITE_PATH})

    def test_attested_human_reads_what_agents_cannot(self, env: DemoEnvironment) -> None:
        token = env.human_credential(REQUESTER, ("tool:read_file",))
        result = env.cp.dispatcher.dispatch(
            REQUESTER, "read_file", {"path": SUITE_PATH}, credential=token
        )
        assert "demo-heldout" in result.value
        with pytest.raises(ToolDenied, match="another principal kind"):
            env.cp.dispatcher.dispatch(
                Principal(REQUESTER.id, PrincipalKind.AGENT),
                "read_file",
                {"path": PROMPT},
                credential=token,
            )

    def test_effective_principal_is_the_directory_entry(self, env: DemoEnvironment) -> None:
        """Self-asserted roles on the passed principal never reach the checks."""
        seen: list[Principal] = []
        original = env.cp.dispatcher._check

        def spy(principal: Principal, *args: Any) -> Any:
            seen.append(principal)
            return original(principal, *args)

        env.cp.dispatcher._check = spy  # type: ignore[method-assign]
        token = env.human_credential(APPROVER, ("tool:read_file",))
        claimed = Principal(APPROVER.id, PrincipalKind.HUMAN, roles=frozenset({"root", "sre"}))
        env.cp.dispatcher.dispatch(claimed, "read_file", {"path": PROMPT}, credential=token)
        assert seen == [Principal(APPROVER.id, PrincipalKind.HUMAN, roles=frozenset({"sre"}))]

    def test_unknown_id_issuance_refused(self, env: DemoEnvironment) -> None:
        with pytest.raises(CredentialIssuanceRefused, match="not in the identity directory"):
            env.cp.credentials.issue(
                Principal("bot-1", PrincipalKind.AGENT, system_id="demo"), scopes=["tool:x"]
            )
        with pytest.raises(CredentialIssuanceRefused, match="issue_for_human"):
            env.cp.credentials.issue(IMPOSTOR, scopes=["tool:read_file"])

    def test_forged_knd_human_payload_bad_signature(self, env: DemoEnvironment) -> None:
        token = _agent_token(env)
        body, mac = token.split(".")
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        payload = json.loads(raw)
        assert payload["knd"] == "agent"
        payload["knd"] = "human"
        forged_raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        forged = base64.urlsafe_b64encode(forged_raw).rstrip(b"=").decode() + "." + mac
        with pytest.raises(CredentialInvalid, match="bad token signature"):
            env.cp.credentials.authenticate(forged)
        with pytest.raises(ToolDenied, match="bad token signature"):
            env.cp.dispatcher.dispatch(IMPOSTOR, "read_file", {"path": PROMPT}, credential=forged)


class TestChallengeAttacks:
    def test_replay_wrong_key_other_person(self, env: DemoEnvironment) -> None:
        from acgs_lite.control_plane import HumanAuthenticationFailed
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        auth = env.cp.human_authenticator
        admin_key = env.human_keys[ADMIN.id]
        challenge = auth.issue_challenge(ADMIN.id)
        signature = admin_key.sign(challenge.message)
        session = auth.verify_response(challenge, signature)
        with pytest.raises(HumanAuthenticationFailed, match="already used"):
            auth.verify_response(challenge, signature)
        env.cp.credentials.issue_for_human(session, scopes=[ADMIN_SCOPE])
        with pytest.raises(CredentialIssuanceRefused, match="already redeemed"):
            env.cp.credentials.issue_for_human(session, scopes=[ADMIN_SCOPE])
        # Another human (a real directory member) answers the admin's challenge.
        challenge = auth.issue_challenge(ADMIN.id)
        with pytest.raises(HumanAuthenticationFailed, match="bad challenge signature"):
            auth.verify_response(challenge, env.human_keys[REQUESTER.id].sign(challenge.message))
        challenge = auth.issue_challenge(ADMIN.id)
        stranger = Ed25519ReceiptSigner.generate()
        with pytest.raises(HumanAuthenticationFailed, match="bad challenge signature"):
            auth.verify_response(challenge, stranger.sign(challenge.message))
        # The agent cannot even be challenged as a human.
        with pytest.raises(HumanAuthenticationFailed, match="not a human"):
            auth.issue_challenge(AGENT.id)

    def test_expired_challenge(self, env: DemoEnvironment, monkeypatch: Any) -> None:
        from acgs_lite.control_plane import HumanAuthenticationFailed

        auth = env.cp.human_authenticator
        challenge = auth.issue_challenge(ADMIN.id)
        later = challenge.expires_at + 1
        monkeypatch.setattr(auth, "_clock", lambda: later)
        with pytest.raises(HumanAuthenticationFailed, match="expired"):
            auth.verify_response(challenge, env.human_keys[ADMIN.id].sign(challenge.message))

    def test_demo_keys_are_random_per_environment(self, tmp_path: Path) -> None:
        first = build_demo_environment(tmp_path / "a")
        second = build_demo_environment(tmp_path / "b")
        try:
            assert first.cp.identity.admin.public_key_hex != second.cp.identity.admin.public_key_hex
            assert first.cp.ledger.public_key_hex != second.cp.ledger.public_key_hex
            assert "human_keys" not in repr(first)
        finally:
            first.close()
            second.close()


AdminCall = Callable[[Principal, Any], Any]
_REVIEW_OUTCOME = "accepted"


def _admin_calls(env: DemoEnvironment) -> dict[str, tuple[type[Exception], AdminCall]]:
    """Every human-only entry point as ``(error, call(actor, credential))``."""
    cp = env.cp
    zed = Principal("zed", PrincipalKind.HUMAN)
    runbook = _runbook("2099-01-01")
    runbook.update(runbook_id="rb-other")
    bot9 = Principal("bot-9", PrincipalKind.AGENT, system_id="demo")
    digest = "sha256:" + "0" * 64
    return {
        "register_approver": (
            ApprovalRegistrationRejected,
            lambda a, c: cp.authority.register_approver(a, zed, "ab" * 32, admin_credential=c),
        ),
        "revoke_approver": (
            ApprovalRegistrationRejected,
            lambda a, c: cp.authority.revoke_approver(a, "key-sam", admin_credential=c),
        ),
        "register_system_member": (
            ApprovalRegistrationRejected,
            lambda a, c: cp.authority.register_system_member(a, bot9, admin_credential=c),
        ),
        "trigger_bind": (
            TriggerBindingRejected,
            lambda a, c: cp.triggers.bind(a, "t-2", principals=[AGENT], admin_credential=c),
        ),
        "trigger_unbind": (
            TriggerBindingRejected,
            lambda a, c: cp.triggers.unbind(a, TRIGGER_ID, admin_credential=c),
        ),
        "breaker_reset": (
            BreakerResetRejected,
            lambda a, c: cp.breaker.reset(a, TRIGGER_ID, admin_credential=c),
        ),
        "grant_capability": (
            RoleConflict,
            lambda a, c: cp.roles.grant_capability(a, "sre", zed, admin_credential=c),
        ),
        "revoke_capability": (
            RoleConflict,
            lambda a, c: cp.roles.revoke_capability(a, "sre", APPROVER, admin_credential=c),
        ),
        "roles_assign": (
            RoleConflict,
            lambda a, c: cp.roles.assign(a, "chg-2", Role.PROPOSER, AGENT, admin_credential=c),
        ),
        "ownership_assign": (
            OwnershipDenied,
            lambda a, c: cp.ownership.assign(a, "chg-2", AGENT, "workspace/o", admin_credential=c),
        ),
        "ownership_release": (
            OwnershipDenied,
            lambda a, c: cp.ownership.release(a, CHANGE_ID, admin_credential=c),
        ),
        "runbook_revoke": (
            RunbookRejected,
            lambda a, c: cp.runbooks.revoke(a, RUNBOOK_ID, admin_credential=c),
        ),
        "runbook_approve": (
            RunbookRejected,
            lambda a, c: cp.runbooks.approve(a, runbook, approvals=[], admin_credential=c),
        ),
        "autonomy_restore": (
            AutonomyRestoreRejected,
            lambda a, c: cp.autonomy.restore(a, AGENT, admin_credential=c),
        ),
        "kill_switch_engage": (
            KillSwitchOperationRejected,
            lambda a, c: cp.kill_switch.engage(a, "probe", admin_credential=c),
        ),
        "kill_switch_release": (
            KillSwitchOperationRejected,
            lambda a, c: cp.kill_switch.release(a, admin_credential=c),
        ),
        "review_resolve": (
            PermissionError,
            lambda a, c: cp.review_queue.resolve(a, "missing", _REVIEW_OUTCOME, admin_credential=c),
        ),
        "telemetry_approval_denied": (
            AgentTelemetryRejected,
            lambda a, c: cp.telemetry.record_approval_denied("h" * 64, a, admin_credential=c),
        ),
        "telemetry_override": (
            AgentTelemetryRejected,
            lambda a, c: cp.telemetry.record_override(
                "dec-1", a, "human_overrode_deny", admin_credential=c
            ),
        ),
        "telemetry_ground_truth": (
            AgentTelemetryRejected,
            lambda a, c: cp.telemetry.record_ground_truth(
                "subject", "pass", reviewer=a, admin_credential=c
            ),
        ),
        "incident_declare": (
            IncidentLockError,
            lambda a, c: cp.incident_lock.declare_incident(a, "inc-9", admin_credential=c),
        ),
        "incident_acquire": (
            IncidentLockError,
            lambda a, c: cp.incident_lock.acquire(AGENT, "inc-9", commander=a, admin_credential=c),
        ),
        "incident_transfer": (
            IncidentLockError,
            lambda a, c: cp.incident_lock.transfer(a, AGENT, admin_credential=c),
        ),
        "incident_release": (
            IncidentLockError,
            lambda a, c: cp.incident_lock.release(a, admin_credential=c),
        ),
        "incident_resolve": (
            IncidentLockError,
            lambda a, c: cp.incident_lock.resolve(a, admin_credential=c),
        ),
        "promotion_promote": (
            PromotionRejected,
            lambda a, c: cp.promotion.promote(
                a, "cand-x", candidate_digest=digest, evidence=[], admin_credential=c
            ),
        ),
    }


# Entry point -> the human-kind gate (module:qualname) it reaches.
ENTRY_POINTS: dict[str, str] = {
    "register_approver": "approvals.py:ApprovalAuthority.register_approver",
    "revoke_approver": "approvals.py:ApprovalAuthority.revoke_approver",
    "register_system_member": "approvals.py:ApprovalAuthority.register_system_member",
    "trigger_bind": "breaker.py:TriggerRegistry.bind",
    "trigger_unbind": "breaker.py:TriggerRegistry.unbind",
    "breaker_reset": "breaker.py:TriggerCircuitBreaker.reset",
    "grant_capability": "roles.py:RoleAssignments.grant_capability",
    "revoke_capability": "roles.py:RoleAssignments._is_admin",
    "roles_assign": "roles.py:RoleAssignments._is_admin",
    "ownership_assign": "change_ownership.py:ChangeOwnershipRegistry.assign",
    "ownership_release": "change_ownership.py:ChangeOwnershipRegistry.release",
    "runbook_revoke": "runbook.py:RunbookRegistry.revoke",
    "runbook_approve": "runbook.py:RunbookRegistry.approve",
    "autonomy_restore": "autonomy.py:AutonomyController.restore",
    "kill_switch_engage": "killswitch.py:KillSwitch.engage",
    "kill_switch_release": "killswitch.py:KillSwitch.release",
    "review_resolve": "tier_policy.py:ReviewQueue.resolve",
    "telemetry_approval_denied": "telemetry.py:TelemetryRecorder._human",
    "telemetry_override": "telemetry.py:TelemetryRecorder._human",
    "telemetry_ground_truth": "telemetry.py:TelemetryRecorder._human",
    "incident_declare": "incident.py:IncidentMutationLock.declare_incident",
    "incident_acquire": "incident.py:IncidentMutationLock._require_commander",
    "incident_transfer": "incident.py:IncidentMutationLock._require_commander",
    "incident_release": "incident.py:IncidentMutationLock._require_commander",
    "incident_resolve": "incident.py:IncidentMutationLock._require_commander",
    # PromotionGate.promote has no kind check of its own (the PDP and the
    # ledger enforce HUMAN); it is attested at its entry.
    "promotion_promote": "receipt_ledger.py:ReceiptLedger.append_promotion",
}
# Human-kind gates that are not entry points, each with the reason.
ALLOWLIST: dict[str, str] = {
    "approvals.py:_require_human": "helper; every caller is an entry point",
    "breaker.py:_require_human": "helper; every caller is an entry point",
    "runbook.py:_require_human": "helper; every caller is an entry point",
    "telemetry.py:_require_human": "helper of TelemetryRecorder._human",
    "approvals.py:ApprovalGate._check": "kind of a signed approver whose key an attested "
    "admin registered against its directory entry",
    "autonomy.py:AutonomyController._governed": "classifies the subject principal the "
    "attested dispatcher passes in",
    "breaker.py:TriggerCircuitBreaker._on_trip": "classifies bound members (bound by an "
    "attested admin) for demotion",
    "credentials.py:CredentialIssuer.issue": "issuance policy; with identity every "
    "principal is directory-checked and HUMAN only via issue_for_human",
    "credentials.py:CredentialIssuer._attest_requester": "is the requester attestation",
    "dispatcher.py:GovernedToolDispatcher._check": "dispatcher uses the attested "
    "directory principal (Phase 6a)",
    "dispatcher.py:GovernedToolDispatcher._plan": "attested dispatcher principal",
    "dispatcher.py:GovernedToolDispatcher._ownership_check": "attested dispatcher principal",
    "dispatcher.py:GovernedToolDispatcher._breaker_check": "attested dispatcher principal",
    "dispatcher.py:GovernedToolDispatcher._harness_checks": "attested dispatcher principal",
    "dispatcher.py:GovernedToolDispatcher._stop_signals": "attested dispatcher principal",
    "iam.py:RepositoryPermissions.__init__": "validates WriteGrant config, not a caller",
    "iam.py:RepositoryPermissions.can_write": "called with the attested dispatcher principal",
    "identity.py:HumanAuthenticator._human": "the identity layer itself",
    "identity.py:StaticIdentityDirectory.__init__": "the identity layer itself",
    "identity.py:_entry": "the identity layer itself (directory parsing)",
    "invariants.py:_core_change_without_attested_second_human": "PDP invariant over "
    "DecisionRequest.principal; requests come from attested callers",
    "invariants.py:_core_write_by_non_human": "PDP invariant (attested callers)",
    "invariants.py:_merge_by_non_human": "PDP invariant (attested callers)",
    "invariants.py:_sensitive_access_by_non_human": "PDP invariant (attested callers)",
    "invariants.py:has_two_person_approval": "kind of signed approvers",
    "roles.py:RoleAssignments.__init__": "validates the configured admin, which the facade "
    "checks against the directory",
    "roles.py:RoleAssignments.has_capability": "capability holder lookup for a subject",
    "tier_policy.py:t3_execution_problem": "executor is the attested dispatcher principal",
    # Round 2: the broadened detector (any comparison mentioning a kind).
    "budgets.py:BudgetLedger.charge": "negative gate (no AGENT reporter); charging only "
    "spends budget (fail-safe) and the ledger is harness-held",
    "budgets.py:BudgetLedger.try_charge": "same negative gate as BudgetLedger.charge",
    "change_ownership.py:ChangeOwnershipRegistry.assert_writer": "compares the attested "
    "dispatcher principal with the writer an attested admin assigned",
    "credentials.py:CredentialIssuer._check_directory": "identity layer: directory check",
    "credentials.py:CredentialIssuer._check_obo": "identity layer: binds on_behalf_of",
    "credentials.py:CredentialIssuer.verify": "identity layer: signed kind vs. label",
    "dispatcher.py:GovernedToolDispatcher.register": "inspect.Parameter.kind (signature "
    "classification), not a principal kind",
    "dispatcher.py:GovernedToolDispatcher._resolve_requested_by": "attested dispatcher principal",
    "dispatcher.py:GovernedToolDispatcher._authorize": "the Phase 6a attestation itself",
    # Phase 6b: the socket service.
    "service.py:_checked_uid_kinds": "validates the uid map config (HUMAN uids dedicated), "
    "not a caller",
    "service.py:ControlPlaneService._admit": "connection-slot accounting by configured uid "
    "map (HUMAN-only reserved slots); grants no authority",
    "service.py:ControlPlaneService._attested_principal": "the P6a attestation (credential "
    "vs. directory) plus the SO_PEERCRED uid->kind check; the dispatcher re-attests",
    "evaluator.py:EvaluatorService.__init__": "construction: the facade passes the "
    "directory-checked SERVICE harness",
    "evidence.py:TrustedRunRegistry.register_run": "harness-held registry; the facade calls "
    "it only through EvaluatorService with the directory-checked harness",
    "facade.py:_require_kind": "config validation (then checked against the directory)",
    "facade.py:build_control_plane": "config vs. identity directory validation",
    "identity.py:AdminAttestor.require": "the identity layer itself",
    "incident.py:_parse": "parses the core incident state file (not a caller label)",
    "incident.py:IncidentMutationLock.write_denial": "compares the attested dispatcher "
    "principal with the holder an attested commander designated",
    "invariants.py:_agent_without_original_requester": "PDP invariant (attested callers)",
    "policy.py:PolicyStatement.matches": "PDP policy match over DecisionRequest.principal "
    "(attested callers)",
    "receipt_verify.py:verify_receipt": "ReceiptKind, not a principal kind",
    "receipt_verify.py:_promotion_problems": "verifies the signed receipt's principal_kind",
    "receipts.py:promotion_evidence_keys": "ReceiptKind, not a principal kind",
    "roles.py:RoleAssignments.assign": "kind of the assignee (subject); the assigning "
    "admin is attested",
    "telemetry.py:OversightEvent.__post_init__": "event field validation (no AGENT recorder)",
    "telemetry.py:_admit": "event field validation (no AGENT recorder)",
    "telemetry.py:TelemetryRecorder.__init__": "construction: the facade passes the "
    "directory-checked SERVICE harness as recorder",
    "telemetry.py:TelemetryRecorder._agent_fields": "kind of the subject agent of an event",
    "telemetry.py:OversightMetrics.override_rate": "metrics segmentation over recorded events",
}

# The 7 spellings of a kind check the detector must catch (re-review probe).
SYNTHETIC_GATES = """
from acgs_lite.control_plane.principal import PrincipalKind
from acgs_lite.control_plane.principal import PrincipalKind as PK
HUMAN = PrincipalKind.HUMAN
class Evil:
    def eq(self, p): return p.kind == PrincipalKind.HUMAN
    def member(self, p): return p.kind in {PrincipalKind.HUMAN}
    def strcmp(self, p): return p.kind.value == "human"
    def alias(self, p): return p.kind is PK.HUMAN
    def modconst(self, p): return p.kind is HUMAN
    def negative(self, p):
        if p.kind is PrincipalKind.AGENT: raise PermissionError
    def detected(self, p): return p.kind is PrincipalKind.HUMAN
    def unrelated(self, p): return p.id == "x"
"""
SYNTHETIC_NO_KIND_ATTR = """
from acgs_lite.control_plane.principal import PrincipalKind as PK
LABEL = PK.HUMAN
def by_alias(label): return label is PK.HUMAN
def by_constant(label): return label == LABEL
def by_string(label): return label != "Human"
def not_a_gate(x): return x > 3
"""


def _kind_names(tree: ast.Module) -> set[str]:
    """Names that denote PrincipalKind (import aliases) or one of its members
    (module-level constants such as ``HUMAN = PrincipalKind.HUMAN``)."""
    names = {"PrincipalKind"}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "PrincipalKind":
                    names.add(alias.asname or alias.name)
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            mentions = value is not None and any(
                isinstance(n, ast.Name) and n.id in names for n in ast.walk(value)
            )
            if mentions:
                names.update(t.id for t in targets if isinstance(t, ast.Name))
    return names


def _mentions_kind(node: ast.AST, names: set[str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr == "kind":
            return True
        if isinstance(sub, ast.Name) and sub.id in names:
            return True
        if (
            isinstance(sub, ast.Constant)
            and isinstance(sub.value, str)
            and (sub.value.lower() == "human")
        ):
            return True
    return False


def _human_kind_gates(root: Path | None = None) -> set[str]:
    """Every comparison (any operator: ==, !=, is, is not, in, not in, ...)
    whose operands mention a principal kind -- ``PrincipalKind`` or an import
    alias of it, a module constant bound to one of its members, any ``.kind``
    attribute, or the literal ``"human"`` -- plus every ``_require_human``
    call, keyed ``module:qualname``."""
    found: set[str] = set()
    for path in sorted((root or CONTROL_PLANE).glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = _kind_names(tree)

        def visit(
            node: ast.AST, stack: list[str], name: str = path.name, kinds: set[str] = names
        ) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    visit(child, [*stack, child.name])
                    continue
                compare = isinstance(child, ast.Compare) and any(
                    _mentions_kind(x, kinds) for x in [child.left, *child.comparators]
                )
                helper = (
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Name)
                    and child.func.id == "_require_human"
                )
                if compare or helper:
                    found.add(f"{name}:{'.'.join(stack) or '<module>'}")
                visit(child, stack)

        visit(tree, [])
    return found


class TestAdminEntryPoints:
    def test_entry_point_list_is_complete(self, env: DemoEnvironment) -> None:
        assert sorted(_admin_calls(env)) == sorted(ENTRY_POINTS)

    def test_detector_catches_every_spelling(self, tmp_path: Path) -> None:
        (tmp_path / "evil.py").write_text(SYNTHETIC_GATES, encoding="utf-8")
        assert _human_kind_gates(tmp_path) == {
            f"evil.py:Evil.{name}"
            for name in ("eq", "member", "strcmp", "alias", "modconst", "negative", "detected")
        }
        (tmp_path / "evil.py").unlink()
        # Without any ``.kind`` attribute: aliases, constants and literals alone.
        (tmp_path / "bare.py").write_text(SYNTHETIC_NO_KIND_ATTR, encoding="utf-8")
        assert _human_kind_gates(tmp_path) == {
            "bare.py:by_alias",
            "bare.py:by_constant",
            "bare.py:by_string",
        }

    def test_every_human_kind_gate_is_covered(self) -> None:
        gates = _human_kind_gates()
        covered = set(ENTRY_POINTS.values()) | set(ALLOWLIST)
        assert gates - covered == set(), "unlisted human-kind gates"
        assert covered - gates == set(), "stale ENTRY_POINTS/ALLOWLIST entries"

    @pytest.mark.parametrize("entry", sorted(ENTRY_POINTS))
    @pytest.mark.parametrize(
        "wrong", ["none", "garbage", "agent", "other_human", "no_admin_scope", "impostor_label"]
    )
    def test_refused_without_verified_human(
        self, env: DemoEnvironment, entry: str, wrong: str
    ) -> None:
        error, call = _admin_calls(env)[entry]
        actor = ADMIN if entry in _ADMIN_ONLY else REQUESTER
        other = REQUESTER if actor is ADMIN else ADMIN
        if wrong == "impostor_label":
            # The agent relabels itself HUMAN and offers its own credential.
            actor, token = IMPOSTOR, _agent_token(env)
        else:
            token = {
                "none": None,
                "garbage": "not.a-token",
                "agent": _agent_token(env),
                "other_human": env.human_credential(other),
                "no_admin_scope": env.human_credential(actor, ("tool:read_file",)),
            }[wrong]
        with pytest.raises(error, match="admin attestation"):
            call(actor, token)
        _assert_demo_state_intact(env)

    @pytest.mark.parametrize("entry", sorted(ENTRY_POINTS))
    def test_credential_is_single_use(self, env: DemoEnvironment, entry: str) -> None:
        error, call = _admin_calls(env)[entry]
        actor = ADMIN if entry in _ADMIN_ONLY else REQUESTER
        token = env.human_credential(actor)
        try:
            call(actor, token)
        except Exception as exc:  # the operation itself may refuse after attestation
            assert "admin attestation" not in str(exc)
        with pytest.raises(error, match="already used"):
            call(actor, token)

    def test_non_admin_human_cannot_use_admin_only_entries(self, env: DemoEnvironment) -> None:
        calls = _admin_calls(env)
        for entry in sorted(
            _ADMIN_ONLY - {"grant_capability", "revoke_capability", "roles_assign"}
        ):
            error, call = calls[entry]
            with pytest.raises(error, match="admin attestation"):
                call(ADMIN, env.human_credential(REQUESTER))
            with pytest.raises(error, match="not the directory admin"):
                call(REQUESTER, env.human_credential(REQUESTER))

    def test_concurrent_reuse_succeeds_once(self, env: DemoEnvironment) -> None:
        token = env.admin_credential
        results: list[bool] = []

        def unbind() -> None:
            try:
                env.cp.triggers.unbind(ADMIN, TRIGGER_ID, admin_credential=token)
                results.append(True)
            except TriggerBindingRejected:
                results.append(False)

        threads = [threading.Thread(target=unbind) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted(results) == [False] * 7 + [True]

    def test_verified_humans_still_work(self, env: DemoEnvironment) -> None:
        cp = env.cp
        cp.triggers.unbind(ADMIN, TRIGGER_ID, admin_credential=env.admin_credential)
        assert not cp.triggers.is_bound(TRIGGER_ID, AGENT)
        cp.breaker.reset(ADMIN, TRIGGER_ID, admin_credential=env.admin_credential)
        assert cp.ownership.release(ADMIN, CHANGE_ID, admin_credential=env.admin_credential)
        assert cp.runbooks.revoke(ADMIN, RUNBOOK_ID, admin_credential=env.admin_credential)
        assert cp.authority.revoke_approver(ADMIN, "key-sam", admin_credential=env.admin_credential)
        cp.autonomy.restore(ADMIN, AGENT, admin_credential=env.admin_credential)
        cp.kill_switch.engage(REQUESTER, "drill", admin_credential=env.requester_credential)
        assert cp.kill_switch.is_engaged()
        # Releasing a halt is admin-only (round 2, N5).
        with pytest.raises(KillSwitchOperationRejected, match="not the directory admin"):
            cp.kill_switch.release(REQUESTER, admin_credential=env.requester_credential)
        assert cp.kill_switch.is_engaged()
        cp.kill_switch.release(ADMIN, admin_credential=env.admin_credential)
        assert not cp.kill_switch.is_engaged()
        cp.telemetry.record_override(
            "dec-1", REQUESTER, "human_overrode_deny", admin_credential=env.requester_credential
        )

    def test_service_kill_switch_engage(self, env: DemoEnvironment) -> None:
        cp = env.cp
        halt = cp.credentials.issue(HARNESS, scopes=[KILL_SWITCH_ENGAGE_SCOPE]).token
        posing = Principal(AGENT.id, PrincipalKind.SERVICE, system_id=AGENT.system_id)
        with pytest.raises(KillSwitchOperationRejected, match="admin attestation"):
            cp.kill_switch.engage(posing, "x", admin_credential=_agent_token(env))
        with pytest.raises(KillSwitchOperationRejected, match="admin attestation"):
            cp.kill_switch.engage(HARNESS, "x")
        assert not cp.kill_switch.is_engaged()
        cp.kill_switch.engage(HARNESS, "watchdog", admin_credential=halt)
        assert cp.kill_switch.is_engaged()
        with pytest.raises(KillSwitchOperationRejected, match="already used"):
            cp.kill_switch.engage(HARNESS, "again", admin_credential=halt)


_ADMIN_ONLY = frozenset(
    {
        "register_approver",
        "revoke_approver",
        "register_system_member",
        "trigger_bind",
        "trigger_unbind",
        "breaker_reset",
        "grant_capability",
        "revoke_capability",
        "roles_assign",
        "ownership_assign",
        "ownership_release",
        "runbook_revoke",
        "autonomy_restore",
        "kill_switch_release",
    }
)


def _assert_demo_state_intact(env: DemoEnvironment) -> None:
    cp = env.cp
    assert cp.runbooks.approved(RUNBOOK_ID) is not None
    assert cp.runbooks.approved("rb-other") is None
    assert cp.triggers.is_bound(TRIGGER_ID, AGENT)
    assert not cp.triggers.is_bound("t-2", AGENT)
    assert cp.ownership.get(CHANGE_ID) is not None
    assert cp.ownership.get("chg-2") is None
    assert cp.roles.has_capability(APPROVER, "sre")
    assert not cp.kill_switch.is_engaged()
    assert cp.incident_lock.state() is None


class TestAdminCredentialLimits:
    def test_admin_scope_ttl_capped(self, env: DemoEnvironment) -> None:
        auth = env.cp.human_authenticator
        key = env.human_keys[ADMIN.id]

        def session() -> Any:
            challenge = auth.issue_challenge(ADMIN.id)
            return auth.verify_response(challenge, key.sign(challenge.message))

        default = env.cp.credentials.issue_for_human(session(), scopes=[ADMIN_SCOPE])
        assert default.expires_at - default.issued_at == 60
        with pytest.raises(CredentialIssuanceRefused, match="admin-scope ttl_s"):
            env.cp.credentials.issue_for_human(session(), scopes=[ADMIN_SCOPE], ttl_s=61)
        tool = env.cp.credentials.issue_for_human(session(), scopes=["tool:read_file"])
        assert tool.expires_at - tool.issued_at == 300

    def test_admin_ttl_configurable(self) -> None:
        from acgs_lite.control_plane import CredentialIssuer

        issuer = CredentialIssuer(admin_max_ttl_s=5)
        alice = Principal("alice", PrincipalKind.HUMAN)
        assert (
            issuer.issue(alice, scopes=["admin:x"]).expires_at
            - issuer.issue(alice, scopes=["admin:x"]).issued_at
            <= 5
        )
        with pytest.raises(ValueError, match="admin_max_ttl_s"):
            CredentialIssuer(admin_max_ttl_s=0)


class TestRequesterAttestation:
    def test_unattested_human_requester_cannot_choose_trigger_or_obo(
        self, env: DemoEnvironment
    ) -> None:
        issue = env.cp.credentials.issue
        with pytest.raises(CredentialIssuanceRefused, match="requester_credential"):
            issue(AGENT, scopes=["tool:read_file"], trigger_id="t-y", requester=REQUESTER)
        with pytest.raises(CredentialIssuanceRefused, match="requester_credential"):
            issue(AGENT, scopes=["tool:read_file"], on_behalf_of=ADMIN.id, requester=ADMIN)
        with pytest.raises(CredentialIssuanceRefused, match="requester_credential refused"):
            issue(
                AGENT,
                scopes=["tool:read_file"],
                trigger_id="t-y",
                requester=REQUESTER,
                requester_credential=env.human_credential(ADMIN),  # another human's
            )
        with pytest.raises(CredentialIssuanceRefused, match="only the harness"):
            issue(AGENT, scopes=["tool:read_file"], trigger_id="t-y", requester=HARNESS)
        # Without obo/trigger a directory-checked requester needs no proof.
        assert issue(AGENT, scopes=["tool:read_file"], requester=REQUESTER).trigger_id is None

    def test_attested_human_requester_and_harness_may_choose(self, env: DemoEnvironment) -> None:
        issue = env.cp.credentials.issue
        token = env.requester_credential
        cred = issue(
            AGENT,
            scopes=["tool:read_file"],
            trigger_id=TRIGGER_ID,
            on_behalf_of=REQUESTER.id,
            requester=REQUESTER,
            requester_credential=token,
        )
        assert (cred.trigger_id, cred.on_behalf_of) == (TRIGGER_ID, REQUESTER.id.casefold())
        with pytest.raises(CredentialIssuanceRefused, match="already used"):
            issue(
                AGENT,
                scopes=["tool:read_file"],
                trigger_id=TRIGGER_ID,
                requester=REQUESTER,
                requester_credential=token,
            )
        assert issue(AGENT, scopes=["tool:read_file"], trigger_id=TRIGGER_ID).trigger_id


class TestOnBehalfOfBinding:
    """Round 2, N1/N2: on_behalf_of is bound, and nothing is spent early."""

    def _issue(self, env: DemoEnvironment, **kwargs: Any) -> Any:
        return env.cp.credentials.issue(AGENT, scopes=["tool:read_file"], **kwargs)

    def test_human_requester_cannot_name_another_human(self, env: DemoEnvironment) -> None:
        token = env.requester_credential
        for other in (ADMIN.id, APPROVER.id, "ghost-nobody"):
            with pytest.raises(CredentialIssuanceRefused, match="only name itself"):
                self._issue(
                    env, requester=REQUESTER, on_behalf_of=other, requester_credential=token
                )
        # The refusals spent nothing: the same credential still works for self.
        cred = self._issue(
            env, requester=REQUESTER, on_behalf_of=REQUESTER.id, requester_credential=token
        )
        assert cred.on_behalf_of == REQUESTER.id.casefold()

    def test_harness_obo_must_be_a_directory_human(self, env: DemoEnvironment) -> None:
        for bad in ("ghost-nobody", HARNESS.id, "replay-verifier"):
            with pytest.raises(CredentialIssuanceRefused, match="human in the identity directory"):
                self._issue(env, on_behalf_of=bad)
        assert self._issue(env, on_behalf_of=ADMIN.id).on_behalf_of == ADMIN.id.casefold()

    def test_invalid_input_does_not_spend_requester_credential(self, env: DemoEnvironment) -> None:
        token = env.requester_credential
        obo = {"requester": REQUESTER, "on_behalf_of": REQUESTER.id}
        with pytest.raises(CredentialIssuanceRefused, match="ttl_s"):
            self._issue(env, **obo, requester_credential=token, ttl_s=10**6)
        with pytest.raises(CredentialIssuanceRefused, match="trigger_id"):
            self._issue(env, **obo, requester_credential=token, trigger_id="bad trigger")
        with pytest.raises(CredentialIssuanceRefused, match="scope"):
            env.cp.credentials.issue(AGENT, scopes=[], **obo, requester_credential=token)
        assert self._issue(env, **obo, requester_credential=token).credential_id

    def test_requester_cannot_approve_own_agents_t2_change(self, env: DemoEnvironment) -> None:
        """Dispatcher level: with obo bound to the requester, the requester's
        own signed approval never counts for the agent's T2 change."""
        from acgs_lite.control_plane import SignedApproval
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        cp = env.cp
        olivia_key = Ed25519ReceiptSigner.generate()
        cp.authority.register_approver(
            ADMIN,
            REQUESTER,
            olivia_key.public_key_hex(),
            key_id="key-olivia",
            admin_credential=env.admin_credential,
        )
        # Steering obo to someone else (so olivia could approve) is refused.
        with pytest.raises(CredentialIssuanceRefused, match="only name itself"):
            cp.credentials.issue(
                AGENT,
                scopes=["tool:write_file"],
                trigger_id=TRIGGER_ID,
                requester=REQUESTER,
                on_behalf_of=APPROVER.id,
                requester_credential=env.requester_credential,
            )
        token = cp.credentials.issue(
            AGENT,
            scopes=["tool:write_file"],
            trigger_id=TRIGGER_ID,
            requester=REQUESTER,
            on_behalf_of=REQUESTER.id,
            requester_credential=env.requester_credential,
        ).token
        args = {"path": PROMPT, "content": "t2 change\n"}
        options = {"credential": token, "change_id": CHANGE_ID}
        digest = cp.dispatcher.action_hash_for(
            AGENT,
            "write_file",
            args,
            requested_by=REQUESTER.id,
            change_id=CHANGE_ID,
            trigger_id=TRIGGER_ID,
        )
        own = SignedApproval.create(olivia_key, approver=REQUESTER, action_hash=digest)
        with pytest.raises(ToolDenied):
            cp.dispatcher.dispatch(AGENT, "write_file", args, approvals=[own], **options)
        assert ("write_file", PROMPT) not in env.tool_calls
        # An independent human's approval of the same call is accepted.
        sams = env.approver_sign(digest)
        cp.dispatcher.dispatch(AGENT, "write_file", args, approvals=[sams], **options)
        assert ("write_file", PROMPT) in env.tool_calls


class TestBoundedState:
    def test_used_map_pruned_after_expiry(self) -> None:
        from acgs_lite.control_plane import CredentialIssuer

        clock = [1_000.0]
        issuer = CredentialIssuer(clock=lambda: clock[0])
        agent = Principal("bot", PrincipalKind.AGENT)
        for _ in range(100):
            token = issuer.issue(agent, scopes=["tool:x"], ttl_s=1).token
            issuer.consume(token, required_scope="tool:x", principal=agent)
        assert len(issuer._used) == 100
        replay = issuer.issue(agent, scopes=["tool:x"], ttl_s=5).token
        issuer.consume(replay, required_scope="tool:x", principal=agent)
        clock[0] += 2  # the first 100 have expired; the replay one has not
        fresh = issuer.issue(agent, scopes=["tool:x"], ttl_s=1).token
        issuer.consume(fresh, required_scope="tool:x", principal=agent)
        assert len(issuer._used) == 2
        with pytest.raises(CredentialInvalid, match="already used"):
            issuer.consume(replay, required_scope="tool:x", principal=agent)

    def test_challenge_spam_cannot_lock_out_the_admin(self, env: DemoEnvironment) -> None:
        from acgs_lite.control_plane.identity import MAX_PENDING_PER_PRINCIPAL

        auth = env.cp.human_authenticator
        for _ in range(MAX_PENDING_PER_PRINCIPAL):
            auth.issue_challenge(ADMIN.id)  # attacker-requested, never answered
        token = env.admin_credential  # a fresh admin login still works
        env.cp.triggers.unbind(ADMIN, TRIGGER_ID, admin_credential=token)
        assert not env.cp.triggers.is_bound(TRIGGER_ID, AGENT)


class TestApproverDirectory:
    @pytest.mark.parametrize(
        "approver",
        [
            Principal("zed", PrincipalKind.HUMAN),  # not in the directory
            Principal(APPROVER.id, PrincipalKind.HUMAN),  # roles differ (no sre)
            Principal(APPROVER.id, PrincipalKind.HUMAN, roles=frozenset({"sre", "root"})),
            Principal(APPROVER.id, PrincipalKind.HUMAN, "demo", frozenset({"sre"})),
        ],
    )
    def test_approver_must_match_directory(self, env: DemoEnvironment, approver: Principal) -> None:
        with pytest.raises(ApprovalRegistrationRejected, match="directory entry"):
            env.cp.authority.register_approver(
                ADMIN, approver, "cd" * 32, key_id="k2", admin_credential=env.admin_credential
            )

    def test_matching_approver_registers(self, env: DemoEnvironment) -> None:
        kid = env.cp.authority.register_approver(
            ADMIN, APPROVER, "ef" * 32, key_id="k3", admin_credential=env.admin_credential
        )
        assert kid == "k3"


class TestMcpSession:
    async def _call(
        self,
        env: DemoEnvironment,
        resolver: Any,
        tool: str,
        args: dict[str, Any],
        meta: dict[str, Any] | None = None,
    ) -> str:
        pytest.importorskip("mcp")
        from mcp import Client, types
        from mcp.server import Server

        from acgs_lite.integrations.control_plane_mcp import make_mcp_call_tool_handler

        async def list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
            return types.ListToolsResult(
                tools=[
                    types.Tool(name=name, description=name, input_schema={"type": "object"})
                    for name in ("read_file", "write_file")
                ]
            )

        server = Server(
            "p6",
            on_list_tools=list_tools,
            on_call_tool=make_mcp_call_tool_handler(env.cp.dispatcher, resolver),
        )
        async with Client(server) as client:
            result = await client.call_tool(tool, args, meta=meta)
        text = result.content[0].text
        assert isinstance(text, str)
        return text

    async def test_meta_credential_allows_and_derives_principal(self, env: DemoEnvironment) -> None:
        pytest.importorskip("mcp")
        from acgs_lite.integrations.control_plane_mcp import credential_principal_resolver

        resolver = credential_principal_resolver(env.cp.credentials)
        token = _agent_token(env)
        text = await self._call(
            env, resolver, "read_file", {"path": PROMPT}, meta={"acgs-credential": token}
        )
        assert "helpful assistant" in text
        # The derived principal is the directory's AGENT, so a core write is
        # denied by the core invariants (opaque reference only).
        text = await self._call(
            env,
            resolver,
            "write_file",
            {"path": POLICY_PATH, "content": "statements: []\n"},
            meta={"acgs-credential": token},
        )
        assert re.fullmatch(r"denied \(ref [0-9a-f]{12}\)", text)
        assert ("write_file", POLICY_PATH) not in env.tool_calls

    async def test_credential_in_arguments_is_ignored(self, env: DemoEnvironment) -> None:
        pytest.importorskip("mcp")
        from acgs_lite.integrations.control_plane_mcp import credential_principal_resolver

        resolver = credential_principal_resolver(env.cp.credentials)
        token = _agent_token(env)
        text = await self._call(
            env, resolver, "read_file", {"path": PROMPT, "acgs-credential": token}
        )
        assert text == "denied: principal could not be resolved"
        text = await self._call(
            env, resolver, "read_file", {"path": PROMPT}, meta={"acgs-credential": "x.y"}
        )
        assert text == "denied: principal could not be resolved"

    async def test_host_asserted_human_label_denied(self, env: DemoEnvironment) -> None:
        # A legacy resolver that trusts a HUMAN label: the dispatcher still
        # requires an attested credential, so the call is denied.
        text = await self._call(env, lambda ctx: IMPOSTOR, "read_file", {"path": SUITE_PATH})
        assert re.fullmatch(r"denied \(ref [0-9a-f]{12}\)", text)

    def test_resolver_requires_identity_issuer(self, env: DemoEnvironment) -> None:
        pytest.importorskip("mcp")
        from acgs_lite.control_plane import CredentialIssuer
        from acgs_lite.integrations.control_plane_mcp import (
            CredentialPrincipalResolver,
            credential_principal_resolver,
        )

        with pytest.raises(TypeError, match="identity"):
            credential_principal_resolver(CredentialIssuer())
        with pytest.raises(ValueError, match="meta_key"):
            CredentialPrincipalResolver(env.cp.credentials, "")

        class Ctx:
            meta: Any = None

        with pytest.raises(PermissionError, match="no credential"):
            credential_principal_resolver(env.cp.credentials)(Ctx())
