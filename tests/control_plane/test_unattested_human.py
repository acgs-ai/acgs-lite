"""A host-asserted HUMAN kind is trusted only for read-only, non-core calls.

HUMAN principals skip the AGENT-only requester, ownership, merge, breaker,
autonomy and budget checks, so a dispatcher without identity attestation
(``require_credential`` + identity-backed issuer) must not take
``PrincipalKind.HUMAN`` on the caller's word: unless the host opts in with
``trust_host_identity=True`` an unattested HUMAN may run only read-only,
non-core calls below T2. These tests go through ``dispatch()``,
``adispatch()``, ``authorize_without_consuming()`` and the MCP adapter.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

from acgs_lite.control_plane import (
    ActionTier,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.approvals import SignedApproval
from acgs_lite.control_plane.credentials import CredentialIssuer
from acgs_lite.control_plane.identity import StaticIdentityDirectory, VerifiedHumanSession

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

ALICE = Principal("alice", PrincipalKind.HUMAN)
CORE_PATH = "evaluator/score.py"
UNATTESTED = "unattested HUMAN principal"
WRITE_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("quick_edit", {"path": "workspace/a.txt"}),
    ("merge_pr", {"pr": "7"}),
    ("push", {"branch": "feature"}),
]


def _dispatcher(
    pdp: PolicyDecisionPoint, calls: list[str], **kwargs: Any
) -> GovernedToolDispatcher:
    d = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            pdp.registry, [WriteGrant(ALICE.id, ALICE.kind, ("workspace/**",))]
        ),
        tool_tiers={
            "edit": ActionTier.T2,
            "quick_edit": ActionTier.T1,
            "merge_pr": ActionTier.T1,
            "push": ActionTier.T1,
            "read": ActionTier.T0,
            "read1": ActionTier.T1,
        },
        read_only_tools=frozenset({"read", "read1"}),
        **kwargs,
    )

    def edit(path: str) -> str:
        calls.append(path)
        return path

    def merge_pr(pr: str) -> str:
        calls.append(f"merge:{pr}")
        return pr

    def push(branch: str) -> str:
        calls.append(f"push:{branch}")
        return branch

    d.register("edit", edit, path_params={"path"}, merge_capable=False)
    d.register("quick_edit", edit, path_params={"path"}, merge_capable=False)
    d.register("read", edit, path_params={"path"}, merge_capable=False)
    d.register("read1", edit, path_params={"path"}, merge_capable=False)
    d.register("merge_pr", merge_pr, opaque_params={"pr"}, merge_capable=True)
    d.register(
        "push",
        push,
        opaque_params={"branch"},
        branch_param="branch",
        merge_capable=False,
        merge_capable_override_reason="test: branch-write tool",
    )
    return d


def _approve(
    d: GovernedToolDispatcher,
    approver_factory: Callable[..., Callable[..., SignedApproval]],
    args: dict[str, Any],
    **kw: Any,
) -> list[SignedApproval]:
    return [approver_factory("bob")(d.action_hash_for(ALICE, "edit", args, **kw))]


class TestUnattestedHumanDeniedByDefault:
    def test_t2_denied_even_with_valid_approval(
        self, gated_pdp: PolicyDecisionPoint, approver_factory: Any
    ) -> None:
        pytest.importorskip("cryptography")
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls)
        args = {"path": "workspace/a.txt"}
        approvals = _approve(d, approver_factory, args)
        with pytest.raises(ToolDenied, match=UNATTESTED):
            d.dispatch(ALICE, "edit", args, approvals=approvals)
        with pytest.raises(ToolDenied, match=UNATTESTED):
            d.authorize_without_consuming(ALICE, "edit", args, approvals=approvals)
        assert calls == []

    @pytest.mark.parametrize("tool", ["quick_edit", "read"])
    def test_core_path_denied_at_low_tier(self, gated_pdp: PolicyDecisionPoint, tool: str) -> None:
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls)
        with pytest.raises(ToolDenied, match=UNATTESTED):
            d.dispatch(ALICE, tool, {"path": CORE_PATH})
        assert calls == []

    @pytest.mark.parametrize(("tool", "args"), WRITE_CALLS)
    def test_t1_write_merge_and_branch_tools_denied(
        self, gated_pdp: PolicyDecisionPoint, tool: str, args: dict[str, Any]
    ) -> None:
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls)
        with pytest.raises(ToolDenied, match=UNATTESTED):
            d.dispatch(ALICE, tool, args)
        assert calls == []

    def test_t0_read_only_non_core_still_allowed(self, gated_pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls)
        d.dispatch(ALICE, "read", {"path": "workspace/a.txt"})
        assert calls == ["workspace/a.txt"]

    def test_adispatch_enforces_the_same_rule(self, gated_pdp: PolicyDecisionPoint) -> None:
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls)
        for tool, args in WRITE_CALLS:
            with pytest.raises(ToolDenied, match=UNATTESTED):
                asyncio.run(d.adispatch(ALICE, tool, args))
        assert calls == []
        asyncio.run(d.adispatch(ALICE, "read", {"path": "workspace/a.txt"}))
        assert calls == ["workspace/a.txt"]

    def test_mcp_adapter_enforces_the_same_rule(self, gated_pdp: PolicyDecisionPoint) -> None:
        pytest.importorskip("mcp")
        from acgs_lite.integrations.control_plane_mcp import make_mcp_call_tool_handler

        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls)
        handler = make_mcp_call_tool_handler(d, lambda ctx: ALICE)
        for tool, args in WRITE_CALLS:
            result = asyncio.run(handler(None, SimpleNamespace(name=tool, arguments=args)))
            assert result.is_error
            assert result.content[0].text.startswith("denied (ref ")
        assert calls == []
        ok = asyncio.run(
            handler(None, SimpleNamespace(name="read", arguments={"path": "workspace/a.txt"}))
        )
        assert not ok.is_error
        assert calls == ["workspace/a.txt"]

    def test_require_credential_without_identity_is_not_attestation(
        self, gated_pdp: PolicyDecisionPoint
    ) -> None:
        # A plain issuer signs whatever kind the host asserts at issue time.
        issuer = CredentialIssuer(registry=gated_pdp.registry)
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, credential_issuer=issuer, require_credential=True)
        token = issuer.issue(ALICE, scopes=["tool:quick_edit"]).token
        with pytest.raises(ToolDenied, match=UNATTESTED):
            d.dispatch(ALICE, "quick_edit", {"path": "workspace/a.txt"}, credential=token)
        assert calls == []


class TestTrustHostIdentityOptIn:
    def test_t2_allowed_with_approval(
        self, gated_pdp: PolicyDecisionPoint, approver_factory: Any
    ) -> None:
        pytest.importorskip("cryptography")
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, trust_host_identity=True)
        args = {"path": "workspace/a.txt"}
        d.dispatch(ALICE, "edit", args, approvals=_approve(d, approver_factory, args))
        assert calls == ["workspace/a.txt"]

    @pytest.mark.parametrize(("tool", "args"), WRITE_CALLS)
    def test_t1_write_merge_and_branch_tools_allowed(
        self, gated_pdp: PolicyDecisionPoint, tool: str, args: dict[str, Any]
    ) -> None:
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, trust_host_identity=True)
        d.dispatch(ALICE, tool, args)
        asyncio.run(d.adispatch(ALICE, tool, args))
        assert len(calls) == 2

    def test_mcp_adapter_allowed(self, gated_pdp: PolicyDecisionPoint) -> None:
        pytest.importorskip("mcp")
        from acgs_lite.integrations.control_plane_mcp import make_mcp_call_tool_handler

        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, trust_host_identity=True)
        handler = make_mcp_call_tool_handler(d, lambda ctx: ALICE)
        result = asyncio.run(handler(None, SimpleNamespace(name="merge_pr", arguments={"pr": "7"})))
        assert not result.is_error
        assert calls == ["merge:7"]

    def test_core_path_falls_through_to_existing_guards(
        self, gated_pdp: PolicyDecisionPoint
    ) -> None:
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, trust_host_identity=True)
        with pytest.raises(ToolDenied) as excinfo:
            d.dispatch(ALICE, "quick_edit", {"path": CORE_PATH})
        assert UNATTESTED not in excinfo.value.decision.reason
        assert calls == []

    @pytest.mark.parametrize("value", ["false", "True", 1, 0, None])
    def test_non_bool_opt_in_refused(self, gated_pdp: PolicyDecisionPoint, value: Any) -> None:
        with pytest.raises(TypeError, match="trust_host_identity must be a bool"):
            _dispatcher(gated_pdp, [], trust_host_identity=value)


class TestAttestedHumanUnaffected:
    @staticmethod
    def _attested(pdp: PolicyDecisionPoint) -> tuple[CredentialIssuer, VerifiedHumanSession]:
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        key = Ed25519ReceiptSigner.from_seed(b"A" * 32)
        directory = StaticIdentityDirectory.from_mapping(
            {
                "version": 1,
                "identities": [
                    {
                        "id": "root",
                        "kind": "human",
                        "admin": True,
                        "public_key": Ed25519ReceiptSigner.from_seed(b"R" * 32).public_key_hex(),
                    },
                    {"id": "alice", "kind": "human", "public_key": key.public_key_hex()},
                ],
            }
        )
        issuer = CredentialIssuer(registry=pdp.registry, identity=directory)
        auth = issuer.human_authenticator
        assert auth is not None
        challenge = auth.issue_challenge("alice")
        return issuer, auth.verify_response(challenge, key.sign(challenge.message))

    def test_attested_human_t2_executes_with_approval(
        self, gated_pdp: PolicyDecisionPoint, approver_factory: Any
    ) -> None:
        pytest.importorskip("cryptography")
        issuer, session = self._attested(gated_pdp)
        token = issuer.issue_for_human(session, scopes=["tool:edit"]).token
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, credential_issuer=issuer, require_credential=True)
        args = {"path": "workspace/a.txt"}
        with pytest.raises(ToolDenied) as excinfo:  # still needs its approval
            d.dispatch(ALICE, "edit", args, credential=token)
        assert UNATTESTED not in excinfo.value.decision.reason
        d.dispatch(
            ALICE, "edit", args, approvals=_approve(d, approver_factory, args), credential=token
        )
        assert calls == ["workspace/a.txt"]

    def test_attested_human_t1_merge_runs(self, gated_pdp: PolicyDecisionPoint) -> None:
        pytest.importorskip("cryptography")
        issuer, session = self._attested(gated_pdp)
        token = issuer.issue_for_human(session, scopes=["tool:merge_pr"]).token
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, credential_issuer=issuer, require_credential=True)
        d.dispatch(ALICE, "merge_pr", {"pr": "7"}, credential=token)
        assert calls == ["merge:7"]

    def test_opt_in_with_attested_identity_refused(self, gated_pdp: PolicyDecisionPoint) -> None:
        pytest.importorskip("cryptography")
        issuer, _ = self._attested(gated_pdp)
        with pytest.raises(ValueError, match="trust_host_identity"):
            _dispatcher(
                gated_pdp,
                [],
                credential_issuer=issuer,
                require_credential=True,
                trust_host_identity=True,
            )


def _seed_workspace(pdp: PolicyDecisionPoint) -> None:
    import os

    root = pdp.registry.repo_root
    assert root is not None
    os.makedirs(os.path.join(root, "workspace", "deploy"), exist_ok=True)
    with open(os.path.join(root, "workspace", ".env"), "w", encoding="utf-8") as fh:
        fh.write("API_KEY=leak")
    with open(os.path.join(root, "workspace", "deploy", "credentials.json"), "w") as fh:
        fh.write("{}")


class TestDirectoryReadGuard:
    """An unattested HUMAN gets the non-human directory-read guard."""

    @pytest.mark.parametrize("target", ["workspace", "workspace/deploy"])
    def test_unattested_directory_read_denied(
        self, gated_pdp: PolicyDecisionPoint, target: str
    ) -> None:
        _seed_workspace(gated_pdp)
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls)
        with pytest.raises(ToolDenied, match="directory-like read target"):
            d.dispatch(ALICE, "read", {"path": target})
        with pytest.raises(ToolDenied, match="directory-like read target"):
            asyncio.run(d.adispatch(ALICE, "read", {"path": target}))
        assert calls == []

    def test_trusted_host_directory_read_allowed(self, gated_pdp: PolicyDecisionPoint) -> None:
        _seed_workspace(gated_pdp)
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, trust_host_identity=True)
        d.dispatch(ALICE, "read", {"path": "workspace"})
        asyncio.run(d.adispatch(ALICE, "read", {"path": "workspace"}))
        assert calls == ["workspace", "workspace"]

    def test_attested_directory_read_allowed(self, gated_pdp: PolicyDecisionPoint) -> None:
        pytest.importorskip("cryptography")
        _seed_workspace(gated_pdp)
        issuer, session = TestAttestedHumanUnaffected._attested(gated_pdp)
        token = issuer.issue_for_human(session, scopes=["tool:read"]).token
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, credential_issuer=issuer, require_credential=True)
        d.dispatch(ALICE, "read", {"path": "workspace"}, credential=token)
        assert calls == ["workspace"]


class TestRelabelledAgentStaysGoverned:
    """Autonomy and budget state is keyed by id: an agent claiming HUMAN on
    a dispatcher without attestation keeps its demotion and budget."""

    IMPOSTOR = Principal("agent-1", PrincipalKind.HUMAN, system_id="sys-a")
    AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")

    def test_demoted_agent_relabelled_human_is_p0_only(
        self, gated_pdp: PolicyDecisionPoint
    ) -> None:
        from acgs_lite.control_plane.autonomy import AutonomyController, ErrorBudget

        autonomy = AutonomyController(ErrorBudget(window_s=60, max_failures=3))
        autonomy.demote(self.AGENT, "test demotion")
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, autonomy=autonomy)
        with pytest.raises(ToolDenied, match="P0_ONLY"):
            d.dispatch(self.IMPOSTOR, "read1", {"path": "workspace/a.txt"})
        d.dispatch(self.IMPOSTOR, "read", {"path": "workspace/a.txt"})  # T0 read stays
        d.dispatch(ALICE, "read1", {"path": "workspace/b.txt"})  # undemoted human
        trusted = _dispatcher(gated_pdp, calls, autonomy=autonomy, trust_host_identity=True)
        trusted.dispatch(self.IMPOSTOR, "read1", {"path": "workspace/c.txt"})
        assert calls == ["workspace/a.txt", "workspace/b.txt", "workspace/c.txt"]

    def test_exhausted_agent_relabelled_human_denied(self, gated_pdp: PolicyDecisionPoint) -> None:
        from acgs_lite.control_plane.budgets import BudgetLedger, BudgetLimits

        budgets = BudgetLedger()
        budgets.start_run(self.AGENT, BudgetLimits(iterations=1))
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, budgets=budgets)
        d.dispatch(self.IMPOSTOR, "read", {"path": "workspace/a.txt"})
        with pytest.raises(ToolDenied, match="budget exhausted"):
            d.dispatch(self.IMPOSTOR, "read", {"path": "workspace/a.txt"})
        # A human the host never budgeted is not denied for lacking a run.
        d.dispatch(ALICE, "read", {"path": "workspace/b.txt"})
        assert calls == ["workspace/a.txt", "workspace/b.txt"]
