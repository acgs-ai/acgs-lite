"""A host-asserted HUMAN kind is not trusted at T2+ or on immutable core.

HUMAN principals skip the AGENT-only requester, breaker, autonomy and budget
checks, so a direct dispatcher (no identity-backed credential issuer) must not
take ``PrincipalKind.HUMAN`` on the caller's word. These tests go through
``dispatch()`` / ``authorize_without_consuming()``.
"""

from __future__ import annotations

from collections.abc import Callable
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


def _dispatcher(
    pdp: PolicyDecisionPoint, calls: list[str], **kwargs: Any
) -> GovernedToolDispatcher:
    d = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            pdp.registry, [WriteGrant(ALICE.id, ALICE.kind, ("workspace/**",))]
        ),
        tool_tiers={"edit": ActionTier.T2, "quick_edit": ActionTier.T1, "read": ActionTier.T0},
        read_only_tools=frozenset({"read"}),
        **kwargs,
    )

    def edit(path: str) -> str:
        calls.append(path)
        return path

    d.register("edit", edit, path_params={"path"}, merge_capable=False)
    d.register("quick_edit", edit, path_params={"path"}, merge_capable=False)
    d.register("read", edit, path_params={"path"}, merge_capable=False)
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

    @pytest.mark.parametrize("tool", ["quick_edit", "read"])
    def test_low_tier_non_core_still_allowed(
        self, gated_pdp: PolicyDecisionPoint, tool: str
    ) -> None:
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls)
        d.dispatch(ALICE, tool, {"path": "workspace/a.txt"})
        assert calls == ["workspace/a.txt"]

    def test_require_credential_without_identity_is_not_attestation(
        self, gated_pdp: PolicyDecisionPoint, approver_factory: Any
    ) -> None:
        # A plain issuer signs whatever kind the host asserts at issue time.
        pytest.importorskip("cryptography")
        issuer = CredentialIssuer(registry=gated_pdp.registry)
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, credential_issuer=issuer, require_credential=True)
        token = issuer.issue(ALICE, scopes=["tool:edit"]).token
        args = {"path": "workspace/a.txt"}
        approvals = _approve(d, approver_factory, args)
        with pytest.raises(ToolDenied, match=UNATTESTED):
            d.dispatch(ALICE, "edit", args, approvals=approvals, credential=token)
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

    def test_core_path_falls_through_to_existing_guards(
        self, gated_pdp: PolicyDecisionPoint
    ) -> None:
        calls: list[str] = []
        d = _dispatcher(gated_pdp, calls, trust_host_identity=True)
        with pytest.raises(ToolDenied) as excinfo:
            d.dispatch(ALICE, "quick_edit", {"path": CORE_PATH})
        assert UNATTESTED not in excinfo.value.decision.reason
        assert calls == []


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
