"""Phase 3: short-TTL scoped credentials issued by the harness, not the agent."""

from __future__ import annotations

import pickle

import pytest

from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    GovernedToolDispatcher,
    PolicyDecisionPoint,
    Principal,
    PrincipalKind,
    RepositoryPermissions,
    ToolDenied,
    WriteGrant,
)
from acgs_lite.control_plane.credentials import (
    CredentialInvalid,
    CredentialIssuanceRefused,
    CredentialIssuer,
    scope_touches_core,
)

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")
OTHER = Principal("agent-2", PrincipalKind.AGENT, system_id="sys-a")
ALICE = Principal("alice", PrincipalKind.HUMAN)


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def issuer(clock: Clock) -> CredentialIssuer:
    return CredentialIssuer(clock=clock)


class TestIssuer:
    def test_round_trip(self, issuer: CredentialIssuer) -> None:
        cred = issuer.issue(AGENT, scopes={"tool:write"})
        verified = issuer.verify(cred.token, required_scope="tool:write", principal=AGENT)
        assert verified.credential_id == cred.credential_id
        assert verified.principal_id == "agent-1"
        assert cred.expires_at - cred.issued_at == 300
        assert issuer.issue(AGENT, scopes="tool:write").scopes == frozenset({"tool:write"})

    def test_agent_cannot_mint_for_others_or_for_core(self, issuer: CredentialIssuer) -> None:
        with pytest.raises(CredentialIssuanceRefused):
            issuer.issue(OTHER, scopes={"tool:write"}, requester=AGENT)
        issuer.issue(AGENT, scopes={"tool:write"}, requester=AGENT)
        for scope in ("policy:update", "path:evaluator/x.py", "core:*", "admin", "path:*"):
            with pytest.raises(CredentialIssuanceRefused, match="core"):
                issuer.issue(AGENT, scopes={scope}, requester=AGENT)
            with pytest.raises(CredentialIssuanceRefused, match="core"):
                issuer.issue(AGENT, scopes={scope})  # not even the harness
            with pytest.raises(CredentialIssuanceRefused):
                issuer.issue(ALICE, scopes={scope}, requester=AGENT)
            with pytest.raises(CredentialIssuanceRefused, match="core"):
                issuer.issue(
                    ALICE, scopes={scope}, requester=Principal("svc", PrincipalKind.SERVICE)
                )
        assert issuer.issue(ALICE, scopes={"policy:update"}).scopes == {"policy:update"}
        with pytest.raises(CredentialIssuanceRefused):
            issuer.issue(AGENT, scopes={"tool:x"}, requester="agent-1")  # type: ignore[arg-type]
        with pytest.raises(CredentialIssuanceRefused):
            issuer.issue("agent-1", scopes={"tool:x"})  # type: ignore[arg-type]
        with pytest.raises(CredentialIssuanceRefused):
            issuer.issue(AGENT, scopes=set())
        with pytest.raises(CredentialIssuanceRefused):
            issuer.issue(AGENT, scopes={"bad scope"})

    def test_ttl_cap(self, issuer: CredentialIssuer) -> None:
        assert issuer.max_ttl_s == 900
        issuer.issue(AGENT, scopes={"tool:write"}, ttl_s=900)
        for bad in (901, 0, -1, float("inf"), True):
            with pytest.raises(CredentialIssuanceRefused):
                issuer.issue(AGENT, scopes={"tool:write"}, ttl_s=bad)

    def test_expired(self, issuer: CredentialIssuer, clock: Clock) -> None:
        cred = issuer.issue(AGENT, scopes={"tool:write"}, ttl_s=10)
        clock.now += 10
        with pytest.raises(CredentialInvalid, match="expired"):
            issuer.verify(cred.token, required_scope="tool:write")
        issuer.verify(cred.token, required_scope="tool:write", now=clock.now - 5)

    def test_revocation(self, issuer: CredentialIssuer) -> None:
        one = issuer.issue(AGENT, scopes={"tool:write"})
        two = issuer.issue(AGENT, scopes={"tool:write"})
        issuer.revoke(one.credential_id)
        with pytest.raises(CredentialInvalid, match="revoked"):
            issuer.verify(one.token, required_scope="tool:write")
        issuer.verify(two.token, required_scope="tool:write")
        issuer.revoke_principal("AGENT-1")
        with pytest.raises(CredentialInvalid, match="epoch"):
            issuer.verify(two.token, required_scope="tool:write")
        fresh = issuer.issue(AGENT, scopes={"tool:write"})
        issuer.verify(fresh.token, required_scope="tool:write")

    def test_scope_principal_and_tamper(self, issuer: CredentialIssuer) -> None:
        cred = issuer.issue(AGENT, scopes={"tool:write"})
        with pytest.raises(CredentialInvalid, match="scope"):
            issuer.verify(cred.token, required_scope="tool:rm")
        with pytest.raises(CredentialInvalid, match="another principal"):
            issuer.verify(cred.token, required_scope="tool:write", principal=OTHER)
        body, mac = cred.token.split(".")
        flipped = body[:-2] + ("A" if body[-2] != "A" else "B") + body[-1]
        for bad in (
            flipped + "." + mac,
            body + "." + ("0" * len(mac)),
            "no-dot",
            "a.b.c",
            "!!!." + mac,
            42,
        ):
            with pytest.raises(CredentialInvalid):
                issuer.verify(bad, required_scope="tool:write")
        other_issuer = CredentialIssuer()
        with pytest.raises(CredentialInvalid, match="signature"):
            other_issuer.verify(cred.token, required_scope="tool:write")

    def test_configuration_and_key_hygiene(self) -> None:
        with pytest.raises(ValueError):
            CredentialIssuer(b"short")
        with pytest.raises(ValueError):
            CredentialIssuer(default_ttl_s=1000, max_ttl_s=900)
        for bad in (0, float("nan"), "5"):
            with pytest.raises(ValueError):
                CredentialIssuer(default_ttl_s=bad)  # type: ignore[arg-type]
        issuer = CredentialIssuer(b"k" * 32)
        assert "k" * 8 not in repr(issuer)
        with pytest.raises(TypeError):
            pickle.dumps(issuer)

    def test_scope_classification(self) -> None:
        assert not scope_touches_core("tool:write")
        assert not scope_touches_core("tool:*")
        assert not scope_touches_core("path:workspace/x")
        assert scope_touches_core("path:policies/a.yaml", DEFAULT_IMMUTABLE_CORE)
        assert scope_touches_core("iam:grant")


def _dispatcher(
    pdp: PolicyDecisionPoint, issuer: CredentialIssuer, calls: list[str]
) -> GovernedToolDispatcher:
    d = GovernedToolDispatcher(
        pdp,
        permissions=RepositoryPermissions(
            pdp.registry, [WriteGrant("agent-1", PrincipalKind.AGENT, ("workspace/**",))]
        ),
        tool_tiers={"write": ActionTier.T1},
        credential_issuer=issuer,
        require_credential=True,
    )

    def write(path: str) -> str:
        calls.append(path)
        return "ok"

    d.register("write", write, path_params={"path"}, merge_capable=False)
    return d


class TestDispatcherRequiresCredential:
    def test_paths(self, pdp: PolicyDecisionPoint, issuer: CredentialIssuer, clock: Clock) -> None:
        calls: list[str] = []
        d = _dispatcher(pdp, issuer, calls)
        args = {"path": "workspace/a"}
        with pytest.raises(ToolDenied, match="credential"):
            d.dispatch(AGENT, "write", args)
        good = issuer.issue(AGENT, scopes={"tool:write"}, ttl_s=60)
        d.dispatch(AGENT, "write", args, credential=good.token)
        wrong_scope = issuer.issue(AGENT, scopes={"tool:other"})
        foreign = issuer.issue(OTHER, scopes={"tool:write"})
        for token in (wrong_scope.token, foreign.token, good.token + "x"):
            with pytest.raises(ToolDenied):
                d.dispatch(AGENT, "write", args, credential=token)
        issuer.revoke(good.credential_id)
        with pytest.raises(ToolDenied, match="revoked"):
            d.dispatch(AGENT, "write", args, credential=good.token)
        expiring = issuer.issue(AGENT, scopes={"tool:write"}, ttl_s=5)
        clock.now += 5
        with pytest.raises(ToolDenied, match="expired"):
            d.dispatch(AGENT, "write", args, credential=expiring.token)
        assert calls == ["workspace/a"]

    def test_construction_rules(self, pdp: PolicyDecisionPoint) -> None:
        permissions = RepositoryPermissions(pdp.registry)
        with pytest.raises(ValueError):
            GovernedToolDispatcher(
                pdp, permissions=permissions, tool_tiers={}, require_credential=True
            )
        with pytest.raises(TypeError):
            GovernedToolDispatcher(
                pdp,
                permissions=permissions,
                tool_tiers={},
                credential_issuer=object(),  # type: ignore[arg-type]
            )
