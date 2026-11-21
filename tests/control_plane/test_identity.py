"""Phase 6a: the identity directory, human challenge-response, attested
credential issuance and the admin attestor."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from acgs_lite.control_plane import (  # noqa: E402
    ADMIN_SCOPE,
    DEFAULT_IMMUTABLE_CORE,
    AdminAttestationFailed,
    AdminAttestor,
    CredentialInvalid,
    CredentialIssuanceRefused,
    CredentialIssuer,
    HumanAuthenticationFailed,
    HumanAuthenticator,
    HumanChallenge,
    IdentityDirectoryError,
    IdentityEntry,
    IdentityProvider,
    Principal,
    PrincipalKind,
    StaticIdentityDirectory,
    VerifiedHumanSession,
)
from acgs_lite.control_plane.identity import checked_attestor  # noqa: E402
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.red_team]

ALICE_KEY = Ed25519ReceiptSigner.from_seed(b"A" * 32)
BOB_KEY = Ed25519ReceiptSigner.from_seed(b"B" * 32)
MALLORY_KEY = Ed25519ReceiptSigner.from_seed(b"M" * 32)
ALICE = Principal("alice", PrincipalKind.HUMAN)
BOB = Principal("bob", PrincipalKind.HUMAN)
BOT = Principal("bot-1", PrincipalKind.AGENT, system_id="sys-a")
SVC = Principal("svc", PrincipalKind.SERVICE)


def _data(*extra: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": 1,
        "identities": [
            {
                "id": "alice",
                "kind": "human",
                "admin": True,
                "public_key": ALICE_KEY.public_key_hex(),
            },
            {
                "id": "bob",
                "kind": "human",
                "roles": ["sre"],
                "public_key": BOB_KEY.public_key_hex(),
            },
            {"id": "bot-1", "kind": "agent", "system_id": "sys-a"},
            {"id": "svc", "kind": "service"},
            *extra,
        ],
    }


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def directory() -> StaticIdentityDirectory:
    return StaticIdentityDirectory.from_mapping(_data())


@pytest.fixture()
def issuer(directory: StaticIdentityDirectory, clock: Clock) -> CredentialIssuer:
    return CredentialIssuer(identity=directory, clock=clock)


def _session(issuer: CredentialIssuer, who: str, key: Ed25519ReceiptSigner) -> VerifiedHumanSession:
    auth = issuer.human_authenticator
    assert auth is not None
    challenge = auth.issue_challenge(who)
    return auth.verify_response(challenge, key.sign(challenge.message))


class TestDirectory:
    def test_entries_and_lookup(self, directory: StaticIdentityDirectory) -> None:
        assert isinstance(directory, IdentityProvider)
        assert directory.admin.id == "alice" and directory.admin.admin
        bob = directory.lookup("BOB")
        assert bob is not None and bob.roles == frozenset({"sre"})
        assert bob.principal() == Principal("bob", PrincipalKind.HUMAN, roles=frozenset({"sre"}))
        bot = directory.lookup("bot-1")
        assert bot is not None and bot.system_id == "sys-a" and bot.public_key_hex is None
        assert directory.lookup("nobody") is None
        assert directory.lookup(42) is None  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        ("data", "match"),
        [
            ("not a mapping", "version"),
            ({"version": 2, "identities": []}, "version"),
            ({"version": 1, "identities": {}}, "list"),
            ({"version": 1, "identities": [], "extra": 1}, "version"),
        ],
    )
    def test_malformed_document(self, data: Any, match: str) -> None:
        with pytest.raises(IdentityDirectoryError, match=match):
            StaticIdentityDirectory.from_mapping(data)

    @pytest.mark.parametrize(
        ("entry", "match"),
        [
            ("x", "mapping"),
            ({"id": "x", "kind": "agent", "groups": []}, "unknown keys"),
            ({"id": "x", "kind": "root"}, "invalid kind"),
            ({"id": "x", "kind": "agent", "roles": "sre"}, "roles"),
            ({"id": "x", "kind": "agent", "roles": [""]}, "roles"),
            ({"id": "x", "kind": "agent", "admin": "yes"}, "boolean"),
            ({"id": "x", "kind": "human"}, "public_key"),
            ({"id": "x", "kind": "human", "public_key": "AB" * 32}, "public_key"),
            ({"id": "x", "kind": "agent", "public_key": "ab" * 32}, "human entries only"),
            ({"id": 7, "kind": "agent"}, "strings"),
            ({"id": "x", "kind": "agent", "system_id": 3}, "strings"),
            ({"id": "bad id", "kind": "agent"}, "canonical"),
            ({"id": "ALICE", "kind": "agent"}, "duplicate"),
            ({"id": "root", "kind": "agent", "admin": True}, "exactly one admin"),
        ],
    )
    def test_malformed_entry(self, entry: Any, match: str) -> None:
        with pytest.raises(IdentityDirectoryError, match=match):
            StaticIdentityDirectory.from_mapping(_data(entry))

    def test_admin_must_be_one_human(self) -> None:
        with pytest.raises(IdentityDirectoryError, match="exactly one admin entry, found 0"):
            StaticIdentityDirectory([IdentityEntry("svc", PrincipalKind.SERVICE)])
        with pytest.raises(IdentityDirectoryError, match="must be a human"):
            StaticIdentityDirectory([IdentityEntry("svc", PrincipalKind.SERVICE, admin=True)])
        with pytest.raises(IdentityDirectoryError, match="IdentityEntry"):
            StaticIdentityDirectory(["alice"])  # type: ignore[list-item]

    def test_load_requires_iam_core(self, tmp_path: Path) -> None:
        import yaml

        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        (tmp_path / "iam").mkdir()
        (tmp_path / "iam" / "identities.yaml").write_text(yaml.safe_dump(_data()))
        loaded = StaticIdentityDirectory.load("iam/identities.yaml", registry)
        assert loaded.admin.id == "alice"
        (tmp_path / "workspace").mkdir()
        (tmp_path / "workspace" / "ids.yaml").write_text(yaml.safe_dump(_data()))
        with pytest.raises(IdentityDirectoryError, match="iam"):
            StaticIdentityDirectory.load("workspace/ids.yaml", registry)
        with pytest.raises(IdentityDirectoryError, match="unreadable"):
            StaticIdentityDirectory.load("iam/missing.yaml", registry)
        (tmp_path / "iam" / "broken.yaml").write_text("identities: [")
        with pytest.raises(IdentityDirectoryError, match="unreadable"):
            StaticIdentityDirectory.load("iam/broken.yaml", registry)
        with pytest.raises(IdentityDirectoryError, match="repo_root"):
            StaticIdentityDirectory.load("iam/identities.yaml", DEFAULT_IMMUTABLE_CORE)


class TestHumanAuthenticator:
    def test_round_trip_principal_from_directory(
        self, directory: StaticIdentityDirectory, clock: Clock
    ) -> None:
        auth = HumanAuthenticator(directory, clock=clock)
        assert auth.identity is directory
        challenge = auth.issue_challenge("Bob")
        assert challenge.principal_id == "bob" and challenge.expires_at == 1_060.0
        session = auth.verify_response(challenge, BOB_KEY.sign(challenge.message))
        # Kind, system_id and roles come from the directory, never the caller.
        assert session.principal == Principal("bob", PrincipalKind.HUMAN, roles=frozenset({"sre"}))
        assert auth.redeem(session) == session.principal
        with pytest.raises(HumanAuthenticationFailed, match="already redeemed"):
            auth.redeem(session)

    @pytest.mark.parametrize("who", ["bot-1", "svc", "nobody", 7])
    def test_challenge_only_for_directory_humans(
        self, directory: StaticIdentityDirectory, who: Any
    ) -> None:
        with pytest.raises(HumanAuthenticationFailed, match="not a human"):
            HumanAuthenticator(directory).issue_challenge(who)

    def test_replay_refused(self, directory: StaticIdentityDirectory) -> None:
        auth = HumanAuthenticator(directory)
        challenge = auth.issue_challenge("alice")
        signature = ALICE_KEY.sign(challenge.message)
        auth.verify_response(challenge, signature)
        with pytest.raises(HumanAuthenticationFailed, match="already used"):
            auth.verify_response(challenge, signature)

    def test_expired_challenge_refused(
        self, directory: StaticIdentityDirectory, clock: Clock
    ) -> None:
        auth = HumanAuthenticator(directory, clock=clock)
        challenge = auth.issue_challenge("alice")
        clock.now += 60
        with pytest.raises(HumanAuthenticationFailed, match="expired"):
            auth.verify_response(challenge, ALICE_KEY.sign(challenge.message))
        # Expired challenges are pruned on the next issue.
        auth.issue_challenge("alice")

    def test_wrong_key_refused_and_consumed(self, directory: StaticIdentityDirectory) -> None:
        auth = HumanAuthenticator(directory)
        challenge = auth.issue_challenge("alice")
        with pytest.raises(HumanAuthenticationFailed, match="bad challenge signature"):
            auth.verify_response(challenge, MALLORY_KEY.sign(challenge.message))
        # One attempt only: the correct signature no longer works.
        with pytest.raises(HumanAuthenticationFailed, match="already used"):
            auth.verify_response(challenge, ALICE_KEY.sign(challenge.message))

    def test_another_persons_challenge_refused(self, directory: StaticIdentityDirectory) -> None:
        auth = HumanAuthenticator(directory)
        alices = auth.issue_challenge("alice")
        # Bob signs Alice's challenge with his own (valid, pinned) key.
        with pytest.raises(HumanAuthenticationFailed, match="bad challenge signature"):
            auth.verify_response(alices, BOB_KEY.sign(alices.message))
        # Relabelling the challenge copy to Bob does not help either.
        alices = auth.issue_challenge("alice")
        relabelled = dataclasses.replace(alices, principal_id="bob")
        with pytest.raises(HumanAuthenticationFailed, match="does not match"):
            auth.verify_response(relabelled, BOB_KEY.sign(relabelled.message))

    def test_malformed_inputs_refused(self, directory: StaticIdentityDirectory) -> None:
        auth = HumanAuthenticator(directory)
        with pytest.raises(HumanAuthenticationFailed, match="HumanChallenge"):
            auth.verify_response("challenge", "00")  # type: ignore[arg-type]
        forged = HumanChallenge("c" * 32, "alice", "0" * 64, 9e12)
        with pytest.raises(HumanAuthenticationFailed, match="unknown"):
            auth.verify_response(forged, ALICE_KEY.sign(forged.message))
        challenge = auth.issue_challenge("alice")
        with pytest.raises(HumanAuthenticationFailed, match="malformed signature"):
            auth.verify_response(challenge, "zz")
        with pytest.raises(HumanAuthenticationFailed, match="VerifiedHumanSession"):
            auth.redeem("session")  # type: ignore[arg-type]

    def test_forged_and_expired_sessions_refused(
        self, directory: StaticIdentityDirectory, clock: Clock
    ) -> None:
        auth = HumanAuthenticator(directory, clock=clock)
        forged = VerifiedHumanSession("s" * 32, ALICE, clock.now, clock.now + 60)
        with pytest.raises(HumanAuthenticationFailed, match="unknown"):
            auth.redeem(forged)
        challenge = auth.issue_challenge("alice")
        session = auth.verify_response(challenge, ALICE_KEY.sign(challenge.message))
        with pytest.raises(HumanAuthenticationFailed, match="unknown"):
            auth.redeem(dataclasses.replace(session, principal=BOB))
        challenge = auth.issue_challenge("alice")
        session = auth.verify_response(challenge, ALICE_KEY.sign(challenge.message))
        clock.now += 61
        with pytest.raises(HumanAuthenticationFailed, match="expired"):
            auth.redeem(session)

    def test_global_cap_evicts_oldest(
        self, directory: StaticIdentityDirectory, monkeypatch: Any
    ) -> None:
        import acgs_lite.control_plane.identity as identity_module

        monkeypatch.setattr(identity_module, "MAX_PENDING", 2)
        auth = HumanAuthenticator(directory)
        oldest = auth.issue_challenge("alice")
        auth.issue_challenge("bob")
        newest = auth.issue_challenge("alice")  # evicts the oldest, never refuses
        with pytest.raises(HumanAuthenticationFailed, match="unknown or already used"):
            auth.verify_response(oldest, ALICE_KEY.sign(oldest.message))
        auth.verify_response(newest, ALICE_KEY.sign(newest.message))
        monkeypatch.setattr(identity_module, "MAX_PENDING", 1)
        second = auth.issue_challenge("alice")
        with pytest.raises(HumanAuthenticationFailed, match="too many open sessions"):
            auth.verify_response(second, ALICE_KEY.sign(second.message))

    def test_per_principal_cap_evicts_that_principals_oldest(
        self, directory: StaticIdentityDirectory, monkeypatch: Any
    ) -> None:
        import acgs_lite.control_plane.identity as identity_module

        monkeypatch.setattr(identity_module, "MAX_PENDING_PER_PRINCIPAL", 2)
        auth = HumanAuthenticator(directory)
        first = auth.issue_challenge("alice")
        bobs = auth.issue_challenge("bob")
        second = auth.issue_challenge("alice")
        third = auth.issue_challenge("ALICE")  # evicts Alice's oldest only
        with pytest.raises(HumanAuthenticationFailed, match="unknown or already used"):
            auth.verify_response(first, ALICE_KEY.sign(first.message))
        for challenge, key in ((second, ALICE_KEY), (third, ALICE_KEY), (bobs, BOB_KEY)):
            auth.verify_response(challenge, key.sign(challenge.message))

    def test_construction_validated(self, directory: StaticIdentityDirectory) -> None:
        with pytest.raises(TypeError, match="IdentityProvider"):
            HumanAuthenticator("directory")  # type: ignore[arg-type]
        for bad in (0, -1, True, "60"):
            with pytest.raises(ValueError, match="positive"):
                HumanAuthenticator(directory, challenge_ttl_s=bad)  # type: ignore[arg-type]


class TestAttestedIssuance:
    @pytest.mark.parametrize("human", [False, True])
    def test_fractional_clock_near_token_limit_is_rejected_before_issuance(
        self, issuer: CredentialIssuer, clock: Clock, human: bool
    ) -> None:
        clock.now = 1794140000.1234567
        scopes = {f"tool:{i:03d}" + "a" * 240 for i in range(48)}
        scopes.add("tool:" + "b" * (32 if human else 30))
        if human:
            session = _session(issuer, "alice", ALICE_KEY)
            with pytest.raises(CredentialIssuanceRefused, match="exceed"):
                issuer.issue_for_human(session, scopes=scopes)
            token = issuer.issue_for_human(session, scopes=["tool:x"])
            assert issuer.authenticate(token.token).principal_id == "alice"
        else:
            plain = CredentialIssuer(clock=clock)
            with pytest.raises(CredentialIssuanceRefused, match="exceed"):
                plain.issue(Principal("agent-1", PrincipalKind.AGENT), scopes=scopes)

    @pytest.mark.parametrize("invalid", ["size", "scopes", "ttl"])
    def test_invalid_human_issuance_preserves_session(
        self, issuer: CredentialIssuer, invalid: str
    ) -> None:
        session = _session(issuer, "alice", ALICE_KEY)
        scopes = (
            [f"tool:{'a' * 240}{index:03d}" for index in range(80)]
            if invalid == "size"
            else ([] if invalid == "scopes" else ["tool:x"])
        )
        with pytest.raises(CredentialIssuanceRefused):
            issuer.issue_for_human(session, scopes=scopes, ttl_s=-1 if invalid == "ttl" else None)
        credential = issuer.issue_for_human(session, scopes=["tool:x"])
        assert issuer.authenticate(credential.token).principal_id == "alice"

    def test_unknown_id_refused(self, issuer: CredentialIssuer) -> None:
        with pytest.raises(CredentialIssuanceRefused, match="not in the identity directory"):
            issuer.issue(Principal("bot-9", PrincipalKind.AGENT), scopes={"tool:x"})

    def test_kind_or_system_id_differing_from_directory_refused(
        self, issuer: CredentialIssuer
    ) -> None:
        with pytest.raises(CredentialIssuanceRefused, match="differs from the directory"):
            issuer.issue(Principal("bot-1", PrincipalKind.SERVICE, "sys-a"), scopes={"tool:x"})
        with pytest.raises(CredentialIssuanceRefused, match="system_id differs"):
            issuer.issue(Principal("bot-1", PrincipalKind.AGENT, "sys-b"), scopes={"tool:x"})

    def test_human_only_through_issue_for_human(self, issuer: CredentialIssuer) -> None:
        # Even the real admin's id cannot be issued a HUMAN credential by label.
        with pytest.raises(CredentialIssuanceRefused, match="issue_for_human"):
            issuer.issue(ALICE, scopes={ADMIN_SCOPE})
        with pytest.raises(CredentialIssuanceRefused, match="issue_for_human"):
            issuer.issue(Principal("bot-1", PrincipalKind.HUMAN, "sys-a"), scopes={"tool:x"})
        cred = issuer.issue_for_human(_session(issuer, "alice", ALICE_KEY), scopes={ADMIN_SCOPE})
        assert cred.kind is PrincipalKind.HUMAN and cred.principal_id == "alice"
        verified = issuer.verify(cred.token, required_scope=ADMIN_SCOPE, principal=ALICE)
        assert verified.kind is PrincipalKind.HUMAN

    def test_issue_for_human_refusals(self, issuer: CredentialIssuer, clock: Clock) -> None:
        session = _session(issuer, "alice", ALICE_KEY)
        issuer.issue_for_human(session, scopes="tool:x")
        with pytest.raises(CredentialIssuanceRefused, match="already redeemed"):
            issuer.issue_for_human(session, scopes="tool:x")
        with pytest.raises(CredentialIssuanceRefused, match="scope strings"):
            issuer.issue_for_human(_session(issuer, "alice", ALICE_KEY), scopes=[])
        # A session from another authenticator over the same directory (the
        # caller still needs the key) is not redeemable by this issuer.
        other = HumanAuthenticator(issuer.identity, clock=clock)  # type: ignore[arg-type]
        challenge = other.issue_challenge("alice")
        foreign = other.verify_response(challenge, ALICE_KEY.sign(challenge.message))
        with pytest.raises(CredentialIssuanceRefused, match="human session refused"):
            issuer.issue_for_human(foreign, scopes="tool:x")
        with pytest.raises(CredentialIssuanceRefused, match="identity provider"):
            CredentialIssuer().issue_for_human(foreign, scopes="tool:x")

    def test_requester_checked_against_directory(self, issuer: CredentialIssuer) -> None:
        with pytest.raises(CredentialIssuanceRefused, match="requester"):
            issuer.issue(BOT, scopes={"tool:x"}, requester=Principal("ghost", PrincipalKind.HUMAN))
        with pytest.raises(CredentialIssuanceRefused, match="requester kind"):
            issuer.issue(BOT, scopes={"tool:x"}, requester=Principal("svc", PrincipalKind.HUMAN))
        assert issuer.issue(BOT, scopes={"tool:x"}, requester=SVC).kind is PrincipalKind.AGENT

    def test_kind_mismatch_on_verify(self, issuer: CredentialIssuer) -> None:
        token = issuer.issue(BOT, scopes={"tool:x"}).token
        impostor = Principal("bot-1", PrincipalKind.HUMAN, system_id="sys-a")
        with pytest.raises(CredentialInvalid, match="another principal kind"):
            issuer.verify(token, required_scope="tool:x", principal=impostor)
        # Identity-only verification skips the scope, never the kind.
        assert issuer.verify(token, required_scope=None, principal=BOT).principal_id == "bot-1"
        assert issuer.authenticate(token).kind is PrincipalKind.AGENT

    def test_constructor_and_properties(self, directory: StaticIdentityDirectory) -> None:
        with pytest.raises(TypeError, match="IdentityProvider"):
            CredentialIssuer(identity="directory")  # type: ignore[arg-type]
        legacy = CredentialIssuer()
        assert legacy.identity is None and legacy.human_authenticator is None
        attested = CredentialIssuer(identity=directory)
        assert attested.identity is directory
        assert isinstance(attested.human_authenticator, HumanAuthenticator)


class TestAdminAttestor:
    def test_requires_identity_issuer(self) -> None:
        with pytest.raises(TypeError, match="identity provider"):
            AdminAttestor(CredentialIssuer())
        with pytest.raises(TypeError, match="AdminAttestor"):
            checked_attestor("attestor")
        assert checked_attestor(None) is None

    def test_admin_credential_accepted(self, issuer: CredentialIssuer) -> None:
        attestor = AdminAttestor(issuer)
        assert attestor.admin == Principal("alice", PrincipalKind.HUMAN)
        token = issuer.issue_for_human(
            _session(issuer, "alice", ALICE_KEY), scopes={ADMIN_SCOPE}
        ).token
        assert attestor.require(ALICE, token) == ALICE
        assert checked_attestor(attestor) is attestor

    def test_refusals(self, issuer: CredentialIssuer) -> None:
        attestor = AdminAttestor(issuer)
        bob_admin = issuer.issue_for_human(
            _session(issuer, "bob", BOB_KEY), scopes={ADMIN_SCOPE}
        ).token
        alice_tool = issuer.issue_for_human(
            _session(issuer, "alice", ALICE_KEY), scopes={"tool:x"}
        ).token
        bot = issuer.issue(BOT, scopes={"tool:x"}).token
        cases: list[tuple[Any, Any, str]] = [
            ("alice", bob_admin, "actor must be a Principal"),
            (ALICE, None, "admin_credential is required"),
            (ALICE, "garbage", "malformed"),
            (ALICE, alice_tool, "lacks scope"),
            (ALICE, bob_admin, "another principal"),
            (BOB, bob_admin, "not the directory admin"),
            (BOT, bot, "lacks scope"),
        ]
        for actor, token, match in cases:
            with pytest.raises(AdminAttestationFailed, match=match):
                attestor.require(actor, token)
        # A delegated human (capability_admin path) attests as itself.
        assert attestor.require(BOB, bob_admin, admin_only=False).id == "bob"
        with pytest.raises(KeyError):
            attestor.require(ALICE, None, error=KeyError)

    def test_non_human_with_admin_scope_cannot_exist(self, issuer: CredentialIssuer) -> None:
        # scope_touches_core refuses "admin" scopes for non-humans at issuance.
        with pytest.raises(CredentialIssuanceRefused, match="core"):
            issuer.issue(BOT, scopes={ADMIN_SCOPE})


def test_admin_scope_reexports_share_neutral_definition() -> None:
    from acgs_lite.control_plane.credentials import ADMIN_SCOPE as credential_scope
    from acgs_lite.control_plane.identity import ADMIN_SCOPE as identity_scope
    from acgs_lite.control_plane.principal import ADMIN_SCOPE as principal_scope

    assert principal_scope == "admin:control-plane"
    assert credential_scope is principal_scope
    assert identity_scope is principal_scope
