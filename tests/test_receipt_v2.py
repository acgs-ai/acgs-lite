"""Receipt schema v2 (criterion 16): domain-separated hash, committed grant and policy.

Dispatcher-level tests mint through ``wrapped.issue_grant(...)``; every refusal asserts
the wrapped side effect never ran. Hash and wire tests pin v1 byte-compatibility.
"""

from __future__ import annotations

import random
from dataclasses import replace
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.constitution.rule import Rule
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import (
    RECEIPT_HASH_DOMAIN_V2,
    AuthorizationProfile,
    DecisionReceipt,
    ExecutionAuthority,
    ExecutionBoundary,
    LegitimacyInvariantError,
    receipt_identity,
    replay_and_verify,
)
from acgs_lite.legitimacy.authorization import EngineDecision, build_issue_receipt
from acgs_lite.legitimacy.invocation import bind_invocation, bind_policy
from acgs_lite.legitimacy.ledger import InProcessGrantLedger
from acgs_lite.legitimacy.receipt import BASELINE_CONSTRAINT_MARKER
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner, _receipt_from_dict

# Captured from origin/main 0cd5e56 (receipt.py unchanged there) before the v2 change.
GOLDEN_V1_HASH = "1733d4f44d414f94d6ec8706b13ba3b6268260c290ad89eaf11a85962ce28e56"

_ALLOW = EngineDecision("ALLOW", (BASELINE_CONSTRAINT_MARKER,), (), None, 1)


def _production_signing() -> dict[str, object]:
    """Pinned, non-ephemeral Ed25519 execution signer the production profile requires."""
    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    return {
        "receipt_signer": signer,
        "trusted_execution_keys": {signer.key_id: signer.public_key_hex()},
    }


def _boundary() -> ExecutionBoundary:
    return ExecutionBoundary(
        allowed_method="transfer",
        allowed_scope="tenant-a",
        allowed_subjects=("acct-1",),
        expires_at=None,
        single_use=True,
    )


def _golden_fields() -> dict[str, Any]:
    return {
        "request_id": "golden-req-1",
        "goal": "Golden v1 receipt",
        "proposed_method": "transfer",
        "decision_type": "ALLOW",
        "authority_basis": "acgs-lite:execution-authority",
        "matched_constraints": (BASELINE_CONSTRAINT_MARKER,),
        "policy_version": "608508a9bd224290",
        "required_controls": ("AUDIT_WARNINGS",),
        "transformation_applied": None,
        "denial_or_review_rationale": None,
        "execution_boundary": _boundary(),
        "issued_at": "2026-10-27T00:00:00+00:00",
    }


_V2_FIELDS: dict[str, Any] = {
    "schema_version": 2,
    "grant_id": "a" * 32,
    "policy_digest": "b" * 64,
    "method_id": "module:transfer",
    "argument_digest": "c" * 64,
}


def _guard(constitution: Constitution | None = None) -> GovernedCallable:
    return GovernedCallable(
        constitution or Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        **_production_signing(),
    )


# --- v1 compatibility --------------------------------------------------------


def test_golden_v1_hash_is_byte_identical_to_origin_main() -> None:
    receipt = DecisionReceipt.create(**_golden_fields())
    assert receipt.schema_version is None
    assert receipt.receipt_hash == GOLDEN_V1_HASH
    explicit = DecisionReceipt.create(**_golden_fields(), schema_version=1)
    assert explicit.receipt_hash == GOLDEN_V1_HASH


def test_v1_wire_shape_has_no_v2_keys_and_round_trips_as_v1() -> None:
    receipt = DecisionReceipt.create(**_golden_fields())
    wire = receipt.to_receipt_dict()
    assert set(wire) == set(_golden_fields()) | {"receipt_hash"}
    restored = _receipt_from_dict(wire)
    assert restored == receipt
    assert restored.schema_version is None
    assert restored.verify_hash()
    assert receipt_identity(restored).startswith("acgs:receipt:v1:sha256:")


def test_v1_signed_receipt_still_verifies() -> None:
    pytest.importorskip("cryptography")
    from acgs_lite.legitimacy import Ed25519ReceiptSigner, SignedReceipt, sign_receipt

    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    signed = sign_receipt(DecisionReceipt.create(**_golden_fields()), signer)
    restored = SignedReceipt.from_dict(signed.to_dict())
    assert restored.verify(signer.public_key_hex()) is True
    assert restored.receipt.receipt_hash == GOLDEN_V1_HASH


@pytest.mark.parametrize("field", sorted(set(_V2_FIELDS) - {"schema_version"}))
def test_v1_receipt_refuses_smuggled_v2_field(field: str) -> None:
    with pytest.raises(ValueError, match="v1 receipt"):
        DecisionReceipt.create(**_golden_fields(), **{field: _V2_FIELDS[field]})
    with pytest.raises(ValueError, match="v1 receipt"):
        DecisionReceipt.create(**_golden_fields(), context_digest="d" * 64)


# --- version tag ------------------------------------------------------------


@pytest.mark.parametrize("version", [0, 3, True, "2", 2.0])
def test_unknown_or_non_int_schema_version_is_refused(version: object) -> None:
    fields = {**_V2_FIELDS, "schema_version": version}
    with pytest.raises(ValueError, match="schema_version"):
        DecisionReceipt.create(**_golden_fields(), **fields)


@pytest.mark.parametrize("missing", ["grant_id", "policy_digest", "method_id", "argument_digest"])
def test_v2_requires_its_commitments(missing: str) -> None:
    fields = {**_V2_FIELDS, missing: None}
    with pytest.raises(ValueError, match=missing):
        DecisionReceipt.create(**_golden_fields(), **fields)
    fields[missing] = ""
    with pytest.raises(ValueError, match=missing):
        DecisionReceipt.create(**_golden_fields(), **fields)


def test_v2_context_digest_must_be_none_or_non_empty() -> None:
    with pytest.raises(ValueError, match="context_digest"):
        DecisionReceipt.create(**_golden_fields(), **_V2_FIELDS, context_digest="")


# --- domain separation -------------------------------------------------------


def test_v2_hash_is_domain_separated_and_omits_absent_extensions() -> None:
    import hashlib
    import json

    v1 = DecisionReceipt.create(**_golden_fields())
    v2 = DecisionReceipt.create(**_golden_fields(), **_V2_FIELDS)
    assert v2.receipt_hash != v1.receipt_hash
    wire = v2.to_receipt_dict(include_hash=False)
    # v1 nulls are kept; absent v2 extensions (context_digest=None) are omitted.
    assert wire["transformation_applied"] is None
    assert "context_digest" not in wire
    assert wire["schema_version"] == 2
    canonical = json.dumps(wire, sort_keys=True, separators=(",", ":"), allow_nan=False)
    expected = hashlib.sha256(RECEIPT_HASH_DOMAIN_V2 + canonical.encode("utf-8")).hexdigest()
    assert v2.receipt_hash == expected
    assert RECEIPT_HASH_DOMAIN_V2 == b"acgs-receipt-v2\x00"
    with_context = DecisionReceipt.create(**_golden_fields(), **_V2_FIELDS, context_digest="d" * 64)
    assert with_context.receipt_hash != v2.receipt_hash


def test_v1_and_v2_hashes_never_collide_over_random_receipts() -> None:
    rng = random.Random(16)
    for _ in range(50):
        fields = _golden_fields()
        fields["request_id"] = f"req-{rng.getrandbits(64):x}"
        fields["goal"] = rng.choice(["a", "b", "goal with spaces", "ünïcode"])
        fields["matched_constraints"] = tuple(
            f"R{rng.randrange(100)}" for _ in range(rng.randrange(1, 4))
        )
        v2_fields = {**_V2_FIELDS, "grant_id": f"{rng.getrandbits(128):032x}"}
        v1 = DecisionReceipt.create(**fields)
        v2 = DecisionReceipt.create(**fields, **v2_fields)
        assert v1.receipt_hash != v2.receipt_hash


def test_replace_across_versions_never_verifies() -> None:
    v1 = DecisionReceipt.create(**_golden_fields())
    v2 = DecisionReceipt.create(**_golden_fields(), **_V2_FIELDS)
    with pytest.raises(ValueError):
        replace(v1, **_V2_FIELDS)
    with pytest.raises(ValueError):
        replace(v2, schema_version=None)
    with pytest.raises(ValueError):
        replace(
            v2,
            schema_version=None,
            grant_id=None,
            policy_digest=None,
            method_id=None,
            argument_digest=None,
        )
    with pytest.raises(ValueError):
        replace(v2, grant_id="e" * 32)


def test_wire_v1_bytes_never_verify_as_v2_and_vice_versa() -> None:
    v1_wire = DecisionReceipt.create(**_golden_fields()).to_receipt_dict()
    v2_wire = DecisionReceipt.create(**_golden_fields(), **_V2_FIELDS).to_receipt_dict()

    # v1 payload relabelled as v2 (with v2 commitments) keeps the v1 hash: refused.
    with pytest.raises(ValueError, match="receipt_hash"):
        _receipt_from_dict({**v1_wire, **_V2_FIELDS})
    # v2 payload with schema_version stripped: v2 keys without the tag are refused.
    stripped = {k: v for k, v in v2_wire.items() if k != "schema_version"}
    with pytest.raises(ValueError, match="schema_version"):
        _receipt_from_dict(stripped)
    # v2 payload stripped down to v1 keys keeps the v2 hash: refused under v1 rules.
    v1_only = {k: v for k, v in v2_wire.items() if k not in _V2_FIELDS}
    with pytest.raises(ValueError, match="receipt_hash"):
        _receipt_from_dict(v1_only)
    # A v2 tag without its grant commitment is refused.
    no_grant = {k: v for k, v in v2_wire.items() if k != "grant_id"}
    with pytest.raises(ValueError, match="grant_id"):
        _receipt_from_dict(no_grant)
    # An explicit null schema_version still means v1, never v2.
    with pytest.raises(ValueError, match="schema_version"):
        _receipt_from_dict({**v2_wire, "schema_version": None})

    restored = _receipt_from_dict(v2_wire)
    assert restored.schema_version == 2
    assert restored.verify_hash()
    assert receipt_identity(restored).startswith("acgs:receipt:v2:sha256:")


# --- dispatcher level: issue_grant commits grant and policy ------------------


def test_issue_grant_mints_v2_receipt_committing_grant_and_policy() -> None:
    constitution = Constitution.default()
    guard = _guard(constitution)
    calls: list[str] = []

    @guard
    def act(text: str) -> str:
        calls.append(text)
        return text

    grant = act.issue_grant("What is the capital of France?")
    receipt = grant.receipt
    assert receipt.schema_version == 2
    assert receipt.grant_id == grant.grant_id
    assert receipt.policy_digest == bind_policy(constitution).digest == grant.policy_digest
    assert receipt.method_id == grant.method_id
    assert receipt.argument_digest == grant.argument_digest
    assert receipt.context_digest is None
    assert len(grant.grant_id) == 32 and int(grant.grant_id, 16) >= 0
    assert receipt.verify_hash()
    assert calls == []
    assert act("What is the capital of France?", execution_grant=grant) is not None
    assert calls == ["What is the capital of France?"]


def test_grant_id_is_never_accepted_from_callers() -> None:
    guard = _guard()
    calls: list[str] = []

    @guard
    def act(text: str) -> str:
        calls.append(text)
        return text

    with pytest.raises(TypeError, match="transport"):
        act.issue_grant("hello", grant_id="caller-made")
    invocation = bind_invocation(act.__wrapped__, ("hello",), {}, include_receiver=True)
    policy = bind_policy(guard.constitution)
    receipt = build_issue_receipt(
        func=act.__wrapped__,
        invocation=invocation,
        policy=policy,
        decision=_ALLOW,
        grant_id="caller-made",
    )
    with pytest.raises(LegitimacyInvariantError, match="not allocated"):
        guard._authority.issue(
            receipt=receipt, invocation=invocation, policy=policy, grant_id="caller-made"
        )
    assert calls == []


def test_one_receipt_mints_at_most_one_grant() -> None:
    guard = _guard()
    calls: list[str] = []

    @guard
    def act(text: str) -> str:
        calls.append(text)
        return text

    grant = act.issue_grant("hello")
    invocation = bind_invocation(act.__wrapped__, ("hello",), {}, include_receiver=True)
    policy = bind_policy(guard.constitution)
    with pytest.raises(LegitimacyInvariantError, match="already minted"):
        guard._authority.issue(receipt=grant.receipt, invocation=invocation, policy=policy)
    fresh_id = guard._authority.allocate_grant_id()
    with pytest.raises(LegitimacyInvariantError, match="already minted"):
        guard._authority.issue(
            receipt=grant.receipt, invocation=invocation, policy=policy, grant_id=fresh_id
        )
    assert calls == []


def test_v1_legacy_receipt_mints_once_without_allocated_id() -> None:
    def action(value: str) -> str:
        return value

    invocation = bind_invocation(action, ("safe",), {})
    policy = bind_policy(Constitution.default())
    receipt = build_issue_receipt(
        func=action, invocation=invocation, policy=policy, decision=_ALLOW
    )
    assert receipt.schema_version is None
    authority = ExecutionAuthority()
    grant = authority.issue(receipt=receipt, invocation=invocation, policy=policy)
    assert len(grant.grant_id) == 32
    with pytest.raises(LegitimacyInvariantError, match="already minted"):
        authority.issue(receipt=receipt, invocation=invocation, policy=policy)


def test_v2_receipt_requires_allocated_matching_bindings() -> None:
    def action(value: str) -> str:
        return value

    invocation = bind_invocation(action, ("safe",), {})
    other_invocation = bind_invocation(action, ("other",), {})
    policy = bind_policy(Constitution.default())
    other_policy = bind_policy(
        Constitution.from_rules([Rule(id="X", text="x rule", keywords=["xyzzy"])])
    )
    authority = ExecutionAuthority()

    def v2(**overrides: Any) -> tuple[DecisionReceipt, str]:
        gid = authority.allocate_grant_id()
        kwargs: dict[str, Any] = {
            "func": action,
            "invocation": invocation,
            "policy": policy,
            "decision": _ALLOW,
            "grant_id": gid,
            **overrides,
        }
        return build_issue_receipt(**kwargs), gid

    receipt, _gid = v2()
    with pytest.raises(LegitimacyInvariantError, match="allocated grant id"):
        authority.issue(receipt=receipt, invocation=invocation, policy=policy)

    receipt, gid = v2()
    other_gid = authority.allocate_grant_id()
    with pytest.raises(LegitimacyInvariantError, match="does not match receipt"):
        authority.issue(receipt=receipt, invocation=invocation, policy=policy, grant_id=other_gid)
    # A refused allocation is spent, not reusable.
    with pytest.raises(LegitimacyInvariantError, match="not allocated"):
        authority.issue(receipt=receipt, invocation=invocation, policy=policy, grant_id=other_gid)

    for kwargs, message in (
        ({"policy": other_policy}, "policy"),
        ({"invocation": other_invocation}, "invocation"),
        ({"context_digest": "ctx"}, "context"),
    ):
        receipt, gid = v2()
        issue_kwargs: dict[str, Any] = {
            "receipt": receipt,
            "invocation": invocation,
            "policy": policy,
            "grant_id": gid,
        }
        issue_kwargs.update(kwargs)
        with pytest.raises(LegitimacyInvariantError, match=message):
            authority.issue(**issue_kwargs)

    receipt, gid = v2(context_digest="ctx")
    grant = authority.issue(
        receipt=receipt, invocation=invocation, policy=policy, grant_id=gid, context_digest="ctx"
    )
    assert grant.grant_id == gid == receipt.grant_id
    authority.verify(grant, invocation=invocation, policy=policy, context_digest="ctx")


def test_failed_issue_releases_pending_grant_id(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = _guard()
    calls: list[str] = []

    @guard
    def act(text: str) -> str:
        calls.append(text)
        return text

    def boom(**_kwargs: Any) -> Any:
        raise RuntimeError("receipt build failed")

    monkeypatch.setattr("acgs_lite.governed.build_issue_receipt", boom)
    with pytest.raises(RuntimeError, match="receipt build failed"):
        act.issue_grant("hello")
    assert guard._authority._pending == set()
    assert calls == []


def test_ledger_refuses_binding_one_receipt_to_two_grants() -> None:
    def action(value: str) -> str:
        return value

    invocation = bind_invocation(action, ("safe",), {})
    policy = bind_policy(Constitution.default())
    ledger = InProcessGrantLedger()
    ledger.consume(
        grant_id="g1", attempt_id="a1", receipt_hash="r" * 64, invocation=invocation, policy=policy
    )
    with pytest.raises(LegitimacyInvariantError, match="different grant"):
        ledger.consume(
            grant_id="g2",
            attempt_id="a2",
            receipt_hash="r" * 64,
            invocation=invocation,
            policy=policy,
        )


# --- replay reads the v2 receipt's committed digest --------------------------


def _replay_signed_v2(constitution: Constitution) -> Any:
    pytest.importorskip("cryptography")
    from acgs_lite.legitimacy import Ed25519ReceiptSigner, sign_receipt

    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    guard = _guard(constitution)

    @guard
    def act(text: str) -> str:
        return text

    grant = act.issue_grant("hello")
    return sign_receipt(grant.receipt, signer), signer.public_key_hex()


_C1 = Constitution.from_rules([Rule(id="P", text="pattern rule", patterns=[r"abc\d"])])
_C2 = Constitution.from_rules([Rule(id="P", text="pattern rule", patterns=[r"xyz\d"])])


def test_v2_replay_uses_receipt_policy_digest_even_in_receipt_scope() -> None:
    signed, pub = _replay_signed_v2(_C1)
    assert _C1.hash == _C2.hash
    ok = replay_and_verify(
        signed,
        lambda _i: "ALLOW",
        expected_public_key=pub,
        expected_policy_digest=bind_policy(_C1).digest,
    )
    assert ok.ok is True
    bad = replay_and_verify(
        signed,
        lambda _i: "ALLOW",
        expected_public_key=pub,
        expected_policy_digest=bind_policy(_C2).digest,
    )
    assert bad.ok is False
    assert any(m.startswith("policy_digest_mismatch") for m in bad.mismatches)


def test_v2_replay_refuses_envelope_that_disagrees_with_receipt() -> None:
    pytest.importorskip("cryptography")
    from acgs_lite.legitimacy import Ed25519ReceiptSigner, sign_execution_authorization
    from acgs_lite.legitimacy.authorization import authorization_envelope_json

    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    guard = _guard(_C1)

    @guard
    def act(text: str) -> str:
        return text

    grant = act.issue_grant("hello")
    invocation = bind_invocation(act.__wrapped__, ("hello",), {}, include_receiver=True)
    envelope = authorization_envelope_json(invocation, bind_policy(_C2))
    signed = sign_execution_authorization(grant.receipt, signer, authorization_json=envelope)
    result = replay_and_verify(
        signed,
        lambda _i: "ALLOW",
        expected_public_key=signer.public_key_hex(),
        expected_policy_digest=bind_policy(_C1).digest,
    )
    assert result.ok is False
    assert "policy_digest_conflict" in result.mismatches
