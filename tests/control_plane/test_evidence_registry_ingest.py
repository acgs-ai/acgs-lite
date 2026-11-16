"""Refusal paths of the signed run registry and of evidence evaluation.

Every case asserts the refusal and that the registry file / in-memory state is
unchanged: a tampered, replayed or shrunk log must fail closed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.control_plane import DEFAULT_IMMUTABLE_CORE, Principal, PrincipalKind
from acgs_lite.control_plane.evidence import (
    RUN_RECORD_SIGNING_DOMAIN,
    CompositeRunVerifier,
    EvidenceSource,
    ExternalRunRef,
    RunRegistrationRejected,
    TrustedRunRegistry,
    evaluate_evidence,
)

pytest.importorskip("cryptography")
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = pytest.mark.unit

CI = Principal("ci-bot", PrincipalKind.SERVICE)
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
SIGNER = Ed25519ReceiptSigner.from_seed(b"\x05" * 32, key_id="runs-1")


def _ref(run_id: str = "1", digest: str | None = None) -> ExternalRunRef:
    return ExternalRunRef("ci", run_id, EvidenceSource.CI_SYSTEM, artifact_digest=digest)


class _Env:
    def __init__(self, tmp_path: Path) -> None:
        self.core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        self.path = tmp_path / "audit" / "runs.jsonl"

    def open(self) -> TrustedRunRegistry:
        return TrustedRunRegistry(path=self.path, registry=self.core, signer=SIGNER)


@pytest.fixture()
def env(tmp_path: Path) -> _Env:
    return _Env(tmp_path)


@pytest.fixture()
def good(env: _Env) -> bytes:
    env.open().register_run(CI, _ref(), conclusion="success", artifact_digest=DIGEST)
    return env.path.read_bytes()


def test_blank_line_is_tolerated(env: _Env, good: bytes) -> None:
    env.path.write_bytes(good + b"\n")

    registry = env.open()

    assert len(registry) == 1
    assert registry.validate(_ref(digest=DIGEST)).valid is True


def test_non_utf8_tail_refuses_open(env: _Env, good: bytes) -> None:
    tampered = good + b"\xff\xfe\n"
    env.path.write_bytes(tampered)

    with pytest.raises(ValueError, match="not UTF-8"):
        env.open()

    assert env.path.read_bytes() == tampered


def test_replayed_backup_claim_line_refuses_open(env: _Env, good: bytes) -> None:
    registry = env.open()
    assert registry.consume_backup(_ref(digest=DIGEST)) is True
    lines = env.path.read_bytes().splitlines(keepends=True)
    # Byte-for-byte replay of a genuine claim; nothing is re-signed.
    replayed = lines[0] + lines[1] + lines[1]
    env.path.write_bytes(replayed)

    with pytest.raises(ValueError, match="duplicate backup consumption"):
        env.open()

    assert env.path.read_bytes() == replayed


def test_registered_conclusion_requires_matching_ref(env: _Env, good: bytes) -> None:
    registry = env.open()

    assert registry.registered_conclusion("x") is None  # type: ignore[arg-type]
    assert registry.registered_conclusion(_ref(digest=OTHER)) is None
    assert registry.registered_conclusion(_ref(digest=DIGEST)) == "success"  # positive control


def test_backup_consumed_on_memory_registry_raises() -> None:
    with pytest.raises(RunRegistrationRejected, match="persistent signing registry"):
        TrustedRunRegistry().backup_consumed(_ref(digest=DIGEST))


def test_shrunk_file_refuses_append(env: _Env, good: bytes) -> None:
    registry = env.open()
    env.path.write_bytes(b"")

    with pytest.raises(RunRegistrationRejected, match="shrank since it was opened"):
        registry.register_run(CI, _ref("3"), conclusion="success")

    assert env.path.read_bytes() == b""


def test_foreign_garbage_after_open_refuses_append(env: _Env, good: bytes) -> None:
    registry = env.open()
    with env.path.open("ab") as handle:
        handle.write(b"{not json\n")
    size = env.path.stat().st_size

    with pytest.raises(RunRegistrationRejected, match="run registry changed"):
        registry.register_run(CI, _ref("4"), conclusion="success")

    assert env.path.stat().st_size == size


def test_cyclic_composite_never_attests_a_digest() -> None:
    class _SelfRouting(CompositeRunVerifier):
        def verifier_for(self, ref: ExternalRunRef) -> Any:
            return self

    reasons = evaluate_evidence([_ref(digest=DIGEST)], _SelfRouting({}), required=True)

    assert any("verifier cannot attest artifact digest" in r for r in reasons)
    assert any("0 validated distinct external run(s)" in r for r in reasons)


class TestTrustedWriterMalformedRecordRefused:
    """Malformed records that nevertheless verify under a trusted key.

    These lines are reachable only through a buggy trusted writer. The test
    signs with the registry's OWN test key, which the registry trusts by
    design; nothing is forged against a key the test does not own, and the
    asserted outcome is a refusal to open (a denial), never an authorization.
    """

    @staticmethod
    def _signed_line(record: dict[str, Any]) -> bytes:
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        signature = SIGNER.sign(RUN_RECORD_SIGNING_DOMAIN + canonical.encode("utf-8"))
        envelope = {"record": record, "key_id": SIGNER.key_id, "signature": signature}
        return (json.dumps(envelope) + "\n").encode()

    @pytest.mark.parametrize(
        ("mutation", "message"),
        [
            ("extra_key", "malformed run registry record"),
            ("bad_conclusion", "malformed run registry conclusion"),
            ("claim_extra_key", "malformed backup consumption record"),
            ("claim_unbound", "needs independent bound evidence"),
        ],
    )
    def test_refuses_open(self, env: _Env, good: bytes, mutation: str, message: str) -> None:
        base = json.loads(good)["record"]
        records = {
            "extra_key": {**base, "extra": 1},
            "bad_conclusion": {**base, "conclusion": "maybe"},
            "claim_extra_key": {"kind": "backup_consumed", "ref": {}, "x": 1},
            "claim_unbound": {"kind": "backup_consumed", "ref": _ref("2").to_dict()},
        }
        line = self._signed_line(records[mutation])
        env.path.write_bytes(line)

        with pytest.raises(ValueError, match=message) as excinfo:
            env.open()

        assert str(excinfo.value).startswith("run registry line 1: ")
        assert env.path.read_bytes() == line
