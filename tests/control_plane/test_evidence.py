"""External run refs, the trusted run registry and run verifiers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.control_plane import (
    DEFAULT_IMMUTABLE_CORE,
    CompositeRunVerifier,
    EvidencePolicy,
    EvidenceSource,
    ExternalRunRef,
    GitHubActionsRunVerifier,
    Principal,
    PrincipalKind,
    RunRegistrationRejected,
    RunValidation,
    TrustedRunRegistry,
)
from acgs_lite.control_plane.evidence import (
    AGENT_LOG_REASON,
    evaluate_evidence,
    parse_external_runs,
    require_audit_store_path,
)

pytestmark = [pytest.mark.unit, pytest.mark.constitutional]

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
SHA = "c" * 40
CI = Principal("ci-bot", PrincipalKind.SERVICE)
AGENT = Principal("agent-1", PrincipalKind.AGENT, system_id="sys-a")


def _ci(run_id: str = "101", **kw: Any) -> ExternalRunRef:
    return ExternalRunRef("ci", run_id, EvidenceSource.CI_SYSTEM, **kw)


def _signer() -> Any:
    pytest.importorskip("cryptography")
    from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

    return Ed25519ReceiptSigner.from_seed(b"\x05" * 32, key_id="runs-1")


class TestExternalRunRef:
    def test_round_trip(self) -> None:
        ref = _ci(artifact_digest=DIGEST, url="https://ci.example/run/101", head_sha=SHA)
        assert ExternalRunRef.from_dict(ref.to_dict()) == ref
        assert ref.label == "ci/101"

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"provider": ""},
            {"provider": "c i"},
            {"run_id": "ünï"},
            {"run_id": "x" * 300},
            {"artifact_digest": "sha256:XYZ"},
            {"artifact_digest": "md5:" + "a" * 32},
            {"url": "https://x y"},
            {"head_sha": "abc"},
            {"source": "bogus"},
        ],
    )
    def test_strict_validation(self, kwargs: dict[str, Any]) -> None:
        base: dict[str, Any] = {"provider": "ci", "run_id": "1", "source": "ci_system"}
        with pytest.raises(ValueError):
            ExternalRunRef(**{**base, **kwargs})

    @pytest.mark.parametrize(
        "data",
        [
            "x",
            {"provider": "ci", "run_id": "1"},
            {"provider": "ci", "run_id": "1", "source": "ci_system", "extra": 1},
        ],
    )
    def test_from_dict_strict(self, data: object) -> None:
        with pytest.raises(ValueError):
            ExternalRunRef.from_dict(data)

    def test_parse_external_runs(self) -> None:
        ref = _ci()
        assert parse_external_runs(None) == ()
        assert parse_external_runs([ref, ref.to_dict()]) == (ref, ref)
        for bad in ("x", {"provider": "ci"}, 3):
            with pytest.raises(ValueError):
                parse_external_runs(bad)


class TestEvidencePolicy:
    def test_agent_log_never_accepted(self) -> None:
        with pytest.raises(ValueError):
            EvidencePolicy(accepted_sources=frozenset({EvidenceSource.AGENT_LOG}))

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"min_external_runs": 0},
            {"min_external_runs": True},
            {"accepted_sources": frozenset()},
            {"success_claim_prefixes": ("",)},
        ],
    )
    def test_invalid(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            EvidencePolicy(**kwargs)

    def test_success_claim(self) -> None:
        policy = EvidencePolicy(success_claim_prefixes=("Deploy.",))
        assert policy.is_success_claim("deploy.prod")
        assert not policy.is_success_claim("file.write")


class TestTrustedRunRegistry:
    def test_agent_cannot_register(self) -> None:
        registry = TrustedRunRegistry()
        with pytest.raises(RunRegistrationRejected):
            registry.register_run(AGENT, _ci(), conclusion="success")
        with pytest.raises(RunRegistrationRejected):
            registry.register_run("ci-bot", _ci(), conclusion="success")  # type: ignore[arg-type]
        assert len(registry) == 0

    @pytest.mark.parametrize(
        ("ref", "kwargs"),
        [
            (ExternalRunRef("ci", "1", EvidenceSource.AGENT_LOG), {"conclusion": "success"}),
            (_ci(), {"conclusion": "passed"}),
            (_ci(), {"conclusion": "success", "artifact_digest": "nope"}),
            (_ci(), {"conclusion": "success", "head_sha": "nope"}),
            (
                _ci(artifact_digest=DIGEST),
                {"conclusion": "success", "artifact_digest": OTHER_DIGEST},
            ),
            (_ci(head_sha=SHA), {"conclusion": "success", "head_sha": "d" * 40}),
            ("not-a-ref", {"conclusion": "success"}),
        ],
    )
    def test_bad_registrations(self, ref: Any, kwargs: dict[str, Any]) -> None:
        with pytest.raises(RunRegistrationRejected):
            TrustedRunRegistry().register_run(CI, ref, **kwargs)

    def test_duplicate_refused(self) -> None:
        registry = TrustedRunRegistry()
        registry.register_run(CI, _ci(), conclusion="success")
        with pytest.raises(RunRegistrationRejected):
            registry.register_run(CI, _ci(), conclusion="failure")

    def test_validate(self) -> None:
        registry = TrustedRunRegistry()
        human = Principal("alice", PrincipalKind.HUMAN)
        registry.register_run(CI, _ci("1"), conclusion="success", artifact_digest=DIGEST)
        registry.register_run(human, _ci("2"), conclusion="failure")
        registry.register_run(CI, _ci("4"), conclusion="success", head_sha=SHA)
        assert registry.validate(_ci("1", artifact_digest=DIGEST)).valid
        assert registry.validate(_ci("4", head_sha=SHA.upper())).valid
        cases = {
            _ci("1", artifact_digest=OTHER_DIGEST): "digest",
            _ci("1"): "digest",  # H1: a ref may not drop the registered binding
            _ci("1", artifact_digest=DIGEST, head_sha=SHA): "head_sha",
            _ci("4"): "head_sha",
            _ci("4", head_sha="d" * 40): "head_sha",  # H1/J: bogus head_sha
            _ci("2"): "failure",
            _ci("3"): "not registered",
            ExternalRunRef("other", "1", EvidenceSource.CI_SYSTEM): "not registered",
            ExternalRunRef("ci", "1", EvidenceSource.EVALUATOR_SERVICE): "source mismatch",
            ExternalRunRef("ci", "1", EvidenceSource.AGENT_LOG): AGENT_LOG_REASON,
        }
        for ref, needle in cases.items():
            result = registry.validate(ref)
            assert not result.valid and needle in result.reason, (ref, result)
        assert not registry.validate("x").valid  # type: ignore[arg-type]

    def test_signed_jsonl_persistence(self, tmp_path: Path) -> None:
        signer = _signer()
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        path = tmp_path / "audit" / "runs.jsonl"
        registry = TrustedRunRegistry(path=path, registry=core, signer=signer)
        registry.register_run(CI, _ci(), conclusion="success", artifact_digest=DIGEST)
        reopened = TrustedRunRegistry(path="audit/runs.jsonl", registry=core, signer=signer)
        assert reopened.validate(_ci(artifact_digest=DIGEST)).valid
        # A verifier holding only the public key can load (but not register).
        readonly = TrustedRunRegistry(
            path=path, registry=core, trusted_public_keys={signer.key_id: signer.public_key_hex()}
        )
        assert readonly.validate(_ci(artifact_digest=DIGEST)).valid
        with pytest.raises(RunRegistrationRejected, match="read-only"):
            readonly.register_run(CI, _ci("2"), conclusion="success")
        with pytest.raises(ValueError, match="signer or trusted_public_keys"):
            TrustedRunRegistry(path=path, registry=core)
        with pytest.raises(TypeError):
            TrustedRunRegistry(signer="x")  # type: ignore[arg-type]
        good = path.read_text()
        path.write_text(good + good)
        with pytest.raises(ValueError, match="duplicate"):
            TrustedRunRegistry(path=path, registry=core, signer=signer)

    def test_m7_forged_registry_line_fails_closed(self, tmp_path: Path) -> None:
        signer = _signer()
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        path = tmp_path / "audit" / "runs.jsonl"
        TrustedRunRegistry(path=path, registry=core, signer=signer).register_run(
            CI, _ci(), conclusion="failure"
        )
        good = json.loads(path.read_text())
        record = {
            "provider": "ci",
            "run_id": "999",
            "source": "ci_system",
            "conclusion": "success",
            "artifact_digest": None,
            "head_sha": None,
            "registered_by": "agent-1",
        }
        flipped = {**good, "record": {**good["record"], "conclusion": "success"}}
        forged_lines = [
            json.dumps(record),  # unsigned (the reviewer's PoC shape)
            json.dumps({"record": record, "key_id": signer.key_id, "signature": "00" * 64}),
            json.dumps({"record": record, "key_id": "other", "signature": good["signature"]}),
            json.dumps(flipped),  # signed record with a rewritten field
            json.dumps({**good, "record": {**good["record"], "extra": 1}}),
            "{not json",
        ]
        for line in forged_lines:
            path.write_text(line + "\n")
            with pytest.raises(ValueError):
                TrustedRunRegistry(path=path, registry=core, signer=signer)

    def test_registry_path_must_be_audit_core(self, tmp_path: Path) -> None:
        core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
        keys = {"k": "00"}
        with pytest.raises(PermissionError):
            TrustedRunRegistry(
                path=tmp_path / "workspace" / "runs.jsonl", registry=core, trusted_public_keys=keys
            )
        with pytest.raises(PermissionError):
            require_audit_store_path(tmp_path / "audit" / "x.jsonl")  # no repo_root


class _Fetch:
    def __init__(self, payload: Any = None, exc: Exception | None = None) -> None:
        self.payload = payload
        self.exc = exc
        self.paths: list[str] = []

    def __call__(self, path: str) -> Any:
        self.paths.append(path)
        if self.exc is not None:
            raise self.exc
        return self.payload


def _gh_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": 42,
        "status": "completed",
        "conclusion": "success",
        "head_sha": SHA,
        "path": ".github/workflows/ci.yml",
        "head_branch": "main",
        "event": "push",
        "repository": {"full_name": "o/r"},
        "head_repository": {"full_name": "o/r"},
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not _MISSING}


_MISSING = object()


def _gh_ref(**kw: Any) -> ExternalRunRef:
    kw.setdefault("head_sha", SHA)
    return ExternalRunRef("github-actions", "42", EvidenceSource.CI_SYSTEM, **kw)


def _gh(fetch: _Fetch, repository: str = "o/r") -> GitHubActionsRunVerifier:
    return GitHubActionsRunVerifier(
        fetch,
        repository=repository,
        allowed_workflows={".github/workflows/ci.yml"},
        allowed_branches={"main"},
        allowed_events={"push"},
    )


class TestGitHubActionsRunVerifier:
    @pytest.mark.parametrize("required", [False, True])
    def test_head_sha_does_not_attest_extra_artifact_digest(self, required: bool) -> None:
        verifier = _gh(_Fetch(_gh_payload()))
        ref = _gh_ref(artifact_digest=DIGEST)
        assert verifier.validate(ref).valid
        reasons = evaluate_evidence((ref,), verifier, EvidencePolicy(), required=required)
        assert any("attest" in reason for reason in reasons)

    def test_success(self) -> None:
        fetch = _Fetch(
            _gh_payload(
                repository={"full_name": "acgs-ai/acgs-lite"},
                head_repository={"full_name": "acgs-ai/acgs-lite"},
            )
        )
        assert _gh(fetch, "acgs-ai/acgs-lite").validate(_gh_ref()).valid
        assert fetch.paths == ["/repos/acgs-ai/acgs-lite/actions/runs/42"]

    @pytest.mark.parametrize(
        ("fetch", "ref", "needle"),
        [
            (_Fetch(exc=ConnectionError("down")), _gh_ref(), "fetch failed"),
            (_Fetch(_gh_payload(conclusion="failure")), _gh_ref(), "conclusion"),
            (_Fetch(_gh_payload(status="in_progress")), _gh_ref(), "status"),
            (_Fetch(_gh_payload(head_sha="d" * 40)), _gh_ref(), "head_sha"),
            (_Fetch(_gh_payload(head_sha=None)), _gh_ref(), "head_sha"),
            (_Fetch(_gh_payload(id=7)), _gh_ref(), "id mismatch"),
            (_Fetch(["not", "a", "mapping"]), _gh_ref(), "JSON object"),
            # H1/D: any workflow / branch / event / repo is no longer enough.
            (_Fetch(_gh_payload(path=".github/workflows/noop.yml")), _gh_ref(), "workflow"),
            (_Fetch(_gh_payload(head_branch="agent/x")), _gh_ref(), "branch"),
            (_Fetch(_gh_payload(event="pull_request")), _gh_ref(), "event"),
            (_Fetch(_gh_payload(repository={"full_name": "evil/r"})), _gh_ref(), "repository"),
            (_Fetch(_gh_payload(repository=_MISSING)), _gh_ref(), "repository"),
            (_Fetch(_gh_payload(path=_MISSING)), _gh_ref(), "workflow"),
            (_Fetch(_gh_payload()), _gh_ref(head_sha=None), "head_sha is required"),
            (_Fetch(_gh_payload()), ExternalRunRef("gh", "42", "ci_system"), "provider"),
            (
                _Fetch(_gh_payload()),
                ExternalRunRef("github-actions", "a1", "ci_system", head_sha=SHA),
                "numeric",
            ),
            (
                _Fetch(_gh_payload()),
                ExternalRunRef("github-actions", "42", "human_review"),
                "ci_system",
            ),
            (_Fetch(_gh_payload()), ExternalRunRef("github-actions", "42", "agent_log"), "agent"),
        ],
    )
    def test_invalid(self, fetch: _Fetch, ref: ExternalRunRef, needle: str) -> None:
        result = _gh(fetch).validate(ref)
        assert not result.valid
        assert needle in result.reason

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"repository": "no-slash"},
            {"allowed_workflows": set()},
            {"allowed_branches": "main"},
            {"allowed_events": {""}},
        ],
    )
    def test_construction(self, kwargs: dict[str, Any]) -> None:
        base: dict[str, Any] = {
            "repository": "o/r",
            "allowed_workflows": {"w"},
            "allowed_branches": {"main"},
            "allowed_events": {"push"},
        }
        with pytest.raises(ValueError):
            GitHubActionsRunVerifier(_Fetch(), **{**base, **kwargs})
        with pytest.raises(TypeError):
            GitHubActionsRunVerifier("x", **base)  # type: ignore[arg-type]
        assert not _gh(_Fetch()).validate("x").valid  # type: ignore[arg-type]


class _Boom:
    verifier_id = "boom"
    attests_artifact_digest = True

    def validate(self, ref: ExternalRunRef) -> RunValidation:
        raise RuntimeError("boom")


class TestCompositeAndEvaluate:
    @pytest.mark.parametrize("depth", [2, 4])
    def test_nested_routers_preserve_digest_attestation(self, depth: int) -> None:
        registry = TrustedRunRegistry()
        ref = _ci(artifact_digest=DIGEST)
        registry.register_run(CI, ref, conclusion="success")
        verifier: Any = registry
        for _ in range(depth):
            verifier = CompositeRunVerifier({"ci": verifier})
        assert verifier.validate(ref).valid
        assert evaluate_evidence([ref], verifier, required=True) == ()
        assert evaluate_evidence([_ci(artifact_digest=OTHER_DIGEST)], verifier, required=True)

    def test_routing(self) -> None:
        registry = TrustedRunRegistry()
        registry.register_run(CI, _ci(), conclusion="success")
        composite = CompositeRunVerifier({"ci": registry, "boom": _Boom()})
        assert tuple(composite.providers) == ("boom", "ci")
        assert composite.validate(_ci()).valid
        assert "no verifier" in composite.validate(_gh_ref()).reason
        assert (
            "verifier error" in composite.validate(ExternalRunRef("boom", "1", "ci_system")).reason
        )
        assert (
            composite.validate(ExternalRunRef("ci", "101", "agent_log")).reason == AGENT_LOG_REASON
        )
        assert not composite.validate("x").valid  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            CompositeRunVerifier({"x": object()})  # type: ignore[dict-item]

    def test_evaluate_evidence(self) -> None:
        registry = TrustedRunRegistry()
        bound = _ci(artifact_digest=DIGEST)
        registry.register_run(CI, bound, conclusion="success")
        agent_log = ExternalRunRef("agent", "log-1", EvidenceSource.AGENT_LOG)
        assert evaluate_evidence([bound], registry, required=True) == ()
        assert evaluate_evidence([bound, agent_log], registry, required=True) == ()
        assert evaluate_evidence([agent_log], registry, required=True) == (
            "only agent-written logs cited as evidence",
        )
        assert evaluate_evidence([], registry, required=True) == ("no external run evidence cited",)
        assert evaluate_evidence([], registry, required=False) == ()
        assert evaluate_evidence([_ci("9")], registry, required=False) != ()
        two = EvidencePolicy(min_external_runs=2)
        assert any(
            "< required 2" in r for r in evaluate_evidence([bound], registry, two, required=True)
        )
        human_only = EvidencePolicy(accepted_sources=frozenset({EvidenceSource.HUMAN_REVIEW}))
        assert any(
            "not accepted" in r
            for r in evaluate_evidence([bound], registry, human_only, required=True)
        )
        assert any(
            "verifier error" in r for r in evaluate_evidence([bound], _Boom(), required=False)
        )
        assert any(
            "artifact_digest does not match" in r
            for r in evaluate_evidence([bound], registry, required=True, bind_digest=OTHER_DIGEST)
        )

        class Weird:
            verifier_id = "weird"
            attests_artifact_digest = True

            def validate(self, ref: ExternalRunRef) -> object:
                return True

        assert any(
            "bad verifier result" in r
            for r in evaluate_evidence([bound], Weird(), required=False)  # type: ignore[arg-type]
        )

    def test_h1_success_claim_refs_must_be_bound(self) -> None:
        registry = TrustedRunRegistry()
        registry.register_run(CI, _ci(), conclusion="success")
        reasons = evaluate_evidence([_ci()], registry, required=True)
        assert any("not bound to an artifact" in r for r in reasons)
        assert evaluate_evidence([_ci()], registry, required=False) == ()

    def test_m4_duplicate_refs_count_once(self) -> None:
        registry = TrustedRunRegistry()
        bound = _ci(artifact_digest=DIGEST)
        registry.register_run(CI, bound, conclusion="success")
        two = EvidencePolicy(min_external_runs=2)
        reasons = evaluate_evidence([bound, bound], registry, two, required=True)
        assert any("1 validated distinct external run(s) < required 2" in r for r in reasons)
        conflicting = evaluate_evidence(
            [bound, _ci(artifact_digest=OTHER_DIGEST)], registry, required=True
        )
        assert any("conflicting duplicate" in r for r in conflicting)


class TestR1DigestAttestation:
    def test_github_cannot_attest_digest_without_artifact_fetch(self) -> None:
        verifier = _gh(_Fetch(_gh_payload()))
        assert verifier.attests_artifact_digest is False
        ref = _gh_ref(artifact_digest=DIGEST)
        assert verifier.validate(ref).valid  # the run itself is fine ...
        reasons = evaluate_evidence([ref], verifier, required=True, bind_digest=DIGEST)
        assert any("verifier cannot attest artifact digest" in r for r in reasons)

    def test_github_artifact_fetch_attests_digest(self) -> None:
        paths: list[str] = []

        def artifacts(path: str) -> list[str]:
            paths.append(path)
            return [OTHER_DIGEST, DIGEST]

        verifier = GitHubActionsRunVerifier(
            _Fetch(_gh_payload()),
            repository="o/r",
            allowed_workflows={".github/workflows/ci.yml"},
            allowed_branches={"main"},
            allowed_events={"push"},
            artifact_fetch=artifacts,
        )
        assert verifier.attests_artifact_digest is True
        good = _gh_ref(artifact_digest=DIGEST)
        assert evaluate_evidence([good], verifier, required=True, bind_digest=DIGEST) == ()
        assert paths == ["/repos/o/r/actions/runs/42/artifacts"]
        forged = _gh_ref(artifact_digest="sha256:" + "f" * 64)
        result = verifier.validate(forged)
        assert not result.valid and "not attested" in result.reason

        def broken(path: str) -> str:
            return DIGEST  # a bare string is not a list of digests

        bad = GitHubActionsRunVerifier(
            _Fetch(_gh_payload()),
            repository="o/r",
            allowed_workflows={".github/workflows/ci.yml"},
            allowed_branches={"main"},
            allowed_events={"push"},
            artifact_fetch=broken,
        )
        assert not bad.validate(good).valid
        with pytest.raises(TypeError):
            GitHubActionsRunVerifier(
                _Fetch(),
                repository="o/r",
                allowed_workflows={"w"},
                allowed_branches={"b"},
                allowed_events={"e"},
                artifact_fetch="x",  # type: ignore[arg-type]
            )

    def test_composite_resolves_attestation_per_provider(self) -> None:
        registry = TrustedRunRegistry()
        bound = _ci(artifact_digest=DIGEST)
        registry.register_run(CI, bound, conclusion="success")
        composite = CompositeRunVerifier(
            {"ci": registry, "github-actions": _gh(_Fetch(_gh_payload()))}
        )
        assert evaluate_evidence([bound], composite, required=True, bind_digest=DIGEST) == ()
        gh_ref = _gh_ref(artifact_digest=DIGEST)
        reasons = evaluate_evidence([gh_ref], composite, required=True, bind_digest=DIGEST)
        assert any("cannot attest" in r for r in reasons)

    def test_digest_only_success_claim_needs_attesting_verifier(self) -> None:
        class NoAttest:
            verifier_id = "no-attest"
            attests_artifact_digest = False

            def validate(self, ref: ExternalRunRef) -> RunValidation:
                return RunValidation(True, "ok", self.verifier_id)

        reasons = evaluate_evidence([_ci(artifact_digest=DIGEST)], NoAttest(), required=True)
        assert any("cannot attest" in r for r in reasons)
        assert evaluate_evidence([_ci(head_sha=SHA)], NoAttest(), required=True) == ()


@pytest.mark.parametrize("event", ["pull_request", "pull_request_target", "workflow_run"])
@pytest.mark.parametrize(
    "head_repo", [{"full_name": "fork/r"}, None, {}, [], {"full_name": 17}, _MISSING]
)
def test_github_rejects_untrusted_head_repository_before_artifact_attestation(
    event: str, head_repo: Any
) -> None:
    artifact_calls: list[str] = []

    def artifacts(path: str) -> tuple[str, ...]:
        artifact_calls.append(path)
        return (DIGEST,)

    verifier = GitHubActionsRunVerifier(
        _Fetch(_gh_payload(event=event, head_repository=head_repo)),
        repository="o/r",
        allowed_workflows={".github/workflows/ci.yml"},
        allowed_branches={"main"},
        allowed_events={event},
        artifact_fetch=artifacts,
    )
    reasons = evaluate_evidence(
        (_gh_ref(artifact_digest=DIGEST),), verifier, required=True, bind_digest=DIGEST
    )
    assert any("head repository" in reason for reason in reasons)
    assert artifact_calls == []


@pytest.mark.parametrize("event", ["push", "pull_request", "pull_request_target", "workflow_run"])
def test_github_accepts_allowed_same_repository_head(event: str) -> None:
    verifier = GitHubActionsRunVerifier(
        _Fetch(_gh_payload(event=event, head_repository={"full_name": "o/r"})),
        repository="o/r",
        allowed_workflows={".github/workflows/ci.yml"},
        allowed_branches={"main"},
        allowed_events={event},
        artifact_fetch=lambda _: (DIGEST,),
    )
    assert (
        evaluate_evidence(
            (_gh_ref(artifact_digest=DIGEST),), verifier, required=True, bind_digest=DIGEST
        )
        == ()
    )
