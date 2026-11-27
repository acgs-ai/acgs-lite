"""Conformance tests for the GitHub issue/PR comment FENCEABLE reference provider."""

from __future__ import annotations

import io
import json
import sys
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from acgs_lite import Constitution, GovernanceEngine, Rule, Severity  # noqa: E402
from acgs_lite.legitimacy import (  # noqa: E402
    ContractedEffectStore,
    Ed25519ReceiptSigner,
    EffectOutcome,
    EffectRequest,
    EffectState,
    EffectStore,
    ExecutionAuthority,
    ProviderContractRegistry,
    local_grant_identity,
    outcome_from_record,
    sign_outcome,
)
from examples.github_fenceable_provider import (  # noqa: E402
    GitHubCommentProvider,
    GitHubFencingProxyServer,
    GitHubFencingProxyTransport,
    GitHubIdempotencyConflictError,
    InMemoryGitHubAPI,
    run_github_conformance_suite,
    run_live_github_verification,
)
from examples.github_fenceable_provider import provider as gh_provider_mod  # noqa: E402
from examples.github_fenceable_provider.provider import _mint_grant, main  # noqa: E402


def test_github_conformance_suite_passes_end_to_end(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    res = run_github_conformance_suite(db_path=tmp_path / "github.sqlite")
    assert res.all_passed is True
    assert res.a1_dedup_single_comment is True
    assert res.a2_timeout_committed_reconciles_done is True
    assert res.a2_timeout_uncommitted_reconciles_fenced_not_done is True
    assert res.deny_zero_provider_calls is True
    assert res.outcome_signatures_verified is True


def test_a1_github_comment_dedup_and_payload_conflict() -> None:
    api = InMemoryGitHubAPI()
    first = api.create_comment(
        idempotency_key="ghk-1", repo="acgs-ai/acgs-lite", issue_number=42, body="Ship it"
    )
    second = api.create_comment(
        idempotency_key="ghk-1", repo="acgs-ai/acgs-lite", issue_number=42, body="Ship it"
    )
    assert first["comment_id"] == second["comment_id"]
    assert "<!-- acgs-effect-key: ghk-1 -->" in first["body"]
    with pytest.raises(GitHubIdempotencyConflictError):
        api.create_comment(
            idempotency_key="ghk-1", repo="acgs-ai/acgs-lite", issue_number=42, body="Different"
        )


def test_a2_github_timeout_before_commit_fences_key(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    db = tmp_path / "gh.sqlite"
    api = InMemoryGitHubAPI()
    provider = GitHubCommentProvider(api)
    signer = Ed25519ReceiptSigner.from_seed(b"\x09" * 32)
    constitution = Constitution(
        name="gh-test",
        version="2026.11",
        rules=[Rule(id="r1", text="block", severity=Severity.CRITICAL, keywords=["ghp_secret"])],
    )
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    registry = ProviderContractRegistry()
    registry.register(provider.contract)

    store = EffectStore(db)
    store.create_budget("gh", 100)
    contracted = ContractedEffectStore(store, registry)

    grant = _mint_grant(
        engine=engine,
        constitution=constitution,
        authority=authority,
        signer=signer,
        repo="acgs-ai/acgs-lite",
        issue_number=7,
        comment_text="hello world",
        scope="prod",
    )
    effect = store.reserve(
        provider_id=provider.provider_id,
        grant_identity=local_grant_identity(grant),
        action={"repo": "acgs-ai/acgs-lite", "issue_number": 7, "body": "hello world"},
        budget_id="gh",
        amount=1,
    )
    api.inject_timeout_once(effect.key, commit_before_timeout=False)
    with pytest.raises(TimeoutError):
        contracted.send(effect.key, provider, grant=grant)

    reopened = ContractedEffectStore(EffectStore(db), registry)
    rec = reopened.reconcile(effect.key, provider)
    assert rec.state is EffectState.NOT_DONE
    signed = sign_outcome(
        outcome_from_record(rec, store=reopened, provider=provider, grant=grant),
        signer,
    )
    assert signed.verify(signer.public_key_hex()) is True

    with pytest.raises(RuntimeError, match="permanently fenced"):
        api.create_comment(
            idempotency_key=effect.key,
            repo="acgs-ai/acgs-lite",
            issue_number=7,
            body="hello world",
        )


def test_github_fencing_proxy_server_and_transport_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("cryptography")
    # Direct GitHub REST host lacks /comments/fence and MUST be rejected fail-closed
    with pytest.raises(ValueError, match="Direct GitHub hosts"):
        GitHubFencingProxyTransport("https://api.github.com", token="tok")
    with pytest.raises(ValueError, match="https://"):
        GitHubFencingProxyTransport("http://gh-proxy.example.com", token="tok")
    with pytest.raises(ValueError, match="non-empty bearer token"):
        GitHubFencingProxyTransport("https://gh-proxy.example.com", token=" ")

    # Real loopback proxy HTTP round-trip (POST /comments, dedup, POST /comments/fence, 409 conflict)
    with GitHubFencingProxyServer(expected_token="proxy-tok") as proxy:
        transport = GitHubFencingProxyTransport(proxy.base_url, token="proxy-tok")
        res = run_live_github_verification(transport, db_path=tmp_path / "proxy_live.sqlite")
        assert res["passed"] is True
        assert res["idempotent_dedup_matched"] is True
        assert res["reconcile_outcome"] == "done"

        with pytest.raises(ValueError, match="owner/name"):
            transport.create_comment(
                idempotency_key="k", repo="../escape/repo", issue_number=1, body="x"
            )

    class _FakeResp:
        def __init__(self, body: dict[str, object]) -> None:
            self._body = json.dumps(body).encode("utf-8")

        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return self._body

    proxy_transport = GitHubFencingProxyTransport("https://gh-proxy.example.com", token="tok")
    for status, fenced_flag, expected in [
        ("created", False, EffectOutcome.DONE),
        ("canceled", True, EffectOutcome.NOT_DONE),
        ("canceled", "false", EffectOutcome.UNKNOWN),
        ("pending", False, EffectOutcome.UNKNOWN),
    ]:
        monkeypatch.setattr(
            gh_provider_mod._GITHUB_NO_REDIRECT_OPENER,
            "open",
            lambda req, timeout=10.0, _s=status, _f=fenced_flag: _FakeResp(
                {"comment_id": "ic_1", "status": _s, "fenced": _f}
            ),
        )
        outcome, _, _ = proxy_transport.find_or_fence_comment(
            idempotency_key="acgs:effect:v1:abc", repo="acgs-ai/acgs-lite", issue_number=1
        )
        assert outcome is expected


def test_github_send_requires_explicit_boolean_fenced_confirmation() -> None:
    class _UnconfirmedCancelTransport:
        def create_comment(self, **_: object) -> dict[str, object]:
            return {"comment_id": "ic_x", "status": "canceled", "fenced": False}

        def find_or_fence_comment(self, **_: object) -> tuple[EffectOutcome, str | None, bool]:
            return EffectOutcome.UNKNOWN, None, False

    provider = GitHubCommentProvider(_UnconfirmedCancelTransport())  # type: ignore[arg-type]
    req = EffectRequest(
        key="acgs:effect:v1:" + "2" * 64,
        provider_id=provider.provider_id,
        grant_identity="grant-1",
        action_json='{"repo":"acgs-ai/acgs-lite","issue_number":1,"body":"hi"}',
    )
    res = provider.send(req)
    assert res.outcome is EffectOutcome.UNKNOWN
    assert res.fenced is False


def test_github_main_with_live_proxy_and_broken_recovery(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("cryptography")
    monkeypatch.setenv("ACGS_GITHUB_PROXY_URL", "https://gh-proxy.example.com")
    monkeypatch.setenv("ACGS_GITHUB_PROXY_TOKEN", "ghs_test_token")

    def _fail(req: object, timeout: float = 10.0) -> object:
        raise urllib.error.HTTPError(
            "https://gh-proxy.example.com/repos/acgs-ai/acgs-lite/issues/1/comments",
            502,
            "Bad Gateway",
            {},  # type: ignore[arg-type]
            io.BytesIO(b"bad gateway"),
        )

    monkeypatch.setattr(gh_provider_mod._GITHUB_NO_REDIRECT_OPENER, "open", _fail)
    assert main() == 1
    assert json.loads(capsys.readouterr().out)["live_verification"]["passed"] is False

    class _FakeResp:
        def __init__(self, body: dict[str, object]) -> None:
            self._body = json.dumps(body).encode("utf-8")

        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return self._body

    monkeypatch.setattr(
        gh_provider_mod._GITHUB_NO_REDIRECT_OPENER,
        "open",
        lambda req, timeout=10.0: _FakeResp(
            {"comment_id": "ic_live_1", "status": "created", "fenced": False}
        ),
    )
    assert main() == 0
    ok_out = json.loads(capsys.readouterr().out)
    assert ok_out["all_passed"] is True
    assert ok_out["live_verification"]["passed"] is True

    class _BrokenFenceTransport:
        def create_comment(self, **_: object) -> dict[str, object]:
            return {"comment_id": "ic_broken", "status": "created", "fenced": False}

        def find_or_fence_comment(self, **_: object) -> tuple[EffectOutcome, str | None, bool]:
            return EffectOutcome.UNKNOWN, "ic_broken", False

    broken = run_live_github_verification(_BrokenFenceTransport())  # type: ignore[arg-type]
    assert broken["reconcile_outcome"] == "unknown"
    assert broken["passed"] is False


def test_github_proxy_transport_refuses_redirects_before_leaking_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.undo()
    leaked: list[dict[str, str]] = []

    class _SinkHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            leaked.append({k.lower(): v for k, v in self.headers.items()})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, format: str, *args: object) -> None:
            return None

    sink = ThreadingHTTPServer(("127.0.0.1", 0), _SinkHandler)
    sink_port = sink.server_address[1]

    class _RedirectHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{sink_port}/steal")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return None

    redir = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    redir_port = redir.server_address[1]
    t1 = threading.Thread(target=sink.serve_forever, daemon=True)
    t2 = threading.Thread(target=redir.serve_forever, daemon=True)
    t1.start()
    t2.start()
    try:
        transport = GitHubFencingProxyTransport(
            f"http://127.0.0.1:{redir_port}", token="ghs_super_secret"
        )
        with pytest.raises(RuntimeError, match="redirect refused"):
            transport.create_comment(
                idempotency_key="ghk-redir",
                repo="acgs-ai/acgs-lite",
                issue_number=1,
                body="hello",
            )
        with pytest.raises(RuntimeError, match="redirect refused"):
            transport.find_or_fence_comment(
                idempotency_key="ghk-redir",
                repo="acgs-ai/acgs-lite",
                issue_number=1,
            )
        assert leaked == []
    finally:
        redir.shutdown()
        redir.server_close()
        sink.shutdown()
        sink.server_close()
