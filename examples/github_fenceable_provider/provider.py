"""GitHub issue/PR comment FENCEABLE reference provider and conformance suite.

Demonstrates ACGS-Lite 4.x ``ContractedEffectStore`` + chained signed
``OutcomeReceipt`` for idempotent GitHub issue/PR comments with embedded
``acgs-effect-key`` markers and atomic ``find_or_fence_comment`` recovery.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from acgs_lite import Constitution, GovernanceEngine, Rule, Severity
from acgs_lite.legitimacy import (
    ActualCall,
    ContractedEffectStore,
    Ed25519ReceiptSigner,
    EffectOutcome,
    EffectRequest,
    EffectState,
    EffectStore,
    ExecutionAuthority,
    ExecutionGrant,
    ProviderContract,
    ProviderContractClass,
    ProviderContractRegistry,
    ProviderResult,
    bind_invocation,
    bind_policy,
    local_grant_identity,
    outcome_from_record,
    sign_execution_authorization,
    sign_outcome,
    validate_receipt_for_execution,
)
from acgs_lite.legitimacy.authorization import (
    authorization_envelope_json,
    build_issue_receipt,
    engine_decision_from_results,
)


class GitHubIdempotencyConflictError(RuntimeError):
    """Raised when an idempotency key is reused with a different comment target or body."""


class _GitHubNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail closed on HTTP redirects so bearer tokens never cross origin/scheme boundaries."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if fp is not None:
            fp.close()
        raise RuntimeError(
            f"GitHub transport redirect refused (HTTP {code}): "
            "automatic redirects are disabled to prevent credential leakage"
        )


_GITHUB_NO_REDIRECT_OPENER = urllib.request.build_opener(_GitHubNoRedirectHandler())


class GitHubTransport(Protocol):
    """Minimal idempotent GitHub comment transport protocol."""

    def create_comment(
        self,
        *,
        idempotency_key: str,
        repo: str,
        issue_number: int,
        body: str,
    ) -> dict[str, Any]:
        """Create or idempotently retrieve a comment marked with *idempotency_key*."""

    def find_or_fence_comment(
        self,
        *,
        idempotency_key: str,
        repo: str,
        issue_number: int,
    ) -> tuple[EffectOutcome, str | None, bool]:
        """Query existing comment for *idempotency_key* or atomically fence the key."""


def _validate_repo_slug(repo: str) -> tuple[str, str]:
    if not isinstance(repo, str) or not repo.strip():
        raise ValueError("repo must be a non-empty 'owner/name' string")
    parts = repo.strip().split("/")
    if (
        len(parts) != 2
        or not parts[0]
        or not parts[1]
        or "." in (parts[0], parts[1])
        or ".." in (parts[0], parts[1])
    ):
        raise ValueError(f"repo must have exact 'owner/name' form; got {repo!r}")
    return parts[0], parts[1]


def _render_marked_body(idempotency_key: str, body: str) -> str:
    return f"{body}\n<!-- acgs-effect-key: {idempotency_key} -->"


class InMemoryGitHubAPI:
    """In-memory GitHub comment API enforcing dedup markers and atomic timeout fencing."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq = 0
        self._comments_by_key: dict[str, dict[str, Any]] = {}
        self._digests_by_key: dict[str, str] = {}
        self._fenced_keys: set[str] = set()
        self._timeout_modes: dict[str, str] = {}
        self.post_calls = 0
        self.query_calls = 0

    def inject_timeout_once(self, idempotency_key: str, *, commit_before_timeout: bool) -> None:
        with self._lock:
            self._timeout_modes[idempotency_key] = (
                "after_commit" if commit_before_timeout else "before_commit"
            )

    def _record_comment(
        self, idempotency_key: str, repo: str, issue_number: int, body: str
    ) -> dict[str, Any]:
        self._seq += 1
        comment_id = f"ic_{self._seq}"
        record = {
            "comment_id": comment_id,
            "repo": repo,
            "issue_number": issue_number,
            "body": _render_marked_body(idempotency_key, body),
            "status": "created",
            "fenced": False,
        }
        self._comments_by_key[idempotency_key] = record
        return dict(record)

    def create_comment(
        self,
        *,
        idempotency_key: str,
        repo: str,
        issue_number: int,
        body: str,
    ) -> dict[str, Any]:
        _validate_repo_slug(repo)
        if type(issue_number) is not int or issue_number <= 0:
            raise ValueError("issue_number must be a positive integer")
        canonical = json.dumps(
            {"repo": repo, "issue_number": issue_number, "body": body},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()

        with self._lock:
            self.post_calls += 1
            if idempotency_key in self._fenced_keys:
                raise RuntimeError(f"Idempotency key {idempotency_key!r} is permanently fenced")
            prev = self._digests_by_key.get(idempotency_key)
            if prev is not None and prev != digest:
                raise GitHubIdempotencyConflictError(
                    f"Idempotency key {idempotency_key!r} reused with mismatched comment payload"
                )
            self._digests_by_key[idempotency_key] = digest

            mode = self._timeout_modes.pop(idempotency_key, None)
            if mode == "after_commit":
                if idempotency_key not in self._comments_by_key:
                    self._record_comment(idempotency_key, repo, issue_number, body)
                raise TimeoutError("simulated GitHub API read timeout after comment creation")
            if mode == "before_commit":
                raise TimeoutError("simulated GitHub API connect timeout before comment creation")

            existing = self._comments_by_key.get(idempotency_key)
            if existing is not None:
                return dict(existing)
            return self._record_comment(idempotency_key, repo, issue_number, body)

    def find_or_fence_comment(
        self,
        *,
        idempotency_key: str,
        repo: str,
        issue_number: int,
    ) -> tuple[EffectOutcome, str | None, bool]:
        _validate_repo_slug(repo)
        if type(issue_number) is not int or issue_number <= 0:
            raise ValueError("issue_number must be a positive integer")
        with self._lock:
            self.query_calls += 1
            existing = self._comments_by_key.get(idempotency_key)
            if existing is not None:
                return EffectOutcome.DONE, str(existing["comment_id"]), False
            self._fenced_keys.add(idempotency_key)
            return EffectOutcome.NOT_DONE, None, True


class LiveGitHubTransport:
    """Real HTTPS GitHub/proxy transport using stdlib ``urllib.request`` without redirects."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str,
        timeout_seconds: float = 10.0,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        host = (parsed.hostname or "").lower()
        is_local = host in ("localhost", "127.0.0.1", "::1")
        if parsed.scheme != "https" and not is_local:
            raise ValueError("LiveGitHubTransport requires an https:// endpoint URL")
        if not isinstance(token, str) or not token.strip():
            raise ValueError("LiveGitHubTransport requires a non-empty bearer token")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout_seconds

    def _headers(self, idempotency_key: str, *, include_json: bool) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-Idempotency-Key": idempotency_key,
        }
        if include_json:
            headers["Content-Type"] = "application/json"
        return headers

    def create_comment(
        self,
        *,
        idempotency_key: str,
        repo: str,
        issue_number: int,
        body: str,
    ) -> dict[str, Any]:
        owner, name = _validate_repo_slug(repo)
        if type(issue_number) is not int or issue_number <= 0:
            raise ValueError("issue_number must be a positive integer")
        payload = json.dumps(
            {
                "body": _render_marked_body(idempotency_key, body),
                "idempotency_key": idempotency_key,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        url = (
            f"{self._base_url}/repos/{urllib.parse.quote(owner, safe='')}/"
            f"{urllib.parse.quote(name, safe='')}/issues/{issue_number}/comments"
        )
        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers=self._headers(idempotency_key, include_json=True),
        )
        try:
            with _GITHUB_NO_REDIRECT_OPENER.open(req, timeout=self._timeout) as resp:  # noqa: S310
                return dict(json.loads(resp.read().decode("utf-8")))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            if exc.code == 409:
                raise GitHubIdempotencyConflictError(err_body) from exc
            raise

    def find_or_fence_comment(
        self,
        *,
        idempotency_key: str,
        repo: str,
        issue_number: int,
    ) -> tuple[EffectOutcome, str | None, bool]:
        owner, name = _validate_repo_slug(repo)
        if type(issue_number) is not int or issue_number <= 0:
            raise ValueError("issue_number must be a positive integer")
        query = urllib.parse.urlencode({"idempotency_key": idempotency_key})
        url = (
            f"{self._base_url}/repos/{urllib.parse.quote(owner, safe='')}/"
            f"{urllib.parse.quote(name, safe='')}/issues/{issue_number}/comments/fence?{query}"
        )
        req = urllib.request.Request(
            url,
            data=b"",
            method="POST",
            headers=self._headers(idempotency_key, include_json=False),
        )
        with _GITHUB_NO_REDIRECT_OPENER.open(req, timeout=self._timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
        comment_id = str(data.get("comment_id")) if data.get("comment_id") else None
        status = str(data.get("status", ""))
        fenced = data.get("fenced") is True
        if status in ("created", "delivered"):
            return EffectOutcome.DONE, comment_id, False
        if status in ("canceled", "fenced") and fenced:
            return EffectOutcome.NOT_DONE, comment_id, True
        return EffectOutcome.UNKNOWN, comment_id, False


class GitHubCommentProvider:
    """``EffectProvider`` adapter for GitHub issue/PR comments under a FENCEABLE contract."""

    contract = ProviderContract(
        provider_id="github-comments",
        contract_class=ProviderContractClass.FENCEABLE,
        version="2026-11",
        dedup_by_key=True,
        atomic_query_fence=True,
    )

    def __init__(self, transport: GitHubTransport | None = None) -> None:
        self._transport: GitHubTransport = (
            transport if transport is not None else InMemoryGitHubAPI()
        )
        self._references: dict[str, str] = {}
        self._targets: dict[str, tuple[str, int]] = {}

    @property
    def provider_id(self) -> str:
        return self.contract.provider_id

    @property
    def transport(self) -> GitHubTransport:
        return self._transport

    def reference_for(self, effect_key: str) -> str | None:
        return self._references.get(effect_key)

    def send(self, request: EffectRequest) -> ProviderResult:
        payload = json.loads(request.action_json)
        repo = str(payload["repo"])
        issue_number = int(payload["issue_number"])
        self._targets[request.key] = (repo, issue_number)
        res = self._transport.create_comment(
            idempotency_key=request.key,
            repo=repo,
            issue_number=issue_number,
            body=str(payload["body"]),
        )
        ref = res.get("comment_id") or res.get("id")
        if ref is not None and str(ref):
            self._references[request.key] = str(ref)
        status = str(res.get("status", "created" if ref is not None else ""))
        fenced = res.get("fenced") is True
        if status in ("created", "delivered"):
            return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE, fenced=True)
        if status in ("canceled", "fenced") and fenced:
            return ProviderResult(
                request.key, self.provider_id, EffectOutcome.NOT_DONE, fenced=True
            )
        return ProviderResult(request.key, self.provider_id, EffectOutcome.UNKNOWN, fenced=False)

    def query_and_fence(self, request: EffectRequest) -> ProviderResult:
        payload = json.loads(request.action_json)
        repo = str(payload.get("repo") or self._targets.get(request.key, ("", 0))[0])
        issue_number = int(
            payload.get("issue_number") or self._targets.get(request.key, ("", 0))[1]
        )
        outcome, ref, fenced = self._transport.find_or_fence_comment(
            idempotency_key=request.key,
            repo=repo,
            issue_number=issue_number,
        )
        if ref is not None:
            self._references[request.key] = ref
        return ProviderResult(request.key, self.provider_id, outcome, fenced=fenced)


def _post_issue_comment(repo: str, issue_number: int, *, scope: str, subject: str) -> None:
    """Callable identity bound into ACGS execution grants."""


def _mint_grant(
    *,
    engine: GovernanceEngine,
    constitution: Constitution,
    authority: ExecutionAuthority,
    signer: Ed25519ReceiptSigner,
    repo: str,
    issue_number: int,
    comment_text: str,
    scope: str,
) -> ExecutionGrant:
    action_text = f"comment on {repo}#{issue_number}: {comment_text}"
    result = engine.validate(action_text, agent_id="github-bot")
    if not result.valid:
        raise ValueError(f"blocked by constitution: {[v.rule_id for v in result.violations]}")
    invocation = bind_invocation(
        _post_issue_comment,
        (repo, issue_number),
        {"scope": scope, "subject": f"{repo}#{issue_number}"},
    )
    policy = bind_policy(constitution)
    decision = engine_decision_from_results([result])
    grant_id = authority.allocate_grant_id()
    try:
        receipt = build_issue_receipt(
            func=_post_issue_comment,
            invocation=invocation,
            policy=policy,
            decision=decision,
            grant_id=grant_id,
        )
        signed = sign_execution_authorization(
            receipt,
            signer,
            authorization_json=authorization_envelope_json(invocation, policy, grant_id=grant_id),
        )
        grant = authority.issue(
            receipt=receipt,
            invocation=invocation,
            policy=policy,
            grant_id=grant_id,
            signed_receipt=signed,
        )
    finally:
        authority.release_grant_id(grant_id)

    validate_receipt_for_execution(
        grant.receipt,
        actual_call=ActualCall(
            method="_post_issue_comment", scope=scope, subjects=(f"{repo}#{issue_number}",)
        ),
    )
    return grant


@dataclass(frozen=True)
class GitHubConformanceResult:
    """Structured conformance summary from :func:`run_github_conformance_suite`."""

    all_passed: bool
    a1_dedup_single_comment: bool
    a2_timeout_committed_reconciles_done: bool
    a2_timeout_uncommitted_reconciles_fenced_not_done: bool
    deny_zero_provider_calls: bool
    outcome_signatures_verified: bool
    contract_identity: str


def run_github_conformance_suite(db_path: Path | None = None) -> GitHubConformanceResult:
    """Run offline A1/A2/DENY conformance checks against InMemoryGitHubAPI."""
    api = InMemoryGitHubAPI()
    provider = GitHubCommentProvider(api)
    signer = Ed25519ReceiptSigner.from_seed(b"acgs-github-conformance-2026-11!"[:32])
    pub = signer.public_key_hex()
    constitution = Constitution(
        name="github-conformance",
        version="2026.11",
        rules=[
            Rule(
                id="no-token-leak",
                text="Block raw credentials from public GitHub comments",
                severity=Severity.CRITICAL,
                keywords=["ghp_secret", "raw_ssn"],
            )
        ],
    )
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    registry = ProviderContractRegistry()
    contract = registry.register(provider.contract)

    def _exec(path: Path) -> GitHubConformanceResult:
        store = EffectStore(path)
        store.create_budget("github-conformance", 100)
        contracted = ContractedEffectStore(store, registry)

        # 1. A1 dedup
        g1 = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            repo="acgs-ai/acgs-lite",
            issue_number=101,
            comment_text="Verified build receipts attached.",
            scope="prod-github",
        )
        e1 = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(g1),
            action={
                "repo": "acgs-ai/acgs-lite",
                "issue_number": 101,
                "body": "Verified build receipts attached.",
            },
            budget_id="github-conformance",
            amount=1,
        )
        rec1 = contracted.send(e1.key, provider, grant=g1)
        dup = api.create_comment(
            idempotency_key=e1.key,
            repo="acgs-ai/acgs-lite",
            issue_number=101,
            body="Verified build receipts attached.",
        )
        o1 = sign_outcome(
            outcome_from_record(
                rec1,
                store=contracted,
                provider=provider,
                grant=g1,
                provider_reference=provider.reference_for(e1.key),
            ),
            signer,
        )
        a1_ok = (
            rec1.state is EffectState.DONE
            and dup["comment_id"] == provider.reference_for(e1.key)
            and o1.verify(pub)
        )

        # 2. A2 timeout committed -> reconcile across store reopen -> DONE
        g2 = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            repo="acgs-ai/acgs-lite",
            issue_number=102,
            comment_text="Release readiness check complete.",
            scope="prod-github",
        )
        e2 = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(g2),
            action={
                "repo": "acgs-ai/acgs-lite",
                "issue_number": 102,
                "body": "Release readiness check complete.",
            },
            budget_id="github-conformance",
            amount=1,
        )
        api.inject_timeout_once(e2.key, commit_before_timeout=True)
        a2_done_ok = False
        o2_ok = False
        try:
            contracted.send(e2.key, provider, grant=g2)
        except TimeoutError:
            reopened = ContractedEffectStore(EffectStore(path), registry)
            rec2 = reopened.reconcile(e2.key, provider)
            o2 = sign_outcome(
                outcome_from_record(
                    rec2,
                    store=reopened,
                    provider=provider,
                    grant=g2,
                    provider_reference=provider.reference_for(e2.key),
                ),
                signer,
            )
            a2_done_ok = rec2.state is EffectState.DONE
            o2_ok = o2.verify(pub)

        # 3. A2 timeout uncommitted -> reconcile fences -> NOT_DONE
        g3 = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            repo="acgs-ai/acgs-lite",
            issue_number=103,
            comment_text="Deploy check summary.",
            scope="prod-github",
        )
        e3 = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(g3),
            action={
                "repo": "acgs-ai/acgs-lite",
                "issue_number": 103,
                "body": "Deploy check summary.",
            },
            budget_id="github-conformance",
            amount=1,
        )
        api.inject_timeout_once(e3.key, commit_before_timeout=False)
        a2_not_done_ok = False
        o3_ok = False
        try:
            contracted.send(e3.key, provider, grant=g3)
        except TimeoutError:
            rec3 = contracted.reconcile(e3.key, provider)
            o3 = sign_outcome(
                outcome_from_record(rec3, store=contracted, provider=provider, grant=g3),
                signer,
            )
            a2_not_done_ok = rec3.state is EffectState.NOT_DONE
            o3_ok = o3.verify(pub)

        # 4. DENY zero dispatch
        before_calls = api.post_calls
        deny_ok = False
        try:
            _mint_grant(
                engine=engine,
                constitution=constitution,
                authority=authority,
                signer=signer,
                repo="acgs-ai/acgs-lite",
                issue_number=104,
                comment_text="token ghp_secret",
                scope="prod-github",
            )
        except ValueError:
            deny_ok = api.post_calls == before_calls

        sigs_ok = o1.verify(pub) and o2_ok and o3_ok
        all_passed = a1_ok and a2_done_ok and a2_not_done_ok and deny_ok and sigs_ok
        return GitHubConformanceResult(
            all_passed=all_passed,
            a1_dedup_single_comment=a1_ok,
            a2_timeout_committed_reconciles_done=a2_done_ok,
            a2_timeout_uncommitted_reconciles_fenced_not_done=a2_not_done_ok,
            deny_zero_provider_calls=deny_ok,
            outcome_signatures_verified=sigs_ok,
            contract_identity=contract.identity,
        )

    if db_path is not None:
        return _exec(db_path)
    with tempfile.TemporaryDirectory(prefix="acgs-github-") as tmp_dir:
        return _exec(Path(tmp_dir) / "github_effects.sqlite")


def run_live_github_verification(
    transport: GitHubTransport,
    *,
    repo: str = "acgs-ai/acgs-lite",
    issue_number: int = 1,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Exercise a live or local HTTPS GitHubTransport end-to-end."""
    provider = GitHubCommentProvider(transport)
    signer = Ed25519ReceiptSigner.from_seed(b"acgs-github-live-verify-2026-11!"[:32])
    constitution = Constitution(
        name="github-live",
        version="2026.11",
        rules=[
            Rule(
                id="no-token-leak",
                text="Block raw credentials from public GitHub comments",
                severity=Severity.CRITICAL,
                keywords=["ghp_secret"],
            )
        ],
    )
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    registry = ProviderContractRegistry()
    registry.register(provider.contract)

    def _run(path: Path) -> dict[str, Any]:
        store = EffectStore(path)
        store.create_budget("github-live", 100)
        contracted = ContractedEffectStore(store, registry)
        grant = _mint_grant(
            engine=engine,
            constitution=constitution,
            authority=authority,
            signer=signer,
            repo=repo,
            issue_number=issue_number,
            comment_text="ACGS GitHub smoke verification comment",
            scope="test-github",
        )
        effect = store.reserve(
            provider_id=provider.provider_id,
            grant_identity=local_grant_identity(grant),
            action={
                "repo": repo,
                "issue_number": issue_number,
                "body": "ACGS GitHub smoke verification comment",
            },
            budget_id="github-live",
            amount=1,
        )
        try:
            rec = contracted.send(effect.key, provider, grant=grant)
            dup = transport.create_comment(
                idempotency_key=effect.key,
                repo=repo,
                issue_number=issue_number,
                body="ACGS GitHub smoke verification comment",
            )
            outcome, _, _ = transport.find_or_fence_comment(
                idempotency_key=effect.key,
                repo=repo,
                issue_number=issue_number,
            )
        except Exception as exc:
            return {
                "transport": type(transport).__name__,
                "effect_key": effect.key,
                "passed": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        ref = provider.reference_for(effect.key)
        dup_ref = dup.get("comment_id") or dup.get("id")
        dedup_ok = (
            isinstance(ref, str) and bool(ref) and dup_ref is not None and str(dup_ref) == ref
        )
        return {
            "transport": type(transport).__name__,
            "effect_key": effect.key,
            "state": rec.state.value,
            "provider_reference": ref,
            "idempotent_dedup_matched": dedup_ok,
            "reconcile_outcome": outcome.value,
            "passed": (
                rec.state is EffectState.DONE and dedup_ok and outcome is EffectOutcome.DONE
            ),
        }

    if db_path is not None:
        return _run(db_path)
    with tempfile.TemporaryDirectory(prefix="acgs-github-live-") as tmp_dir:
        return _run(Path(tmp_dir) / "github_live.sqlite")


def main() -> int:
    res = run_github_conformance_suite()
    live_url = os.environ.get("ACGS_GITHUB_TEST_URL")
    if not live_url:
        print(json.dumps(res.__dict__, indent=2))
        return 0 if res.all_passed else 1

    token = os.environ.get("ACGS_GITHUB_TEST_TOKEN", "")
    repo = os.environ.get("ACGS_GITHUB_TEST_REPO", "acgs-ai/acgs-lite")
    try:
        issue_number = int(os.environ.get("ACGS_GITHUB_TEST_ISSUE", "1"))
        transport = LiveGitHubTransport(live_url, token=token)
        live = run_live_github_verification(transport, repo=repo, issue_number=issue_number)
    except Exception as exc:
        live = {
            "transport": "LiveGitHubTransport",
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    all_passed = bool(res.all_passed and live["passed"])
    print(
        json.dumps(
            {
                "all_passed": all_passed,
                "sandbox_conformance": res.__dict__,
                "live_verification": live,
            },
            indent=2,
        )
    )
    return 0 if all_passed else 1
