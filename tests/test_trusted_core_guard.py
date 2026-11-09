"""Trusted workflow authorization rejects forged, stale and ambiguous evidence."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import urllib.error
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

spec = importlib.util.spec_from_file_location(
    "trusted_core_guard", Path(__file__).parents[1] / "scripts/trusted_core_guard.py"
)
assert spec and spec.loader
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
pytestmark = pytest.mark.unit
BASE, HEAD = "a" * 40, "b" * 40
REPO = {"full_name": "acgs-ai/acgs-lite", "id": 1201916496}
ACTOR = {"login": "dislovelhl", "id": 253742157, "type": "User"}
NOW = datetime(2026, 11, 9, tzinfo=timezone.utc)
PREFIX = "/repos/acgs-ai/acgs-lite"
WORKFLOW = "immutable-core-authorize.yml"
COMPARE = PREFIX + f"/compare/{BASE}...{HEAD}?per_page=1&page=1"


class FakeAPI:
    def __init__(self) -> None:
        self.routes: dict[str, Any] = {}
        self.calls: list[str] = []
        self.raw = b""

    def json(self, path: str) -> Any:
        self.calls.append(path)
        result = self.routes[path]
        if isinstance(result, Exception):
            raise result
        return copy.deepcopy(result)

    def archive(self, path: str) -> bytes:
        assert path == PREFIX + "/actions/artifacts/30/zip"
        return self.raw


@pytest.fixture()
def case(tmp_path: Path) -> tuple[Any, FakeAPI, dict[str, Any]]:
    policy = {
        "schema_version": 1,
        "repository": REPO,
        "default_branch": "main",
        "maintainers": [{"login": ACTOR["login"], "id": ACTOR["id"]}],
        "authorization_workflow": WORKFLOW,
        "max_age_seconds": 86400,
        "protected_paths": [{"pattern": "core/**", "regex": "core/.*", "flags": 50}],
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))
    policy = guard.policy_from(str(policy_path))
    env = {
        "PR_NUMBER": "237",
        "BASE_SHA": BASE,
        "HEAD_SHA": HEAD,
        "GITHUB_SHA": BASE,
        "GITHUB_WORKFLOW_SHA": BASE,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": "acgs-ai/acgs-lite/.github/workflows/immutable-core-guard.yml@refs/heads/main",
        "GITHUB_EVENT_NAME": "pull_request_target",
        "GITHUB_ACTOR": ACTOR["login"],
        "GITHUB_TRIGGERING_ACTOR": ACTOR["login"],
        "GITHUB_RUN_ID": "20",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    api = FakeAPI()
    api.routes[PREFIX] = REPO
    api.routes[PREFIX + "/git/ref/heads/main"] = {"object": {"sha": BASE}}
    api.routes[PREFIX + "/pulls/237"] = {
        "number": 237,
        "state": "open",
        "merged": False,
        "changed_files": 1,
        "base": {"ref": "main", "sha": BASE, "repo": REPO},
        "head": {"sha": HEAD, "repo": {**REPO, "fork": False}},
    }
    api.routes[COMPARE] = {
        "base_commit": {"sha": BASE},
        "merge_base_commit": {"sha": BASE},
        "files": [{"filename": "core/guard.py", "status": "modified"}],
    }
    api.routes[PREFIX + "/collaborators/dislovelhl/permission"] = {
        "permission": "admin",
        "user": ACTOR,
    }
    api.routes[PREFIX + "/actions/workflows/" + WORKFLOW] = {
        "id": 10,
        "path": ".github/workflows/" + WORKFLOW,
        "state": "active",
    }
    api.routes[
        PREFIX
        + "/actions/workflows/10/runs?event=workflow_dispatch&branch=main&status=success&per_page=100&page=1"
    ] = {"workflow_runs": [{"id": 20}]}
    api.routes[PREFIX + "/actions/runs/20"] = {
        "id": 20,
        "workflow_id": 10,
        "path": ".github/workflows/" + WORKFLOW,
        "repository": REPO,
        "head_repository": REPO,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": BASE,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "created_at": (NOW - timedelta(minutes=5)).isoformat(),
        "updated_at": (NOW - timedelta(minutes=1)).isoformat(),
        "actor": ACTOR,
        "triggering_actor": ACTOR,
    }
    record = {
        "schema_version": 1,
        "repository": REPO,
        "pr_number": 237,
        "base_sha": BASE,
        "head_sha": HEAD,
        "trusted_revision": BASE,
        "actor": {"login": ACTOR["login"], "id": ACTOR["id"]},
        "run_id": 20,
        "issued_at": (NOW - timedelta(minutes=2)).isoformat(),
    }
    set_artifact(api, record)
    return guard.Guard(policy, api, env, NOW), api, record


def set_artifact(
    api: FakeAPI, record: Any, name: str = "authorization.json", duplicate: bool = False
) -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(name, json.dumps(record))
        if duplicate:
            archive.writestr("extra.json", "{}")
    api.raw = stream.getvalue()
    api.routes[PREFIX + "/actions/runs/20/artifacts?per_page=100&page=1"] = {
        "total_count": 1,
        "artifacts": [
            {
                "name": "immutable-core-authorization",
                "id": 30,
                "expired": False,
                "expires_at": (NOW + timedelta(days=1)).isoformat(),
                "size_in_bytes": len(api.raw),
                "workflow_run": {"id": 20},
                "digest": "sha256:" + hashlib.sha256(api.raw).hexdigest(),
            }
        ],
    }


def test_valid_exact_authorization(case: Any) -> None:
    verifier, api, _ = case
    assert verifier.verify() == {
        "authorized": True,
        "protected": True,
        "pr_number": 237,
        "run_id": 20,
    }
    assert not any("statuses" in path or "check-runs" in path for path in api.calls)
    assert api.calls.count(PREFIX + "/pulls/237") == 2


@pytest.mark.parametrize(
    "key,value",
    [
        ("PR_NUMBER", "01"),
        ("PR_NUMBER", "237/../238"),
        ("HEAD_SHA", "bad"),
        ("BASE_SHA", HEAD),
        ("GITHUB_WORKFLOW_SHA", HEAD),
        ("GITHUB_SHA", HEAD),
        ("GITHUB_REF", "refs/pull/237/merge"),
        (
            "GITHUB_WORKFLOW_REF",
            "evil/repo/.github/workflows/immutable-core-guard.yml@refs/heads/main",
        ),
        ("GITHUB_EVENT_NAME", "pull_request"),
    ],
)
def test_untrusted_environment(case: Any, key: str, value: str) -> None:
    verifier, _, _ = case
    verifier.env[key] = value
    with pytest.raises(guard.Denied):
        verifier.verify()


@pytest.mark.parametrize("mutation", ["closed", "fork", "head", "base", "target", "repo", "main"])
def test_pr_identity_and_revisions(case: Any, mutation: str) -> None:
    verifier, api, _ = case
    pr = api.routes[PREFIX + "/pulls/237"]
    if mutation == "closed":
        pr["state"] = "closed"
    elif mutation == "fork":
        pr["head"]["repo"]["fork"] = True
    elif mutation in ("head", "base"):
        pr[mutation]["sha"] = "c" * 40
    elif mutation == "target":
        pr["base"]["ref"] = "other"
    elif mutation == "repo":
        pr["head"]["repo"]["id"] = 99
    else:
        api.routes[PREFIX + "/git/ref/heads/main"]["object"]["sha"] = HEAD
    with pytest.raises(guard.Denied):
        verifier.verify()


@pytest.mark.parametrize(
    "path",
    [
        "../core/a",
        "/core/a",
        "core//a",
        "core/./a",
        "core/a\x00",
        "core\\a",
        "core/%2e%2e/a",
        "",
        None,
    ],
)
def test_malformed_paths_fail_closed(case: Any, path: Any) -> None:
    verifier, api, _ = case
    api.routes[COMPARE]["files"][0]["filename"] = path
    with pytest.raises(guard.Denied):
        verifier.verify()


def test_rename_old_path_and_case_flags_protected(case: Any) -> None:
    verifier, api, _ = case
    api.routes[COMPARE]["files"] = [
        {"filename": "docs/a", "previous_filename": "CORE/a", "status": "renamed"}
    ]
    assert verifier.verify()["protected"]


def test_unprotected_change_requires_no_artifact(case: Any) -> None:
    verifier, api, _ = case
    api.routes[COMPARE]["files"] = [{"filename": "docs/core/a", "status": "modified"}]
    assert verifier.verify()["protected"] is False
    assert not any("/actions/" in path for path in api.calls)


@pytest.mark.parametrize("count", [101, 299])
def test_complete_immutable_comparison(case: Any, count: int) -> None:
    verifier, api, _ = case
    api.routes[PREFIX + "/pulls/237"]["changed_files"] = count
    api.routes[COMPARE]["files"] = [
        {"filename": f"docs/{i}", "status": "modified"} for i in range(count)
    ]
    assert verifier.verify()["protected"] is False
    assert api.calls.count(COMPARE) == 1


@pytest.mark.parametrize("count", [0, 2, 300, 3001, True])
def test_changed_file_count_mismatch(case: Any, count: Any) -> None:
    verifier, api, _ = case
    api.routes[PREFIX + "/pulls/237"]["changed_files"] = count
    with pytest.raises(guard.Denied):
        verifier.verify()


@pytest.mark.parametrize(
    "field,value",
    [
        ("workflow_id", 11),
        ("path", ".github/workflows/fake.yml"),
        ("event", "push"),
        ("head_branch", "other"),
        ("head_sha", HEAD),
        ("run_attempt", 2),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("created_at", "2026-11-01T00:00:00Z"),
        ("actor", {"login": "intruder", "id": 77}),
        ("triggering_actor", {"login": "dislovelhl", "id": 77}),
        ("repository", {"id": 1, "full_name": "acgs-ai/acgs-lite"}),
    ],
)
def test_untrusted_run_rejected_even_if_listed_successful(
    case: Any, field: str, value: Any
) -> None:
    verifier, api, _ = case
    api.routes[PREFIX + "/actions/runs/20"][field] = value
    with pytest.raises(guard.Denied):
        verifier.verify()


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", BASE),
        ("base_sha", HEAD),
        ("trusted_revision", HEAD),
        ("pr_number", 238),
        ("run_id", 21),
        ("actor", {"login": "intruder", "id": 77}),
        ("issued_at", "2026-11-01T00:00:00Z"),
        ("issued_at", "2026-11-10T00:00:00Z"),
        ("schema_version", 2),
    ],
)
def test_stale_or_replayed_artifact_record(case: Any, field: str, value: Any) -> None:
    verifier, api, record = case
    record[field] = value
    set_artifact(api, record)
    with pytest.raises(guard.Denied):
        verifier.verify()


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "duplicate",
        "expired",
        "digest",
        "run",
        "oversize",
        "corrupt",
        "path",
        "extra",
        "truncated_listing",
    ],
)
def test_bad_artifacts_rejected(case: Any, mutation: str) -> None:
    verifier, api, record = case
    listing = api.routes[PREFIX + "/actions/runs/20/artifacts?per_page=100&page=1"]
    artifact = listing["artifacts"][0]
    if mutation == "missing":
        listing.update(total_count=0, artifacts=[])
    elif mutation == "duplicate":
        listing["artifacts"].append(copy.deepcopy(artifact))
        listing["total_count"] = 2
    elif mutation == "expired":
        artifact["expired"] = True
    elif mutation == "digest":
        artifact["digest"] = "sha256:" + "0" * 64
    elif mutation == "run":
        artifact["workflow_run"]["id"] = 21
    elif mutation == "oversize":
        artifact["size_in_bytes"] = guard.MAX_BYTES + 1
    elif mutation == "corrupt":
        api.raw = b"not zip"
        artifact["digest"] = "sha256:" + hashlib.sha256(api.raw).hexdigest()
    elif mutation == "path":
        set_artifact(api, record, "../authorization.json")
    elif mutation == "extra":
        set_artifact(api, record, duplicate=True)
    else:
        listing["total_count"] = 2
    with pytest.raises(guard.Denied):
        verifier.verify()


@pytest.mark.parametrize("permission", ["write", "read", "none"])
def test_revoked_admin_cannot_authorize(case: Any, permission: str) -> None:
    verifier, api, _ = case
    api.routes[PREFIX + "/collaborators/dislovelhl/permission"]["permission"] = permission
    with pytest.raises(guard.Denied):
        verifier.verify()


def prepare_authorize(case: Any, tmp_path: Path) -> tuple[Any, FakeAPI]:
    verifier, api, _ = case
    verifier.env.update(
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_WORKFLOW_REF="acgs-ai/acgs-lite/.github/workflows/immutable-core-authorize.yml@refs/heads/main",
    )
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps({"inputs": {"pr_number": "237", "base_sha": BASE, "head_sha": HEAD}})
    )
    verifier.env["GITHUB_EVENT_PATH"] = str(event)
    api.routes[PREFIX + "/actions/runs/20"].update(status="in_progress", conclusion=None)
    return verifier, api


def test_authorize_checks_server_run_and_writes_exact_record(case: Any, tmp_path: Path) -> None:
    verifier, api = prepare_authorize(case, tmp_path)
    output = tmp_path / "authorization.json"
    assert verifier.authorize(str(output))["authorized"]
    data = json.loads(output.read_text())
    assert data["run_id"] == 20 and data["base_sha"] == BASE and data["head_sha"] == HEAD
    assert PREFIX + "/actions/runs/20" in api.calls


@pytest.mark.parametrize(
    "mutation", ["rerun", "actor", "trigger", "server_actor", "inputs", "workflow"]
)
def test_authorize_refuses_untrusted_dispatch(case: Any, tmp_path: Path, mutation: str) -> None:
    verifier, api = prepare_authorize(case, tmp_path)
    if mutation == "rerun":
        verifier.env["GITHUB_RUN_ATTEMPT"] = "2"
    elif mutation == "actor":
        verifier.env["GITHUB_ACTOR"] = "intruder"
    elif mutation == "trigger":
        verifier.env["GITHUB_TRIGGERING_ACTOR"] = "intruder"
    elif mutation == "server_actor":
        api.routes[PREFIX + "/actions/runs/20"]["actor"] = {"login": "intruder", "id": 77}
    elif mutation == "inputs":
        Path(verifier.env["GITHUB_EVENT_PATH"]).write_text(
            json.dumps({"inputs": {"pr_number": "238", "base_sha": BASE, "head_sha": HEAD}})
        )
    else:
        api.routes[PREFIX + "/actions/runs/20"]["workflow_id"] = 99
    output = tmp_path / "authorization.json"
    with pytest.raises(guard.Denied):
        verifier.authorize(str(output))
    assert not output.exists()


def test_json_duplicate_keys_and_nonfinite_fail() -> None:
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
        with pytest.raises(guard.Denied):
            guard.strict_json(raw)


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/archive?sig=x",
        "http://x.blob.core.windows.net/a?sig=x",
        "https://x.blob.core.windows.net/a",
        "https://user:pass@x.blob.core.windows.net/a?sig=x",
        "https://x.blob.core.windows.net.evil.example/a?sig=x",
    ],
)
def test_artifact_redirect_host_restrictions(location: str) -> None:
    api = guard.GitHubAPI("secret-token")

    class Opener:
        def open(self, request: Any, timeout: int) -> Any:
            raise urllib.error.HTTPError(
                request.full_url, 302, "redirect", {"Location": location}, None
            )

    api.opener = Opener()
    with pytest.raises(guard.Denied):
        api.archive(PREFIX + "/actions/artifacts/30/zip")


def test_artifact_redirect_never_forwards_token() -> None:
    api = guard.GitHubAPI("secret-token")
    calls = []

    class Opener:
        def open(self, request: Any, timeout: int) -> Any:
            calls.append(request)
            if len(calls) == 1:
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "redirect",
                    {"Location": "https://production.blob.core.windows.net/artifact?sig=signed"},
                    None,
                )
            return io.BytesIO(b"archive")

    api.opener = Opener()
    assert api.archive(PREFIX + "/actions/artifacts/30/zip") == b"archive"
    assert calls[0].get_header("Authorization") == "Bearer secret-token"
    assert calls[1].get_header("Authorization") is None


def test_guard_dispatch_recheck_uses_guard_source(case: Any, tmp_path: Path) -> None:
    verifier, _, _ = case
    event = tmp_path / "dispatch.json"
    event.write_text(
        json.dumps({"inputs": {"pr_number": "237", "base_sha": BASE, "head_sha": HEAD}})
    )
    verifier.env.update(GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_EVENT_PATH=str(event))
    assert verifier.verify()["authorized"]
    verifier.env["GITHUB_WORKFLOW_REF"] = (
        "acgs-ai/acgs-lite/.github/workflows/immutable-core-authorize.yml@refs/heads/main"
    )
    with pytest.raises(guard.Denied):
        verifier.verify()


def test_guard_dispatch_recheck_rejects_mismatched_inputs(case: Any, tmp_path: Path) -> None:
    verifier, _, _ = case
    event = tmp_path / "dispatch.json"
    event.write_text(
        json.dumps({"inputs": {"pr_number": "238", "base_sha": BASE, "head_sha": HEAD}})
    )
    verifier.env.update(GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_EVENT_PATH=str(event))
    with pytest.raises(guard.Denied):
        verifier.verify()


def test_authorize_creates_missing_output_parent(case: Any, tmp_path: Path) -> None:
    verifier, _ = prepare_authorize(case, tmp_path)
    output = tmp_path / "new" / "authorization.json"
    verifier.authorize(str(output))
    assert output.is_file()


def test_head_change_during_verification_invalidates_result(
    case: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, api, _ = case
    original = api.archive

    def move_head(path: str) -> bytes:
        api.routes[PREFIX + "/pulls/237"]["head"]["sha"] = "c" * 40
        return original(path)

    monkeypatch.setattr(api, "archive", move_head)
    with pytest.raises(guard.Denied):
        verifier.verify()


def test_duplicate_changed_paths_are_not_complete(case: Any) -> None:
    verifier, api, _ = case
    api.routes[PREFIX + "/pulls/237"]["changed_files"] = 2
    api.routes[COMPARE]["files"] *= 2
    with pytest.raises(guard.Denied):
        verifier.verify()


def test_rename_missing_previous_path_is_denied(case: Any) -> None:
    verifier, api, _ = case
    api.routes[COMPARE]["files"][0]["status"] = "renamed"
    with pytest.raises(guard.Denied):
        verifier.verify()


def test_run_search_is_bounded(case: Any) -> None:
    verifier, api, _ = case
    route = (
        PREFIX
        + "/actions/workflows/10/runs?event=workflow_dispatch&branch=main&status=success&per_page=100&page=1"
    )
    api.routes[route]["workflow_runs"] = [{"id": 20}] * 101
    with pytest.raises(guard.Denied):
        verifier.verify()


def test_missing_permission_access_fails_closed(case: Any) -> None:
    verifier, api, _ = case
    api.routes[PREFIX + "/collaborators/dislovelhl/permission"] = OSError("API denied")
    with pytest.raises(guard.Denied):
        verifier.verify()


@pytest.mark.parametrize(
    "path",
    [
        "ｓｃｒｉｐｔｓ/untrusted.py",
        " scripts/evil.py",
        "scripts./evil.py",
        "scripts /evil.py",
        "core/a ",
        "core/a.",
        "C:/temp/evil.py",
        "C:temp/evil.py",
        "~/evil.py",
        "https://evil.example/a",
    ],
)
def test_registry_path_aliases_fail_closed(case: Any, path: str) -> None:
    verifier, api, _ = case
    api.routes[COMPARE]["files"][0]["filename"] = path
    with pytest.raises(guard.Denied, match="noncanonical"):
        verifier.verify()


def test_transient_pr_head_swap_cannot_hide_protected_diff(case: Any) -> None:
    verifier, api, _ = case
    # Before and after metadata both name HEAD. While the mutable files API is
    # served, an attacker switches to a benign same-size diff and restores HEAD.
    api.routes[PREFIX + "/pulls/237/files?per_page=100&page=1"] = [
        {"filename": "docs/benign.txt", "status": "modified"}
    ]
    api.routes[PREFIX + f"/compare/{BASE}...{HEAD}?per_page=1&page=1"] = {
        "base_commit": {"sha": BASE},
        "merge_base_commit": {"sha": BASE},
        "files": [{"filename": "core/guard.py", "status": "modified"}],
    }
    api.routes[
        PREFIX
        + "/actions/workflows/10/runs?event=workflow_dispatch&branch=main&status=success&per_page=100&page=1"
    ]["workflow_runs"] = []
    with pytest.raises(guard.Denied, match="no fresh trusted authorization"):
        verifier.verify()
    assert not any("/pulls/237/files" in path for path in api.calls)


@pytest.mark.parametrize(
    "mutation", ["missing_files", "saturated", "base", "duplicate", "rename_source"]
)
def test_immutable_comparison_requires_complete_bound_paths(case: Any, mutation: str) -> None:
    verifier, api, _ = case
    comparison = api.routes[COMPARE]
    if mutation == "missing_files":
        del comparison["files"]
    elif mutation == "saturated":
        comparison["files"] = [{"filename": f"docs/{i}", "status": "modified"} for i in range(300)]
    elif mutation == "base":
        comparison["base_commit"]["sha"] = HEAD
    elif mutation == "duplicate":
        api.routes[PREFIX + "/pulls/237"]["changed_files"] = 2
        comparison["files"] *= 2
    else:
        comparison["files"][0] = {"filename": "docs/a", "status": "renamed"}
    with pytest.raises(guard.Denied):
        verifier.verify()
