#!/usr/bin/env python3
"""Verify immutable-core authorization from trusted workflow runs and artifacts."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_BYTES = 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}")


class Denied(ValueError):
    """Unverifiable authorization never permits a protected change."""


def require(condition: Any, reason: str) -> None:
    if not condition:
        raise Denied(reason)


def strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def invalid(value: str) -> Any:
        raise Denied("non-finite JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def timestamp(value: Any) -> datetime:
    require(isinstance(value, str), "missing timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Denied("invalid timestamp") from exc
    require(result.tzinfo is not None, "timestamp must include timezone")
    return result.astimezone(timezone.utc)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any
    ) -> None:
        return None


class GitHubAPI:
    def __init__(self, token: str) -> None:
        require(bool(token), "GitHub API token missing")
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def _request(self, url: str, *, authenticated: bool) -> Any:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        return self.opener.open(urllib.request.Request(url, headers=headers), timeout=30)

    @staticmethod
    def _read(response: Any) -> bytes:
        data = response.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "response exceeds size limit")
        return data

    def json(self, path: str) -> Any:
        require(path.startswith("/") and not path.startswith("//"), "invalid API path")
        with self._request("https://api.github.com" + path, authenticated=True) as response:
            return strict_json(self._read(response))

    def archive(self, path: str) -> bytes:
        require(
            re.fullmatch(r"/repos/[\w.-]+/[\w.-]+/actions/artifacts/[1-9][0-9]*/zip", path),
            "invalid artifact API path",
        )
        try:
            with self._request("https://api.github.com" + path, authenticated=True) as response:
                return self._read(response)
        except urllib.error.HTTPError as exc:
            require(exc.code in (301, 302, 303, 307, 308), "artifact download failed")
            url = exc.headers.get("Location", "")
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
        query = urllib.parse.parse_qs(parsed.query)
        require(
            parsed.scheme == "https"
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password,
            "unsafe artifact redirect",
        )
        require(
            host.endswith(".blob.core.windows.net") and bool(query.get("sig")),
            "untrusted artifact download host",
        )
        # Never forward the repository token to the signed storage URL.
        with self._request(url, authenticated=False) as response:
            return self._read(response)


def policy_from(path: str) -> dict[str, Any]:
    policy = strict_json(Path(path).read_bytes())
    require(type(policy) is dict and policy.get("schema_version") == 1, "unsupported policy")
    repo = policy.get("repository")
    require(
        type(repo) is dict and re.fullmatch(r"[\w.-]+/[\w.-]+", str(repo.get("full_name", ""))),
        "invalid policy repository",
    )
    require(type(repo.get("id")) is int and repo["id"] > 0, "invalid repository id")
    require(policy.get("default_branch") == "main", "only main policy supported")
    require(
        re.fullmatch(r"[\w.-]+\.yml", str(policy.get("authorization_workflow", ""))),
        "invalid workflow name",
    )
    require(
        type(policy.get("max_age_seconds")) is int and 0 < policy["max_age_seconds"] <= 86400,
        "invalid authorization lifetime",
    )
    maintainers = policy.get("maintainers")
    require(type(maintainers) is list and bool(maintainers), "missing maintainers")
    for actor in maintainers:
        require(
            type(actor) is dict
            and re.fullmatch(r"[\w-]+", str(actor.get("login", "")))
            and type(actor.get("id")) is int
            and actor["id"] > 0,
            "invalid maintainer",
        )
    patterns = policy.get("protected_paths")
    require(type(patterns) is list and bool(patterns), "missing protected paths")
    for entry in patterns:
        require(
            type(entry) is dict
            and isinstance(entry.get("pattern"), str)
            and isinstance(entry.get("regex"), str),
            "invalid protected pattern",
        )
        flags = entry.get("flags")
        require(
            type(flags) is int
            and flags >= 0
            and not flags & ~(re.I | re.M | re.S | re.X | re.A | re.U),
            "invalid regex flags",
        )
        re.compile(entry["regex"], flags)
    return policy


class Guard:
    def __init__(
        self, policy: dict[str, Any], api: Any, env: dict[str, str], now: datetime | None = None
    ) -> None:
        self.policy, self.api, self.env = policy, api, env
        self.now = now or datetime.now(timezone.utc)
        self.repo = policy["repository"]
        self.prefix = "/repos/" + self.repo["full_name"]
        self.workflow_name = policy["authorization_workflow"]

    def repository(self, repo: Any) -> None:
        require(
            type(repo) is dict
            and repo.get("id") == self.repo["id"]
            and repo.get("full_name") == self.repo["full_name"],
            "repository identity mismatch",
        )

    def maintainer(self, actor: Any) -> dict[str, Any]:
        require(
            type(actor) is dict and actor.get("type", "User") == "User",
            "actor is not a User account",
        )
        identity = {"login": actor.get("login"), "id": actor.get("id")}
        require(identity in self.policy["maintainers"], "actor is not an authorized maintainer")
        current = self.api.json(self.prefix + "/collaborators/" + identity["login"] + "/permission")
        require(current.get("permission") == "admin", "maintainer admin permission revoked")
        user = current.get("user", {})
        require(
            user.get("login") == identity["login"]
            and user.get("id") == identity["id"]
            and user.get("type") == "User",
            "maintainer identity changed",
        )
        return identity

    def live_pr(self, workflow_name: str = "immutable-core-guard.yml") -> dict[str, Any]:
        number = self.env.get("PR_NUMBER", "")
        require(re.fullmatch(r"[1-9][0-9]*", number), "invalid PR number")
        base, head = self.env.get("BASE_SHA", ""), self.env.get("HEAD_SHA", "")
        require(SHA.fullmatch(base) and SHA.fullmatch(head), "invalid revision")
        require(
            self.env.get("GITHUB_SHA") == base and self.env.get("GITHUB_WORKFLOW_SHA") == base,
            "workflow revision is not trusted base",
        )
        require(self.env.get("GITHUB_REF") == "refs/heads/main", "workflow must run from main")
        workflow_ref = self.env.get("GITHUB_WORKFLOW_REF", "")
        require(
            workflow_ref
            == self.repo["full_name"] + "/.github/workflows/" + workflow_name + "@refs/heads/main",
            "unexpected workflow source",
        )
        self.repository(self.api.json(self.prefix))
        main = self.api.json(self.prefix + "/git/ref/heads/main")
        require(main.get("object", {}).get("sha") == base, "main moved from authorized base")
        pr = self.api.json(self.prefix + "/pulls/" + number)
        require(
            pr.get("number") == int(number) and pr.get("state") == "open" and not pr.get("merged"),
            "PR is not open",
        )
        self.repository(pr.get("base", {}).get("repo"))
        self.repository(pr.get("head", {}).get("repo"))
        require(
            pr["base"].get("ref") == "main"
            and pr["base"].get("sha") == base
            and pr["head"].get("sha") == head,
            "PR revision or target changed",
        )
        require(pr["head"]["repo"].get("fork") is False, "fork PR is unsupported")
        return pr

    def protected(self, pr: dict[str, Any]) -> bool:
        count = pr.get("changed_files")
        # GitHub comparison files are only present on page 1 and capped at 300.
        # Never guess whether a saturated response is complete. Larger changes
        # need to be split before this guard can authorize them.
        if type(count) is not int or not 0 <= count < 300:
            raise Denied("immutable comparison supports fewer than 300 changed files")
        comparison = self.api.json(
            self.prefix
            + f"/compare/{self.env['BASE_SHA']}...{self.env['HEAD_SHA']}?per_page=1&page=1"
        )
        require(type(comparison) is dict, "invalid immutable comparison")
        require(
            comparison.get("base_commit", {}).get("sha") == self.env["BASE_SHA"],
            "comparison base revision mismatch",
        )
        entries = comparison.get("files")
        require(type(entries) is list and len(entries) < 300, "incomplete immutable comparison")
        require(len(entries) == count, "immutable comparison file count mismatch")
        seen: set[str] = set()
        protected = False
        for item in entries:
            require(type(item) is dict, "invalid changed-file entry")
            path = item.get("filename")
            require(path not in seen if isinstance(path, str) else False, "duplicate changed file")
            seen.add(path)
            paths = [path]
            if item.get("status") == "renamed":
                require("previous_filename" in item, "rename source missing")
            if "previous_filename" in item:
                paths.append(item["previous_filename"])
            for filename in paths:
                require(
                    isinstance(filename, str) and 0 < len(filename) <= 4096,
                    "invalid changed path",
                )
                require(
                    not any(ord(c) < 32 or ord(c) == 127 for c in filename)
                    and "\\" not in filename
                    and "%" not in filename,
                    "ambiguous changed path",
                )
                require(
                    filename == filename.strip()
                    and unicodedata.normalize("NFKC", filename) == filename
                    and not filename.startswith("~")
                    and re.match(r"[A-Za-z]:", filename) is None
                    and "://" not in filename
                    and all(
                        part not in ("", ".", "..") and part.rstrip(". ") == part
                        for part in filename.split("/")
                    ),
                    "noncanonical changed path",
                )
                protected |= any(
                    re.fullmatch(rule["regex"], filename, rule["flags"]) is not None
                    for rule in self.policy["protected_paths"]
                )
        require(len(seen) == count, "incomplete immutable comparison")
        return protected

    def workflow(self) -> dict[str, Any]:
        result = self.api.json(self.prefix + "/actions/workflows/" + self.workflow_name)
        require(
            type(result.get("id")) is int
            and result["id"] > 0
            and result.get("path") == ".github/workflows/" + self.workflow_name
            and result.get("state") == "active",
            "unexpected authorization workflow",
        )
        return result

    def run(
        self, run: dict[str, Any], workflow: dict[str, Any], *, finished: bool
    ) -> dict[str, Any]:
        self.repository(run.get("repository"))
        self.repository(run.get("head_repository"))
        require(
            type(run.get("id")) is int
            and run["id"] > 0
            and run.get("workflow_id") == workflow["id"]
            and run.get("path") == workflow["path"],
            "workflow run identity mismatch",
        )
        require(
            run.get("event") == "workflow_dispatch"
            and run.get("head_branch") == "main"
            and run.get("head_sha") == self.env["BASE_SHA"],
            "untrusted workflow run source",
        )
        require(
            type(run.get("run_attempt")) is int and run["run_attempt"] == 1,
            "rerun authorization is forbidden",
        )
        if finished:
            require(
                run.get("status") == "completed" and run.get("conclusion") == "success",
                "authorization workflow did not succeed",
            )
        else:
            require(
                run.get("status") == "in_progress" and run.get("conclusion") is None,
                "authorization workflow is not running",
            )
        created = timestamp(run.get("created_at"))
        require(
            0 <= (self.now - created).total_seconds() <= self.policy["max_age_seconds"],
            "authorization run expired",
        )
        self.maintainer(run.get("triggering_actor"))
        return self.maintainer(run.get("actor"))

    def authorize(self, output: str) -> dict[str, Any]:
        require(
            self.env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and self.env.get("GITHUB_RUN_ATTEMPT") == "1",
            "manual first-attempt authorization required",
        )
        pr = self.live_pr(self.workflow_name)
        self.protected(pr)  # Validate the complete change even for manual approval.
        event = strict_json(Path(self.env["GITHUB_EVENT_PATH"]).read_bytes())
        expected = {
            "pr_number": self.env["PR_NUMBER"],
            "base_sha": self.env["BASE_SHA"],
            "head_sha": self.env["HEAD_SHA"],
        }
        require(event.get("inputs") == expected, "dispatch inputs mismatch")
        run_id = self.env.get("GITHUB_RUN_ID", "")
        require(re.fullmatch(r"[1-9][0-9]*", run_id), "invalid authorization run id")
        run = self.api.json(self.prefix + "/actions/runs/" + run_id)
        require(run.get("id") == int(run_id), "run id mismatch")
        actor = self.run(run, self.workflow(), finished=False)
        require(
            run["actor"]["login"] == self.env.get("GITHUB_ACTOR")
            and run["triggering_actor"]["login"] == self.env.get("GITHUB_TRIGGERING_ACTOR"),
            "workflow actor mismatch",
        )
        record = {
            "schema_version": 1,
            "repository": self.repo,
            "pr_number": pr["number"],
            "base_sha": self.env["BASE_SHA"],
            "head_sha": self.env["HEAD_SHA"],
            "trusted_revision": self.env["BASE_SHA"],
            "actor": actor,
            "run_id": int(run_id),
            "issued_at": self.now.isoformat(),
        }
        self.live_pr(self.workflow_name)  # Recheck before issuing evidence.
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        return {"authorized": True, "run_id": int(run_id), "pr_number": pr["number"]}

    def artifact(self, run: dict[str, Any], actor: dict[str, Any]) -> None:
        listing = self.api.json(
            self.prefix + f"/actions/runs/{run['id']}/artifacts?per_page=100&page=1"
        )
        artifacts = listing.get("artifacts")
        require(
            type(artifacts) is list
            and listing.get("total_count") == len(artifacts)
            and len(artifacts) <= 100,
            "incomplete artifact listing",
        )
        matches = [a for a in artifacts if a.get("name") == "immutable-core-authorization"]
        require(len(matches) == 1, "authorization artifact missing or duplicated")
        artifact = matches[0]
        require(
            artifact.get("expired") is False
            and type(artifact.get("id")) is int
            and artifact["id"] > 0,
            "artifact expired or invalid",
        )
        require(timestamp(artifact.get("expires_at")) > self.now, "artifact expired")
        require(
            type(artifact.get("size_in_bytes")) is int
            and 0 < artifact["size_in_bytes"] <= MAX_BYTES,
            "artifact too large",
        )
        require(
            artifact.get("workflow_run", {}).get("id") == run["id"], "artifact run binding mismatch"
        )
        digest = artifact.get("digest", "")
        require(
            isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest),
            "artifact digest unavailable",
        )
        raw = self.api.archive(self.prefix + f"/actions/artifacts/{artifact['id']}/zip")
        require(
            len(raw) <= MAX_BYTES and "sha256:" + hashlib.sha256(raw).hexdigest() == digest,
            "artifact digest mismatch",
        )
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            require(
                len(entries) == 1
                and entries[0].filename == "authorization.json"
                and not entries[0].is_dir(),
                "unexpected archive contents",
            )
            entry = entries[0]
            require(
                not stat.S_ISLNK(entry.external_attr >> 16)
                and not entry.flag_bits & 1
                and entry.file_size <= MAX_BYTES,
                "unsafe archive entry",
            )
            record = strict_json(archive.read(entry))
        expected = {
            "schema_version": 1,
            "repository": self.repo,
            "pr_number": int(self.env["PR_NUMBER"]),
            "base_sha": self.env["BASE_SHA"],
            "head_sha": self.env["HEAD_SHA"],
            "trusted_revision": self.env["BASE_SHA"],
            "actor": actor,
            "run_id": run["id"],
        }
        require(
            type(record) is dict and set(record) == set(expected) | {"issued_at"},
            "invalid authorization record",
        )
        require(
            all(record.get(k) == v for k, v in expected.items()),
            "authorization record binding mismatch",
        )
        issued = timestamp(record["issued_at"])
        require(
            timestamp(run["created_at"]) <= issued <= timestamp(run["updated_at"]) <= self.now,
            "authorization issuance outside run",
        )
        require(
            0 <= (self.now - issued).total_seconds() <= self.policy["max_age_seconds"],
            "authorization expired",
        )

    def verify(self) -> dict[str, Any]:
        require(
            self.env.get("GITHUB_EVENT_NAME") in ("pull_request_target", "workflow_dispatch"),
            "trusted PR verification event required",
        )
        pr = self.live_pr()
        if self.env.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
            event = strict_json(Path(self.env["GITHUB_EVENT_PATH"]).read_bytes())
            require(
                event.get("inputs")
                == {
                    "pr_number": self.env["PR_NUMBER"],
                    "base_sha": self.env["BASE_SHA"],
                    "head_sha": self.env["HEAD_SHA"],
                },
                "dispatch inputs mismatch",
            )
        protected = self.protected(pr)
        if not protected:
            self.live_pr()
            return {"authorized": True, "protected": False, "pr_number": pr["number"]}
        workflow = self.workflow()
        listing = self.api.json(
            self.prefix
            + f"/actions/workflows/{workflow['id']}/runs?event=workflow_dispatch&branch=main&status=success&per_page=100&page=1"
        )
        runs = listing.get("workflow_runs")
        require(type(runs) is list and len(runs) <= 100, "invalid authorization run listing")
        for candidate in runs:
            try:
                require(
                    type(candidate.get("id")) is int and candidate["id"] > 0,
                    "invalid candidate run",
                )
                run = self.api.json(self.prefix + f"/actions/runs/{candidate['id']}")
                require(run.get("id") == candidate["id"], "run lookup identity mismatch")
                actor = self.run(run, workflow, finished=True)
                self.artifact(run, actor)
                self.live_pr()
                return {
                    "authorized": True,
                    "protected": True,
                    "pr_number": pr["number"],
                    "run_id": run["id"],
                }
            except (Denied, KeyError, TypeError, ValueError, OSError, zipfile.BadZipFile):
                continue
        raise Denied("no fresh trusted authorization for this exact PR head and base")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("authorize", "verify"))
    parser.add_argument("--policy", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        guard = Guard(
            policy_from(args.policy),
            GitHubAPI(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")),
            dict(os.environ),
        )
        if args.command == "authorize":
            require(bool(args.output), "authorize requires --output")
            result = guard.authorize(args.output)
        else:
            result = guard.verify()
        print(json.dumps(result, sort_keys=True))
        return 0
    except Denied as exc:
        # Denial messages are static strings, never API bodies or input values.
        print(json.dumps({"authorized": False, "reason": str(exc)}))
        return 1
    except Exception as exc:
        # Do not print server errors, URLs, token material or untrusted payloads.
        print(
            json.dumps(
                {
                    "authorized": False,
                    "reason": "verification unavailable",
                    "error_type": type(exc).__name__,
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
