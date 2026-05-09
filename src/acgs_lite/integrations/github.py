"""ACGS-Lite GitHub Integration.

Governs GitHub pull requests with constitutional validation, MACI separation
of powers enforcement, and automated governance comments.

Three main classes:
1. GitHubGovernanceBot: Validates PRs against constitutional rules
2. GitHubWebhookHandler: Receives GitHub webhook events (Starlette-compatible)
3. GitHubMACIEnforcer: Enforces MACI role separation on PR participants

Usage::

    from acgs_lite.integrations.github import GitHubGovernanceBot
    from acgs_lite import Constitution

    bot = GitHubGovernanceBot(
        token="ghp_...",
        repo="owner/repo",
        constitution=Constitution.from_yaml("rules.yaml"),
    )
    report = await bot.validate_pull_request(pr_number=42)

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from typing import Any

from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.engine import GovernanceEngine, ValidationResult
from acgs_lite.integrations.github_merge_queue import GitHubMergeQueueAdapter
from acgs_lite.maci import MACIEnforcer, MACIRole

logger = logging.getLogger(__name__)

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GovernanceReport:
    """Immutable governance report for a pull request."""

    pr_number: int
    title: str
    passed: bool
    risk_score: float
    violations: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)
    rules_checked: int = 0
    constitutional_hash: str = ""
    latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# GitHubGovernanceBot
# ---------------------------------------------------------------------------


class GitHubGovernanceBot:
    """Validates GitHub pull requests against constitutional governance rules.

    Usage::

        bot = GitHubGovernanceBot(
            token="ghp_...",
            repo="owner/repo",
            constitution=Constitution.from_yaml("rules.yaml"),
        )
        report = await bot.validate_pull_request(pr_number=42)
    """

    _BASE_URL = "https://api.github.com"

    def __init__(
        self,
        *,
        token: str,
        repo: str,
        constitution: Constitution | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
        strict: bool = False,
    ) -> None:
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required for GitHub integration. "
                "Install with: pip install acgs-lite[github]"
            )

        self._token = token
        self._repo = repo
        self._base_url = (base_url or self._BASE_URL).rstrip("/")
        self._timeout = timeout

        self.constitution = constitution or Constitution.default()
        self.audit_log = AuditLog()
        self.engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict,
        )

    # -- HTTP helpers -------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _repo_url(self, path: str) -> str:
        return f"{self._base_url}/repos/{self._repo}/{path}"

    async def _get(self, path: str) -> Any:
        """GET request to the GitHub repository API."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(self._repo_url(path), headers=self._headers())
            resp.raise_for_status()
            result: Any = resp.json()
            return result

    async def _post(self, path: str, json_body: dict[str, Any]) -> Any:
        """POST request to the GitHub repository API."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                self._repo_url(path),
                headers=self._headers(),
                json=json_body,
            )
            resp.raise_for_status()
            result: Any = resp.json()
            return result

    # -- Core governance methods -------------------------------------------

    async def validate_pull_request(self, pr_number: int) -> GovernanceReport:
        """Fetch PR details and diff, validate against constitutional rules.

        Args:
            pr_number: The pull request number.

        Returns:
            GovernanceReport with violation details, risk score, and decision.
        """
        pr_data = await self._get(f"pulls/{pr_number}")
        files = await self._get(f"pulls/{pr_number}/files")

        title = pr_data.get("title", "")
        body = pr_data.get("body", "") or ""

        all_violations: list[dict[str, Any]] = []
        all_warnings: list[dict[str, Any]] = []
        total_checked = 0

        # Validate title + body
        for text, source in [(title, "title"), (body, "body")]:
            if not text:
                continue
            result = self._validate_text(text, agent_id=f"github-pr-{pr_number}:{source}")
            total_checked += result.rules_checked
            for v in result.blocking_violations:
                all_violations.append(
                    {
                        **_violation_to_dict(v),
                        "source": source,
                        "file": None,
                        "line": None,
                    }
                )
            for w in result.warnings:
                all_warnings.append(
                    {
                        **_violation_to_dict(w),
                        "source": source,
                        "file": None,
                        "line": None,
                    }
                )

        # Validate each file patch
        for file_entry in files:
            filename = file_entry.get("filename", "unknown")
            patch = file_entry.get("patch", "")
            if not patch:
                continue

            for line_no, line in _parse_added_lines(patch):
                result = self._validate_text(line, agent_id=f"github-pr-{pr_number}:{filename}")
                total_checked += result.rules_checked
                for v in result.blocking_violations:
                    entry = {
                        **_violation_to_dict(v),
                        "source": "diff",
                        "file": filename,
                        "line": line_no,
                    }
                    all_violations.append(entry)
                for w in result.warnings:
                    entry = {
                        **_violation_to_dict(w),
                        "source": "diff",
                        "file": filename,
                        "line": line_no,
                    }
                    all_warnings.append(entry)

        risk_score = _compute_risk_score(all_violations, all_warnings)

        report = GovernanceReport(
            pr_number=pr_number,
            title=title,
            passed=len(all_violations) == 0,
            risk_score=risk_score,
            violations=all_violations,
            warnings=all_warnings,
            rules_checked=total_checked,
            constitutional_hash=self.constitution.hash,
        )

        self.audit_log.record(
            AuditEntry(
                id=f"github-pr-{pr_number}",
                type="github_pr_validation",
                agent_id="github-governance-bot",
                action=f"validate PR #{pr_number}: {title}",
                valid=report.passed,
                violations=[v["rule_id"] for v in all_violations],
                constitutional_hash=self.constitution.hash,
                metadata={"pr_number": pr_number, "risk_score": risk_score},
            )
        )

        return report

    async def post_governance_comment(self, pr_number: int, report: GovernanceReport) -> Any:
        """Post a formatted governance comment on the pull request.

        Args:
            pr_number: The pull request number.
            report: The governance report to format and post.

        Returns:
            GitHub API response for the created comment.
        """
        body = format_governance_report(report)
        return await self._post(f"issues/{pr_number}/comments", {"body": body})

    async def run_governance_pipeline(self, pr_number: int) -> GovernanceReport:
        """Run the full governance pipeline: validate, comment, approve/block.

        Args:
            pr_number: The pull request number.

        Returns:
            The complete GovernanceReport.
        """
        report = await self.validate_pull_request(pr_number)

        await self.post_governance_comment(pr_number, report)

        logger.info(
            "Governance pipeline complete for PR #%s: %s (risk=%.2f, violations=%d)",
            pr_number,
            "PASSED" if report.passed else "BLOCKED",
            report.risk_score,
            len(report.violations),
        )

        return report

    def _validate_text(self, text: str, agent_id: str) -> ValidationResult:
        """Validate text using the governance engine in non-strict mode."""
        return self.engine.validate(text, agent_id=agent_id, strict=False)

    @property
    def stats(self) -> dict[str, Any]:
        """Return governance statistics."""
        return {
            **self.engine.stats,
            "repo": self._repo,
            "audit_chain_valid": self.audit_log.verify_chain(),
        }


# ---------------------------------------------------------------------------
# GitHubWebhookHandler
# ---------------------------------------------------------------------------


class GitHubWebhookHandler:
    """Starlette-compatible handler for GitHub webhook events.

    Validates HMAC-SHA256 signatures, routes pull_request events to governance
    checks, and returns structured JSON responses.

    Usage::

        from starlette.applications import Starlette
        from starlette.routing import Route

        handler = GitHubWebhookHandler(
            webhook_secret="my-secret",
            bot=GitHubGovernanceBot(token="ghp_...", repo="owner/repo"),
        )
        app = Starlette(routes=[
            Route("/webhook", handler.handle, methods=["POST"]),
        ])
    """

    # Supported pull_request actions
    _PR_ACTIONS = frozenset({"opened", "synchronize", "reopened"})

    def __init__(
        self,
        *,
        webhook_secret: str,
        bot: GitHubGovernanceBot,
        merge_queue_adapter: GitHubMergeQueueAdapter | None = None,
    ) -> None:
        self._secret = webhook_secret.encode()
        self._bot = bot
        self._merge_queue_adapter = merge_queue_adapter

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify the GitHub webhook HMAC-SHA256 signature.

        GitHub sends the signature in the ``X-Hub-Signature-256`` header
        as ``sha256=<hex-digest>``. We compute the expected digest using
        the shared secret and compare in constant time.

        Args:
            payload: The raw request body bytes.
            signature: The value of the X-Hub-Signature-256 header.

        Returns:
            True if the signature is valid.
        """
        if not signature.startswith("sha256="):
            return False

        expected = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        received = signature[len("sha256=") :]
        return hmac.compare_digest(expected, received)

    async def handle(self, request: Any) -> Any:
        """Handle an incoming GitHub webhook request.

        Args:
            request: Starlette Request object.

        Returns:
            Starlette JSONResponse with the governance result.
        """
        try:
            from starlette.responses import JSONResponse
        except ImportError as exc:
            raise ImportError(
                "starlette is required for webhook handling. Install with: pip install starlette"
            ) from exc

        # Read raw body for signature verification
        raw_body = await request.body()
        signature = request.headers.get("X-Hub-Signature-256", "")
        if not self.verify_signature(raw_body, signature):
            return JSONResponse({"error": "Invalid webhook signature"}, status_code=401)

        event_type = request.headers.get("X-GitHub-Event", "")
        body: dict[str, Any] = await request.json()

        try:
            result = await self._route_event(event_type, body)
            return JSONResponse({"status": "processed", "result": result})
        except (ValueError, TypeError, KeyError, RuntimeError):
            logger.error("Webhook processing failed", exc_info=True)
            return JSONResponse({"error": "Processing failed"}, status_code=500)

    async def _route_event(self, event_type: str, body: dict[str, Any]) -> dict[str, Any]:
        """Route a webhook event to the appropriate handler."""
        if event_type == "pull_request":
            return await self._handle_pull_request(body)
        if event_type == "merge_group":
            return await self._handle_merge_group(body)

        return {
            "event": event_type,
            "action": "ignored",
            "reason": "unsupported event type",
        }

    async def _handle_pull_request(self, body: dict[str, Any]) -> dict[str, Any]:
        """Handle pull_request events."""
        action = body.get("action", "")
        pr_data = body.get("pull_request", {})
        pr_number = pr_data.get("number")

        if action not in self._PR_ACTIONS or pr_number is None:
            return {
                "event": "pull_request",
                "action": action,
                "status": "skipped",
            }

        report = await self._bot.run_governance_pipeline(pr_number)
        return {
            "event": "pull_request",
            "action": action,
            "pr_number": pr_number,
            "governance_passed": report.passed,
            "violations": len(report.violations),
            "risk_score": report.risk_score,
        }

    async def _handle_merge_group(self, body: dict[str, Any]) -> dict[str, Any]:
        """Handle merge_group events (merge queue checks_requested)."""
        action = body.get("action", "")
        if action != "checks_requested" or self._merge_queue_adapter is None:
            return {
                "event": "merge_group",
                "action": action,
                "status": "skipped",
            }

        outcome = await self._merge_queue_adapter.evaluate_merge_group(body)
        return {
            "event": "merge_group",
            "action": action,
            **outcome.to_dict(),
        }


# ---------------------------------------------------------------------------
# GitHubMACIEnforcer
# ---------------------------------------------------------------------------


class GitHubMACIEnforcer:
    """Maps GitHub PR roles to MACI roles and enforces separation of powers.

    - PR author -> PROPOSER
    - PR reviewer -> VALIDATOR
    - PR merger -> EXECUTOR

    Usage::

        enforcer = GitHubMACIEnforcer()
        result = await enforcer.check_pr_separation(bot, pr_number=42)
    """

    # GitHub role -> MACI role mapping
    _ROLE_MAP: dict[str, MACIRole] = {
        "author": MACIRole.PROPOSER,
        "reviewer": MACIRole.VALIDATOR,
        "merger": MACIRole.EXECUTOR,
    }

    def __init__(self, *, audit_log: AuditLog | None = None) -> None:
        self.enforcer = MACIEnforcer(audit_log=audit_log)

    async def check_pr_separation(
        self,
        bot: GitHubGovernanceBot,
        pr_number: int,
    ) -> dict[str, Any]:
        """Validate MACI separation of powers on a PR.

        Checks that the PR author has not also submitted an approving review,
        enforcing the constitutional rule that proposers cannot validate
        their own proposals.

        Args:
            bot: The GitHubGovernanceBot (provides API access).
            pr_number: The pull request number.

        Returns:
            Dict with separation check results and any violations.
        """
        pr_data = await bot._get(f"pulls/{pr_number}")
        reviews = await bot._get(f"pulls/{pr_number}/reviews")

        author_login = pr_data.get("user", {}).get("login", "")

        # Collect users who submitted an APPROVED review
        approved_by = [
            r.get("user", {}).get("login", "") for r in reviews if r.get("state") == "APPROVED"
        ]

        # Assign MACI roles
        self.enforcer.assign_role(author_login, MACIRole.PROPOSER)
        for reviewer in approved_by:
            if reviewer:
                self.enforcer.assign_role(reviewer, MACIRole.VALIDATOR)

        # Check for self-approval
        violations: list[dict[str, str]] = []
        for reviewer in approved_by:
            if reviewer == author_login:
                violations.append(
                    {
                        "type": "self_approval",
                        "agent": author_login,
                        "message": (
                            f"MACI violation: {author_login} authored and "
                            f"approved PR #{pr_number}. Proposers cannot "
                            "validate their own proposals."
                        ),
                    }
                )

        result = {
            "pr_number": pr_number,
            "author": author_login,
            "approvers": approved_by,
            "separation_valid": len(violations) == 0,
            "violations": violations,
            "role_assignments": self.enforcer.role_assignments,
        }

        bot.audit_log.record(
            AuditEntry(
                id=f"maci-pr-{pr_number}",
                type="maci_pr_check",
                agent_id="github-maci-enforcer",
                action=f"MACI separation check PR #{pr_number}",
                valid=len(violations) == 0,
                violations=[v["type"] for v in violations],
                constitutional_hash=bot.constitution.hash,
                metadata=result,
            )
        )

        return result

    async def post_maci_violation(
        self,
        bot: GitHubGovernanceBot,
        pr_number: int,
        violations: list[dict[str, str]],
    ) -> Any:
        """Post a MACI violation comment on the pull request.

        Args:
            bot: The GitHubGovernanceBot (provides API access).
            pr_number: The pull request number.
            violations: List of violation dicts from check_pr_separation.

        Returns:
            GitHub API response for the created comment.
        """
        lines = ["## MACI Separation of Powers Violation\n"]
        for v in violations:
            lines.append(f"- **{v['type']}**: {v['message']}")
        lines.append(
            "\n> Constitutional rule ACGS-004: Proposers cannot validate their own proposals."
        )

        body = "\n".join(lines)
        return await bot._post(f"issues/{pr_number}/comments", {"body": body})


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _violation_to_dict(v: Any) -> dict[str, Any]:
    """Convert a Violation namedtuple to a serialisable dict."""
    return {
        "rule_id": v.rule_id,
        "rule_text": v.rule_text,
        "severity": v.severity.value,
        "matched_content": v.matched_content,
        "category": v.category,
    }


def _parse_added_lines(diff_text: str) -> list[tuple[int, str]]:
    """Parse unified diff text, returning (line_number, content) for added lines."""
    results: list[tuple[int, str]] = []
    current_line = 0

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("@@"):
            # Parse hunk header: @@ -old,count +new,count @@
            parts = raw_line.split("+")
            if len(parts) >= 2:
                line_part = parts[1].split(",")[0].split(" ")[0]
                try:
                    current_line = int(line_part)
                except ValueError:
                    current_line = 0
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            content = raw_line[1:]
            if content.strip():
                results.append((current_line, content))
            current_line += 1
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            # Deleted line: don't advance the new-file line counter
            pass
        else:
            # Context line
            current_line += 1

    return results


def _compute_risk_score(
    violations: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> float:
    """Compute a 0.0-1.0 risk score from violations and warnings."""
    if not violations and not warnings:
        return 0.0

    severity_weights = {
        "critical": 1.0,
        "high": 0.7,
        "medium": 0.3,
        "low": 0.1,
    }
    total = 0.0

    for v in violations:
        total += severity_weights.get(v.get("severity", "medium"), 0.3)
    for w in warnings:
        total += severity_weights.get(w.get("severity", "low"), 0.1) * 0.5

    # Normalize to 0.0-1.0 range (cap at 1.0)
    return min(total / max(len(violations) + len(warnings), 1), 1.0)


def format_governance_report(report: GovernanceReport) -> str:
    """Format a GovernanceReport as Markdown for GitHub PR comments.

    Args:
        report: The governance report to format.

    Returns:
        Markdown-formatted string suitable for a GitHub PR comment.
    """
    status = "PASSED" if report.passed else "FAILED"
    icon = "white_check_mark" if report.passed else "x"

    lines = [
        f"## Governance Report :{icon}:",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Status | **{status}** |",
        f"| Risk Score | {report.risk_score:.2f} |",
        f"| Rules Checked | {report.rules_checked} |",
        f"| Constitutional Hash | `{report.constitutional_hash}` |",
        "",
    ]

    if report.violations:
        lines.append("### Violations")
        lines.append("")
        for v in report.violations:
            sev = v.get("severity", "unknown").upper()
            source = v.get("source", "")
            file_ref = ""
            if v.get("file") and v.get("line"):
                file_ref = f" (`{v['file']}:{v['line']}`)"
            lines.append(
                f"- **[{sev}]** `{v['rule_id']}`: {v.get('rule_text', '')}{file_ref} ({source})"
            )
        lines.append("")

    if report.warnings:
        lines.append("### Warnings")
        lines.append("")
        for w in report.warnings:
            sev = w.get("severity", "unknown").upper()
            lines.append(f"- **[{sev}]** `{w['rule_id']}`: {w.get('rule_text', '')}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by ACGS Governance Bot*")

    return "\n".join(lines)


def create_github_actions_config(
    constitution: Constitution | None = None,
) -> str:
    """Generate a .github/workflows/governance.yml workflow.

    Args:
        constitution: Optional constitution for hash reference.

    Returns:
        YAML string for a GitHub Actions governance workflow.
    """
    constitution = constitution or Constitution.default()
    const_hash = constitution.hash

    return (
        "# ACGS Governance Workflow\n"
        "# Constitutional Hash: " + const_hash + "\n"
        "\n"
        "name: Governance\n"
        "\n"
        "on:\n"
        "  pull_request:\n"
        "    types: [opened, synchronize, reopened]\n"
        "\n"
        "permissions:\n"
        "  contents: read\n"
        "  pull-requests: write\n"
        "\n"
        "jobs:\n"
        "  governance:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "\n"
        "      - name: Set up Python\n"
        "        uses: actions/setup-python@v5\n"
        "        with:\n"
        "          python-version: '3.11'\n"
        "\n"
        "      - name: Install acgs-lite\n"
        "        run: pip install acgs-lite[github]\n"
        "\n"
        "      - name: Run governance validation\n"
        "        env:\n"
        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        '          CONSTITUTIONAL_HASH: "' + const_hash + '"\n'
        "        run: |\n"
        '          python -c "\n'
        "          import asyncio, os\n"
        "          from acgs_lite.integrations.github import "
        "GitHubGovernanceBot\n"
        "\n"
        "          async def main():\n"
        "              bot = GitHubGovernanceBot(\n"
        "                  token=os.environ['GITHUB_TOKEN'],\n"
        "                  repo=os.environ['GITHUB_REPOSITORY'],\n"
        "              )\n"
        "              pr_number = int(\n"
        "                  os.environ['GITHUB_REF'].split('/')[-2]\n"
        "              )\n"
        "              report = await bot.run_governance_pipeline(\n"
        "                  pr_number=pr_number,\n"
        "              )\n"
        "              assert report.passed, (\n"
        "                  f'Governance: "
        "{len(report.violations)} violations'\n"
        "              )\n"
        "\n"
        "          asyncio.run(main())\n"
        '          "\n'
    )


def create_merge_group_github_actions_config(
    *, receipts_url_env: str = "ACGS_RECEIPTS_URL", api_key_env: str = "ACGS_API_KEY"
) -> str:
    """Generate the merge-group governance workflow template."""
    from acgs_lite.integrations.github_merge_queue import (
        create_merge_group_github_actions_config as _create_merge_group_github_actions_config,
    )

    return _create_merge_group_github_actions_config(
        receipts_url_env=receipts_url_env,
        api_key_env=api_key_env,
    )
