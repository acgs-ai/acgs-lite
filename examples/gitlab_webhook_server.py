# requires: acgs-lite[gitlab], starlette, uvicorn, GITLAB_TOKEN, GITLAB_PROJECT_ID, server
"""
Example: GitLab Webhook Server for ACGS Governance

Standalone Starlette/uvicorn server that receives GitLab webhook events and
validates merge requests against constitutional governance rules in real-time.

Endpoints:
    POST /webhook            - GitLab webhook receiver (validates X-Gitlab-Token)
    GET  /health             - Health check with constitutional hash
    GET  /governance/summary - Active ruleset governance posture

Setup:
    pip install acgs-lite[gitlab] uvicorn starlette

Usage:
    # Minimal (uses default constitution and env vars for secrets):
    export GITLAB_TOKEN="glpat-..."
    export GITLAB_WEBHOOK_SECRET="my-webhook-secret"
    python gitlab_webhook_server.py --project-id 12345

    # Full CLI:
    python gitlab_webhook_server.py \\
        --host 0.0.0.0 \\
        --port 9000 \\
        --constitution rules.yaml \\
        --gitlab-token glpat-... \\
        --gitlab-url https://gitlab.company.com/api/v4 \\
        --project-id 12345

Testing with ngrok (for GitLab.com webhooks):
    1. Start this server:
         python gitlab_webhook_server.py --project-id 12345

    2. In a separate terminal, expose it via ngrok:
         ngrok http 8000

    3. Copy the ngrok HTTPS URL (e.g. https://abc123.ngrok-free.app)

    4. In GitLab project settings -> Webhooks, add:
         URL:    https://abc123.ngrok-free.app/webhook
         Secret: <same value as --webhook-secret or GITLAB_WEBHOOK_SECRET>
         Trigger: Merge request events, Pipeline events

    5. Open or update an MR -- the server will validate it and post
       governance comments automatically.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import dataclass
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("acgs.webhook")


# ---------------------------------------------------------------------------
# Server configuration (immutable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServerConfig:
    """Immutable server configuration built from CLI args + env vars."""

    host: str = "0.0.0.0"
    port: int = 8000
    constitution_path: str = ""
    gitlab_token: str = ""
    gitlab_url: str = "https://gitlab.com/api/v4"
    project_id: int = 0
    webhook_secret: str = ""


def _parse_args(argv: list[str] | None = None) -> ServerConfig:
    """Parse CLI arguments with environment variable fallbacks.

    Args:
        argv: Command-line arguments (defaults to sys.argv).

    Returns:
        Immutable ServerConfig with all resolved values.
    """
    parser = argparse.ArgumentParser(
        description="ACGS Governance Webhook Server for GitLab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Environment variable fallbacks:\n"
            "  GITLAB_TOKEN          GitLab API token (--gitlab-token)\n"
            "  GITLAB_WEBHOOK_SECRET Webhook verification secret (--webhook-secret)\n"
            "  GITLAB_URL            GitLab API base URL (--gitlab-url)\n"
            "  GITLAB_PROJECT_ID     Project numeric ID (--project-id)\n"
            "  CONSTITUTION_PATH     Path to constitution YAML (--constitution)\n"
        ),
    )

    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument(
        "--constitution",
        default=os.environ.get("CONSTITUTION_PATH", ""),
        help="Path to constitution YAML file (default: built-in constitution)",
    )
    parser.add_argument(
        "--gitlab-token",
        default=os.environ.get("GITLAB_TOKEN", ""),
        help="GitLab API access token (env: GITLAB_TOKEN)",
    )
    parser.add_argument(
        "--gitlab-url",
        default=os.environ.get("GITLAB_URL", "https://gitlab.com/api/v4"),
        help="GitLab API base URL (env: GITLAB_URL)",
    )
    parser.add_argument(
        "--project-id",
        type=int,
        default=int(os.environ.get("GITLAB_PROJECT_ID", "0")),
        help="GitLab project numeric ID (env: GITLAB_PROJECT_ID)",
    )
    parser.add_argument(
        "--webhook-secret",
        default=os.environ.get("GITLAB_WEBHOOK_SECRET", ""),
        help="Webhook secret for X-Gitlab-Token verification (env: GITLAB_WEBHOOK_SECRET)",
    )

    args = parser.parse_args(argv)

    return ServerConfig(
        host=args.host,
        port=args.port,
        constitution_path=args.constitution,
        gitlab_token=args.gitlab_token,
        gitlab_url=args.gitlab_url,
        project_id=args.project_id,
        webhook_secret=args.webhook_secret,
    )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


@dataclass
class GovernanceState:
    """Mutable governance state — tracks reports processed during server lifetime."""

    reports_processed: int = 0
    violations_found: int = 0
    last_mr_iid: int | None = None
    errors: int = 0


def create_app(config: ServerConfig) -> Any:
    """Build the Starlette application with governance endpoints.

    Args:
        config: Immutable server configuration.

    Returns:
        Starlette application instance.

    Raises:
        ImportError: If starlette or acgs_lite dependencies are missing.
        SystemExit: If required configuration (gitlab-token, project-id) is missing.
    """
    try:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
    except ImportError:
        logger.error("starlette is required: pip install starlette uvicorn")
        sys.exit(1)

    try:
        from acgs_lite.constitution import Constitution
        from acgs_lite.integrations.gitlab import GitLabGovernanceBot, GitLabWebhookHandler
    except ImportError:
        logger.error("acgs[gitlab] is required: pip install acgs-lite[gitlab]")
        sys.exit(1)

    # --- Validate required config ---

    if not config.gitlab_token:
        logger.error("GitLab token is required. Use --gitlab-token or set GITLAB_TOKEN.")
        sys.exit(1)

    if config.project_id == 0:
        logger.error("Project ID is required. Use --project-id or set GITLAB_PROJECT_ID.")
        sys.exit(1)

    if not config.webhook_secret:
        logger.warning(
            "No webhook secret configured. "
            "Set --webhook-secret or GITLAB_WEBHOOK_SECRET for production use."
        )

    # --- Load constitution ---

    if config.constitution_path:
        try:
            constitution = Constitution.from_yaml(config.constitution_path)
            logger.info("Loaded constitution from %s", config.constitution_path)
        except (FileNotFoundError, ValueError) as exc:
            logger.error("Failed to load constitution from %s: %s", config.constitution_path, exc)
            sys.exit(1)
    else:
        constitution = Constitution.default()
        logger.info("Using default constitution")

    # --- Initialize governance components ---

    bot = GitLabGovernanceBot(
        token=config.gitlab_token,
        project_id=config.project_id,
        constitution=constitution,
        base_url=config.gitlab_url,
    )

    webhook_handler = GitLabWebhookHandler(
        webhook_secret=config.webhook_secret or "unconfigured",
        bot=bot,
    )

    state = GovernanceState()

    # --- Route handlers ---

    async def webhook_endpoint(request: Request) -> JSONResponse:
        """Receive and process GitLab webhook events.

        Validates the X-Gitlab-Token header, routes the event through
        the governance pipeline, and returns structured results.
        """
        event_type = request.headers.get("X-Gitlab-Event", "unknown")
        logger.info("Webhook received: %s", event_type)

        response = await webhook_handler.handle(request)

        # Track governance metrics from response
        try:
            response_body = response.body.decode()  # type: ignore[union-attr]
            import json

            result = json.loads(response_body)
            if result.get("status") == "processed":
                state.reports_processed += 1
                inner = result.get("result", {})
                state.violations_found += inner.get("violations", 0)
                mr_iid = inner.get("mr_iid")
                if mr_iid is not None:
                    state.last_mr_iid = mr_iid

                logger.info(
                    "Governance result: event=%s mr=!%s passed=%s violations=%d",
                    event_type,
                    inner.get("mr_iid", "N/A"),
                    inner.get("governance_passed", inner.get("post_approval_valid", "N/A")),
                    inner.get("violations", 0),
                )
        except Exception:
            state.errors += 1
            logger.warning("Failed to parse webhook response for metrics", exc_info=True)

        return response  # type: ignore[return-value]

    async def health_endpoint(request: Request) -> JSONResponse:
        """Health check returning service status and constitutional hash."""
        return JSONResponse(
            {
                "status": "healthy",
                "constitutional_hash": constitution.hash,
                "rules_loaded": len(constitution.rules),
                "project_id": config.project_id,
                "gitlab_url": config.gitlab_url,
                "reports_processed": state.reports_processed,
                "violations_found": state.violations_found,
            }
        )

    async def governance_summary_endpoint(request: Request) -> JSONResponse:
        """Return the active constitution's governance posture summary."""
        summary = constitution.governance_summary()
        return JSONResponse(
            {
                "constitutional_hash": constitution.hash,
                "constitution_name": constitution.name,
                "rules_loaded": len(constitution.rules),
                "summary": summary,
                "server_stats": {
                    "reports_processed": state.reports_processed,
                    "violations_found": state.violations_found,
                    "last_mr_iid": state.last_mr_iid,
                    "errors": state.errors,
                },
            }
        )

    # --- Build app ---

    return Starlette(
        routes=[
            Route("/webhook", webhook_endpoint, methods=["POST"]),
            Route("/health", health_endpoint, methods=["GET"]),
            Route("/governance/summary", governance_summary_endpoint, methods=["GET"]),
        ],
    )


# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------


def _print_banner(config: ServerConfig, constitutional_hash: str) -> None:
    """Print a clear startup banner showing configured endpoints and settings.

    Args:
        config: Server configuration to display.
        constitutional_hash: Hash of the active constitution.
    """
    base_url = f"http://{config.host}:{config.port}"

    print()
    print("=" * 62)
    print("  ACGS Governance Webhook Server")
    print("=" * 62)
    print()
    print(f"  Constitutional Hash:  {constitutional_hash}")
    print(f"  GitLab URL:           {config.gitlab_url}")
    print(f"  Project ID:           {config.project_id}")
    print(f"  Webhook Secret:       {'configured' if config.webhook_secret else 'NOT SET'}")
    print(f"  Constitution:         {config.constitution_path or '(default)'}")
    print()
    print("  Endpoints:")
    print(f"    POST {base_url}/webhook              GitLab webhook receiver")
    print(f"    GET  {base_url}/health               Health check")
    print(f"    GET  {base_url}/governance/summary    Governance posture")
    print()
    print("  Tip: Use ngrok to expose this server for GitLab.com webhooks:")
    print(f"    ngrok http {config.port}")
    print()
    print("=" * 62)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """Entry point: parse config, build app, start uvicorn.

    Args:
        argv: Optional CLI arguments (defaults to sys.argv).
    """
    config = _parse_args(argv)

    # Load constitution early to get hash for banner and fail fast
    from acgs_lite.constitution import Constitution

    if config.constitution_path:
        try:
            constitution = Constitution.from_yaml(config.constitution_path)
        except (FileNotFoundError, ValueError) as exc:
            logger.error("Failed to load constitution: %s", exc)
            sys.exit(1)
    else:
        constitution = Constitution.default()

    _print_banner(config, constitution.hash)

    app = create_app(config)

    try:
        import uvicorn
    except ImportError:
        logger.error("uvicorn is required: pip install uvicorn")
        sys.exit(1)

    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
