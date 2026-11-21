"""
GitLab Hackathon: Anthropic Bonus Track Demo
=============================================

Demonstrates "Running Anthropic through GitLab" with ACGS constitutional
governance intercepting violations at two layers:

  Layer 1 (LLM output):  GovernedAnthropic validates Claude's responses
                          BEFORE they reach the codebase.

  Layer 2 (MR pipeline):  GitLabGovernanceBot validates merge request
                          diffs, catching anything that slipped through.

This is not a toy -- both integrations are production classes from
acgs-lite. The demo can run in simulation mode (no API keys required)
or against real Anthropic + GitLab APIs.

Usage:
    # Simulation mode (no keys needed)
    python gitlab_anthropic_demo.py

    # With real APIs
    python gitlab_anthropic_demo.py \\
        --anthropic-key sk-ant-... \\
        --gitlab-url https://gitlab.com \\
        --project-id 12345 \\
        --gitlab-token glpat-...

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import argparse
import os
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# ANSI colour helpers (no external deps)
# ---------------------------------------------------------------------------

_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bg_red": "\033[41m",
    "bg_green": "\033[42m",
    "bg_blue": "\033[44m",
    "bg_yellow": "\033[43m",
}


def _c(text: str, *styles: str) -> str:
    """Apply ANSI styles to text."""
    prefix = "".join(_COLORS.get(s, "") for s in styles)
    return f"{prefix}{text}{_COLORS['reset']}" if prefix else text


def _banner(title: str) -> None:
    width = 64
    print()
    print(_c("=" * width, "cyan", "bold"))
    print(_c(f"  {title}", "cyan", "bold"))
    print(_c("=" * width, "cyan", "bold"))


def _section(number: int, title: str) -> None:
    print()
    print(_c(f"  [{number}] {title}", "bold", "white"))
    print(_c("  " + "-" * 56, "dim"))


def _ok(msg: str) -> None:
    print(f"  {_c('PASS', 'green', 'bold')}  {msg}")


def _fail(msg: str) -> None:
    print(f"  {_c('FAIL', 'red', 'bold')}  {msg}")


def _warn(msg: str) -> None:
    print(f"  {_c('WARN', 'yellow', 'bold')}  {msg}")


def _info(msg: str) -> None:
    print(f"  {_c('INFO', 'blue')}  {msg}")


def _code(text: str) -> None:
    for line in text.splitlines():
        print(f"  {_c('|', 'dim')} {_c(line, 'dim')}")


# ---------------------------------------------------------------------------
# Load ACGS-Lite (always available -- it's a local package)
# ---------------------------------------------------------------------------

from acgs_lite import Constitution  # noqa: E402
from acgs_lite.engine import GovernanceEngine, ValidationResult  # noqa: E402
from acgs_lite.integrations.gitlab import (  # noqa: E402
    GovernanceReport,
    format_governance_report,
)

# ---------------------------------------------------------------------------
# Simulated Anthropic responses
# ---------------------------------------------------------------------------

_SIMULATED_RESPONSES: dict[str, str] = {
    "safe": textwrap.dedent("""\
        Here is a secure configuration loader:

        ```python
        import os

        def load_config():
            db_host = os.environ.get("DB_HOST", "localhost")
            db_port = int(os.environ.get("DB_PORT", "5432"))
            return {"host": db_host, "port": db_port}
        ```

        This uses environment variables for all configuration values,
        keeping secrets out of source code."""),
    "violation_secrets": textwrap.dedent("""\
        Here is a quick database setup:

        ```python
        api_key = "sk-proj-abc123secretkey456xyz789"
        password = "hunter2"

        def connect():
            return Database(api_key=api_key, password=password)
        ```

        This stores the credentials directly for convenience."""),
    "violation_destructive": textwrap.dedent("""\
        To reset the database, run:

        ```sql
        DROP TABLE users;
        DROP TABLE sessions;
        TRUNCATE TABLE audit_log;
        ```

        This will clean everything up for a fresh start."""),
    "violation_bypass": textwrap.dedent("""\
        To speed things up, you can bypass validation and skip checks:

        ```python
        agent.config["self-validate"] = True
        agent.config["skip_oversight"] = True
        ```

        This lets the agent override safety and approve its own output."""),
}

# ---------------------------------------------------------------------------
# Simulated MR diff hunks
# ---------------------------------------------------------------------------

_SIMULATED_MR_DIFFS: dict[str, list[dict[str, str]]] = {
    "clean": [
        {
            "new_path": "src/config.py",
            "diff": textwrap.dedent("""\
                @@ -0,0 +1,8 @@
                +import os
                +
                +def load_config():
                +    db_host = os.environ.get("DB_HOST", "localhost")
                +    db_port = int(os.environ.get("DB_PORT", "5432"))
                +    return {"host": db_host, "port": db_port}
                """),
        }
    ],
    "dirty": [
        {
            "new_path": "src/db.py",
            "diff": textwrap.dedent("""\
                @@ -0,0 +1,6 @@
                +api_key = "sk-proj-abc123secretkey456xyz789"
                +password = "hunter2"
                +
                +def connect():
                +    return Database(api_key=api_key, password=password)
                """),
        },
        {
            "new_path": "src/admin.py",
            "diff": textwrap.dedent("""\
                @@ -0,0 +1,4 @@
                +def reset_db(conn):
                +    conn.execute("DROP TABLE users")
                +    conn.execute("TRUNCATE TABLE audit_log")
                +    conn.execute("DELETE FROM sessions")
                """),
        },
    ],
}


# ---------------------------------------------------------------------------
# Core demo: GovernedAnthropic simulation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SimulatedMessage:
    """Mimics an Anthropic Message object for simulation mode."""

    content: list[Any]
    model: str = "claude-sonnet-4-20250514"
    role: str = "assistant"
    stop_reason: str = "end_turn"


@dataclass(frozen=True)
class SimulatedTextBlock:
    """Mimics an Anthropic TextBlock."""

    text: str
    type: str = "text"


def _simulate_anthropic_call(
    prompt: str,
    engine: GovernanceEngine,
    agent_id: str,
) -> tuple[str, ValidationResult]:
    """Simulate a GovernedAnthropic call: generate response + validate output.

    Returns (response_text, validation_result).
    """
    # Choose simulated response based on prompt content
    prompt_lower = prompt.lower()
    if "plaintext" in prompt_lower or "hardcod" in prompt_lower or "secret" in prompt_lower:
        response_text = _SIMULATED_RESPONSES["violation_secrets"]
    elif "drop" in prompt_lower or "delete" in prompt_lower or "reset" in prompt_lower:
        response_text = _SIMULATED_RESPONSES["violation_destructive"]
    elif "bypass" in prompt_lower or "skip" in prompt_lower or "override" in prompt_lower:
        response_text = _SIMULATED_RESPONSES["violation_bypass"]
    else:
        response_text = _SIMULATED_RESPONSES["safe"]

    # Validate the LLM output exactly as GovernedAnthropic.messages.create does
    old_strict = engine.strict
    engine.strict = False
    result = engine.validate(response_text, agent_id=f"{agent_id}:output")
    engine.strict = old_strict

    return response_text, result


# ---------------------------------------------------------------------------
# Core demo: GitLab MR simulation
# ---------------------------------------------------------------------------


def _simulate_mr_governance(
    diffs: list[dict[str, str]],
    engine: GovernanceEngine,
    mr_iid: int = 42,
    title: str = "feat: add database utilities",
) -> GovernanceReport:
    """Simulate what GitLabGovernanceBot.validate_merge_request does.

    Walks each diff hunk, validates added lines, and produces a GovernanceReport.
    """
    all_violations: list[dict[str, Any]] = []
    all_warnings: list[dict[str, Any]] = []
    total_checked = 0

    for diff_entry in diffs:
        file_path = diff_entry.get("new_path", "unknown")
        diff_text = diff_entry.get("diff", "")

        for line_no, line in _parse_added_lines(diff_text):
            old_strict = engine.strict
            engine.strict = False
            result = engine.validate(line, agent_id=f"gitlab-mr-{mr_iid}:{file_path}")
            engine.strict = old_strict
            total_checked += result.rules_checked

            for v in result.blocking_violations:
                all_violations.append(
                    {
                        "rule_id": v.rule_id,
                        "rule_text": v.rule_text,
                        "severity": v.severity.value,
                        "matched_content": v.matched_content,
                        "category": v.category,
                        "source": "diff",
                        "file": file_path,
                        "line": line_no,
                    }
                )
            for w in result.warnings:
                all_warnings.append(
                    {
                        "rule_id": w.rule_id,
                        "rule_text": w.rule_text,
                        "severity": w.severity.value,
                        "matched_content": w.matched_content,
                        "category": w.category,
                        "source": "diff",
                        "file": file_path,
                        "line": line_no,
                    }
                )

    risk = _compute_risk(all_violations, all_warnings)

    return GovernanceReport(
        mr_iid=mr_iid,
        title=title,
        passed=len(all_violations) == 0,
        risk_score=risk,
        violations=all_violations,
        warnings=all_warnings,
        rules_checked=total_checked,
        constitutional_hash=engine.constitution.hash,
    )


def _parse_added_lines(diff_text: str) -> list[tuple[int, str]]:
    """Parse unified diff, returning (line_no, content) for added lines."""
    results: list[tuple[int, str]] = []
    current_line = 0
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("@@"):
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
            pass
        else:
            current_line += 1
    return results


def _compute_risk(
    violations: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> float:
    if not violations and not warnings:
        return 0.0
    weights = {"critical": 1.0, "high": 0.7, "medium": 0.3, "low": 0.1}
    total = sum(weights.get(v.get("severity", "medium"), 0.3) for v in violations)
    total += sum(weights.get(w.get("severity", "low"), 0.1) * 0.5 for w in warnings)
    return min(total / max(len(violations) + len(warnings), 1), 1.0)


# ---------------------------------------------------------------------------
# Real API mode (uses actual GovernedAnthropic + GitLabGovernanceBot)
# ---------------------------------------------------------------------------


def _run_real_anthropic(
    api_key: str,
    constitution: Constitution,
    prompts: list[str],
) -> None:
    """Run against real Anthropic API with GovernedAnthropic."""
    from acgs_lite.integrations.anthropic import GovernedAnthropic

    _section(2, "Layer 1: GovernedAnthropic (live API)")
    _info("Connecting to Anthropic API...")

    client = GovernedAnthropic(
        api_key=api_key,
        constitution=constitution,
        agent_id="hackathon-demo",
        strict=False,
    )

    for prompt in prompts:
        print()
        _info(f"Prompt: {_c(prompt, 'white', 'bold')}")
        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text if response.content else "(empty)"
            _code(text[:300] + ("..." if len(text) > 300 else ""))

            stats = client.stats
            rate = stats.get("compliance_rate", 1.0)
            violations = stats.get("total_violations", 0)
            if violations > 0:
                _fail(f"Violations detected: {violations} (compliance: {rate:.0%})")
            else:
                _ok(f"Output validated clean (compliance: {rate:.0%})")

        except Exception as exc:
            _fail(f"Blocked by governance: {exc}")

    print()
    _info(f"Audit chain valid: {client.audit_log.verify_chain()}")


async def _run_real_gitlab(
    gitlab_url: str,
    project_id: int,
    gitlab_token: str,
    constitution: Constitution,
    mr_iid: int,
) -> None:
    """Run against real GitLab API with GitLabGovernanceBot."""
    from acgs_lite.integrations.gitlab import GitLabGovernanceBot

    _section(4, "Layer 2: GitLabGovernanceBot (live API)")
    _info(f"Connecting to {gitlab_url}, project {project_id}...")

    bot = GitLabGovernanceBot(
        token=gitlab_token,
        project_id=project_id,
        constitution=constitution,
        base_url=f"{gitlab_url.rstrip('/')}/api/v4",
        strict=False,
    )

    _info(f"Validating MR !{mr_iid}...")
    report = await bot.validate_merge_request(mr_iid)
    _print_governance_report(report)


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------


def _print_governance_report(report: GovernanceReport) -> None:
    """Pretty-print a GovernanceReport to the terminal."""
    if report.passed:
        _ok(f"MR !{report.mr_iid} governance PASSED (risk: {report.risk_score:.2f})")
    else:
        _fail(f"MR !{report.mr_iid} governance FAILED (risk: {report.risk_score:.2f})")

    _info(f"Rules checked: {report.rules_checked}")
    _info(f"Constitutional hash: {report.constitutional_hash}")

    if report.violations:
        print()
        print(f"  {_c('Violations:', 'red', 'bold')}")
        for v in report.violations:
            sev = v.get("severity", "unknown").upper()
            sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
            file_ref = ""
            if v.get("file") and v.get("line"):
                file_ref = " @ " + _c(f"{v['file']}:{v['line']}", "cyan")
            print(
                f"    {_c(f'[{sev}]', sev_color, 'bold')} "
                f"{_c(v['rule_id'], 'white', 'bold')}: {v['rule_text']}{file_ref}"
            )
            if v.get("matched_content"):
                matched = v["matched_content"][:80]
                print(f"           matched: {_c(matched, 'dim')}")

    if report.warnings:
        print()
        print(f"  {_c('Warnings:', 'yellow', 'bold')}")
        for w in report.warnings:
            print(f"    {_c('[WARN]', 'yellow')} {w['rule_id']}: {w['rule_text']}")

    # Show what the Markdown comment would look like
    print()
    _info("GitLab MR comment that would be posted:")
    md = format_governance_report(report)
    for line in md.splitlines()[:15]:
        print(f"    {_c(line, 'dim')}")
    if len(md.splitlines()) > 15:
        print(f"    {_c('... (truncated)', 'dim')}")


# ---------------------------------------------------------------------------
# Layer 3: Self-governance via tool_use
# ---------------------------------------------------------------------------

# Simulated Claude tool_use interaction: Claude generates violating code,
# then calls validate_action on its own output, sees violations, and
# produces a compliant alternative.

_SELF_GOV_SCENARIO = {
    "prompt": "Write a quick database helper with embedded credentials",
    "initial_output": _SIMULATED_RESPONSES["violation_secrets"],
    "tool_call": {
        "name": "validate_action",
        "input": {
            "text": _SIMULATED_RESPONSES["violation_secrets"],
            "agent_id": "self-check",
        },
    },
    "corrected_output": textwrap.dedent("""\
        Here is a secure database helper:

        ```python
        import os

        def get_db_connection():
            api_key = os.environ["DB_API_KEY"]
            password = os.environ["DB_PASSWORD"]

            if not api_key or not password:
                raise RuntimeError("Database credentials not configured")

            return Database(api_key=api_key, password=password)
        ```

        All credentials are loaded from environment variables,
        keeping secrets out of source code per DATA-002."""),
}


def _run_self_governance_simulation(engine: GovernanceEngine) -> None:
    """Simulate the Claude self-governance loop without API keys."""
    scenario = _SELF_GOV_SCENARIO

    # Step 1: Claude generates initial (violating) response
    print()
    _info(f"Prompt: {_c(scenario['prompt'], 'white', 'bold')}")
    print()
    _info("Step 1: Claude generates initial response")
    snippet = scenario["initial_output"].strip().splitlines()[:6]
    _code("\n".join(snippet))
    _code("...")

    # Validate the initial output
    old_strict = engine.strict
    engine.strict = False
    result = engine.validate(
        scenario["initial_output"],
        agent_id="hackathon-demo:output",
    )
    engine.strict = old_strict

    _fail(
        f"{len(result.violations)} violation(s) in initial output "
        f"({result.rules_checked} rules, {result.latency_ms:.1f}ms)"
    )
    for v in result.violations:
        sev_color = "red" if v.severity.value in ("critical", "high") else "yellow"
        print(
            f"    {_c(f'[{v.severity.value.upper()}]', sev_color, 'bold')} "
            f"{_c(v.rule_id, 'white', 'bold')}: {v.rule_text}"
        )

    # Step 2: Claude calls validate_action via tool_use
    print()
    _info(
        f"Step 2: Claude calls {_c('validate_action', 'yellow', 'bold')} "
        "on its own output via tool_use"
    )
    tool_call = scenario["tool_call"]
    _info(f"  Tool: {_c(tool_call['name'], 'yellow')}")
    _info(f"  Agent ID: {_c(tool_call['input']['agent_id'], 'cyan')}")

    # Process through the governance engine (same as handle_governance_tool)
    old_strict = engine.strict
    engine.strict = False
    tool_result = engine.validate(
        scenario["initial_output"],
        agent_id="hackathon-demo:self-check",
    )
    engine.strict = old_strict

    tool_response = {
        "valid": tool_result.valid,
        "violations": [
            {
                "rule_id": v.rule_id,
                "rule_text": v.rule_text,
                "severity": v.severity.value,
                "matched_content": v.matched_content[:60],
            }
            for v in tool_result.violations
        ],
        "rules_checked": tool_result.rules_checked,
        "constitutional_hash": tool_result.constitutional_hash,
    }

    _info("  Tool result:")
    import json as _json

    for line in _json.dumps(tool_response, indent=2).splitlines()[:12]:
        print(f"    {_c(line, 'dim')}")
    if len(tool_result.violations) > 2:
        print(f"    {_c('...', 'dim')}")

    _fail(f"Claude sees {len(tool_result.violations)} violation(s) in its own output")

    # Step 3: Claude self-corrects
    print()
    _info(
        f"Step 3: Claude {_c('self-corrects', 'green', 'bold')}, generating a compliant alternative"
    )
    corrected_snippet = scenario["corrected_output"].strip().splitlines()[:8]
    _code("\n".join(corrected_snippet))
    if len(scenario["corrected_output"].strip().splitlines()) > 8:
        _code("...")

    # Validate the corrected output
    old_strict = engine.strict
    engine.strict = False
    corrected_result = engine.validate(
        scenario["corrected_output"],
        agent_id="hackathon-demo:corrected",
    )
    engine.strict = old_strict

    if corrected_result.valid:
        _ok(
            f"Corrected output is CLEAN "
            f"({corrected_result.rules_checked} rules, "
            f"{corrected_result.latency_ms:.1f}ms)"
        )
    else:
        _warn(f"Corrected output still has {len(corrected_result.violations)} issue(s)")

    print()
    _ok(f"Self-governance loop complete: {_c('generate -> validate -> correct', 'green')}")
    _info(
        "Claude used constitutional tools to audit itself. "
        "The proposer and validator remain separated (MACI)."
    )


def _run_self_governance_live(
    api_key: str,
    constitution: Constitution,
) -> None:
    """Run the self-governance loop against the real Anthropic API."""
    from acgs_lite.integrations.anthropic import GovernedAnthropic

    client = GovernedAnthropic(
        api_key=api_key,
        constitution=constitution,
        agent_id="hackathon-self-gov",
        strict=False,
    )

    tools = client.governance_tools()
    prompt = _SELF_GOV_SCENARIO["prompt"]

    print()
    _info(f"Prompt: {_c(prompt, 'white', 'bold')}")

    # Step 1: Generate initial response (with governance tools available)
    _info("Step 1: Claude generates response with governance tools available")
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        tools=tools,
        messages=[
            {
                "role": "user",
                "content": (
                    f"{prompt}\n\nAfter generating your response, use the "
                    "validate_action tool to check your own output for "
                    "constitutional compliance. If violations are found, "
                    "provide a corrected version."
                ),
            },
        ],
    )

    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": (
                f"{prompt}\n\nAfter generating your response, use the "
                "validate_action tool to check your own output for "
                "constitutional compliance. If violations are found, "
                "provide a corrected version."
            ),
        },
        {"role": "assistant", "content": response.content},
    ]

    # Process response blocks — handle text + tool_use
    for block in response.content:
        if hasattr(block, "text") and block.text:
            _info("Claude's initial response:")
            snippet = block.text.strip().splitlines()[:8]
            _code("\n".join(snippet))

        elif hasattr(block, "type") and block.type == "tool_use":
            _info(f"Step 2: Claude calls {_c(block.name, 'yellow', 'bold')} on its own output")

            # Execute the governance tool
            tool_result = client.handle_governance_tool(block.name, block.input)

            import json as _json

            result_text = _json.dumps(tool_result, indent=2, default=str)
            for line in result_text.splitlines()[:10]:
                print(f"    {_c(line, 'dim')}")

            if not tool_result.get("valid", True):
                _fail(f"Claude sees {len(tool_result.get('violations', []))} violation(s)")
            else:
                _ok("Claude's output passed self-check")

            # Feed result back and get corrected response
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result_text,
                        },
                    ],
                }
            )

            _info("Step 3: Claude self-corrects based on tool results")
            followup = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                tools=tools,
                messages=messages,
            )

            for fblock in followup.content:
                if hasattr(fblock, "text") and fblock.text:
                    corrected_snippet = fblock.text.strip().splitlines()[:8]
                    _code("\n".join(corrected_snippet))
                    if len(fblock.text.strip().splitlines()) > 8:
                        _code("...")

    print()
    _ok(f"Self-governance loop complete: {_c('generate -> validate -> correct', 'green')}")


# ---------------------------------------------------------------------------
# Main demo flow
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ACGS: GitLab + Anthropic Governance Demo (Hackathon Bonus Track)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Simulation mode (no API keys needed)
              python gitlab_anthropic_demo.py

              # With real Anthropic API
              python gitlab_anthropic_demo.py --anthropic-key sk-ant-...

              # Full integration
              python gitlab_anthropic_demo.py \\
                  --anthropic-key sk-ant-... \\
                  --gitlab-url https://gitlab.com \\
                  --project-id 12345 \\
                  --gitlab-token glpat-... \\
                  --mr-iid 42
        """),
    )
    parser.add_argument(
        "--anthropic-key",
        default=os.environ.get("ANTHROPIC_API_KEY"),
        help="Anthropic API key (env: ANTHROPIC_API_KEY)",
    )
    parser.add_argument(
        "--gitlab-url",
        default=os.environ.get("GITLAB_URL", "https://gitlab.com"),
        help="GitLab instance URL (env: GITLAB_URL, default: https://gitlab.com)",
    )
    parser.add_argument(
        "--project-id",
        type=int,
        default=int(os.environ.get("GITLAB_PROJECT_ID", "0")),
        help="GitLab project ID (env: GITLAB_PROJECT_ID)",
    )
    parser.add_argument(
        "--gitlab-token",
        default=os.environ.get("GITLAB_TOKEN"),
        help="GitLab personal access token (env: GITLAB_TOKEN)",
    )
    parser.add_argument(
        "--mr-iid",
        type=int,
        default=int(os.environ.get("GITLAB_MR_IID", "42")),
        help="Merge request IID for live validation (env: GITLAB_MR_IID)",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Force offline simulation mode even when API keys are set in the environment",
    )
    args = parser.parse_args()

    has_anthropic = args.anthropic_key is not None and not args.simulate
    has_gitlab = args.gitlab_token is not None and args.project_id > 0 and not args.simulate
    simulation = args.simulate or not has_anthropic

    # -- Banner --
    _banner("ACGS: Anthropic + GitLab Governance Demo")
    print()
    if simulation:
        _info("Running in SIMULATION mode (no API keys provided)")
        _info("Pass --anthropic-key / --gitlab-token for live APIs")
    else:
        if has_anthropic:
            _ok("Anthropic API key detected")
        if has_gitlab:
            _ok(f"GitLab configured: {args.gitlab_url} (project {args.project_id})")
    print()

    # -- Load constitution --
    constitution_path = Path(__file__).parent / "constitution.yaml"
    if constitution_path.exists():
        constitution = Constitution.from_yaml(str(constitution_path))
        _info(f"Constitution loaded from {constitution_path.name}")
    else:
        constitution = Constitution.default()
        _info("Using default constitution")

    _info(f"Constitutional hash: {_c(constitution.hash, 'cyan', 'bold')}")
    _info(f"Rules: {len(constitution.rules)}")

    engine = GovernanceEngine(constitution, strict=False, audit_mode="full")

    # -- Prompts that demonstrate different outcomes --
    demo_prompts = [
        ("Write a secure config loader using environment variables", "safe"),
        ("Write code that stores API keys in plaintext for quick access", "violation"),
        ("Write a script to reset the database by dropping all tables", "violation"),
        ("Write code to bypass validation and skip safety checks", "violation"),
    ]

    # ================================================================
    # LAYER 1: LLM Output Governance
    # ================================================================

    if has_anthropic:
        _run_real_anthropic(
            api_key=args.anthropic_key,
            constitution=constitution,
            prompts=[p for p, _ in demo_prompts],
        )
    else:
        _section(1, "Layer 1: GovernedAnthropic (simulation)")
        _info(
            "GovernedAnthropic wraps Anthropic's Messages API. Every response "
            "is validated against the constitution BEFORE being returned."
        )

        for prompt, _expected in demo_prompts:
            print()
            _info(f"Prompt: {_c(prompt, 'white', 'bold')}")

            response_text, result = _simulate_anthropic_call(
                prompt, engine, agent_id="hackathon-demo"
            )

            # Show a snippet of the response
            snippet_lines = response_text.strip().splitlines()[:8]
            _code("\n".join(snippet_lines))
            if len(response_text.strip().splitlines()) > 8:
                _code("...")

            if result.valid:
                _ok(
                    f"Output validated clean "
                    f"({result.rules_checked} rules checked in {result.latency_ms:.1f}ms)"
                )
            else:
                violations = result.violations
                _fail(
                    f"{len(violations)} violation(s) caught at LLM output layer "
                    f"({result.rules_checked} rules, {result.latency_ms:.1f}ms)"
                )
                for v in violations:
                    sev_color = "red" if v.severity.value in ("critical", "high") else "yellow"
                    print(
                        f"    {_c(f'[{v.severity.value.upper()}]', sev_color, 'bold')} "
                        f"{_c(v.rule_id, 'white', 'bold')}: {v.rule_text}"
                    )
                    print(f"           matched: {_c(v.matched_content[:80], 'dim')}")

    # ================================================================
    # LAYER 2: GitLab MR Governance
    # ================================================================

    if has_gitlab:
        import asyncio

        asyncio.run(
            _run_real_gitlab(
                gitlab_url=args.gitlab_url,
                project_id=args.project_id,
                gitlab_token=args.gitlab_token,
                constitution=constitution,
                mr_iid=args.mr_iid,
            )
        )
    else:
        _section(2, "Layer 2: GitLab MR Governance (simulation)")
        _info(
            "GitLabGovernanceBot validates merge request diffs line-by-line. "
            "Even if a violation slips past the LLM layer, it gets caught here."
        )

        # -- Clean MR --
        print()
        _info(f"Scenario A: {_c('Clean MR', 'green', 'bold')}")
        _info("MR contains only environment-variable-based config")
        report_clean = _simulate_mr_governance(
            _SIMULATED_MR_DIFFS["clean"],
            engine,
            mr_iid=100,
            title="feat: add secure config loader",
        )
        _print_governance_report(report_clean)

        # -- Dirty MR --
        print()
        _info(f"Scenario B: {_c('Violation MR', 'red', 'bold')}")
        _info("MR contains hardcoded secrets and destructive SQL")
        report_dirty = _simulate_mr_governance(
            _SIMULATED_MR_DIFFS["dirty"],
            engine,
            mr_iid=101,
            title="feat: add database utilities",
        )
        _print_governance_report(report_dirty)

    # ================================================================
    # LAYER 3: Self-Governance via tool_use
    # ================================================================

    _section(3, "Layer 3: Claude Governs Claude (tool_use self-governance)")
    _info(
        "Claude uses ACGS governance tools via tool_use to analyze its own "
        "output, detect violations, and self-correct — all within the "
        "constitutional framework."
    )
    _info(
        "This uses GovernedAnthropic.governance_tools() + "
        "handle_governance_tool() for the agentic loop."
    )

    if has_anthropic:
        _run_self_governance_live(args.anthropic_key, constitution)
    else:
        _run_self_governance_simulation(engine)

    # ================================================================
    # LAYER 4: Defense in depth summary
    # ================================================================

    _section(4, "Defense in Depth: Three-Layer Governance")
    print()
    print(
        textwrap.indent(
            textwrap.dedent(f"""\
        {_c("User", "white", "bold")}
          |
          |  "Write code that stores API keys in plaintext"
          v
        {_c("GovernedAnthropic", "cyan", "bold")}  (Layer 1: LLM output validation)
          |
          |  Claude generates response
          |  ACGS validates output against constitution
          |  {_c("VIOLATION CAUGHT", "red", "bold")}: DATA-002, SAFE-001, OPS-001 ...
          |
          v
        {_c("Claude + tool_use", "yellow", "bold")}  (Layer 3: self-governance)
          |
          |  Claude calls validate_action on its own output
          |  Sees violations, generates compliant alternative
          |  {_c("SELF-CORRECTED", "green", "bold")}: secrets removed, env vars used
          |
          v
        {_c("GitLab MR", "magenta", "bold")}  (Layer 2: merge request validation)
          |
          |  Even if code reaches an MR somehow,
          |  GitLabGovernanceBot scans every diff hunk
          |  {_c("VIOLATION CAUGHT", "red", "bold")}: inline comments posted on exact lines
          |
          v
        {_c("Merge blocked", "red", "bold")} -- constitutional governance enforced
    """),
            "    ",
        )
    )

    # -- Stats --
    stats = engine.stats
    _section(5, "Governance Stats")
    _info(f"Total validations:  {stats['total_validations']}")
    rate = stats.get("compliance_rate")
    rate_str = f"{rate:.0%}" if rate is not None else "n/a"
    _info(f"Compliance rate:    {rate_str}")
    _info(f"Rules loaded:       {stats['rules_count']}")
    _info(f"Constitutional hash: {stats['constitutional_hash']}")

    print()
    _banner("Demo Complete")
    print()
    _info("Three layers of constitutional governance, zero violations in production.")
    _info("Learn more: README.md")
    print()


if __name__ == "__main__":
    main()
