"""ACGS-Lite Agno Integration.

Agno describes itself as "the runtime for agentic software" (agents/teams/workflows,
FastAPI runtime, and an optional control plane UI). ACGS-Lite is a governance layer.

This adapter lets you run Agno agents with ACGS constitutional validation by attaching:
- an input guardrail (blocks on unconstitutional user input)
- an output hook (optional: block or warn on unconstitutional model output)

Agno primitives mapped to ACGS:
- Agno *pre_hooks*  -> ACGS input validation (fail-closed)
- Agno *post_hooks* -> ACGS output validation (warn by default, optionally fail-closed)
- ACGS AuditLog     -> Tamper-evident audit chain independent of Agno DB storage

Usage::

    from agno.agent import Agent
    from agno.models.openai import OpenAIChat

    from acgs_lite import Constitution
    from acgs_lite.integrations.agno import AgnoACGSGovernor

    constitution = Constitution.from_template("general")
    governor = AgnoACGSGovernor(constitution=constitution, agent_id="agno-agent")

    agent = Agent(
        name="My Agent",
        model=OpenAIChat(id="gpt-5.5"),
        pre_hooks=[governor],                 # input guardrail
        post_hooks=[governor.output_hook],    # output check
    )

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.engine import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError

logger = logging.getLogger(__name__)

try:
    from agno.exceptions import CheckTrigger, InputCheckError, OutputCheckError  # noqa: F401
    from agno.guardrails.base import BaseGuardrail  # noqa: F401

    AGNO_AVAILABLE = True
except ImportError:  # pragma: no cover
    AGNO_AVAILABLE = False
    BaseGuardrail = object  # type: ignore[assignment,misc]


def _extract_run_input_text(run_input: Any) -> str:
    """Best-effort extraction of user input text from Agno RunInput-like objects."""
    if run_input is None:
        return ""
    if hasattr(run_input, "input_content_string"):
        try:
            return str(run_input.input_content_string())
        except Exception:
            pass
    if hasattr(run_input, "input_content"):
        try:
            return str(run_input.input_content)
        except Exception:
            pass
    return str(run_input)


def _extract_run_output_text(run_output: Any) -> str:
    """Best-effort extraction of output text from Agno RunOutput-like objects."""
    if run_output is None:
        return ""
    if hasattr(run_output, "content"):
        try:
            content = run_output.content
            if content is None:
                return ""
            if isinstance(content, str):
                return content
            return str(content)
        except Exception:
            pass
    return str(run_output)


class AgnoACGSGovernor(BaseGuardrail):  # type: ignore[misc]  # agno is an optional dependency
    """Attach ACGS validation to an Agno Agent via pre_hooks/post_hooks.

    This object is:
    - a pre-hook guardrail (implements BaseGuardrail.check / async_check)
    - a provider of an output hook (`output_hook`) for post_hooks

    Design note:
    Agno guarantees guardrails run synchronously even when hooks are configured to run
    in FastAPI background tasks. Using a BaseGuardrail instance for input enforcement
    ensures ACGS remains fail-closed in production.
    """

    def __init__(
        self,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "agno-agent",
        strict_input: bool = True,
        strict_output: bool = False,
    ) -> None:
        if not AGNO_AVAILABLE:
            raise ImportError("agno is required. Install with: pip install acgs-lite[agno]")

        self.constitution = constitution or Constitution.default()
        self.audit_log = AuditLog()
        self.input_engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict_input,
            audit_mode="full",
        )
        # Separate engine avoids mutating `.strict` during concurrent requests.
        self.output_engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict_output,
            audit_mode="full",
        )
        self.agent_id = agent_id
        self.strict_output = strict_output

    @property
    def output_hook(self) -> Callable[..., None]:
        """Post-hook that validates the model output.

        Intended usage: `post_hooks=[governor.output_hook]`.
        """
        return self.check_output

    @property
    def governance_stats(self) -> dict[str, Any]:
        return {
            **self.input_engine.stats,
            "output_checks_total": self.output_engine.stats.get("total_checks", 0),
            "agent_id": self.agent_id,
            "audit_chain_valid": self.audit_log.verify_chain(),
        }

    def check(self, run_input: Any) -> None:
        """Guardrail check for user input (fail-closed by default)."""
        text = _extract_run_input_text(run_input)
        if not text:
            return
        try:
            self.input_engine.validate(text, agent_id=self.agent_id)
        except ConstitutionalViolationError as e:
            # Translate ACGS into Agno's expected "guardrail failed" exception type.
            raise InputCheckError(
                str(e),
                check_trigger=CheckTrigger.VALIDATION_FAILED,  # type: ignore[name-defined]
                additional_data={
                    "acgs_rule_id": e.rule_id,
                    "acgs_severity": e.severity,
                    "acgs_enforcement_action": getattr(
                        e.enforcement_action, "value", str(e.enforcement_action)
                    ),
                    "audit_chain_valid": self.audit_log.verify_chain(),
                },
            ) from e

    async def async_check(self, run_input: Any) -> None:
        # GovernanceEngine.validate is sync; keep async variant lightweight.
        self.check(run_input)

    def check_output(self, *, run_output: Any, **_: Any) -> None:
        """Validate output content (warn by default, optionally fail-closed)."""
        text = _extract_run_output_text(run_output)
        if not text:
            return

        try:
            result = self.output_engine.validate(text, agent_id=f"{self.agent_id}:output")
        except ConstitutionalViolationError as e:
            raise OutputCheckError(
                str(e),
                check_trigger=CheckTrigger.VALIDATION_FAILED,  # type: ignore[name-defined]
                additional_data={
                    "acgs_rule_id": e.rule_id,
                    "acgs_severity": e.severity,
                    "acgs_enforcement_action": getattr(
                        e.enforcement_action, "value", str(e.enforcement_action)
                    ),
                    "audit_chain_valid": self.audit_log.verify_chain(),
                },
            ) from e

        if (not self.strict_output) and (not result.valid):
            logger.warning(
                "Agno output governance violations: %s",
                [v.rule_id for v in result.violations],
            )
