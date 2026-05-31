"""GovernedBase mixin — shared governance setup for integration wrappers.

Eliminates ~200 lines of duplicated init, stats, and non-strict validation
boilerplate across CrewAI, DSPy, Haystack, Pydantic AI, and other governed
wrapper classes.

No framework-specific imports live here.  Only ``acgs_lite.constitution``,
``acgs_lite.engine``, and ``acgs_lite.audit`` are used.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import logging
from typing import Any

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.engine import GovernanceEngine
from acgs_lite.engine.types import ValidationResult
from acgs_lite.errors import ConstitutionalViolationError

logger = logging.getLogger(__name__)


class GovernedBase:
    """Mixin providing common governance plumbing for integration wrappers.

    Subclasses call :meth:`_init_governance` in their ``__init__`` to set up
    the standard ``constitution``, ``audit_log``, ``engine``, and ``agent_id``
    attributes.  They can then use :attr:`governance_stats` and
    :meth:`_validate_nonstrict` to avoid repeating the same patterns.
    """

    # These are set by _init_governance; declared here for type checkers.
    constitution: Constitution
    audit_log: AuditLog
    engine: GovernanceEngine
    agent_id: str

    def _init_governance(
        self,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "governed",
        strict: bool = True,
    ) -> None:
        """Initialise the governance attributes shared by every wrapper.

        Parameters
        ----------
        constitution:
            Constitution to validate against.  Defaults to
            ``Constitution.default()``.
        agent_id:
            Identifier for this governed entity in audit entries.
        strict:
            Whether to raise on violation (``True``) or just warn
            (``False``).
        """
        self.constitution = constitution or Constitution.default()
        self.audit_log = AuditLog()
        self.engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict,
        )
        self.agent_id = agent_id

    @property
    def governance_stats(self) -> dict[str, Any]:
        """Return the standard governance statistics dict."""
        return {
            **self.engine.stats,
            "agent_id": self.agent_id,
            "audit_chain_valid": self.audit_log.verify_chain(),
        }

    def _validate_nonstrict(
        self,
        text: str,
        *,
        label: str = "output",
        context: dict[str, Any] | None = None,
    ) -> ValidationResult | None:
        """Validate *text* non-strictly and log warnings on violation.

        Returns the :class:`ValidationResult` when validation ran, or
        ``None`` when *text* was empty/falsy and validation was skipped, or when
        the engine raised on an absolute-HALT rule (see below).

        Non-blocking contract: this helper must **never** raise.  ``strict=False``
        suppresses ordinary blocking violations, but the engine still raises
        :class:`ConstitutionalViolationError` for ``HALT`` rules regardless of
        strictness (HALT is absolute at the engine layer).  Integration hooks
        that document themselves as non-blocking rely on this method swallowing
        that exception — so we catch it, log, and return ``None`` rather than let
        a HALT rule tear down a caller's loop.

        *context* is forwarded to :meth:`GovernanceEngine.validate` so callers can
        opt produced content into context-gated validators (e.g. pass
        ``{"action_type": "code"}`` to run the AST code validator on step code).
        """
        if not text:
            return None
        try:
            result = self.engine.validate(
                text,
                agent_id=f"{self.agent_id}:{label}",
                context=context,
                strict=False,
            )
        except ConstitutionalViolationError as exc:
            logger.warning(
                "%s governance HALT (suppressed; non-blocking hook): rule=%s",
                label,
                exc.rule_id,
            )
            return None
        if not result.valid:
            logger.warning(
                "%s governance violations: %s",
                label,
                [v.rule_id for v in result.violations],
            )
        return result
