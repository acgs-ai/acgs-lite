# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Constitutional Hash: 608508a9bd224290

"""LitServe integration for ACGS constitutional governance.

Provides GovernedLitAPI, a LitServe LitAPI base class that injects
constitutional checks into any inference server.

Usage::

    from acgs_lite.integrations.litserve import GovernedLitAPI
    from acgs_lite.constitution import Constitution
    from acgs_lite.maci import MACIRole
    import litserve as ls

    class MyAPI(GovernedLitAPI):
        def model_setup(self, device):
            self.model = load_my_model()

        def model_predict(self, request):
            return self.model(request["input"])

    if __name__ == "__main__":
        server = ls.LitServer(
            MyAPI(
                constitution=Constitution.default(),
                maci_role=MACIRole.VALIDATOR,
            )
        )
        server.run(port=8000)
"""

from __future__ import annotations

from typing import Any

import structlog

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.engine import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError, MACIViolationError
from acgs_lite.maci import MACIEnforcer, MACIRole
from acgs_lite.serialization import serialize_for_governance

logger = structlog.get_logger(__name__)

_CONSTITUTIONAL_HASH = "608508a9bd224290"

try:
    import litserve  # type: ignore[import-untyped]
    from fastapi import HTTPException  # litserve depends on fastapi

    LITSERVE_AVAILABLE = True
    _LitAPIBase = litserve.LitAPI
except ImportError:
    LITSERVE_AVAILABLE = False
    _LitAPIBase = object  # type: ignore[assignment,misc]
    HTTPException = Exception  # type: ignore[assignment,misc]


class GovernedLitAPI(_LitAPIBase):  # type: ignore[misc,valid-type]
    """LitServe LitAPI base with ACGS constitutional governance injected.

    Subclass this instead of litserve.LitAPI. Implement model_setup() and
    model_predict() rather than setup() and predict().

    On every predict() call:
    1. Pre-validates the request against the constitution (fail-closed: 422 on violation)
    2. Enforces MACI role by default (403 on violation)
    3. Calls model_predict() (your inference logic)
    4. Post-validates the response (422 on violation)
    5. Returns the response

    If model_predict() raises an unexpected exception, returns 500 without
    leaking the traceback (fail-closed behavior).

    Args:
        constitution: Constitution to validate against. Defaults to Constitution.default().
        agent_id: Identifier for this agent in audit logs.
        maci_role: MACI role to assign. Required unless enforce_maci=False is
            explicitly used for advisory-only evaluation.
        enforce_maci: Whether to enforce MACI role boundaries on each predict call.
            Defaults to True.
        strict: Whether to raise on violations (True) or just log (False).
    """

    def __init__(
        self,
        constitution: Constitution | None = None,
        *,
        agent_id: str = "governed",
        maci_role: MACIRole | None = None,
        enforce_maci: bool = True,
        strict: bool = True,
    ) -> None:
        self._constitution = constitution or Constitution.default()
        self._agent_id = agent_id
        self._maci_role = maci_role
        self._enforce_maci = enforce_maci
        self._strict = strict
        if enforce_maci and maci_role is None:
            raise ValueError("enforce_maci=True requires an explicit maci_role")
        # Engine and audit log are initialised in setup() once device is known
        self._audit_log: AuditLog | None = None
        self._engine: GovernanceEngine | None = None
        self._maci: MACIEnforcer | None = None

    # ------------------------------------------------------------------
    # LitServe lifecycle hooks
    # ------------------------------------------------------------------

    def setup(self, device: Any) -> None:
        """Called once per worker by LitServe. Do not override — use model_setup()."""
        self._audit_log = AuditLog()
        self._engine = GovernanceEngine(
            self._constitution,
            audit_log=self._audit_log,
            strict=self._strict,
            audit_mode="full",
        )
        # Verify constitutional hash — fail-closed if constitution is stale
        if self._engine._const_hash != _CONSTITUTIONAL_HASH:
            raise RuntimeError(
                f"constitutional hash mismatch: expected {_CONSTITUTIONAL_HASH!r}, "
                f"got {self._engine._const_hash!r} — stale constitution"
            )
        if self._maci_role is not None:
            self._maci = MACIEnforcer(audit_log=self._audit_log)
            self._maci.assign_role(self._agent_id, self._maci_role)

        self.model_setup(device)
        logger.info(
            "governed_litapi_ready",
            agent_id=self._agent_id,
            constitutional_hash=_CONSTITUTIONAL_HASH,
            maci_role=self._maci_role.value if self._maci_role else None,
            enforce_maci=self._enforce_maci,
        )

    def predict(self, request: Any) -> Any:
        """Called per request by LitServe. Do not override — use model_predict()."""
        engine = self._engine
        assert engine is not None, "setup() must be called before predict()"

        try:
            # 1. Pre-validate input
            raw = serialize_for_governance(request) or str(request)
            try:
                engine.validate(raw, agent_id=self._agent_id)
            except ConstitutionalViolationError as exc:
                logger.warning(
                    "governed_litapi_input_violation",
                    agent_id=self._agent_id,
                    rule_id=exc.rule_id,
                    violations=getattr(exc, "violations_list", []),
                )
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "constitutional_violation",
                        "rule_id": exc.rule_id,
                        "violations": getattr(exc, "violations_list", []),
                    },
                ) from exc

            # 2. MACI check
            if self._enforce_maci and self._maci is not None:
                try:
                    self._maci.check(self._agent_id, "validate")
                except MACIViolationError as exc:
                    logger.warning(
                        "governed_litapi_maci_violation",
                        agent_id=self._agent_id,
                        exc_type=type(exc).__name__,
                    )
                    raise HTTPException(
                        status_code=403,
                        detail={"error": "maci_violation"},
                    ) from exc

            # 3. Run model
            result = self.model_predict(request)

            # 4. Post-validate output
            out_raw = serialize_for_governance(result)
            if out_raw is not None:
                try:
                    engine.validate(out_raw, agent_id=f"{self._agent_id}:output")
                except ConstitutionalViolationError as exc:
                    logger.warning(
                        "governed_litapi_output_violation",
                        agent_id=self._agent_id,
                        rule_id=exc.rule_id,
                    )
                    raise HTTPException(
                        status_code=422,
                        detail={
                            "error": "constitutional_violation_output",
                            "rule_id": exc.rule_id,
                            "violations": getattr(exc, "violations_list", []),
                        },
                    ) from exc

            return result

        except HTTPException:
            raise  # already formatted, pass through
        except Exception as exc:
            logger.error(
                "governed_litapi_unexpected_error",
                agent_id=self._agent_id,
                exc_type=type(exc).__name__,
            )
            raise HTTPException(
                status_code=500,
                detail={"error": "governance_error"},
            ) from exc

    # ------------------------------------------------------------------
    # Subclass hooks
    # ------------------------------------------------------------------

    def model_setup(self, device: Any) -> None:
        """Override to load your model. Called once per worker after governance setup."""
        raise NotImplementedError(f"{type(self).__name__} must implement model_setup()")

    def model_predict(self, request: Any) -> Any:
        """Override to run inference. Called per request after governance pre-checks."""
        raise NotImplementedError(f"{type(self).__name__} must implement model_predict()")

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    @property
    def audit_entries(self) -> list:
        """Audit entries recorded during this worker lifetime."""
        if self._audit_log is None:
            return []
        return self._audit_log.entries

    @property
    def governance_stats(self) -> dict[str, Any]:
        """Governance engine statistics."""
        if self._engine is None:
            return {}
        return self._engine.stats


__all__ = ["LITSERVE_AVAILABLE", "GovernedLitAPI"]
