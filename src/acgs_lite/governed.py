# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""GovernedAgent — Wrap any agent/callable in constitutional governance.

This is the main user-facing API. Wrap any agent, function, or callable
in governance with a single line of code.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import asyncio
import functools
import hmac
import inspect
import logging
import math
import os
import threading
import time
import uuid
import warnings
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, TypeVar, cast, runtime_checkable

_log = logging.getLogger(__name__)

_MAX_RETRIES_LIMIT = 10

from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.circuit_breaker import GovernanceCircuitBreaker, WebhookNotificationChannel
from acgs_lite.constitution import Constitution
from acgs_lite.constitution.refusal_reasoning import RefusalReasoningEngine
from acgs_lite.constrained_output import attach_response_format
from acgs_lite.engine import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError, GovernanceError
from acgs_lite.legitimacy.authorization import (
    AuthorizationProfile,
    EngineDecision,
    ExecutionAuthority,
    ExecutionGrant,
    TrustedExecutionContext,
    authorization_envelope_json,
    build_issue_receipt,
    engine_decision_from_results,
    extract_authorization_kwargs,
    parse_authorization_envelope,
    resolve_profile,
)
from acgs_lite.legitimacy.decide import canonicalize_decision_state
from acgs_lite.legitimacy.invariants import (
    LegitimacyInvariantError,
    normalize_actual_call,
    validate_receipt_for_execution,
)
from acgs_lite.legitimacy.invocation import (
    InvocationBinding,
    PolicyBinding,
    _bound_arguments,
    bind_invocation,
    bind_policy,
    canonical_argument_digest,
    defaulted_argument_values,
    reject_method_spoof_kwargs,
)
from acgs_lite.legitimacy.ledger import (
    AttemptStatus,
    ConsumeDecision,
    InProcessGrantLedger,
    digest_output,
)
from acgs_lite.legitimacy.receipt import RECEIPT_SCHEMA_V2, DecisionReceipt
from acgs_lite.legitimacy.signing import (
    SIGNATURE_ALGORITHM,
    SIGNATURE_SCOPE_EXECUTION,
    ReceiptSigner,
    SignedReceipt,
    sign_execution_authorization,
)
from acgs_lite.maci import MACIEnforcer, MACIRole
from acgs_lite.provider_capabilities import (
    CapabilityStability,
    CapabilitySupportLevel,
    RequestShape,
    get_capability_registry,
)
from acgs_lite.serialization import GovernancePayloadError, governance_payloads_for_enforcement

T = TypeVar("T")
_PROCEED = object()

DEFAULT_SIGNED_GRANT_TTL_SECONDS = 300.0


@dataclass(slots=True, frozen=True)
class _IssuedSignedGrant:
    """What this instance signed for one production grant id.

    A grant id is not secret, so the registry binds the exact issued receipt and
    the issuing key: a receipt signed by any other pinned key, or a different
    receipt reusing a live grant id, is refused before the ledger consume.
    """

    deadline: float
    func_ref: weakref.ref[Callable[..., Any]]
    receipt_hash: str
    key_id: str
    public_key: str


def _carrier_grant_id(carrier: object) -> str | None:
    """The grant id an execution grant or signed receipt names, if it is a string."""
    if isinstance(carrier, ExecutionGrant):
        grant_id: object = carrier.grant_id
    elif isinstance(carrier, SignedReceipt):
        grant_id = getattr(carrier.receipt, "grant_id", None)
    else:
        return None
    return grant_id if isinstance(grant_id, str) else None


def _deny_unless_valid(result: object, *, action: str) -> None:
    """Fail closed on any engine result that is not explicitly ``valid is True``.

    Under ``strict=False`` the engine returns blocking verdicts instead of raising;
    discarding that result used to allow the call.
    """
    if getattr(result, "valid", None) is True:
        return
    violations = getattr(result, "violations", None) or ()
    rule_id = getattr(violations[0], "rule_id", None) if violations else None
    raise ConstitutionalViolationError(
        "constitution denied the invocation",
        rule_id=rule_id if isinstance(rule_id, str) and rule_id else "EXECUTION-GRANT-DENIED",
        action=action[:200],
    )


@runtime_checkable
class AgentProtocol(Protocol):
    """Protocol for agent-like objects that ACGS can wrap."""

    def run(self, input: str, **kwargs: Any) -> Any: ...


@runtime_checkable
class AsyncAgentProtocol(Protocol):
    """Protocol for async agent-like objects."""

    async def run(self, input: str, **kwargs: Any) -> Any: ...


@runtime_checkable
class CapabilityProfileProtocol(Protocol):
    """Minimal capability profile surface used by GovernedAgent."""

    model_id: str
    provider_type: str
    structured_output: Any
    support_level: CapabilitySupportLevel
    request_shape: RequestShape
    stability: CapabilityStability


class GovernedAgent:
    """Wrap any agent in constitutional governance.

    Validates inputs, keyword arguments and outputs against the constitution
    with the same fail-closed contract as :class:`GovernedCallable`: each value
    must be JSON-native and is evaluated in full, never truncated; an oversize
    (over 10,000 characters) or non-JSON value denies with
    :class:`~acgs_lite.serialization.GovernancePayloadError`, and any engine
    result that is not ``valid is True`` denies. ``strict`` does not change the
    decision: a blocking violation denies under ``strict=False`` too, while
    non-blocking (warning) violations pass in both modes. ``validate_output=False``
    is the explicit opt-out for output enforcement (it also disables the
    structured-output request injection). Produces full audit
    trails. MACI role checks are enforced by default: callers must provide an
    explicit ``maci_role`` when constructing the wrapper and a permitted
    ``governance_action`` on every execution. Passing ``enforce_maci=False`` is
    an explicit advisory-mode opt-out for non-side-effecting evaluation flows.

    Usage::

        from acgs_lite import Constitution, GovernedAgent, MACIRole

        constitution = Constitution.from_yaml("rules.yaml")
        agent = GovernedAgent(
            my_agent,
            constitution=constitution,
            maci_role=MACIRole.EXECUTOR,
        )
        result = agent.run("process this request", governance_action="execute")

    With default constitution::

        agent = GovernedAgent(my_agent, maci_role=MACIRole.EXECUTOR)
        result = agent.run("do something safe", governance_action="execute")

    With custom constitution::

        from acgs_lite import Constitution, Rule, Severity

        rules = Constitution.from_rules([
            Rule(id="R1", text="No PII", severity=Severity.CRITICAL,
                 keywords=["ssn", "social security"]),
        ])
        agent = GovernedAgent(my_agent, constitution=rules, maci_role=MACIRole.EXECUTOR)
        result = agent.run("review custom constitution", governance_action="execute")
    """

    def __init__(
        self,
        agent: Any,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "default",
        strict: bool = True,
        validate_output: bool = True,
        maci_role: MACIRole | None = None,
        enforce_maci: bool = True,
        max_retries: int = 0,
        side_effectful: bool = False,
        circuit_breaker: GovernanceCircuitBreaker | None = None,
        cdp_backend: Any | None = None,
        intervention_engine: Any | None = None,
    ) -> None:
        webhook_url = os.getenv("ACGS_HALT_WEBHOOK_URL")
        if circuit_breaker is None and webhook_url:
            circuit_breaker = GovernanceCircuitBreaker(
                system_id=agent_id,
                notification_channels=[
                    WebhookNotificationChannel(
                        webhook_url,
                        secret=os.getenv("ACGS_HALT_WEBHOOK_SECRET"),
                    )
                ],
            )
        self._agent = agent
        self.agent_id = agent_id
        self.validate_output = validate_output
        self.maci_role = maci_role
        self.enforce_maci = enforce_maci
        self.max_retries = min(max(0, max_retries), _MAX_RETRIES_LIMIT)
        self.side_effectful = side_effectful
        if self.side_effectful and self.max_retries:
            raise ValueError("side-effectful GovernedAgent does not permit output retries")
        self._circuit_breaker = circuit_breaker
        self.constitution = constitution or Constitution.default()
        self.audit_log = AuditLog()
        self.engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict,
            audit_mode="full",
        )
        self.maci = MACIEnforcer(audit_log=self.audit_log)
        self._refusal_engine = RefusalReasoningEngine(self.constitution)
        self._cdp_backend = cdp_backend  # None = disabled; set via ACGS_CDP_ENABLED too
        self._intervention_engine = intervention_engine

        if maci_role:
            self.maci.assign_role(agent_id, maci_role)
        if maci_role is not None and not self.enforce_maci:
            warnings.warn(
                "maci_role is set but enforce_maci=False — role separation is "
                "advisory only. GovernedAgent enforces MACI by default; pass "
                "enforce_maci=False only for explicit non-side-effecting evaluation flows.",
                DeprecationWarning,
                stacklevel=2,
            )

    def _check_maci(self, governance_action: str | None) -> None:
        if not self.enforce_maci:
            return
        if self.maci_role is None:
            raise GovernanceError(
                "GovernedAgent with MACI enforcement requires an explicit maci_role",
                rule_id="MACI-ROLE",
            )
        if not governance_action:
            raise GovernanceError(
                "GovernedAgent with MACI enforcement requires governance_action",
                rule_id="MACI-ACTION",
            )
        self.maci.check(self.agent_id, governance_action)

    def _build_retry_prompt(
        self,
        original_input: str,
        error: ConstitutionalViolationError,
        attempt: int,
    ) -> str:
        """Build a remediation prompt from violation details.

        Only trusted content (rule IDs, rule text from the constitution) is
        used as top-level instructions.  User-controlled text (original_input)
        is truncated and quoted to reduce prompt-injection surface.
        """
        rule_id = error.rule_id or "UNKNOWN"
        # Look up the canonical rule text from the constitution (trusted source)
        rule_text = ""
        for r in self.constitution.rules:
            if r.id == rule_id:
                rule_text = r.text
                break

        decision = self._refusal_engine.reason_refusal(
            action=error.action or original_input,
            triggered_rule_ids=[rule_id] if rule_id != "UNKNOWN" else [],
        )
        parts = [
            f"[GOVERNANCE RETRY {attempt}] Your previous output violated constitutional rule {rule_id}.",
            f"Rule: {rule_text}" if rule_text else f"Rule ID: {rule_id}",
        ]
        if decision.suggestions:
            parts.append("Suggestions to produce a compliant response:")
            for s in decision.suggestions:
                parts.append(f"  - {s.rationale}")
        # Truncate and quote user-controlled input to limit injection surface.
        # Escape triple-quote sequences to prevent prompt breakout.
        safe_input = original_input[:200].replace('"""', '\\"\\"\\""')
        parts.append(f'Original request (quoted): """{safe_input}"""')
        parts.append("Please provide a response that complies with all governance rules.")
        return "\n".join(parts)

    def _execute_agent(self, input: str, **kwargs: Any) -> Any:
        """Execute the underlying agent (sync)."""
        if hasattr(self._agent, "run"):
            return self._agent.run(input, **kwargs)
        elif callable(self._agent):
            return self._agent(input, **kwargs)
        else:
            raise GovernanceError(
                f"Agent of type {type(self._agent).__name__} is not callable "
                "and has no .run() method",
                rule_id="AGENT-PROTOCOL",
            )

    def _resolve_capability_profile(
        self,
        explicit_profile: CapabilityProfileProtocol | None,
    ) -> CapabilityProfileProtocol | None:
        if explicit_profile is not None:
            return explicit_profile

        for attr_name in ("capability_profile", "provider_capability_profile"):
            profile = getattr(self._agent, attr_name, None)
            if profile is not None:
                return cast(CapabilityProfileProtocol, profile)

        provider_name_getter = getattr(self._agent, "get_provider_name", None)
        provider_name = provider_name_getter() if callable(provider_name_getter) else None
        if provider_name is None:
            provider_name = getattr(self._agent, "provider_type", None)

        model = getattr(self._agent, "model", None)
        if not isinstance(model, str):
            return None

        capability_registry = get_capability_registry()
        if isinstance(provider_name, str):
            resolved = capability_registry.resolve(model, provider_name)
            if resolved is not None:
                return resolved

        prefixed_provider_name: str | None = None
        normalized_model = model
        if ":" in model:
            prefixed_provider_name, normalized_model = model.split(":", 1)
        resolved_provider_name = (
            provider_name if isinstance(provider_name, str) else prefixed_provider_name
        )
        return capability_registry.resolve(normalized_model, resolved_provider_name)

    def _prepare_execution_kwargs(
        self, kwargs: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        execution_kwargs = dict(kwargs)
        explicit_profile = cast(
            CapabilityProfileProtocol | None,
            execution_kwargs.pop("capability_profile", None),
        )
        if explicit_profile is None:
            explicit_profile = cast(
                CapabilityProfileProtocol | None,
                execution_kwargs.pop("provider_capability_profile", None),
            )
        # Every caller-supplied kwarg the agent receives is governed. The request
        # shape attach_response_format injects is generated from the constitution
        # itself (its schema names the rules' own terms), so it is not caller content.
        governance_kwargs = dict(execution_kwargs)

        if self.validate_output:
            capability_profile = self._resolve_capability_profile(explicit_profile)
            execution_kwargs = attach_response_format(
                execution_kwargs,
                self.constitution,
                capability_profile,
            )
        return execution_kwargs, governance_kwargs

    def _enforce_payloads(
        self, *values: Any, agent_id: str, context: dict[str, Any] | None = None
    ) -> None:
        """Deny unless every value projects in full and the engine returns ``valid is True``.

        Same contract as GovernedCallable: JSON-native values only, never truncated
        (oversize and non-JSON values raise :class:`GovernancePayloadError`), and a
        blocking verdict denies whatever ``strict`` is set to.
        """
        for payload in governance_payloads_for_enforcement(*values):
            _deny_unless_valid(
                self.engine.validate(payload, agent_id=agent_id, context=context),
                action=payload,
            )

    def _validate_invocation(
        self, input: str, governance_kwargs: dict[str, Any], context: dict[str, Any]
    ) -> None:
        """Validate the input and the caller's kwargs before the agent runs."""
        self._enforce_payloads(input, agent_id=self.agent_id, context=context)
        if governance_kwargs:
            self._enforce_payloads(governance_kwargs, agent_id=f"{self.agent_id}:kwargs")

    def _validate_output(self, result: Any) -> None:
        """Validate agent output against constitution. Raises on violation."""
        if not self.validate_output:
            return
        self._enforce_payloads(
            result, agent_id=f"{self.agent_id}:output", context={"source": "agent_output"}
        )

    def run(self, input: str, *, governance_action: str | None = None, **kwargs: Any) -> Any:
        """Run the wrapped agent with governance.

        1. Enforce MACI role boundaries by default
        2. Validate the primary input and the caller's keyword arguments
        3. Execute the agent
        4. Validate the output (if enabled)
        5. On an output rule violation with ``max_retries > 0``, re-invoke the
           agent with a remediation prompt (up to ``max_retries`` times); an
           oversize or non-JSON output denies without a retry
        6. Return result with audit trail

        Raises:
            ConstitutionalViolationError: If input/output violates rules
                after all retries are exhausted, whatever ``strict`` is set to.
            GovernancePayloadError: If the input, a keyword argument or the
                output is oversize or not JSON-native (a
                ``ConstitutionalViolationError`` subclass).
            GovernanceHaltError: If the circuit breaker is tripped.
        """
        # Step 0: Check circuit breaker (Article 14 kill-switch)
        if self._circuit_breaker is not None:
            self._circuit_breaker.check()

        # Step 1: Enforce MACI boundary before any wrapped side effect
        self._check_maci(governance_action)
        execution_kwargs, governance_kwargs = self._prepare_execution_kwargs(kwargs)

        # Step 2: Validate input (no retries for input violations)
        context = dict(governance_kwargs)
        if governance_action is not None:
            context["governance_action"] = governance_action
        self._validate_invocation(input, governance_kwargs, context)

        # Step 3: Execute agent
        result = self._execute_agent(input, **execution_kwargs)

        # Step 4: Validate output with retry loop
        last_error: ConstitutionalViolationError | None = None
        for attempt in range(1, self.max_retries + 2):  # 1-indexed, includes original
            try:
                self._validate_output(result)
                self._emit_cdp(input, verdict="allow", context=context)
                return result
            except ConstitutionalViolationError as exc:
                last_error = exc
                retries_remaining = self.max_retries - attempt + 1
                # Oversize or non-JSON output is a shape error a re-prompt cannot be
                # relied on to fix, so it denies without re-invoking the agent.
                if retries_remaining <= 0 or isinstance(exc, GovernancePayloadError):
                    self._emit_cdp(
                        input,
                        verdict="deny",
                        context=context,
                        violated_rules=[exc.rule_id or "UNKNOWN"],
                        risk_score=1.0,
                    )
                    raise
                # Audit the retry attempt
                self.audit_log.record(
                    AuditEntry(
                        id=f"retry-{self.agent_id}-{attempt}-{uuid.uuid4().hex[:8]}",
                        type="output_retry",
                        agent_id=self.agent_id,
                        action=f"retry:output_violation:{attempt}",
                        valid=False,
                        violations=[exc.rule_id or "UNKNOWN"],
                        constitutional_hash=self.engine._const_hash,
                        metadata={
                            "attempt": attempt,
                            "retries_after_this": retries_remaining - 1,
                            "rule_id": exc.rule_id,
                        },
                    )
                )
                retry_prompt = self._build_retry_prompt(input, exc, attempt)
                result = self._execute_agent(retry_prompt, **execution_kwargs)

        # Should not reach here, but fail-closed
        if last_error is not None:
            raise last_error
        return result

    def _emit_cdp(
        self,
        raw_input: str,
        *,
        verdict: str = "allow",
        context: dict[str, Any] | None = None,
        matched_rules: list[str] | None = None,
        violated_rules: list[str] | None = None,
        compliance_frameworks: list[str] | None = None,
        risk_score: float = 0.0,
    ) -> None:
        """Assemble and persist a CDP record if CDP is enabled (post-decision, AD-6)."""
        if not os.getenv("ACGS_CDP_ENABLED") and self._cdp_backend is None:
            return

        _halt_error: Exception | None = None
        try:
            from acgs_lite.cdp.assembler import assemble_cdp_record

            backend = self._cdp_backend
            if backend is None:
                # Lazy import of default global backend from server module
                try:
                    from acgs_lite.server import _cdp_backend as _server_backend

                    backend = _server_backend
                except Exception as exc:
                    _log.debug(
                        "cdp: server backend unavailable (%s); falling back to in-memory",
                        type(exc).__name__,
                    )
                    from acgs_lite.cdp.store import InMemoryCDPBackend

                    backend = InMemoryCDPBackend()

            audit_entries = list(self.audit_log._entries)
            action = (context or {}).get("governance_action", "")

            # Run compliance checker to derive runtime obligations (Phase 2)
            obligations: list[Any] = []
            effective_verdict = verdict
            try:
                from acgs_lite.compliance.runtime_checker import RuntimeComplianceChecker

                checker = RuntimeComplianceChecker()
                decision_context: dict[str, Any] = {
                    "verdict": verdict,
                    "risk_score": risk_score,
                    "matched_rules": list(matched_rules or []),
                    "violated_rules": list(violated_rules or []),
                    "compliance_frameworks": list(compliance_frameworks or []),
                    "human_approval": (context or {}).get("human_approval"),
                    "domain": (context or {}).get("domain", ""),
                }
                obligations = checker.check(decision_context)
                # If blocking obligations are unsatisfied, escalate verdict to conditional
                blocking_unsatisfied = [o for o in obligations if o.is_blocking and not o.satisfied]
                if blocking_unsatisfied and effective_verdict == "allow":
                    effective_verdict = "conditional"
            except Exception as exc:
                # Compliance check failure must not affect CDP emission, but it must be observable.
                _log.error(
                    "cdp: runtime compliance check failed (%s); continuing without obligations",
                    type(exc).__name__,
                    exc_info=True,
                )

            record = assemble_cdp_record(
                raw_input=raw_input,
                agent_id=self.agent_id,
                constitutional_hash=self.engine._const_hash,
                verdict=effective_verdict,
                action=str(action),
                matched_rules=list(matched_rules or []),
                violated_rules=violated_rules or [],
                risk_score=risk_score,
                compliance_frameworks=list(compliance_frameworks or []),
                runtime_obligations=obligations,
                audit_entries=audit_entries,
            )
            backend.save(record)

            # Phase 5: Run intervention engine if configured (post-CDP, AD-6)
            if self._intervention_engine is not None:
                from acgs_lite.circuit_breaker import GovernanceHaltError as _GHE

                try:
                    self._intervention_engine.evaluate(record.to_dict())
                except _GHE as exc:
                    _halt_error = exc  # Defer re-raise past the outer except
                except Exception as exc:
                    # All other handler failures are non-fatal, but must be observable.
                    _log.error(
                        "cdp: intervention handler failed (%s); continuing",
                        type(exc).__name__,
                        exc_info=True,
                    )
        except Exception as exc:
            # CDP emission must never fail the governed call (fail-open for observability)
            # but the failure must be observable in logs.
            _log.error(
                "cdp: emission failed (%s); governed call continues without CDP record",
                type(exc).__name__,
                exc_info=True,
            )

        # Re-raise BLOCK halt outside the CDP fail-open guard so it reaches the caller
        if _halt_error is not None:
            raise _halt_error

    async def _aexecute_agent(self, input: str, **kwargs: Any) -> Any:
        """Execute the underlying agent (async)."""
        if hasattr(self._agent, "arun"):
            return await self._agent.arun(input, **kwargs)
        elif hasattr(self._agent, "run"):
            if inspect.iscoroutinefunction(self._agent.run):
                return await self._agent.run(input, **kwargs)
            else:
                return await asyncio.to_thread(self._agent.run, input, **kwargs)
        elif callable(self._agent):
            if inspect.iscoroutinefunction(self._agent):
                return await self._agent(input, **kwargs)
            else:
                return await asyncio.to_thread(self._agent, input, **kwargs)
        else:
            raise GovernanceError(
                f"Agent of type {type(self._agent).__name__} is not callable",
                rule_id="AGENT-PROTOCOL",
            )

    async def arun(
        self,
        input: str,
        *,
        governance_action: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Async version of run() with output-violation retry support."""
        # Step 1: Enforce MACI boundary before any wrapped side effect
        self._check_maci(governance_action)
        execution_kwargs, governance_kwargs = self._prepare_execution_kwargs(kwargs)

        # Step 2: Validate input (no retries for input violations)
        context = dict(governance_kwargs)
        if governance_action is not None:
            context["governance_action"] = governance_action
        self._validate_invocation(input, governance_kwargs, context)

        # Step 3: Execute agent
        result = await self._aexecute_agent(input, **execution_kwargs)

        # Step 4: Validate output with retry loop
        last_error: ConstitutionalViolationError | None = None
        for attempt in range(1, self.max_retries + 2):
            try:
                self._validate_output(result)
                return result
            except ConstitutionalViolationError as exc:
                last_error = exc
                retries_remaining = self.max_retries - attempt + 1
                # Oversize or non-JSON output is a shape error a re-prompt cannot be
                # relied on to fix, so it denies without re-invoking the agent.
                if retries_remaining <= 0 or isinstance(exc, GovernancePayloadError):
                    raise
                self.audit_log.record(
                    AuditEntry(
                        id=f"retry-{self.agent_id}-{attempt}-{uuid.uuid4().hex[:8]}",
                        type="output_retry",
                        agent_id=self.agent_id,
                        action=f"retry:output_violation:{attempt}",
                        valid=False,
                        violations=[exc.rule_id or "UNKNOWN"],
                        constitutional_hash=self.engine._const_hash,
                        metadata={
                            "attempt": attempt,
                            "retries_after_this": retries_remaining - 1,
                            "rule_id": exc.rule_id,
                        },
                    )
                )
                retry_prompt = self._build_retry_prompt(input, exc, attempt)
                result = await self._aexecute_agent(retry_prompt, **execution_kwargs)

        if last_error is not None:
            raise last_error
        return result

    @property
    def stats(self) -> dict[str, Any]:
        """Return governance statistics."""
        return {
            **self.engine.stats,
            "agent_id": self.agent_id,
            "audit_chain_valid": self.audit_log.verify_chain(),
        }

    def __repr__(self) -> str:
        return (
            f"GovernedAgent(agent={type(self._agent).__name__}, "
            f"agent_id={self.agent_id!r}, "
            f"rules={len(self.constitution)}, "
            f"maci_role={self.maci_role.value if self.maci_role else None!r}, "
            f"enforce_maci={self.enforce_maci})"
        )


def _enforce_z3_gate(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    policies: list[Any],
    *,
    audit_log: AuditLog,
    agent_id: str,
    require_durable_audit: bool = False,
) -> None:
    """Run the Z3 boundary check and raise unless the call is cleared.

    Shared by the sync and async wrappers. It lives here as one function rather
    than twice inline because two copies of an enforcement rule is two places for
    it to drift, and only one of them would be noticed.

    Order matters and is deliberate:

    1. verify — always, even for an exempt callable, so an exemption can never
       hide a policy that *does* apply and *does* fail;
    2. block/allow on :func:`blocks_execution`, the single enforcement rule;
    3. only for ``INAPPLICABLE``, consider an exemption;
    4. record the exemption to the audit log **before** returning, so the call
       cannot proceed on an unrecorded exemption.

    :raises ConstitutionalViolationError: on any status the gate does not clear.
    """
    from acgs_lite.formal.exemption import active_exemption
    from acgs_lite.z3_verify import (
        VerificationStatus,
        blocks_execution,
        verify_callable_arguments,
    )

    runtime_res = verify_callable_arguments(func, args, kwargs, policies)
    if not blocks_execution(runtime_res):
        return

    if runtime_res.status is VerificationStatus.FAIL:
        raise ConstitutionalViolationError(
            f"Action violates mathematical constraints: {runtime_res.counterexample}",
            rule_id="Z3-CONSTRAINT-VIOLATION",
        )

    exemption_error: str | None = None
    if runtime_res.status is VerificationStatus.INAPPLICABLE:
        # The ONLY status an exemption can clear. A proven violation is handled
        # above; a malformed policy, a missing solver, a timeout, and a crashed
        # solver all fall through to the raise below regardless of any exemption.
        exemption, exemption_error = active_exemption(func)
        if exemption is not None:
            entry = AuditEntry(
                id=str(uuid.uuid4()),
                type="verification_exemption",
                agent_id=agent_id,
                action=getattr(func, "__name__", "<callable>"),
                # Not a clean pass: execution proceeded without verification.
                # Recorded as invalid so "where did we run unverified" is a
                # query over the audit trail, not an investigation.
                valid=False,
                violations=["Z3-VERIFICATION-INAPPLICABLE"],
                metadata={
                    "verification_status": runtime_res.status.value,
                    **exemption.to_audit_metadata(),
                },
            )
            if require_durable_audit:
                audit_log.record_durable(entry)
            else:
                audit_log.record_atomic(entry)
            return

    detail = (
        f"Z3 verification could not clear this call [{runtime_res.status.value}]: "
        f"{runtime_res.error}"
    )
    if exemption_error is not None:
        detail = f"{detail} (no usable exemption: {exemption_error})"
    raise ConstitutionalViolationError(detail, rule_id="Z3-CONSTRAINT-VIOLATION")


class GovernedCallable:
    """Decorator to govern any function.

    Usage::

        from acgs_lite import GovernedCallable, Constitution

        constitution = Constitution.default()

        @GovernedCallable(constitution)
        def process_data(input: str) -> str:
            return f"Processed: {input}"

        result = process_data("safe input")  # Works
        result = process_data("self-validate bypass")  # Raises!
    """

    def __init__(
        self,
        constitution: Constitution | None = None,
        *,
        agent_id: str = "callable",
        strict: bool = True,
        authorization_profile: AuthorizationProfile | str | None = None,
        trusted_issuer_keys: Mapping[str, str] | None = None,
        audit_log: AuditLog | None = None,
        require_durable_audit: bool = False,
        require_durable_execution: bool = False,
        require_restart_recovery: bool = False,
        trusted_execution_context: TrustedExecutionContext | None = None,
        require_trusted_context: bool = False,
        receipt_signer: ReceiptSigner | None = None,
        trusted_execution_keys: Mapping[str, str] | None = None,
        grant_ttl_seconds: float | None = None,
    ) -> None:
        """Construct the governed-callable decorator.

        The production profile requires ``receipt_signer``: a non-ephemeral Ed25519
        signer whose public key is pinned in ``trusted_execution_keys``
        (``key_id -> public key hex``). "Non-ephemeral" is detected only for
        ``Ed25519ReceiptSigner.generate()`` keys; that the key and its pin are
        provisioned out of band is the operator's responsibility and is not
        verified. A pinned key authorizes execution only of the exact receipt this
        instance issued and signed with it; ``trusted_issuer_keys`` never does.
        Every production grant is signed with execution scope and expires after
        ``grant_ttl_seconds`` (default 300); expiry blocks new attempts, not
        recovery of an attempt already recorded for the grant. The signing
        arguments are refused outside the production profile.
        """
        self.constitution = constitution or Constitution.default()
        self.agent_id = agent_id
        self.audit_log = audit_log if audit_log is not None else AuditLog()
        self.engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict,
            audit_mode="full",
        )
        self.authorization_profile = resolve_profile(authorization_profile)
        if self.authorization_profile is AuthorizationProfile.PRODUCTION and not strict:
            raise LegitimacyInvariantError("production profile requires strict engine")
        self.trusted_issuer_keys = dict(trusted_issuer_keys or {})
        self.trusted_execution_keys = dict(trusted_execution_keys or {})
        self.receipt_signer = receipt_signer
        self.grant_ttl_seconds = (
            DEFAULT_SIGNED_GRANT_TTL_SECONDS if grant_ttl_seconds is None else grant_ttl_seconds
        )
        # Production grant id -> what was issued and signed for it. Process-local, like
        # the ledger: a signed receipt executes only on the instance that issued it.
        # Weak callable refs, so the issuer never keeps an abandoned grant's target alive.
        self._signed_grants: dict[str, _IssuedSignedGrant] = {}
        # Grant ids between registry verification and ledger consume; never pruned.
        self._signed_grants_reserved: dict[str, int] = {}
        self._signed_grants_lock = threading.Lock()
        self._authority = ExecutionAuthority()
        self._ledger = InProcessGrantLedger()
        # Serialize terminal ledger/audit confirmation with replay visibility.
        self._completion_lock = threading.Lock()
        self._execution_disabled = False
        self._wrapped_targets: weakref.WeakKeyDictionary[Callable[..., Any], Callable[..., Any]] = (
            weakref.WeakKeyDictionary()
        )
        self.require_durable_audit = require_durable_audit
        self.trusted_execution_context = trusted_execution_context
        self.require_trusted_context = require_trusted_context
        if self.authorization_profile is not AuthorizationProfile.PRODUCTION and (
            trusted_execution_context is not None
            or require_trusted_context
            or require_durable_audit
        ):
            raise LegitimacyInvariantError(
                "trusted context and durable audit requirements require the production profile"
            )
        if require_trusted_context and trusted_execution_context is None:
            raise LegitimacyInvariantError("required trusted execution context is missing")
        if require_durable_execution:
            raise LegitimacyInvariantError(
                "production durable execution ledger is not supported by the in-process ledger"
            )
        if require_restart_recovery:
            raise LegitimacyInvariantError(
                "production restart recovery is not supported by the in-process ledger"
            )
        if require_durable_audit:
            contract = self.audit_log.invariant_contract()
            if not (contract.durable and contract.supports_fail_closed_persistence):
                raise LegitimacyInvariantError(
                    "required durable audit confirmation needs a supported durable backend"
                )
        if self.authorization_profile is AuthorizationProfile.PRODUCTION:
            self._require_production_signer()
        elif (
            receipt_signer is not None
            or trusted_execution_keys is not None
            or grant_ttl_seconds is not None
        ):
            raise LegitimacyInvariantError(
                "receipt signing and execution key pins require the production profile"
            )

    def _require_production_signer(self) -> None:
        """Refuse production construction without a pinned, non-ephemeral Ed25519 key."""
        signer = self.receipt_signer
        if signer is None:
            raise LegitimacyInvariantError("production profile requires an Ed25519 receipt signer")
        if not isinstance(signer, ReceiptSigner) or signer.algorithm != SIGNATURE_ALGORITHM:
            raise LegitimacyInvariantError("production receipt signer must be Ed25519")
        if getattr(signer, "ephemeral", False):
            raise LegitimacyInvariantError(
                "production receipt signer must not use an ephemeral per-process key"
            )
        pinned = self.trusted_execution_keys.get(signer.key_id)
        public_key = signer.public_key_hex()
        if not (
            isinstance(pinned, str)
            and isinstance(public_key, str)
            and pinned.isascii()
            and public_key.isascii()
            and hmac.compare_digest(pinned, public_key)
        ):
            raise LegitimacyInvariantError(
                "production receipt signer key must be pinned in trusted_execution_keys"
            )
        ttl = self.grant_ttl_seconds
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl):
            raise LegitimacyInvariantError("grant_ttl_seconds must be a positive finite number")
        if ttl <= 0:
            raise LegitimacyInvariantError("grant_ttl_seconds must be a positive finite number")

    def issue_grant(
        self, target: Callable[..., Any], /, *args: Any, **kwargs: Any
    ) -> ExecutionGrant:
        """Mint a same-instance grant after constitutional validation.

        Never invokes ``target``. Refuses a caller-created receipt so a forged
        ALLOW cannot be wrapped into a capability.
        """
        return self._issue_grant(self._wrapped_targets.get(target, target), *args, **kwargs)

    def _issue_grant(
        self, func: Callable[..., Any], /, *args: Any, **kwargs: Any
    ) -> ExecutionGrant:
        if self._execution_disabled:
            raise LegitimacyInvariantError("execution disabled after uncertain terminal failure")
        """Bind the exact executed callable; never unwrap user wrappers."""
        if "receipt" in kwargs or "decision_receipt" in kwargs or "acgs_receipt" in kwargs:
            raise TypeError("issue_grant refuses caller-created receipts")
        if self.require_durable_audit:
            self.audit_log.validate_durable_state()
        tokens = extract_authorization_kwargs(kwargs)
        if any(tokens.get(name) is not None for name in tokens):
            raise TypeError("issue_grant refuses authorization transport kwargs")
        self._reject_production_receiver(func, args, kwargs)
        decision = self._evaluate_invocation(func, args, kwargs)
        invocation = bind_invocation(
            func,
            args,
            kwargs,
            include_receiver=self.authorization_profile is AuthorizationProfile.PRODUCTION,
            strict_context=self.authorization_profile is AuthorizationProfile.PRODUCTION,
        )
        context_digest = self._trusted_context_digest(invocation)
        policy = bind_policy(self.constitution)
        signer = (
            self.receipt_signer
            if self.authorization_profile is AuthorizationProfile.PRODUCTION
            else None
        )
        expires_at: str | None = None
        deadline: float | None = None
        if signer is not None:
            deadline = time.monotonic() + self.grant_ttl_seconds
            expires_at = (
                datetime.now(timezone.utc) + timedelta(seconds=self.grant_ttl_seconds)
            ).isoformat()
        grant_id = self._authority.allocate_grant_id()
        try:
            receipt = build_issue_receipt(
                func=func,
                invocation=invocation,
                policy=policy,
                decision=decision,
                grant_id=grant_id,
                context_digest=context_digest,
                expires_at=expires_at,
            )
            signed: SignedReceipt | None = None
            if signer is not None:
                # Sign before issue so a signing failure never leaves an unsigned grant.
                signed = sign_execution_authorization(
                    receipt,
                    signer,
                    authorization_json=authorization_envelope_json(
                        invocation,
                        policy,
                        grant_id=grant_id,
                        context_digest=context_digest,
                        expires_at=expires_at,
                    ),
                )
            grant = self._authority.issue(
                receipt=receipt,
                invocation=invocation,
                policy=policy,
                expires_at=expires_at,
                single_use=True,
                context_digest=context_digest,
                callable_target=func,
                grant_id=grant_id,
                signed_receipt=signed,
            )
        finally:
            # No-op once issued; otherwise the allocation never outlives this call.
            self._authority.release_grant_id(grant_id)
        if deadline is not None and signer is not None:
            self._register_signed_grant(
                grant_id,
                _IssuedSignedGrant(
                    deadline=deadline,
                    func_ref=weakref.ref(func),
                    receipt_hash=receipt.receipt_hash,
                    key_id=signer.key_id,
                    public_key=signer.public_key_hex(),
                ),
            )
        return grant

    def _register_signed_grant(self, grant_id: str, issued: _IssuedSignedGrant) -> None:
        now = time.monotonic()
        with self._signed_grants_lock:
            for stale in [
                gid
                for gid, entry in self._signed_grants.items()
                if gid not in self._signed_grants_reserved and self._prunable(entry, gid, now)
            ]:
                del self._signed_grants[stale]
            self._signed_grants[grant_id] = issued

    def _prunable(self, entry: _IssuedSignedGrant, grant_id: str, now: float) -> bool:
        """Whether a registry entry can be dropped without losing anything executable.

        Never-consumed: once expired it can never execute. Consumed: kept while the
        attempt runs, then for one more ``grant_ttl_seconds`` after the later of
        expiry and settlement, so a slow attempt's recorded result stays
        recoverable. Dropping it only refuses recovery; the ledger still refuses any
        reuse, so no replay window opens.
        """
        if entry.deadline >= now:
            return False
        status = self._ledger.attempt_status_for_grant(grant_id)
        if status is None:
            return True
        if status is AttemptStatus.STARTED:
            return False
        settled_at = self._ledger.settled_at_for_grant(grant_id)
        retained_from = entry.deadline if settled_at is None else max(entry.deadline, settled_at)
        # No replay after prune only because InProcessGrantLedger never prunes consumed
        # attempts; if ledger pruning is ever added, revisit this.
        return retained_from + self.grant_ttl_seconds < now

    def _reserve_signed_grant(self, grant_id: str) -> None:
        with self._signed_grants_lock:
            self._signed_grants_reserved[grant_id] = (
                self._signed_grants_reserved.get(grant_id, 0) + 1
            )

    def _release_signed_grant(self, grant_id: str) -> None:
        with self._signed_grants_lock:
            remaining = self._signed_grants_reserved.get(grant_id, 0) - 1
            if remaining > 0:
                self._signed_grants_reserved[grant_id] = remaining
            else:
                self._signed_grants_reserved.pop(grant_id, None)

    def _is_recorded_attempt(self, carrier: object, attempt_id: object) -> bool:
        """True only for a retry of the attempt the ledger already bound to this grant.

        Such a retry performs no new side effect, so grant expiry does not block it;
        every other check still runs.
        """
        grant_id = _carrier_grant_id(carrier)
        if grant_id is None or not isinstance(attempt_id, str) or not attempt_id:
            return False
        return self._ledger.attempt_for_grant(grant_id) == attempt_id

    def _trusted_context_digest(self, invocation: InvocationBinding) -> str | None:
        context = self.trusted_execution_context
        if context is None:
            if self.require_trusted_context:
                raise LegitimacyInvariantError("required trusted execution context is missing")
            return None
        context.authorize(invocation)
        return context.digest

    def _reject_production_receiver(
        self, func: Callable[..., Any], args: tuple[Any, ...], kwargs: Mapping[str, Any]
    ) -> None:
        """Refuse receiver methods until their exact instance can be grant-bound."""
        if self.authorization_profile is not AuthorizationProfile.PRODUCTION:
            return
        receiver_method = inspect.ismethod(func) and func.__self__ is not None
        bound = _bound_arguments(func, args, kwargs, include_receiver=True)
        if bound:
            first = args[0] if args else next(iter(bound.values()))
            owner = first if inspect.isclass(first) else type(first)
            # Inspect actual MRO dictionaries without invoking descriptors. Names
            # need not match __name__: a class may alias an existing function.
            for base in owner.__mro__:
                for descriptor in vars(base).values():
                    if isinstance(descriptor, staticmethod):
                        continue
                    if isinstance(descriptor, classmethod):
                        descriptor = descriptor.__func__
                    if inspect.isfunction(descriptor):
                        receiver_method = (
                            receiver_method
                            or self._wrapped_targets.get(descriptor, descriptor) is func
                        )
        if receiver_method:
            raise LegitimacyInvariantError(
                "production grants do not support receiver methods without exact instance binding"
            )

    def _evaluate_invocation(
        self, func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> EngineDecision:
        """Evaluate every governed payload and return the engine's aggregated verdict.

        The per-call ``strict=False`` override returns review and block verdicts as
        values so the issue path maps them itself; HALT still raises from the engine.
        Only ALLOW and ALLOW_WITH_CONTROLS are mintable. Parameter defaults the call
        relies on are evaluated after the call arguments, since the digest commits them.
        """
        payloads = governance_payloads_for_enforcement(*args, kwargs)
        payloads += governance_payloads_for_enforcement(
            *defaulted_argument_values(func, args, kwargs)
        )
        results = [
            self.engine.validate(payload, agent_id=self.agent_id, strict=False)
            for payload in payloads
        ]
        decision = engine_decision_from_results(results)
        if decision.decision_type not in ("ALLOW", "ALLOW_WITH_CONTROLS"):
            raise ConstitutionalViolationError(
                f"constitution decision {decision.decision_type} does not permit a grant"
                f" ({decision.rationale})",
                rule_id=decision.primary_rule_id or "EXECUTION-GRANT-DENIED",
                action=payloads[0][:200] if payloads else "",
            )
        return decision

    def _gate(
        self, func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> tuple[ConsumeDecision | None, str]:
        """Authorize the call; return the ledger outcome and the bound argument digest."""
        if self.require_durable_audit:
            self.audit_log.validate_durable_state()
        tokens = extract_authorization_kwargs(kwargs)
        production = self.authorization_profile is AuthorizationProfile.PRODUCTION
        if production:
            self._reject_production_receiver(func, args, kwargs)
            reject_method_spoof_kwargs(func, kwargs)
        invocation = bind_invocation(
            func, args, kwargs, include_receiver=production, strict_context=production
        )
        context_digest = self._trusted_context_digest(invocation) if production else None
        policy = bind_policy(self.constitution)
        grant = tokens.get("execution_grant") or tokens.get("acgs_grant")
        signed = tokens.get("signed_receipt")
        grant_id = tokens.get("grant_id")
        receipt = tokens.get("decision_receipt") or tokens.get("acgs_receipt")

        if production:
            if grant_id is not None:
                raise LegitimacyInvariantError(
                    "grant id is not executable until a ledger is configured"
                )
            if grant is None and signed is None:
                raise LegitimacyInvariantError("unsigned receipt is not executable")
            if tokens.get("human_approval") is not None:
                raise LegitimacyInvariantError("raw human_approval is not executable in production")
            attempt_id = tokens.get("execution_attempt_id")
            # Expiry blocks new executions only. Recovering the attempt already recorded
            # for this grant runs no side effect, so it is allowed after expiry.
            enforce_expiry = not self._is_recorded_attempt(
                grant if grant is not None else signed, attempt_id
            )
            # Reserve before verification reads the registry, so a concurrent issue
            # cannot prune the entry between the deadline check and the ledger consume.
            reserved_id = _carrier_grant_id(grant if grant is not None else signed)
            if reserved_id is not None:
                self._reserve_signed_grant(reserved_id)
            try:
                if grant is not None:
                    if not isinstance(grant, ExecutionGrant):
                        raise LegitimacyInvariantError("Invalid execution grant type")
                    self._authority.verify(
                        grant,
                        invocation=invocation,
                        policy=policy,
                        context_digest=context_digest,
                        enforce_expiry=enforce_expiry,
                    )
                    if grant.callable_target is not func:
                        raise LegitimacyInvariantError("grant callable identity mismatch")
                    if not grant.single_use:
                        raise LegitimacyInvariantError(
                            "production execution requires a single-use grant"
                        )
                    if grant.signed_receipt is None:
                        raise LegitimacyInvariantError(
                            "production grant carries no execution signature"
                        )
                    if not isinstance(grant.signed_receipt, SignedReceipt) or (
                        grant.signed_receipt.receipt.receipt_hash != grant.receipt.receipt_hash
                    ):
                        raise LegitimacyInvariantError(
                            "grant execution signature does not sign the grant receipt"
                        )
                    signed = grant.signed_receipt
                verified_receipt = self._verify_signed_production(
                    signed, invocation, policy, context_digest, func, enforce_expiry
                )
                self._enforce_receipt(
                    verified_receipt,
                    func=func,
                    args=args,
                    kwargs=kwargs,
                    human_approval=None,
                    trust_kwargs=False,
                    enforce_expiry=enforce_expiry,
                )
                return (
                    self._consume_and_audit(
                        verified_receipt,
                        attempt_id=attempt_id,
                        invocation=invocation,
                        policy=policy,
                        context_digest=context_digest,
                    ),
                    invocation.argument_digest,
                )
            finally:
                if reserved_id is not None:
                    self._release_signed_grant(reserved_id)

        if grant is not None:
            if not isinstance(grant, ExecutionGrant):
                raise LegitimacyInvariantError("Invalid execution grant type")
            self._authority.verify(grant, invocation=invocation, policy=policy)
            self._enforce_receipt(
                grant.receipt,
                func=func,
                args=args,
                kwargs=kwargs,
                human_approval=tokens.get("human_approval"),
                trust_kwargs=False,
            )
            return None, invocation.argument_digest
        self._enforce_receipt(
            receipt,
            func=func,
            args=args,
            kwargs=kwargs,
            human_approval=tokens.get("human_approval"),
            trust_kwargs=True,
        )
        return None, invocation.argument_digest

    def _enforce_receipt(
        self,
        receipt: DecisionReceipt | None,
        *,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        human_approval: dict[str, Any] | None,
        trust_kwargs: bool,
        enforce_expiry: bool = True,
    ) -> None:
        actual_call = normalize_actual_call(
            fallback_method=func.__name__,
            args=args,
            kwargs=kwargs,
            func=func,
            trust_kwargs=trust_kwargs,
            strict_context=self.authorization_profile is AuthorizationProfile.PRODUCTION,
        )
        validate_receipt_for_execution(
            receipt,
            actual_call=actual_call,
            human_approval=human_approval,
            audit_log=self.audit_log,
            enforce_expiry=enforce_expiry,
        )

    def _recovered_result(self, outcome: ConsumeDecision | None) -> Any:
        if outcome is None or outcome.mode == "proceed":
            return _PROCEED
        if outcome.record.status is AttemptStatus.COMPLETED:
            recovered_digest = digest_output(outcome.result)
            if (
                recovered_digest is None
                or outcome.record.output_sha256 is None
                or recovered_digest != outcome.record.output_sha256
            ):
                self._ledger.mark_unknown(
                    attempt_id=outcome.record.attempt_id,
                    error_code="recovered_result_mismatch",
                )
                raise LegitimacyInvariantError(
                    "stored side-effect result is unknown; recovery integrity check failed"
                )
            return outcome.result
        raise LegitimacyInvariantError(f"attempt already {outcome.record.status.value}")

    def _finalize_attempt(
        self,
        outcome: ConsumeDecision | None,
        status: AttemptStatus,
        *,
        result: Any = None,
        error_code: str | None = None,
        output_sha256: str | None = None,
    ) -> None:
        if outcome is None:
            return
        self._ledger.finalize(
            attempt_id=outcome.record.attempt_id,
            status=status,
            result=result,
            error_code=error_code,
            output_sha256=output_sha256 if status is AttemptStatus.COMPLETED else None,
        )

    def _finalize_completed(self, outcome: ConsumeDecision | None, result: Any) -> None:
        """Commit success, exposing unknown outcome if terminal evidence cannot be stored."""
        try:
            with self._completion_lock:
                self._commit_completed(outcome, result)
        except Exception:
            raise
        except BaseException:
            # KeyboardInterrupt, SystemExit or GeneratorExit while committing: the side
            # effect ran, so an attempt still STARTED is settled PARTIAL. The ledger's
            # first terminal write wins, so this is a no-op once the attempt settled.
            try:
                self._finalize_attempt(outcome, AttemptStatus.PARTIAL, error_code="interrupted")
            except Exception:
                self._execution_disabled = True
            raise

    def _commit_completed(self, outcome: ConsumeDecision | None, result: Any) -> None:
        """Keep replay excluded until both terminal confirmations have succeeded."""
        ledger_write_started = False
        try:
            output_digest = digest_output(result)
            if outcome is not None and output_digest is None:
                raise LegitimacyInvariantError("side-effect result cannot be digested")
            ledger_write_started = True
            self._finalize_attempt(
                outcome, AttemptStatus.COMPLETED, result=result, output_sha256=output_digest
            )
            if self.require_durable_audit and outcome is not None:
                self.audit_log.record_durable(
                    AuditEntry(
                        id=f"execution-completed-{outcome.record.attempt_id}",
                        type="execution_completed",
                        agent_id=self.agent_id,
                        action=outcome.record.method_id,
                        valid=True,
                        metadata={
                            "attempt_id": outcome.record.attempt_id,
                            "grant_id": outcome.record.grant_id,
                            "output_sha256": output_digest,
                        },
                    )
                )
        except Exception as exc:
            try:
                if outcome is not None:
                    self._ledger.mark_unknown(
                        attempt_id=outcome.record.attempt_id,
                        error_code="terminal_commit_failed",
                    )
            except Exception:
                # Preserve the original terminal failure and still raise unknown;
                # failure to update local evidence cannot establish completion.
                self._execution_disabled = True
            raise LegitimacyInvariantError(
                "side effect may have completed but terminal result is unknown"
            ) from exc
        except BaseException:
            # Interrupted once the ledger write began but before the durable audit
            # entry confirmed it: replay must not trust a COMPLETED record, so it is
            # replaced with PARTIAL. Without durable audit the ledger write is the
            # commit; an attempt still STARTED is settled by _finalize_completed.
            if ledger_write_started and self.require_durable_audit and outcome is not None:
                try:
                    self._ledger.mark_unknown(
                        attempt_id=outcome.record.attempt_id, error_code="interrupted"
                    )
                except Exception:
                    self._execution_disabled = True
            raise

    def _consume_and_audit(
        self,
        receipt: DecisionReceipt,
        *,
        attempt_id: object,
        invocation: InvocationBinding,
        policy: PolicyBinding,
        context_digest: str | None,
    ) -> ConsumeDecision:
        """Single-use consume of a verified production receipt, then durable audit."""
        grant_id = receipt.grant_id
        if not isinstance(grant_id, str) or not grant_id:
            raise LegitimacyInvariantError("verified receipt carries no grant id")
        if attempt_id is None:
            attempt_id = uuid.uuid4().hex
        if not isinstance(attempt_id, str) or not attempt_id:
            raise LegitimacyInvariantError("execution_attempt_id must be a non-empty string")
        with self._completion_lock:
            if self._execution_disabled:
                raise LegitimacyInvariantError(
                    "execution disabled after uncertain terminal failure"
                )
            outcome = self._ledger.consume(
                grant_id=grant_id,
                attempt_id=attempt_id,
                receipt_hash=receipt.receipt_hash,
                invocation=invocation,
                policy=policy,
                context_digest=context_digest,
            )
        if self.require_durable_audit and outcome.mode == "proceed":
            try:
                self.audit_log.record_durable(
                    AuditEntry(
                        id=f"execution-authorized-{outcome.record.attempt_id}",
                        type="execution_authorized",
                        agent_id=self.agent_id,
                        action=invocation.method_id,
                        valid=True,
                        constitutional_hash=policy.version,
                        metadata={
                            "attempt_id": outcome.record.attempt_id,
                            "grant_id": grant_id,
                            "receipt_hash": receipt.receipt_hash,
                            "policy_digest": policy.digest,
                            "argument_digest": invocation.argument_digest,
                            "trusted_context_digest": context_digest,
                        },
                    )
                )
            except Exception:
                self._ledger.finalize(
                    attempt_id=outcome.record.attempt_id,
                    status=AttemptStatus.FAILED,
                    error_code="audit_persistence_failed",
                )
                raise
        return outcome

    def _verify_signed_production(
        self,
        signed: object,
        invocation: InvocationBinding,
        policy: PolicyBinding,
        context_digest: str | None,
        func: Callable[..., Any],
        enforce_expiry: bool = True,
    ) -> DecisionReceipt:
        """Verify an execution-scope Ed25519 signature against the live invocation.

        Every production execution passes through here (grant and ``signed_receipt``
        branches alike). Each failure raises; the caller then consumes the ledger,
        which makes the receipt single use. Only the exact receipt this instance
        issued, signed by the key that issued it, executes, so the in-process
        ledger's single-use guarantee covers it. ``enforce_expiry=False`` (recovery
        of an already-recorded attempt only) skips the two clock comparisons and
        nothing else.
        """
        if not isinstance(signed, SignedReceipt):
            raise LegitimacyInvariantError("Invalid signed receipt type")
        if signed.signature_scope != SIGNATURE_SCOPE_EXECUTION:
            raise LegitimacyInvariantError("unsigned receipt is not executable")
        if signed.algorithm != SIGNATURE_ALGORITHM:
            raise LegitimacyInvariantError("execution signature must be Ed25519")
        if not signed.authorization_json:
            raise LegitimacyInvariantError(
                "execution signature is missing an authorization envelope"
            )
        pinned = (
            self.trusted_execution_keys.get(signed.key_id)
            if isinstance(signed.key_id, str)
            else None
        )
        if pinned is None:
            raise LegitimacyInvariantError("signed receipt key is not pinned for execution")
        try:
            authentic = signed.verify(pinned)
        except (TypeError, ValueError):
            authentic = False
        if not authentic:
            raise LegitimacyInvariantError("signed receipt authenticity check failed")
        receipt = signed.receipt
        if receipt.schema_version != RECEIPT_SCHEMA_V2:
            raise LegitimacyInvariantError("only v2 receipts are executable in production")
        try:
            decision_type = canonicalize_decision_state(receipt.decision_type)
        except ValueError as exc:
            raise LegitimacyInvariantError("Unknown decision type is not allow") from exc
        if decision_type not in ("ALLOW", "ALLOW_WITH_CONTROLS"):
            raise LegitimacyInvariantError(f"Decision {decision_type} does not permit execution")
        envelope = parse_authorization_envelope(signed.authorization_json)
        expires_at = envelope.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at:
            raise LegitimacyInvariantError("execution signature has no expiry")
        if receipt.execution_boundary.expires_at != expires_at:
            raise LegitimacyInvariantError("execution signature expiry does not match receipt")
        try:
            expires = datetime.fromisoformat(expires_at)
        except ValueError as exc:
            raise LegitimacyInvariantError("execution signature expiry is not parseable") from exc
        if expires.tzinfo is None:
            raise LegitimacyInvariantError("execution signature expiry must carry a timezone")
        if enforce_expiry and datetime.now(timezone.utc) > expires:
            raise LegitimacyInvariantError("execution signature has expired")
        if (
            envelope.get("context_digest") != context_digest
            or receipt.context_digest != context_digest
        ):
            raise LegitimacyInvariantError("trusted execution context binding mismatch")
        grant_id = envelope.get("grant_id")
        if not isinstance(grant_id, str) or not grant_id or grant_id != receipt.grant_id:
            raise LegitimacyInvariantError("grant id does not match receipt")
        if (
            envelope.get("method_id") != invocation.method_id
            or receipt.method_id != invocation.method_id
        ):
            raise LegitimacyInvariantError("grant method identity mismatch")
        if (
            envelope.get("argument_digest") != invocation.argument_digest
            or receipt.argument_digest != invocation.argument_digest
        ):
            raise LegitimacyInvariantError("invocation binding mismatch")
        if envelope.get("policy_digest") != policy.digest or receipt.policy_digest != policy.digest:
            raise LegitimacyInvariantError("policy binding mismatch")
        boundary = receipt.execution_boundary
        if envelope.get("scope") != invocation.scope or boundary.allowed_scope != invocation.scope:
            raise LegitimacyInvariantError("invocation scope mismatch")
        if envelope.get("subjects") != list(invocation.subjects) or tuple(
            boundary.allowed_subjects
        ) != tuple(invocation.subjects):
            raise LegitimacyInvariantError("invocation subjects mismatch")
        with self._signed_grants_lock:
            issued = self._signed_grants.get(grant_id)
        if issued is None:
            raise LegitimacyInvariantError(
                "signed receipt was not issued by this governed callable"
            )
        # Monotonic deadline: a wall-clock rollback cannot extend the grant lifetime.
        if enforce_expiry and time.monotonic() > issued.deadline:
            raise LegitimacyInvariantError("execution signature monotonic deadline has expired")
        if issued.func_ref() is not func:
            raise LegitimacyInvariantError("grant callable identity mismatch")
        if signed.key_id != issued.key_id or pinned != issued.public_key:
            raise LegitimacyInvariantError("signed receipt key did not issue this grant")
        if receipt.receipt_hash != issued.receipt_hash:
            raise LegitimacyInvariantError(
                "signed receipt is not the receipt issued for this grant"
            )
        return receipt

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        engine = self.engine
        agent_id = self.agent_id

        # SMT / Z3 integration
        from acgs_lite.formal.policy_ast import PolicyParseError, parse_policy_source
        from acgs_lite.z3_verify import (
            VerificationStatus,
            _extract_z3_policies,
            verify_callable_safety,
        )

        audit_log = self.audit_log
        # Same binding option _gate passes to bind_invocation.
        include_receiver = self.authorization_profile is AuthorizationProfile.PRODUCTION

        # Extracted unconditionally, NOT gated on Z3_AVAILABLE. If the constitution
        # carries policies, the fact that no solver is installed to check them must
        # reach the enforcement gate as UNAVAILABLE -> block, rather than silently
        # producing an empty policy list that disables the whole layer.
        policies = _extract_z3_policies(self.constitution)

        # A policy that cannot be parsed is a broken control. Reject it when the
        # constitution is wired up rather than skipping it with a WARNING at each
        # call, which is how enforcement used to disappear.
        for policy in policies:
            if isinstance(policy, str):
                try:
                    parse_policy_source(policy)
                except PolicyParseError as exc:
                    raise ConstitutionalViolationError(
                        f"Constitution contains an invalid Z3 policy: {exc}",
                        rule_id="Z3-POLICY-MALFORMED",
                    ) from exc

        if policies:
            # Perform static boundary checks. Advisory only; the runtime gate below
            # is the enforcing one.
            static_res = verify_callable_safety(func, policies)
            # `status is FAIL`, not the old `verified and not satisfiable` -- that
            # expression is the fail-open predicate this change removes, and a live
            # copy of it is how it gets reintroduced later.
            if static_res.status is VerificationStatus.FAIL:
                _log.warning(
                    "Static verification warning for function '%s': "
                    "Possible constitutional violation detected in input space boundaries! "
                    "Counterexample: %s",
                    func.__name__,
                    static_res.counterexample,
                )

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                outcome, bound_digest = self._gate(func, args, kwargs)
                recovered = self._recovered_result(outcome)
                if recovered is not _PROCEED:
                    return recovered

                execution_started = False
                try:
                    # Fail-closed: only a completed check that found no violation
                    # clears the call. Missing solver, malformed policy, timeout,
                    # exception, and "no policy applies here" all block. See
                    # _enforce_z3_gate for the exemption path.
                    if policies:
                        _enforce_z3_gate(
                            func,
                            args,
                            kwargs,
                            policies,
                            audit_log=audit_log,
                            agent_id=agent_id,
                            require_durable_audit=self.require_durable_audit,
                        )

                    for payload in governance_payloads_for_enforcement(*args, kwargs):
                        _deny_unless_valid(
                            engine.validate(payload, agent_id=agent_id), action=payload
                        )
                    # Defaults are digested into the binding, so they are evaluated too.
                    for payload in governance_payloads_for_enforcement(
                        *defaulted_argument_values(func, args, kwargs)
                    ):
                        _deny_unless_valid(
                            engine.validate(payload, agent_id=agent_id), action=payload
                        )
                    # The checks above ran on the arguments as bound at the gate. A
                    # list/dict argument mutated since then (another thread, a hook
                    # inside validation) would run unchecked content, so re-digest.
                    if (
                        canonical_argument_digest(
                            func, args, kwargs, include_receiver=include_receiver
                        )
                        != bound_digest
                    ):
                        raise LegitimacyInvariantError(
                            "invocation binding mismatch: arguments changed after authorization"
                        )
                    execution_started = True
                    result = await func(*args, **kwargs)
                    for output_payload in governance_payloads_for_enforcement(result):
                        _deny_unless_valid(
                            engine.validate(output_payload, agent_id=f"{agent_id}:output"),
                            action=output_payload,
                        )
                except asyncio.CancelledError:
                    self._finalize_attempt(
                        outcome,
                        AttemptStatus.CANCELLED,
                        error_code="cancelled",
                    )
                    raise
                except Exception:
                    status = AttemptStatus.PARTIAL if execution_started else AttemptStatus.FAILED
                    self._finalize_attempt(outcome, status, error_code="exception")
                    raise
                except BaseException:
                    # GeneratorExit (coroutine closed mid-await), KeyboardInterrupt,
                    # SystemExit: settle the attempt so it is not left STARTED forever.
                    status = AttemptStatus.PARTIAL if execution_started else AttemptStatus.FAILED
                    self._finalize_attempt(outcome, status, error_code="interrupted")
                    raise
                self._finalize_completed(outcome, result)
                return result

            async_wrapper.issue_grant = (  # type: ignore[attr-defined]
                lambda *grant_args, **grant_kwargs: self._issue_grant(
                    func, *grant_args, **grant_kwargs
                )
            )
            self._wrapped_targets[async_wrapper] = func
            return cast(Callable[..., T], async_wrapper)
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                outcome, bound_digest = self._gate(func, args, kwargs)
                recovered = self._recovered_result(outcome)
                if recovered is not _PROCEED:
                    return recovered

                execution_started = False
                try:
                    # Fail-closed: only a completed check that found no violation
                    # clears the call. Missing solver, malformed policy, timeout,
                    # exception, and "no policy applies here" all block. See
                    # _enforce_z3_gate for the exemption path.
                    if policies:
                        _enforce_z3_gate(
                            func,
                            args,
                            kwargs,
                            policies,
                            audit_log=audit_log,
                            agent_id=agent_id,
                            require_durable_audit=self.require_durable_audit,
                        )

                    for payload in governance_payloads_for_enforcement(*args, kwargs):
                        _deny_unless_valid(
                            engine.validate(payload, agent_id=agent_id), action=payload
                        )
                    # Defaults are digested into the binding, so they are evaluated too.
                    for payload in governance_payloads_for_enforcement(
                        *defaulted_argument_values(func, args, kwargs)
                    ):
                        _deny_unless_valid(
                            engine.validate(payload, agent_id=agent_id), action=payload
                        )
                    # The checks above ran on the arguments as bound at the gate. A
                    # list/dict argument mutated since then (another thread, a hook
                    # inside validation) would run unchecked content, so re-digest.
                    if (
                        canonical_argument_digest(
                            func, args, kwargs, include_receiver=include_receiver
                        )
                        != bound_digest
                    ):
                        raise LegitimacyInvariantError(
                            "invocation binding mismatch: arguments changed after authorization"
                        )
                    execution_started = True
                    result = func(*args, **kwargs)
                    for output_payload in governance_payloads_for_enforcement(result):
                        _deny_unless_valid(
                            engine.validate(output_payload, agent_id=f"{agent_id}:output"),
                            action=output_payload,
                        )
                except Exception:
                    status = AttemptStatus.PARTIAL if execution_started else AttemptStatus.FAILED
                    self._finalize_attempt(outcome, status, error_code="exception")
                    raise
                except BaseException:
                    # KeyboardInterrupt, SystemExit: settle the attempt so it is not
                    # left STARTED forever.
                    status = AttemptStatus.PARTIAL if execution_started else AttemptStatus.FAILED
                    self._finalize_attempt(outcome, status, error_code="interrupted")
                    raise
                self._finalize_completed(outcome, result)
                return result

            sync_wrapper.issue_grant = (  # type: ignore[attr-defined]
                lambda *grant_args, **grant_kwargs: self._issue_grant(
                    func, *grant_args, **grant_kwargs
                )
            )
            self._wrapped_targets[sync_wrapper] = func
            return cast(Callable[..., T], sync_wrapper)
