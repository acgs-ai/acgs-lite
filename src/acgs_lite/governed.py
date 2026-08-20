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
import inspect
import logging
import os
import uuid
import warnings
from collections.abc import Callable, Mapping
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
    ExecutionAuthority,
    ExecutionGrant,
    authorization_envelope_json,
    build_issue_receipt,
    extract_authorization_kwargs,
    parse_authorization_envelope,
    resolve_profile,
)
from acgs_lite.legitimacy.invariants import (
    LegitimacyInvariantError,
    normalize_actual_call,
    validate_receipt_for_execution,
)
from acgs_lite.legitimacy.invocation import (
    InvocationBinding,
    PolicyBinding,
    bind_invocation,
    bind_policy,
    reject_method_spoof_kwargs,
)
from acgs_lite.legitimacy.ledger import (
    AttemptStatus,
    ConsumeDecision,
    InProcessGrantLedger,
    digest_output,
)
from acgs_lite.legitimacy.receipt import DecisionReceipt
from acgs_lite.legitimacy.signing import (
    SIGNATURE_SCOPE_EXECUTION,
    SignedReceipt,
)
from acgs_lite.maci import MACIEnforcer, MACIRole
from acgs_lite.provider_capabilities import (
    CapabilityStability,
    CapabilitySupportLevel,
    RequestShape,
    get_capability_registry,
)
from acgs_lite.serialization import iter_governance_payloads, serialize_for_governance

T = TypeVar("T")
_PROCEED = object()


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

    Validates inputs and outputs against the constitution. Structured outputs
    and keyword arguments are normalized before validation. Produces full audit
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

        if self.validate_output:
            capability_profile = self._resolve_capability_profile(explicit_profile)
            execution_kwargs = attach_response_format(
                execution_kwargs,
                self.constitution,
                capability_profile,
            )

        governance_kwargs = {
            key: value for key, value in execution_kwargs.items() if key != "response_format"
        }
        return execution_kwargs, governance_kwargs

    def _validate_output(self, result: Any) -> None:
        """Validate agent output against constitution. Raises on violation."""
        if not self.validate_output:
            return
        output_payload = serialize_for_governance(result)
        if output_payload:
            self.engine.validate(
                output_payload,
                agent_id=f"{self.agent_id}:output",
                context={"source": "agent_output"},
            )

    def run(self, input: str, *, governance_action: str | None = None, **kwargs: Any) -> Any:
        """Run the wrapped agent with governance.

        1. Enforce MACI role boundaries by default
        2. Validate the primary input and serialized keyword arguments
        3. Execute the agent
        4. Validate serialized output (if enabled)
        5. On output violation with ``max_retries > 0``, re-invoke the agent
           with a remediation prompt (up to ``max_retries`` times)
        6. Return result with audit trail

        Raises:
            ConstitutionalViolationError: If input/output violates rules
                after all retries are exhausted.
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
        self.engine.validate(input, agent_id=self.agent_id, context=context)
        kwargs_payload = serialize_for_governance(governance_kwargs)
        if kwargs_payload:
            self.engine.validate(kwargs_payload, agent_id=f"{self.agent_id}:kwargs")

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
                if retries_remaining <= 0:
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
        self.engine.validate(input, agent_id=self.agent_id, context=context)
        kwargs_payload = serialize_for_governance(governance_kwargs)
        if kwargs_payload:
            self.engine.validate(kwargs_payload, agent_id=f"{self.agent_id}:kwargs")

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
                if retries_remaining <= 0:
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
            audit_log.record_atomic(
                AuditEntry(
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
            )
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
    ) -> None:
        self.constitution = constitution or Constitution.default()
        self.agent_id = agent_id
        self.audit_log = AuditLog()
        self.engine = GovernanceEngine(
            self.constitution,
            audit_log=self.audit_log,
            strict=strict,
            audit_mode="full",
        )
        self.authorization_profile = resolve_profile(authorization_profile)
        self.trusted_issuer_keys = dict(trusted_issuer_keys or {})
        self._authority = ExecutionAuthority()
        self._ledger = InProcessGrantLedger()

    def issue_grant(
        self, target: Callable[..., Any], /, *args: Any, **kwargs: Any
    ) -> ExecutionGrant:
        """Mint a same-instance grant after constitutional validation.

        Never invokes ``target``. Refuses a caller-created receipt so a forged
        ALLOW cannot be wrapped into a capability.
        """
        if "receipt" in kwargs or "decision_receipt" in kwargs or "acgs_receipt" in kwargs:
            raise TypeError("issue_grant refuses caller-created receipts")
        func = inspect.unwrap(target)
        tokens = extract_authorization_kwargs(kwargs)
        if any(tokens.get(name) is not None for name in tokens):
            raise TypeError("issue_grant refuses authorization transport kwargs")
        self._validate_payloads(func, args, kwargs, invoke_denied=True)
        invocation = bind_invocation(func, args, kwargs)
        policy = bind_policy(self.constitution)
        receipt = build_issue_receipt(func=func, invocation=invocation, policy=policy)
        return self._authority.issue(
            receipt=receipt,
            invocation=invocation,
            policy=policy,
            single_use=True,
        )

    def _validate_payloads(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        invoke_denied: bool,
    ) -> None:
        del func, invoke_denied
        for payload in iter_governance_payloads(*args, kwargs):
            result = self.engine.validate(payload, agent_id=self.agent_id)
            if not getattr(result, "valid", True):
                raise ConstitutionalViolationError(
                    "constitution denied the invocation",
                    rule_id="EXECUTION-GRANT-DENIED",
                    action=str(payload),
                )

    def _gate(
        self, func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> ConsumeDecision | None:
        tokens = extract_authorization_kwargs(kwargs)
        production = self.authorization_profile is AuthorizationProfile.PRODUCTION
        if production:
            reject_method_spoof_kwargs(func, kwargs)
        invocation = bind_invocation(func, args, kwargs)
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
            verified_receipt: DecisionReceipt | None = None
            if grant is not None:
                if not isinstance(grant, ExecutionGrant):
                    raise LegitimacyInvariantError("Invalid execution grant type")
                self._authority.verify(grant, invocation=invocation, policy=policy)
                verified_receipt = grant.receipt
            else:
                verified_receipt = self._verify_signed_production(signed, invocation, policy)
            self._enforce_receipt(
                verified_receipt,
                func=func,
                args=args,
                kwargs=kwargs,
                human_approval=None,
                trust_kwargs=False,
            )
            if isinstance(grant, ExecutionGrant) and grant.single_use:
                attempt_id = tokens.get("execution_attempt_id") or uuid.uuid4().hex
                if not isinstance(attempt_id, str) or not attempt_id:
                    raise LegitimacyInvariantError(
                        "execution_attempt_id must be a non-empty string"
                    )
                return self._ledger.consume(
                    grant_id=grant.grant_id,
                    attempt_id=attempt_id,
                    receipt_hash=grant.receipt.receipt_hash,
                    invocation=invocation,
                    policy=policy,
                )
            return None

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
            return None
        self._enforce_receipt(
            receipt,
            func=func,
            args=args,
            kwargs=kwargs,
            human_approval=tokens.get("human_approval"),
            trust_kwargs=True,
        )
        return None

    def _enforce_receipt(
        self,
        receipt: DecisionReceipt | None,
        *,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        human_approval: dict[str, Any] | None,
        trust_kwargs: bool,
    ) -> None:
        actual_call = normalize_actual_call(
            fallback_method=func.__name__,
            args=args,
            kwargs=kwargs,
            func=func,
            trust_kwargs=trust_kwargs,
        )
        validate_receipt_for_execution(
            receipt,
            actual_call=actual_call,
            human_approval=human_approval,
            audit_log=self.audit_log,
        )

    def _recovered_result(self, outcome: ConsumeDecision | None) -> Any:
        if outcome is None or outcome.mode == "proceed":
            return _PROCEED
        if outcome.record.status is AttemptStatus.COMPLETED:
            return outcome.result
        raise LegitimacyInvariantError(f"attempt already {outcome.record.status.value}")

    def _finalize_attempt(
        self,
        outcome: ConsumeDecision | None,
        status: AttemptStatus,
        *,
        result: Any = None,
        error_code: str | None = None,
    ) -> None:
        if outcome is None:
            return
        self._ledger.finalize(
            attempt_id=outcome.record.attempt_id,
            status=status,
            result=result,
            error_code=error_code,
            output_sha256=digest_output(result) if status is AttemptStatus.COMPLETED else None,
        )

    def _verify_signed_production(
        self,
        signed: object,
        invocation: InvocationBinding,
        policy: PolicyBinding,
    ) -> DecisionReceipt:
        if not isinstance(signed, SignedReceipt):
            raise LegitimacyInvariantError("Invalid signed receipt type")
        if signed.signature_scope != SIGNATURE_SCOPE_EXECUTION:
            raise LegitimacyInvariantError("unsigned receipt is not executable")
        if not signed.authorization_json:
            raise LegitimacyInvariantError(
                "execution signature is missing an authorization envelope"
            )
        expected = self.trusted_issuer_keys.get(signed.key_id)
        if expected is None:
            raise LegitimacyInvariantError("signed receipt key is not pinned")
        if not signed.verify(expected):
            raise LegitimacyInvariantError("signed receipt authenticity check failed")
        envelope = parse_authorization_envelope(signed.authorization_json)
        expected_json = authorization_envelope_json(invocation, policy)
        expected_envelope = parse_authorization_envelope(expected_json)
        if envelope.get("argument_digest") != expected_envelope["argument_digest"]:
            raise LegitimacyInvariantError("invocation binding mismatch")
        if envelope.get("method_id") != expected_envelope["method_id"]:
            raise LegitimacyInvariantError("grant method identity mismatch")
        if envelope.get("policy_digest") != expected_envelope["policy_digest"]:
            raise LegitimacyInvariantError("policy binding mismatch")
        if envelope.get("scope") != expected_envelope["scope"]:
            raise LegitimacyInvariantError("invocation scope mismatch")
        if envelope.get("subjects") != expected_envelope["subjects"]:
            raise LegitimacyInvariantError("invocation subjects mismatch")
        return signed.receipt

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
                outcome = self._gate(func, args, kwargs)
                recovered = self._recovered_result(outcome)
                if recovered is not _PROCEED:
                    return recovered

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
                        )

                    for payload in iter_governance_payloads(*args, kwargs):
                        engine.validate(payload, agent_id=agent_id)
                    result = await func(*args, **kwargs)
                    output_payload = serialize_for_governance(result)
                    if output_payload:
                        engine.validate(output_payload, agent_id=f"{agent_id}:output")
                except Exception:
                    self._finalize_attempt(outcome, AttemptStatus.FAILED, error_code="exception")
                    raise
                self._finalize_attempt(outcome, AttemptStatus.COMPLETED, result=result)
                return result

            async_wrapper.issue_grant = (  # type: ignore[attr-defined]
                lambda *grant_args, **grant_kwargs: self.issue_grant(
                    func, *grant_args, **grant_kwargs
                )
            )
            return cast(Callable[..., T], async_wrapper)
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                outcome = self._gate(func, args, kwargs)
                recovered = self._recovered_result(outcome)
                if recovered is not _PROCEED:
                    return recovered

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
                        )

                    for payload in iter_governance_payloads(*args, kwargs):
                        engine.validate(payload, agent_id=agent_id)
                    result = func(*args, **kwargs)
                    output_payload = serialize_for_governance(result)
                    if output_payload:
                        engine.validate(output_payload, agent_id=f"{agent_id}:output")
                except Exception:
                    self._finalize_attempt(outcome, AttemptStatus.FAILED, error_code="exception")
                    raise
                self._finalize_attempt(outcome, AttemptStatus.COMPLETED, result=result)
                return result

            sync_wrapper.issue_grant = (  # type: ignore[attr-defined]
                lambda *grant_args, **grant_kwargs: self.issue_grant(
                    func, *grant_args, **grant_kwargs
                )
            )
            return cast(Callable[..., T], sync_wrapper)
