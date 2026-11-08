"""Cedar-style policy decision point (PDP).

Semantics, in order:

1. The non-overridable :data:`CONSTITUTION_INVARIANTS` are evaluated first,
   always, whatever policy set is loaded.
2. Any satisfied forbid (invariant or policy) -> DENY.
3. Otherwise any satisfied permit -> PERMIT.
4. Otherwise -> DENY (default deny).

An error while evaluating *any* statement denies the whole decision. Cedar
skips an erroring policy instead; that is unsafe here because a forbid that
errors would silently stop forbidding, which turns an exception into an
allow. Unparseable input, a missing policy set, a missing constitution
binding, a stale expected constitution hash and an evaluation timeout also
deny. Every decision carries ``constitution_hash`` and ``policy_digest``
(from :func:`acgs_lite.legitimacy.invocation.bind_policy`; the digest is the
real "policy unchanged" proof because ``Constitution.hash`` omits patterns,
``enabled`` and conditions).

Receipts (Phase 2): with ``receipt_ledger=`` the PDP binds that
:class:`~acgs_lite.control_plane.receipt_ledger.ReceiptLedger` (one PDP per
ledger, via a private capability) and appends a receipt for every decision it
publishes. Publishing is private: no public method accepts a caller-built
:class:`Decision` except :meth:`PolicyDecisionPoint.record_denial`, which can
only record a deny. Unlike best-effort ``listeners``, a receipt failure on an
allow withdraws the allow; on a deny it increments
:attr:`PolicyDecisionPoint.receipt_failures` and is audited best-effort.
"""

from __future__ import annotations

import collections
import concurrent.futures
import logging
import math
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.control_plane.context import DecisionContext, DecisionRequest
from acgs_lite.control_plane.immutable_core import DEFAULT_IMMUTABLE_CORE, ImmutableCoreRegistry
from acgs_lite.control_plane.invariants import CONSTITUTION_INVARIANTS, core_category_for
from acgs_lite.control_plane.policy import (
    PolicyEffect,
    PolicyParseError,
    PolicySet,
    PolicyStatement,
)
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.receipts import ORIGIN_DISPATCHER_PRE_DENIAL, ORIGIN_PDP
from acgs_lite.control_plane.tiers import ActionTier
from acgs_lite.fail_closed import fail_closed
from acgs_lite.legitimacy.invocation import bind_policy

if TYPE_CHECKING:
    from acgs_lite.control_plane.receipt_ledger import ReceiptLedger

__all__ = [
    "DEFAULT_TIMEOUT_S",
    "Decision",
    "PolicyDecisionPoint",
    "PolicyEffect",
    "PolicyParseError",
    "PolicySet",
    "PolicyStatement",
]

logger = logging.getLogger(__name__)

# TODO(control-plane-gap): 250 ms is a design inference (declarative
# statements evaluate in microseconds; the bound only exists to stop a hung
# Python condition from stalling a decision). No primary evidence for the
# value; it is configurable per PDP.
DEFAULT_TIMEOUT_S = 0.25
DEFAULT_MAX_WORKERS = 4
DEFAULT_PRE_DENIAL_RECEIPT_LIMIT = 100
DEFAULT_PRE_DENIAL_WINDOW_S = 60.0
_MAX_TRACKED_PRE_DENIAL_KEYS = 4096


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Decision:
    """Outcome of one PDP evaluation. ``allowed`` is the only gate bit."""

    allowed: bool
    reason: str
    determining_policies: tuple[str, ...]
    constitution_hash: str
    policy_digest: str
    inputs_digest: str
    decided_at: str
    principal_id: str
    action: str
    resource: str
    tier: ActionTier | None
    error: str | None = None
    policy_set_digest: str = ""
    decision_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    """Opaque id, recorded in the audit entry; safe to show to an agent."""

    @classmethod
    def denied(
        cls,
        reason: str,
        *,
        constitution_hash: str = "",
        policy_digest: str = "",
        inputs_digest: str = "",
        principal_id: str = "",
        action: str = "",
        resource: str = "",
        tier: ActionTier | None = None,
        determining_policies: tuple[str, ...] = (),
        error: str | None = None,
        policy_set_digest: str = "",
    ) -> Decision:
        return cls(
            allowed=False,
            reason=reason,
            determining_policies=determining_policies,
            constitution_hash=constitution_hash,
            policy_digest=policy_digest,
            inputs_digest=inputs_digest,
            decided_at=_now(),
            principal_id=principal_id,
            action=action,
            resource=resource,
            tier=tier,
            error=error,
            policy_set_digest=policy_set_digest,
        )

    def with_id(self, decision_id: str) -> Decision:
        return replace(self, decision_id=decision_id)


# Returned by the @fail_closed backstop when something outside the explicit
# handling raised. It deliberately carries no hashes: it is not a decision
# about any particular request.
_BACKSTOP_DENY = Decision(
    allowed=False,
    reason="fail-closed: unexpected error in decision path",
    determining_policies=(),
    constitution_hash="",
    policy_digest="",
    inputs_digest="",
    decided_at="",
    principal_id="",
    action="",
    resource="",
    tier=None,
    error="fail_closed",
)


class _StatementError(Exception):
    def __init__(self, statement_id: str, cause: BaseException) -> None:
        # Only the exception *type*: messages can carry secrets or paths.
        super().__init__(f"{statement_id}: {type(cause).__name__}")
        self.statement_id = statement_id


def _evaluate_statements(
    statements: Sequence[PolicyStatement], ctx: DecisionContext
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    forbids: list[str] = []
    permits: list[str] = []
    for statement in statements:
        try:
            matched = statement.matches(ctx)
        except Exception as exc:
            raise _StatementError(statement.id, exc) from exc
        if matched:
            (forbids if statement.effect is PolicyEffect.FORBID else permits).append(statement.id)
    return tuple(forbids), tuple(permits)


def _validate_request(request: DecisionRequest) -> str | None:
    principal = request.principal
    if not isinstance(principal, Principal) or not isinstance(principal.kind, PrincipalKind):
        return "principal must be a Principal"
    if not isinstance(principal.id, str) or not principal.id.strip():
        return "principal id must be a non-empty string"
    if not isinstance(request.action, str) or not request.action.strip():
        return "action must be a non-empty string"
    if not isinstance(request.resource, str) or not request.resource:
        return "resource must be a non-empty string"
    if not isinstance(request.tier, ActionTier):
        return "tier must be an ActionTier"
    if not isinstance(request.approvers, tuple) or not all(
        isinstance(approver, Principal) for approver in request.approvers
    ):
        return "approvers must be a tuple of Principal"
    if not isinstance(request.attributes, Mapping) or not all(
        isinstance(key, str) for key in request.attributes
    ):
        return "attributes must be a mapping with string keys"
    if request.expected_constitution_hash is not None and not isinstance(
        request.expected_constitution_hash, str
    ):
        return "expected_constitution_hash must be a string or None"
    return None


class PolicyDecisionPoint:
    """Evaluate :class:`DecisionRequest` objects against invariants + policy."""

    def __init__(
        self,
        policy_set: PolicySet | None,
        *,
        constitution_hash: str,
        policy_digest: str,
        registry: ImmutableCoreRegistry = DEFAULT_IMMUTABLE_CORE,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        audit_log: AuditLog | None = None,
        durable_audit: bool = False,
        listeners: Sequence[Callable[[Decision], None]] = (),
        max_workers: int = DEFAULT_MAX_WORKERS,
        receipt_ledger: ReceiptLedger | None = None,
        pre_denial_receipt_limit: int | None = DEFAULT_PRE_DENIAL_RECEIPT_LIMIT,
        pre_denial_window_s: float = DEFAULT_PRE_DENIAL_WINDOW_S,
    ) -> None:
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
            raise ValueError("timeout_s must be a number")
        if not math.isfinite(timeout_s) or timeout_s <= 0:
            raise ValueError("timeout_s must be a positive finite number")
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        if not isinstance(registry, ImmutableCoreRegistry):
            raise ValueError("registry must be an ImmutableCoreRegistry")
        if durable_audit and audit_log is None:
            # Otherwise every allow would go out unrecorded although
            # durability was explicitly requested.
            raise ValueError("durable_audit=True requires an audit_log")
        if pre_denial_receipt_limit is not None and (
            isinstance(pre_denial_receipt_limit, bool)
            or not isinstance(pre_denial_receipt_limit, int)
            or pre_denial_receipt_limit < 1
        ):
            raise ValueError("pre_denial_receipt_limit must be None or an int >= 1")
        if not math.isfinite(pre_denial_window_s) or pre_denial_window_s <= 0:
            raise ValueError("pre_denial_window_s must be a positive finite number")
        self._receipt_ledger: ReceiptLedger | None = None
        # The ledger token is held only by this closure, never as an attribute.
        self._append_receipt: Callable[[Decision, DecisionRequest | None, str], object] | None
        self._append_receipt = None
        if receipt_ledger is not None:
            from acgs_lite.control_plane import receipt_ledger as ledger_module

            # Exact type: a subclass could intercept the capability token.
            if type(receipt_ledger) is not ledger_module.ReceiptLedger:
                raise ValueError("receipt_ledger must be a ReceiptLedger")
            token = receipt_ledger.bind_decision_source(ledger_module._PDP_BINDING)
            bound = receipt_ledger

            def append_receipt(
                decision: Decision, request: DecisionRequest | None, origin: str
            ) -> object:
                return bound.append_decision(decision, request, capability=token, origin=origin)

            self._append_receipt = append_receipt
            self._receipt_ledger = receipt_ledger
        self._receipt_failures = 0
        self._suppressed_denial_receipts = 0
        self._receipt_failures_lock = threading.Lock()
        self._pre_denial_limit = pre_denial_receipt_limit
        self._pre_denial_window_s = float(pre_denial_window_s)
        self._pre_denials: dict[str, collections.deque[float]] = {}
        self._policy_set = policy_set
        self._constitution_hash = constitution_hash if isinstance(constitution_hash, str) else ""
        self._policy_digest = policy_digest if isinstance(policy_digest, str) else ""
        self._registry = registry
        self._timeout_s = float(timeout_s)
        self._audit_log = audit_log
        self._durable_audit = durable_audit
        self._listeners = tuple(listeners)
        self._max_workers = max_workers
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._executor_lock = threading.Lock()

    @classmethod
    def for_constitution(
        cls, constitution: Any, policy_set: PolicySet | None, **kwargs: Any
    ) -> PolicyDecisionPoint:
        """Bind to *constitution* via :func:`bind_policy` (hash + full digest)."""
        binding = bind_policy(constitution)
        return cls(
            policy_set,
            constitution_hash=binding.version,
            policy_digest=binding.digest,
            **kwargs,
        )

    @property
    def constitution_hash(self) -> str:
        return self._constitution_hash

    @property
    def policy_digest(self) -> str:
        return self._policy_digest

    @property
    def registry(self) -> ImmutableCoreRegistry:
        return self._registry

    @property
    def timeout_s(self) -> float:
        return self._timeout_s

    @property
    def receipt_ledger(self) -> ReceiptLedger | None:
        return self._receipt_ledger

    @property
    def receipt_failures(self) -> int:
        """Count of receipt emissions that failed (allow or deny)."""
        with self._receipt_failures_lock:
            return self._receipt_failures

    @property
    def suppressed_denial_receipts(self) -> int:
        """Pre-denials that were denied but not receipted (rate limit)."""
        with self._receipt_failures_lock:
            return self._suppressed_denial_receipts

    def __repr__(self) -> str:
        return (
            f"PolicyDecisionPoint(constitution_hash={self._constitution_hash!r}, "
            f"receipts={'bound' if self._receipt_ledger is not None else 'none'})"
        )

    def __copy__(self) -> PolicyDecisionPoint:
        raise TypeError("PolicyDecisionPoint cannot be copied")

    def __deepcopy__(self, memo: object) -> PolicyDecisionPoint:
        raise TypeError("PolicyDecisionPoint cannot be copied")

    def close(self) -> None:
        with self._executor_lock:
            if self._executor is not None:
                self._executor.shutdown(wait=False, cancel_futures=True)
                self._executor = None

    def __enter__(self) -> PolicyDecisionPoint:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def decide(self, request: object) -> Decision:
        """Evaluate *request*; never raises, never fails open."""
        decision = self._decide(request)
        if decision.error == "fail_closed":
            # The backstop is a shared constant; give each occurrence its own id.
            decision = replace(decision, decision_id=uuid.uuid4().hex, decided_at=_now())
        return self._publish(decision, request if isinstance(request, DecisionRequest) else None)

    def record_denial(
        self,
        reason: str,
        *,
        principal_id: str = "",
        action: str = "",
        resource: str = "",
        error: str = "dispatch_denied",
    ) -> Decision:
        """Publish (audit, receipt, listeners) a deny decided outside the PDP,
        e.g. a dispatcher pre-check. It can only ever record a deny.

        Its receipt has origin ``dispatcher_pre_denial`` and no principal
        kind (the principal was never validated). Per principal id at most
        ``pre_denial_receipt_limit`` such receipts are written per window;
        beyond that the call still denies but is only counted
        (:attr:`suppressed_denial_receipts`).
        """
        decision = Decision.denied(
            reason,
            constitution_hash=self._constitution_hash,
            policy_digest=self._policy_digest,
            principal_id=principal_id,
            action=action,
            resource=resource,
            error=error,
        )
        receipted = self._pre_denial_within_limit(principal_id)
        if not receipted:
            with self._receipt_failures_lock:
                self._suppressed_denial_receipts += 1
        return self._publish(decision, None, origin=ORIGIN_DISPATCHER_PRE_DENIAL, receipt=receipted)

    def _pre_denial_within_limit(self, principal_id: str) -> bool:
        # TODO(control-plane-gap): the pre-denial receipt rate limit (count,
        # window, keyed by the unvalidated principal id) is design inference.
        limit = self._pre_denial_limit
        if limit is None:
            return True
        now = time.monotonic()
        horizon = now - self._pre_denial_window_s
        with self._receipt_failures_lock:
            if (
                principal_id not in self._pre_denials
                and len(self._pre_denials) >= _MAX_TRACKED_PRE_DENIAL_KEYS
            ):
                for key in [k for k, q in self._pre_denials.items() if not q or q[-1] < horizon]:
                    del self._pre_denials[key]
                if len(self._pre_denials) >= _MAX_TRACKED_PRE_DENIAL_KEYS:
                    # Unvalidated labels are attacker-chosen: at capacity a new
                    # label gets no receipt budget (the call still denies and
                    # is counted), so the map and the prune scan stay bounded.
                    return False
            window = self._pre_denials.setdefault(principal_id, collections.deque())
            while window and window[0] < horizon:
                window.popleft()
            if len(window) >= limit:
                return False
            window.append(now)
            return True

    def _publish(
        self,
        decision: Decision,
        request: DecisionRequest | None,
        *,
        origin: str = ORIGIN_PDP,
        receipt: bool = True,
    ) -> Decision:
        """Audit, emit a receipt and notify listeners. None of them can turn a
        deny into an allow; an allow whose audit write or receipt emission
        fails becomes a deny (and that deny is audited and receipted)."""
        try:
            decision = self._audit(decision)
        except Exception as exc:  # pragma: no cover - _audit handles its own errors
            logger.error("pdp audit path failed: %s", type(exc).__name__)
            if decision.allowed:
                decision = self._audit_failure_deny(decision)
        if receipt:
            decision = self._emit_receipt(decision, request, origin)
        for listener in self._listeners:
            try:
                listener(decision)
            except Exception as exc:
                logger.warning("pdp listener failed: %s", type(exc).__name__)
        return decision

    # -- internals -----------------------------------------------------

    def _deny(
        self,
        request: DecisionRequest | None,
        reason: str,
        *,
        error: str | None,
        inputs_digest: str = "",
        determining_policies: tuple[str, ...] = (),
    ) -> Decision:
        principal_id = action = resource = ""
        tier: ActionTier | None = None
        if request is not None:
            principal = getattr(request, "principal", None)
            principal_id = str(getattr(principal, "id", "") or "")
            action = request.action if isinstance(request.action, str) else ""
            resource = request.resource if isinstance(request.resource, str) else ""
            tier = request.tier if isinstance(request.tier, ActionTier) else None
        return Decision.denied(
            reason,
            constitution_hash=self._constitution_hash,
            policy_digest=self._policy_digest,
            inputs_digest=inputs_digest,
            principal_id=principal_id,
            action=action,
            resource=resource,
            tier=tier,
            determining_policies=determining_policies,
            error=error,
            policy_set_digest=self._policy_set.source_digest if self._policy_set else "",
        )

    def _get_executor(self) -> concurrent.futures.ThreadPoolExecutor:
        with self._executor_lock:
            if self._executor is None:
                self._executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=self._max_workers, thread_name_prefix="acgs-pdp"
                )
            return self._executor

    @fail_closed(deny_value=_BACKSTOP_DENY, log_level=logging.ERROR)
    def _decide(self, request: object) -> Decision:
        if not isinstance(request, DecisionRequest):
            return self._deny(
                None, "unparseable request: not a DecisionRequest", error="invalid_request"
            )
        problem = _validate_request(request)
        if problem is not None:
            return self._deny(None, f"unparseable request: {problem}", error="invalid_request")
        try:
            # PDP-owned deep snapshot: the digest below and the evaluation in
            # the worker thread see the same inputs, whatever the caller does
            # with its own request object meanwhile.
            request = replace(request)
        except Exception as exc:
            return self._deny(
                None,
                f"unparseable request: cannot snapshot ({type(exc).__name__})",
                error="invalid_request",
            )
        if not self._constitution_hash.strip() or not self._policy_digest.strip():
            return self._deny(
                request, "missing constitution hash or policy digest", error="missing_binding"
            )
        if self._policy_set is None:
            return self._deny(request, "no policy set loaded", error="missing_policy")
        if (
            request.expected_constitution_hash is not None
            and request.expected_constitution_hash != self._constitution_hash
        ):
            return self._deny(
                request,
                "stale policy: expected constitution hash "
                f"{request.expected_constitution_hash!r} != {self._constitution_hash!r}",
                error="stale_policy",
            )
        try:
            inputs_digest = request.inputs_digest()
        except (TypeError, ValueError) as exc:
            return self._deny(
                request, f"unparseable request attributes: {exc}", error="invalid_request"
            )
        ctx = DecisionContext(
            request=request,
            constitution_hash=self._constitution_hash,
            policy_digest=self._policy_digest,
            core_category=core_category_for(request, self._registry),
            registry=self._registry,
        )
        statements = (*CONSTITUTION_INVARIANTS, *self._policy_set.statements)
        future = self._get_executor().submit(_evaluate_statements, statements, ctx)
        try:
            forbids, permits = future.result(timeout=self._timeout_s)
        except concurrent.futures.TimeoutError:
            future.cancel()
            return self._deny(
                request,
                f"policy evaluation exceeded {self._timeout_s}s",
                error="timeout",
                inputs_digest=inputs_digest,
            )
        except _StatementError as exc:
            return self._deny(
                request,
                f"policy evaluation error: {exc}",
                error="evaluation_error",
                inputs_digest=inputs_digest,
                determining_policies=(exc.statement_id,),
            )
        if forbids:
            return self._deny(
                request,
                "forbidden by " + ", ".join(forbids),
                error=None,
                inputs_digest=inputs_digest,
                determining_policies=forbids,
            )
        if not permits:
            return self._deny(
                request,
                "no permit matched (default deny)",
                error=None,
                inputs_digest=inputs_digest,
            )
        return Decision(
            allowed=True,
            reason="permitted by " + ", ".join(permits),
            determining_policies=permits,
            constitution_hash=self._constitution_hash,
            policy_digest=self._policy_digest,
            inputs_digest=inputs_digest,
            decided_at=_now(),
            principal_id=request.principal.id,
            action=request.action,
            resource=request.resource,
            tier=request.tier,
            error=None,
            policy_set_digest=self._policy_set.source_digest,
        )

    def _receipt_failed(self, decision: Decision, exc: BaseException) -> None:
        logger.error("pdp receipt emission failed: %s", type(exc).__name__)
        with self._receipt_failures_lock:
            self._receipt_failures += 1
        if self._audit_log is None:
            return
        try:
            self._audit_log.record(
                AuditEntry(
                    id=f"pdp-receipt-failure-{uuid.uuid4().hex}",
                    type="pdp_receipt_failure",
                    agent_id=decision.principal_id,
                    action=decision.action,
                    valid=False,
                    violations=[],
                    constitutional_hash=decision.constitution_hash,
                    metadata={
                        "decision_id": decision.decision_id,
                        "allowed": decision.allowed,
                        "error": type(exc).__name__,
                    },
                )
            )
        except Exception as audit_exc:
            logger.error("pdp receipt-failure audit failed: %s", type(audit_exc).__name__)

    def _emit_receipt(
        self, decision: Decision, request: DecisionRequest | None, origin: str
    ) -> Decision:
        # TODO(control-plane-gap): receipt emission is synchronous and runs
        # outside timeout_s, so a slow store delays (but never flips) a
        # decision; an async/bounded sink is a later-phase concern.
        append = self._append_receipt
        if append is None:
            return decision
        try:
            append(decision, request, origin)
            return decision
        except Exception as exc:
            self._receipt_failed(decision, exc)
            if not decision.allowed:
                return decision
        withdrawn = self._audit_failure_deny(
            decision,
            reason="receipt emission failed; allow withdrawn",
            error="receipt_failed",
        )
        withdrawn = self._audit(withdrawn)
        try:
            append(withdrawn, request, origin)
        except Exception as exc:
            self._receipt_failed(withdrawn, exc)
        return withdrawn

    def _audit_failure_deny(
        self,
        decision: Decision,
        *,
        reason: str = "audit record failed; allow withdrawn",
        error: str = "audit_failed",
    ) -> Decision:
        return Decision.denied(
            reason,
            constitution_hash=decision.constitution_hash,
            policy_digest=decision.policy_digest,
            inputs_digest=decision.inputs_digest,
            principal_id=decision.principal_id,
            action=decision.action,
            resource=decision.resource,
            tier=decision.tier,
            error=error,
            policy_set_digest=decision.policy_set_digest,
        ).with_id(decision.decision_id)

    def _audit(self, decision: Decision) -> Decision:
        if self._audit_log is None:
            return decision
        entry = AuditEntry(
            id=f"pdp-{decision.decision_id}",
            type="pdp_decision",
            agent_id=decision.principal_id,
            action=decision.action,
            valid=decision.allowed,
            violations=[] if decision.allowed else list(decision.determining_policies),
            constitutional_hash=decision.constitution_hash,
            metadata={
                "policy_digest": decision.policy_digest,
                "inputs_digest": decision.inputs_digest,
                "determining_policies": list(decision.determining_policies),
                "tier": None if decision.tier is None else int(decision.tier),
                "resource": decision.resource,
                "reason": decision.reason,
                "error": decision.error,
                "policy_set_digest": decision.policy_set_digest,
                "decision_id": decision.decision_id,
            },
        )
        try:
            if self._durable_audit:
                self._audit_log.record_durable(entry)
            else:
                # record() swallows backend write errors; record_atomic()
                # raises them (and rolls the entry back), so a failed write
                # withdraws the allow below.
                self._audit_log.record_atomic(entry)
        except Exception as exc:
            logger.error("pdp audit record failed: %s", type(exc).__name__)
            if decision.allowed:
                return self._audit_failure_deny(decision)
        return decision
