"""Example-local context manager: creates acgs.governed_execution parent span.

Wraps a per-call invocation of a `GovernedCallable`-decorated tool function so
that the outcome (allow / deny / review / fail-closed) and audit receipt land
on a single OTLP span. The schema is documented in GOVERNANCE_ATTRIBUTES.md.

This module deliberately depends only on `opentelemetry.trace`, the public
`acgs_lite` exports, and the `ViolationAction` enum — no Phoenix import — so
the same context manager works under console export, in-process Phoenix, or a
remote OTLP collector.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from acgs_lite import ConstitutionalViolationError
from acgs_lite.constitution.rule import ViolationAction

tracer = trace.get_tracer("acgs.governed_execution")


@contextmanager
def governance_span(
    gc: Any,
    wrapped_fn: Any,
    input_value: Any,
    *,
    scenario: str = "unknown",
):
    """Create acgs.governed_execution parent span and run a governed tool call.

    The ``wrapped_fn`` argument must be the closure returned by
    ``GovernedCallable.__call__`` — i.e. ``gc(my_tool_fn)``. The context
    manager classifies the outcome by inspecting which exception (if any)
    the closure raised and, for ``ConstitutionalViolationError``, looks up
    the rule's ``workflow_action`` to distinguish *deny* from *review*.

    Yields ``(span, result, error)`` where exactly one of ``result``/``error``
    is non-None. For ``fail-closed`` (unexpected exception type) the
    exception is re-raised after the span is finalized.
    """
    with tracer.start_as_current_span("acgs.governed_execution") as span:
        span.set_attribute("acgs.fail_closed", True)
        span.set_attribute("governance.decision.version", "1.0")
        span.set_attribute("acgs.policy.version", "1.0")
        span.set_attribute("governance.scenario", scenario)
        try:
            result = wrapped_fn(input_value)
            span.set_attribute("governance.decision.outcome", "allow")
            span.set_attribute(
                "governance.decision.reason", "policy evaluation passed"
            )
            _set_receipt_attrs(span, gc)
            span.set_status(Status(StatusCode.OK))
            yield span, result, None
        except ConstitutionalViolationError as e:
            rule = next(
                (r for r in gc.constitution.rules if r.id == e.rule_id), None
            )
            is_review = (
                rule is not None
                and rule.workflow_action == ViolationAction.REQUIRE_HUMAN_REVIEW
            )
            if is_review:
                span.set_attribute("governance.decision.outcome", "review")
                span.set_attribute(
                    "governance.decision.reason", "requires human review"
                )
                span.set_attribute(
                    "governance.decision.rule_id", e.rule_id or ""
                )
                span.set_attribute("acgs.review.auto_approved", False)
                span.set_attribute("acgs.review.outcome", "pending")
                # Pending review is not an error — operator may still approve
                span.set_status(Status(StatusCode.OK))
            else:
                span.set_attribute("governance.decision.outcome", "deny")
                span.set_attribute("governance.decision.reason", str(e))
                span.set_attribute(
                    "governance.decision.rule_id", e.rule_id or ""
                )
                span.set_status(Status(StatusCode.ERROR, str(e)))
            _set_receipt_attrs(span, gc)
            yield span, None, e
        except Exception as e:  # noqa: BLE001 — fail-closed catches everything
            # fail-closed: unexpected error inside tool body
            span.set_attribute("governance.decision.outcome", "fail-closed")
            span.set_attribute("governance.decision.reason", str(e))
            span.set_status(Status(StatusCode.ERROR, str(e)))
            _set_receipt_attrs(span, gc)
            yield span, None, e
            raise


def _set_receipt_attrs(span, gc) -> None:
    """Set acgs.receipt.* attributes from the audit log's most recent entry.

    The audit log writes an entry on every governed call (allow + deny). For
    review/fail-closed paths an entry may not have been written yet — in that
    case we leave the attributes off the span rather than fabricating values.
    """
    # TODO: switch to a public API once acgs_lite.AuditLog exposes a stable
    # accessor for the latest entry (e.g. ``audit_log.latest()`` or
    # ``audit_log.export()``). The internal ``_entries`` list is the only
    # currently-shipped path to the entry id + hash needed for receipt
    # correlation.
    entries = gc.audit_log._entries  # noqa: SLF001
    if not entries:
        return
    last = entries[-1]
    span.set_attribute("acgs.receipt.id", str(getattr(last, "id", "") or ""))
    entry_hash = ""
    try:
        entry_hash = last.entry_hash  # property on AuditEntry
    except Exception:  # noqa: BLE001
        entry_hash = ""
    span.set_attribute("acgs.receipt.hash", str(entry_hash or ""))
