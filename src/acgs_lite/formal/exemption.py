"""Explicit, expiring, audited exemptions from formal-verification coverage.

``INAPPLICABLE`` blocks. A constitution's Z3 policies are global while callables
are many, so a policy naming none of a callable's parameters says nothing about
it — and *saying nothing* is not evidence of safety. It is also indistinguishable
from the dangerous case: policy variables are built from type hints, so a callable
with no annotations binds no variables, every policy looks inapplicable to it, and
enforcement silently disappears. Deleting an annotation must not be a way to opt
out of a control.

The cost of blocking on absence is that a genuinely unrelated callable now needs
an operator to say so. This module is how they say it, and the requirements are
deliberately awkward:

- **explicit** — an exemption is written at the callable, never inferred, never
  configured globally, never pattern-matched onto a set of functions;
- **attributed** — a human reason and an approver, both non-empty;
- **expiring** — a timezone-aware deadline, bounded at one year, after which the
  callable blocks again and someone has to look at it a second time. Note the
  two paths: a live process starts blocking the call, but a process *starting*
  after the deadline raises :class:`ExemptionError` at import and does not boot,
  because validation happens at decoration time. Both refuse to execute
  unverified; only the first is a runtime denial;
- **audited** — every *use* writes to the tamper-evident audit log before the
  call proceeds, so "how often did we execute without verification, and under
  whose authority" is a query rather than an archaeology project.

Usage — note the decorator order, which matters::

    @GovernedCallable(constitution)
    @verification_exempt(
        reason="read-only key lookup; the financial policy set does not apply",
        approved_by="security@example.com",
        expires_at="2026-12-31T00:00:00+00:00",
        ticket="SEC-1421",
    )
    def rotate_key(name: str) -> str:
        ...

``verification_exempt`` must sit **below** ``GovernedCallable`` so that it marks
the underlying function before the governance wrapper closes over it. Applied
above, the mark lands on the wrapper and the gate never sees it — the call blocks.
That is the intended failure direction: a misapplied exemption denies rather than
grants.

An exemption rescues ``INAPPLICABLE`` and nothing else. It cannot clear a proven
violation, a malformed policy, a solver timeout, a solver crash, or a missing
solver. See :func:`acgs_lite.z3_verify.blocks_execution`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

__all__ = [
    "EXEMPTION_ATTRIBUTE",
    "MAX_EXEMPTION_DAYS",
    "ExemptionError",
    "VerificationExemption",
    "active_exemption",
    "verification_exempt",
]

T = TypeVar("T")

#: Attribute set on the decorated function. Read by the enforcement gate.
EXEMPTION_ATTRIBUTE = "__acgs_verification_exemption__"

#: An exemption is a deferral, not a decision. Beyond this horizon it is a way of
#: never revisiting the question, so it is refused at decoration time.
MAX_EXEMPTION_DAYS = 365


class ExemptionError(ValueError):
    """An exemption is malformed, unbounded, or otherwise unusable.

    Raised at decoration time so a bad exemption fails at import rather than
    silently failing to protect anything at the first call.
    """


@dataclass(frozen=True)
class VerificationExemption:
    """A recorded decision to run a callable that verification cannot clear."""

    reason: str
    approved_by: str
    expires_at: datetime
    ticket: str | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        """True once the exemption has lapsed.

        The comparison is between two timezone-aware instants; ``expires_at`` is
        validated as aware at construction, so this cannot raise the
        naive-vs-aware ``TypeError`` that would otherwise have to be caught (and
        a caught exception here would be an exemption that never expires).
        """
        return (now or datetime.now(timezone.utc)) >= self.expires_at

    def to_audit_metadata(self) -> dict[str, Any]:
        """Fields recorded on every use. Enough to answer 'who allowed this'."""
        return {
            "exemption_reason": self.reason,
            "exemption_approved_by": self.approved_by,
            "exemption_expires_at": self.expires_at.isoformat(),
            "exemption_ticket": self.ticket,
        }


def _coerce_expiry(value: str | datetime) -> datetime:
    """Parse and validate an expiry, rejecting everything ambiguous.

    Naive datetimes are refused rather than assumed UTC: an exemption whose
    deadline depends on the reader's timezone is not a deadline.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ExemptionError(
                f"expires_at {value!r} is not an ISO-8601 datetime: {exc}"
            ) from exc
    else:
        raise ExemptionError(
            f"expires_at must be a datetime or ISO-8601 string, got {type(value).__name__}"
        )

    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise ExemptionError(
            f"expires_at {parsed.isoformat()!r} has no timezone; "
            "use an explicit offset such as '2026-12-31T00:00:00+00:00'"
        )

    now = datetime.now(timezone.utc)
    if parsed <= now:
        raise ExemptionError(f"expires_at {parsed.isoformat()!r} is already in the past")
    if parsed - now > timedelta(days=MAX_EXEMPTION_DAYS):
        raise ExemptionError(
            f"expires_at {parsed.isoformat()!r} is more than {MAX_EXEMPTION_DAYS} days out; "
            "an exemption defers a decision, it does not replace one"
        )
    return parsed


def _require_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExemptionError(f"{field} is required and must be a non-empty string")
    return value.strip()


def verification_exempt(
    *,
    reason: str,
    approved_by: str,
    expires_at: str | datetime,
    ticket: str | None = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Mark a callable as knowingly outside formal-verification coverage.

    Every argument is validated here, at decoration time, so a malformed
    exemption raises at import instead of quietly failing to apply at the first
    call — the failure mode this whole change exists to remove.

    :raises ExemptionError: if any field is missing, empty, naive, past, or
        further out than :data:`MAX_EXEMPTION_DAYS`.
    """
    exemption = VerificationExemption(
        reason=_require_text(reason, "reason"),
        approved_by=_require_text(approved_by, "approved_by"),
        expires_at=_coerce_expiry(expires_at),
        ticket=ticket.strip() if isinstance(ticket, str) and ticket.strip() else None,
    )

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        if not callable(func):
            raise ExemptionError("verification_exempt must decorate a callable")
        setattr(func, EXEMPTION_ATTRIBUTE, exemption)
        return func

    return decorator


def active_exemption(
    func: Any,
    now: datetime | None = None,
) -> tuple[VerificationExemption | None, str | None]:
    """Return the usable exemption on *func*, or the reason there is none.

    Returns ``(exemption, None)`` only for an exemption that is present, of the
    right type, and unexpired. Every other outcome returns ``(None, reason)`` and
    the caller must block — including the case where the attribute exists but
    holds something that is not a :class:`VerificationExemption`, which is how a
    hand-set attribute would otherwise become a bypass.

    Uses plain attribute access on purpose: no ``__wrapped__`` traversal. An
    exemption applied above the governance decorator marks the wrapper, not the
    function the gate holds, and therefore does not apply.
    """
    raw = getattr(func, EXEMPTION_ATTRIBUTE, None)
    if raw is None:
        return None, "no verification exemption is declared for this callable"
    if not isinstance(raw, VerificationExemption):
        return None, (
            f"{EXEMPTION_ATTRIBUTE} holds {type(raw).__name__}, not a VerificationExemption; "
            "declare exemptions with @verification_exempt"
        )
    if raw.is_expired(now):
        return None, (
            f"verification exemption expired at {raw.expires_at.isoformat()} "
            f"(approved by {raw.approved_by})"
        )
    return raw, None
