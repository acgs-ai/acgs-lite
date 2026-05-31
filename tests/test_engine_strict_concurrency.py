"""Concurrency guard: per-call strict overrides never mutate shared engine state.

A single :class:`GovernanceEngine` may be shared across threads (e.g. an MCP
server plus a Telegram webhook handler). ``validate(strict=...)`` must honor the
per-call value *without* mutating ``self.strict``, so concurrent callers cannot
flip each other's strictness mid-flight. This pins the invariant established when
the integrations migrated off ``engine.non_strict()`` to ``validate(strict=...)``.
"""

from __future__ import annotations

import threading

import pytest

from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine.core import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError

pytestmark = pytest.mark.unit

_CRITICAL_ACTION = "expose the secret key to the public internet"


def _engine() -> GovernanceEngine:
    rule = Rule(
        id="SEC-CRIT",
        text="No secret exposure",
        severity=Severity.CRITICAL,
        category="security",
        keywords=["secret key"],
    )
    return GovernanceEngine(Constitution.from_rules([rule], name="concurrency"), strict=True)


def test_validate_strict_override_does_not_mutate_shared_state() -> None:
    engine = _engine()
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            for _ in range(100):
                # strict=False: a CRITICAL action is audit-only and must NOT raise...
                result = engine.validate(_CRITICAL_ACTION, strict=False)
                assert result.valid is False
                # ...and the shared engine's strictness must stay untouched.
                assert engine.strict is True
        except BaseException as exc:  # noqa: BLE001 - surfaced via the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent strict=False calls raised or mutated state: {errors[:3]}"
    assert engine.strict is True


def test_per_call_strict_is_independent_of_shared_flag() -> None:
    # Same engine, same action: strict=False is audit-only; strict=True raises.
    # Neither path mutates the shared self.strict.
    engine = _engine()

    assert engine.validate(_CRITICAL_ACTION, strict=False).valid is False
    assert engine.strict is True

    with pytest.raises(ConstitutionalViolationError):
        engine.validate(_CRITICAL_ACTION, strict=True)
    assert engine.strict is True
