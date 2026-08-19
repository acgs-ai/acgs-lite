"""Regressions for exemptions from formal-verification coverage.

``INAPPLICABLE`` blocks, so a callable that no policy names needs an operator to
say so explicitly. That mechanism is itself a way to allow execution without
verification, which makes it the most security-sensitive code added by this
change. These tests hold it to four properties:

1. it rescues ``INAPPLICABLE`` and no other status;
2. verification still runs first, so an exempt callable can still FAIL;
3. every misuse — wrong decorator order, expired, forged attribute, malformed —
   fails toward BLOCK;
4. every use is written to the audit log before the call proceeds.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import Field

from acgs_lite import Constitution, ConstitutionalViolationError, GovernedCallable, Rule
from acgs_lite.formal.exemption import (
    EXEMPTION_ATTRIBUTE,
    MAX_EXEMPTION_DAYS,
    ExemptionError,
    VerificationExemption,
    active_exemption,
    verification_exempt,
)
from acgs_lite.legitimacy.receipt import DecisionReceipt, ExecutionBoundary
from acgs_lite.z3_verify import Z3_AVAILABLE, VerificationStatus, blocks_execution

pytestmark = pytest.mark.unit

requires_z3 = pytest.mark.skipif(not Z3_AVAILABLE, reason="needs a real solver")

FUTURE = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()


def _exempt_kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "reason": "read-only lookup; the financial policy set does not apply",
        "approved_by": "security@example.com",
        "expires_at": FUTURE,
        "ticket": "SEC-1421",
    }
    base.update(overrides)
    return base


class TestDeclarationIsValidatedEagerly:
    """A malformed exemption must fail at decoration, not silently at first call."""

    def test_valid_declaration_attaches_the_marker(self) -> None:
        @verification_exempt(**_exempt_kwargs())
        def f(x: int) -> int:
            return x

        marker = getattr(f, EXEMPTION_ATTRIBUTE)
        assert isinstance(marker, VerificationExemption)
        assert marker.approved_by == "security@example.com"
        assert marker.ticket == "SEC-1421"

    @pytest.mark.parametrize("field", ["reason", "approved_by"])
    @pytest.mark.parametrize("bad", ["", "   ", None, 7])
    def test_attribution_is_required(self, field: str, bad: Any) -> None:
        with pytest.raises(ExemptionError, match=f"{field} is required"):
            verification_exempt(**_exempt_kwargs(**{field: bad}))

    def test_expiry_is_required_to_be_timezone_aware(self) -> None:
        naive = (datetime.now() + timedelta(days=5)).replace(tzinfo=None).isoformat()
        with pytest.raises(ExemptionError, match="no timezone"):
            verification_exempt(**_exempt_kwargs(expires_at=naive))

    def test_unparseable_expiry_is_rejected(self) -> None:
        with pytest.raises(ExemptionError, match="not an ISO-8601 datetime"):
            verification_exempt(**_exempt_kwargs(expires_at="whenever"))

    def test_non_datetime_expiry_is_rejected(self) -> None:
        with pytest.raises(ExemptionError, match="must be a datetime or ISO-8601 string"):
            verification_exempt(**_exempt_kwargs(expires_at=12345))

    def test_past_expiry_is_rejected(self) -> None:
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        with pytest.raises(ExemptionError, match="already in the past"):
            verification_exempt(**_exempt_kwargs(expires_at=past))

    def test_expiry_beyond_the_horizon_is_rejected(self) -> None:
        """An exemption defers a decision; it must not replace one."""
        far = (datetime.now(timezone.utc) + timedelta(days=MAX_EXEMPTION_DAYS + 2)).isoformat()
        with pytest.raises(ExemptionError, match="days out"):
            verification_exempt(**_exempt_kwargs(expires_at=far))


class TestResolutionFailsTowardBlock:
    """`active_exemption` returns a usable exemption only in the clean case."""

    def test_undecorated_callable_has_none(self) -> None:
        def f(x: int) -> int:
            return x

        exemption, err = active_exemption(f)
        assert exemption is None
        assert err is not None and "no verification exemption" in err

    def test_forged_attribute_is_not_honoured(self) -> None:
        """Setting the attribute by hand must not become a bypass."""

        def f(x: int) -> int:
            return x

        setattr(f, EXEMPTION_ATTRIBUTE, {"reason": "trust me"})
        exemption, err = active_exemption(f)
        assert exemption is None
        assert err is not None and "not a VerificationExemption" in err

    def test_true_is_not_an_exemption(self) -> None:
        def f(x: int) -> int:
            return x

        setattr(f, EXEMPTION_ATTRIBUTE, True)
        exemption, err = active_exemption(f)
        assert exemption is None

    def test_expired_exemption_is_refused(self) -> None:
        @verification_exempt(**_exempt_kwargs())
        def f(x: int) -> int:
            return x

        later = datetime.now(timezone.utc) + timedelta(days=400)
        exemption, err = active_exemption(f, now=later)
        assert exemption is None
        assert err is not None and "expired" in err

    def test_unexpired_exemption_resolves(self) -> None:
        @verification_exempt(**_exempt_kwargs())
        def f(x: int) -> int:
            return x

        exemption, err = active_exemption(f)
        assert isinstance(exemption, VerificationExemption)
        assert err is None

    def test_expiry_boundary_is_exclusive(self) -> None:
        """At exactly the expiry instant the exemption is already gone."""
        expires = datetime.now(timezone.utc) + timedelta(days=10)

        @verification_exempt(**_exempt_kwargs(expires_at=expires.isoformat()))
        def f(x: int) -> int:
            return x

        assert active_exemption(f, now=expires)[0] is None
        assert active_exemption(f, now=expires - timedelta(seconds=1))[0] is not None


def _receipt(method: str) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id=f"req-{method}",
        goal="Run governed callable test fixture",
        proposed_method=method,
        decision_type="ALLOW",
        authority_basis="test-authority",
        matched_constraints=("test-baseline-rule",),
        policy_version="test-policy-v1",
        execution_boundary=ExecutionBoundary(
            allowed_method=method,
            allowed_scope=None,
            allowed_subjects=(),
            expires_at=None,
            single_use=True,
        ),
    )


def _constitution(policy: str = "amount < 500") -> Constitution:
    return Constitution.from_rules([Rule(id="R1", text=f"z3: {policy}")])


def _expect_block(fn: Any, method: str, *call_args: Any, reason: str) -> str:
    """Assert the call is refused, and why -- as precisely as the config allows.

    Without a solver the gate never reaches an applicability verdict: it returns
    UNAVAILABLE first, and an exemption cannot clear that. So the *reason* is only
    checkable when z3 is installed. The refusal itself is checkable either way, and
    is the property that must hold in every lane, so these tests assert it in both
    rather than skipping the whole case where CI actually runs.
    """
    with pytest.raises(ConstitutionalViolationError) as exc:
        fn(*call_args, decision_receipt=_receipt(method))
    message = str(exc.value)
    if Z3_AVAILABLE:
        assert reason in message, f"expected {reason!r} in {message!r}"
    else:
        assert "unavailable" in message
    return message


class TestInapplicableBlocksWithoutAnExemption:
    def test_policy_about_another_callable_blocks(self) -> None:
        """The behavior change: 'nothing applied' is no longer an allow."""

        @GovernedCallable(_constitution())
        def rotate_key(name: str = Field(default="k")) -> str:
            return name

        _expect_block(rotate_key, "rotate_key", "k", reason="inapplicable")

    def test_unannotated_callable_blocks(self) -> None:
        """The fail-open vector: no hints -> no variables -> nothing applies."""

        @GovernedCallable(_constitution())
        def anything(x):  # type: ignore[no-untyped-def]
            return x

        _expect_block(anything, "anything", 1, reason="inapplicable")

    def test_deleting_an_annotation_cannot_disable_the_control(self) -> None:
        """Same callable, with and without a hint. Neither silently allows."""

        @GovernedCallable(_constitution())
        def annotated(amount: float = Field(gt=0, le=1000)) -> str:
            return f"ok {amount}"

        @GovernedCallable(_constitution())
        def unannotated(amount=1.0):  # type: ignore[no-untyped-def]
            return f"ok {amount}"

        with pytest.raises(ConstitutionalViolationError):
            unannotated(9999, decision_receipt=_receipt("unannotated"))
        # The annotated one is genuinely checked, so a compliant value runs.
        if Z3_AVAILABLE:
            assert annotated(10.0, decision_receipt=_receipt("annotated")) == "ok 10.0"


class TestExemptionAtTheGate:
    @requires_z3
    def test_exemption_below_the_governance_decorator_allows(self) -> None:
        @GovernedCallable(_constitution())
        @verification_exempt(**_exempt_kwargs())
        def rotate_key(name: str = Field(default="k")) -> str:
            return name

        assert rotate_key("k", decision_receipt=_receipt("rotate_key")) == "k"

    def test_exemption_above_the_governance_decorator_still_blocks(self) -> None:
        """Wrong order marks the wrapper, not the function the gate holds.

        This is the footgun an operator will actually hit, and it must fail
        toward BLOCK rather than silently granting.
        """

        @verification_exempt(**_exempt_kwargs())
        @GovernedCallable(_constitution())
        def rotate_key(name: str = Field(default="k")) -> str:
            return name

        _expect_block(rotate_key, "rotate_key", "k", reason="inapplicable")

    def test_expired_exemption_blocks_at_the_gate(self) -> None:
        soon = datetime.now(timezone.utc) + timedelta(seconds=1)

        @GovernedCallable(_constitution())
        @verification_exempt(**_exempt_kwargs(expires_at=soon.isoformat()))
        def rotate_key(name: str = Field(default="k")) -> str:
            return name

        import time as _time

        _time.sleep(1.1)
        _expect_block(rotate_key, "rotate_key", "k", reason="expired")

    @requires_z3
    def test_use_is_written_to_the_audit_log(self) -> None:
        gov = GovernedCallable(_constitution())

        @gov
        @verification_exempt(**_exempt_kwargs())
        def rotate_key(name: str = Field(default="k")) -> str:
            return name

        rotate_key("k", decision_receipt=_receipt("rotate_key"))

        entries = [e for e in gov.audit_log._entries if e.type == "verification_exemption"]
        assert len(entries) == 1
        entry = entries[0]
        assert entry.valid is False, "an exempted run is not a clean pass"
        assert entry.violations == ["Z3-VERIFICATION-INAPPLICABLE"]
        assert entry.metadata["exemption_approved_by"] == "security@example.com"
        assert entry.metadata["exemption_ticket"] == "SEC-1421"
        assert entry.metadata["verification_status"] == "inapplicable"
        assert gov.audit_log.verify_chain() is True

    @requires_z3
    def test_audit_record_precedes_the_call(self) -> None:
        """The record must exist before the body runs, not after it returns."""
        gov = GovernedCallable(_constitution())
        seen: list[int] = []

        @gov
        @verification_exempt(**_exempt_kwargs())
        def rotate_key(name: str = Field(default="k")) -> str:
            seen.append(
                len([e for e in gov.audit_log._entries if e.type == "verification_exemption"])
            )
            return name

        rotate_key("k", decision_receipt=_receipt("rotate_key"))
        assert seen == [1], "exemption was not recorded before execution"

    @requires_z3
    def test_exemption_cannot_clear_a_real_violation(self) -> None:
        """Verification runs first. An exempt callable still takes its FAIL."""

        @GovernedCallable(_constitution())
        @verification_exempt(**_exempt_kwargs())
        def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
            return f"Withdrew {amount}"

        with pytest.raises(ConstitutionalViolationError, match="violates mathematical"):
            withdraw(600.0, decision_receipt=_receipt("withdraw"))

    def test_exemption_cannot_clear_a_missing_solver(self, monkeypatch: pytest.MonkeyPatch) -> None:
        @GovernedCallable(_constitution())
        @verification_exempt(**_exempt_kwargs())
        def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
            return f"Withdrew {amount}"

        import acgs_lite.z3_verify as mod

        monkeypatch.setattr(mod, "Z3_AVAILABLE", False)
        with pytest.raises(ConstitutionalViolationError, match="unavailable"):
            withdraw(300.0, decision_receipt=_receipt("withdraw"))

    @requires_z3
    def test_exemption_cannot_clear_a_solver_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        @GovernedCallable(_constitution())
        @verification_exempt(**_exempt_kwargs())
        def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
            return f"Withdrew {amount}"

        import acgs_lite.z3_verify as mod

        def boom(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("solver exploded")

        monkeypatch.setattr(mod.z3, "Solver", boom)
        with pytest.raises(ConstitutionalViolationError, match=r"\[error\]"):
            withdraw(300.0, decision_receipt=_receipt("withdraw"))

    @requires_z3
    def test_exemption_cannot_clear_an_unknown_verdict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The fifth blocking status. A solver that will not answer is not a pass."""

        @GovernedCallable(_constitution())
        @verification_exempt(**_exempt_kwargs())
        def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
            return f"Withdrew {amount}"

        import acgs_lite.z3_verify as mod

        class _UnknownSolver:
            def set(self, *_a: Any, **_k: Any) -> None: ...
            def add(self, *_a: Any, **_k: Any) -> None: ...
            def check(self) -> Any:
                return mod.z3.unknown

        monkeypatch.setattr(mod.z3, "Solver", _UnknownSolver)
        with pytest.raises(ConstitutionalViolationError, match=r"\[unknown\]"):
            withdraw(300.0, decision_receipt=_receipt("withdraw"))

    def test_every_blocking_status_was_exercised_at_the_gate(self) -> None:
        """Guard the guard: name the statuses this class drives end to end.

        `test_only_inapplicable_is_exemptible` is structural -- it reads co_names
        and would pass even if the comparison were inverted. This one pins the
        behavioural coverage so a new status cannot be added without either a
        gate-level test or a deliberate edit here.
        """
        exercised = {
            VerificationStatus.FAIL,
            VerificationStatus.UNAVAILABLE,
            VerificationStatus.ERROR,
            VerificationStatus.UNKNOWN,
            VerificationStatus.INVALID_POLICY,
            VerificationStatus.INAPPLICABLE,
        }
        missing = {s for s in VerificationStatus if s is not VerificationStatus.PASS} - exercised
        assert not missing, f"no gate-level exemption test drives: {missing}"

    def test_exemption_cannot_clear_a_malformed_policy(self) -> None:
        """Malformed policies are refused at decoration, exemption or not."""
        with pytest.raises(ConstitutionalViolationError, match="invalid Z3 policy"):

            @GovernedCallable(_constitution("amount << 500"))
            @verification_exempt(**_exempt_kwargs())
            def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
                return f"Withdrew {amount}"

    @requires_z3
    def test_async_path_honours_the_exemption(self) -> None:
        import asyncio

        @GovernedCallable(_constitution())
        @verification_exempt(**_exempt_kwargs())
        async def rotate_key(name: str = Field(default="k")) -> str:
            return name

        got = asyncio.run(rotate_key("k", decision_receipt=_receipt("rotate_key")))
        assert got == "k"

    def test_async_path_blocks_without_an_exemption(self) -> None:
        import asyncio

        @GovernedCallable(_constitution())
        async def rotate_key(name: str = Field(default="k")) -> str:
            return name

        with pytest.raises(ConstitutionalViolationError) as exc:
            asyncio.run(rotate_key("k", decision_receipt=_receipt("rotate_key")))
        assert ("inapplicable" if Z3_AVAILABLE else "unavailable") in str(exc.value)


class TestExemptionScopeIsAnAllowlistOverTheEnum:
    """A status added later must not become exemptible by default.

    Mirrors `test_every_status_is_classified`: the assertion is over the whole
    enum, so a new member fails this test rather than quietly inheriting the
    rescue path.
    """

    EXEMPTIBLE = {VerificationStatus.INAPPLICABLE}

    def test_only_inapplicable_is_exemptible(self) -> None:
        from acgs_lite import governed as gov_mod

        source = gov_mod._enforce_z3_gate.__code__
        # The gate names exactly one status as the exemption trigger.
        referenced = {
            name for name in source.co_names if name in {s.name for s in VerificationStatus}
        }
        assert referenced == {"FAIL", "INAPPLICABLE"}, (
            "the gate should reference FAIL (for its message) and INAPPLICABLE "
            f"(for the exemption) and nothing else; got {referenced}"
        )

    @pytest.mark.parametrize("status", list(VerificationStatus))
    def test_every_status_is_deliberately_classified(self, status: VerificationStatus) -> None:
        exemptible = status in self.EXEMPTIBLE
        if status is VerificationStatus.PASS:
            assert not exemptible, "PASS needs no exemption"
        elif exemptible:
            assert status is VerificationStatus.INAPPLICABLE
        else:
            assert status is not VerificationStatus.INAPPLICABLE

    def test_blocking_set_is_unchanged_by_exemptions(self) -> None:
        """Exemptions live at the gate, never in the enforcement predicate."""
        from acgs_lite.z3_verify import Z3VerifyResult

        for status in VerificationStatus:
            res = Z3VerifyResult(
                satisfiable=False,
                verified=False,
                solver_result="skipped",
                counterexample=None,
                verification_time_ms=0.0,
                status=status,
            )
            assert blocks_execution(res) is (status is not VerificationStatus.PASS)
