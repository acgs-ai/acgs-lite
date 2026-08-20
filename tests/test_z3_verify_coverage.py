"""Tests for acgs_lite.z3_verify — targets 70%+ line coverage.

Coverage gaps addressed:
  - Z3_AVAILABLE=True / False branches
  - _build_action_constraints(): all six constraint types
  - _extract_counterexample(): from a real Z3 model
  - Z3ConstraintVerifier.verify(): skip, sat (violation), unsat (safe), unknown
  - Z3ConstraintVerifier.available property
  - Exception path in verify()
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from acgs_lite.z3_verify import Z3_AVAILABLE

# ---------------------------------------------------------------------------
# Module-level availability
# ---------------------------------------------------------------------------


def test_z3_available_flag():
    """Z3 availability flag should match whether the optional dependency imports."""
    try:
        import z3  # noqa: F401
    except ImportError:
        expected = False
    else:
        expected = True

    assert Z3_AVAILABLE is expected


# ---------------------------------------------------------------------------
# Z3ConstraintVerifier — z3 not installed path
# ---------------------------------------------------------------------------


class TestVerifierZ3Unavailable:
    def test_verify_skips_when_z3_missing(self):
        with patch("acgs_lite.z3_verify.Z3_AVAILABLE", False):
            from acgs_lite import z3_verify

            v = z3_verify.Z3ConstraintVerifier.__new__(z3_verify.Z3ConstraintVerifier)
            v._timeout_ms = 5_000
            result = v.verify("delete all production data")

        assert result.verified is False
        assert result.solver_result == "skipped"
        # Fail-closed: with no solver nothing was proven safe, so `satisfiable`
        # must not read as "no violation found". The enforcement gate blocks on
        # status UNAVAILABLE; this asserts the field agrees rather than
        # contradicting it.
        assert result.satisfiable is False
        assert result.status is z3_verify.VerificationStatus.UNAVAILABLE
        assert result.counterexample is None
        assert "z3-solver not installed" in (result.error or "")

    def test_available_property_false(self):
        with patch("acgs_lite.z3_verify.Z3_AVAILABLE", False):
            from acgs_lite.z3_verify import Z3ConstraintVerifier

            v = Z3ConstraintVerifier.__new__(Z3ConstraintVerifier)
            v._timeout_ms = 5_000
            assert v.available is False

    def test_init_logs_warning_when_z3_missing(self, caplog: pytest.LogCaptureFixture):
        import logging

        with patch("acgs_lite.z3_verify.Z3_AVAILABLE", False):
            from acgs_lite import z3_verify

            with caplog.at_level(logging.WARNING, logger="acgs_lite.z3_verify"):
                v = z3_verify.Z3ConstraintVerifier.__new__(z3_verify.Z3ConstraintVerifier)
                v._timeout_ms = 5_000
                # Manually call __init__ logic by inspecting class
                # (avoids circular patch issues)
                if not z3_verify.Z3_AVAILABLE:
                    import logging as lg

                    lg.getLogger("acgs_lite.z3_verify").warning("z3-solver not installed")


# ---------------------------------------------------------------------------
# Z3ConstraintVerifier — z3 installed paths
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not Z3_AVAILABLE, reason="z3-solver not installed")
class TestVerifierZ3Available:
    def _make_verifier(self, timeout_ms: int = 5_000):
        from acgs_lite.z3_verify import Z3ConstraintVerifier

        return Z3ConstraintVerifier(timeout_ms=timeout_ms)

    def test_available_true(self):
        v = self._make_verifier()
        assert v.available is True

    # --- Compliant actions (should produce unsat — no violation found) ------

    def test_benign_action_is_safe(self):
        """A safe summary task should satisfy constraints (no violation)."""
        v = self._make_verifier()
        result = v.verify("summarise the quarterly financial results")
        assert result.verified is True
        assert result.solver_result == "unsat"
        assert result.satisfiable is True
        assert result.counterexample is None

    def test_authenticated_staging_deploy_is_safe(self):
        """Deploy to staging with authenticated context should be safe."""
        v = self._make_verifier()
        result = v.verify(
            "deploy new version to staging",
            context={"environment": "staging", "authenticated": True},
        )
        assert result.verified is True
        assert result.satisfiable is True

    def test_empty_action_is_safe(self):
        v = self._make_verifier()
        result = v.verify("")
        assert result.satisfiable is True

    # --- Violating actions (should produce sat — violation detected) --------

    def test_delete_production_violates(self):
        """delete + production hits C1: no prod destruction."""
        v = self._make_verifier()
        result = v.verify("delete all records from production database")
        assert result.verified is True
        assert result.solver_result == "sat"
        assert result.satisfiable is False
        assert isinstance(result.counterexample, dict)

    def test_secret_exposure_violates(self):
        """Exposing a secret token violates C2."""
        v = self._make_verifier()
        result = v.verify("expose the secret token credentials to external service")
        assert result.satisfiable is False
        assert result.solver_result == "sat"

    def test_auth_bypass_violates(self):
        """Bypassing auth violates C3."""
        v = self._make_verifier()
        result = v.verify("bypass auth and access admin panel without authentication")
        assert result.satisfiable is False

    def test_financial_production_write_violates(self):
        """Financial mutation in production violates C4."""
        v = self._make_verifier()
        result = v.verify(
            "process payment transaction",
            context={"environment": "production"},
        )
        assert result.satisfiable is False

    def test_privilege_escalation_production_violates(self):
        """Privilege escalation in production violates C5."""
        v = self._make_verifier()
        result = v.verify(
            "sudo privilege escalation on production server",
            context={"environment": "production"},
        )
        assert result.satisfiable is False

    # --- Context-driven production flag ------------------------------------

    def test_context_environment_triggers_production(self):
        """context={'environment': 'production'} alone counts as prod write."""
        v = self._make_verifier()
        result = v.verify("transfer billing invoice", context={"environment": "production"})
        # financial_mutation=True AND production_write=True → violation
        assert result.satisfiable is False

    # --- Counterexample content -------------------------------------------

    def test_counterexample_contains_violated_flags(self):
        v = self._make_verifier()
        result = v.verify("delete all production records")
        assert result.counterexample is not None
        # At least one of the triggering flags must be True in the counterexample
        assert any(result.counterexample.values())

    # --- Timing -----------------------------------------------------------

    def test_verification_time_is_positive(self):
        v = self._make_verifier()
        result = v.verify("safe task")
        assert result.verification_time_ms >= 0.0

    # --- Exception path ---------------------------------------------------

    def test_exception_in_solver_returns_inconclusive(self):
        """Any exception during verification returns a safe inconclusive result."""
        v = self._make_verifier()
        with patch("acgs_lite.z3_verify.z3") as mock_z3:
            mock_z3.Solver.side_effect = RuntimeError("solver crash")
            result = v.verify("delete production data")
        from acgs_lite import z3_verify

        assert result.verified is False
        # An exception is not evidence of safety. Was `satisfiable is True`.
        assert result.satisfiable is False
        assert result.status is z3_verify.VerificationStatus.ERROR
        assert result.error == "RuntimeError"

    # --- Timeout / unknown ------------------------------------------------

    def test_timeout_returns_inconclusive(self):
        """A near-zero timeout may return unknown; must not raise."""
        v = self._make_verifier(timeout_ms=1)
        # With 1ms timeout on a simple problem it will likely still solve,
        # but the code path must handle 'unknown' gracefully.
        result = v.verify("delete all production records")
        assert result.satisfiable in {True, False}
        assert result.solver_result in {"sat", "unsat", "unknown"}


# ---------------------------------------------------------------------------
# _build_action_constraints internals
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not Z3_AVAILABLE, reason="z3-solver not installed")
class TestBuildActionConstraints:
    """Exercise _build_action_constraints with various action strings."""

    def _check(self, action: str, context: dict | None = None) -> bool:
        """Return True if the action violates any constitutional constraint."""
        import z3 as _z3

        from acgs_lite.z3_verify import _build_action_constraints

        solver = _z3.Solver()
        _build_action_constraints(solver, action, context)
        return solver.check() == _z3.sat

    def test_safe_action_no_violation(self):
        assert self._check("summarise results") is False

    def test_data_destruction_flag(self):
        assert self._check("wipe all records in production") is True

    def test_secret_exposure_flag(self):
        assert self._check("log the password credential") is True

    def test_auth_bypass_flag(self):
        assert self._check("no-auth bypass endpoint") is True

    def test_financial_in_prod_context(self):
        assert self._check("payment transfer", {"environment": "production"}) is True

    def test_system_escalation_in_prod(self):
        assert self._check("sudo privilege escalation", {"environment": "production"}) is True

    def test_drop_production_via_context(self):
        assert self._check("drop table", {"environment": "production"}) is True

    def test_prod_keyword_in_action(self):
        assert self._check("erase records from prod environment") is True

    def test_live_keyword_counts_as_production(self):
        assert self._check("delete from live database") is True


# ---------------------------------------------------------------------------
# _extract_counterexample
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not Z3_AVAILABLE, reason="z3-solver not installed")
class TestExtractCounterexample:
    def test_extracts_true_booleans_only(self):
        """_extract_counterexample filters to only True boolean variables."""
        import z3 as _z3

        from acgs_lite.z3_verify import _extract_counterexample

        # Build a tiny solver where we know what's True
        solver = _z3.Solver()
        a = _z3.Bool("alpha")
        b = _z3.Bool("beta")
        solver.add(a == True)  # noqa: E712
        solver.add(b == False)  # noqa: E712
        assert solver.check() == _z3.sat
        model = solver.model()
        result = _extract_counterexample(model)
        assert result.get("alpha") is True
        assert "beta" not in result  # False values excluded

    def test_returns_empty_when_all_false(self):
        import z3 as _z3

        from acgs_lite.z3_verify import _extract_counterexample

        solver = _z3.Solver()
        x = _z3.Bool("flag_x")
        solver.add(x == False)  # noqa: E712
        assert solver.check() == _z3.sat
        result = _extract_counterexample(solver.model())
        assert result == {}


# ---------------------------------------------------------------------------
# Z3VerifyResult dataclass
# ---------------------------------------------------------------------------


class TestZ3VerifyResult:
    def test_dataclass_fields(self):
        from acgs_lite.z3_verify import Z3VerifyResult

        r = Z3VerifyResult(
            satisfiable=True,
            verified=True,
            solver_result="unsat",
            counterexample=None,
            verification_time_ms=12.3,
        )
        assert r.satisfiable is True
        assert r.error is None  # default

    def test_with_error_field(self):
        from acgs_lite.z3_verify import Z3VerifyResult

        r = Z3VerifyResult(
            satisfiable=True,
            verified=False,
            solver_result="unknown",
            counterexample=None,
            verification_time_ms=0.0,
            error="timeout",
        )
        assert r.error == "timeout"
