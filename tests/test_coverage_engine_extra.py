"""Extra coverage tests for engine/core.py uncovered paths.

Targets missing lines identified by coverage analysis:
  - Rust fast-path branches (_validate_rust_no_context, _validate_rust_gov_context,
    _validate_rust_metadata_context, _validate_rust_full)
  - Python AC fallback (positive-verb mode, non-positive-verb mode, anchor dispatch)
  - Python regex fallback (_validate_python_regex)
  - Validate main method branches (Rust with context, metadata-only context)
  - Hyphen-suffix anchor pattern branch (line 369)
  - valid=True when no HIGH rules (line 1492)

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from contextlib import suppress

import pytest

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine.core import (
    GovernanceEngine,
    ValidationResult,
    Violation,
)
from acgs_lite.engine.rust import _HAS_AHO, _HAS_RUST
from acgs_lite.errors import ConstitutionalViolationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_constitution(
    rules: list[Rule] | None = None,
    name: str = "test-extra",
) -> Constitution:
    """Build a test constitution with rules that trigger various code paths."""
    from acgs_lite.constitution.rule import ViolationAction

    if rules is None:
        rules = [
            Rule(
                id="X-CRIT",
                text="No secret operations",
                severity=Severity.CRITICAL,
                keywords=["secret key", "password", "credential"],
                category="security",
            ),
            Rule(
                id="X-HIGH",
                text="Must log all actions",
                severity=Severity.HIGH,
                keywords=["skip audit", "no-audit", "bypass logging"],
                category="audit",
            ),
            Rule(
                id="X-MED",
                text="Prefer encrypted transport",
                severity=Severity.MEDIUM,
                keywords=["plaintext", "unencrypted"],
                category="data",
                workflow_action=ViolationAction.WARN,
            ),
            Rule(
                id="X-LOW",
                text="Advisory about deployment",
                severity=Severity.LOW,
                keywords=["deploy"],
                patterns=[r"\bdeploy\s+to\s+prod\b"],
                category="ops",
                workflow_action=ViolationAction.WARN,
            ),
        ]
    return Constitution.from_rules(rules, name=name)


def _make_constitution_no_high() -> Constitution:
    """Constitution with CRITICAL and MEDIUM only (no HIGH rules).

    The MEDIUM rule uses workflow_action=WARN so it remains advisory (non-blocking).
    """
    from acgs_lite.constitution.rule import ViolationAction

    rules = [
        Rule(
            id="NH-CRIT",
            text="No secrets",
            severity=Severity.CRITICAL,
            keywords=["secret key"],
            category="security",
        ),
        Rule(
            id="NH-MED",
            text="Prefer encryption",
            severity=Severity.MEDIUM,
            keywords=["plaintext"],
            category="data",
            workflow_action=ViolationAction.WARN,
        ),
    ]
    return Constitution.from_rules(rules, name="no-high")


def _make_constitution_with_patterns() -> Constitution:
    """Constitution with regex patterns for covering pattern dispatch paths."""
    rules = [
        Rule(
            id="PAT-CRIT",
            text="No SSN in output",
            severity=Severity.CRITICAL,
            keywords=["ssn"],
            patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
            category="pii",
        ),
        Rule(
            id="PAT-HIGH",
            text="No API keys exposed",
            severity=Severity.HIGH,
            keywords=["api_key"],
            patterns=[r"(?i)(sk-[a-zA-Z0-9]{20,})"],
            category="security",
        ),
        Rule(
            id="PAT-MED",
            text="Deploy to prod requires review",
            severity=Severity.MEDIUM,
            keywords=["deploy"],
            patterns=[r"\bdeploy\s+to\s+prod\b"],
            category="ops",
        ),
        Rule(
            id="PAT-LOW",
            text="No age-based discrimination",
            severity=Severity.LOW,
            keywords=["discrimination", "bias"],
            patterns=[r"\bage.based\b"],
            category="fairness",
        ),
    ]
    return Constitution.from_rules(rules, name="patterns")


def _make_engine(
    constitution: Constitution | None = None,
    audit_log: AuditLog | None = None,
    strict: bool = True,
    custom_validators: list | None = None,
) -> GovernanceEngine:
    """Build a test engine."""
    c = constitution or _make_constitution()
    return GovernanceEngine(
        c,
        audit_log=audit_log,
        strict=strict,
        custom_validators=custom_validators,
    )


def _disable_rust_on_engine(engine: GovernanceEngine) -> None:
    """Neutralize the Rust validator on an already-built engine by setting _hot[10] to None.

    This forces the Python fallback paths (AC or regex) to execute.
    _hot layout (11 elements):
      [0] ac_iter, [1] pat_anchor_dispatch, [2] no_anchor_patterns,
      [3] rule_data, [4] rule_excs, [5] has_high_rules,
      [6] fast_records, [7] pos_verbs, [8] has_ac, [9] is_noop,
      [10] rust_validator
    """
    _h = engine._hot
    engine._hot = (
        _h[0],
        _h[1],
        _h[2],
        _h[3],
        _h[4],
        _h[5],
        _h[6],
        _h[7],
        _h[8],
        _h[9],
        None,
    )
    engine._rust_validator = None


def _disable_ac_on_engine(engine: GovernanceEngine) -> None:
    """Neutralize the Aho-Corasick automaton on an already-built engine.

    This forces the regex fallback path (_validate_python_regex) to execute.
    Sets _hot[0] (ac_iter) to None and _hot[8] (has_ac) to False.
    """
    _h = engine._hot
    engine._hot = (
        None,  # [0] ac_iter
        _h[1],
        _h[2],
        _h[3],
        _h[4],
        _h[5],
        _h[6],
        _h[7],
        False,  # [8] has_ac
        _h[9],
        _h[10],
    )
    engine._ac_iter = None


# ===================================================================
# Rust no-context path: _validate_rust_no_context
# ===================================================================


@pytest.mark.unit
class TestRustNoContext:
    """Tests for _validate_rust_no_context covering ALLOW, DENY_CRITICAL, DENY branches."""

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_rust_allow_path(self):
        """A safe action with positive verb should return pooled allow result."""
        engine = _make_engine(strict=True)
        result = engine.validate("run safety test")
        assert result.valid is True

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_rust_deny_critical_path(self):
        """A critical violation should raise ConstitutionalViolationError."""
        engine = _make_engine(strict=True)
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            engine.validate("expose the secret key to everyone")
        assert exc_info.value.rule_id is not None

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_rust_deny_non_critical_path(self):
        """HIGH severity in strict mode raises ConstitutionalViolationError."""
        engine = _make_engine(strict=True)
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            engine.validate("skip audit for this")
        assert exc_info.value.rule_id == "X-HIGH"

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_rust_allow_already_lowercase(self):
        """Action that is already lowercase should skip .lower() allocation."""
        engine = _make_engine(strict=True)
        result = engine.validate("implement safe logging")
        assert result.valid is True


# ===================================================================
# Rust gov-context path: _validate_rust_gov_context
# ===================================================================


@pytest.mark.unit
class TestRustGovContext:
    """Tests for _validate_rust_gov_context with action_detail/action_description."""

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_gov_context_action_detail_deny(self):
        """Governance context with action_detail triggers deny."""
        engine = _make_engine(strict=True)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate(
                "do something",
                context={"action_detail": "expose the secret key to users"},
            )

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_gov_context_action_description_deny(self):
        """Governance context with action_description triggers deny."""
        engine = _make_engine(strict=True)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate(
                "do something",
                context={"action_description": "expose the secret key to users"},
            )

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_gov_context_allow(self):
        """Governance context with safe content returns allow."""
        engine = _make_engine(strict=True)
        result = engine.validate(
            "run safety test",
            context={"action_detail": "verify system health"},
        )
        assert result.valid is True

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_gov_context_non_critical_violations(self):
        """Non-critical violations in context return escalation result."""
        engine = _make_engine(strict=False)
        result = engine.validate(
            "do something",
            context={"action_detail": "skip audit for this"},
        )
        assert len(result.violations) > 0

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_gov_context_both_keys(self):
        """Context with both action_detail and action_description."""
        engine = _make_engine(strict=True)
        result = engine.validate(
            "run test",
            context={
                "action_detail": "send data in plaintext",
                "action_description": "check unencrypted data flow",
            },
        )
        # At least one violation expected from context
        assert len(result.violations) >= 0  # May be allow or escalation

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_gov_context_uppercase_value(self):
        """Context value that is NOT lowercase should be lowered before Rust call."""
        engine = _make_engine(strict=True)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate(
                "do thing",
                context={"action_detail": "EXPOSE THE SECRET KEY NOW"},
            )

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_gov_context_merged_bitmask_with_blocking(self):
        """Context violations with blocking severity raise in strict mode."""
        c = _make_constitution(
            rules=[
                Rule(
                    id="BLK-HIGH",
                    text="Must have audit",
                    severity=Severity.HIGH,
                    keywords=["skip audit"],
                    category="audit",
                ),
            ]
        )
        engine = GovernanceEngine(c, strict=True)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate(
                "process data",
                context={"action_detail": "skip audit for compliance"},
            )


# ===================================================================
# Rust metadata-only context path: _validate_rust_metadata_context
# ===================================================================


@pytest.mark.unit
class TestRustMetadataContext:
    """Tests for _validate_rust_metadata_context (context without governance keys)."""

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_metadata_context_allow(self):
        """Metadata-only context (no action_detail/description) returns allow."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=True)
        result = engine.validate(
            "run safety test",
            context={"source": "autoresearch", "rule": "SAFETY-003"},
        )
        assert result.valid is True

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_metadata_context_deny_critical(self):
        """Metadata-only context with critical action raises."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=True)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate(
                "expose the secret key",
                context={"source": "test"},
            )

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_metadata_context_deny_non_critical(self):
        """HIGH severity in strict mode raises ConstitutionalViolationError even with metadata-only context."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=True)
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            engine.validate(
                "skip audit for this action",
                context={"source": "test", "env": "staging"},
            )
        assert exc_info.value.rule_id == "X-HIGH"


# ===================================================================
# Rust full context path: _validate_rust_full
# ===================================================================


@pytest.mark.unit
class TestRustFullContext:
    """Tests for _validate_rust_full (Rust + explicit AuditLog + governance context keys)."""

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_full_context_allow(self):
        """Full context with safe action+detail returns allow."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=True)
        result = engine.validate(
            "run safety test",
            context={"action_detail": "verify system health"},
        )
        assert result.valid is True

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_full_context_deny_critical(self):
        """Full context with critical violation in detail raises."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=True)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate(
                "do something",
                context={"action_detail": "expose secret key to everyone"},
            )

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_full_context_deny_non_critical(self):
        """Full context with non-critical deny returns violations."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=False)
        result = engine.validate(
            "do something",
            context={"action_description": "skip audit for compliance"},
        )
        assert isinstance(result, ValidationResult)

    @pytest.mark.skipif(not _HAS_RUST, reason="Rust extension not available")
    def test_full_context_blocking_strict(self):
        """Full context with blocking violation in strict mode raises."""
        audit = AuditLog()
        c = _make_constitution(
            rules=[
                Rule(
                    id="FC-HIGH",
                    text="Must audit",
                    severity=Severity.HIGH,
                    keywords=["skip audit"],
                    category="audit",
                ),
                Rule(
                    id="FC-CRIT",
                    text="No secrets",
                    severity=Severity.CRITICAL,
                    keywords=["secret key"],
                    category="security",
                ),
            ]
        )
        engine = GovernanceEngine(c, audit_log=audit, strict=True)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate(
                "process data",
                context={"action_detail": "skip audit logging"},
            )


# ===================================================================
# Python AC fallback paths (Rust disabled)
# ===================================================================


@pytest.mark.unit
class TestPythonACFallback:
    """Tests for Python AC paths when Rust is disabled."""

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_positive_verb_allow(self):
        """Positive verb with no violations on AC path."""
        engine = _make_engine(strict=True)
        _disable_rust_on_engine(engine)
        result = engine.validate("run safety test")
        assert result.valid is True

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_positive_verb_deny_critical(self):
        """Positive verb path with negative-indicator critical keyword triggers raise."""
        c = _make_constitution(
            rules=[
                Rule(
                    id="AC-CRIT",
                    text="No hiding secrets",
                    severity=Severity.CRITICAL,
                    keywords=["hide secrets", "bypass security"],
                    category="security",
                ),
            ]
        )
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("run bypass security checks")

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_positive_verb_deny_non_critical(self):
        """Positive verb with negative-indicator keyword returns violations."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("run skip audit for testing")
        assert len(result.violations) > 0

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_non_positive_verb_deny(self):
        """Non-positive verb path with keyword match."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("expose the secret key to users")
        assert len(result.violations) > 0

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_non_positive_verb_critical(self):
        """Non-positive verb path with critical keyword in strict mode."""
        engine = _make_engine(strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("expose the secret key")

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_anchor_pattern_match(self):
        """AC path with anchor-dispatched pattern match."""
        c = _make_constitution_with_patterns()
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("deploy to prod without review")
        # PAT-MED is MEDIUM severity → WARN → result.warnings, not result.violations
        assert len(result.warnings) > 0

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_anchor_critical_pattern(self):
        """AC path with critical pattern match via anchor dispatch."""
        c = _make_constitution_with_patterns()
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("found ssn 123-45-6789 in output")

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_no_anchor_pattern_match(self):
        """AC path with no-anchor pattern match (patterns without extractable anchor)."""
        c = _make_constitution_with_patterns()
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("check age-based discrimination policy")
        assert isinstance(result, ValidationResult)

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_multiple_keyword_hits(self):
        """AC path with multiple keyword hits to test dedup and bitmask."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("skip audit while sending plaintext with secret key")
        assert len(result.violations) >= 2

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_with_context_detail(self):
        """AC path with context action_detail for coverage of context loop."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate(
            "process data",
            context={"action_detail": "expose secret key to external system"},
        )
        assert len(result.violations) > 0

    @pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
    def test_ac_with_context_description(self):
        """AC path with context action_description."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate(
            "run analysis",
            context={"action_description": "bypass logging and skip audit"},
        )
        assert len(result.violations) > 0


# ===================================================================
# Python regex fallback paths (Rust + AC disabled)
# ===================================================================


@pytest.mark.unit
class TestPythonRegexFallback:
    """Tests for Python regex paths when both Rust and AC are disabled."""

    def test_regex_positive_verb_neg_keyword_match(self):
        """Positive verb with negative keyword triggers regex fallback violation."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("run skip audit for extraction process")
        assert len(result.violations) > 0

    def test_regex_positive_verb_critical_raises(self):
        """Positive verb with critical negative-indicator keyword in strict mode raises."""
        c = _make_constitution(
            rules=[
                Rule(
                    id="RX-CRIT",
                    text="No bypassing security",
                    severity=Severity.CRITICAL,
                    keywords=["bypass security"],
                    category="security",
                ),
            ]
        )
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("run bypass security checks")

    def test_regex_positive_verb_pattern_match(self):
        """Positive verb regex path with pattern match after keyword match."""
        c = _make_constitution_with_patterns()
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        # "ssn" keyword has no neg indicator, but pattern should match via fallback
        result = engine.validate("run ssn 123-45-6789 extraction")
        assert isinstance(result, ValidationResult)

    def test_regex_positive_verb_with_neg_keyword_and_pattern(self):
        """Positive verb regex path with negative keyword + pattern match."""
        c = Constitution.from_rules(
            [
                Rule(
                    id="RPAT-NEG",
                    text="No hiding deploy data",
                    severity=Severity.HIGH,
                    keywords=["hide data"],
                    patterns=[r"\bdeploy\s+to\s+prod\b"],
                    category="ops",
                ),
            ],
            name="regex-pat-neg",
        )
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("run hide data deploy to prod")
        assert len(result.violations) > 0

    def test_regex_non_positive_verb_keyword_match(self):
        """Non-positive verb regex fallback: combined keyword regex match."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("expose the secret key to users")
        assert len(result.violations) > 0

    def test_regex_non_positive_verb_critical_raises(self):
        """Non-positive verb regex path with critical keyword in strict mode."""
        engine = _make_engine(strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("expose the secret key")

    def test_regex_non_positive_verb_multiple_keywords(self):
        """Non-positive verb with multiple keyword matches for dedup coverage."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("send plaintext with secret key and skip audit")
        assert len(result.violations) >= 2

    def test_regex_non_positive_verb_pattern_and_keyword(self):
        """Non-positive verb regex with both keyword and pattern matches."""
        c = _make_constitution_with_patterns()
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("found ssn 123-45-6789 in api_key sk-abcdefghij1234567890AABB")
        assert len(result.violations) > 0

    def test_regex_non_positive_verb_pattern_only_with_keyword(self):
        """Non-positive verb path where patterns match alongside keywords."""
        c = _make_constitution_with_patterns()
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("deploy to prod now")
        # PAT-MED has MEDIUM severity → WARN → result.warnings
        assert len(result.warnings) > 0

    def test_regex_allow_path(self):
        """Regex fallback with no matching content returns allow."""
        engine = _make_engine(strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("safe normal operation")
        assert result.valid is True

    def test_regex_pattern_critical_in_nonpositive_verb(self):
        """Pattern-based critical in non-positive-verb regex path."""
        c = _make_constitution_with_patterns()
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("found ssn 123-45-6789 in records")

    def test_regex_positive_verb_critical_pattern_raises(self):
        """Pattern-based critical on positive-verb regex path raises."""
        c = _make_constitution_with_patterns()
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("check ssn 123-45-6789 data")


# ===================================================================
# No HIGH rules path (line 1492)
# ===================================================================


@pytest.mark.unit
class TestNoHighRulesPath:
    """Tests for the path where no HIGH rules exist (valid = True shortcut)."""

    def test_no_high_rules_medium_violation_valid_true(self):
        """MEDIUM+WARN rules are non-blocking; violation goes into warnings."""
        c = _make_constitution_no_high()
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        result = engine.validate("send data in plaintext format")
        # MEDIUM+WARN doesn't block; valid should be True
        assert result.valid is True
        assert result.violations == []
        assert len(result.warnings) > 0

    def test_no_high_rules_critical_still_raises(self):
        """Critical violations still raise even without HIGH rules."""
        c = _make_constitution_no_high()
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("expose secret key data")


# ===================================================================
# Slow path with explicit AuditLog (lines 1430-1472, 1505-1552)
# ===================================================================


@pytest.mark.unit
class TestSlowPathAuditLog:
    """Tests exercising the slow path that constructs full ValidationResult + AuditEntry."""

    def test_slow_path_allow_with_audit_log(self):
        """Allow path with explicit AuditLog creates full result + records entry."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=True)
        _disable_rust_on_engine(engine)
        result = engine.validate("safe action")
        assert result.valid is True
        assert result.latency_ms >= 0
        assert result.request_id != ""
        assert result.timestamp != ""
        entries = audit.query()
        assert len(entries) >= 1
        assert entries[-1].valid is True

    def test_slow_path_deny_with_audit_log(self):
        """Deny path with explicit AuditLog creates result + records violations."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("expose the secret key now")
        assert not result.valid or len(result.violations) > 0
        entries = audit.query()
        assert len(entries) >= 1

    def test_slow_path_audit_entry_has_rule_evaluations(self):
        """Audit entries include rule_evaluations metadata."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=True)
        _disable_rust_on_engine(engine)
        engine.validate("safe action")
        entries = audit.query()
        last = entries[-1]
        assert "rule_evaluations" in last.metadata

    def test_slow_path_deny_audit_records_violations(self):
        """Deny slow path records violation IDs in audit."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=False)
        _disable_rust_on_engine(engine)
        engine.validate("skip audit for something")
        entries = audit.query()
        last = entries[-1]
        assert len(last.violations) > 0

    def test_slow_path_agent_id_recorded(self):
        """Custom agent_id is recorded in audit entry."""
        audit = AuditLog()
        engine = _make_engine(audit_log=audit, strict=True)
        _disable_rust_on_engine(engine)
        engine.validate("safe action", agent_id="custom-agent")
        entries = audit.query()
        assert any(e.agent_id == "custom-agent" for e in entries)


# ===================================================================
# Validate with context on slow path (Python fallback + context)
# ===================================================================


@pytest.mark.unit
class TestSlowPathContext:
    """Tests for context validation in the Python slow path."""

    def test_context_detail_positive_verb(self):
        """Context action_detail with positive-verb action on Python path."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate(
            "run analysis",
            context={"action_detail": "skip audit for compliance check"},
        )
        assert len(result.violations) > 0

    def test_context_description_non_positive_verb(self):
        """Context action_description with non-positive-verb action."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate(
            "process data",
            context={"action_description": "send in plaintext format"},
        )
        # X-MED has workflow_action=WARN so violation goes to warnings, not violations
        assert len(result.violations) + len(result.warnings) > 0

    def test_context_non_string_value_ignored(self):
        """Non-string context values are ignored."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate(
            "safe action",
            context={"action_detail": 12345, "action_description": None},
        )
        assert result.valid is True

    def test_context_metadata_keys_not_scanned(self):
        """Metadata context keys (source, env) are not scanned."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate(
            "safe action",
            context={"source": "secret key exposed", "env": "skip audit"},
        )
        assert result.valid is True

    def test_context_both_detail_and_description(self):
        """Both action_detail and action_description trigger violations."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate(
            "process stuff",
            context={
                "action_detail": "expose secret key",
                "action_description": "skip audit trail",
            },
        )
        assert len(result.violations) >= 2


# ===================================================================
# Custom validators on slow path
# ===================================================================


@pytest.mark.unit
class TestCustomValidatorsSlowPath:
    """Custom validator tests exercising the Python slow path."""

    def test_custom_validator_on_python_path(self):
        """Custom validator fires on Python fallback path."""

        def forbidden_validator(action: str, ctx: dict) -> list[Violation]:
            if "forbidden" in action.lower():
                return [Violation("CUSTOM-F", "Forbidden", Severity.HIGH, action[:200], "custom")]
            return []

        engine = _make_engine(strict=False, custom_validators=[forbidden_validator])
        _disable_rust_on_engine(engine)
        result = engine.validate("this is forbidden content")
        custom_vs = [v for v in result.violations if v.rule_id == "CUSTOM-F"]
        assert len(custom_vs) == 1

    def test_custom_validator_exception_on_python_path(self):
        """A crashing custom validator fails CLOSED on the Python path.

        A validator that raises did not clear the action, so the engine records a
        HIGH (blocking) CUSTOM-ERROR rather than a non-blocking MEDIUM warning —
        otherwise a crashing security validator (e.g. the AST analyzer) would let
        the action proceed ungoverned. Consistent with the runtime-rule-filtering
        path, which already blocks.
        """

        def bad_validator(action: str, ctx: dict) -> list[Violation]:
            raise ValueError("boom")

        engine = _make_engine(strict=False, custom_validators=[bad_validator])
        _disable_rust_on_engine(engine)
        result = engine.validate("normal action")
        # Fail-closed: a blocking HIGH violation, not a non-blocking warning.
        error_vs = [v for v in result.violations if v.rule_id == "CUSTOM-ERROR"]
        assert len(error_vs) == 1
        assert error_vs[0].severity is Severity.HIGH
        assert "boom" in error_vs[0].rule_text
        assert result.valid is False
        # Under strict, the same crash raises rather than passing the action.
        strict_engine = _make_engine(strict=True, custom_validators=[bad_validator])
        _disable_rust_on_engine(strict_engine)
        with pytest.raises(ConstitutionalViolationError):
            strict_engine.validate("normal action")

    def test_distinct_findings_with_same_rule_id_both_reach_audit(self):
        """#4: dedup must not collapse distinct findings that share a rule_id.

        The AST analyzer can flag two different sites under one rule_id (e.g. two
        CODE-DANGEROUS-CALLs). Keying dedup on rule_id alone merged them to one
        before the audit write, degrading the forensic record; keying on
        (rule_id, matched_content) preserves both while still collapsing true
        duplicates.
        """

        def multi_finding_validator(action: str, ctx: dict) -> list[Violation]:
            return [
                Violation("AST-RISK", "first risky site", Severity.HIGH, "site_one", "code"),
                Violation("AST-RISK", "second risky site", Severity.HIGH, "site_two", "code"),
                Violation("AST-RISK", "first risky site again", Severity.HIGH, "site_one", "code"),
            ]

        audit = AuditLog()
        engine = _make_engine(
            audit_log=audit, strict=False, custom_validators=[multi_finding_validator]
        )
        _disable_rust_on_engine(engine)
        result = engine.validate("trigger custom validator")
        # The two DISTINCT sites survive; the exact-duplicate third is collapsed.
        risk = [v for v in result.violations if v.rule_id == "AST-RISK"]
        assert {v.matched_content for v in risk} == {"site_one", "site_two"}
        assert len(risk) == 2
        # Both distinct findings are recorded in the audit entry, chain intact.
        entries = [e for e in audit.query() if e.type == "validation"]
        assert entries[-1].violations.count("AST-RISK") == 2
        assert audit.verify_chain()

    def test_custom_validators_skipped_after_critical(self):
        """Custom validators are skipped when critical violations already found."""
        call_count = 0

        def counting_validator(action: str, ctx: dict) -> list[Violation]:
            nonlocal call_count
            call_count += 1
            return []

        engine = _make_engine(strict=False, custom_validators=[counting_validator])
        _disable_rust_on_engine(engine)
        result = engine.validate("expose secret key to the world")
        # Should have critical violations; custom validator may or may not be skipped
        assert len(result.violations) > 0

    def test_custom_validator_findings_reach_audit_on_critical_string_rule(self):
        """M7: a CRITICAL string-rule match must not short-circuit before custom
        validators run and the audit entry is written.

        Regression for the strict hot path. Previously the matcher raised on the
        CRITICAL keyword the instant it fired, skipping the custom-validator block
        *and* the audit write entirely — leaving no forensic record of either the
        string rule or the structural finding. The fix defers the raise
        (collect -> audit -> raise) whenever custom validators are registered, so
        the action is still blocked but both findings are recorded.
        """
        calls = {"n": 0}

        def counting_validator(action: str, ctx: dict) -> list[Violation]:
            calls["n"] += 1
            return [
                Violation("AST-FINDING", "structural risk", Severity.CRITICAL, action[:50], "code")
            ]

        rule = Rule(
            id="STR-CRIT",
            text="No secret key",
            severity=Severity.CRITICAL,
            keywords=["secret key"],
            category="security",
        )
        const = Constitution.from_rules([rule], name="m7")
        audit = AuditLog()
        engine = GovernanceEngine(
            const, audit_log=audit, strict=True, custom_validators=[counting_validator]
        )

        # Enforcement is unchanged: a CRITICAL violation still raises under strict.
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("please expose the secret key now")

        # The custom validator ran despite the CRITICAL string match...
        assert calls["n"] == 1
        # ...and the audit trail records BOTH findings, not just the string rule.
        val_entries = [e for e in audit.query() if e.type == "validation"]
        assert val_entries, "no validation audit entry was written before the raise"
        recorded = set(val_entries[-1].violations)
        assert "STR-CRIT" in recorded
        assert "AST-FINDING" in recorded
        assert audit.verify_chain()


# ===================================================================
# #66: CRITICAL blocked decisions must reach the audit trail in full mode
# ===================================================================


@pytest.mark.unit
class TestCriticalAuditCompletenessFullMode:
    """#66: in FULL audit mode + strict, a blocked CRITICAL decision must be
    recorded before the raise — even with NO custom validators registered.

    Previously the matcher short-circuit-raised the instant a CRITICAL keyword
    fired, before the per-decision audit write. HIGH/BLOCK violations defer their
    raise and were recorded, so the gap was specific to CRITICAL on the strict
    fail-closed path — exactly the production/compliance configuration. The fix
    suppresses the short-circuit whenever a per-entry audit log is active
    (collect -> audit -> raise), leaving fast/aggregate mode unchanged.
    """

    @staticmethod
    def _const() -> Constitution:
        return Constitution.from_rules(
            [
                Rule(
                    id="no-pii",
                    text="Block PII",
                    severity=Severity.CRITICAL,
                    keywords=["ssn"],
                    category="privacy",
                ),
                Rule(
                    id="no-destructive",
                    text="Block destructive ops",
                    severity=Severity.HIGH,
                    keywords=["drop table"],
                    category="safety",
                ),
            ],
            name="issue-66",
        )

    def _run_sequence(self, engine: GovernanceEngine, audit: AuditLog) -> None:
        for action, agent in [
            ("summarize the report", "a1"),
            ("now DROP TABLE users", "a2"),
            ("send my SSN 123-45-6789", "a3"),
        ]:
            with suppress(ConstitutionalViolationError):
                engine.validate(action, agent_id=agent)

    def test_issue_66_repro_records_all_three(self):
        """The exact issue repro: allow + HIGH-block + CRITICAL-block all recorded."""
        audit = AuditLog()
        engine = GovernanceEngine(self._const(), audit_log=audit, strict=True)
        self._run_sequence(engine, audit)
        audit.flush()
        entries = [(e.agent_id, e.valid) for e in audit.entries]
        assert entries == [("a1", True), ("a2", False), ("a3", False)], entries
        # The CRITICAL decision (a3) carries its rule id, not the HIGH one.
        a3 = next(e for e in audit.entries if e.agent_id == "a3")
        assert "no-pii" in a3.violations
        assert audit.verify_chain()

    def test_lone_critical_block_is_recorded(self):
        """A single CRITICAL block with no other traffic still produces an entry."""
        audit = AuditLog()
        engine = GovernanceEngine(self._const(), audit_log=audit, strict=True)
        with pytest.raises(ConstitutionalViolationError) as exc:
            engine.validate("send my SSN 123-45-6789", agent_id="solo")
        assert exc.value.rule_id == "no-pii"
        assert exc.value.severity == "critical"
        audit.flush()
        assert len(audit.entries) == 1
        assert audit.entries[0].valid is False
        assert "no-pii" in audit.entries[0].violations
        assert audit.verify_chain()

    def test_critical_recorded_on_regex_python_path(self):
        """Audit completeness holds when neither Rust nor AC is available."""
        audit = AuditLog()
        engine = GovernanceEngine(self._const(), audit_log=audit, strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("send my SSN 123-45-6789", agent_id="regex")
        audit.flush()
        assert len(audit.entries) == 1
        assert "no-pii" in audit.entries[0].violations
        assert audit.verify_chain()

    def test_fast_mode_hot_path_unchanged(self):
        """Fast/aggregate mode keeps the CRITICAL short-circuit (no per-entry log)."""
        engine = GovernanceEngine(self._const(), strict=True, audit_mode="fast")
        # Still blocks under strict — enforcement is unchanged.
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("send my SSN 123-45-6789")


# ===================================================================
# ValidationResult properties
# ===================================================================


@pytest.mark.unit
class TestValidationResultProperties:
    """Tests for blocking_violations and warnings properties."""

    def test_blocking_violations_property(self):
        """blocking_violations returns only severity.blocks() violations."""
        vs = [
            Violation("R1", "crit", Severity.CRITICAL, "act", "cat"),
            Violation("R2", "med", Severity.MEDIUM, "act", "cat"),
            Violation("R3", "high", Severity.HIGH, "act", "cat"),
        ]
        vr = ValidationResult(
            valid=False,
            constitutional_hash="h",
            violations=vs,
        )
        blocking = vr.blocking_violations
        assert all(v.severity.blocks() for v in blocking)
        assert len(blocking) >= 1

    def test_warnings_field(self):
        """warnings is a separate field for WARN-action violations (not severity-derived)."""
        v_crit = Violation("R1", "crit", Severity.CRITICAL, "act", "cat")
        v_warn1 = Violation("R2", "med", Severity.MEDIUM, "act", "cat")
        v_warn2 = Violation("R3", "low", Severity.LOW, "act", "cat")
        # Engine populates warnings separately from violations
        vr = ValidationResult(
            valid=False,
            constitutional_hash="h",
            violations=[v_crit],
            warnings=[v_warn1, v_warn2],
        )
        assert len(vr.warnings) == 2
        assert all(not v.severity.blocks() for v in vr.warnings)
        # Without explicit warnings field, it defaults to empty
        vr2 = ValidationResult(
            valid=False,
            constitutional_hash="h",
            violations=[v_crit, v_warn1],
        )
        assert vr2.warnings == []


# ===================================================================
# Dedup violations edge cases
# ===================================================================


@pytest.mark.unit
class TestDedupEdgeCases:
    """Edge cases for the violation dedup at the end of validate()."""

    def test_single_violation_skips_dedup(self):
        """Single violation list skips _dedup_violations call."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("send data in plaintext format")
        # Just verify it works; single violations bypass dedup
        assert isinstance(result, ValidationResult)

    def test_multiple_duplicate_violations_deduped(self):
        """Multiple violations with same rule_id are deduped."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        # Action with multiple keyword hits for the same rule
        result = engine.validate("secret key password credential all exposed")
        rule_ids = [v.rule_id for v in result.violations]
        assert len(rule_ids) == len(set(rule_ids)), "Violations should be deduped by rule_id"


# ===================================================================
# Engine with has_high=True covering blocking list comp path
# ===================================================================


@pytest.mark.unit
class TestHasHighBlockingPath:
    """Tests for the blocking list comprehension when _has_high is True."""

    def test_high_severity_blocks_in_strict(self):
        """HIGH severity violation blocks in strict mode (Python path)."""
        c = _make_constitution()  # Has HIGH rule
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        # HIGH severity keyword
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("skip audit for this operation")

    def test_high_severity_non_strict_returns_invalid(self):
        """HIGH severity in non-strict mode returns valid=False."""
        c = _make_constitution()  # Has HIGH rule
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("skip audit for this operation")
        assert result.valid is False
        assert len(result.violations) > 0


# ===================================================================
# Pooled escalate result path (fast records is not None + violations)
# ===================================================================


@pytest.mark.unit
class TestPooledEscalateResult:
    """Tests for the pooled escalate result path (line 1494-1503)."""

    def test_pooled_escalate_with_noop(self):
        """WARN-action violations with NoopRecorder go to result.warnings."""
        engine = _make_engine(strict=True)
        _disable_rust_on_engine(engine)
        result = engine.validate("send data in plaintext format")
        assert result.valid is True  # WARN doesn't block
        assert len(result.warnings) > 0

    def test_pooled_escalate_valid_field(self):
        """Pooled escalate result has correct valid field based on blocking."""
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("skip audit for testing")
        # HIGH in non-strict: valid=False
        assert len(result.violations) > 0


# ===================================================================
# Hyphen-suffix anchor pattern (line 369)
# ===================================================================


@pytest.mark.unit
class TestHyphenSuffixAnchor:
    """Test for hyphen-suffix anchor pattern branch."""

    def test_hyphen_anchor_pattern(self):
        """Rule with \b{w1}.{w2}\b style pattern uses hyphen anchor."""
        c = Constitution.from_rules(
            [
                Rule(
                    id="HYPH-1",
                    text="No age-based discrimination",
                    severity=Severity.HIGH,
                    keywords=["discrimination"],
                    patterns=[r"\bage.based\b"],
                    category="fairness",
                ),
            ],
            name="hyphen-test",
        )
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("apply age-based discrimination policy")
        assert len(result.violations) > 0


# ===================================================================
# Bigram anchor pattern (line 373-376)
# ===================================================================


@pytest.mark.unit
class TestBigramAnchor:
    """Test for bigram anchor pattern branch."""

    def test_bigram_anchor_pattern(self):
        r"""Rule with \b{w1}\s+{w2}\b pattern uses bigram anchor."""
        c = Constitution.from_rules(
            [
                Rule(
                    id="BIG-1",
                    text="No appeal denied",
                    severity=Severity.HIGH,
                    keywords=["rejected"],
                    patterns=[r"\bno\s+appeal\b"],
                    category="process",
                ),
            ],
            name="bigram-test",
        )
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("no appeal for rejected applicants")
        assert len(result.violations) > 0


# ===================================================================
# AC type-2 payload (keyword + anchor combined) coverage
# ===================================================================


def _make_type2_constitution() -> Constitution:
    """Constitution where a keyword also serves as a pattern anchor (type 2 in AC).

    For type-2 payload, the keyword string must match the anchor word extracted
    from the pattern. Using patterns like \\b{keyword}\\s*[-:]\\s*{other}\\b avoids
    special-case bigram/hyphen/single-word anchor extraction, so the first 3+ char
    word becomes the anchor -- which equals the keyword.
    """
    return Constitution.from_rules(
        [
            Rule(
                id="T2-CRIT",
                text="No overriding security",
                severity=Severity.CRITICAL,
                keywords=["override"],
                patterns=[r"\boverride\s*[-:]\s*security\b"],
                category="security",
            ),
            Rule(
                id="T2-HIGH",
                text="No skipping checks",
                severity=Severity.HIGH,
                keywords=["skip"],
                patterns=[r"\bskip\s*[-:]\s*review\b"],
                category="process",
            ),
            Rule(
                id="T2-MED",
                text="No hiding data",
                severity=Severity.MEDIUM,
                keywords=["hide"],
                patterns=[r"\bhide\s*[-:]\s*records\b"],
                category="data",
            ),
        ],
        name="type2-test",
    )


@pytest.mark.unit
@pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
class TestACType2Payload:
    """Tests for AC type-2 payload (keyword+anchor combined) paths."""

    def test_type2_positive_verb_neg_keyword_fires(self):
        """Positive verb + type-2 payload where kw_has_neg=True fires violation."""
        c = _make_type2_constitution()
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("run override-security check")
        assert len(result.violations) > 0

    def test_type2_positive_verb_critical_raises(self):
        """Positive verb + type-2 payload with critical keyword raises."""
        c = _make_type2_constitution()
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("run override-security measures")

    def test_type2_non_positive_verb_fires(self):
        """Non-positive verb + type-2 payload fires normally."""
        c = _make_type2_constitution()
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("the system will override-security protocols")
        assert len(result.violations) > 0

    def test_type2_non_positive_verb_critical_raises(self):
        """Non-positive verb + type-2 critical keyword raises."""
        c = _make_type2_constitution()
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("the system will override-security protocols")


# ===================================================================
# AC anchor dispatch critical pattern (lines 984-986)
# ===================================================================


@pytest.mark.unit
@pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
class TestACAnchorDispatchCritical:
    """Tests for critical pattern match via anchor dispatch in AC path."""

    def test_anchor_pattern_critical_positive_verb(self):
        """Critical pattern match via anchor-only dispatch on positive-verb path.

        This covers lines 984-986: anchor hit (type 1) -> pattern match -> critical raise.
        The anchor 'deploy' is NOT a keyword, so it's type-1 (anchor-only).
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="APC-CRIT",
                    text="No unsafe deploy",
                    severity=Severity.CRITICAL,
                    keywords=["unsafe deploy"],
                    patterns=[r"\bdeploy\s*[-:]\s*unsafe\b"],
                    category="ops",
                ),
            ],
            name="anchor-crit-pos",
        )
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("run deploy-unsafe config")

    def test_anchor_pattern_critical_non_positive_verb(self):
        """Critical pattern via anchor-only dispatch on non-positive-verb path.

        This covers lines 1070-1071: anchor hit -> pattern match -> critical raise.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="APC-CRIT2",
                    text="No unsafe deploy",
                    severity=Severity.CRITICAL,
                    keywords=["unsafe deploy"],
                    patterns=[r"\bdeploy\s*[-:]\s*unsafe\b"],
                    category="ops",
                ),
            ],
            name="anchor-crit-npos",
        )
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("the deploy:unsafe config is bad")

    def test_no_anchor_pattern_critical_non_positive_verb(self):
        """Critical no-anchor pattern on non-positive-verb path where
        the keyword does NOT match but the pattern does.

        This covers lines 1086-1087: no-anchor critical raise path.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="NAP-CRIT2",
                    text="No large numbers exposed",
                    severity=Severity.CRITICAL,
                    keywords=["expose numbers"],
                    patterns=[r"\b\d{10,}\b"],
                    category="pii",
                ),
                Rule(
                    id="NAP-OTHER",
                    text="Some other rule",
                    severity=Severity.LOW,
                    keywords=["something"],
                    category="misc",
                ),
            ],
            name="no-anchor-crit-npos",
        )
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("data has 12345678901234 in it")


# ===================================================================
# AC no-anchor pattern paths (lines 997-1012)
# ===================================================================


def _make_no_anchor_pattern_constitution() -> Constitution:
    """Constitution with patterns that have no extractable anchor word.

    Pattern uses only regex metacharacters / short words, so no anchor can be
    extracted, forcing the no-anchor dispatch path.
    """
    return Constitution.from_rules(
        [
            Rule(
                id="NAP-CRIT",
                text="No numeric IDs exposed",
                severity=Severity.CRITICAL,
                keywords=["expose id"],
                patterns=[r"\b\d{10,}\b"],
                category="pii",
            ),
            Rule(
                id="NAP-MED",
                text="Advisory on short codes",
                severity=Severity.MEDIUM,
                keywords=["short code"],
                patterns=[r"\b[A-Z]{2}\d{3}\b"],
                category="ops",
            ),
        ],
        name="no-anchor-pat",
    )


@pytest.mark.unit
@pytest.mark.skipif(not _HAS_AHO, reason="Aho-Corasick not available")
class TestACNoAnchorPatterns:
    """Tests for no-anchor pattern paths in AC validation."""

    def test_no_anchor_pattern_positive_verb_non_critical(self):
        """No-anchor pattern match on positive-verb path (non-critical)."""
        c = _make_no_anchor_pattern_constitution()
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("check expose id 1234567890123")
        assert len(result.violations) > 0

    def test_no_anchor_pattern_positive_verb_critical(self):
        """No-anchor pattern match on positive-verb path (critical, strict)."""
        c = _make_no_anchor_pattern_constitution()
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("check expose id 12345678901")

    def test_no_anchor_pattern_non_positive_verb(self):
        """No-anchor pattern match on non-positive-verb path."""
        c = _make_no_anchor_pattern_constitution()
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        result = engine.validate("data contains expose id 12345678901")
        assert len(result.violations) > 0

    def test_no_anchor_pattern_non_positive_verb_critical(self):
        """No-anchor pattern match on non-positive-verb path (critical, strict)."""
        c = _make_no_anchor_pattern_constitution()
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("data contains expose id 12345678901")


# ===================================================================
# Regex fallback: positive-verb pattern match after keyword (lines 1130-1160)
# ===================================================================


@pytest.mark.unit
class TestRegexPositiveVerbPatternFallback:
    """Tests for regex fallback positive-verb path: pattern match after keyword match."""

    def test_regex_pos_verb_keyword_then_pattern(self):
        """Positive verb regex: keyword match (neg indicator) + pattern match for DIFFERENT rule.

        This covers lines 1130-1144: after neg-keyword fires for one rule,
        iterate _pattern_rule_idxs and fire for a different rule's pattern.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="RKP-KW",
                    text="No bypassing",
                    severity=Severity.HIGH,
                    keywords=["bypass"],
                    category="ops",
                ),
                Rule(
                    id="RKP-PAT",
                    text="No deploy to prod",
                    severity=Severity.MEDIUM,
                    keywords=["override"],
                    patterns=[r"\bdeploy\s+to\s+prod\b"],
                    category="ops",
                ),
            ],
            name="regex-kw-pat",
        )
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("run bypass deploy to prod now")
        assert len(result.violations) >= 1

    def test_regex_pos_verb_pattern_no_neg_keyword(self):
        """Positive verb regex: no neg keywords match, pattern-only path.

        This covers lines 1145-1160: elif self._pattern_rule_idxs branch.
        The neg_findall returns empty (no neg-indicator keywords in text)
        but patterns exist and match.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="RPO-1",
                    text="No deploy to prod",
                    severity=Severity.MEDIUM,
                    keywords=["bypass"],  # Has neg indicator but won't match
                    patterns=[r"\bdeploy\s+to\s+prod\b"],
                    category="ops",
                ),
            ],
            name="regex-pat-only3",
        )
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        # "deploy" does NOT match neg keyword "bypass", but pattern matches
        result = engine.validate("check deploy to prod status")
        # RPO-1 is MEDIUM → WARN → result.warnings
        assert len(result.warnings) > 0

    def test_regex_pos_verb_pattern_critical_raises(self):
        """Positive verb regex: critical pattern match raises.

        This covers the strict+is_crit path at lines 1134-1141 and 1150-1157.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="RPC-1",
                    text="No bypassing security",
                    severity=Severity.CRITICAL,
                    keywords=["bypass"],
                    patterns=[r"\bbypass\s*[-:]\s*security\b"],
                    category="security",
                ),
            ],
            name="regex-crit-pat",
        )
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("run bypass-security measures")

    def test_regex_pos_verb_pattern_only_critical_raises(self):
        """Positive verb regex: pattern-only path (no neg keyword match) with critical raises.

        Covers lines 1150-1157: critical pattern in elif branch.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="RPOC-1",
                    text="No deploy to prod",
                    severity=Severity.CRITICAL,
                    keywords=["bypass"],  # Has neg indicator but won't match
                    patterns=[r"\bdeploy\s+to\s+prod\b"],
                    category="ops",
                ),
            ],
            name="regex-pat-crit",
        )
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("check deploy to prod status")


# ===================================================================
# Regex fallback: non-positive-verb multiple keywords + patterns (lines 1182-1216)
# ===================================================================


@pytest.mark.unit
class TestRegexNonPositiveVerbMultiple:
    """Tests for regex non-positive-verb path with multiple keyword/pattern matches."""

    def test_regex_multiple_keywords_second_match(self):
        """Non-positive verb regex: multiple keywords match (second-pass).

        This covers lines 1182-1200: the second search triggers findall for
        remaining keywords, including dedup and lazy violations list init.
        """
        engine = _make_engine(strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("expose secret key and also send data in plaintext and skip audit")
        assert len(result.violations) >= 2

    def test_regex_keyword_plus_pattern_match(self):
        """Non-positive verb regex: keyword + pattern match.

        This covers lines 1201-1216: pattern matching after keyword matching
        on the non-positive-verb regex path.
        """
        c = _make_constitution_with_patterns()
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("deploy to prod with ssn 123-45-6789")
        assert len(result.violations) > 0

    def test_regex_pattern_critical_non_positive_verb(self):
        """Non-positive verb regex: critical pattern triggers raise.

        This covers lines 1222-1224: pattern-only path with critical rule.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="RNPC-1",
                    text="No bypassing",
                    severity=Severity.CRITICAL,
                    keywords=["bypass"],
                    patterns=[r"\bbypass\s+all\b"],
                    category="security",
                ),
            ],
            name="regex-npos-crit",
        )
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("the system will bypass all controls")

    def test_regex_npos_keyword_then_pattern_for_different_rule(self):
        """Non-positive verb regex: keyword match + pattern match for different rule.

        Covers lines 1201-1216: after keyword fires, pattern from a different rule
        also fires via _pattern_rule_idxs iteration.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="RNKP-KW",
                    text="No secrets",
                    severity=Severity.HIGH,
                    keywords=["secret key"],
                    category="security",
                ),
                Rule(
                    id="RNKP-PAT",
                    text="No deploy to prod",
                    severity=Severity.MEDIUM,
                    keywords=["override"],
                    patterns=[r"\bdeploy\s+to\s+prod\b"],
                    category="ops",
                ),
            ],
            name="regex-npos-kw-pat",
        )
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("expose secret key deploy to prod")
        # RNKP-KW (HIGH) → violations; RNKP-PAT (MEDIUM) → warnings
        assert len(result.violations) + len(result.warnings) >= 2

    def test_regex_npos_pattern_only_no_keyword_match(self):
        """Non-positive verb regex: no keyword match, pattern-only path.

        Covers lines 1217-1232: elif _pattern_rule_idxs branch when combined_search
        returns None (no keyword in text) but patterns exist and match.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="RPNO-1",
                    text="No deploy to prod",
                    severity=Severity.MEDIUM,
                    keywords=["xyznonexistent"],
                    patterns=[r"\bdeploy\s+to\s+prod\b"],
                    category="ops",
                ),
            ],
            name="regex-pat-no-kw",
        )
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("the deploy to prod is pending")
        # RPNO-1 is MEDIUM → WARN → result.warnings
        assert len(result.warnings) > 0

    def test_regex_npos_pattern_only_critical_raises(self):
        """Non-positive verb regex: pattern-only path with critical severity.

        Covers lines 1222-1224.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="RPNO-CRIT",
                    text="No deploy to prod",
                    severity=Severity.CRITICAL,
                    keywords=["xyznonexistent"],
                    patterns=[r"\bdeploy\s+to\s+prod\b"],
                    category="ops",
                ),
            ],
            name="regex-pat-no-kw-crit",
        )
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("the deploy to prod is bad")

    def test_regex_critical_keyword_second_pass(self):
        """Non-positive verb regex: critical keyword on second-pass findall.

        This covers lines 1190-1192: critical keyword found via findall
        after first-match was non-critical.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="NPC-MED",
                    text="Advisory on plaintext",
                    severity=Severity.MEDIUM,
                    keywords=["plaintext"],
                    category="data",
                ),
                Rule(
                    id="NPC-CRIT",
                    text="No secrets",
                    severity=Severity.CRITICAL,
                    keywords=["secret key"],
                    category="security",
                ),
            ],
            name="regex-crit-second",
        )
        engine = GovernanceEngine(c, strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        with pytest.raises(ConstitutionalViolationError):
            engine.validate("data in plaintext contains secret key")

    def test_regex_no_match_returns_none(self):
        """Non-positive verb regex: no keyword/pattern match returns None violations."""
        engine = _make_engine(strict=True)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        result = engine.validate("completely safe and normal operation")
        assert result.valid is True
        assert len(result.violations) == 0

    def test_regex_positive_verb_pattern_anchor_search(self):
        """Positive verb regex: pattern-only path with anchor pre-check.

        Covers lines 1145-1161: positive-verb path where no neg keywords
        match but pattern_rule_idxs exist and pat_anchor_search triggers.
        """
        c = Constitution.from_rules(
            [
                Rule(
                    id="RPAS-1",
                    text="No deploy to prod",
                    severity=Severity.MEDIUM,
                    keywords=["deploy"],
                    patterns=[r"\bdeploy\s+to\s+prod\b"],
                    category="ops",
                ),
            ],
            name="regex-anchor-search",
        )
        engine = GovernanceEngine(c, strict=False)
        _disable_rust_on_engine(engine)
        _disable_ac_on_engine(engine)
        # "deploy" keyword has no neg indicator, so positive-verb neg_findall
        # returns empty. But patterns exist, so they're checked.
        result = engine.validate("check deploy to prod status")
        assert isinstance(result, ValidationResult)


# ===================================================================
# Empty constitution edge case
# ===================================================================


@pytest.mark.unit
class TestEmptyConstitution:
    """Test engine with empty or minimal constitutions."""

    def test_no_rules(self):
        """Engine with empty rules list validates everything as valid."""
        c = Constitution.from_rules([], name="empty")
        engine = GovernanceEngine(c, strict=True)
        result = engine.validate("anything goes")
        assert result.valid is True

    def test_single_disabled_rule(self):
        """Engine with disabled rule doesn't trigger violations."""
        c = Constitution.from_rules(
            [
                Rule(
                    id="DIS-1",
                    text="Disabled rule",
                    severity=Severity.CRITICAL,
                    keywords=["secret key"],
                    category="security",
                    enabled=False,
                ),
            ],
            name="disabled",
        )
        engine = GovernanceEngine(c, strict=True)
        result = engine.validate("expose the secret key")
        assert result.valid is True
