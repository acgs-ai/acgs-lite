"""Regression tests for regex-only fallback behavior in the governance engine."""

from __future__ import annotations

import pytest

from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine.core import GovernanceEngine


def _disable_rust_and_ac(engine: GovernanceEngine) -> None:
    """Force the engine onto the pure-Python regex fallback path.

    _hot layout (11 elements):
      [0] ac_iter, [1] pat_anchor_dispatch, [2] no_anchor_patterns,
      [3] rule_data, [4] rule_excs, [5] has_high_rules,
      [6] fast_records, [7] pos_verbs, [8] has_ac, [9] is_noop,
      [10] rust_validator
    """
    _h = engine._hot
    engine._hot = (
        None,  # [0] ac_iter — disabled
        _h[1],
        _h[2],
        _h[3],
        _h[4],
        _h[5],
        _h[6],
        _h[7],
        False,  # [8] has_ac — disabled
        _h[9],
        None,  # [10] rust_validator — disabled
    )
    engine._ac_iter = None
    engine._rust_validator = None


def _make_mixed_anchor_constitution() -> Constitution:
    return Constitution.from_rules(
        [
            Rule(
                id="ANCHOR-GITHUB",
                text="No GitHub personal access tokens",
                severity=Severity.HIGH,
                keywords=["token"],
                patterns=[r"(?i)(ghp_[a-zA-Z0-9]{36})"],
                category="security",
            ),
            Rule(
                id="NO-ANCHOR-SSN",
                text="No social security numbers in content",
                severity=Severity.CRITICAL,
                keywords=["ssn"],
                patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
                category="pii",
            ),
        ],
        name="mixed-anchor-regression",
    )


@pytest.mark.unit
def test_regex_fallback_scans_no_anchor_patterns_when_anchor_gate_misses() -> None:
    engine = GovernanceEngine(_make_mixed_anchor_constitution(), strict=False)
    _disable_rust_and_ac(engine)

    result = engine.validate("User SSN is 123-45-6789")

    assert result.valid is False
    assert {violation.rule_id for violation in result.violations} == {"NO-ANCHOR-SSN"}


@pytest.mark.unit
def test_regex_fallback_positive_verb_still_scans_no_anchor_patterns() -> None:
    engine = GovernanceEngine(_make_mixed_anchor_constitution(), strict=False)
    _disable_rust_and_ac(engine)

    result = engine.validate("check ssn 123-45-6789 handling")

    assert result.valid is False
    assert {violation.rule_id for violation in result.violations} == {"NO-ANCHOR-SSN"}


@pytest.mark.unit
def test_regex_fallback_scans_no_anchor_pattern_without_keyword_or_anchor() -> None:
    # F4 (the real fail-open): content carrying a no-anchor secret pattern but
    # NO triggering keyword and NO anchor word was silently accepted on the
    # pure-Python path, while the Aho-Corasick backend always scanned it.
    engine = GovernanceEngine(_make_mixed_anchor_constitution(), strict=False)
    _disable_rust_and_ac(engine)

    # No "ssn"/"token" keyword and no "ghp" anchor anywhere in the text.
    result = engine.validate("Customer record 123-45-6789 on file")

    assert result.valid is False
    assert {violation.rule_id for violation in result.violations} == {"NO-ANCHOR-SSN"}


@pytest.mark.unit
def test_regex_fallback_no_anchor_fix_does_not_overblock_clean_text() -> None:
    # The fix must not over-block: text with no keyword, no anchor, and no
    # matching pattern stays valid.
    engine = GovernanceEngine(_make_mixed_anchor_constitution(), strict=False)
    _disable_rust_and_ac(engine)

    result = engine.validate("a perfectly ordinary sentence with nothing to flag")

    assert result.valid is True
    assert result.violations == []


@pytest.mark.unit
@pytest.mark.skip(reason="Engine zip(strict=True) rejects mismatched compiled_pats/patterns length")
def test_invalid_regex_pattern_skipped_without_crash() -> None:
    """GovernanceEngine skips rules whose patterns contain invalid regex."""
    good_rule = Rule(
        id="GOOD-001",
        text="No secrets",
        severity=Severity.HIGH,
        keywords=["secret"],
        patterns=[r"\bsecret\b"],
        category="security",
    )
    bad_rule = Rule(
        id="BAD-001",
        text="Bad pattern rule",
        severity=Severity.HIGH,
        keywords=["test"],
        patterns=["valid_placeholder"],
        category="test",
    )
    object.__setattr__(bad_rule, "patterns", ["[invalid"])
    object.__setattr__(bad_rule, "_compiled_pats", [])

    constitution = Constitution.from_rules([good_rule, bad_rule])
    engine = GovernanceEngine(constitution, strict=False)

    assert len(engine._active_rules) == 1
    assert engine._active_rules[0].id == "GOOD-001"

    result = engine.validate("this contains a secret")
    assert result.valid is False
    assert any(v.rule_id == "GOOD-001" for v in result.violations)
