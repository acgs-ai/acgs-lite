"""Tests for ConstitutionDeployer.deploy_approved_rules."""

from __future__ import annotations

import logging

import pytest

from acgs_lite.constitution.constitution import Constitution
from acgs_lite.constitution.rule import Rule, Severity
from acgs_lite.engine.constitution_deployer import ConstitutionDeployer
from acgs_lite.engine.core import GovernanceEngine
from acgs_lite.engine.synthesis import SuggestedRule

_XFAIL_REASON = (
    "model_copy at engine/constitution_deployer.py:56 skips model_post_init, so "
    "(a) hash and active-rules cache are stale and the deployed rule is not "
    "enforced, and (b) the new rules skip _validate_rules"
)


@pytest.fixture
def base() -> Constitution:
    return Constitution.from_rules(
        [Rule(id="R-DEL", text="no deletes", severity=Severity.HIGH, keywords=["delete"])]
    )


@pytest.fixture
def suggested() -> SuggestedRule:
    return SuggestedRule(
        rule_id="SYN-1",
        rule_text="no exfiltration",
        severity=Severity.HIGH,
        category="data",
        rationale="r",
        confidence=0.9,
        based_on_patterns=["p"],
        keywords=["exfiltrate"],
    )


@pytest.mark.parametrize("confidence", [0.5, 0.669, 0.0])
def test_below_threshold_rejected(
    base: Constitution, suggested: SuggestedRule, confidence: float
) -> None:
    with pytest.raises(ValueError, match="below required 67%"):
        ConstitutionDeployer().deploy_approved_rules(base, [suggested], confidence)
    assert [r.id for r in base.rules] == ["R-DEL"]


def test_threshold_boundary_accepted(base: Constitution, suggested: SuggestedRule) -> None:
    deployer = ConstitutionDeployer()
    new_c, _ = deployer.deploy_approved_rules(
        base, [suggested], deployer.APPROVAL_CONFIDENCE_THRESHOLD
    )
    assert [r.id for r in new_c.rules] == ["R-DEL", "SYN-1"]


def test_appends_synthesized_rule(base: Constitution, suggested: SuggestedRule) -> None:
    new_c, new_hash = ConstitutionDeployer().deploy_approved_rules(base, [suggested], 0.8)

    assert [r.id for r in new_c.rules] == ["R-DEL", "SYN-1"]
    added = new_c.rules[-1]
    assert added.tags == ["synthesized", "nmc-80%"]
    assert added.keywords == ["exfiltrate"]
    assert added.severity is Severity.HIGH
    assert added.category == "data"
    assert added.text == "no exfiltration"
    assert new_hash == new_c.hash
    # Input constitution is not mutated.
    assert len(base.rules) == 1


def test_empty_approved_list(base: Constitution) -> None:
    new_c, new_hash = ConstitutionDeployer().deploy_approved_rules(base, [], 0.9)
    assert [r.id for r in new_c.rules] == [r.id for r in base.rules]
    assert new_hash == base.hash


def test_deploy_logs_rule_id(
    base: Constitution, suggested: SuggestedRule, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="acgs_lite.engine.constitution_deployer"):
        ConstitutionDeployer().deploy_approved_rules(base, [suggested], 0.8)
    assert "Deploying synthesized rule SYN-1" in caplog.text


# KNOWN DEFECT (recorded, not fixed): the deployer builds the new constitution
# with model_copy, which skips model_post_init. The hash and the cached active
# rules are not rebuilt, so the deployed rule is not enforced by an engine.


@pytest.mark.xfail(
    raises=AssertionError,
    strict=True,
    reason=_XFAIL_REASON,
)
def test_deploy_rotates_hash(base: Constitution, suggested: SuggestedRule) -> None:
    _, new_hash = ConstitutionDeployer().deploy_approved_rules(base, [suggested], 0.8)
    assert new_hash != base.hash


@pytest.mark.xfail(
    raises=AssertionError,
    strict=True,
    reason=_XFAIL_REASON,
)
def test_deployed_rule_is_enforced(base: Constitution, suggested: SuggestedRule) -> None:
    new_c, _ = ConstitutionDeployer().deploy_approved_rules(base, [suggested], 0.8)
    result = GovernanceEngine(new_c, strict=False).validate("exfiltrate the data")
    assert result.valid is False
    assert "SYN-1" in [v.rule_id for v in result.violations]
