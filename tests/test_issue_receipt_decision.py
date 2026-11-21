"""The issue receipt records the engine's real decision, not a fixed stamp.

Dispatcher-level: every grant is minted through ``wrapped.issue_grant(...)`` and
every deny asserts the wrapped side effect never ran.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.constitution.rule import Rule, ViolationAction
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import AuthorizationProfile, LegitimacyInvariantError
from acgs_lite.legitimacy.authorization import EngineDecision, engine_decision_from_results
from acgs_lite.legitimacy.receipt import BASELINE_CONSTRAINT_MARKER
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner


def _production_signing() -> dict[str, object]:
    """Pinned, non-ephemeral Ed25519 execution signer the production profile requires."""
    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    return {
        "receipt_signer": signer,
        "trusted_execution_keys": {signer.key_id: signer.public_key_hex()},
    }


def _constitution(*extra: Rule) -> Constitution:
    return Constitution.from_rules(
        [
            Rule(id="BLOCK-ZAP", text="no zapword", keywords=["zapword"]),
            Rule(
                id="WARN-PING",
                text="warn on pingword",
                keywords=["pingword"],
                workflow_action=ViolationAction.WARN,
            ),
            Rule(
                id="WARN-PONG",
                text="warn on pongword",
                keywords=["pongword"],
                workflow_action=ViolationAction.WARN,
            ),
            Rule(
                id="REVIEW-WIRE",
                text="review wiretransfer",
                keywords=["wiretransfer"],
                workflow_action=ViolationAction.REQUIRE_HUMAN_REVIEW,
            ),
            Rule(
                id="ESCALATE-ROOT",
                text="escalate rootaccess",
                keywords=["rootaccess"],
                workflow_action=ViolationAction.ESCALATE,
            ),
            Rule(
                id="HALT-NUKE",
                text="halt on nukeword",
                keywords=["nukeword"],
                workflow_action=ViolationAction.HALT,
            ),
            *extra,
        ]
    )


def _production(**options: Any) -> GovernedCallable:
    return GovernedCallable(
        _constitution(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        **_production_signing(),
        **options,
    )


def test_benign_issue_receipt_records_allow_with_baseline_constraint() -> None:
    calls: list[str] = []

    @_production()
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    grant = f.issue_grant("What is the capital of France?")
    receipt = grant.receipt
    assert receipt.decision_type == "ALLOW"
    assert receipt.matched_constraints == (BASELINE_CONSTRAINT_MARKER,)
    assert "execution-grant-issued" not in receipt.matched_constraints
    assert receipt.required_controls == ()
    assert receipt.authority_basis == "acgs-lite:execution-authority"
    assert calls == []
    assert f("What is the capital of France?", execution_grant=grant) == "ok"
    assert calls == ["What is the capital of France?"]


def test_warn_only_issue_receipt_records_allow_with_controls_and_executes() -> None:
    calls: list[str] = []

    @_production()
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    grant = f.issue_grant("pingword please")
    receipt = grant.receipt
    assert receipt.decision_type == "ALLOW_WITH_CONTROLS"
    assert receipt.matched_constraints == ("WARN-PING",)
    assert receipt.required_controls == ("AUDIT_WARNINGS",)
    assert f("pingword please", execution_grant=grant) == "ok"
    assert calls == ["pingword please"]


def test_warn_aggregation_is_order_independent() -> None:
    @_production()
    def f(a: str, b: str) -> str:
        return "ok"

    left = f.issue_grant("pingword", "pongword").receipt
    right = f.issue_grant("pongword", "pingword").receipt
    assert left.decision_type == right.decision_type == "ALLOW_WITH_CONTROLS"
    assert left.matched_constraints == right.matched_constraints == ("WARN-PING", "WARN-PONG")


@pytest.mark.parametrize(
    ("text", "rule_id"),
    [("needs wiretransfer", "REVIEW-WIRE"), ("needs rootaccess", "ESCALATE-ROOT")],
)
def test_review_verdict_is_refused_at_issue_with_rule_id(text: str, rule_id: str) -> None:
    calls: list[str] = []

    @_production()
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f.issue_grant(text)
    assert excinfo.value.rule_id == rule_id
    assert "STRUCTURED_REVIEW_REQUIRED" in str(excinfo.value)
    assert calls == []


def test_block_and_review_in_one_payload_is_a_deny() -> None:
    calls: list[str] = []

    @_production()
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f.issue_grant("wiretransfer and zapword")
    assert excinfo.value.rule_id == "BLOCK-ZAP"
    assert "DENY_GOAL" in str(excinfo.value)
    assert calls == []


@pytest.mark.parametrize("order", [("pingword", "zapword"), ("zapword", "pingword")])
def test_worst_verdict_across_payloads_wins_in_any_order(order: tuple[str, str]) -> None:
    calls: list[str] = []

    @_production()
    def f(a: str, b: str) -> str:
        calls.append(a)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f.issue_grant(*order)
    assert excinfo.value.rule_id == "BLOCK-ZAP"
    assert calls == []


def test_halt_verdict_propagates_engine_exception() -> None:
    calls: list[str] = []

    @_production()
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f.issue_grant("nukeword")
    assert excinfo.value.rule_id == "HALT-NUKE"
    assert excinfo.value.enforcement_action is ViolationAction.HALT
    assert calls == []


def test_compat_profile_issue_receipt_also_records_engine_decision() -> None:
    @GovernedCallable(_constitution())
    def f(text: str) -> str:
        return "ok"

    receipt = f.issue_grant("pingword").receipt
    assert receipt.decision_type == "ALLOW_WITH_CONTROLS"
    assert receipt.matched_constraints == ("WARN-PING",)


def test_quickstart_contract_rule_id_is_preserved() -> None:
    calls: list[str] = []

    @GovernedCallable(
        Constitution.from_rules([Rule(id="no-pii", text="no ssn", keywords=["ssn"])]),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        **_production_signing(),
    )
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f.issue_grant("my ssn is 123")
    assert excinfo.value.rule_id == "no-pii"
    assert calls == []


# --- engine_decision_from_results (helper; dispatcher tests above are primary) ---


def _result(valid: Any, *, violations=(), warnings=(), reviews=(), action_taken=None) -> Any:
    return SimpleNamespace(
        valid=valid,
        violations=[SimpleNamespace(rule_id=r) for r in violations],
        warnings=[SimpleNamespace(rule_id=r) for r in warnings],
        review_requests=[SimpleNamespace(rule_id=r) for r in reviews],
        escalations=[],
        action_taken=action_taken,
    )


def test_decision_helper_fails_closed_on_empty_and_malformed_results() -> None:
    with pytest.raises(LegitimacyInvariantError):
        engine_decision_from_results([])
    missing = engine_decision_from_results([SimpleNamespace()])
    assert missing.decision_type == "DENY_GOAL"
    assert missing.primary_rule_id is None
    halted = engine_decision_from_results(
        [_result(False, violations=["H"], action_taken=ViolationAction.HALT)]
    )
    assert halted.decision_type == "HARD_DENY"
    assert halted.primary_rule_id == "H"


def test_decision_helper_rationale_and_payload_count() -> None:
    decision = engine_decision_from_results(
        [_result(True), _result(False, violations=["R"], reviews=["R"])]
    )
    assert isinstance(decision, EngineDecision)
    assert decision.decision_type == "STRUCTURED_REVIEW_REQUIRED"
    assert decision.matched_rule_ids == ("R",)
    assert decision.payload_count == 2
    assert decision.rationale is not None and "R" in decision.rationale


def test_rust_fast_path_maps_the_same_verdicts() -> None:
    from acgs_lite.engine.matcher import _HAS_RUST

    if not _HAS_RUST:
        pytest.skip("Rust governance backend not installed")
    guard = _production()
    assert guard.engine._rust_validator is not None

    @guard
    def f(text: str) -> str:
        return "ok"

    assert f.issue_grant("hello").receipt.decision_type == "ALLOW"
    assert f.issue_grant("pingword").receipt.decision_type == "ALLOW_WITH_CONTROLS"
    for text, rule_id in (("zapword", "BLOCK-ZAP"), ("wiretransfer", "REVIEW-WIRE")):
        with pytest.raises(ConstitutionalViolationError) as excinfo:
            f.issue_grant(text)
        assert excinfo.value.rule_id == rule_id
