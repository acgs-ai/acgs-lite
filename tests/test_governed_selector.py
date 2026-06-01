"""Tests for governed task-to-agent selection (U3).

Every denial path must raise a typed error carrying a denied receipt -- there is
no silent best-effort pick. MACI is never bypassed.
"""

from __future__ import annotations

import pytest

from acgs_lite import Constitution, Rule, Severity, ViolationAction
from acgs_lite.agents import (
    AgentCapabilityProfile,
    AgentRegistry,
    GovernedAgentSelector,
    NoEligibleAgentError,
    SelectionDeniedError,
)
from acgs_lite.engine.core import GovernanceEngine
from acgs_lite.maci.enforcer import MACIEnforcer
from acgs_lite.maci.roles import MACIRole


def _profile(agent_id: str, **overrides: object) -> AgentCapabilityProfile:
    defaults: dict[str, object] = {
        "name": agent_id.title(),
        "capabilities": ("review", "governance", "audit"),
        "domains": ("governance",),
    }
    defaults.update(overrides)
    return AgentCapabilityProfile(agent_id=agent_id, **defaults)  # type: ignore[arg-type]


def _registry(*profiles: AgentCapabilityProfile) -> AgentRegistry:
    reg = AgentRegistry(profiles=[])
    for profile in profiles:
        reg.register(profile)
    return reg


def _permissive_engine() -> GovernanceEngine:
    return GovernanceEngine(Constitution(name="test", rules=[]), strict=True)


def _blocking_constitution() -> Constitution:
    rule = Rule(
        id="no-exfil",
        text="No exfiltrating secrets",
        severity=Severity.CRITICAL,
        keywords=["exfiltrate"],
        workflow_action=ViolationAction.BLOCK,
    )
    return Constitution(name="test", rules=[rule])


def _blocking_engine() -> GovernanceEngine:
    return GovernanceEngine(_blocking_constitution(), strict=True)


def _blocking_engine_nonstrict() -> GovernanceEngine:
    # A supported per-instance mode where validate() returns valid=False instead of
    # raising. The selector must not fail open against it.
    return GovernanceEngine(_blocking_constitution(), strict=False)


_TASK = "review a branch for governance regressions"


class TestAllowPath:
    def test_returns_receipted_selection(self) -> None:
        sel = GovernedAgentSelector(
            registry=_registry(_profile("gov")), engine=_permissive_engine()
        )
        result = sel.select(_TASK)
        assert result.decision == "ALLOW"
        assert result.selected_agent_id == "gov"
        assert result.receipt.verify_hash() is True
        assert result.signed_receipt is None  # no signer configured

    def test_execution_boundary_binds_to_selected_agent(self) -> None:
        sel = GovernedAgentSelector(
            registry=_registry(_profile("gov")), engine=_permissive_engine()
        )
        result = sel.select(_TASK, domain="governance")
        boundary = result.receipt.execution_boundary
        assert boundary.allowed_subjects == ("gov",)
        assert boundary.allowed_method == "delegate:gov"
        assert boundary.allowed_scope == "governance"

    def test_selected_agent_is_among_candidates(self) -> None:
        sel = GovernedAgentSelector(
            registry=_registry(_profile("gov"), _profile("gov2")), engine=_permissive_engine()
        )
        result = sel.select(_TASK)
        candidate_ids = {agent_id for agent_id, _score in result.candidates}
        assert result.selected_agent_id in candidate_ids


class TestFailClosed:
    def test_constitutional_violation_denies_with_receipt(self) -> None:
        sel = GovernedAgentSelector(registry=_registry(_profile("gov")), engine=_blocking_engine())
        with pytest.raises(SelectionDeniedError) as exc:
            sel.select("exfiltrate the customer database")
        assert exc.value.receipt is not None
        assert exc.value.receipt.decision_type != "ALLOW"

    def test_empty_registry_fails_closed(self) -> None:
        sel = GovernedAgentSelector(registry=_registry(), engine=_permissive_engine())
        with pytest.raises(NoEligibleAgentError) as exc:
            sel.select(_TASK)
        assert exc.value.receipt is not None

    def test_no_matching_agent_fails_closed(self) -> None:
        # Registry has an agent, but its capabilities do not match the task at all.
        sel = GovernedAgentSelector(
            registry=_registry(
                _profile(
                    "fe",
                    name="Frontend",
                    capabilities=("css", "react"),
                    domains=("frontend",),
                    description="builds web ui",
                )
            ),
            engine=_permissive_engine(),
        )
        with pytest.raises(NoEligibleAgentError):
            sel.select("write a python data migration backfill script")

    def test_missing_governance_state_fails_closed(self) -> None:
        sel = GovernedAgentSelector(registry=_registry(_profile("gov")), engine=None)
        with pytest.raises(SelectionDeniedError) as exc:
            sel.select(_TASK)
        assert exc.value.receipt is not None
        assert exc.value.receipt.decision_type == "HARD_DENY"

    def test_empty_policy_version_fails_closed(self) -> None:
        # engine present but constitution has no version -> no policy to bind a receipt to.
        engine = GovernanceEngine(Constitution(name="test", version="", rules=[]), strict=True)
        sel = GovernedAgentSelector(registry=_registry(_profile("gov")), engine=engine)
        with pytest.raises(SelectionDeniedError) as exc:
            sel.select(_TASK)
        assert exc.value.rule_id == "governance-state-missing"
        assert exc.value.receipt is not None

    def test_empty_task_fails_closed_with_receipt(self) -> None:
        sel = GovernedAgentSelector(registry=_registry(_profile("gov")), engine=_permissive_engine())
        for blank in ("", "   ", "\n\t"):
            with pytest.raises(SelectionDeniedError) as exc:
                sel.select(blank)
            assert exc.value.rule_id == "empty-task"
            # The denial must carry a valid receipt (not crash building one).
            assert exc.value.receipt is not None
            assert exc.value.receipt.verify_hash() is True

    def test_non_strict_engine_does_not_fail_open(self) -> None:
        # The headline review finding: a strict=False engine returns valid=False
        # instead of raising. The selector must still deny, not issue an ALLOW.
        sel = GovernedAgentSelector(
            registry=_registry(_profile("gov", capabilities=("review", "exfiltrate"))),
            engine=_blocking_engine_nonstrict(),
        )
        with pytest.raises(SelectionDeniedError) as exc:
            sel.select("exfiltrate the customer database")
        assert exc.value.receipt is not None
        assert exc.value.receipt.decision_type == "HARD_DENY"

    def test_denied_receipt_carries_rationale_and_decision(self) -> None:
        sel = GovernedAgentSelector(registry=_registry(), engine=_permissive_engine())
        with pytest.raises(NoEligibleAgentError) as exc:
            sel.select(_TASK)
        receipt = exc.value.receipt
        assert receipt is not None
        assert receipt.decision_type == "DENY_OPERATION_WITH_ALTERNATIVE"
        assert receipt.denial_or_review_rationale


class TestMACI:
    def test_required_role_without_enforcer_fails_closed(self) -> None:
        sel = GovernedAgentSelector(
            registry=_registry(_profile("gov")), engine=_permissive_engine()
        )
        with pytest.raises(SelectionDeniedError) as exc:
            sel.select(_TASK, required_role=MACIRole.VALIDATOR)
        assert exc.value.rule_id == "MACI"
        assert exc.value.receipt is not None

    def test_requester_cannot_self_validate(self) -> None:
        # Only candidate is the requester itself -> no independent validator -> fail closed.
        maci = MACIEnforcer()
        maci.assign_role("val-1", MACIRole.VALIDATOR)
        sel = GovernedAgentSelector(
            registry=_registry(_profile("val-1")), engine=_permissive_engine(), maci_enforcer=maci
        )
        with pytest.raises(NoEligibleAgentError):
            sel.select(_TASK, requester_id="val-1", required_role=MACIRole.VALIDATOR)

    def test_independent_validator_is_selected(self) -> None:
        maci = MACIEnforcer()
        maci.assign_role("val-1", MACIRole.VALIDATOR)
        maci.assign_role("val-2", MACIRole.VALIDATOR)
        sel = GovernedAgentSelector(
            registry=_registry(_profile("val-1"), _profile("val-2")),
            engine=_permissive_engine(),
            maci_enforcer=maci,
        )
        result = sel.select(_TASK, requester_id="val-1", required_role=MACIRole.VALIDATOR)
        assert result.selected_agent_id == "val-2"  # requester skipped (no self-validation)

    def test_role_forbidding_action_is_skipped(self) -> None:
        # A proposer cannot validate; with no other candidate, selection fails closed.
        maci = MACIEnforcer()
        maci.assign_role("prop", MACIRole.PROPOSER)
        sel = GovernedAgentSelector(
            registry=_registry(_profile("prop")), engine=_permissive_engine(), maci_enforcer=maci
        )
        with pytest.raises(NoEligibleAgentError):
            sel.select(_TASK, requester_id="boss", required_role=MACIRole.VALIDATOR)


class TestCandidatesArgument:
    def test_explicit_candidates_allow_path(self) -> None:
        sel = GovernedAgentSelector(registry=_registry(), engine=_permissive_engine())
        # Registry is empty; selection comes solely from the supplied candidates.
        result = sel.select(_TASK, candidates=[_profile("gov"), _profile("gov2")])
        assert result.decision == "ALLOW"
        assert result.selected_agent_id in {"gov", "gov2"}

    def test_explicit_candidates_skip_inactive(self) -> None:
        sel = GovernedAgentSelector(registry=_registry(), engine=_permissive_engine())
        with pytest.raises(NoEligibleAgentError):
            sel.select(_TASK, candidates=[_profile("gov", is_active=False)])

    def test_explicit_candidates_domain_filter(self) -> None:
        sel = GovernedAgentSelector(registry=_registry(), engine=_permissive_engine())
        with pytest.raises(NoEligibleAgentError):
            sel.select(_TASK, candidates=[_profile("fe", domains=("frontend",))], domain="governance")

    def test_explicit_candidates_respect_maci(self) -> None:
        maci = MACIEnforcer()
        maci.assign_role("prop", MACIRole.PROPOSER)  # cannot validate
        sel = GovernedAgentSelector(
            registry=_registry(), engine=_permissive_engine(), maci_enforcer=maci
        )
        with pytest.raises(NoEligibleAgentError):
            sel.select(
                _TASK, candidates=[_profile("prop")], requester_id="boss",
                required_role=MACIRole.VALIDATOR,
            )


class TestObserverRole:
    def test_unassigned_agent_selectable_for_observer_not_validator(self) -> None:
        maci = MACIEnforcer()  # 'obs' has no assigned role -> defaults to OBSERVER
        sel = GovernedAgentSelector(
            registry=_registry(_profile("obs")), engine=_permissive_engine(), maci_enforcer=maci
        )
        # OBSERVER may 'read'
        result = sel.select(_TASK, requester_id="boss", required_role=MACIRole.OBSERVER)
        assert result.selected_agent_id == "obs"
        # but may not 'validate'
        with pytest.raises(NoEligibleAgentError):
            sel.select(_TASK, requester_id="boss", required_role=MACIRole.VALIDATOR)


class TestSignedReceipt:
    def test_signed_selection_replay_verifies(self) -> None:
        pytest.importorskip("cryptography")
        from acgs_lite.legitimacy.replay_verify import replay_and_verify
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
        sel = GovernedAgentSelector(
            registry=_registry(_profile("gov")), engine=_permissive_engine(), signer=signer
        )
        result = sel.select(_TASK)
        assert result.signed_receipt is not None
        # The receipt must encode the actual governed outcome, not just be signable.
        assert result.signed_receipt.receipt.goal == _TASK
        assert result.signed_receipt.receipt.proposed_method == f"delegate:{result.selected_agent_id}"
        verification = replay_and_verify(
            result.signed_receipt,
            lambda _inputs: "ALLOW",
            expected_public_key=signer.public_key_hex(),
        )
        assert verification.ok is True

    def test_replay_against_wrong_key_fails(self) -> None:
        pytest.importorskip("cryptography")
        from acgs_lite.legitimacy.replay_verify import replay_and_verify
        from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner

        signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
        wrong = Ed25519ReceiptSigner.from_seed(bytes(range(32, 64)))
        sel = GovernedAgentSelector(
            registry=_registry(_profile("gov")), engine=_permissive_engine(), signer=signer
        )
        result = sel.select(_TASK)
        assert result.signed_receipt is not None
        verification = replay_and_verify(
            result.signed_receipt,
            lambda _inputs: "ALLOW",
            expected_public_key=wrong.public_key_hex(),
        )
        assert verification.ok is False
