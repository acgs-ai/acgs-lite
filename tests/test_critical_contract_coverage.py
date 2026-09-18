"""Tests for acgs_lite.maci — MACI separation of powers enforcement.

Covers: MACIRole, ActionRiskTier, EscalationTier, recommend_escalation,
MACIEnforcer, DomainScopedRole, DomainRoleRegistry, DerivedRole,
DelegationGrant, DelegationRegistry.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from acgs_lite.errors import MACIViolationError

_LEGACY_NAME = "acgs_lite._legacy_maci_contract"
_LEGACY_PATH = Path(__file__).resolve().parents[1] / "src" / "acgs_lite" / "maci.py"
_LEGACY_SPEC = importlib.util.spec_from_file_location(_LEGACY_NAME, _LEGACY_PATH)
assert _LEGACY_SPEC is not None and _LEGACY_SPEC.loader is not None
_LEGACY_MODULE = importlib.util.module_from_spec(_LEGACY_SPEC)
sys.modules[_LEGACY_NAME] = _LEGACY_MODULE
_LEGACY_SPEC.loader.exec_module(_LEGACY_MODULE)

from acgs_lite._legacy_maci_contract import (
    ActionRiskTier,
    DelegationGrant,
    DelegationRegistry,
    DerivedRole,
    DomainRoleRegistry,
    DomainScopedRole,
    EscalationTier,
    MACIEnforcer,
    MACIRole,
    recommend_escalation,
)


# ---------------------------------------------------------------------------
# MACIRole enum
# ---------------------------------------------------------------------------
class TestMACIRole:
    def test_values(self):
        assert MACIRole.PROPOSER.value == "proposer"
        assert MACIRole.VALIDATOR.value == "validator"
        assert MACIRole.EXECUTOR.value == "executor"
        assert MACIRole.OBSERVER.value == "observer"

    def test_is_str_enum(self):
        assert isinstance(MACIRole.PROPOSER, str)


# ---------------------------------------------------------------------------
# ActionRiskTier
# ---------------------------------------------------------------------------
class TestActionRiskTier:
    def test_values(self):
        assert ActionRiskTier.LOW.value == "low"
        assert ActionRiskTier.CRITICAL.value == "critical"

    def test_escalation_path_property(self):
        assert ActionRiskTier.LOW.escalation_path == "auto_approve"
        assert ActionRiskTier.MEDIUM.escalation_path == "supervisor_notify"
        assert ActionRiskTier.HIGH.escalation_path == "human_review_queue"
        assert ActionRiskTier.CRITICAL.escalation_path == "governance_lead_immediate"


# ---------------------------------------------------------------------------
# recommend_escalation
# ---------------------------------------------------------------------------
class TestRecommendEscalation:
    def test_low_everything(self):
        result = recommend_escalation("low", 0.0, "low")
        assert result["tier"] == EscalationTier.TIER_0_AUTO.value
        assert result["requires_human"] is False

    def test_critical_severity_high_action(self):
        result = recommend_escalation("critical", 0.5, "critical")
        assert result["tier"] == EscalationTier.TIER_4_BLOCK.value
        assert result["requires_human"] is True
        assert result["sla"] == "immediate"

    def test_medium_severity_medium_action(self):
        result = recommend_escalation("medium", 0.3, "medium")
        # combined = 1 + 1 + 0.9 = 2.9 => tier_1
        assert result["tier"] == EscalationTier.TIER_1_NOTIFY.value

    def test_high_severity_zero_context(self):
        result = recommend_escalation("high", 0.0, "high")
        # combined = 2 + 2 + 0 = 4 => tier_2
        assert result["tier"] == EscalationTier.TIER_2_REVIEW.value
        assert result["requires_human"] is True

    def test_critical_severity_full_context(self):
        result = recommend_escalation("critical", 1.0, "high")
        # combined = 3 + 2 + 3 = 8 => tier_4
        assert result["tier"] == EscalationTier.TIER_4_BLOCK.value

    def test_unknown_severity_defaults_zero(self):
        result = recommend_escalation("unknown", 0.0, "low")
        # combined = 0 + 0 + 0 = 0 => tier_0
        assert result["tier"] == EscalationTier.TIER_0_AUTO.value


# ---------------------------------------------------------------------------
# MACIEnforcer
# ---------------------------------------------------------------------------
class TestMACIEnforcer:
    def test_assign_and_get_role(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("a1", MACIRole.PROPOSER)
        assert enforcer.get_role("a1") == MACIRole.PROPOSER

    def test_get_role_unassigned(self):
        enforcer = MACIEnforcer()
        assert enforcer.get_role("unknown") is None

    def test_check_allowed_action(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("a1", MACIRole.PROPOSER)
        assert enforcer.check("a1", "propose") is True

    def test_check_denied_action_raises(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("a1", MACIRole.PROPOSER)
        with pytest.raises(MACIViolationError) as exc_info:
            enforcer.check("a1", "validate")
        assert exc_info.value.actor_role == "proposer"
        assert exc_info.value.attempted_action == "validate"

    def test_validator_cannot_execute(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("v1", MACIRole.VALIDATOR)
        with pytest.raises(MACIViolationError):
            enforcer.check("v1", "execute")

    def test_executor_cannot_validate(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("e1", MACIRole.EXECUTOR)
        with pytest.raises(MACIViolationError):
            enforcer.check("e1", "validate")

    def test_observer_cannot_propose(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("o1", MACIRole.OBSERVER)
        with pytest.raises(MACIViolationError):
            enforcer.check("o1", "propose")

    def test_unassigned_agent_treated_as_observer(self):
        enforcer = MACIEnforcer()
        assert enforcer.check("unregistered", "read") is True
        with pytest.raises(MACIViolationError):
            enforcer.check("unregistered", "execute")

    def test_query_literal_is_allowed_but_query_phrase_is_denied(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("a1", MACIRole.PROPOSER)
        assert enforcer.check("a1", "query") is True
        with pytest.raises(MACIViolationError):
            enforcer.check("a1", "query secrets")

    def test_check_no_self_validation_different_agents(self):
        enforcer = MACIEnforcer()
        assert enforcer.check_no_self_validation("a1", "a2") is True

    def test_check_no_self_validation_same_agent_raises(self):
        enforcer = MACIEnforcer()
        with pytest.raises(MACIViolationError) as exc_info:
            enforcer.check_no_self_validation("a1", "a1")
        assert "self-validate" in exc_info.value.attempted_action

    def test_role_assignments_property(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("a1", MACIRole.PROPOSER)
        enforcer.assign_role("a2", MACIRole.VALIDATOR)
        assignments = enforcer.role_assignments
        assert assignments == {"a1": "proposer", "a2": "validator"}

    def test_summary(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("a1", MACIRole.PROPOSER)
        enforcer.check("a1", "propose")
        summary = enforcer.summary()
        assert summary["agents"] == 1
        assert summary["checks_total"] >= 1

    def test_classify_action_risk_critical(self):
        enforcer = MACIEnforcer()
        result = enforcer.classify_action_risk("self-validate the output")
        assert result["risk_tier"] == "critical"

    def test_classify_action_risk_high(self):
        enforcer = MACIEnforcer()
        result = enforcer.classify_action_risk("deploy to production cluster")
        assert result["risk_tier"] == "high"

    def test_classify_action_risk_medium(self):
        enforcer = MACIEnforcer()
        result = enforcer.classify_action_risk("modify config settings")
        assert result["risk_tier"] == "medium"

    def test_classify_action_risk_low(self):
        enforcer = MACIEnforcer()
        result = enforcer.classify_action_risk("read the document")
        assert result["risk_tier"] == "low"
        assert result["matched_signal"] == ""

    def test_classify_action_risk_bypass_governance(self):
        enforcer = MACIEnforcer()
        result = enforcer.classify_action_risk("bypass validation checks")
        assert result["risk_tier"] == "critical"

    def test_classify_action_risk_password(self):
        enforcer = MACIEnforcer()
        result = enforcer.classify_action_risk("expose password in logs")
        assert result["risk_tier"] == "critical"


# ---------------------------------------------------------------------------
# DomainScopedRole
# ---------------------------------------------------------------------------
class TestDomainScopedRole:
    def test_can_act_in_assigned_domain(self):
        scoped = DomainScopedRole("a1", MACIRole.PROPOSER, ["finance"])
        assert scoped.can_act_in("finance") is True

    def test_cannot_act_in_other_domain(self):
        scoped = DomainScopedRole("a1", MACIRole.PROPOSER, ["finance"])
        assert scoped.can_act_in("healthcare") is False

    def test_empty_domains_means_unrestricted(self):
        scoped = DomainScopedRole("a1", MACIRole.PROPOSER, [])
        assert scoped.can_act_in("anything") is True

    def test_case_insensitive(self):
        scoped = DomainScopedRole("a1", MACIRole.PROPOSER, ["Finance"])
        assert scoped.can_act_in("finance") is True

    def test_to_dict(self):
        scoped = DomainScopedRole("a1", MACIRole.PROPOSER, ["finance"])
        d = scoped.to_dict()
        assert d["agent_id"] == "a1"
        assert d["role"] == "proposer"
        assert d["domains"] == ["finance"]

    def test_repr(self):
        scoped = DomainScopedRole("a1", MACIRole.PROPOSER, ["finance"])
        assert "a1" in repr(scoped)


# ---------------------------------------------------------------------------
# DomainRoleRegistry
# ---------------------------------------------------------------------------
class TestDomainRoleRegistry:
    def test_assign_and_get(self):
        reg = DomainRoleRegistry()
        reg.assign("a1", MACIRole.PROPOSER, domains=["finance"])
        scoped = reg.get("a1")
        assert scoped is not None
        assert scoped.role == MACIRole.PROPOSER

    def test_check_allowed(self):
        reg = DomainRoleRegistry()
        reg.assign("a1", MACIRole.PROPOSER, domains=["finance"])
        result = reg.check("a1", "propose", domain="finance")
        assert result["allowed"] is True

    def test_check_cross_domain_violation(self):
        reg = DomainRoleRegistry()
        reg.assign("a1", MACIRole.PROPOSER, domains=["finance"])
        result = reg.check("a1", "propose", domain="healthcare")
        assert result["allowed"] is False
        assert "cross-domain" in result["reason"]

    def test_check_role_violation(self):
        reg = DomainRoleRegistry()
        reg.assign("a1", MACIRole.PROPOSER, domains=["finance"])
        result = reg.check("a1", "validate", domain="finance")
        assert result["allowed"] is False
        assert "role violation" in result["reason"]

    def test_check_unknown_action_is_denied(self):
        reg = DomainRoleRegistry()
        reg.assign("a1", MACIRole.PROPOSER, domains=["finance"])
        result = reg.check("a1", "delete", domain="finance")
        assert result["allowed"] is False
        assert "role violation" in result["reason"]

    def test_check_query_phrase_is_denied(self):
        reg = DomainRoleRegistry()
        reg.assign("a1", MACIRole.PROPOSER, domains=["finance"])
        result = reg.check("a1", "query secrets", domain="finance")
        assert result["allowed"] is False
        assert "role violation" in result["reason"]

    def test_check_unregistered_agent(self):
        reg = DomainRoleRegistry()
        result = reg.check("unknown", "read", domain="finance")
        assert result["allowed"] is False
        assert "not registered" in result["reason"]

    def test_check_no_domain_constraint(self):
        reg = DomainRoleRegistry()
        reg.assign("a1", MACIRole.PROPOSER, domains=["finance"])
        result = reg.check("a1", "propose", domain="")
        assert result["allowed"] is True

    def test_isolation_report(self):
        reg = DomainRoleRegistry()
        reg.assign("a1", MACIRole.PROPOSER, domains=["finance"])
        reg.assign("a2", MACIRole.VALIDATOR, domains=["healthcare"])
        reg.assign("a3", MACIRole.EXECUTOR, domains=[])
        report = reg.isolation_report()
        assert report["total_agents"] == 3
        assert "finance" in report["domains"]
        assert "healthcare" in report["domains"]
        assert "a3" in report["cross_domain_risk"]

    def test_len_and_repr(self):
        reg = DomainRoleRegistry()
        assert len(reg) == 0
        reg.assign("a1", MACIRole.PROPOSER, domains=["finance"])
        assert len(reg) == 1
        assert "1 agents" in repr(reg)


# ---------------------------------------------------------------------------
# DerivedRole
# ---------------------------------------------------------------------------
class TestDerivedRole:
    def test_single_base_role_permissions(self):
        derived = DerivedRole("test", [MACIRole.PROPOSER])
        assert derived.can_perform("propose") is True
        assert derived.can_perform("validate") is False

    def test_composed_permissions(self):
        derived = DerivedRole("senior", [MACIRole.PROPOSER, MACIRole.VALIDATOR])
        assert derived.can_perform("propose") is True
        assert derived.can_perform("validate") is True

    def test_deny_override(self):
        derived = DerivedRole(
            "restricted",
            [MACIRole.PROPOSER, MACIRole.VALIDATOR],
            deny_override={"execute", "deploy"},
        )
        assert derived.can_perform("execute") is False

    def test_allow_override(self):
        derived = DerivedRole(
            "special",
            [MACIRole.OBSERVER],
            allow_override={"execute"},
        )
        assert derived.can_perform("execute") is True

    def test_denials_win_over_permissions(self):
        # execute is denied by shared denials of proposer+validator (no, actually
        # both deny execute so shared_denials includes execute)
        derived = DerivedRole("combo", [MACIRole.PROPOSER, MACIRole.VALIDATOR])
        assert derived.can_perform("execute") is False

    def test_check_returns_structured_verdict(self):
        derived = DerivedRole("test", [MACIRole.PROPOSER])
        result = derived.check("propose")
        assert result["allowed"] is True
        assert result["derived_role"] == "test"
        assert "inherited:proposer" in result["source"]

    def test_check_denied_action(self):
        derived = DerivedRole("test", [MACIRole.PROPOSER], deny_override={"draft"})
        result = derived.check("draft")
        assert result["allowed"] is False
        assert "denied:override" in result["source"]

    def test_check_not_found(self):
        derived = DerivedRole("test", [MACIRole.PROPOSER])
        result = derived.check("completely_unknown_action")
        assert result["allowed"] is False
        assert result["source"] == "not_found"

    def test_check_query_phrase_is_not_treated_as_query_permission(self):
        derived = DerivedRole("test", [MACIRole.PROPOSER])
        result = derived.check("query secrets")
        assert result["allowed"] is False
        assert result["source"] == "not_found"

    def test_to_dict(self):
        derived = DerivedRole("test", [MACIRole.PROPOSER])
        d = derived.to_dict()
        assert d["name"] == "test"
        assert "proposer" in d["base_roles"]
        assert isinstance(d["permissions"], list)
        assert isinstance(d["denials"], list)

    def test_repr(self):
        derived = DerivedRole("test", [MACIRole.PROPOSER])
        assert "test" in repr(derived)

    def test_empty_base_roles(self):
        derived = DerivedRole("empty", [])
        assert derived.can_perform("propose") is False
        assert len(derived.permissions) == 0


# ---------------------------------------------------------------------------
# DelegationGrant
# ---------------------------------------------------------------------------
class TestDelegationGrant:
    def test_is_active_default(self):
        grant = DelegationGrant(
            grant_id="DLG-1",
            grantor_id="admin",
            grantee_id="user1",
            scopes=["SAFE-*"],
        )
        assert grant.is_active() is True
        assert grant.revoked is False

    def test_is_expired_no_expiry(self):
        grant = DelegationGrant(
            grant_id="DLG-1",
            grantor_id="admin",
            grantee_id="user1",
            scopes=["*"],
        )
        assert grant.is_expired() is False

    def test_is_expired_past_expiry(self):
        grant = DelegationGrant(
            grant_id="DLG-1",
            grantor_id="admin",
            grantee_id="user1",
            scopes=["*"],
            expires_at="2020-01-01T00:00:00+00:00",
        )
        assert grant.is_expired() is True
        assert grant.is_active() is False

    def test_covers_scope_exact(self):
        grant = DelegationGrant(
            grant_id="DLG-1",
            grantor_id="admin",
            grantee_id="user1",
            scopes=["SAFE-001"],
        )
        assert grant.covers_scope("SAFE-001") is True
        assert grant.covers_scope("SAFE-002") is False

    def test_covers_scope_wildcard(self):
        grant = DelegationGrant(
            grant_id="DLG-1",
            grantor_id="admin",
            grantee_id="user1",
            scopes=["SAFE-*"],
        )
        assert grant.covers_scope("SAFE-001") is True
        assert grant.covers_scope("PII-001") is False

    def test_covers_scope_global(self):
        grant = DelegationGrant(
            grant_id="DLG-1",
            grantor_id="admin",
            grantee_id="user1",
            scopes=["*"],
        )
        assert grant.covers_scope("anything") is True

    def test_can_redelegate(self):
        grant = DelegationGrant(
            grant_id="DLG-1",
            grantor_id="admin",
            grantee_id="user1",
            scopes=["*"],
            max_depth=1,
            depth=0,
        )
        assert grant.can_redelegate() is True

    def test_cannot_redelegate_at_max(self):
        grant = DelegationGrant(
            grant_id="DLG-1",
            grantor_id="admin",
            grantee_id="user1",
            scopes=["*"],
            max_depth=1,
            depth=1,
        )
        assert grant.can_redelegate() is False

    def test_to_dict(self):
        grant = DelegationGrant(
            grant_id="DLG-1",
            grantor_id="admin",
            grantee_id="user1",
            scopes=["SAFE-*"],
        )
        d = grant.to_dict()
        assert d["grant_id"] == "DLG-1"
        assert d["is_active"] is True
        assert d["can_redelegate"] is False

    def test_repr(self):
        grant = DelegationGrant(
            grant_id="DLG-1",
            grantor_id="admin",
            grantee_id="user1",
            scopes=["*"],
        )
        assert "DLG-1" in repr(grant)
        assert "active" in repr(grant)


# ---------------------------------------------------------------------------
# DelegationRegistry
# ---------------------------------------------------------------------------
class TestDelegationRegistry:
    def test_delegate_creates_grant(self):
        reg = DelegationRegistry()
        grant = reg.delegate(
            grantor_id="admin",
            grantee_id="user1",
            scopes=["SAFE-*"],
        )
        assert grant.grant_id == "DLG-00001"
        assert grant.grantor_id == "admin"
        assert grant.grantee_id == "user1"

    def test_delegate_self_raises(self):
        reg = DelegationRegistry()
        with pytest.raises(ValueError, match="Cannot delegate authority to self"):
            reg.delegate(grantor_id="admin", grantee_id="admin", scopes=["*"])

    def test_delegate_empty_scopes_raises(self):
        reg = DelegationRegistry()
        with pytest.raises(ValueError, match="at least one scope"):
            reg.delegate(grantor_id="admin", grantee_id="user1", scopes=[])

    def test_check_authority_authorized(self):
        reg = DelegationRegistry()
        reg.delegate(grantor_id="admin", grantee_id="user1", scopes=["SAFE-*"])
        result = reg.check_authority("user1", scope="SAFE-001")
        assert result["authorized"] is True

    def test_check_authority_not_authorized(self):
        reg = DelegationRegistry()
        result = reg.check_authority("nobody", scope="SAFE-001")
        assert result["authorized"] is False

    def test_redelegate(self):
        reg = DelegationRegistry()
        parent = reg.delegate(
            grantor_id="admin",
            grantee_id="lead",
            scopes=["SAFE-*"],
            max_depth=1,
        )
        child = reg.redelegate(
            parent_grant_id=parent.grant_id,
            grantee_id="analyst",
            scopes=["SAFE-*"],
        )
        assert child.depth == 1
        assert child.parent_grant_id == parent.grant_id
        result = reg.check_authority("analyst", scope="SAFE-001")
        assert result["authorized"] is True

    def test_redelegate_exceeds_depth_raises(self):
        reg = DelegationRegistry()
        parent = reg.delegate(
            grantor_id="admin",
            grantee_id="lead",
            scopes=["*"],
            max_depth=0,
        )
        with pytest.raises(ValueError, match="cannot re-delegate"):
            reg.redelegate(
                parent_grant_id=parent.grant_id,
                grantee_id="analyst",
            )

    def test_redelegate_same_grantee_raises(self):
        reg = DelegationRegistry()
        parent = reg.delegate(
            grantor_id="admin",
            grantee_id="lead",
            scopes=["*"],
            max_depth=1,
        )
        with pytest.raises(ValueError, match="same grantee"):
            reg.redelegate(
                parent_grant_id=parent.grant_id,
                grantee_id="lead",
            )

    def test_redelegate_scope_violation_raises(self):
        reg = DelegationRegistry()
        parent = reg.delegate(
            grantor_id="admin",
            grantee_id="lead",
            scopes=["SAFE-*"],
            max_depth=1,
        )
        with pytest.raises(ValueError, match="not covered"):
            reg.redelegate(
                parent_grant_id=parent.grant_id,
                grantee_id="analyst",
                scopes=["PII-*"],
            )

    def test_revoke_single(self):
        reg = DelegationRegistry()
        grant = reg.delegate(grantor_id="admin", grantee_id="user1", scopes=["*"])
        count = reg.revoke(grant.grant_id, reason="test")
        assert count == 1
        assert grant.revoked is True

    def test_revoke_cascade(self):
        reg = DelegationRegistry()
        parent = reg.delegate(
            grantor_id="admin",
            grantee_id="lead",
            scopes=["*"],
            max_depth=1,
        )
        child = reg.redelegate(
            parent_grant_id=parent.grant_id,
            grantee_id="analyst",
        )
        count = reg.revoke(parent.grant_id, reason="cascade test", cascade=True)
        assert count == 2
        assert parent.revoked is True
        assert child.revoked is True

    def test_revoke_already_revoked_returns_zero(self):
        reg = DelegationRegistry()
        grant = reg.delegate(grantor_id="admin", grantee_id="user1", scopes=["*"])
        reg.revoke(grant.grant_id)
        count = reg.revoke(grant.grant_id)
        assert count == 0

    def test_revoke_unknown_raises(self):
        reg = DelegationRegistry()
        with pytest.raises(KeyError):
            reg.revoke("DLG-99999")

    def test_grants_for_and_by(self):
        reg = DelegationRegistry()
        reg.delegate(grantor_id="admin", grantee_id="user1", scopes=["*"])
        assert len(reg.grants_for("user1")) == 1
        assert len(reg.grants_by("admin")) == 1
        assert len(reg.grants_for("admin")) == 0

    def test_delegation_tree(self):
        reg = DelegationRegistry()
        parent = reg.delegate(
            grantor_id="admin",
            grantee_id="lead",
            scopes=["*"],
            max_depth=1,
        )
        reg.redelegate(
            parent_grant_id=parent.grant_id,
            grantee_id="analyst",
        )
        tree = reg.delegation_tree()
        assert len(tree["roots"]) == 1
        assert tree["summary"]["total_grants"] == 2
        assert tree["summary"]["max_depth"] == 1

    def test_summary(self):
        reg = DelegationRegistry()
        reg.delegate(grantor_id="admin", grantee_id="user1", scopes=["SAFE-*"])
        summary = reg.summary()
        assert summary["total"] == 1
        assert summary["active"] == 1
        assert summary["revoked"] == 0

    def test_history(self):
        reg = DelegationRegistry()
        reg.delegate(grantor_id="admin", grantee_id="user1", scopes=["*"])
        history = reg.history()
        assert len(history) == 1
        assert history[0]["action"] == "delegate"

    def test_len_and_repr(self):
        reg = DelegationRegistry()
        assert len(reg) == 0
        reg.delegate(grantor_id="admin", grantee_id="user1", scopes=["*"])
        assert len(reg) == 1
        assert "1 grants" in repr(reg)


# ---------------------------------------------------------------------------
# Synthetic acceleration decoder contracts
# ---------------------------------------------------------------------------

from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.engine._rust_dispatch import RustDispatchMixin
from acgs_lite.engine.core import GovernanceEngine
from acgs_lite.engine.matcher import GovernanceMatcherMixin
from acgs_lite.engine.models import ValidationResult
from acgs_lite.engine.rust import _RUST_ALLOW, _RUST_DENY, _RUST_DENY_CRITICAL
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.legitimacy import LegitimacyInvariantError, TrustedExecutionContext
from acgs_lite.legitimacy.authorization import (
    ExecutionAuthority,
    build_issue_receipt,
    extract_authorization_kwargs,
    parse_authorization_envelope,
    resolve_profile,
)
from acgs_lite.legitimacy.decide import canonicalize_decision_state, is_allow_state
from acgs_lite.legitimacy.invariants import (
    ActualCall,
    call_matches,
    normalize_actual_call,
    route_ambiguous_decision,
    validate_receipt_for_execution,
)
from acgs_lite.legitimacy.invocation import (
    ArgumentNotDigestible,
    bind_invocation,
    bind_policy,
    canonical_argument_digest,
    reject_method_spoof_kwargs,
    trusted_method_id,
)
from acgs_lite.legitimacy.receipt import DecisionReceipt, ExecutionBoundary
from acgs_lite.legitimacy.signing import (
    SIGNATURE_SCOPE_EXECUTION,
    Ed25519ReceiptSigner,
    SignedReceipt,
    sign_execution_authorization,
    verify_signature,
)


class _SyntheticRustValidator:
    """Controlled decoder input; this is not evidence of a native Rust integration."""

    def __init__(self) -> None:
        self.hot: dict[str, tuple[int, int]] = {}
        self.full: tuple[int, list[tuple[str, str, str, str, str]], bool] = (
            _RUST_ALLOW,
            [],
            False,
        )

    def validate_hot(self, action: str) -> tuple[int, int]:
        return self.hot.get(action, (_RUST_ALLOW, 0))

    def validate_full(
        self, action: str, context: list[tuple[str, str]]
    ) -> tuple[int, list[tuple[str, str, str, str, str]], bool]:
        del action, context
        return self.full


def _rule_contract() -> tuple[list[tuple[object, ...]], list[ConstitutionalViolationError]]:
    rule_data = [
        ("WARN", "warn text", Severity.MEDIUM, (), "quality", False, ()),
        ("BLOCK", "block text", Severity.HIGH, (), "security", True, ()),
    ]
    errors = [
        ConstitutionalViolationError("warn text", rule_id="WARN", severity="medium", action=""),
        ConstitutionalViolationError("block text", rule_id="BLOCK", severity="high", action=""),
    ]
    return rule_data, errors


class _DormantDispatchHost(RustDispatchMixin):
    def __init__(self, *, strict: bool = True) -> None:
        self._rule_data, self._rule_excs = _rule_contract()
        self._rule_id_to_exc_idx = {"WARN": 0, "BLOCK": 1}
        self._rust_validator = _SyntheticRustValidator()
        self._pooled_result = ValidationResult(True, "synthetic")
        self._pooled_escalate = ValidationResult(True, "synthetic")
        self.strict = strict


class _MatcherHost(GovernanceMatcherMixin):
    def __init__(self, *, strict: bool = True) -> None:
        self._rule_data, self._rule_excs = _rule_contract()
        self._rule_id_to_exc_idx = {"WARN": 0, "BLOCK": 1}
        self._rule_id_to_wa = {
            "WARN": ViolationAction.WARN,
            "BLOCK": ViolationAction.BLOCK,
        }
        self._rust_validator = _SyntheticRustValidator()
        self.strict = strict

    def _new_fast_allow_result(self) -> ValidationResult:
        return ValidationResult(True, "synthetic")

    def _new_fast_result(self, *, valid: bool, violations: list, action: str) -> ValidationResult:
        return ValidationResult(valid, "synthetic", violations, action=action)


@pytest.mark.parametrize("host_type", [_DormantDispatchHost, _MatcherHost])
def test_synthetic_no_context_allow_and_unknown(host_type):
    host = host_type()
    records: list[object] = []
    args = ("safe", _RUST_ALLOW, 0, host._rule_excs, records)
    if host_type is _MatcherHost:
        result = host._validate_rust_no_context(*args, strict=True)
    else:
        result = host._validate_rust_no_context(*args)
    assert result is not None and result.valid
    assert records == [None]
    if host_type is _MatcherHost:
        assert host._validate_rust_no_context("x", 999, 0, [], [], strict=True) is None
    else:
        assert host._validate_rust_no_context("x", 999, 0, [], []) is None


@pytest.mark.parametrize("host_type", [_DormantDispatchHost, _MatcherHost])
def test_synthetic_no_context_critical_and_bitmap(host_type):
    host = host_type()
    records: list[object] = []
    with pytest.raises(ConstitutionalViolationError, match="index out of range"):
        if host_type is _MatcherHost:
            host._validate_rust_no_context("bad", _RUST_DENY_CRITICAL, 9, [], records, True)
        else:
            host._validate_rust_no_context("bad", _RUST_DENY_CRITICAL, 9, [], records)
    with pytest.raises(ConstitutionalViolationError):
        if host_type is _MatcherHost:
            host._validate_rust_no_context("bad", _RUST_DENY_CRITICAL, 1, host._rule_excs, [], True)
        else:
            host._validate_rust_no_context("bad", _RUST_DENY_CRITICAL, 1, host._rule_excs, [])
    with pytest.raises(ConstitutionalViolationError, match="BLOCK"):
        if host_type is _MatcherHost:
            host._validate_rust_no_context("bad", _RUST_DENY, 3, host._rule_excs, [], True)
        else:
            host._validate_rust_no_context("bad", _RUST_DENY, 3, host._rule_excs, [])

    host.strict = False
    if host_type is _MatcherHost:
        result = host._validate_rust_no_context("warn", _RUST_DENY, 1, host._rule_excs, [], False)
    else:
        result = host._validate_rust_no_context("warn", _RUST_DENY, 1, host._rule_excs, [])
    assert result is not None and result.valid
    assert [v.rule_id for v in result.violations] == ["WARN"]


@pytest.mark.parametrize("host_type", [_DormantDispatchHost, _MatcherHost])
def test_synthetic_governance_context_merge(host_type):
    host = host_type(strict=False)
    host._rust_validator.hot = {
        "detail": (_RUST_DENY, 1),
        "DETAIL": (_RUST_DENY, 1),
        "critical": (_RUST_DENY_CRITICAL, 1),
    }
    result = host._validate_rust_gov_context(
        "base",
        _RUST_ALLOW,
        0,
        {"action_detail": "DETAIL", "ignored": 1},
        host._rule_excs,
        [],
    )
    assert result is not None
    assert [v.rule_id for v in result.violations] == ["WARN"]

    with pytest.raises(ConstitutionalViolationError):
        host._validate_rust_gov_context(
            "base",
            _RUST_ALLOW,
            0,
            {"action_description": "critical"},
            host._rule_excs,
            [],
        )
    with pytest.raises(ConstitutionalViolationError, match="index out of range"):
        host._validate_rust_gov_context("base", _RUST_DENY_CRITICAL, 99, {}, host._rule_excs, [])
    allowed = host._validate_rust_gov_context(
        "base", _RUST_ALLOW, 0, {"action_detail": 4}, host._rule_excs, []
    )
    assert allowed is not None and allowed.valid


@pytest.mark.parametrize("host_type", [_DormantDispatchHost, _MatcherHost])
def test_synthetic_metadata_context(host_type):
    host = host_type()
    assert host._validate_rust_metadata_context(
        "safe", _RUST_ALLOW, 0, host._rule_excs, [], True
    ).valid
    with pytest.raises(ConstitutionalViolationError, match="index out of range"):
        host._validate_rust_metadata_context(
            "bad", _RUST_DENY_CRITICAL, 8, host._rule_excs, [], True
        )
    with pytest.raises(ConstitutionalViolationError):
        host._validate_rust_metadata_context(
            "bad", _RUST_DENY_CRITICAL, 1, host._rule_excs, [], False
        )
    if host_type is _MatcherHost:
        with pytest.raises(ConstitutionalViolationError, match="BLOCK"):
            host._validate_rust_metadata_context("bad", _RUST_DENY, 3, host._rule_excs, [], True)
    else:
        blocked = host._validate_rust_metadata_context(
            "bad", _RUST_DENY, 3, host._rule_excs, [], True
        )
        assert blocked is not None and [v.rule_id for v in blocked.violations] == ["WARN", "BLOCK"]
    result = host._validate_rust_metadata_context("warn", _RUST_DENY, 1, host._rule_excs, [], False)
    assert result is not None and result.valid
    assert host._validate_rust_metadata_context("x", 999, 0, [], [], False) is None


@pytest.mark.parametrize("host_type", [_DormantDispatchHost, _MatcherHost])
def test_synthetic_full_decoder_contract(host_type):
    host = host_type()
    rv = host._rust_validator
    rv.full = (_RUST_ALLOW, [], False)
    assert host._validate_rust_full("SAFE", True, [], host._rule_excs, []).valid

    rv.full = (_RUST_DENY_CRITICAL, [("OTHER", "other", "high", "", "x")], True)
    with pytest.raises(ConstitutionalViolationError, match="OTHER"):
        host._validate_rust_full("bad", True, [], host._rule_excs, [])

    rv.full = (_RUST_DENY_CRITICAL, [("BLOCK", "block", "high", "", "x")], True)
    with pytest.raises(ConstitutionalViolationError):
        host._validate_rust_full("bad", True, [], host._rule_excs, [])

    rv.full = (_RUST_DENY, [("WARN", "warn", "medium", "", "x")], False)
    result = host._validate_rust_full("warn", False, [], host._rule_excs, [])
    assert result is not None and [v.rule_id for v in result.violations] == ["WARN"]

    rv.full = (_RUST_DENY, [("BLOCK", "block", "high", "", "x")], True)
    with pytest.raises(ConstitutionalViolationError):
        host._validate_rust_full("bad", True, [], host._rule_excs, [])


def test_public_engine_synthetic_dispatch_allows_or_blocks_before_tool() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="BLOCK",
                text="block text",
                severity=Severity.HIGH,
                keywords=["blocked"],
                category="security",
            )
        ],
        name="synthetic-dispatch",
    )
    engine = GovernanceEngine(constitution, strict=True)
    validator = _SyntheticRustValidator()
    validator.hot = {
        "synthetic allow": (_RUST_ALLOW, 0),
        "synthetic deny": (_RUST_DENY, 1),
    }
    hot = list(engine._hot)
    hot[10] = validator
    engine._hot = tuple(hot)
    calls: list[str] = []

    def execute(action: str) -> None:
        engine.validate(action)
        calls.append(action)

    execute("synthetic allow")
    with pytest.raises(ConstitutionalViolationError):
        execute("synthetic deny")
    assert calls == ["synthetic allow"]


def test_authorization_transport_rejects_ambiguous_or_malformed_tokens() -> None:
    with pytest.raises(LegitimacyInvariantError, match="one authorization token"):
        extract_authorization_kwargs({"decision_receipt": object(), "execution_grant": object()})
    extracted = extract_authorization_kwargs(
        {"acgs_receipt": "receipt", "human_approval": {"ok": True}, "other": 1}
    )
    assert extracted["acgs_receipt"] == "receipt"
    assert extracted["human_approval"] == {"ok": True}
    with pytest.raises(LegitimacyInvariantError, match="must be a string"):
        parse_authorization_envelope(3)  # type: ignore[arg-type]
    with pytest.raises(LegitimacyInvariantError, match="valid JSON"):
        parse_authorization_envelope("{")
    with pytest.raises(LegitimacyInvariantError, match="must be an object"):
        parse_authorization_envelope("[]")
    assert parse_authorization_envelope('{"method_id":"m"}') == {"method_id": "m"}
    with pytest.raises(LegitimacyInvariantError, match="unknown authorization profile"):
        resolve_profile("not-a-profile")


def test_invocation_canonicalization_refuses_ambiguous_values() -> None:
    def action(value, *, subjects=(), scope="tenant-a"):
        return value, subjects, scope

    with pytest.raises(LegitimacyInvariantError, match="method override"):
        trusted_method_id(action, override="")
    with pytest.raises(LegitimacyInvariantError, match="override method identity"):
        reject_method_spoof_kwargs(action, {"method": "forged"})
    with pytest.raises(ArgumentNotDigestible, match="arguments do not match"):
        bind_invocation(action, (), {})
    with pytest.raises(ArgumentNotDigestible, match="non-finite"):
        canonical_argument_digest(action, (float("nan"),), {})
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ArgumentNotDigestible, match="cyclic"):
        canonical_argument_digest(action, (cyclic,), {})
    with pytest.raises(ArgumentNotDigestible, match="unsupported argument type"):
        canonical_argument_digest(action, (object(),), {})

    bound = bind_invocation(
        action,
        (b"bytes",),
        {"subjects": {"first": 1, "second": 2}},
    )
    assert bound.scope == "tenant-a"
    assert bound.subjects == ("1", "2")


def test_policy_binding_requires_canonical_content_and_version() -> None:
    class MissingProjection:
        pass

    class MissingVersion:
        def to_dict(self):
            return {"rules": []}

    class ValidProjection:
        version = "policy-v1"

        def to_dict(self):
            return {"rules": [{"id": "A"}]}

    with pytest.raises(ArgumentNotDigestible, match="cannot be canonically digested"):
        bind_policy(MissingProjection())
    with pytest.raises(ArgumentNotDigestible, match="no version"):
        bind_policy(MissingVersion())
    binding = bind_policy(ValidProjection())
    assert binding.version == "policy-v1"
    assert len(binding.digest) == 64


def test_trusted_context_rejects_unbound_and_invalid_subjects() -> None:
    with pytest.raises(LegitimacyInvariantError, match="non-empty strings"):
        TrustedExecutionContext("actor", "tenant-a", frozenset({""}))
    context = TrustedExecutionContext("actor", "tenant-a", frozenset({"account-1"}))

    def action(value: str, *, scope: str, subjects=()):
        return value, scope, subjects

    invocation = bind_invocation(action, ("safe",), {"scope": "tenant-a"})
    with pytest.raises(LegitimacyInvariantError, match="requires bound subjects"):
        context.authorize(invocation)


def test_execution_authority_rejects_every_changed_binding() -> None:
    def action(value: str, *, scope="tenant-a", subjects=("account-1",)):
        return value, scope, subjects

    constitution = Constitution.default()
    invocation = bind_invocation(action, ("safe",), {})
    policy = bind_policy(constitution)
    receipt = build_issue_receipt(func=action, invocation=invocation, policy=policy)
    authority = ExecutionAuthority()
    grant = authority.issue(
        receipt=receipt,
        invocation=invocation,
        policy=policy,
        context_digest="context-a",
    )
    authority.verify(
        grant,
        invocation=invocation,
        policy=policy,
        context_digest="context-a",
    )

    cases = [
        (replace(grant, issuer_id="other"), "issuer"),
        (replace(grant, binding_mac="0" * 64), "authenticity"),
        (replace(grant, method_id="other"), "authenticity"),
        (replace(grant, argument_digest="0" * 64), "authenticity"),
        (replace(grant, policy_digest="0" * 64), "authenticity"),
        (replace(grant, context_digest="context-b"), "authenticity"),
    ]
    for changed, message in cases:
        with pytest.raises(LegitimacyInvariantError, match=message):
            authority.verify(
                changed,
                invocation=invocation,
                policy=policy,
                context_digest="context-a",
            )

    other_invocation = bind_invocation(action, ("different",), {})
    with pytest.raises(LegitimacyInvariantError, match="invocation binding"):
        authority.verify(
            grant,
            invocation=other_invocation,
            policy=policy,
            context_digest="context-a",
        )
    with pytest.raises(LegitimacyInvariantError, match="context binding"):
        authority.verify(grant, invocation=invocation, policy=policy, context_digest="other")


@pytest.mark.parametrize(
    ("expires_at", "message"),
    [
        ("not-a-date", "not parseable"),
        (
            (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            "expired",
        ),
        ((datetime.now() - timedelta(seconds=1)).isoformat(), "expired"),
    ],
)
def test_execution_authority_rejects_bad_or_expired_timestamps(
    expires_at: str, message: str
) -> None:
    def action(value: str):
        return value

    invocation = bind_invocation(action, ("safe",), {})
    policy = bind_policy(Constitution.default())
    receipt = build_issue_receipt(func=action, invocation=invocation, policy=policy)
    authority = ExecutionAuthority()
    grant = authority.issue(
        receipt=receipt,
        invocation=invocation,
        policy=policy,
        expires_at=expires_at,
    )
    with pytest.raises(LegitimacyInvariantError, match=message):
        authority.verify(grant, invocation=invocation, policy=policy)


@pytest.mark.parametrize("positive", [True, False])
def test_python_matcher_synthetic_automaton_contract(positive: bool) -> None:
    """Exercise decoded Aho payloads without claiming a native backend is present."""
    host = _MatcherHost(strict=False)
    if positive:
        payloads = [
            (0, (0, [(0, True), (1, False)])),
            (1, (1, 0)),
            (2, (2, [(1, True)], 0)),
        ]
    else:
        payloads = [
            (0, (0, [(0, False), (0, False)])),
            (1, (1, 0)),
            (2, (2, [(1, False)], 0)),
        ]
    host._ac_iter = lambda _text: iter(payloads)
    host._pat_anchor_dispatch = (("detail", [(0, re.compile("detail")), (1, re.compile("never"))]),)
    host._no_anchor_patterns = [
        (1, re.compile("secret")),
        (0, re.compile("detail")),
    ]
    result = host._validate_python_ac(
        "detail secret",
        False,
        "detail secret",
        positive,
        None,
    )
    assert result is not None
    assert {violation.rule_id for violation in result} == {"WARN", "BLOCK"}


@pytest.mark.parametrize("positive", [True, False])
def test_python_matcher_strict_critical_payload_blocks(positive: bool) -> None:
    host = _MatcherHost()
    host._ac_iter = lambda _text: iter([(0, (0, [(1, True)]))])
    host._pat_anchor_dispatch = ()
    host._no_anchor_patterns = []
    with pytest.raises(ConstitutionalViolationError, match="block text"):
        host._validate_python_ac("blocked", True, "blocked", positive, None)


def test_execution_boundary_rejects_method_scope_subject_and_expiry_mismatch() -> None:
    actual = ActualCall("transfer", "tenant-a", ("account-1",))
    boundaries = [
        ExecutionBoundary("other", "tenant-a", ("account-1",), None, True),
        ExecutionBoundary("transfer", "tenant-b", ("account-1",), None, True),
        ExecutionBoundary("transfer", "tenant-a", ("account-2",), None, True),
        ExecutionBoundary("transfer", "tenant-a", ("account-1",), "invalid", True),
        ExecutionBoundary(
            "transfer",
            "tenant-a",
            ("account-1",),
            (datetime.now() - timedelta(seconds=1)).isoformat(),
            True,
        ),
    ]
    assert all(not call_matches(boundary, actual) for boundary in boundaries)
    missing_subject = ActualCall("transfer", "tenant-a", ())
    assert not call_matches(boundaries[2], missing_subject)
    future = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    assert call_matches(
        ExecutionBoundary("transfer", "tenant-a", ("account-1",), future, True),
        actual,
    )


def test_actual_call_normalization_uses_signature_and_trust_mode() -> None:
    def action(account_id: str, *, tenant_id="tenant-a", **kwargs):
        return account_id, tenant_id, kwargs

    trusted = normalize_actual_call(
        fallback_method="action",
        args=("account-1",),
        kwargs={"method": "caller-label", "scope": "caller-scope"},
        func=action,
        trust_kwargs=True,
    )
    assert trusted == ActualCall("caller-label", "caller-scope", ("account-1",))
    untrusted = normalize_actual_call(
        fallback_method="action",
        args=("account-1",),
        kwargs={"method": "caller-label", "scope": "caller-scope"},
        func=action,
        trust_kwargs=False,
    )
    assert untrusted == ActualCall("action", "tenant-a", ("account-1",))
    assert normalize_actual_call(fallback_method="opaque", kwargs={}, func=None) == ActualCall(
        "opaque", None, ()
    )


def test_receipt_execution_refuses_unverifiable_audit_and_control_evidence() -> None:
    def action(account_id: str):
        return account_id

    invocation = bind_invocation(action, ("account-1",), {})
    policy = bind_policy(Constitution.default())
    receipt = build_issue_receipt(func=action, invocation=invocation, policy=policy)

    class MissingVerifier:
        pass

    class RaisingVerifier:
        def verify_chain(self):
            raise RuntimeError("synthetic failure")

    for audit in (MissingVerifier(), RaisingVerifier()):
        with pytest.raises(LegitimacyInvariantError, match="Audit evidence"):
            validate_receipt_for_execution(receipt, audit_log=audit)

    controlled = DecisionReceipt.create(
        request_id=receipt.request_id,
        goal=receipt.goal,
        proposed_method=receipt.proposed_method,
        decision_type=receipt.decision_type,
        authority_basis=receipt.authority_basis,
        matched_constraints=receipt.matched_constraints,
        policy_version=receipt.policy_version,
        required_controls=("HUMAN_APPROVAL",),
        execution_boundary=receipt.execution_boundary,
        issued_at=receipt.issued_at,
    )
    with pytest.raises(LegitimacyInvariantError, match="structured approval"):
        validate_receipt_for_execution(controlled)
    validate_receipt_for_execution(
        controlled,
        human_approval={
            "approved_by": "reviewer",
            "approved_at": "2026-09-17T00:00:00Z",
            "approval_id": "approval-1",
        },
    )
    assert route_ambiguous_decision(None) == "STRUCTURED_REVIEW_REQUIRED"
    assert route_ambiguous_decision(0.9) == "ALLOW"


def test_decision_taxonomy_rejects_unknown_and_preserves_fail_closed_states() -> None:
    assert canonicalize_decision_state("deny", critical=True) == "DENY_GOAL"
    assert canonicalize_decision_state("allow", kill_switch=True) == "HARD_DENY"
    assert is_allow_state("ALLOW") is True
    assert is_allow_state("unknown-state") is False


def test_execution_signature_binds_envelope_and_rejects_malformed_wire_data() -> None:
    def action(account_id: str):
        return account_id

    invocation = bind_invocation(action, ("account-1",), {})
    policy = bind_policy(Constitution.default())
    receipt = build_issue_receipt(func=action, invocation=invocation, policy=policy)
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        Ed25519ReceiptSigner.from_seed(b"short")
    signer = Ed25519ReceiptSigner.from_seed(b"s" * 32, key_id="test-key")
    signed = sign_execution_authorization(
        receipt,
        signer,
        authorization_json='{ "method_id": "action" }',
    )
    assert signed.signature_scope == SIGNATURE_SCOPE_EXECUTION
    assert signed.verify(signer.public_key_hex()) is True
    assert signed.verify("00" * 32) is False
    assert signed.to_dict()["authorization_json"] is not None
    assert SignedReceipt.from_dict(signed.to_dict()).verify_integrity() is True

    with pytest.raises(ValueError, match="Unsupported"):
        verify_signature("rsa", signer.public_key_hex(), b"message", "00")
    assert verify_signature("ed25519", "not-hex", b"message", "00") is False
    with pytest.raises(ValueError, match="malformed signed-receipt"):
        SignedReceipt.from_dict({"authorization_json": 7})
    missing_envelope = replace(signed, authorization_json=None)
    assert missing_envelope.verify_integrity() is False


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("policy_version", "", "policy version"),
        ("authority_basis", "", "authority basis"),
        ("execution_boundary", None, "execution boundary"),
        ("matched_constraints", None, "constraint proof"),
        ("matched_constraints", (), "Empty constraint proof"),
    ],
)
def test_corrupted_receipt_fields_fail_before_execution(
    field: str, value: object, message: str
) -> None:
    def action(value: str):
        return value

    invocation = bind_invocation(action, ("safe",), {})
    policy = bind_policy(Constitution.default())
    receipt = build_issue_receipt(func=action, invocation=invocation, policy=policy)
    object.__setattr__(receipt, field, value)
    with pytest.raises(LegitimacyInvariantError, match=message):
        validate_receipt_for_execution(receipt)


def test_receipt_hash_verifier_failure_is_fail_closed(monkeypatch) -> None:
    def action(value: str):
        return value

    invocation = bind_invocation(action, ("safe",), {})
    policy = bind_policy(Constitution.default())
    receipt = build_issue_receipt(func=action, invocation=invocation, policy=policy)

    def raises(_self):
        raise RuntimeError("synthetic verifier failure")

    monkeypatch.setattr(DecisionReceipt, "verify_hash", raises)
    with pytest.raises(LegitimacyInvariantError, match="integrity check"):
        validate_receipt_for_execution(receipt)


def test_actual_call_normalizes_mapping_scalar_and_uninspectable_inputs() -> None:
    def action(*, subjects=()):
        return subjects

    mapping = normalize_actual_call(
        fallback_method="action",
        kwargs={"subjects": {"first": 1, "second": 2}},
        func=action,
    )
    assert mapping.subjects == ("1", "2")
    scalar = normalize_actual_call(fallback_method="action", kwargs={"subjects": 7}, func=action)
    assert scalar.subjects == ("7",)
    invalid = normalize_actual_call(
        fallback_method="action", kwargs={}, args=("extra",), func=action
    )
    assert invalid == ActualCall("action", None, ())
    opaque = normalize_actual_call(
        fallback_method="action",
        kwargs={},
        func=object(),  # type: ignore[arg-type]
    )
    assert opaque == ActualCall("action", None, ())
