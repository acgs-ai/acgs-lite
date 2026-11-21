"""Comprehensive tests for under-covered acgs-lite constitution modules (batch 3c).

Targets: access_control, consent, delegation_token, change_request,
observability_exporter, incident, obligation_engine, nearmiss, notification,
attestation, certificate, abac, compliance_mapping, emergency,
intent_alignment, ratelimit, cost_budget, escrow, data_classification,
autonomy_ratio, enforcement, boundaries.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

# ── access_control ──────────────────────────────────────────────────────────
from acgs_lite.constitution.access_control import (
    AccessCheckResult,
    AccessCondition,
    AccessDecision,
    AccessPolicy,
    AccessRole,
    GovernanceAccessControl,
    Permission,
)


class TestAccessCondition:
    def test_evaluate_true(self) -> None:
        cond = AccessCondition("is_admin", lambda ctx: ctx.get("role") == "admin")
        assert cond.evaluate({"role": "admin"}) is True

    def test_evaluate_false(self) -> None:
        cond = AccessCondition("is_admin", lambda ctx: ctx.get("role") == "admin")
        assert cond.evaluate({"role": "viewer"}) is False

    def test_evaluate_exception_returns_false(self) -> None:
        cond = AccessCondition("boom", lambda ctx: 1 / 0)  # type: ignore[arg-type]
        assert cond.evaluate({}) is False


class TestAccessPolicy:
    def test_grants_permission_present(self) -> None:
        policy = AccessPolicy("p1", permissions={Permission.READ_RULES})
        assert policy.grants(Permission.READ_RULES) is True

    def test_grants_denied_permission_returns_false(self) -> None:
        policy = AccessPolicy(
            "p1",
            permissions={Permission.READ_RULES, Permission.WRITE_RULES},
            denied_permissions={Permission.WRITE_RULES},
        )
        assert policy.grants(Permission.WRITE_RULES) is False

    def test_grants_not_in_permissions_returns_false(self) -> None:
        policy = AccessPolicy("p1", permissions={Permission.READ_RULES})
        assert policy.grants(Permission.DELETE_RULES) is False

    def test_grants_with_conditions_true(self) -> None:
        cond = AccessCondition("ok", lambda ctx: ctx.get("ok") is True)
        policy = AccessPolicy("p1", permissions={Permission.EXECUTE}, conditions=[cond])
        assert policy.grants(Permission.EXECUTE, {"ok": True}) is True

    def test_grants_with_conditions_false(self) -> None:
        cond = AccessCondition("ok", lambda ctx: ctx.get("ok") is True)
        policy = AccessPolicy("p1", permissions={Permission.EXECUTE}, conditions=[cond])
        assert policy.grants(Permission.EXECUTE, {"ok": False}) is False

    def test_grants_with_conditions_no_context_returns_false(self) -> None:
        cond = AccessCondition("ok", lambda ctx: True)
        policy = AccessPolicy("p1", permissions={Permission.EXECUTE}, conditions=[cond])
        assert policy.grants(Permission.EXECUTE) is False

    def test_matches_resource_wildcard(self) -> None:
        policy = AccessPolicy("p1", permissions=set(), resource_scope="*")
        assert policy.matches_resource("anything") is True

    def test_matches_resource_prefix(self) -> None:
        policy = AccessPolicy("p1", permissions=set(), resource_scope="rules/*")
        assert policy.matches_resource("rules/abc") is True
        assert policy.matches_resource("audit/abc") is False

    def test_matches_resource_exact(self) -> None:
        policy = AccessPolicy("p1", permissions=set(), resource_scope="rules/abc")
        assert policy.matches_resource("rules/abc") is True
        assert policy.matches_resource("rules/xyz") is False


class TestGovernanceAccessControl:
    def _setup_acl(self) -> GovernanceAccessControl:
        acl = GovernanceAccessControl()
        admin_policy = AccessPolicy(
            "admin_pol",
            permissions={Permission.READ_RULES, Permission.WRITE_RULES, Permission.MANAGE_ROLES},
        )
        reader_policy = AccessPolicy(
            "reader_pol",
            permissions={Permission.READ_RULES, Permission.READ_AUDIT, Permission.VIEW_METRICS},
        )
        acl.add_role(AccessRole("admin", policies=[admin_policy]))
        acl.add_role(AccessRole("reader", policies=[reader_policy]))
        acl.assign("alice", "admin")
        acl.assign("bob", "reader")
        return acl

    def test_check_allow(self) -> None:
        acl = self._setup_acl()
        result = acl.check("alice", Permission.WRITE_RULES)
        assert result.decision == AccessDecision.ALLOW

    def test_check_deny_no_roles(self) -> None:
        acl = self._setup_acl()
        result = acl.check("nobody", Permission.READ_RULES)
        assert result.decision == AccessDecision.DENY
        assert "No roles" in result.reason

    def test_check_deny_no_matching_policy(self) -> None:
        acl = self._setup_acl()
        result = acl.check("bob", Permission.WRITE_RULES)
        assert result.decision == AccessDecision.DENY

    def test_check_deny_explicit_denied(self) -> None:
        acl = GovernanceAccessControl()
        policy = AccessPolicy(
            "restricted",
            permissions={Permission.READ_RULES, Permission.WRITE_RULES},
            denied_permissions={Permission.WRITE_RULES},
        )
        acl.add_role(AccessRole("restricted_role", policies=[policy]))
        acl.assign("agent", "restricted_role")
        result = acl.check("agent", Permission.WRITE_RULES)
        assert result.decision == AccessDecision.DENY
        assert "Explicitly denied" in result.reason

    def test_check_resource_scoping(self) -> None:
        acl = GovernanceAccessControl()
        policy = AccessPolicy(
            "scoped",
            permissions={Permission.READ_RULES},
            resource_scope="rules/*",
        )
        acl.add_role(AccessRole("scoped_reader", policies=[policy]))
        acl.assign("agent", "scoped_reader")
        assert (
            acl.check("agent", Permission.READ_RULES, "rules/abc").decision == AccessDecision.ALLOW
        )
        assert (
            acl.check("agent", Permission.READ_RULES, "audit/abc").decision == AccessDecision.DENY
        )

    def test_check_no_record(self) -> None:
        acl = self._setup_acl()
        acl.check("alice", Permission.READ_RULES, record=False)
        assert len(acl.audit_log()) == 0

    def test_assign_invalid_role(self) -> None:
        acl = GovernanceAccessControl()
        assert acl.assign("alice", "nonexistent") is False

    def test_revoke(self) -> None:
        acl = self._setup_acl()
        assert acl.revoke("alice", "admin") is True
        result = acl.check("alice", Permission.WRITE_RULES)
        assert result.decision == AccessDecision.DENY

    def test_revoke_missing_principal(self) -> None:
        acl = GovernanceAccessControl()
        assert acl.revoke("nobody", "admin") is False

    def test_remove_role(self) -> None:
        acl = self._setup_acl()
        assert acl.remove_role("admin") is True
        result = acl.check("alice", Permission.WRITE_RULES)
        assert result.decision == AccessDecision.DENY

    def test_remove_role_missing(self) -> None:
        acl = GovernanceAccessControl()
        assert acl.remove_role("nonexistent") is False

    def test_check_all(self) -> None:
        acl = self._setup_acl()
        results = acl.check_all("alice", [Permission.READ_RULES, Permission.DELETE_RULES])
        assert results[Permission.READ_RULES.value].decision == AccessDecision.ALLOW
        assert results[Permission.DELETE_RULES.value].decision == AccessDecision.DENY

    def test_effective_permissions(self) -> None:
        acl = self._setup_acl()
        perms = acl.effective_permissions("alice")
        assert Permission.READ_RULES in perms
        assert Permission.WRITE_RULES in perms
        assert Permission.DELETE_RULES not in perms

    def test_principals_with_permission(self) -> None:
        acl = self._setup_acl()
        principals = acl.principals_with_permission(Permission.READ_RULES)
        assert "alice" in principals
        assert "bob" in principals

    def test_audit_log_filtered(self) -> None:
        acl = self._setup_acl()
        acl.check("alice", Permission.READ_RULES)
        acl.check("bob", Permission.READ_RULES)
        log = acl.audit_log(principal="alice")
        assert all(e["principal"] == "alice" for e in log)

    def test_audit_log_by_decision(self) -> None:
        acl = self._setup_acl()
        acl.check("alice", Permission.READ_RULES)
        acl.check("nobody", Permission.READ_RULES)
        deny_log = acl.audit_log(decision=AccessDecision.DENY)
        assert all(e["decision"] == "deny" for e in deny_log)

    def test_summary(self) -> None:
        acl = self._setup_acl()
        acl.check("alice", Permission.READ_RULES)
        s = acl.summary()
        assert s["role_count"] == 2
        assert s["principal_count"] == 2
        assert s["total_checks"] >= 1

    def test_role_inheritance(self) -> None:
        acl = GovernanceAccessControl()
        base_policy = AccessPolicy("base", permissions={Permission.READ_RULES})
        child_policy = AccessPolicy("child", permissions={Permission.WRITE_RULES})
        acl.add_role(AccessRole("base_role", policies=[base_policy]))
        acl.add_role(AccessRole("child_role", policies=[child_policy], parent="base_role"))
        acl.assign("agent", "child_role")
        assert acl.check("agent", Permission.WRITE_RULES).decision == AccessDecision.ALLOW
        assert acl.check("agent", Permission.READ_RULES).decision == AccessDecision.ALLOW

    def test_access_check_result_to_dict(self) -> None:
        result = AccessCheckResult(
            decision=AccessDecision.ALLOW,
            permission=Permission.READ_RULES,
            principal="alice",
            resource="*",
        )
        d = result.to_dict()
        assert d["decision"] == "allow"
        assert d["permission"] == "read_rules"


# ── consent ─────────────────────────────────────────────────────────────────

from acgs_lite.constitution.consent import (
    ConsentManager,
    ConsentRecord,
    ConsentStatus,
    DataSubjectRight,
    LawfulBasis,
    RightsRequest,
)


class TestConsentRecord:
    def test_is_valid_active(self) -> None:
        record = ConsentRecord(
            "user1", "marketing", LawfulBasis.CONSENT, status=ConsentStatus.ACTIVE
        )
        assert record.is_valid is True

    def test_is_valid_withdrawn(self) -> None:
        record = ConsentRecord(
            "user1", "marketing", LawfulBasis.CONSENT, status=ConsentStatus.WITHDRAWN
        )
        assert record.is_valid is False

    def test_is_valid_expired(self) -> None:
        record = ConsentRecord(
            "user1",
            "marketing",
            LawfulBasis.CONSENT,
            status=ConsentStatus.ACTIVE,
            expires_at=time.time() - 10,
        )
        assert record.is_valid is False

    def test_integrity_hash(self) -> None:
        record = ConsentRecord("user1", "marketing", LawfulBasis.CONSENT)
        h = record.integrity_hash()
        assert isinstance(h, str) and len(h) == 16


class TestRightsRequest:
    def test_is_overdue_fresh(self) -> None:
        req = RightsRequest("user1", DataSubjectRight.ACCESS)
        assert req.is_overdue is False

    def test_is_overdue_old(self) -> None:
        req = RightsRequest(
            "user1",
            DataSubjectRight.ACCESS,
            requested_at=time.time() - (31 * 24 * 3600),
        )
        assert req.is_overdue is True

    def test_is_overdue_fulfilled(self) -> None:
        req = RightsRequest(
            "user1",
            DataSubjectRight.ACCESS,
            requested_at=time.time() - (31 * 24 * 3600),
            status="fulfilled",
        )
        assert req.is_overdue is False


class TestConsentManager:
    def test_grant_and_has_valid(self) -> None:
        mgr = ConsentManager()
        mgr.grant("user1", "marketing", LawfulBasis.CONSENT)
        assert mgr.has_valid_consent("user1", "marketing") is True

    def test_withdraw(self) -> None:
        mgr = ConsentManager()
        mgr.grant("user1", "marketing", LawfulBasis.CONSENT)
        assert mgr.withdraw("user1", "marketing") is True
        assert mgr.has_valid_consent("user1", "marketing") is False

    def test_withdraw_nonexistent(self) -> None:
        mgr = ConsentManager()
        assert mgr.withdraw("user1", "marketing") is False

    def test_withdraw_all(self) -> None:
        mgr = ConsentManager()
        mgr.grant("user1", "marketing", LawfulBasis.CONSENT)
        mgr.grant("user1", "analytics", LawfulBasis.LEGITIMATE_INTERESTS)
        count = mgr.withdraw_all("user1")
        assert count == 2
        assert mgr.has_valid_consent("user1", "marketing") is False

    def test_withdraw_all_empty(self) -> None:
        mgr = ConsentManager()
        assert mgr.withdraw_all("nobody") == 0

    def test_has_valid_consent_expired(self) -> None:
        mgr = ConsentManager()
        mgr.grant("user1", "marketing", LawfulBasis.CONSENT, expires_at=time.time() - 1)
        assert mgr.has_valid_consent("user1", "marketing") is False

    def test_check_processing_allowed(self) -> None:
        mgr = ConsentManager()
        mgr.grant(
            "user1",
            "marketing",
            LawfulBasis.CONSENT,
            processing_activities=["email", "sms"],
        )
        result = mgr.check_processing_allowed("user1", "marketing", "email")
        assert result["allowed"] is True

    def test_check_processing_disallowed_activity(self) -> None:
        mgr = ConsentManager()
        mgr.grant(
            "user1",
            "marketing",
            LawfulBasis.CONSENT,
            processing_activities=["email"],
        )
        result = mgr.check_processing_allowed("user1", "marketing", "sms")
        assert result["allowed"] is False

    def test_check_processing_no_consent(self) -> None:
        mgr = ConsentManager()
        result = mgr.check_processing_allowed("user1", "marketing", "email")
        assert result["allowed"] is False

    def test_check_processing_withdrawn(self) -> None:
        mgr = ConsentManager()
        mgr.grant("user1", "marketing", LawfulBasis.CONSENT)
        mgr.withdraw("user1", "marketing")
        result = mgr.check_processing_allowed("user1", "marketing", "email")
        assert result["allowed"] is False

    def test_grant_versioning(self) -> None:
        mgr = ConsentManager()
        r1 = mgr.grant("user1", "marketing", LawfulBasis.CONSENT)
        assert r1.version == 1
        r2 = mgr.grant("user1", "marketing", LawfulBasis.CONSENT)
        assert r2.version == 2

    def test_submit_and_fulfill_rights_request(self) -> None:
        mgr = ConsentManager()
        req = mgr.submit_rights_request("user1", DataSubjectRight.ACCESS)
        assert req.status == "pending"
        mgr.fulfill_rights_request(req, "data exported")
        assert req.status == "fulfilled"

    def test_subject_report(self) -> None:
        mgr = ConsentManager()
        mgr.grant("user1", "marketing", LawfulBasis.CONSENT, data_categories=["email"])
        report = mgr.subject_report("user1")
        assert report["active_consents"] == 1
        assert "email" in report["data_categories_in_scope"]

    def test_compliance_report(self) -> None:
        mgr = ConsentManager()
        mgr.grant("user1", "marketing", LawfulBasis.CONSENT)
        report = mgr.compliance_report()
        assert report["total_subjects"] == 1
        assert report["gdpr_compliant"] is True

    def test_export_subject_data(self) -> None:
        mgr = ConsentManager()
        mgr.grant("user1", "marketing", LawfulBasis.CONSENT)
        data = mgr.export_subject_data("user1")
        assert data["subject_id"] == "user1"
        assert len(data["consent_records"]) == 1

    def test_erase_subject(self) -> None:
        mgr = ConsentManager()
        mgr.grant("user1", "marketing", LawfulBasis.CONSENT)
        assert mgr.erase_subject("user1") is True
        assert mgr.erase_subject("user1") is False

    def test_audit_log(self) -> None:
        mgr = ConsentManager()
        mgr.grant("user1", "marketing", LawfulBasis.CONSENT)
        log = mgr.audit_log(subject_id="user1")
        assert len(log) >= 1


# ── delegation_token ────────────────────────────────────────────────────────

from acgs_lite.constitution.delegation_token import (
    DelegationScope,
    DelegationTokenAuthority,
    TokenStatus,
    VerificationResult,
)


class TestDelegationScope:
    def test_allows_permission(self) -> None:
        scope = DelegationScope(permissions={"read", "write"})
        assert scope.allows("read") is True
        assert scope.allows("delete") is False

    def test_allows_excluded(self) -> None:
        scope = DelegationScope(permissions={"read", "write"}, excluded_actions={"write"})
        assert scope.allows("write") is False

    def test_allows_resource_pattern(self) -> None:
        scope = DelegationScope(permissions={"read"}, resource_patterns=["data/*"])
        assert scope.allows("read", "data/abc") is True
        assert scope.allows("read", "logs/abc") is False

    def test_allows_empty_perms_allows_all(self) -> None:
        scope = DelegationScope()
        assert scope.allows("anything") is True

    def test_narrow(self) -> None:
        parent = DelegationScope(permissions={"read", "write"}, max_depth=3)
        child = DelegationScope(permissions={"read"}, max_depth=2)
        narrowed = parent.narrow(child)
        assert narrowed.permissions == {"read"}
        assert narrowed.max_depth == 2

    def test_narrow_excluded_union(self) -> None:
        parent = DelegationScope(excluded_actions={"delete"})
        child = DelegationScope(excluded_actions={"write"})
        narrowed = parent.narrow(child)
        assert narrowed.excluded_actions == {"delete", "write"}

    def test_to_dict(self) -> None:
        scope = DelegationScope(permissions={"read"}, max_depth=2)
        d = scope.to_dict()
        assert d["permissions"] == ["read"]
        assert d["max_depth"] == 2


class TestDelegationTokenAuthority:
    def test_issue_and_verify(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read"})
        token = auth.issue("admin", "agent", scope)
        result = auth.verify(token)
        assert result.status == TokenStatus.VALID

    def test_verify_invalid_signature(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read"})
        token = auth.issue("admin", "agent", scope)
        token.signature = "tampered"
        result = auth.verify(token)
        assert result.status == TokenStatus.INVALID_SIGNATURE

    def test_verify_revoked(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read"})
        token = auth.issue("admin", "agent", scope)
        auth.revoke(token.token_id)
        result = auth.verify(token)
        assert result.status == TokenStatus.REVOKED

    def test_delegate(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read", "write"}, max_depth=2)
        parent = auth.issue("admin", "agent-1", scope)
        child = auth.delegate(parent, "agent-1", "agent-2", DelegationScope(permissions={"read"}))
        assert child is not None
        assert auth.verify(child).status == TokenStatus.VALID
        assert child.chain_depth == 1

    def test_delegate_wrong_delegator(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read"}, max_depth=2)
        parent = auth.issue("admin", "agent-1", scope)
        result = auth.delegate(parent, "agent-2", "agent-3", DelegationScope())
        assert result is None

    def test_delegate_max_depth_reached(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read"}, max_depth=1)
        parent = auth.issue("admin", "agent-1", scope)
        child = auth.delegate(parent, "agent-1", "agent-2", DelegationScope())
        assert child is not None
        result = auth.delegate(child, "agent-2", "agent-3", DelegationScope())
        assert result is None

    def test_check_permission(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read"})
        token = auth.issue("admin", "agent", scope)
        result = auth.check_permission(token, "read")
        assert result.status == TokenStatus.VALID
        result = auth.check_permission(token, "write")
        assert result.status == TokenStatus.SCOPE_VIOLATION

    def test_revoke_chain(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read"}, max_depth=3)
        parent = auth.issue("admin", "agent-1", scope)
        child = auth.delegate(parent, "agent-1", "agent-2", DelegationScope())
        assert child is not None
        count = auth.revoke_chain(parent.token_id)
        assert count >= 2

    def test_active_tokens(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read"})
        auth.issue("admin", "agent", scope)
        active = auth.active_tokens()
        assert len(active) == 1

    def test_chain_for(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read"}, max_depth=2)
        parent = auth.issue("admin", "agent-1", scope)
        child = auth.delegate(parent, "agent-1", "agent-2", DelegationScope())
        assert child is not None
        chain = auth.chain_for(child.token_id)
        assert parent.token_id in chain

    def test_summary(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        s = auth.summary()
        assert s["total_issued"] == 0

    def test_verify_parent_revoked(self) -> None:
        auth = DelegationTokenAuthority(signing_key="secret")
        scope = DelegationScope(permissions={"read"}, max_depth=2)
        parent = auth.issue("admin", "agent-1", scope)
        child = auth.delegate(parent, "agent-1", "agent-2", DelegationScope())
        assert child is not None
        auth.revoke(parent.token_id)
        result = auth.verify(child)
        assert result.status == TokenStatus.REVOKED

    def test_verification_result_to_dict(self) -> None:
        r = VerificationResult(TokenStatus.VALID, "token-1")
        d = r.to_dict()
        assert d["status"] == "valid"


# ── change_request ──────────────────────────────────────────────────────────

from acgs_lite.constitution.change_request import (
    ChangeRequestManager,
    ChangeRequestStatus,
    ChangeType,
)


class TestChangeRequestManager:
    def test_create(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Add rule", ChangeType.ADD_RULE, "admin")
        assert cr.status == ChangeRequestStatus.DRAFT
        assert cr.request_id.startswith("CR-")

    def test_full_lifecycle(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Add rule", ChangeType.ADD_RULE, "admin")
        assert mgr.submit(cr.request_id) is True
        assert mgr.review(cr.request_id) is True
        assert mgr.approve(cr.request_id, approver="lead") is True
        assert cr.status == ChangeRequestStatus.APPROVED
        assert mgr.apply(cr.request_id) is True
        assert cr.status == ChangeRequestStatus.APPLIED

    def test_reject(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Bad rule", ChangeType.ADD_RULE, "admin")
        mgr.submit(cr.request_id)
        assert mgr.reject(cr.request_id, "reviewer", "Not compliant") is True
        assert cr.status == ChangeRequestStatus.REJECTED

    def test_approve_self_blocked(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Rule", ChangeType.ADD_RULE, "admin")
        mgr.submit(cr.request_id)
        assert mgr.approve(cr.request_id, approver="admin") is False

    def test_approve_duplicate_blocked(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Rule", ChangeType.ADD_RULE, "admin", required_approvals=3)
        mgr.submit(cr.request_id)
        assert mgr.approve(cr.request_id, approver="lead-1") is True
        assert mgr.approve(cr.request_id, approver="lead-1") is False

    def test_multi_approver(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Rule", ChangeType.ADD_RULE, "admin", required_approvals=2)
        mgr.submit(cr.request_id)
        mgr.approve(cr.request_id, approver="lead-1")
        assert cr.status != ChangeRequestStatus.APPROVED
        mgr.approve(cr.request_id, approver="lead-2")
        assert cr.status == ChangeRequestStatus.APPROVED

    def test_rollback(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Rule", ChangeType.ADD_RULE, "admin")
        mgr.submit(cr.request_id)
        mgr.approve(cr.request_id, approver="lead")
        mgr.apply(cr.request_id)
        assert mgr.rollback(cr.request_id, reason="broken") is True
        assert cr.status == ChangeRequestStatus.ROLLED_BACK

    def test_rollback_not_applied(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Rule", ChangeType.ADD_RULE, "admin")
        assert mgr.rollback(cr.request_id) is False

    def test_cancel(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Rule", ChangeType.ADD_RULE, "admin")
        assert mgr.cancel(cr.request_id) is True
        assert cr.status == ChangeRequestStatus.CANCELLED

    def test_cancel_cancelled_fails(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Rule", ChangeType.ADD_RULE, "admin")
        mgr.cancel(cr.request_id)
        assert mgr.cancel(cr.request_id) is False

    def test_reopen(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Rule", ChangeType.ADD_RULE, "admin")
        mgr.submit(cr.request_id)
        mgr.reject(cr.request_id, "reviewer")
        assert mgr.reopen(cr.request_id) is True
        assert cr.status == ChangeRequestStatus.DRAFT
        assert len(cr.approvers) == 0

    def test_reopen_invalid(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Rule", ChangeType.ADD_RULE, "admin")
        assert mgr.reopen(cr.request_id) is False

    def test_get(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("Rule", ChangeType.ADD_RULE, "admin")
        assert mgr.get(cr.request_id) is cr
        assert mgr.get("nonexistent") is None

    def test_query_by_status(self) -> None:
        mgr = ChangeRequestManager()
        mgr.create("A", ChangeType.ADD_RULE, "admin")
        assert len(mgr.query_by_status(ChangeRequestStatus.DRAFT)) == 1

    def test_query_by_proposer(self) -> None:
        mgr = ChangeRequestManager()
        mgr.create("A", ChangeType.ADD_RULE, "admin")
        mgr.create("B", ChangeType.ADD_RULE, "other")
        assert len(mgr.query_by_proposer("admin")) == 1

    def test_query_pending(self) -> None:
        mgr = ChangeRequestManager()
        mgr.create("A", ChangeType.ADD_RULE, "admin")
        assert len(mgr.query_pending()) == 1

    def test_summary(self) -> None:
        mgr = ChangeRequestManager()
        mgr.create("A", ChangeType.ADD_RULE, "admin")
        s = mgr.summary()
        assert s["total"] == 1

    def test_apply_not_approved(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("A", ChangeType.ADD_RULE, "admin")
        assert mgr.apply(cr.request_id) is False

    def test_reject_wrong_status(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("A", ChangeType.ADD_RULE, "admin")
        # Draft status, reject not valid from draft
        assert mgr.reject(cr.request_id, "reviewer") is False

    def test_approve_wrong_status(self) -> None:
        mgr = ChangeRequestManager()
        cr = mgr.create("A", ChangeType.ADD_RULE, "admin")
        # Draft status, approve not valid from draft
        assert mgr.approve(cr.request_id, approver="lead") is False

    def test_nonexistent_operations(self) -> None:
        mgr = ChangeRequestManager()
        assert mgr.submit("XX") is False
        assert mgr.apply("XX") is False
        assert mgr.approve("XX", "lead") is False
        assert mgr.reject("XX", "lead") is False
        assert mgr.rollback("XX") is False
        assert mgr.reopen("XX") is False


# ── observability_exporter ──────────────────────────────────────────────────

from acgs_lite.constitution.observability_exporter import (
    GovernanceObservabilityExporter,
    HistogramBucket,
    HistogramMetric,
)


class TestHistogramMetric:
    def test_record_and_mean(self) -> None:
        h = HistogramMetric(name="test", buckets=[HistogramBucket(le=1.0), HistogramBucket(le=5.0)])
        h.record(0.5)
        h.record(3.0)
        assert h.count == 2
        assert h.mean == pytest.approx(1.75)

    def test_mean_empty(self) -> None:
        h = HistogramMetric(name="test")
        assert h.mean == 0.0


class TestGovernanceObservabilityExporter:
    def test_record_decision(self) -> None:
        exp = GovernanceObservabilityExporter(service_name="test")
        exp.record_decision(action="deploy", outcome="allow", latency_ms=1.0)
        assert exp.decision_counts["allow"] == 1
        assert len(exp.traces) == 1

    def test_record_with_violations(self) -> None:
        exp = GovernanceObservabilityExporter()
        exp.record_decision(action="delete", outcome="deny", violations=["SAFE-001"])
        assert exp.rule_trigger_counts["SAFE-001"] == 1

    def test_compliance_gauge(self) -> None:
        exp = GovernanceObservabilityExporter()
        exp.record_decision(action="a", outcome="allow")
        exp.record_decision(action="b", outcome="deny")
        assert 0.0 < exp.compliance_gauge < 1.0

    def test_prometheus_exposition(self) -> None:
        exp = GovernanceObservabilityExporter()
        exp.record_decision(action="deploy", outcome="allow", latency_ms=1.0)
        text = exp.prometheus_exposition()
        assert "governance_decisions_total" in text
        assert "governance_decision_latency_ms" in text

    def test_otel_json(self) -> None:
        exp = GovernanceObservabilityExporter()
        exp.record_decision(action="deploy", outcome="allow", latency_ms=1.0)
        data = exp.otel_json()
        assert "resourceMetrics" in data
        assert "resourceSpans" in data

    def test_otel_json_no_traces(self) -> None:
        exp = GovernanceObservabilityExporter()
        data = exp.otel_json()
        assert data["resourceSpans"] == []

    def test_reset(self) -> None:
        exp = GovernanceObservabilityExporter()
        exp.record_decision(action="deploy", outcome="allow")
        exp.reset()
        assert exp.decision_counts == {}
        assert len(exp.traces) == 0
        assert exp.compliance_gauge == 1.0

    def test_summary(self) -> None:
        exp = GovernanceObservabilityExporter()
        exp.record_decision(action="a", outcome="allow")
        s = exp.summary()
        assert s["total_decisions"] == 1

    def test_decision_trace_to_otel_span(self) -> None:
        exp = GovernanceObservabilityExporter()
        exp.record_decision(action="deploy", outcome="allow", latency_ms=0.5)
        trace = exp.traces[0]
        span = trace.to_otel_span()
        assert span["name"] == "governance.validate"
        assert span["status"]["code"] == "STATUS_CODE_OK"

    def test_deny_trace_status_error(self) -> None:
        exp = GovernanceObservabilityExporter()
        exp.record_decision(action="delete", outcome="deny")
        trace = exp.traces[0]
        span = trace.to_otel_span()
        assert span["status"]["code"] == "STATUS_CODE_ERROR"


# ── incident ────────────────────────────────────────────────────────────────

from acgs_lite.constitution.incident import (
    IncidentManager,
    IncidentPhase,
    IncidentSeverity,
)


class TestIncidentManager:
    def test_create(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test incident", IncidentSeverity.HIGH, "audit")
        assert inc.phase == IncidentPhase.DETECTED
        assert inc.incident_id.startswith("INC-")

    def test_transition_valid(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.HIGH)
        assert mgr.transition(inc.incident_id, IncidentPhase.TRIAGED) is True
        assert inc.phase == IncidentPhase.TRIAGED

    def test_transition_invalid(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.HIGH)
        assert mgr.transition(inc.incident_id, IncidentPhase.RESOLVED) is False

    def test_transition_nonexistent(self) -> None:
        mgr = IncidentManager()
        assert mgr.transition("XX", IncidentPhase.TRIAGED) is False

    def test_transition_closed_sets_closed_at(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.LOW)
        mgr.transition(inc.incident_id, IncidentPhase.CONTAINED)
        mgr.transition(inc.incident_id, IncidentPhase.RESOLVED)
        mgr.transition(inc.incident_id, IncidentPhase.CLOSED)
        assert inc.closed_at is not None

    def test_assign(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.HIGH)
        assert mgr.assign(inc.incident_id, "security-team") is True
        assert inc.assignee == "security-team"

    def test_assign_nonexistent(self) -> None:
        mgr = IncidentManager()
        assert mgr.assign("XX", "team") is False

    def test_add_note(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.HIGH)
        assert mgr.add_note(inc.incident_id, "Investigation started") is True
        assert len(inc.timeline) == 2

    def test_add_note_nonexistent(self) -> None:
        mgr = IncidentManager()
        assert mgr.add_note("XX", "note") is False

    def test_add_tag(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.HIGH)
        assert mgr.add_tag(inc.incident_id, "security") is True
        assert "security" in inc.tags
        mgr.add_tag(inc.incident_id, "security")  # duplicate ignored
        assert inc.tags.count("security") == 1

    def test_add_tag_nonexistent(self) -> None:
        mgr = IncidentManager()
        assert mgr.add_tag("XX", "tag") is False

    def test_link_artifact(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.HIGH)
        assert mgr.link_artifact(inc.incident_id, "ART-1") is True
        assert "ART-1" in inc.related_artifact_ids

    def test_link_artifact_nonexistent(self) -> None:
        mgr = IncidentManager()
        assert mgr.link_artifact("XX", "ART-1") is False

    def test_escalate(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.LOW)
        assert mgr.escalate(inc.incident_id, IncidentSeverity.CRITICAL) is True
        assert inc.severity == IncidentSeverity.CRITICAL

    def test_escalate_downward_blocked(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.HIGH)
        assert mgr.escalate(inc.incident_id, IncidentSeverity.LOW) is False

    def test_escalate_nonexistent(self) -> None:
        mgr = IncidentManager()
        assert mgr.escalate("XX", IncidentSeverity.HIGH) is False

    def test_query_open(self) -> None:
        mgr = IncidentManager()
        mgr.create("Open", IncidentSeverity.HIGH)
        inc2 = mgr.create("Closed", IncidentSeverity.LOW)
        mgr.transition(inc2.incident_id, IncidentPhase.CONTAINED)
        mgr.transition(inc2.incident_id, IncidentPhase.RESOLVED)
        assert len(mgr.query_open()) == 1

    def test_query_by_severity(self) -> None:
        mgr = IncidentManager()
        mgr.create("Low", IncidentSeverity.LOW)
        mgr.create("Critical", IncidentSeverity.CRITICAL)
        assert len(mgr.query_by_severity(IncidentSeverity.HIGH)) == 1

    def test_query_by_phase(self) -> None:
        mgr = IncidentManager()
        mgr.create("Test", IncidentSeverity.HIGH)
        assert len(mgr.query_by_phase(IncidentPhase.DETECTED)) == 1

    def test_query_by_source(self) -> None:
        mgr = IncidentManager()
        mgr.create("Test", IncidentSeverity.HIGH, source="audit")
        assert len(mgr.query_by_source("audit")) == 1
        assert len(mgr.query_by_source("other")) == 0

    def test_incident_report(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.HIGH, source="audit")
        mgr.transition(inc.incident_id, IncidentPhase.CONTAINED)
        report = mgr.incident_report(inc.incident_id)
        assert report is not None
        assert report["time_to_contain_seconds"] is not None

    def test_incident_report_nonexistent(self) -> None:
        mgr = IncidentManager()
        assert mgr.incident_report("XX") is None

    def test_summary(self) -> None:
        mgr = IncidentManager()
        mgr.create("Test", IncidentSeverity.HIGH)
        s = mgr.summary()
        assert s["total"] == 1
        assert s["open"] == 1

    def test_get(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.HIGH)
        assert mgr.get(inc.incident_id) is inc
        assert mgr.get("XX") is None

    def test_transition_with_resolution(self) -> None:
        mgr = IncidentManager()
        inc = mgr.create("Test", IncidentSeverity.HIGH)
        mgr.transition(inc.incident_id, IncidentPhase.CONTAINED)
        mgr.transition(inc.incident_id, IncidentPhase.RESOLVED, resolution="Fixed")
        assert inc.resolution == "Fixed"


# ── obligation_engine ───────────────────────────────────────────────────────

from acgs_lite.constitution.obligation_engine import (
    ObligationEngine,
    ObligationSpec,
    ObligationStatus,
)


class TestObligationEngine:
    def test_emit(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log access", sla_minutes=60)],
            }
        )
        ids = engine.emit("agent-1", "read data", ["RULE-1"])
        assert len(ids) == 1
        assert ids[0].startswith("obl-")

    def test_emit_no_specs(self) -> None:
        engine = ObligationEngine()
        ids = engine.emit("agent-1", "read data", ["UNKNOWN"])
        assert len(ids) == 0

    def test_fulfill(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log access", sla_minutes=60)],
            }
        )
        ids = engine.emit("agent-1", "read data", ["RULE-1"])
        record = engine.fulfill(ids[0], fulfilled_by="agent-1")
        assert record.status == ObligationStatus.FULFILLED

    def test_fulfill_not_found(self) -> None:
        engine = ObligationEngine()
        with pytest.raises(KeyError):
            engine.fulfill("nonexistent")

    def test_fulfill_already_fulfilled(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log access")],
            }
        )
        ids = engine.emit("agent-1", "read data", ["RULE-1"])
        engine.fulfill(ids[0])
        with pytest.raises(ValueError):
            engine.fulfill(ids[0])

    def test_waive(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log access")],
            }
        )
        ids = engine.emit("agent-1", "read data", ["RULE-1"])
        record = engine.waive(ids[0], reason="Not applicable")
        assert record.status == ObligationStatus.WAIVED

    def test_waive_empty_reason(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log access")],
            }
        )
        ids = engine.emit("agent-1", "read data", ["RULE-1"])
        with pytest.raises(ValueError, match="non-empty reason"):
            engine.waive(ids[0], reason="")

    def test_waive_invalid_status(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log access")],
            }
        )
        ids = engine.emit("agent-1", "read data", ["RULE-1"])
        engine.fulfill(ids[0])
        with pytest.raises(ValueError):
            engine.waive(ids[0], reason="test")

    def test_register_and_unregister_spec(self) -> None:
        engine = ObligationEngine()
        engine.register_spec("RULE-1", ObligationSpec("Log access"))
        ids = engine.emit("agent-1", "read data", ["RULE-1"])
        assert len(ids) == 1
        removed = engine.unregister_specs("RULE-1")
        assert removed == 1

    def test_pending_and_fulfilled_queries(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log access", sla_minutes=0)],
            }
        )
        ids = engine.emit("agent-1", "read data", ["RULE-1"])
        assert len(engine.pending()) == 1
        engine.fulfill(ids[0])
        assert len(engine.fulfilled()) == 1
        assert len(engine.pending()) == 0

    def test_for_agent_and_for_rule(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log access")],
            }
        )
        engine.emit("agent-1", "read data", ["RULE-1"])
        assert len(engine.for_agent("agent-1")) == 1
        assert len(engine.for_rule("RULE-1")) == 1

    def test_breach_report(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log access", sla_minutes=60)],
            }
        )
        engine.emit("agent-1", "read data", ["RULE-1"])
        report = engine.breach_report()
        assert report["overdue_count"] == 0

    def test_summary(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log")],
            }
        )
        engine.emit("agent-1", "action", ["RULE-1"])
        s = engine.summary()
        assert s["total"] == 1

    def test_repr(self) -> None:
        engine = ObligationEngine()
        r = repr(engine)
        assert "ObligationEngine" in r

    def test_obligation_record_to_dict(self) -> None:
        engine = ObligationEngine(
            {
                "RULE-1": [ObligationSpec("Log access", sla_minutes=5)],
            }
        )
        engine.emit("agent-1", "read data", ["RULE-1"])
        records = engine.for_agent("agent-1")
        d = records[0].to_dict()
        assert d["rule_id"] == "RULE-1"
        assert d["sla_minutes"] == 5

    def test_obligation_spec_to_dict(self) -> None:
        spec = ObligationSpec("Log access", sla_minutes=5, assignee="admin")
        d = spec.to_dict()
        assert d["assignee"] == "admin"


# ── nearmiss ────────────────────────────────────────────────────────────────

from acgs_lite.constitution.nearmiss import NearMissRecord, NearMissTracker


class TestNearMissTracker:
    def test_record_and_len(self) -> None:
        tracker = NearMissTracker()
        tracker.record("action1", "RULE-1", "text", "narrow miss")
        assert len(tracker) == 1

    def test_record_to_dict(self) -> None:
        record = NearMissRecord("action", "RULE-1", "text", "margin", "2026-01-01T00:00:00Z")
        d = record.to_dict()
        assert d["rule_id"] == "RULE-1"

    def test_query_by_rule(self) -> None:
        tracker = NearMissTracker()
        tracker.record("a", "RULE-1", "t", "m")
        tracker.record("b", "RULE-2", "t", "m")
        results = tracker.query(rule_id="RULE-1")
        assert len(results) == 1

    def test_query_by_time(self) -> None:
        tracker = NearMissTracker()
        tracker.record("a", "R1", "t", "m", timestamp="2026-01-01T00:00:00Z")
        tracker.record("b", "R2", "t", "m", timestamp="2026-06-01T00:00:00Z")
        results = tracker.query(since="2026-03-01T00:00:00Z")
        assert len(results) == 1
        results = tracker.query(until="2026-03-01T00:00:00Z")
        assert len(results) == 1

    def test_summary_empty(self) -> None:
        tracker = NearMissTracker()
        s = tracker.summary()
        assert s["total"] == 0
        assert s["time_range"] is None

    def test_summary_populated(self) -> None:
        tracker = NearMissTracker()
        tracker.record("a", "R1", "t", "m", timestamp="2026-01-01T00:00:00Z")
        tracker.record("b", "R1", "t", "m", timestamp="2026-02-01T00:00:00Z")
        s = tracker.summary()
        assert s["total"] == 2
        assert s["by_rule"]["R1"] == 2
        assert s["time_range"]["earliest"] == "2026-01-01T00:00:00Z"

    def test_export(self) -> None:
        tracker = NearMissTracker()
        tracker.record("a", "R1", "t", "m")
        exported = tracker.export()
        assert len(exported) == 1

    def test_clear(self) -> None:
        tracker = NearMissTracker()
        tracker.record("a", "R1", "t", "m")
        tracker.clear()
        assert len(tracker) == 0

    def test_max_records_bounded(self) -> None:
        tracker = NearMissTracker(max_records=3)
        for i in range(5):
            tracker.record(f"action-{i}", "R1", "t", "m")
        assert len(tracker) == 3


# ── notification ────────────────────────────────────────────────────────────

from acgs_lite.constitution.notification import (
    DeliveryStatus,
    GovernanceNotification,
    GovernanceNotificationBus,
    NotificationPriority,
    Subscriber,
)


class TestSubscriber:
    def test_accepts_matching_topic(self) -> None:
        sub = Subscriber("s1", lambda n: None, topics={"decision.deny"})
        notif = GovernanceNotification(topic="decision.deny", payload={})
        assert sub.accepts(notif) is True

    def test_rejects_wrong_topic(self) -> None:
        sub = Subscriber("s1", lambda n: None, topics={"decision.deny"})
        notif = GovernanceNotification(topic="decision.allow", payload={})
        assert sub.accepts(notif) is False

    def test_rejects_low_priority(self) -> None:
        sub = Subscriber("s1", lambda n: None, min_priority=NotificationPriority.HIGH)
        notif = GovernanceNotification(
            topic="test", payload={}, priority=NotificationPriority.NORMAL
        )
        assert sub.accepts(notif) is False

    def test_accepts_high_priority(self) -> None:
        sub = Subscriber("s1", lambda n: None, min_priority=NotificationPriority.HIGH)
        notif = GovernanceNotification(
            topic="test", payload={}, priority=NotificationPriority.CRITICAL
        )
        assert sub.accepts(notif) is True

    def test_inactive_rejects(self) -> None:
        sub = Subscriber("s1", lambda n: None, active=False)
        notif = GovernanceNotification(topic="test", payload={})
        assert sub.accepts(notif) is False

    def test_custom_filter(self) -> None:
        sub = Subscriber(
            "s1",
            lambda n: None,
            filter_fn=lambda n: n.payload.get("important") is True,
        )
        assert sub.accepts(GovernanceNotification(topic="t", payload={"important": True})) is True
        assert sub.accepts(GovernanceNotification(topic="t", payload={"important": False})) is False


class TestGovernanceNotificationBus:
    def test_publish_delivers(self) -> None:
        received: list[GovernanceNotification] = []
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", received.append))
        notif = GovernanceNotification(topic="test", payload={"x": 1})
        records = bus.publish(notif)
        assert len(received) == 1
        assert records[0].status == DeliveryStatus.DELIVERED

    def test_publish_filtered(self) -> None:
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", lambda n: None, topics={"other"}))
        records = bus.publish(GovernanceNotification(topic="test", payload={}))
        assert records[0].status == DeliveryStatus.FILTERED

    def test_publish_callback_error(self) -> None:
        def boom(n: GovernanceNotification) -> None:
            raise RuntimeError("fail")

        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", boom))
        records = bus.publish(GovernanceNotification(topic="test", payload={}))
        assert records[0].status == DeliveryStatus.FAILED

    def test_unsubscribe(self) -> None:
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", lambda n: None))
        assert bus.unsubscribe("s1") is True
        assert bus.unsubscribe("s1") is False

    def test_pause_resume(self) -> None:
        received: list[GovernanceNotification] = []
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", received.append))
        assert bus.pause("s1") is True
        bus.publish(GovernanceNotification(topic="t", payload={}))
        assert len(received) == 0
        assert bus.resume("s1") is True
        bus.publish(GovernanceNotification(topic="t", payload={}))
        assert len(received) == 1

    def test_pause_resume_nonexistent(self) -> None:
        bus = GovernanceNotificationBus()
        assert bus.pause("xx") is False
        assert bus.resume("xx") is False

    def test_publish_batch(self) -> None:
        received: list[GovernanceNotification] = []
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", received.append))
        notifs = [GovernanceNotification(topic="t", payload={"i": i}) for i in range(3)]
        results = bus.publish_batch(notifs)
        assert len(results) == 3
        assert len(received) == 3

    def test_publish_batch_unique_ids_same_millisecond(self) -> None:
        received: list[GovernanceNotification] = []
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", received.append))
        notifs = [
            GovernanceNotification(topic="t", payload={"i": i}, created_at=1700000000.0)
            for i in range(500)
        ]
        results = bus.publish_batch(notifs)
        assert len(results) == 500
        assert len(received) == 500
        assert len({n.notification_id for n in notifs}) == 500

    def test_replay(self) -> None:
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", lambda n: None))
        bus.publish(GovernanceNotification(topic="a", payload={}))
        bus.publish(GovernanceNotification(topic="b", payload={}))
        assert len(bus.replay(topic="a")) == 1

    def test_replay_since(self) -> None:
        bus = GovernanceNotificationBus()
        bus.publish(GovernanceNotification(topic="a", payload={}))
        replayed = bus.replay(since=time.time() - 10)
        assert len(replayed) >= 1

    def test_delivery_report(self) -> None:
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", lambda n: None))
        bus.publish(GovernanceNotification(topic="t", payload={}))
        report = bus.delivery_report(subscriber_name="s1")
        assert len(report) >= 1

    def test_delivery_report_by_status(self) -> None:
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", lambda n: None))
        bus.publish(GovernanceNotification(topic="t", payload={}))
        report = bus.delivery_report(status=DeliveryStatus.DELIVERED)
        assert all(r["status"] == "delivered" for r in report)

    def test_subscriber_stats(self) -> None:
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", lambda n: None))
        bus.publish(GovernanceNotification(topic="t", payload={}))
        stats = bus.subscriber_stats()
        assert "s1" in stats

    def test_topics(self) -> None:
        bus = GovernanceNotificationBus()
        bus.publish(GovernanceNotification(topic="a", payload={}))
        bus.publish(GovernanceNotification(topic="b", payload={}))
        assert bus.topics() == {"a", "b"}

    def test_summary(self) -> None:
        bus = GovernanceNotificationBus()
        bus.subscribe(Subscriber("s1", lambda n: None))
        bus.publish(GovernanceNotification(topic="t", payload={}))
        s = bus.summary()
        assert s["subscriber_count"] == 1
        assert s["total_notifications"] == 1

    def test_max_history_bounded(self) -> None:
        bus = GovernanceNotificationBus(max_history=2)
        for _ in range(5):
            bus.publish(GovernanceNotification(topic="t", payload={}))
        assert len(bus.replay()) == 2


# ── attestation ─────────────────────────────────────────────────────────────

from acgs_lite.constitution.attestation import (
    AttestationRegistry,
    GovernanceAttestation,
)


class TestAttestationRegistry:
    def test_attest_and_verify(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        att = reg.attest(action="deploy", decision="allow", constitution_hash="abc123")
        assert reg.verify(att) is True

    def test_verify_tampered(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        att = reg.attest(action="deploy", decision="allow", constitution_hash="abc123")
        att.decision = "deny"
        assert reg.verify(att) is False

    def test_verify_unsigned(self) -> None:
        reg = AttestationRegistry()
        att = reg.attest(action="deploy", decision="allow", constitution_hash="abc123")
        assert reg.verify(att) is False

    def test_chain_integrity(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        reg.attest(action="a", decision="allow", constitution_hash="abc")
        reg.attest(action="b", decision="deny", constitution_hash="abc")
        integrity = reg.verify_chain_integrity()
        assert integrity["valid"] is True
        assert integrity["total"] == 2

    def test_query_by_decision(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        reg.attest(action="a", decision="allow", constitution_hash="abc")
        reg.attest(action="b", decision="deny", constitution_hash="abc")
        results = reg.query(decision="deny")
        assert len(results) == 1

    def test_query_by_constitution_hash(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        reg.attest(action="a", decision="allow", constitution_hash="abc")
        reg.attest(action="b", decision="allow", constitution_hash="xyz")
        results = reg.query(constitution_hash="abc")
        assert len(results) == 1

    def test_export_chain_json(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        reg.attest(action="a", decision="allow", constitution_hash="abc")
        exported = reg.export_chain(format="json")
        assert isinstance(exported, str)
        assert "schema_version" in exported

    def test_export_chain_dict(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        reg.attest(action="a", decision="allow", constitution_hash="abc")
        exported = reg.export_chain(format="dict")
        assert isinstance(exported, dict)

    def test_summary(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        reg.attest(action="a", decision="allow", constitution_hash="abc")
        s = reg.summary()
        assert s["total"] == 1

    def test_summary_empty(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        s = reg.summary()
        assert s["chain_intact"] is True

    def test_len(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        reg.attest(action="a", decision="allow", constitution_hash="abc")
        assert len(reg) == 1

    def test_from_dict(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        att = reg.attest(action="deploy", decision="allow", constitution_hash="abc")
        d = att.to_dict()
        restored = GovernanceAttestation.from_dict(d)
        assert restored.attestation_id == att.attestation_id

    def test_repr(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        assert "AttestationRegistry" in repr(reg)

    def test_attestation_repr(self) -> None:
        reg = AttestationRegistry(signing_key="secret")
        att = reg.attest(action="deploy", decision="allow", constitution_hash="abcdef0123456789")
        r = repr(att)
        assert "GovernanceAttestation" in r


# ── certificate ─────────────────────────────────────────────────────────────

from acgs_lite.constitution.certificate import (
    CertificateAuthority,
    CertificateStatus,
)


class TestCertificateAuthority:
    def test_requires_secret(self) -> None:
        with pytest.raises(ValueError, match="requires an explicit"):
            CertificateAuthority("issuer", secret="")

    def test_issue_and_verify(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        cert = ca.issue_certificate("subject", "framework", 0.95, 10, 9)
        assert ca.verify_signature(cert) is True

    def test_status_valid(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        cert = ca.issue_certificate("subject", "framework", 0.95, 10, 9)
        assert ca.get_status(cert.certificate_id) == CertificateStatus.VALID

    def test_status_revoked(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        cert = ca.issue_certificate("subject", "framework", 0.95, 10, 9)
        ca.revoke(cert.certificate_id)
        assert ca.get_status(cert.certificate_id) == CertificateStatus.REVOKED

    def test_status_superseded(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        cert1 = ca.issue_certificate("subject", "framework", 0.90, 10, 9)
        ca.issue_certificate("subject", "framework", 0.95, 10, 10)
        assert ca.get_status(cert1.certificate_id) == CertificateStatus.SUPERSEDED

    def test_status_unknown(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        with pytest.raises(ValueError, match="Unknown"):
            ca.get_status("nonexistent")

    def test_revoke_unknown(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        with pytest.raises(ValueError, match="Unknown"):
            ca.revoke("nonexistent")

    def test_get_certificate(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        cert = ca.issue_certificate("subject", "framework", 0.95, 10, 9)
        assert ca.get_certificate(cert.certificate_id) is cert
        assert ca.get_certificate("xx") is None

    def test_certificates_for_subject(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        ca.issue_certificate("subject", "fw1", 0.95, 10, 9)
        ca.issue_certificate("subject", "fw2", 0.90, 10, 9)
        certs = ca.certificates_for_subject("subject")
        assert len(certs) == 2
        certs = ca.certificates_for_subject("subject", framework="fw1")
        assert len(certs) == 1

    def test_verify_chain(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        ca.issue_certificate("subject", "fw", 0.95, 10, 9)
        ca.issue_certificate("subject", "fw", 0.90, 10, 9)
        assert ca.verify_chain() is True

    def test_chain_length(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        ca.issue_certificate("s", "f", 0.95, 10, 9)
        ca.issue_certificate("s", "f", 0.90, 10, 9)
        assert ca.chain_length() == 2

    def test_stats(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        ca.issue_certificate("s", "f", 0.95, 10, 9)
        s = ca.stats()
        assert s["total_issued"] == 1

    def test_len(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        ca.issue_certificate("s", "f", 0.95, 10, 9)
        assert len(ca) == 1

    def test_pass_rate(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        cert = ca.issue_certificate("s", "f", 0.9, 10, 8)
        assert cert.pass_rate == pytest.approx(0.8)

    def test_pass_rate_zero_rules(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        cert = ca.issue_certificate("s", "f", 1.0, 0, 0)
        assert cert.pass_rate == 1.0

    def test_to_dict(self) -> None:
        ca = CertificateAuthority("issuer", secret="secret")
        cert = ca.issue_certificate("s", "f", 0.95, 10, 9, findings=["F1"])
        d = cert.to_dict()
        assert d["issuer"] == "issuer"
        assert "F1" in d["findings"]


# ── abac ────────────────────────────────────────────────────────────────────

from acgs_lite.constitution.abac import (
    CLASS_PHI,
    CLASS_PUBLIC,
    RISK_CRITICAL,
    TIER_PRIVILEGED,
    TIER_RESTRICTED,
    TIER_STANDARD,
    EvaluationContext,
)


class TestEvaluationContext:
    def test_to_dict_excludes_empty(self) -> None:
        ctx = EvaluationContext(agent_id="alpha")
        d = ctx.to_dict()
        assert "agent_id" in d
        assert "agent_tier" not in d

    def test_for_interpolation(self) -> None:
        ctx = EvaluationContext(agent_id="alpha", agent_tier="standard", deployment_region="EU")
        nested = ctx.for_interpolation()
        assert nested["agent"]["id"] == "alpha"
        assert nested["deployment"]["region"] == "EU"

    def test_risk_level_public(self) -> None:
        ctx = EvaluationContext()
        assert ctx.risk_level == 0

    def test_risk_level_restricted(self) -> None:
        ctx = EvaluationContext(agent_tier=TIER_RESTRICTED)
        assert ctx.risk_level == 3

    def test_risk_level_phi(self) -> None:
        ctx = EvaluationContext(data_classification=CLASS_PHI)
        assert ctx.risk_level == 3

    def test_risk_level_critical_tenant(self) -> None:
        ctx = EvaluationContext(tenant_risk_profile=RISK_CRITICAL)
        assert ctx.risk_level == 4

    def test_risk_label(self) -> None:
        ctx = EvaluationContext(data_classification=CLASS_PUBLIC)
        assert ctx.risk_label == "none"
        ctx2 = EvaluationContext(tenant_risk_profile=RISK_CRITICAL)
        assert ctx2.risk_label == "critical"

    def test_merge(self) -> None:
        base = EvaluationContext(agent_tier=TIER_STANDARD, deployment_region="EU")
        override = EvaluationContext(agent_tier=TIER_PRIVILEGED)
        merged = base.merge(override)
        assert merged.agent_tier == TIER_PRIVILEGED
        assert merged.deployment_region == "EU"

    def test_merge_custom(self) -> None:
        base = EvaluationContext(custom={"a": 1})
        override = EvaluationContext(custom={"b": 2})
        merged = base.merge(override)
        assert merged.custom == {"a": 1, "b": 2}

    def test_from_dict_flat(self) -> None:
        ctx = EvaluationContext.from_dict({"agent_tier": "privileged", "extra_key": "val"})
        assert ctx.agent_tier == "privileged"
        assert ctx.custom["extra_key"] == "val"

    def test_from_dict_nested(self) -> None:
        ctx = EvaluationContext.from_dict(
            {
                "agent": {"id": "alpha", "tier": "standard"},
                "deployment": {"region": "US"},
            }
        )
        assert ctx.agent_id == "alpha"
        assert ctx.deployment_region == "US"

    def test_now(self) -> None:
        ctx = EvaluationContext.now(agent_id="alpha")
        assert ctx.time_of_day != ""
        assert ctx.agent_id == "alpha"

    def test_to_summary(self) -> None:
        ctx = EvaluationContext(agent_id="alpha", agent_tier=TIER_RESTRICTED)
        s = ctx.to_summary()
        assert s["agent_id"] == "alpha"
        assert "3" in s["risk_level"]

    def test_repr(self) -> None:
        ctx = EvaluationContext(agent_id="alpha")
        assert "alpha" in repr(ctx)


# ── compliance_mapping ──────────────────────────────────────────────────────

from acgs_lite.constitution.compliance_mapping import (
    ComplianceMapper,
    RegulatoryFramework,
)


class TestComplianceMapper:
    def _setup(self) -> ComplianceMapper:
        mapper = ComplianceMapper()
        mapper.register_framework(
            RegulatoryFramework(
                framework_id="eu_ai",
                name="EU AI Act",
                controls=["Art.9", "Art.13", "Art.14"],
            )
        )
        return mapper

    def test_map_rule(self) -> None:
        mapper = self._setup()
        m = mapper.map_rule("SAFE-001", "eu_ai", "Art.9", evidence="Blocks risk")
        assert m is not None
        assert m.rule_id == "SAFE-001"

    def test_map_rule_unknown_framework(self) -> None:
        mapper = self._setup()
        assert mapper.map_rule("SAFE-001", "xx", "Art.9") is None

    def test_map_rule_unknown_control(self) -> None:
        mapper = self._setup()
        assert mapper.map_rule("SAFE-001", "eu_ai", "Art.99") is None

    def test_map_rule_dedup_update(self) -> None:
        mapper = self._setup()
        mapper.map_rule("SAFE-001", "eu_ai", "Art.9", evidence="v1")
        m = mapper.map_rule("SAFE-001", "eu_ai", "Art.9", evidence="v2")
        assert m is not None
        assert m.evidence == "v2"
        assert len(mapper.mappings_for_rule("SAFE-001")) == 1

    def test_unmap_rule(self) -> None:
        mapper = self._setup()
        mapper.map_rule("SAFE-001", "eu_ai", "Art.9")
        assert mapper.unmap_rule("SAFE-001", "eu_ai", "Art.9") is True
        assert mapper.unmap_rule("SAFE-001", "eu_ai", "Art.9") is False

    def test_coverage_gaps(self) -> None:
        mapper = self._setup()
        mapper.map_rule("SAFE-001", "eu_ai", "Art.9")
        gaps = mapper.coverage_gaps("eu_ai")
        assert len(gaps) == 2
        gap_ids = {g.control_id for g in gaps}
        assert "Art.13" in gap_ids

    def test_coverage_gaps_unknown_framework(self) -> None:
        mapper = self._setup()
        assert mapper.coverage_gaps("xx") == []

    def test_coverage_score(self) -> None:
        mapper = self._setup()
        mapper.map_rule("SAFE-001", "eu_ai", "Art.9")
        score = mapper.coverage_score("eu_ai")
        assert score == pytest.approx(1.0 / 3.0)

    def test_coverage_score_unknown(self) -> None:
        mapper = self._setup()
        assert mapper.coverage_score("xx") == 0.0

    def test_compliance_matrix(self) -> None:
        mapper = self._setup()
        mapper.map_rule("SAFE-001", "eu_ai", "Art.9")
        matrix = mapper.compliance_matrix("eu_ai")
        assert matrix["Art.9"] == ["SAFE-001"]
        assert matrix["Art.13"] == []

    def test_compliance_matrix_unknown(self) -> None:
        mapper = self._setup()
        assert mapper.compliance_matrix("xx") == {}

    def test_cross_framework_overlap(self) -> None:
        mapper = self._setup()
        mapper.register_framework(
            RegulatoryFramework(framework_id="nist", name="NIST", controls=["GOV-1"])
        )
        mapper.map_rule("SAFE-001", "eu_ai", "Art.9")
        mapper.map_rule("SAFE-001", "nist", "GOV-1")
        overlap = mapper.cross_framework_overlap("SAFE-001")
        assert "eu_ai" in overlap
        assert "nist" in overlap

    def test_remove_framework(self) -> None:
        mapper = self._setup()
        mapper.map_rule("SAFE-001", "eu_ai", "Art.9")
        assert mapper.remove_framework("eu_ai") is True
        assert mapper.remove_framework("eu_ai") is False
        assert len(mapper.mappings_for_framework("eu_ai")) == 0

    def test_list_frameworks(self) -> None:
        mapper = self._setup()
        assert len(mapper.list_frameworks()) == 1

    def test_get_framework(self) -> None:
        mapper = self._setup()
        assert mapper.get_framework("eu_ai") is not None
        assert mapper.get_framework("xx") is None

    def test_mappings_for_control(self) -> None:
        mapper = self._setup()
        mapper.map_rule("SAFE-001", "eu_ai", "Art.9")
        assert len(mapper.mappings_for_control("eu_ai", "Art.9")) == 1

    def test_summary(self) -> None:
        mapper = self._setup()
        mapper.map_rule("SAFE-001", "eu_ai", "Art.9")
        s = mapper.summary()
        assert s["frameworks"] == 1
        assert s["total_mappings"] == 1


# ── emergency ───────────────────────────────────────────────────────────────

from acgs_lite.constitution.emergency import (
    GovernanceEmergencyOverride,
    OverridePolicy,
    OverrideScope,
    OverrideStatus,
)


class TestGovernanceEmergencyOverride:
    def _justification(self) -> str:
        return "Production incident INC-001: service degradation requiring override"

    def test_activate(self) -> None:
        eo = GovernanceEmergencyOverride()
        override = eo.activate(
            requestor_id="ops",
            authorizer_id="sec",
            justification=self._justification(),
            scope=OverrideScope.ALL_RULES,
        )
        assert override.is_active is True

    def test_activate_self_authorization_blocked(self) -> None:
        eo = GovernanceEmergencyOverride()
        with pytest.raises(ValueError, match="MACI violation"):
            eo.activate("ops", "ops", self._justification(), OverrideScope.ALL_RULES)

    def test_activate_self_authorization_allowed(self) -> None:
        policy = OverridePolicy(allow_self_authorization=True)
        eo = GovernanceEmergencyOverride(policy)
        override = eo.activate("ops", "ops", self._justification(), OverrideScope.ALL_RULES)
        assert override.is_active is True

    def test_activate_short_justification(self) -> None:
        eo = GovernanceEmergencyOverride()
        with pytest.raises(ValueError, match="at least"):
            eo.activate("ops", "sec", "short", OverrideScope.ALL_RULES)

    def test_activate_no_justification_required(self) -> None:
        policy = OverridePolicy(require_justification=False)
        eo = GovernanceEmergencyOverride(policy)
        override = eo.activate("ops", "sec", "ok", OverrideScope.ALL_RULES)
        assert override.is_active is True

    def test_activate_duration_capped(self) -> None:
        policy = OverridePolicy(max_duration=timedelta(hours=1))
        eo = GovernanceEmergencyOverride(policy)
        override = eo.activate(
            "ops",
            "sec",
            self._justification(),
            OverrideScope.ALL_RULES,
            duration=timedelta(hours=10),
        )
        diff = override.expires_at - override.activated_at
        assert diff <= timedelta(hours=1) + timedelta(seconds=1)

    def test_is_overridden_all_rules(self) -> None:
        eo = GovernanceEmergencyOverride()
        eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        assert eo.is_overridden("ANY-RULE") is True

    def test_is_overridden_specific_rules(self) -> None:
        eo = GovernanceEmergencyOverride()
        eo.activate(
            "ops",
            "sec",
            self._justification(),
            OverrideScope.SPECIFIC_RULES,
            scope_filter=["RULE-1"],
        )
        assert eo.is_overridden("RULE-1") is True
        assert eo.is_overridden("RULE-2") is False

    def test_is_overridden_severity_tier(self) -> None:
        eo = GovernanceEmergencyOverride()
        eo.activate(
            "ops",
            "sec",
            self._justification(),
            OverrideScope.SEVERITY_TIER,
            scope_filter=["medium", "low"],
        )
        assert eo.is_overridden("RULE-1", severity="medium") is True
        assert eo.is_overridden("RULE-1", severity="critical") is False

    def test_is_overridden_category(self) -> None:
        eo = GovernanceEmergencyOverride()
        eo.activate(
            "ops",
            "sec",
            self._justification(),
            OverrideScope.CATEGORY,
            scope_filter=["financial"],
        )
        assert eo.is_overridden("RULE-1", category="financial") is True
        assert eo.is_overridden("RULE-1", category="safety") is False

    def test_revoke(self) -> None:
        eo = GovernanceEmergencyOverride()
        override = eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        revoked = eo.revoke(override.override_id, "sec", "Incident resolved")
        assert revoked.status == OverrideStatus.REVOKED

    def test_revoke_not_active(self) -> None:
        eo = GovernanceEmergencyOverride()
        override = eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        eo.revoke(override.override_id, "sec")
        with pytest.raises(ValueError, match="not active"):
            eo.revoke(override.override_id, "sec")

    def test_complete(self) -> None:
        eo = GovernanceEmergencyOverride()
        override = eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        completed = eo.complete(override.override_id, "ops")
        assert completed.status == OverrideStatus.COMPLETED

    def test_complete_not_active(self) -> None:
        eo = GovernanceEmergencyOverride()
        override = eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        eo.complete(override.override_id, "ops")
        with pytest.raises(ValueError, match="not active"):
            eo.complete(override.override_id, "ops")

    def test_active_overrides(self) -> None:
        eo = GovernanceEmergencyOverride()
        eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        assert len(eo.active_overrides()) == 1

    def test_get(self) -> None:
        eo = GovernanceEmergencyOverride()
        override = eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        assert eo.get(override.override_id) is override

    def test_get_nonexistent(self) -> None:
        eo = GovernanceEmergencyOverride()
        with pytest.raises(KeyError):
            eo.get("XX")

    def test_record_action(self) -> None:
        eo = GovernanceEmergencyOverride()
        override = eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        override.record_action("deploy", "agent-1", "deployed hotfix")
        assert len(override.actions_taken) == 1

    def test_summary(self) -> None:
        eo = GovernanceEmergencyOverride()
        eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        s = eo.summary()
        assert s["total"] == 1
        assert s["active_count"] == 1

    def test_history(self) -> None:
        eo = GovernanceEmergencyOverride()
        eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        assert len(eo.history()) >= 1

    def test_to_dict(self) -> None:
        eo = GovernanceEmergencyOverride()
        override = eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        d = override.to_dict()
        assert d["status"] == "active"

    def test_remaining_active(self) -> None:
        eo = GovernanceEmergencyOverride()
        override = eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        assert override.remaining.total_seconds() > 0

    def test_remaining_inactive(self) -> None:
        eo = GovernanceEmergencyOverride()
        override = eo.activate("ops", "sec", self._justification(), OverrideScope.ALL_RULES)
        eo.revoke(override.override_id, "sec")
        assert override.remaining.total_seconds() == 0


# ── intent_alignment ────────────────────────────────────────────────────────

from acgs_lite.constitution.intent_alignment import (
    IntentAlignmentTracker,
    IntentProfile,
    _ewm,
    _extract_keywords,
    _jaccard_overlap,
)


class TestIntentAlignmentHelpers:
    def test_extract_keywords_stopwords(self) -> None:
        kws = _extract_keywords("the quick brown fox is not a cat")
        assert "the" not in kws
        assert "quick" in kws

    def test_extract_keywords_short_words_excluded(self) -> None:
        kws = _extract_keywords("I am ok to go")
        assert "am" not in kws
        assert "ok" not in kws  # 2 chars

    def test_jaccard_identical(self) -> None:
        assert _jaccard_overlap(frozenset({"a", "b"}), frozenset({"a", "b"})) == 1.0

    def test_jaccard_disjoint(self) -> None:
        assert _jaccard_overlap(frozenset({"a"}), frozenset({"b"})) == 0.0

    def test_jaccard_both_empty(self) -> None:
        assert _jaccard_overlap(frozenset(), frozenset()) == 1.0

    def test_ewm_empty(self) -> None:
        assert _ewm([], 0.3) == 0.0

    def test_ewm_single(self) -> None:
        assert _ewm([1.0], 0.3) == 1.0


class TestIntentAlignmentTracker:
    def test_from_text(self) -> None:
        tracker = IntentAlignmentTracker.from_text("summarise legal documents")
        assert len(tracker._intent.keywords) > 0

    def test_record_aligned(self) -> None:
        tracker = IntentAlignmentTracker.from_text("summarise legal documents")
        rec = tracker.record("summarise contract clause")
        assert rec.alignment_score > 0

    def test_current_state_empty(self) -> None:
        tracker = IntentAlignmentTracker.from_text("summarise legal documents")
        state = tracker.current_state()
        assert state.drift_score == 0.0
        assert state.drift_level == "low"

    def test_drift_increases_with_unrelated_actions(self) -> None:
        tracker = IntentAlignmentTracker.from_text("summarise legal documents")
        tracker.record("summarise contract clause")
        state1 = tracker.current_state()
        tracker.record("send email to everyone")
        tracker.record("post tweet announcement")
        tracker.record("delete all records immediately")
        state2 = tracker.current_state()
        assert state2.drift_score > state1.drift_score

    def test_should_escalate(self) -> None:
        tracker = IntentAlignmentTracker.from_text(
            "summarise legal documents", escalation_threshold=0.3
        )
        for _ in range(5):
            tracker.record("send email to everyone")
        state = tracker.current_state()
        assert state.should_escalate is True

    def test_record_batch(self) -> None:
        tracker = IntentAlignmentTracker.from_text("analyse data")
        records = tracker.record_batch(["analyse sales", "query database"])
        assert len(records) == 2

    def test_most_drifted_actions(self) -> None:
        tracker = IntentAlignmentTracker.from_text("summarise legal documents")
        tracker.record("summarise contract")
        tracker.record("send spam email")
        drifted = tracker.most_drifted_actions(1)
        assert len(drifted) == 1

    def test_drift_trend(self) -> None:
        tracker = IntentAlignmentTracker.from_text("summarise legal documents")
        tracker.record("summarise contract")
        tracker.record("send email")
        trend = tracker.drift_trend()
        assert len(trend) == 2

    def test_history_summary(self) -> None:
        tracker = IntentAlignmentTracker.from_text("summarise legal documents")
        tracker.record("summarise contract")
        s = tracker.history_summary()
        assert "intent_declaration" in s

    def test_reset(self) -> None:
        tracker = IntentAlignmentTracker.from_text("summarise legal documents")
        tracker.record("summarise contract")
        tracker.reset()
        assert tracker.current_state().action_count == 0

    def test_invalid_escalation_threshold(self) -> None:
        with pytest.raises(ValueError):
            IntentAlignmentTracker.from_text("test", escalation_threshold=0.0)
        with pytest.raises(ValueError):
            IntentAlignmentTracker.from_text("test", escalation_threshold=1.5)

    def test_invalid_ewm_alpha(self) -> None:
        with pytest.raises(ValueError):
            IntentAlignmentTracker.from_text("test", ewm_alpha=0.0)

    def test_repr(self) -> None:
        tracker = IntentAlignmentTracker.from_text("summarise docs")
        assert "IntentAlignmentTracker" in repr(tracker)

    def test_intent_profile_to_dict(self) -> None:
        profile = IntentProfile.from_text("summarise legal documents")
        d = profile.to_dict()
        assert d["keyword_count"] > 0

    def test_state_repr(self) -> None:
        tracker = IntentAlignmentTracker.from_text("test", escalation_threshold=0.01)
        tracker.record("completely unrelated action sequence")
        state = tracker.current_state()
        r = repr(state)
        assert "IntentAlignmentState" in r


# ── ratelimit ───────────────────────────────────────────────────────────────

from acgs_lite.constitution.ratelimit import (
    GovernanceRateLimiter,
    RateLimitAction,
    RateLimitPolicy,
)


class TestGovernanceRateLimiter:
    def test_check_allows(self) -> None:
        limiter = GovernanceRateLimiter(RateLimitPolicy(requests_per_window=100))
        result = limiter.check("agent-1")
        assert result.allowed is True

    def test_check_and_record(self) -> None:
        limiter = GovernanceRateLimiter(RateLimitPolicy(requests_per_window=5, burst_allowance=0))
        for _ in range(5):
            result = limiter.check_and_record("agent-1")
            assert result.allowed is True
        result = limiter.check_and_record("agent-1")
        assert result.allowed is False

    def test_warn_threshold(self) -> None:
        limiter = GovernanceRateLimiter(
            RateLimitPolicy(requests_per_window=10, burst_allowance=0, warn_threshold=0.5)
        )
        for _ in range(5):
            limiter.check_and_record("agent-1")
        # 6th request sees current=5 which is >= warn_level(5), triggers WARN
        result = limiter.check_and_record("agent-1")
        assert result.allowed is True
        assert result.action == RateLimitAction.WARN

    def test_agent_usage(self) -> None:
        limiter = GovernanceRateLimiter()
        limiter.check_and_record("agent-1")
        usage = limiter.agent_usage("agent-1")
        assert usage["current_count"] == 1

    def test_agent_usage_unknown(self) -> None:
        limiter = GovernanceRateLimiter()
        usage = limiter.agent_usage("unknown")
        assert usage["current_count"] == 0

    def test_all_agents_usage(self) -> None:
        limiter = GovernanceRateLimiter()
        limiter.check_and_record("a")
        limiter.check_and_record("b")
        assert len(limiter.all_agents_usage()) == 2

    def test_violations(self) -> None:
        limiter = GovernanceRateLimiter(RateLimitPolicy(requests_per_window=1, burst_allowance=0))
        limiter.check_and_record("agent-1")
        limiter.check_and_record("agent-1")
        assert len(limiter.violations()) == 1

    def test_reset(self) -> None:
        limiter = GovernanceRateLimiter()
        limiter.check_and_record("agent-1")
        limiter.reset("agent-1")
        usage = limiter.agent_usage("agent-1")
        assert usage["current_count"] == 0

    def test_reset_all(self) -> None:
        limiter = GovernanceRateLimiter()
        limiter.check_and_record("agent-1")
        limiter.check_and_record("agent-2")
        limiter.reset_all()
        assert len(limiter.all_agents_usage()) == 0

    def test_summary(self) -> None:
        limiter = GovernanceRateLimiter()
        limiter.check_and_record("agent-1")
        s = limiter.summary()
        assert s["tracked_agents"] == 1

    def test_result_to_dict(self) -> None:
        limiter = GovernanceRateLimiter()
        result = limiter.check("agent-1")
        d = result.to_dict()
        assert "allowed" in d

    def test_check_without_record(self) -> None:
        limiter = GovernanceRateLimiter()
        limiter.check("agent-1")
        usage = limiter.agent_usage("agent-1")
        assert usage["current_count"] == 0

    def test_action_tracking(self) -> None:
        limiter = GovernanceRateLimiter()
        limiter.check_and_record("agent-1", action="deploy")
        s = limiter.summary()
        assert s["tracked_actions"] >= 1


# ── cost_budget ─────────────────────────────────────────────────────────────

from acgs_lite.constitution.cost_budget import (
    CostBudget,
    CostBudgetManager,
    ResetPeriod,
)


class TestCostBudget:
    def test_soft_exceeds_hard_raises(self) -> None:
        with pytest.raises(ValueError, match="soft_limit"):
            CostBudget("b1", soft_limit=200, hard_limit=100)

    def test_zero_hard_raises(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            CostBudget("b1", soft_limit=0, hard_limit=0)

    def test_string_reset_period(self) -> None:
        b = CostBudget("b1", soft_limit=50, hard_limit=100, reset_period="weekly")  # type: ignore[arg-type]
        assert b.reset_period == ResetPeriod.WEEKLY


class TestCostBudgetManager:
    def test_set_and_record(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=800, hard_limit=1000))
        status = mgr.record("b1", tokens=100)
        assert not status.hard_blocked
        assert not status.soft_warned

    def test_soft_warn(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=100, hard_limit=200))
        mgr.record("b1", tokens=100)
        status = mgr.record("b1", tokens=1)
        assert status.soft_warned

    def test_hard_block(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=100, hard_limit=200))
        mgr.record("b1", tokens=200)
        status = mgr.record("b1", tokens=1)
        assert status.hard_blocked

    def test_record_unregistered(self) -> None:
        mgr = CostBudgetManager()
        with pytest.raises(KeyError):
            mgr.record("xx", tokens=10)

    def test_record_negative(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=100, hard_limit=200))
        with pytest.raises(ValueError, match="tokens must be"):
            mgr.record("b1", tokens=-1)

    def test_set_budget_no_overwrite(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=100, hard_limit=200))
        with pytest.raises(ValueError, match="already registered"):
            mgr.set_budget(CostBudget("b1", soft_limit=100, hard_limit=200), overwrite=False)

    def test_remove_budget(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=100, hard_limit=200))
        mgr.remove_budget("b1")
        with pytest.raises(KeyError):
            mgr.record("b1", tokens=10)

    def test_remove_budget_missing(self) -> None:
        mgr = CostBudgetManager()
        with pytest.raises(KeyError):
            mgr.remove_budget("xx")

    def test_status(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=100, hard_limit=200))
        mgr.record("b1", tokens=50)
        status = mgr.status("b1")
        assert status.cumulative == 50

    def test_reset(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=100, hard_limit=200))
        mgr.record("b1", tokens=150)
        mgr.reset("b1")
        status = mgr.status("b1")
        assert status.cumulative == 0

    def test_reset_missing(self) -> None:
        mgr = CostBudgetManager()
        with pytest.raises(KeyError):
            mgr.reset("xx")

    def test_list_budgets(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b2", soft_limit=50, hard_limit=100))
        mgr.set_budget(CostBudget("b1", soft_limit=50, hard_limit=100))
        assert mgr.list_budgets() == ["b1", "b2"]

    def test_breached(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=50, hard_limit=100))
        mgr.record("b1", tokens=100)
        assert "b1" in mgr.breached()

    def test_soft_warned_list(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=50, hard_limit=100))
        mgr.record("b1", tokens=60)
        assert "b1" in mgr.soft_warned()

    def test_history(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=50, hard_limit=100))
        mgr.record("b1", tokens=10)
        h = mgr.history("b1")
        assert len(h) == 1

    def test_history_missing(self) -> None:
        mgr = CostBudgetManager()
        with pytest.raises(KeyError):
            mgr.history("xx")

    def test_summary(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(CostBudget("b1", soft_limit=50, hard_limit=100))
        mgr.record("b1", tokens=10)
        s = mgr.summary()
        assert s["budget_count"] == 1

    def test_auto_reset_daily(self) -> None:
        mgr = CostBudgetManager()
        mgr.set_budget(
            CostBudget("b1", soft_limit=50, hard_limit=100, reset_period=ResetPeriod.DAILY)
        )
        mgr.record("b1", tokens=80)
        # Record far in the future so the daily window has elapsed
        future = datetime.now(timezone.utc) + timedelta(days=2)
        status = mgr.record("b1", tokens=10, _now=future)
        # Usage should have been reset before charging the 10
        assert status.cumulative == 10


# ── escrow ──────────────────────────────────────────────────────────────────

from acgs_lite.constitution.escrow import (
    EscrowPolicy,
    EscrowStatus,
    GovernanceEscrow,
)


class TestGovernanceEscrow:
    def test_hold(self) -> None:
        escrow = GovernanceEscrow()
        item = escrow.hold("deploy", {"env": "prod"}, "agent-1")
        assert item.status == EscrowStatus.HELD

    def test_approve_and_release(self) -> None:
        policy = EscrowPolicy(required_approvals=2)
        escrow = GovernanceEscrow(policy)
        item = escrow.hold("deploy", {}, "agent-1")
        escrow.approve(item.escrow_id, "reviewer-1")
        assert item.status == EscrowStatus.HELD
        escrow.approve(item.escrow_id, "reviewer-2")
        assert item.status == EscrowStatus.APPROVED

    def test_self_approval_blocked(self) -> None:
        escrow = GovernanceEscrow()
        item = escrow.hold("deploy", {}, "agent-1")
        with pytest.raises(ValueError, match="MACI"):
            escrow.approve(item.escrow_id, "agent-1")

    def test_self_approval_allowed(self) -> None:
        policy = EscrowPolicy(allow_self_approval=True)
        escrow = GovernanceEscrow(policy)
        item = escrow.hold("deploy", {}, "agent-1")
        escrow.approve(item.escrow_id, "agent-1")

    def test_duplicate_vote_blocked(self) -> None:
        escrow = GovernanceEscrow()
        item = escrow.hold("deploy", {}, "agent-1")
        escrow.approve(item.escrow_id, "reviewer-1")
        with pytest.raises(ValueError, match="already voted"):
            escrow.approve(item.escrow_id, "reviewer-1")

    def test_reject(self) -> None:
        escrow = GovernanceEscrow()
        item = escrow.hold("deploy", {}, "agent-1")
        escrow.reject(item.escrow_id, "reviewer-1", "Too risky")
        assert item.status == EscrowStatus.REJECTED

    def test_reject_duplicate_vote(self) -> None:
        policy = EscrowPolicy(rejection_threshold=2)
        escrow = GovernanceEscrow(policy)
        item = escrow.hold("deploy", {}, "agent-1")
        escrow.reject(item.escrow_id, "reviewer-1")
        with pytest.raises(ValueError, match="already voted"):
            escrow.reject(item.escrow_id, "reviewer-1")

    def test_get_nonexistent(self) -> None:
        escrow = GovernanceEscrow()
        with pytest.raises(KeyError):
            escrow.get("xx")

    def test_get(self) -> None:
        escrow = GovernanceEscrow()
        item = escrow.hold("deploy", {}, "agent-1")
        assert escrow.get(item.escrow_id) is item

    def test_held(self) -> None:
        escrow = GovernanceEscrow()
        escrow.hold("deploy", {}, "agent-1")
        assert len(escrow.held()) == 1

    def test_by_requestor(self) -> None:
        escrow = GovernanceEscrow()
        escrow.hold("deploy", {}, "agent-1")
        escrow.hold("test", {}, "agent-2")
        assert len(escrow.by_requestor("agent-1")) == 1

    def test_summary(self) -> None:
        escrow = GovernanceEscrow()
        escrow.hold("deploy", {}, "agent-1")
        s = escrow.summary()
        assert s["total"] == 1

    def test_history(self) -> None:
        escrow = GovernanceEscrow()
        escrow.hold("deploy", {}, "agent-1")
        assert len(escrow.history()) >= 1

    def test_to_dict(self) -> None:
        escrow = GovernanceEscrow()
        item = escrow.hold("deploy", {"env": "prod"}, "agent-1")
        d = item.to_dict()
        assert d["action"] == "deploy"
        assert d["status"] == "held"

    def test_approval_and_rejection_count(self) -> None:
        policy = EscrowPolicy(required_approvals=3, rejection_threshold=3)
        escrow = GovernanceEscrow(policy)
        item = escrow.hold("deploy", {}, "agent-1")
        escrow.approve(item.escrow_id, "r1")
        escrow.reject(item.escrow_id, "r2")
        assert item.approval_count == 1
        assert item.rejection_count == 1

    def test_approve_already_resolved(self) -> None:
        escrow = GovernanceEscrow(EscrowPolicy(required_approvals=1))
        item = escrow.hold("deploy", {}, "agent-1")
        escrow.approve(item.escrow_id, "r1")
        assert item.status == EscrowStatus.APPROVED
        with pytest.raises(ValueError, match="already resolved"):
            escrow.approve(item.escrow_id, "r2")


# ── data_classification ─────────────────────────────────────────────────────

from acgs_lite.constitution.data_classification import (
    DataClassifier,
    HandlingRequirement,
    SensitivityLevel,
)


class TestDataClassifier:
    def test_add_policy_and_classify(self) -> None:
        dc = DataClassifier()
        dc.add_policy(
            "pii", SensitivityLevel.CONFIDENTIAL, HandlingRequirement(encrypt_at_rest=True)
        )
        result = dc.classify("record-1", labels=["pii"])
        assert result.level == SensitivityLevel.CONFIDENTIAL
        assert result.handling.encrypt_at_rest is True

    def test_highest_level_wins(self) -> None:
        dc = DataClassifier()
        dc.add_policy("pii", SensitivityLevel.CONFIDENTIAL)
        dc.add_policy(
            "financial",
            SensitivityLevel.RESTRICTED,
            HandlingRequirement(cross_border_allowed=False),
        )
        result = dc.classify("record-1", labels=["pii", "financial"])
        assert result.level == SensitivityLevel.RESTRICTED
        assert result.handling.cross_border_allowed is False

    def test_classify_no_labels(self) -> None:
        dc = DataClassifier()
        result = dc.classify("record-1")
        assert result.level == SensitivityLevel.PUBLIC

    def test_classify_unknown_label(self) -> None:
        dc = DataClassifier()
        result = dc.classify("record-1", labels=["unknown"])
        assert result.level == SensitivityLevel.PUBLIC

    def test_remove_policy(self) -> None:
        dc = DataClassifier()
        dc.add_policy("pii", SensitivityLevel.CONFIDENTIAL)
        assert dc.remove_policy("pii") is True
        assert dc.remove_policy("pii") is False

    def test_get_policy(self) -> None:
        dc = DataClassifier()
        dc.add_policy("pii", SensitivityLevel.CONFIDENTIAL)
        assert dc.get_policy("pii") is not None
        assert dc.get_policy("xx") is None

    def test_list_policies(self) -> None:
        dc = DataClassifier()
        dc.add_policy("pii", SensitivityLevel.CONFIDENTIAL)
        assert len(dc.list_policies()) == 1

    def test_classify_batch(self) -> None:
        dc = DataClassifier()
        dc.add_policy("pii", SensitivityLevel.CONFIDENTIAL)
        results = dc.classify_batch([("r1", ["pii"]), ("r2", [])])
        assert len(results) == 2

    def test_get_classification(self) -> None:
        dc = DataClassifier()
        dc.classify("record-1", labels=[])
        assert dc.get_classification("record-1") is not None
        assert dc.get_classification("xx") is None

    def test_query_by_level(self) -> None:
        dc = DataClassifier()
        dc.add_policy("pii", SensitivityLevel.CONFIDENTIAL)
        dc.classify("r1", labels=["pii"])
        dc.classify("r2", labels=[])
        results = dc.query_by_level(SensitivityLevel.CONFIDENTIAL)
        assert len(results) == 1

    def test_query_by_label(self) -> None:
        dc = DataClassifier()
        dc.add_policy("pii", SensitivityLevel.CONFIDENTIAL)
        dc.classify("r1", labels=["pii"])
        results = dc.query_by_label("pii")
        assert len(results) == 1

    def test_reclassify(self) -> None:
        dc = DataClassifier()
        dc.add_policy("pii", SensitivityLevel.CONFIDENTIAL)
        dc.classify("r1", labels=[])
        result = dc.reclassify("r1", labels=["pii"])
        assert result is not None
        assert result.level == SensitivityLevel.CONFIDENTIAL

    def test_reclassify_nonexistent(self) -> None:
        dc = DataClassifier()
        assert dc.reclassify("xx", labels=["pii"]) is None

    def test_declassify(self) -> None:
        dc = DataClassifier()
        dc.classify("r1", labels=[])
        assert dc.declassify("r1") is True
        assert dc.declassify("r1") is False

    def test_audit_log(self) -> None:
        dc = DataClassifier()
        dc.classify("r1", labels=[])
        log = dc.audit_log()
        assert len(log) >= 1
        log_r1 = dc.audit_log(artifact_id="r1")
        assert len(log_r1) >= 1

    def test_compliance_report(self) -> None:
        dc = DataClassifier()
        dc.add_policy(
            "pii",
            SensitivityLevel.CONFIDENTIAL,
            HandlingRequirement(encrypt_at_rest=True, cross_border_allowed=False),
        )
        dc.classify("r1", labels=["pii"])
        report = dc.compliance_report()
        assert report["total_classified"] == 1
        assert report["encrypted_at_rest"] == 1
        assert report["cross_border_restricted"] == 1

    def test_merge_handling_roles_intersection(self) -> None:
        h1 = HandlingRequirement(allowed_roles=frozenset({"admin", "analyst"}))
        h2 = HandlingRequirement(allowed_roles=frozenset({"admin", "viewer"}))
        merged = DataClassifier._merge_handling([h1, h2])
        assert merged.allowed_roles == frozenset({"admin"})

    def test_merge_handling_retention_min(self) -> None:
        h1 = HandlingRequirement(max_retention_days=90)
        h2 = HandlingRequirement(max_retention_days=365)
        merged = DataClassifier._merge_handling([h1, h2])
        assert merged.max_retention_days == 90

    def test_merge_handling_empty(self) -> None:
        merged = DataClassifier._merge_handling([])
        assert merged.encrypt_at_rest is False


# ── autonomy_ratio ──────────────────────────────────────────────────────────

from acgs_lite.constitution.autonomy_ratio import (
    ActionCommitment,
    CommitmentRatioTracker,
    classify_action,
)


class TestAutonomyRatio:
    def test_classify_commit(self) -> None:
        assert classify_action("delete all records") == ActionCommitment.COMMIT

    def test_classify_propose(self) -> None:
        assert classify_action("draft report") == ActionCommitment.PROPOSE

    def test_classify_neutral(self) -> None:
        assert classify_action("hmm thinking") == ActionCommitment.NEUTRAL

    def test_tracker_record(self) -> None:
        tracker = CommitmentRatioTracker("agent-1")
        rec = tracker.record("deploy to production")
        assert rec.commitment == ActionCommitment.COMMIT
        assert len(rec.matched_keywords) > 0

    def test_tracker_state(self) -> None:
        tracker = CommitmentRatioTracker("agent-1")
        tracker.record("draft report")
        tracker.record("send email")
        state = tracker.current_state()
        assert state.commit_count == 1
        assert state.propose_count == 1

    def test_tracker_should_flag(self) -> None:
        tracker = CommitmentRatioTracker("agent-1", flag_threshold=0.5)
        tracker.record("delete records")
        tracker.record("send email")
        tracker.record("deploy service")
        state = tracker.current_state()
        assert state.should_flag is True

    def test_tracker_empty_state(self) -> None:
        tracker = CommitmentRatioTracker("agent-1")
        state = tracker.current_state()
        assert state.commit_ratio == 0.0
        assert state.ratio_level == "low"

    def test_record_batch(self) -> None:
        tracker = CommitmentRatioTracker("agent-1")
        records = tracker.record_batch(["draft report", "send email"])
        assert len(records) == 2

    def test_most_committing_actions(self) -> None:
        tracker = CommitmentRatioTracker("agent-1")
        tracker.record("deploy service")
        tracker.record("draft report")
        commits = tracker.most_committing_actions()
        assert len(commits) == 1

    def test_summary(self) -> None:
        tracker = CommitmentRatioTracker("agent-1")
        tracker.record("deploy")
        s = tracker.summary()
        assert s["agent_id"] == "agent-1"

    def test_reset(self) -> None:
        tracker = CommitmentRatioTracker("agent-1")
        tracker.record("deploy")
        tracker.reset()
        assert tracker.current_state().total_actions == 0

    def test_invalid_flag_threshold(self) -> None:
        with pytest.raises(ValueError):
            CommitmentRatioTracker("a", flag_threshold=0.0)
        with pytest.raises(ValueError):
            CommitmentRatioTracker("a", flag_threshold=1.5)

    def test_repr(self) -> None:
        tracker = CommitmentRatioTracker("agent-1")
        assert "CommitmentRatioTracker" in repr(tracker)

    def test_state_to_dict(self) -> None:
        tracker = CommitmentRatioTracker("agent-1")
        tracker.record("deploy")
        d = tracker.current_state().to_dict()
        assert "commit_ratio" in d

    def test_state_repr(self) -> None:
        tracker = CommitmentRatioTracker("agent-1")
        tracker.record("deploy")
        r = repr(tracker.current_state())
        assert "CommitmentRatioState" in r


# ── enforcement ─────────────────────────────────────────────────────────────

from acgs_lite.constitution.enforcement import (
    DecisionOutcome,
    EnforcementAction,
    EnforcementPolicy,
    PEPNetwork,
    PolicyDecisionPoint,
    PolicyEnforcementPoint,
)


class TestPolicyDecisionPoint:
    def test_decide_allow(self) -> None:
        pdp = PolicyDecisionPoint("test-pdp")
        decision = pdp.decide("safe action")
        assert decision.outcome == DecisionOutcome.ALLOW

    def test_decide_deny(self) -> None:
        pdp = PolicyDecisionPoint(
            "test-pdp",
            rules=[
                {"id": "R1", "keywords": ["delete"], "severity": "critical"},
            ],
        )
        decision = pdp.decide("delete everything")
        assert decision.outcome == DecisionOutcome.DENY
        assert "R1" in decision.matched_rules

    def test_decide_conditional(self) -> None:
        pdp = PolicyDecisionPoint(
            "test-pdp",
            rules=[
                {"id": "R1", "keywords": ["modify"], "severity": "low"},
            ],
        )
        decision = pdp.decide("modify settings")
        assert decision.outcome == DecisionOutcome.CONDITIONAL

    def test_stats_empty(self) -> None:
        pdp = PolicyDecisionPoint("test-pdp")
        s = pdp.stats()
        assert s["total"] == 0

    def test_stats_populated(self) -> None:
        pdp = PolicyDecisionPoint("test-pdp")
        pdp.decide("safe action")
        s = pdp.stats()
        assert s["total"] == 1

    def test_recent_decisions(self) -> None:
        pdp = PolicyDecisionPoint("test-pdp")
        pdp.decide("a")
        pdp.decide("b")
        assert len(pdp.recent_decisions(1)) == 1

    def test_add_rule(self) -> None:
        pdp = PolicyDecisionPoint("test-pdp")
        pdp.add_rule({"id": "R1", "keywords": ["delete"], "severity": "high"})
        decision = pdp.decide("delete data")
        assert decision.outcome == DecisionOutcome.DENY


class TestPolicyEnforcementPoint:
    def test_enforce_strict(self) -> None:
        pdp = PolicyDecisionPoint(
            "pdp",
            rules=[
                {"id": "R1", "keywords": ["delete"], "severity": "critical"},
            ],
        )
        pep = PolicyEnforcementPoint("pep", pdp, EnforcementPolicy.strict())
        result = pep.enforce("delete everything")
        assert result.enforcement_action == EnforcementAction.BLOCK

    def test_enforce_permissive(self) -> None:
        pdp = PolicyDecisionPoint(
            "pdp",
            rules=[
                {"id": "R1", "keywords": ["delete"], "severity": "critical"},
            ],
        )
        pep = PolicyEnforcementPoint("pep", pdp, EnforcementPolicy.permissive())
        result = pep.enforce("delete everything")
        assert result.enforcement_action == EnforcementAction.WARN

    def test_enforce_audit_only(self) -> None:
        pdp = PolicyDecisionPoint(
            "pdp",
            rules=[
                {"id": "R1", "keywords": ["delete"], "severity": "critical"},
            ],
        )
        pep = PolicyEnforcementPoint("pep", pdp, EnforcementPolicy.audit_only())
        result = pep.enforce("delete everything")
        assert result.enforcement_action == EnforcementAction.LOG_ONLY

    def test_is_allowed(self) -> None:
        pdp = PolicyDecisionPoint("pdp")
        pep = PolicyEnforcementPoint("pep", pdp)
        assert pep.is_allowed("safe action") is True

    def test_set_policy(self) -> None:
        pdp = PolicyDecisionPoint("pdp")
        pep = PolicyEnforcementPoint("pep", pdp)
        pep.set_policy(EnforcementPolicy.permissive())
        assert pep.policy == EnforcementPolicy.permissive()

    def test_stats(self) -> None:
        pdp = PolicyDecisionPoint("pdp")
        pep = PolicyEnforcementPoint("pep", pdp)
        pep.enforce("action")
        s = pep.stats()
        assert s["total"] == 1

    def test_stats_empty(self) -> None:
        pdp = PolicyDecisionPoint("pdp")
        pep = PolicyEnforcementPoint("pep", pdp)
        s = pep.stats()
        assert s["total"] == 0

    def test_recent_enforcements(self) -> None:
        pdp = PolicyDecisionPoint("pdp")
        pep = PolicyEnforcementPoint("pep", pdp)
        pep.enforce("a")
        pep.enforce("b")
        assert len(pep.recent_enforcements(1)) == 1

    def test_enforcement_result_to_dict(self) -> None:
        pdp = PolicyDecisionPoint("pdp")
        pep = PolicyEnforcementPoint("pep", pdp)
        result = pep.enforce("action")
        d = result.to_dict()
        assert "enforcement_action" in d


class TestPEPNetwork:
    def test_register_and_query(self) -> None:
        net = PEPNetwork()
        pdp = PolicyDecisionPoint("pdp")
        pep = PolicyEnforcementPoint("pep", pdp)
        net.register_pdp(pdp)
        net.register_pep(pep)
        assert net.get_pdp("pdp") is pdp
        assert net.get_pep("pep") is pep
        assert net.get_pdp("xx") is None
        assert net.get_pep("xx") is None

    def test_network_summary(self) -> None:
        net = PEPNetwork()
        pdp = PolicyDecisionPoint("pdp")
        pep = PolicyEnforcementPoint("pep", pdp)
        net.register_pdp(pdp)
        net.register_pep(pep)
        s = net.network_summary()
        assert s["pdp_count"] == 1
        assert s["pep_count"] == 1

    def test_all_stats(self) -> None:
        net = PEPNetwork()
        pdp = PolicyDecisionPoint("pdp")
        pep = PolicyEnforcementPoint("pep", pdp)
        net.register_pdp(pdp)
        net.register_pep(pep)
        pep.enforce("action")
        assert len(net.all_pep_stats()) == 1
        assert len(net.all_pdp_stats()) == 1


# ── boundaries ──────────────────────────────────────────────────────────────

from acgs_lite.constitution.boundaries import (
    BoundaryViolation,
    PolicyBoundary,
    PolicyBoundarySet,
)


class TestPolicyBoundary:
    def test_matches_keyword(self) -> None:
        b = PolicyBoundary("B1", "No card storage", "PCI", forbidden_keywords=["store card"])
        assert b.matches("store card number 4111") is True
        assert b.matches("deploy service") is False

    def test_matches_pattern(self) -> None:
        b = PolicyBoundary(
            "B1",
            "No Visa",
            "PCI",
            forbidden_patterns=[r"4[0-9]{12}(?:[0-9]{3})?"],
        )
        assert b.matches("charge 4111111111111111") is True
        assert b.matches("charge 5111111111111111") is False

    def test_violation(self) -> None:
        b = PolicyBoundary("B1", "No card", "PCI", forbidden_keywords=["store card"])
        v = b.violation("store card 4111")
        assert v is not None
        assert v.boundary_id == "B1"

    def test_no_violation(self) -> None:
        b = PolicyBoundary("B1", "No card", "PCI", forbidden_keywords=["store card"])
        assert b.violation("deploy service") is None

    def test_to_dict(self) -> None:
        b = PolicyBoundary("B1", "No card", "PCI", forbidden_keywords=["store card"])
        d = b.to_dict()
        assert d["boundary_id"] == "B1"

    def test_violation_to_dict(self) -> None:
        v = BoundaryViolation("action", "B1", "No card", "PCI")
        d = v.to_dict()
        assert d["boundary_id"] == "B1"


class TestPolicyBoundarySet:
    def test_check_blocked(self) -> None:
        bs = PolicyBoundarySet(
            [
                PolicyBoundary("B1", "No card", "PCI", forbidden_keywords=["store card"]),
            ]
        )
        result = bs.check("store card number")
        assert result["blocked"] is True
        assert len(result["violations"]) == 1

    def test_check_allowed(self) -> None:
        bs = PolicyBoundarySet(
            [
                PolicyBoundary("B1", "No card", "PCI", forbidden_keywords=["store card"]),
            ]
        )
        result = bs.check("deploy service")
        assert result["blocked"] is False

    def test_add_and_remove(self) -> None:
        bs = PolicyBoundarySet()
        bs.add(PolicyBoundary("B1", "No card", "PCI", forbidden_keywords=["store card"]))
        assert len(bs) == 1
        assert bs.remove("B1") is True
        assert len(bs) == 0
        assert bs.remove("B1") is False

    def test_check_batch(self) -> None:
        bs = PolicyBoundarySet(
            [
                PolicyBoundary("B1", "No card", "PCI", forbidden_keywords=["store card"]),
            ]
        )
        result = bs.check_batch(["store card 4111", "deploy service"])
        assert result["total"] == 2
        assert result["blocked_count"] == 1
        assert result["compliance_rate"] == 0.5

    def test_check_batch_empty(self) -> None:
        bs = PolicyBoundarySet()
        result = bs.check_batch([])
        assert result["compliance_rate"] == 1.0

    def test_summary(self) -> None:
        bs = PolicyBoundarySet(
            [
                PolicyBoundary("B1", "No card", "PCI", forbidden_keywords=["store card"]),
            ]
        )
        s = bs.summary()
        assert s["count"] == 1

    def test_repr(self) -> None:
        bs = PolicyBoundarySet()
        assert "PolicyBoundarySet" in repr(bs)
