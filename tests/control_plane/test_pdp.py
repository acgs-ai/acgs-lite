"""PDP: Cedar semantics, invariants, fail-closed matrix, T3, binding, audit."""

from __future__ import annotations

import time
from typing import Any

import pytest

from acgs_lite.audit import AuditLog, InMemoryAuditBackend
from acgs_lite.constitution import Constitution
from acgs_lite.control_plane import (
    CONSTITUTION_INVARIANTS,
    DEFAULT_IMMUTABLE_CORE,
    ActionTier,
    Decision,
    DecisionContext,
    DecisionRequest,
    PolicyDecisionPoint,
    PolicyEffect,
    PolicyParseError,
    PolicySet,
    PolicyStatement,
    Principal,
    PrincipalKind,
    is_write_action,
)
from acgs_lite.legitimacy.invocation import bind_policy

pytestmark = [pytest.mark.unit, pytest.mark.constitutional]


def _request(
    principal: Principal,
    action: str = "file.write",
    resource: str = "workspace/x.py",
    tier: ActionTier = ActionTier.T1,
    **kwargs: Any,
) -> DecisionRequest:
    return DecisionRequest(principal, action, resource, tier, **kwargs)


def _policy(*statements: dict[str, Any]) -> PolicySet:
    return PolicySet.from_mapping({"version": 1, "statements": list(statements)})


def _pdp(constitution: Constitution, policy: PolicySet | None, **kw: Any) -> PolicyDecisionPoint:
    return PolicyDecisionPoint.for_constitution(constitution, policy, **kw)


class TestCedarSemantics:
    def test_permit_match_allows(self, constitution: Constitution, agent: Principal) -> None:
        policy = _policy(
            {
                "id": "agent-workspace",
                "effect": "permit",
                "principal_kinds": ["agent"],
                "actions": ["file.*"],
                "resources": ["workspace/**"],
            }
        )
        with _pdp(constitution, policy) as pdp:
            decision = pdp.decide(_request(agent))
        assert decision.allowed
        assert decision.determining_policies == ("agent-workspace",)
        assert decision.error is None

    def test_no_match_is_default_deny(self, constitution: Constitution, agent: Principal) -> None:
        policy = _policy(
            {"id": "other", "effect": "permit", "actions": ["file.read"], "resources": ["x/**"]}
        )
        with _pdp(constitution, policy) as pdp:
            decision = pdp.decide(_request(agent))
        assert not decision.allowed
        assert "default deny" in decision.reason
        assert decision.determining_policies == ()

    def test_empty_policy_set_denies(self, constitution: Constitution, agent: Principal) -> None:
        with _pdp(constitution, _policy()) as pdp:
            assert not pdp.decide(_request(agent)).allowed

    def test_forbid_beats_permit(self, constitution: Constitution, agent: Principal) -> None:
        policy = _policy(
            {"id": "permit-all", "effect": "permit", "actions": ["*"], "resources": ["**"]},
            {"id": "no-tmp", "effect": "forbid", "actions": ["*"], "resources": ["workspace/**"]},
        )
        with _pdp(constitution, policy) as pdp:
            decision = pdp.decide(_request(agent))
        assert not decision.allowed
        assert decision.determining_policies == ("no-tmp",)

    @pytest.mark.red_team
    def test_invariant_beats_explicit_permit_on_evaluator(
        self, constitution: Constitution, agent: Principal
    ) -> None:
        policy = _policy(
            {
                "id": "agent-may-edit-evaluator",
                "effect": "permit",
                "principal_kinds": ["agent"],
                "actions": ["file.write"],
                "resources": ["evaluator/**"],
            }
        )
        with _pdp(constitution, policy) as pdp:
            decision = pdp.decide(_request(agent, resource="evaluator/score.py"))
        assert not decision.allowed
        assert "INV-CORE-WRITE" in decision.determining_policies

    def test_principal_kind_and_tier_constraints(
        self, constitution: Constitution, agent: Principal, human: Principal
    ) -> None:
        policy = _policy(
            {
                "id": "humans-low-tier",
                "effect": "permit",
                "principal_kinds": ["human"],
                "actions": ["file.write"],
                "resources": ["**"],
                "max_tier": "T1",
            }
        )
        with _pdp(constitution, policy) as pdp:
            assert pdp.decide(_request(human)).allowed
            assert not pdp.decide(_request(agent)).allowed
            assert not pdp.decide(_request(human, tier=ActionTier.T2)).allowed

    def test_unnormalisable_resource_never_permitted(
        self, constitution: Constitution, human: Principal, permit_all: PolicySet
    ) -> None:
        with _pdp(constitution, permit_all) as pdp:
            assert not pdp.decide(_request(human, resource="../escape")).allowed

    def test_repo_root_absolute_path_can_match_permit(
        self, constitution: Constitution, agent: Principal
    ) -> None:
        policy = _policy(
            {"id": "ws", "effect": "permit", "actions": ["file.*"], "resources": ["workspace/**"]}
        )
        registry = DEFAULT_IMMUTABLE_CORE.with_repo_root("/srv/repo")
        with _pdp(constitution, policy, registry=registry) as pdp:
            assert pdp.decide(_request(agent, resource="/srv/repo/workspace/x.py")).allowed
            core = pdp.decide(_request(agent, resource="/srv/repo/evaluator/x.py"))
            assert "INV-CORE-WRITE" in core.determining_policies
            assert not pdp.decide(_request(agent, resource="/srv/other/x.py")).allowed

    def test_python_condition(self, constitution: Constitution, agent: Principal) -> None:
        statement = PolicyStatement(
            id="only-ticketed",
            effect=PolicyEffect.PERMIT,
            principal_kinds=None,
            actions=("*",),
            resources=("**",),
            condition=lambda ctx: ctx.request.attributes.get("ticket") == "T-1",
        )
        with _pdp(constitution, PolicySet.from_statements([statement])) as pdp:
            assert pdp.decide(_request(agent, attributes={"ticket": "T-1"})).allowed
            assert not pdp.decide(_request(agent, attributes={"ticket": "T-2"})).allowed


class TestInvariants:
    def test_invariants_are_forbids_with_inv_prefix(self) -> None:
        ids = [statement.id for statement in CONSTITUTION_INVARIANTS]
        assert ids == [
            "INV-CORE-WRITE",
            "INV-CORE-SENSITIVE-READ",
            "INV-CORE-HUMAN-ONLY-CHANGE",
            "INV-T3-TWO-PERSON",
            "INV-TOOL-ARG-CORE",
            "INV-APPROVAL-QUORUM",
            "INV-AGENT-REQUESTED-BY",
            "INV-HUMAN-ONLY-CHANGE-CLASS",
        ]
        assert all(s.effect is PolicyEffect.FORBID for s in CONSTITUTION_INVARIANTS)

    def test_policy_cannot_reuse_invariant_ids(self) -> None:
        with pytest.raises(PolicyParseError):
            _policy(
                {"id": "INV-CORE-WRITE", "effect": "permit", "actions": ["*"], "resources": ["**"]}
            )

    @pytest.mark.red_team
    @pytest.mark.parametrize(
        ("action", "resource"),
        [
            ("file.write", "evaluator/score.py"),
            ("file.delete", "policies/main.yaml"),
            ("file.write", "cfg/tool_allowlist.json"),
            ("file.write", ".github/workflows/ci.yml"),
            ("file.truncate", "audit/log.jsonl"),
            ("file.write", "src/acgs_lite/control_plane/pdp.py"),
            ("file.write", "data/heldout/x.jsonl"),
            ("file.write", "secrets/x"),
            ("file.frobnicate", "evaluator/x.py"),
            ("policy.update", "main-policy"),
            ("audit.truncate", "primary"),
        ],
    )
    def test_agent_core_write_forbidden(
        self, pdp: PolicyDecisionPoint, agent: Principal, action: str, resource: str
    ) -> None:
        decision = pdp.decide(_request(agent, action=action, resource=resource))
        assert not decision.allowed
        assert "INV-CORE-WRITE" in decision.determining_policies

    def test_service_core_write_forbidden(self, pdp: PolicyDecisionPoint) -> None:
        service = Principal("ci-bot", PrincipalKind.SERVICE)
        assert not pdp.decide(_request(service, resource="evaluator/x.py")).allowed

    def test_agent_core_read_allowed_by_permit(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        decision = pdp.decide(_request(agent, action="file.read", resource="policies/main.yaml"))
        assert decision.allowed
        grader = pdp.decide(_request(agent, action="file.read", resource="evaluator/x.py"))
        assert "INV-CORE-SENSITIVE-READ" in grader.determining_policies

    @pytest.mark.parametrize("tier", [ActionTier.T0, ActionTier.T1])
    def test_human_core_change_requires_t2(
        self, pdp: PolicyDecisionPoint, human: Principal, tier: ActionTier
    ) -> None:
        decision = pdp.decide(_request(human, resource="policies/main.yaml", tier=tier))
        assert not decision.allowed
        assert "INV-CORE-HUMAN-ONLY-CHANGE" in decision.determining_policies

    def test_human_core_change_without_attested_approval_denied(
        self, pdp: PolicyDecisionPoint, human: Principal
    ) -> None:
        # Phase 3: T2 alone is not enough; an ungated PDP cannot attest a
        # second human, so even host-asserted approvers do not count.
        bob = Principal("bob", PrincipalKind.HUMAN)
        for approvers in ((), (bob,)):
            decision = pdp.decide(
                _request(
                    human, resource="policies/main.yaml", tier=ActionTier.T2, approvers=approvers
                )
            )
            assert not decision.allowed
            assert decision.determining_policies == ("INV-HUMAN-ONLY-CHANGE-CLASS",)

    def test_human_low_tier_write_to_other_core_category_allowed(
        self, pdp: PolicyDecisionPoint, human: Principal
    ) -> None:
        # CREDENTIALS is core but not a CORE_HUMAN_ONLY change category.
        assert pdp.decide(_request(human, resource="secrets/rotation.txt")).allowed

    def test_tool_name_is_not_classified_as_path(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        decision = pdp.decide(
            _request(agent, action="tool.call", resource="audit", attributes={"paths": []})
        )
        assert decision.allowed

    def test_tool_arg_core_forbidden_unless_read_only(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        write = pdp.decide(
            _request(
                agent, action="tool.call", resource="edit", attributes={"paths": ["evaluator/x"]}
            )
        )
        assert not write.allowed
        assert "INV-TOOL-ARG-CORE" in write.determining_policies
        single = pdp.decide(
            _request(agent, action="tool.call", resource="edit", attributes={"paths": "secrets/x"})
        )
        assert not single.allowed
        read = pdp.decide(
            _request(
                agent,
                action="tool.call",
                resource="cat",
                attributes={"paths": ["evaluator/x"], "tool_read_only": True},
            )
        )
        assert read.allowed

    def test_tool_arg_malformed_paths_deny(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        decision = pdp.decide(
            _request(agent, action="tool.call", resource="edit", attributes={"paths": [1, 2]})
        )
        assert not decision.allowed
        assert decision.error == "evaluation_error"
        assert decision.determining_policies == ("INV-TOOL-ARG-CORE",)


class TestTwoPersonRule:
    @pytest.mark.parametrize(
        ("approver_specs", "allowed"),
        [
            ((), False),
            ((("bob", PrincipalKind.HUMAN),), False),
            ((("bob", PrincipalKind.HUMAN), ("bob", PrincipalKind.HUMAN)), False),
            ((("bob", PrincipalKind.HUMAN), ("alice", PrincipalKind.HUMAN)), False),
            ((("bob", PrincipalKind.HUMAN), ("agent-9", PrincipalKind.AGENT)), False),
            ((("bob", PrincipalKind.HUMAN), ("carol", PrincipalKind.HUMAN)), True),
        ],
        ids=[
            "none",
            "one-human",
            "same-human-twice",
            "includes-requester",
            "with-agent",
            "two-humans",
        ],
    )
    def test_t3_approvals(
        self,
        pdp: PolicyDecisionPoint,
        human: Principal,
        approver_specs: tuple[tuple[str, PrincipalKind], ...],
        allowed: bool,
    ) -> None:
        approvers = tuple(Principal(pid, kind) for pid, kind in approver_specs)
        decision = pdp.decide(
            _request(
                human, action="db.drop", resource="prod/db", tier=ActionTier.T3, approvers=approvers
            )
        )
        assert decision.allowed is allowed
        if not allowed:
            assert "INV-T3-TWO-PERSON" in decision.determining_policies

    def test_t3_still_needs_a_permit(self, constitution: Constitution, human: Principal) -> None:
        approvers = (Principal("bob", PrincipalKind.HUMAN), Principal("carol", PrincipalKind.HUMAN))
        with _pdp(constitution, _policy()) as pdp:
            decision = pdp.decide(
                _request(
                    human,
                    action="db.drop",
                    resource="prod/db",
                    tier=ActionTier.T3,
                    approvers=approvers,
                )
            )
        assert not decision.allowed
        assert "default deny" in decision.reason


class TestBinding:
    def test_every_decision_carries_bind_policy_output(
        self, constitution: Constitution, permit_all: PolicySet, agent: Principal
    ) -> None:
        binding = bind_policy(constitution)
        with _pdp(constitution, permit_all) as pdp:
            assert pdp.constitution_hash == binding.version == constitution.hash
            assert pdp.policy_digest == binding.digest
            for request in (
                _request(agent),
                _request(agent, resource="evaluator/x.py"),
                _request(agent, expected_constitution_hash="stale"),
            ):
                decision = pdp.decide(request)
                assert decision.constitution_hash == binding.version
                assert decision.policy_digest == binding.digest
                assert decision.policy_set_digest == permit_all.source_digest
                assert decision.decided_at.endswith("+00:00")

    def test_inputs_digest_is_stable_and_sensitive(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        a = pdp.decide(_request(agent, attributes={"k": [1, 2]}))
        b = pdp.decide(_request(agent, attributes={"k": [1, 2]}))
        c = pdp.decide(_request(agent, attributes={"k": [2, 1]}))
        assert (
            a.inputs_digest
            == b.inputs_digest
            == _request(agent, attributes={"k": [1, 2]}).inputs_digest()
        )
        assert len(a.inputs_digest) == 64
        assert a.inputs_digest != c.inputs_digest

    def test_matching_expected_hash_allows(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        request = _request(agent, expected_constitution_hash=pdp.constitution_hash)
        assert pdp.decide(request).allowed

    def test_stale_expected_hash_denies(self, pdp: PolicyDecisionPoint, agent: Principal) -> None:
        decision = pdp.decide(_request(agent, expected_constitution_hash="0" * 16))
        assert not decision.allowed
        assert decision.error == "stale_policy"


class _FailingBackend(InMemoryAuditBackend):
    def write(self, entry_dict: dict[str, Any], chain_hash: str) -> None:
        raise RuntimeError("disk full")


def _RaisingAudit() -> AuditLog:  # noqa: N802 - keeps the call sites readable
    # A real AuditLog whose backend write fails: AuditLog.record() would
    # swallow this, so the PDP must use a write path that propagates it.
    return AuditLog(backend=_FailingBackend())


@pytest.mark.red_team
class TestFailClosedMatrix:
    def test_missing_policy_set(self, constitution: Constitution, agent: Principal) -> None:
        with _pdp(constitution, None) as pdp:
            decision = pdp.decide(_request(agent))
        assert not decision.allowed
        assert decision.error == "missing_policy"

    @pytest.mark.parametrize(("chash", "digest"), [("", "d"), ("h", ""), ("  ", "d"), (None, "d")])
    def test_blank_binding(
        self, permit_all: PolicySet, agent: Principal, chash: Any, digest: str
    ) -> None:
        with PolicyDecisionPoint(permit_all, constitution_hash=chash, policy_digest=digest) as pdp:
            decision = pdp.decide(_request(agent))
        assert not decision.allowed
        assert decision.error == "missing_binding"

    @pytest.mark.parametrize("request_obj", [None, {"action": "file.write"}, "file.write"])
    def test_not_a_request(self, pdp: PolicyDecisionPoint, request_obj: object) -> None:
        decision = pdp.decide(request_obj)
        assert not decision.allowed
        assert decision.error == "invalid_request"

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("tier", 7),
            ("tier", True),
            ("action", ""),
            ("action", 3),
            ("resource", ""),
            ("principal", "agent-1"),
            ("approvers", ["bob"]),
            ("attributes", {1: "x"}),
            ("expected_constitution_hash", 5),
        ],
    )
    def test_invalid_field_types(
        self, pdp: PolicyDecisionPoint, agent: Principal, field: str, value: object
    ) -> None:
        request = _request(agent)
        object.__setattr__(request, field, value)
        decision = pdp.decide(request)
        assert not decision.allowed
        assert decision.error == "invalid_request"

    def test_unserialisable_attributes(self, pdp: PolicyDecisionPoint, agent: Principal) -> None:
        decision = pdp.decide(_request(agent, attributes={"x": {1, 2}}))
        assert not decision.allowed
        assert decision.error == "invalid_request"
        nan = pdp.decide(_request(agent, attributes={"x": float("nan")}))
        assert not nan.allowed

    def test_condition_raises(self, constitution: Constitution, agent: Principal) -> None:
        def boom(ctx: DecisionContext) -> bool:
            raise RuntimeError("bad condition")

        policy = PolicySet.from_statements(
            [
                PolicyStatement("permit-all", PolicyEffect.PERMIT, None, ("*",), ("**",)),
                PolicyStatement(
                    "broken", PolicyEffect.FORBID, None, ("*",), ("**",), condition=boom
                ),
            ]
        )
        with _pdp(constitution, policy) as pdp:
            decision = pdp.decide(_request(agent))
        assert not decision.allowed
        assert decision.error == "evaluation_error"
        assert decision.determining_policies == ("broken",)

    def test_condition_returns_non_bool(self, constitution: Constitution, agent: Principal) -> None:
        policy = PolicySet.from_statements(
            [
                PolicyStatement(
                    "truthy", PolicyEffect.PERMIT, None, ("*",), ("**",), condition=lambda c: 1
                )
            ]  # type: ignore[arg-type,return-value]
        )
        with _pdp(constitution, policy) as pdp:
            assert not pdp.decide(_request(agent)).allowed

    def test_timeout_denies(self, constitution: Constitution, agent: Principal) -> None:
        def slow(ctx: DecisionContext) -> bool:
            time.sleep(0.3)
            return True

        policy = PolicySet.from_statements(
            [PolicyStatement("slow", PolicyEffect.PERMIT, None, ("*",), ("**",), condition=slow)]
        )
        with _pdp(constitution, policy, timeout_s=0.05) as pdp:
            started = time.monotonic()
            decision = pdp.decide(_request(agent))
            elapsed = time.monotonic() - started
        assert not decision.allowed
        assert decision.error == "timeout"
        assert "exceeded" in decision.reason
        assert elapsed < 2.0

    @pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), "1", True])
    def test_invalid_timeout_rejected(self, permit_all: PolicySet, timeout: Any) -> None:
        with pytest.raises(ValueError):
            PolicyDecisionPoint(
                permit_all, constitution_hash="h", policy_digest="d", timeout_s=timeout
            )

    def test_invalid_construction(self, permit_all: PolicySet) -> None:
        with pytest.raises(ValueError):
            PolicyDecisionPoint(permit_all, constitution_hash="h", policy_digest="d", max_workers=0)
        with pytest.raises(ValueError):
            PolicyDecisionPoint(
                permit_all,
                constitution_hash="h",
                policy_digest="d",
                registry="x",  # type: ignore[arg-type]
            )

    def test_listener_failure_does_not_flip_deny(
        self, constitution: Constitution, permit_all: PolicySet, agent: Principal
    ) -> None:
        seen: list[Decision] = []

        def bad_listener(decision: Decision) -> None:
            raise RuntimeError("listener down")

        with _pdp(constitution, permit_all, listeners=[bad_listener, seen.append]) as pdp:
            deny = pdp.decide(_request(agent, resource="evaluator/x.py"))
            allow = pdp.decide(_request(agent))
        assert not deny.allowed
        assert allow.allowed
        assert seen == [deny, allow]

    def test_audit_failure_turns_allow_into_deny(
        self, constitution: Constitution, permit_all: PolicySet, agent: Principal
    ) -> None:
        with _pdp(constitution, permit_all, audit_log=_RaisingAudit()) as pdp:
            allow = pdp.decide(_request(agent))
            deny = pdp.decide(_request(agent, resource="evaluator/x.py"))
        assert not allow.allowed
        assert allow.error == "audit_failed"
        assert not deny.allowed
        assert "INV-CORE-WRITE" in deny.determining_policies

    def test_durable_audit_without_backend_denies(
        self, constitution: Constitution, permit_all: PolicySet, agent: Principal
    ) -> None:
        with _pdp(constitution, permit_all, audit_log=AuditLog(), durable_audit=True) as pdp:
            decision = pdp.decide(_request(agent))
        assert not decision.allowed
        assert decision.error == "audit_failed"

    def test_backstop_denies_on_unexpected_error(
        self, pdp: PolicyDecisionPoint, agent: Principal, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("executor gone")

        monkeypatch.setattr(pdp, "_get_executor", explode)
        decision = pdp.decide(_request(agent))
        assert not decision.allowed
        assert decision.error == "fail_closed"

    def test_close_is_idempotent_and_executor_recreated(
        self, pdp: PolicyDecisionPoint, agent: Principal
    ) -> None:
        assert pdp.decide(_request(agent)).allowed
        pdp.close()
        pdp.close()
        assert pdp.decide(_request(agent)).allowed
        assert pdp.timeout_s == 0.25


class TestAuditRecording:
    def test_each_decision_recorded(
        self, constitution: Constitution, permit_all: PolicySet, agent: Principal
    ) -> None:
        log = AuditLog()
        with _pdp(constitution, permit_all, audit_log=log) as pdp:
            allow = pdp.decide(_request(agent))
            deny = pdp.decide(_request(agent, resource="evaluator/x.py", tier=ActionTier.T2))
        entries = log.entries
        assert [entry.type for entry in entries] == ["pdp_decision", "pdp_decision"]
        assert [entry.valid for entry in entries] == [True, False]
        assert entries[1].violations == [
            "INV-CORE-WRITE",
            "INV-CORE-SENSITIVE-READ",
            "INV-AGENT-REQUESTED-BY",
            "INV-HUMAN-ONLY-CHANGE-CLASS",
        ]
        for entry, decision in zip(entries, (allow, deny), strict=True):
            assert entry.constitutional_hash == constitution.hash
            assert entry.agent_id == "agent-1"
            assert entry.metadata["policy_digest"] == decision.policy_digest
            assert entry.metadata["inputs_digest"] == decision.inputs_digest
            assert entry.metadata["determining_policies"] == list(decision.determining_policies)
            assert entry.metadata["resource"] == decision.resource
        assert entries[1].metadata["tier"] == 2
        assert log.verify_chain()


class TestPolicyParsing:
    def test_yaml_round_trip_and_digest(self) -> None:
        text = """
version: 1
statements:
  - id: a
    effect: permit
    principal_kinds: [agent, human]
    actions: ["file.read"]
    resources: ["**"]
    max_tier: 1
    description: reads
"""
        first = PolicySet.from_yaml_str(text)
        second = PolicySet.from_yaml_str(text)
        assert first.source_digest == second.source_digest
        assert len(first.source_digest) == 64
        statement = first.statements[0]
        assert statement.max_tier is ActionTier.T1
        assert statement.principal_kinds == frozenset({PrincipalKind.AGENT, PrincipalKind.HUMAN})

    def test_from_yaml_file(self, tmp_path: Any) -> None:
        path = tmp_path / "p.yaml"
        path.write_text("version: 1\nstatements: []\n", encoding="utf-8")
        assert PolicySet.from_yaml(path).statements == ()

    @pytest.mark.parametrize(
        "data",
        [
            [],
            {"version": 1, "statements": [], "extra": True},
            {"version": 2, "statements": []},
            {"version": 1, "statements": {}},
            {"version": 1, "statements": ["x"]},
            {"version": 1, "statements": [{"id": "a", "effect": "permit", "actions": ["*"]}]},
            {
                "version": 1,
                "statements": [
                    {"id": "a", "effect": "allow", "actions": ["*"], "resources": ["**"]}
                ],
            },
            {
                "version": 1,
                "statements": [
                    {
                        "id": "a",
                        "effect": "permit",
                        "actions": ["*"],
                        "resources": ["**"],
                        "max_tier": "T9",
                    }
                ],
            },
            {
                "version": 1,
                "statements": [
                    {
                        "id": "a",
                        "effect": "permit",
                        "actions": ["*"],
                        "resources": ["**"],
                        "max_tier": True,
                    }
                ],
            },
            {
                "version": 1,
                "statements": [
                    {
                        "id": "a",
                        "effect": "permit",
                        "actions": ["*"],
                        "resources": ["**"],
                        "when": "x",
                    }
                ],
            },
            {
                "version": 1,
                "statements": [{"id": "a", "effect": "permit", "actions": [], "resources": ["**"]}],
            },
            {
                "version": 1,
                "statements": [
                    {"id": "a", "effect": "permit", "actions": [""], "resources": ["**"]}
                ],
            },
            {
                "version": 1,
                "statements": [
                    {"id": "", "effect": "permit", "actions": ["*"], "resources": ["**"]}
                ],
            },
            {
                "version": 1,
                "statements": [
                    {
                        "id": "a",
                        "effect": "permit",
                        "actions": ["*"],
                        "resources": ["**"],
                        "principal_kinds": ["robot"],
                    }
                ],
            },
            {
                "version": 1,
                "statements": [
                    {
                        "id": "a",
                        "effect": "permit",
                        "actions": ["*"],
                        "resources": ["**"],
                        "description": 3,
                    }
                ],
            },
            {
                "version": 1,
                "statements": [
                    {"id": "a", "effect": "permit", "actions": ["*"], "resources": ["**"]},
                    {"id": "a", "effect": "forbid", "actions": ["*"], "resources": ["**"]},
                ],
            },
        ],
    )
    def test_strict_schema(self, data: Any) -> None:
        with pytest.raises(PolicyParseError):
            PolicySet.from_mapping(data)

    def test_invalid_yaml(self) -> None:
        with pytest.raises(PolicyParseError):
            PolicySet.from_yaml_str("statements: [unclosed")

    def test_statement_validation(self) -> None:
        with pytest.raises(ValueError):
            PolicyStatement("", PolicyEffect.PERMIT, None, ("*",), ("**",))
        with pytest.raises(ValueError):
            PolicyStatement("a", PolicyEffect.PERMIT, frozenset(), ("*",), ("**",))
        with pytest.raises(ValueError):
            PolicyStatement("a", PolicyEffect.PERMIT, None, "*", ("**",))  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            PolicyStatement("a", PolicyEffect.PERMIT, None, ("*",), ("**",), condition=3)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            PolicySet((object(),), "d")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            PolicySet((), "")

    def test_declarative_projection_names_condition(self) -> None:
        def cond(ctx: DecisionContext) -> bool:
            return True

        statement = PolicyStatement("a", "permit", ["agent"], ("*",), ("**",), 2, cond)  # type: ignore[arg-type]
        projection = statement.declarative_projection()
        assert projection["condition"].endswith(
            ":TestPolicyParsing.test_declarative_projection_names_condition.<locals>.cond"
        )
        assert projection["max_tier"] == 2
        assert projection["principal_kinds"] == ["agent"]


class TestRequestModel:
    def test_write_action_classification(self) -> None:
        assert not is_write_action("file.read")
        assert not is_write_action("repo.LIST")
        assert is_write_action("file.write")
        assert is_write_action("file.unknownverb")
        assert is_write_action("")
        assert is_write_action(None)

    def test_request_attributes_are_read_only(self, agent: Principal) -> None:
        request = _request(agent, attributes={"a": 1})
        with pytest.raises(TypeError):
            request.attributes["a"] = 2  # type: ignore[index]

    def test_principal_validation(self) -> None:
        with pytest.raises(ValueError):
            Principal("", PrincipalKind.AGENT)
        with pytest.raises(ValueError):
            Principal("a", "robot")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            Principal("a", PrincipalKind.AGENT, system_id="")
        with pytest.raises(ValueError):
            Principal("a", PrincipalKind.AGENT, roles=frozenset({""}))
        principal = Principal("a", "agent", roles={"r"})  # type: ignore[arg-type]
        assert principal.kind is PrincipalKind.AGENT
        assert principal.roles == frozenset({"r"})
