"""Tests for acgs-lite core functionality.

Constitutional Hash: 608508a9bd224290
"""

import inspect
import tempfile
from dataclasses import dataclass

import pytest
from pydantic import BaseModel

from acgs_lite import (
    AuditEntry,
    AuditLog,
    Constitution,
    ConstitutionalViolationError,
    GovernanceEngine,
    GovernanceError,
    GovernedAgent,
    GovernedCallable,
    MACIEnforcer,
    MACIRole,
    MACIViolationError,
    PolicyDeniedError,
    Rule,
    Severity,
)
from acgs_lite.constitution.rule import ViolationAction
from acgs_lite.legitimacy import DecisionReceipt, ExecutionBoundary
from acgs_lite.serialization import serialize_for_governance


@pytest.mark.unit
class TestGovernanceSerialization:
    def test_serializes_dataclass(self) -> None:
        @dataclass
        class Payload:
            secret: str
            count: int

        payload = serialize_for_governance(Payload(secret="hunter2", count=2))
        assert '"secret": "hunter2"' in payload
        assert '"count": 2' in payload

    def test_serializes_pydantic_model(self) -> None:
        class PayloadModel(BaseModel):
            token: str
            active: bool

        payload = serialize_for_governance(PayloadModel(token="abc123", active=True))
        assert '"token": "abc123"' in payload
        assert '"active": true' in payload

    def test_truncates_large_payload(self) -> None:
        payload = serialize_for_governance({"blob": "x" * 128}, max_chars=40)
        assert payload.endswith("… [truncated]")
        assert len(payload) == 40


@pytest.mark.unit
class TestPolicyDeniedError:
    def test_signature_preserves_policy_and_parent_kwargs(self) -> None:
        sig = inspect.signature(PolicyDeniedError)

        for name in (
            "message",
            "policy_id",
            "rule_id",
            "policy_hash",
            "severity",
            "action",
            "enforcement_action",
        ):
            assert name in sig.parameters, sig

    def test_maps_policy_id_to_rule_id_when_rule_id_omitted(self) -> None:
        err = PolicyDeniedError("denied", policy_id="p1", policy_hash="h1", action="tool")

        assert isinstance(err, ConstitutionalViolationError)
        assert err.rule_id == "p1"
        assert err.policy_id == "p1"
        assert err.policy_hash == "h1"
        assert err.severity == "high"
        assert err.action == "tool"
        assert err.enforcement_action is ViolationAction.BLOCK
        assert err.__dict__ == {}

    def test_rule_id_overrides_policy_id(self) -> None:
        err = PolicyDeniedError("denied", rule_id="r1", policy_id="p1")

        assert err.rule_id == "r1"
        assert err.policy_id == "p1"

    def test_default_rule_id_is_policy(self) -> None:
        err = PolicyDeniedError("denied")

        assert err.rule_id == "policy"

    def test_exported_from_acgs_compat_namespace(self) -> None:
        from acgs import PolicyDeniedError as CompatPolicyDeniedError

        assert CompatPolicyDeniedError is PolicyDeniedError


# ─── Constitution Tests ───────────────────────────────────────────────────


@pytest.mark.unit
class TestConstitution:
    def test_default_constitution(self):
        c = Constitution.default()
        assert c.name == "acgs-default"
        assert len(c.rules) >= 6
        assert c.hash  # Non-empty hash

    def test_from_rules(self):
        rules = [
            Rule(id="R1", text="No PII", severity=Severity.CRITICAL, keywords=["pii"]),
            Rule(id="R2", text="Log everything", severity=Severity.HIGH, keywords=["log"]),
        ]
        c = Constitution.from_rules(rules, name="test")
        assert c.name == "test"
        assert len(c) == 2

    def test_hash_deterministic(self):
        rules = [Rule(id="R1", text="Test rule", severity=Severity.HIGH, keywords=["test"])]
        c1 = Constitution.from_rules(rules)
        c2 = Constitution.from_rules(rules)
        assert c1.hash == c2.hash

    def test_hash_changes_with_rules(self):
        c1 = Constitution.from_rules([Rule(id="R1", text="Rule A", keywords=["rule-a"])])
        c2 = Constitution.from_rules([Rule(id="R1", text="Rule B", keywords=["rule-b"])])
        assert c1.hash != c2.hash

    def test_hash_changes_with_hardcoded_flag(self):
        c1 = Constitution.from_rules(
            [Rule(id="R1", text="Rule A", hardcoded=False, keywords=["rule-a"])]
        )
        c2 = Constitution.from_rules(
            [Rule(id="R1", text="Rule A", hardcoded=True, keywords=["rule-a"])]
        )
        assert c1.hash != c2.hash

    def test_versioned_hash(self):
        c = Constitution.default()
        assert c.hash_versioned.startswith("sha256:v1:")

    def test_from_yaml(self):
        yaml_content = """
name: test-constitution
version: "1.0"
rules:
  - id: R001
    text: No PII access
    severity: critical
    keywords: [ssn, social security]
  - id: R002
    text: Always log
    severity: high
    keywords: [log]
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            c = Constitution.from_yaml(f.name)

        assert c.name == "test-constitution"
        assert len(c.rules) == 2
        assert c.rules[0].severity == Severity.CRITICAL
        assert "ssn" in c.rules[0].keywords

    def test_from_dict(self):
        data = {
            "name": "dict-test",
            "rules": [
                {"id": "R1", "text": "Test", "severity": "medium", "keywords": ["test"]},
            ],
        }
        c = Constitution.from_dict(data)
        assert c.name == "dict-test"
        assert c.rules[0].severity == Severity.MEDIUM

    def test_from_dict_normalizes_uppercase_severity(self):
        data = {
            "name": "dict-test",
            "rules": [
                {"id": "R1", "text": "Test", "severity": " CRITICAL ", "keywords": ["test"]},
            ],
        }

        c = Constitution.from_dict(data)

        assert c.rules[0].severity == Severity.CRITICAL

    def test_from_yaml_rejects_non_list_rules(self):
        yaml_content = "name: invalid\nrules: not-a-list\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            with pytest.raises(ValueError, match="rules"):
                Constitution.from_yaml(f.name)

    def test_get_rule(self):
        c = Constitution.default()
        rule = c.get_rule("ACGS-001")
        assert rule is not None
        assert rule.id == "ACGS-001"
        assert c.get_rule("NONEXISTENT") is None

    def test_active_rules_filters_disabled(self):
        rules = [
            Rule(id="R1", text="Active", enabled=True, keywords=["active"]),
            Rule(id="R2", text="Disabled", enabled=False, keywords=["disabled"]),
        ]
        c = Constitution.from_rules(rules)
        assert len(c.active_rules()) == 1


@pytest.mark.unit
class TestRule:
    def test_keyword_matching(self):
        rule = Rule(id="R1", text="No PII", keywords=["ssn", "credit card"])
        assert rule.matches("Please provide your SSN")
        assert rule.matches("enter credit card number")
        assert not rule.matches("safe input here")

    def test_pattern_matching(self):
        rule = Rule(
            id="R1",
            text="No API keys",
            patterns=[r"sk-[a-zA-Z0-9]{20,}"],
        )
        assert rule.matches("Here is key sk-abcdefghijklmnopqrstuvwxyz")
        assert not rule.matches("safe text")

    def test_disabled_rule_never_matches(self):
        rule = Rule(id="R1", text="Test", keywords=["match"], enabled=False)
        assert not rule.matches("this should match but won't")

    def test_invalid_regex_rejected(self):
        with pytest.raises(ValueError, match="Invalid regex"):
            Rule(id="R1", text="Bad", patterns=["[invalid"])


# ─── Engine Tests ──────────────────────────────────────────────────────────


@pytest.mark.constitutional
class TestGovernanceEngine:
    def test_valid_action_passes(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=False)
        result = engine.validate("Deploy new feature to staging")
        assert result.valid
        assert result.constitutional_hash == c.hash
        assert result.latency_ms >= 0

    def test_violation_detected(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=False)
        result = engine.validate("Agent will self-validate its output")
        assert not result.valid
        assert len(result.violations) > 0
        assert result.violations[0].rule_id == "ACGS-001"

    def test_fast_mode_allow_results_do_not_share_identity(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=False)

        first = engine.validate("review governance documentation")
        second = engine.validate("review governance documentation")

        assert first.valid is True
        assert second.valid is True
        assert first is not second

    def test_fast_mode_violation_results_do_not_share_mutable_state(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=False)

        first = engine.validate("skip audit trail for release")
        first.violations.append(
            type(first.violations[0])(
                "TEST-ONLY",
                "synthetic",
                Severity.LOW,
                "synthetic",
                "test",
            )
        )
        second = engine.validate("skip audit trail for release")

        assert first is not second
        assert [violation.rule_id for violation in second.violations] == ["ACGS-002"]

    def test_strict_mode_raises(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=True)
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            engine.validate("bypass validation checks")
        assert exc_info.value.rule_id == "ACGS-001"

    def test_context_validation(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=False)
        # Only action_detail/action_description context keys are matched
        # against rules (domain/risk/data labels are metadata, not actions)
        result = engine.validate(
            "process request",
            context={"action_detail": "contains secret key exposure"},
        )
        assert not result.valid
        # Regular context keys should NOT trigger violations
        result2 = engine.validate(
            "process request",
            context={"data": "contains secret key exposure"},
        )
        assert result2.valid

    def test_batch_validation(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=True)
        results = engine.validate_batch(
            [
                "safe action",
                "self-validate bypass",
                "another safe action",
            ]
        )
        assert len(results) == 3
        assert results[0].valid
        assert not results[1].valid
        assert results[2].valid

    def test_custom_validator(self):
        from acgs_lite.engine import Violation

        def no_sql_injection(action: str, ctx: dict) -> list[Violation]:
            if "DROP TABLE" in action.upper():
                return [
                    Violation(
                        rule_id="CUSTOM-SQL",
                        rule_text="SQL injection detected",
                        severity=Severity.CRITICAL,
                        matched_content=action[:100],
                        category="security",
                    )
                ]
            return []

        c = Constitution.from_rules([])
        engine = GovernanceEngine(c, strict=False, custom_validators=[no_sql_injection])
        result = engine.validate("DROP TABLE users;")
        assert not result.valid
        assert result.violations[0].rule_id == "CUSTOM-SQL"

    def test_stats(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=False)
        engine.validate("action 1")
        engine.validate("action 2")
        stats = engine.stats
        assert stats["total_validations"] == 2
        assert stats["constitutional_hash"] == c.hash
        assert stats["audit_mode"] == "fast"
        assert stats["audit_entry_count"] == 0
        assert stats["audit_metrics_complete"] is False
        assert stats["compliance_rate"] is None
        assert stats["avg_latency_ms"] is None

    def test_full_audit_mode_records_entries_without_explicit_log(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=False, audit_mode="full")
        engine.validate("safe action")
        assert engine.audit_mode == "full"
        assert len(engine.audit_log.entries) == 1
        assert engine.stats["audit_entry_count"] == 1
        assert engine.stats["audit_metrics_complete"] is True

    def test_fast_audit_mode_rejects_explicit_audit_log(self):
        c = Constitution.default()
        with pytest.raises(ValueError, match="audit_log cannot be provided"):
            GovernanceEngine(c, strict=False, audit_log=AuditLog(), audit_mode="fast")

    def test_ssn_pattern_detection(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=False)
        # Include a keyword from ACGS-006 so the rule's patterns are evaluated
        result = engine.validate("password reset, SSN is 123-45-6789")
        assert not result.valid
        assert any(v.rule_id == "ACGS-006" for v in result.violations)

    def test_api_key_pattern_detection(self):
        c = Constitution.default()
        engine = GovernanceEngine(c, strict=False)
        result = engine.validate("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert not result.valid


# ─── Audit Tests ───────────────────────────────────────────────────────────


@pytest.mark.unit
class TestAuditLog:
    def test_record_and_query(self):
        log = AuditLog()
        log.record(AuditEntry(id="1", type="validation", agent_id="a1", valid=True))
        log.record(AuditEntry(id="2", type="validation", agent_id="a2", valid=False))
        assert len(log) == 2
        assert log.compliance_rate == 0.5

    def test_chain_integrity(self):
        log = AuditLog()
        log.record(AuditEntry(id="1", type="test", valid=True))
        log.record(AuditEntry(id="2", type="test", valid=True))
        log.record(AuditEntry(id="3", type="test", valid=True))
        assert log.verify_chain()

    def test_query_filters(self):
        log = AuditLog()
        log.record(AuditEntry(id="1", type="validation", agent_id="a1", valid=True))
        log.record(AuditEntry(id="2", type="maci", agent_id="a2", valid=False))
        assert len(log.query(agent_id="a1")) == 1
        assert len(log.query(entry_type="maci")) == 1
        assert len(log.query(valid=False)) == 1

    def test_export_json(self):
        log = AuditLog()
        log.record(AuditEntry(id="1", type="test", valid=True))
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            log.export_json(f.name)
            import json

            with open(f.name) as rf:
                data = json.load(rf)
            assert data["entry_count"] == 1
            assert data["chain_valid"]

    def test_max_entries_trim(self):
        log = AuditLog(max_entries=5)
        for i in range(10):
            log.record(AuditEntry(id=str(i), type="test", valid=True))
        assert len(log) == 5

    def test_record_atomic_rolls_back_on_persist_failure(self):
        """A failing persist callback must leave the log unchanged."""
        log = AuditLog()
        log.record(AuditEntry(id="pre", type="test", valid=True))
        pre_len = len(log)
        pre_entries = list(log.entries)

        def failing_persist(_log):
            raise OSError("disk full")

        entry = AuditEntry(id="would-be-rolled-back", type="test", valid=True)
        with pytest.raises(OSError):
            log.record_atomic(entry, persist=failing_persist)

        # Log is back to pre-append state — no orphan entry, chain still valid.
        assert len(log) == pre_len
        assert [e.id for e in log.entries] == [e.id for e in pre_entries]
        assert log.verify_chain()

    def test_record_atomic_commits_when_persist_succeeds(self):
        log = AuditLog()
        committed: list[bool] = []

        def ok_persist(_log):
            committed.append(True)

        log.record_atomic(
            AuditEntry(id="committed", type="test", valid=True),
            persist=ok_persist,
        )
        assert committed == [True]
        assert len(log) == 1
        assert log.entries[0].id == "committed"
        assert log.verify_chain()

    def test_record_atomic_retry_is_idempotent_on_persist_error(self):
        """Reviewer's concern: a retry after persist failure must not
        leave a stale duplicate behind.  With rollback + idempotent
        retry, the log ends up with exactly one entry, not two."""
        log = AuditLog()
        fail_count = [0]

        def flaky_persist(_log):
            fail_count[0] += 1
            if fail_count[0] == 1:
                raise OSError("transient disk fault")

        entry = AuditEntry(id="retry-me", type="test", valid=True)

        # First attempt: persist fails, rollback runs.
        with pytest.raises(OSError):
            log.record_atomic(entry, persist=flaky_persist)
        assert len(log) == 0

        # Caller retries with a semantically-identical entry.
        log.record_atomic(entry, persist=flaky_persist)
        assert len(log) == 1
        assert log.entries[0].id == "retry-me"
        assert log.verify_chain()

    def test_record_atomic_rollback_preserves_concurrent_writer(self, tmp_path):
        """Codex finding: a rollback from record_atomic must not erase an
        entry that a concurrent record() caller committed between checkpoint
        and persist. Regression test for the backend-write-outside-lock race."""
        import threading
        import time

        from acgs_lite.audit import JSONLAuditBackend

        backend_path = tmp_path / "audit.jsonl"
        backend = JSONLAuditBackend(backend_path)
        log = AuditLog(backend=backend)

        # Atomic writer's persist blocks until the concurrent writer has landed,
        # then fails — forcing rollback to happen *after* the other write.
        concurrent_done = threading.Event()

        def slow_failing_persist(_log):
            # Give the other thread a window to sneak a record() in.
            concurrent_done.wait(timeout=2.0)
            raise OSError("persist failed — triggers rollback")

        errors: list[BaseException] = []

        def atomic_writer():
            try:
                log.record_atomic(
                    AuditEntry(id="atomic-rolled-back", type="test", valid=True),
                    persist=slow_failing_persist,
                )
            except OSError:
                pass
            except BaseException as e:
                errors.append(e)

        def concurrent_writer():
            # Small delay so the atomic writer has acquired the lock first.
            time.sleep(0.05)
            log.record(AuditEntry(id="concurrent-committed", type="test", valid=True))
            concurrent_done.set()

        t1 = threading.Thread(target=atomic_writer)
        t2 = threading.Thread(target=concurrent_writer)
        t1.start()
        t2.start()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)

        assert not errors, f"unexpected errors: {errors}"

        # In-memory: exactly the committed entry survives.
        ids = [e.id for e in log.entries]
        assert ids == ["concurrent-committed"], f"unexpected entries: {ids}"

        # Durable backend: same — rollback did not erase the concurrent write.
        backend.flush()
        reconstructed = AuditLog.from_backend(JSONLAuditBackend(backend_path))
        rec_ids = [e.id for e in reconstructed.entries]
        assert rec_ids == ["concurrent-committed"], f"backend has: {rec_ids}"
        assert reconstructed.verify_chain()

    def test_record_atomic_rolls_back_durable_backend_on_persist_failure(self, tmp_path):
        """Codex finding: durable backends must roll back too, otherwise
        from_backend() replays a phantom entry after a failed atomic write."""
        from acgs_lite.audit import JSONLAuditBackend

        backend_path = tmp_path / "audit.jsonl"
        backend = JSONLAuditBackend(backend_path)
        log = AuditLog(backend=backend)

        # First entry commits normally.
        log.record_atomic(AuditEntry(id="committed", type="test", valid=True))

        def failing_persist(_log):
            raise OSError("persist failed after backend write")

        with pytest.raises(OSError):
            log.record_atomic(
                AuditEntry(id="rolled-back", type="test", valid=True),
                persist=failing_persist,
            )

        # In-memory: rollback worked.
        assert len(log) == 1
        assert log.entries[0].id == "committed"

        # Durable backend: rollback also worked — the file does not contain
        # the rolled-back entry, so reconstruction sees only the committed one.
        backend.flush()
        reconstructed = AuditLog.from_backend(JSONLAuditBackend(backend_path))
        assert len(reconstructed) == 1
        assert reconstructed.entries[0].id == "committed"
        assert reconstructed.verify_chain()

    def test_record_atomic_many_commits_batch(self):
        log = AuditLog()
        committed: list[bool] = []

        def ok_persist(_log):
            committed.append(True)

        entries = [AuditEntry(id=f"batch-{i}", type="test", valid=True) for i in range(3)]
        hashes = log.record_atomic_many(entries, persist=ok_persist)

        assert committed == [True]
        assert len(hashes) == 3
        assert [e.id for e in log.entries] == ["batch-0", "batch-1", "batch-2"]
        assert log.verify_chain()

    def test_record_atomic_many_rolls_back_on_persist_failure(self):
        """All batch entries must be rolled back if persist fails — no partial state."""
        log = AuditLog()
        log.record(AuditEntry(id="pre", type="test", valid=True))
        pre_ids = [e.id for e in log.entries]

        def failing_persist(_log):
            raise OSError("disk full")

        batch = [AuditEntry(id=f"batch-{i}", type="test", valid=True) for i in range(3)]
        with pytest.raises(OSError):
            log.record_atomic_many(batch, persist=failing_persist)

        # No partial batch remains; chain still valid.
        assert [e.id for e in log.entries] == pre_ids
        assert log.verify_chain()

    def test_record_atomic_many_retry_does_not_duplicate(self):
        """Retry after persist failure must not leave stale partial history."""
        log = AuditLog()
        fail_count = [0]

        def flaky_persist(_log):
            fail_count[0] += 1
            if fail_count[0] == 1:
                raise OSError("transient")

        batch = [AuditEntry(id=f"retry-{i}", type="test", valid=True) for i in range(2)]

        with pytest.raises(OSError):
            log.record_atomic_many(batch, persist=flaky_persist)
        assert len(log) == 0

        log.record_atomic_many(batch, persist=flaky_persist)
        assert [e.id for e in log.entries] == ["retry-0", "retry-1"]
        assert log.verify_chain()

    def test_record_atomic_many_empty_is_noop(self):
        log = AuditLog()
        assert log.record_atomic_many([]) == []
        assert len(log) == 0

    def test_record_atomic_many_rolls_back_durable_backend(self, tmp_path):
        """Batch rollback must also truncate the durable backend."""
        from acgs_lite.audit import JSONLAuditBackend

        backend_path = tmp_path / "audit.jsonl"
        backend = JSONLAuditBackend(backend_path)
        log = AuditLog(backend=backend)

        log.record_atomic(AuditEntry(id="pre", type="test", valid=True))

        def failing_persist(_log):
            raise OSError("persist boom")

        batch = [AuditEntry(id=f"batch-{i}", type="test", valid=True) for i in range(3)]
        with pytest.raises(OSError):
            log.record_atomic_many(batch, persist=failing_persist)

        backend.flush()
        reconstructed = AuditLog.from_backend(JSONLAuditBackend(backend_path))
        assert [e.id for e in reconstructed.entries] == ["pre"]
        assert reconstructed.verify_chain()


# ─── MACI Tests ────────────────────────────────────────────────────────────


@pytest.mark.constitutional
class TestMACIEnforcer:
    def test_role_assignment(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("agent-1", MACIRole.PROPOSER)
        assert enforcer.get_role("agent-1") == MACIRole.PROPOSER

    def test_proposer_cannot_validate(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("agent-1", MACIRole.PROPOSER)
        with pytest.raises(MACIViolationError):
            enforcer.check("agent-1", "validate")

    def test_validator_cannot_execute(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("agent-1", MACIRole.VALIDATOR)
        with pytest.raises(MACIViolationError):
            enforcer.check("agent-1", "execute")

    def test_validator_cannot_run_unlisted_action(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("agent-1", MACIRole.VALIDATOR)
        with pytest.raises(MACIViolationError):
            enforcer.check("agent-1", "approve")

    def test_executor_cannot_validate(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("agent-1", MACIRole.EXECUTOR)
        with pytest.raises(MACIViolationError):
            enforcer.check("agent-1", "validate")

    def test_valid_role_actions_pass(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("p", MACIRole.PROPOSER)
        enforcer.assign_role("v", MACIRole.VALIDATOR)
        enforcer.assign_role("e", MACIRole.EXECUTOR)
        assert enforcer.check("p", "propose")
        assert enforcer.check("v", "validate")
        assert enforcer.check("e", "execute")

    def test_no_self_validation(self):
        enforcer = MACIEnforcer()
        with pytest.raises(MACIViolationError):
            enforcer.check_no_self_validation("agent-1", "agent-1")

    def test_cross_validation_allowed(self):
        enforcer = MACIEnforcer()
        assert enforcer.check_no_self_validation("agent-1", "agent-2")

    def test_unassigned_agent_cannot_run_unlisted_action(self):
        enforcer = MACIEnforcer()
        with pytest.raises(MACIViolationError):
            enforcer.check("agent-1", "delete")

    def test_summary(self):
        enforcer = MACIEnforcer()
        enforcer.assign_role("a1", MACIRole.PROPOSER)
        enforcer.check("a1", "propose")
        summary = enforcer.summary()
        assert summary["agents"] == 1
        assert summary["checks_total"] >= 1


# ─── GovernedAgent Tests ──────────────────────────────────────────────────


@pytest.mark.constitutional
class TestGovernedAgent:
    def test_wrap_callable(self):
        def my_agent(input: str) -> str:
            return f"Processed: {input}"

        agent = GovernedAgent(my_agent, agent_id="test-agent")
        result = agent.run("safe input")
        assert result == "Processed: safe input"

    def test_wrap_class_with_run(self):
        class MyAgent:
            def run(self, input: str) -> str:
                return f"Agent: {input}"

        agent = GovernedAgent(MyAgent(), agent_id="class-agent")
        result = agent.run("hello world")
        assert result == "Agent: hello world"

    def test_blocks_violation(self):
        def my_agent(input: str) -> str:
            return input

        agent = GovernedAgent(my_agent, strict=True)
        with pytest.raises(ConstitutionalViolationError):
            agent.run("self-validate bypass")

    def test_validates_output(self):
        def leaky_agent(input: str) -> str:
            return "Here is the secret key: sk-abcdefghijklmnopqrstuvwxyz1234"

        agent = GovernedAgent(leaky_agent, strict=True, validate_output=True)
        with pytest.raises(ConstitutionalViolationError):
            agent.run("get me the key")

    def test_validates_structured_output(self):
        def leaky_agent(input: str) -> dict[str, str]:
            return {"password": "hunter2"}

        agent = GovernedAgent(leaky_agent, strict=True, validate_output=True)
        with pytest.raises(ConstitutionalViolationError):
            agent.run("safe input")

    def test_validates_keyword_arguments(self):
        def my_agent(input: str, **kwargs: str) -> str:
            return "ok"

        agent = GovernedAgent(my_agent, strict=True)
        with pytest.raises(ConstitutionalViolationError):
            agent.run("safe input", password="hunter2")

    def test_custom_constitution(self):
        rules = Constitution.from_rules(
            [
                Rule(id="CUSTOM-1", text="No cats", severity=Severity.CRITICAL, keywords=["cat"]),
            ]
        )

        def my_agent(input: str) -> str:
            return input

        agent = GovernedAgent(my_agent, constitution=rules, strict=True)
        agent.run("dogs are great")  # Works
        with pytest.raises(ConstitutionalViolationError):
            agent.run("I love my cat")  # Blocked

    def test_stats(self):
        agent = GovernedAgent(lambda x: x, strict=False)
        agent.run("action 1")
        agent.run("action 2")
        stats = agent.stats
        assert stats["total_validations"] >= 2
        assert stats["audit_chain_valid"]

    def test_repr(self):
        agent = GovernedAgent(lambda x: x, agent_id="test")
        r = repr(agent)
        assert "GovernedAgent" in r
        assert "test" in r

    def test_enforce_maci_requires_governance_action(self):
        agent = GovernedAgent(
            lambda x: x,
            agent_id="proposer-agent",
            maci_role=MACIRole.PROPOSER,
            enforce_maci=True,
        )

        with pytest.raises(GovernanceError, match="requires governance_action"):
            agent.run("draft proposal")

    def test_enforce_maci_allows_matching_action(self):
        agent = GovernedAgent(
            lambda x: x,
            agent_id="proposer-agent",
            maci_role=MACIRole.PROPOSER,
            enforce_maci=True,
        )

        assert agent.run("draft proposal", governance_action="propose") == "draft proposal"

    def test_enforce_maci_blocks_disallowed_action(self):
        agent = GovernedAgent(
            lambda x: x,
            agent_id="proposer-agent",
            maci_role=MACIRole.PROPOSER,
            enforce_maci=True,
        )

        with pytest.raises(MACIViolationError):
            agent.run("validate proposal", governance_action="validate")


@pytest.mark.constitutional
class TestGovernedCallable:
    @staticmethod
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

    def test_decorator(self):
        @GovernedCallable()
        def process(input: str) -> str:
            return f"Done: {input}"

        result = process("safe data", decision_receipt=self._receipt("process"))
        assert result == "Done: safe data"

    def test_decorator_blocks_violation(self):
        @GovernedCallable()
        def process(input: str) -> str:
            return input

        with pytest.raises(ConstitutionalViolationError):
            process("self-validate bypass", decision_receipt=self._receipt("process"))

    def test_decorator_validates_output(self):
        @GovernedCallable()
        def leaky(input: str) -> str:
            return "password is hunter2"

        with pytest.raises(ConstitutionalViolationError):
            leaky("get password", decision_receipt=self._receipt("leaky"))

    def test_decorator_validates_keyword_arguments(self):
        @GovernedCallable(strict=True)
        def process(*, input: str) -> str:
            return "ok"

        with pytest.raises(ConstitutionalViolationError):
            process(input="here is the password", decision_receipt=self._receipt("process"))

    def test_decorator_preserves_keyword_names_in_validation(self):
        @GovernedCallable(strict=True)
        def process(*, password: str) -> str:
            return "ok"

        with pytest.raises(ConstitutionalViolationError):
            process(password="hunter2", decision_receipt=self._receipt("process"))

    def test_decorator_validates_structured_output(self):
        @GovernedCallable(strict=True)
        def leaky(input: str) -> dict[str, str]:
            return {"password": "hunter2"}

        with pytest.raises(ConstitutionalViolationError):
            leaky("safe input", decision_receipt=self._receipt("leaky"))


# ─── Async Tests ──────────────────────────────────────────────────────────


@pytest.mark.constitutional
class TestAsyncGovernedAgent:
    async def test_async_run(self):
        async def my_agent(input: str) -> str:
            return f"Async: {input}"

        agent = GovernedAgent(my_agent, agent_id="async-agent")
        result = await agent.arun("hello")
        assert result == "Async: hello"

    async def test_async_blocks_violation(self):
        async def my_agent(input: str) -> str:
            return input

        agent = GovernedAgent(my_agent, strict=True)
        with pytest.raises(ConstitutionalViolationError):
            await agent.arun("self-validate bypass")


# ─── Integration Tests ────────────────────────────────────────────────────


@pytest.mark.constitutional
class TestIntegration:
    def test_full_governance_pipeline(self):
        """End-to-end: constitution → engine → agent → audit."""
        # 1. Define constitution
        constitution = Constitution.from_rules(
            [
                Rule(
                    id="SAFE-001",
                    text="No financial advice",
                    severity=Severity.CRITICAL,
                    keywords=["invest", "buy stocks"],
                ),
                Rule(
                    id="SAFE-002",
                    text="No medical advice",
                    severity=Severity.CRITICAL,
                    keywords=["prescribe", "diagnosis"],
                ),
            ],
            name="safety-rules",
        )

        # 2. Create governed agent
        def assistant(input: str) -> str:
            return f"I can help with: {input}"

        agent = GovernedAgent(
            assistant,
            constitution=constitution,
            agent_id="assistant-v1",
            strict=False,
        )

        # 3. Run safe actions
        r1 = agent.run("What is the weather?")
        assert r1 == "I can help with: What is the weather?"

        # 4. Run violating action (non-strict, so doesn't raise)
        r2 = agent.run("Should I invest in crypto?")
        assert r2 == "I can help with: Should I invest in crypto?"

        # 5. Check audit trail
        stats = agent.stats
        assert stats["total_validations"] >= 2
        assert stats["audit_chain_valid"]

        # 6. Verify some violations were recorded
        violations = agent.audit_log.query(valid=False)
        assert len(violations) > 0

    def test_maci_with_governed_agents(self):
        """MACI enforcement with multiple governed agents."""
        audit = AuditLog()
        maci = MACIEnforcer(audit_log=audit)

        # Assign roles
        maci.assign_role("proposer-1", MACIRole.PROPOSER)
        maci.assign_role("validator-1", MACIRole.VALIDATOR)
        maci.assign_role("executor-1", MACIRole.EXECUTOR)

        # Proposer can propose
        assert maci.check("proposer-1", "propose")

        # Validator can validate
        assert maci.check("validator-1", "validate")

        # Executor can execute
        assert maci.check("executor-1", "execute")

        # Cross-role violations blocked
        with pytest.raises(MACIViolationError):
            maci.check("proposer-1", "validate")

        with pytest.raises(MACIViolationError):
            maci.check("validator-1", "execute")

        # No self-validation
        with pytest.raises(MACIViolationError):
            maci.check_no_self_validation("agent-1", "agent-1")


# ─── Retry on Output Violation ──────────────────────────────────────────


@pytest.mark.constitutional
class TestGovernedAgentRetry:
    """Tests for retry-on-output-violation behavior."""

    def test_default_no_retry(self):
        """max_retries=0 (default): violation raises immediately, same as before."""

        def leaky_agent(input: str) -> str:
            return "password is hunter2"

        agent = GovernedAgent(leaky_agent, strict=True, validate_output=True)
        with pytest.raises(ConstitutionalViolationError):
            agent.run("get credential")

    def test_retry_succeeds_on_second_attempt(self):
        """Agent produces violating output first, compliant output on retry."""
        call_count = 0

        def smart_agent(input: str) -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "password is hunter2"
            return "I cannot share credentials"

        agent = GovernedAgent(smart_agent, strict=True, validate_output=True, max_retries=2)
        result = agent.run("get credential")
        assert result == "I cannot share credentials"
        assert call_count == 2

    def test_retry_exhausted_raises(self):
        """All retries produce violations → raises the last violation."""
        call_count = 0

        def stubborn_agent(input: str) -> str:
            nonlocal call_count
            call_count += 1
            return "password is hunter2"

        agent = GovernedAgent(stubborn_agent, strict=True, validate_output=True, max_retries=3)
        with pytest.raises(ConstitutionalViolationError):
            agent.run("get credential")
        # 1 original + 3 retries = 4 total calls, then stops
        assert call_count == 4

    def test_retry_prompt_contains_violation_info(self):
        """Retry prompt should include which rule was violated."""
        prompts_received: list[str] = []
        call_count = 0

        def recording_agent(input: str) -> str:
            nonlocal call_count
            call_count += 1
            prompts_received.append(input)
            if call_count == 1:
                return "password is hunter2"
            return "I cannot share that"

        agent = GovernedAgent(recording_agent, strict=True, validate_output=True, max_retries=1)
        agent.run("get credential")
        assert len(prompts_received) == 2
        retry_prompt = prompts_received[1]
        # Retry prompt must reference the violation
        assert "violated" in retry_prompt.lower() or "violation" in retry_prompt.lower()

    def test_retry_does_not_apply_to_input_violations(self):
        """Input violations should NOT trigger retries — only output violations do."""

        def safe_agent(input: str) -> str:
            return "safe output"

        rules = Constitution.from_rules(
            [
                Rule(
                    id="NO-CAT",
                    text="No cats allowed",
                    severity=Severity.CRITICAL,
                    keywords=["cat"],
                ),
            ]
        )
        agent = GovernedAgent(
            safe_agent,
            constitution=rules,
            strict=True,
            validate_output=True,
            max_retries=3,
        )
        with pytest.raises(ConstitutionalViolationError):
            agent.run("I love my cat")

    def test_retry_audit_trail(self):
        """Retries should appear in the audit log."""
        call_count = 0

        def retry_agent(input: str) -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "password is hunter2"
            return "safe response"

        agent = GovernedAgent(retry_agent, strict=True, validate_output=True, max_retries=1)
        agent.run("do something")
        # Audit log should have entries for the retry
        entries = agent.audit_log.entries
        actions = [e.action for e in entries]
        assert any("retry" in a.lower() for a in actions)


@pytest.mark.constitutional
class TestGovernedAgentRetryAsync:
    """Async retry tests."""

    async def test_async_retry_succeeds(self):
        call_count = 0

        async def smart_agent(input: str) -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "password is hunter2"
            return "I cannot share credentials"

        agent = GovernedAgent(smart_agent, strict=True, validate_output=True, max_retries=2)
        result = await agent.arun("get credential")
        assert result == "I cannot share credentials"
        assert call_count == 2

    async def test_async_retry_exhausted(self):
        async def stubborn(input: str) -> str:
            return "password is hunter2"

        agent = GovernedAgent(stubborn, strict=True, validate_output=True, max_retries=1)
        with pytest.raises(ConstitutionalViolationError):
            await agent.arun("get credential")

    async def test_async_input_violation_no_retry(self):
        """Async: input violations do NOT trigger retries."""

        async def safe(input: str) -> str:
            return "safe"

        rules = Constitution.from_rules(
            [
                Rule(id="NO-CAT", text="No cats", severity=Severity.CRITICAL, keywords=["cat"]),
            ]
        )
        agent = GovernedAgent(
            safe,
            constitution=rules,
            strict=True,
            validate_output=True,
            max_retries=3,
        )
        with pytest.raises(ConstitutionalViolationError):
            await agent.arun("I love my cat")

    async def test_async_audit_trail(self):
        """Async retries appear in audit log."""
        call_count = 0

        async def retry_agent(input: str) -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "password is hunter2"
            return "safe response"

        agent = GovernedAgent(
            retry_agent,
            strict=True,
            validate_output=True,
            max_retries=1,
        )
        await agent.arun("do something")
        entries = agent.audit_log.entries
        actions = [e.action for e in entries]
        assert any("retry" in a.lower() for a in actions)


@pytest.mark.constitutional
class TestGovernedAgentRetryEdgeCases:
    """Edge cases for retry behavior."""

    def test_negative_max_retries_clamped_to_zero(self):
        """Negative max_retries is treated as 0."""

        def leaky(input: str) -> str:
            return "password is hunter2"

        agent = GovernedAgent(leaky, strict=True, validate_output=True, max_retries=-5)
        assert agent.max_retries == 0
        with pytest.raises(ConstitutionalViolationError):
            agent.run("get credential")

    def test_max_retries_capped_at_limit(self):
        """max_retries above 10 is clamped to 10."""
        agent = GovernedAgent(lambda x: x, max_retries=999)
        assert agent.max_retries == 10

    def test_validate_output_false_skips_retry(self):
        """When validate_output=False, no output validation or retry occurs."""
        call_count = 0

        def leaky(input: str) -> str:
            nonlocal call_count
            call_count += 1
            return "password is hunter2"

        agent = GovernedAgent(
            leaky,
            strict=True,
            validate_output=False,
            max_retries=3,
        )
        result = agent.run("anything")
        assert result == "password is hunter2"
        assert call_count == 1

    def test_retry_audit_metadata_semantics(self):
        """Verify exact audit metadata fields on retry entries."""
        call_count = 0

        def agent_fn(input: str) -> str:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return "password is hunter2"
            return "safe response"

        agent = GovernedAgent(
            agent_fn,
            strict=True,
            validate_output=True,
            max_retries=3,
        )
        agent.run("do it")
        retry_entries = [e for e in agent.audit_log.entries if e.type == "output_retry"]
        assert len(retry_entries) == 2  # 2 retries before success on call 3

        first = retry_entries[0]
        assert first.metadata["attempt"] == 1
        assert first.metadata["retries_after_this"] == 2  # 3 max - 1 used = 2 left
        assert first.metadata["rule_id"] is not None
        assert not first.valid

        second = retry_entries[1]
        assert second.metadata["attempt"] == 2
        assert second.metadata["retries_after_this"] == 1

    def test_retry_prompt_uses_rule_text_not_raw_error(self):
        """Retry prompt should contain rule text from constitution, not raw str(error)."""
        prompts: list[str] = []
        call_count = 0

        def recording(input: str) -> str:
            nonlocal call_count
            call_count += 1
            prompts.append(input)
            if call_count == 1:
                return "password is hunter2"
            return "safe"

        rules = Constitution.from_rules(
            [
                Rule(
                    id="CRED-001",
                    text="No credentials in output",
                    severity=Severity.CRITICAL,
                    keywords=["password"],
                ),
            ]
        )
        agent = GovernedAgent(
            recording,
            constitution=rules,
            strict=True,
            validate_output=True,
            max_retries=1,
        )
        agent.run("get info")
        retry_prompt = prompts[1]
        # Should reference rule ID and rule text (trusted)
        assert "CRED-001" in retry_prompt
        assert "No credentials in output" in retry_prompt
        # Original input should be quoted
        assert '"""get info"""' in retry_prompt

    def test_multiple_runs_produce_unique_audit_ids(self):
        """Two run() calls on same instance produce distinct audit entry IDs."""
        call_count = 0

        def flaky(input: str) -> str:
            nonlocal call_count
            call_count += 1
            # Odd calls violate, even calls pass
            if call_count % 2 == 1:
                return "password is hunter2"
            return "safe"

        agent = GovernedAgent(
            flaky,
            strict=True,
            validate_output=True,
            max_retries=1,
        )
        agent.run("first")
        agent.run("second")

        retry_entries = [e for e in agent.audit_log.entries if e.type == "output_retry"]
        ids = [e.id for e in retry_entries]
        assert len(ids) == len(set(ids)), f"Duplicate audit IDs: {ids}"


@pytest.mark.unit
class TestFailClosedStreamingExceptions:
    """Regression tests: non_strict() must restore strict mode in all exit paths."""

    def _make_engine(self, strict: bool = True) -> GovernanceEngine:
        c = Constitution.from_rules([Rule(id="R1", text="block all", keywords=["block"])])
        return GovernanceEngine(c, strict=strict)

    def test_non_strict_restores_after_normal_exit(self):
        """strict is True after non_strict() exits normally."""
        engine = self._make_engine(strict=True)
        with engine.non_strict():
            assert engine.strict is False
        assert engine.strict is True

    def test_non_strict_restores_after_exception(self):
        """strict is restored even when an exception is raised inside non_strict()."""
        engine = self._make_engine(strict=True)
        try:
            with engine.non_strict():
                assert engine.strict is False
                raise RuntimeError("simulated streaming error")
        except RuntimeError:
            pass
        assert engine.strict is True, "strict must be restored after exception inside non_strict()"

    def test_non_strict_preserves_false_when_engine_starts_non_strict(self):
        """If engine starts with strict=False, non_strict() leaves it False after exit."""
        engine = self._make_engine(strict=False)
        with engine.non_strict():
            assert engine.strict is False
        assert engine.strict is False
