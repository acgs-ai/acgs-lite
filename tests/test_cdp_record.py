"""Tests for Constitutional Decision Provenance (CDP) — Phase 1.

Covers:
- CDPRecordV1 schema validation and hash determinism
- Chain linking across 10+ sequential records
- input_hash privacy (no raw input stored)
- Opt-in via ACGS_CDP_ENABLED env var
- InMemoryCDPBackend save/retrieve/list/chain_verify
- assemble_cdp_record() — pure function determinism
- API endpoints: /cdp/records, /cdp/records/{id}, /cdp/chain
"""

from __future__ import annotations

import hashlib

import pytest

from acgs_lite.cdp.assembler import assemble_cdp_record
from acgs_lite.cdp.record import (
    CDPRecordV1,
    ComplianceEvidenceRef,
    InterventionOutcome,
    MACIStep,
)
from acgs_lite.cdp.store import InMemoryCDPBackend

_CONST_HASH = "608508a9bd224290"
_WRONG_HASH = "deadbeef00000000"


# ---------------------------------------------------------------------------
# CDPRecordV1 — schema and hash
# ---------------------------------------------------------------------------


class TestCDPRecordV1Schema:
    def test_minimal_record_finalizes(self) -> None:
        record = CDPRecordV1(cdp_id="test-1", tenant_id="default")
        record.finalize()
        assert len(record.cdp_hash) == 16

    def test_constitutional_hash_default_is_canonical(self) -> None:
        record = CDPRecordV1(cdp_id="test-2")
        assert record.constitutional_hash == _CONST_HASH

    def test_verify_passes_after_finalize(self) -> None:
        record = CDPRecordV1(cdp_id="test-3", verdict="deny")
        record.finalize()
        assert record.verify() is True

    def test_verify_fails_after_mutation(self) -> None:
        record = CDPRecordV1(cdp_id="test-4", verdict="allow")
        record.finalize()
        record.verdict = "deny"  # tamper
        assert record.verify() is False

    def test_to_dict_contains_all_fields(self) -> None:
        record = CDPRecordV1(
            cdp_id="test-5",
            verdict="allow",
            compliance_frameworks=["eu_ai_act"],
        )
        record.finalize()
        d = record.to_dict()
        assert d["cdp_id"] == "test-5"
        assert d["verdict"] == "allow"
        assert d["compliance_frameworks"] == ["eu_ai_act"]
        assert "cdp_hash" in d
        assert "input_hash" in d
        assert "created_at" in d

    def test_maci_step_serializes(self) -> None:
        step = MACIStep(
            agent_id="agent-1",
            role="validator",
            action="validate_output",
            outcome="allow",
        )
        d = step.to_dict()
        assert d["role"] == "validator"
        assert d["outcome"] == "allow"

    def test_compliance_evidence_ref_serializes(self) -> None:
        ref = ComplianceEvidenceRef(
            framework_id="eu_ai_act",
            article_ref="Art.14",
            evidence="HITL requirement met",
            compliant=True,
        )
        d = ref.to_dict()
        assert d["framework_id"] == "eu_ai_act"
        assert d["compliant"] is True

    def test_intervention_outcome_serializes(self) -> None:
        iv = InterventionOutcome(action="block", triggered=True, reason="PHI detected")
        d = iv.to_dict()
        assert d["action"] == "block"
        assert d["triggered"] is True


# ---------------------------------------------------------------------------
# Hash determinism
# ---------------------------------------------------------------------------


_FIXED_TS = "2026-04-10T00:00:00+00:00"


class TestHashDeterminism:
    def _make_record(self, cdp_id: str) -> CDPRecordV1:
        record = CDPRecordV1(
            cdp_id=cdp_id,
            tenant_id="acme",
            input_hash=hashlib.sha256(b"test input").hexdigest(),
            verdict="allow",
            matched_rules=["R-001", "R-002"],
            created_at=_FIXED_TS,
        )
        record.finalize()
        return record

    def test_same_inputs_same_hash(self) -> None:
        r1 = self._make_record("det-1")
        r2 = self._make_record("det-1")
        assert r1.cdp_hash == r2.cdp_hash

    def test_different_id_different_hash(self) -> None:
        r1 = self._make_record("det-2")
        r2 = self._make_record("det-3")
        assert r1.cdp_hash != r2.cdp_hash

    def test_different_verdict_different_hash(self) -> None:
        r1 = CDPRecordV1(cdp_id="det-4", verdict="allow", created_at=_FIXED_TS)
        r1.finalize()
        r2 = CDPRecordV1(cdp_id="det-4", verdict="deny", created_at=_FIXED_TS)
        r2.finalize()
        assert r1.cdp_hash != r2.cdp_hash


# ---------------------------------------------------------------------------
# Chain linking
# ---------------------------------------------------------------------------


class TestChainLinking:
    def test_chain_of_12_records(self) -> None:
        backend = InMemoryCDPBackend()
        prev_hash = "genesis"

        for i in range(12):
            record = CDPRecordV1(
                cdp_id=f"chain-{i}",
                prev_cdp_hash=prev_hash,
                verdict="allow",
            )
            record.finalize()
            backend.save(record)
            prev_hash = record.cdp_hash

        hashes = backend.chain_hashes()
        assert len(hashes) == 12

    def test_first_record_links_to_genesis(self) -> None:
        record = CDPRecordV1(cdp_id="gen-1")
        record.finalize()
        assert record.prev_cdp_hash == "genesis"

    def test_sequential_records_link_correctly(self) -> None:
        r1 = CDPRecordV1(cdp_id="seq-1", prev_cdp_hash="genesis")
        r1.finalize()
        r2 = CDPRecordV1(cdp_id="seq-2", prev_cdp_hash=r1.cdp_hash)
        r2.finalize()
        assert r2.prev_cdp_hash == r1.cdp_hash

    def test_chain_verification_passes_valid_chain(self) -> None:
        backend = InMemoryCDPBackend()
        prev_hash = "genesis"

        for i in range(5):
            record = CDPRecordV1(cdp_id=f"valid-{i}", prev_cdp_hash=prev_hash)
            record.finalize()
            backend.save(record)
            prev_hash = record.cdp_hash

        is_valid, broken = backend.verify_chain()
        assert is_valid is True
        assert broken == []

    def test_chain_verification_detects_tamper(self) -> None:
        backend = InMemoryCDPBackend()
        record = CDPRecordV1(cdp_id="tamper-1", verdict="allow")
        record.finalize()
        backend.save(record)

        # Tamper after saving
        record.verdict = "deny"
        is_valid, broken = backend.verify_chain()
        assert is_valid is False
        assert "tamper-1" in broken


# ---------------------------------------------------------------------------
# Input hash privacy (AD-2)
# ---------------------------------------------------------------------------


class TestInputHashPrivacy:
    def test_raw_input_not_in_record_dict(self) -> None:
        raw = "Patient SSN: 123-45-6789"
        record = assemble_cdp_record(
            raw_input=raw,
            agent_id="healthcare-agent",
            constitutional_hash=_CONST_HASH,
        )
        d = record.to_dict()
        assert raw not in str(d)

    def test_input_hash_is_sha256(self) -> None:
        raw = "hello world"
        expected_hash = hashlib.sha256(raw.encode()).hexdigest()
        record = assemble_cdp_record(
            raw_input=raw,
            agent_id="test-agent",
            constitutional_hash=_CONST_HASH,
        )
        assert record.input_hash == expected_hash

    def test_empty_input_hashes_consistently(self) -> None:
        record = assemble_cdp_record(
            raw_input="",
            agent_id="agent",
            constitutional_hash=_CONST_HASH,
        )
        assert record.input_hash == hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# assemble_cdp_record() — pure function
# ---------------------------------------------------------------------------


class TestAssembler:
    def test_rejects_wrong_constitutional_hash(self) -> None:
        with pytest.raises(ValueError, match="Constitutional hash mismatch"):
            assemble_cdp_record(
                raw_input="test",
                agent_id="a",
                constitutional_hash=_WRONG_HASH,
            )

    def test_accepts_canonical_hash(self) -> None:
        record = assemble_cdp_record(
            raw_input="test",
            agent_id="a",
            constitutional_hash=_CONST_HASH,
        )
        assert record.cdp_hash != ""
        assert record.constitutional_hash == _CONST_HASH

    def test_deterministic_output(self) -> None:
        kwargs: dict = {
            "raw_input": "deterministic test",
            "agent_id": "agent-det",
            "constitutional_hash": _CONST_HASH,
            "verdict": "allow",
            "policy_id": "policy-001",
            "matched_rules": ["R-A", "R-B"],
            "tenant_id": "acme",
            "prev_cdp_hash": "genesis",
            "cdp_id": "fixed-id-001",
            "created_at": _FIXED_TS,
        }
        r1 = assemble_cdp_record(**kwargs)
        r2 = assemble_cdp_record(**kwargs)
        assert r1.cdp_hash == r2.cdp_hash

    def test_auto_generates_cdp_id(self) -> None:
        record = assemble_cdp_record(
            raw_input="test",
            agent_id="a",
            constitutional_hash=_CONST_HASH,
        )
        assert record.cdp_id.startswith("cdp-")

    def test_maci_chain_from_explicit_steps(self) -> None:
        step = MACIStep(
            agent_id="validator-1",
            role="validator",
            action="validate_input",
            outcome="allow",
        )
        record = assemble_cdp_record(
            raw_input="test",
            agent_id="proposer-1",
            constitutional_hash=_CONST_HASH,
            maci_chain=[step],
        )
        assert len(record.maci_chain) == 1
        assert record.maci_chain[0].role == "validator"

    def test_default_maci_chain_has_proposer(self) -> None:
        record = assemble_cdp_record(
            raw_input="test",
            agent_id="my-agent",
            constitutional_hash=_CONST_HASH,
            action="process_claim",
        )
        assert len(record.maci_chain) >= 1
        assert record.maci_chain[0].agent_id == "my-agent"
        assert record.maci_chain[0].role == "proposer"

    def test_subject_id_defaults_to_agent_id(self) -> None:
        record = assemble_cdp_record(
            raw_input="x",
            agent_id="my-agent",
            constitutional_hash=_CONST_HASH,
        )
        assert record.subject_id == "my-agent"

    def test_compliance_evidence_attached(self) -> None:
        ev = ComplianceEvidenceRef(
            framework_id="hipaa",
            article_ref="§164.502",
            evidence="PHI scan passed",
            compliant=True,
        )
        record = assemble_cdp_record(
            raw_input="x",
            agent_id="a",
            constitutional_hash=_CONST_HASH,
            compliance_evidence=[ev],
        )
        assert len(record.compliance_evidence) == 1
        assert record.compliance_evidence[0].framework_id == "hipaa"

    def test_intervention_attached(self) -> None:
        iv = InterventionOutcome(action="escalate", triggered=True)
        record = assemble_cdp_record(
            raw_input="x",
            agent_id="a",
            constitutional_hash=_CONST_HASH,
            intervention=iv,
        )
        assert record.intervention is not None
        assert record.intervention.action == "escalate"


# ---------------------------------------------------------------------------
# InMemoryCDPBackend
# ---------------------------------------------------------------------------


class TestInMemoryCDPBackend:
    def _make_record(self, cdp_id: str, tenant_id: str = "default") -> CDPRecordV1:
        r = CDPRecordV1(cdp_id=cdp_id, tenant_id=tenant_id)
        r.finalize()
        return r

    def test_save_and_get(self) -> None:
        backend = InMemoryCDPBackend()
        r = self._make_record("get-1")
        backend.save(r)
        retrieved = backend.get("get-1")
        assert retrieved is not None
        assert retrieved.cdp_id == "get-1"

    def test_get_missing_returns_none(self) -> None:
        backend = InMemoryCDPBackend()
        assert backend.get("nonexistent") is None

    def test_save_calls_tracked(self) -> None:
        backend = InMemoryCDPBackend()
        r = self._make_record("track-1")
        backend.save(r)
        assert len(backend.save_calls) == 1
        assert backend.save_calls[0].cdp_id == "track-1"

    def test_list_returns_newest_first(self) -> None:
        backend = InMemoryCDPBackend()
        for i in range(5):
            backend.save(self._make_record(f"list-{i}"))
        records = backend.list()
        ids = [r.cdp_id for r in records]
        assert ids[0] == "list-4"
        assert ids[-1] == "list-0"

    def test_list_filters_by_tenant(self) -> None:
        backend = InMemoryCDPBackend()
        backend.save(self._make_record("t-acme-1", tenant_id="acme"))
        backend.save(self._make_record("t-beta-1", tenant_id="beta"))
        acme_records = backend.list(tenant_id="acme")
        assert len(acme_records) == 1
        assert acme_records[0].cdp_id == "t-acme-1"

    def test_list_pagination(self) -> None:
        backend = InMemoryCDPBackend()
        for i in range(10):
            backend.save(self._make_record(f"page-{i}"))
        page1 = backend.list(limit=3, offset=0)
        page2 = backend.list(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert {r.cdp_id for r in page1}.isdisjoint({r.cdp_id for r in page2})

    def test_count_total(self) -> None:
        backend = InMemoryCDPBackend()
        for i in range(7):
            backend.save(self._make_record(f"cnt-{i}"))
        assert backend.count() == 7

    def test_count_by_tenant(self) -> None:
        backend = InMemoryCDPBackend()
        backend.save(self._make_record("tc-1", tenant_id="x"))
        backend.save(self._make_record("tc-2", tenant_id="x"))
        backend.save(self._make_record("tc-3", tenant_id="y"))
        assert backend.count(tenant_id="x") == 2
        assert backend.count(tenant_id="y") == 1

    def test_max_records_evicts_oldest(self) -> None:
        backend = InMemoryCDPBackend(max_records=3)
        for i in range(5):
            backend.save(self._make_record(f"evict-{i}"))
        # Oldest 2 should be evicted
        assert backend.count() == 3
        assert backend.get("evict-0") is None
        assert backend.get("evict-4") is not None


# ---------------------------------------------------------------------------
# Opt-in behavior (ACGS_CDP_ENABLED env var)
# ---------------------------------------------------------------------------


class TestOptIn:
    def test_governed_agent_emits_cdp_when_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACGS_CDP_ENABLED", "true")

        from acgs_lite.governed import GovernedAgent
        from acgs_lite.maci import MACIRole

        cdp_backend = InMemoryCDPBackend()
        agent = GovernedAgent(
            agent=lambda x, **kw: f"response: {x}",
            agent_id="opt-in-agent",
            cdp_backend=cdp_backend,
            maci_role=MACIRole.EXECUTOR,
        )
        agent.run("test input", governance_action="execute")

        assert cdp_backend.count() == 1
        assert cdp_backend.save_calls[0].cdp_id.startswith("cdp-")

    def test_governed_agent_no_cdp_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When ACGS_CDP_ENABLED is not set and no explicit backend is provided, no CDP."""
        monkeypatch.delenv("ACGS_CDP_ENABLED", raising=False)

        from acgs_lite.governed import GovernedAgent
        from acgs_lite.maci import MACIRole
        from acgs_lite.server import _cdp_backend as server_backend

        initial_count = server_backend.count()
        agent = GovernedAgent(
            agent=lambda x, **kw: f"response: {x}",
            agent_id="opt-out-agent",
            # No cdp_backend passed → only emits if ACGS_CDP_ENABLED is set
            maci_role=MACIRole.EXECUTOR,
        )
        agent.run("test input", governance_action="execute")

        # Server backend should not have grown (no env var, no explicit backend)
        assert server_backend.count() == initial_count


# ---------------------------------------------------------------------------
# API endpoints (uses FastAPI TestClient)
# ---------------------------------------------------------------------------


class TestCDPAPI:
    @pytest.fixture()
    def client_with_records(self):
        from fastapi.testclient import TestClient

        import acgs_lite.server as server_mod
        from acgs_lite.server import create_governance_app

        # Replace the module-level backend with a fresh one for test isolation
        fresh_backend = InMemoryCDPBackend()
        server_mod._cdp_backend = fresh_backend

        for i in range(3):
            r = CDPRecordV1(cdp_id=f"api-{i}", tenant_id="default")
            r.finalize()
            fresh_backend.save(r)

        app = create_governance_app(require_auth=False)
        yield TestClient(app)

        # Restore
        from acgs_lite.cdp.store import InMemoryCDPBackend as _IMB

        server_mod._cdp_backend = _IMB()

    def test_list_records_endpoint(self, client_with_records) -> None:
        resp = client_with_records.get("/cdp/records")
        assert resp.status_code == 200
        data = resp.json()
        assert "records" in data
        assert "total" in data
        assert isinstance(data["records"], list)

    def test_get_record_endpoint(self, client_with_records) -> None:
        resp = client_with_records.get("/cdp/records/api-0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cdp_id"] == "api-0"

    def test_get_record_not_found(self, client_with_records) -> None:
        resp = client_with_records.get("/cdp/records/nonexistent")
        assert resp.status_code == 404

    def test_chain_endpoint(self, client_with_records) -> None:
        resp = client_with_records.get("/cdp/chain")
        assert resp.status_code == 200
        data = resp.json()
        assert "valid" in data
        assert "record_count" in data
