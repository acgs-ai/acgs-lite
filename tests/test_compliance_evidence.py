"""Regression coverage migrated from the retired framework-specific collectors.

Legacy scores and compliance verdicts are intentionally replaced with observable
evidence, confidence, filtering, and JSON-safe bundle contracts. Evidence presence
does not certify compliance. The old-to-current mapping is recorded in
planning/test-skip-remediation.md.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json
from datetime import datetime
from types import SimpleNamespace

import pytest

from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.compliance import evidence
from acgs_lite.compliance.evidence import (
    ACGSLiteImportCollector,
    AuditLogEvidenceCollector,
    ComplianceEvidenceEngine,
    EnvironmentVarCollector,
    EvidenceBundle,
    EvidenceCollector,
    EvidenceItem,
    EvidenceRecord,
    FileSystemCollector,
    collect_evidence,
)
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine import GovernanceEngine


def _make_item(framework="gdpr", ref="GDPR Art.30(1)", confidence=0.75):
    return EvidenceItem(framework, (ref,), "test:record", "Observed test evidence", confidence)


def _make_bundle(*items):
    return EvidenceBundle("test-system", "2026-01-01T00:00:00+00:00", tuple(items))


def _make_log(count=1, entry_type="validation", valid=True):
    log = AuditLog()
    for index in range(count):
        log.record(AuditEntry(id=str(index), type=entry_type, valid=valid, action="test"))
    return log


@pytest.fixture
def clean_environment(monkeypatch):
    for name, *_ in evidence._ENV_EVIDENCE:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def audit_only_imports(monkeypatch):
    monkeypatch.setattr(
        ACGSLiteImportCollector,
        "_is_importable",
        staticmethod(lambda path: path == "acgs_lite.audit.AuditLog"),
    )
    return ACGSLiteImportCollector()


class TestEvidenceRecord:
    """The seven legacy record cases retain coverage of the supported alias."""

    def test_default_creation(self):
        rec = EvidenceRecord()
        assert rec.record_id
        assert rec.framework == ""
        assert rec.status == "not_assessed"
        assert rec.evidence_type == "attestation"
        assert rec.data == {}

    def test_creation_with_fields(self):
        rec = EvidenceRecord(
            record_id="r1",
            framework="SOC2",
            control_id="CC6.1",
            evidence_type="audit_trail",
            data={"key": "value"},
            status="partial",
        )
        assert (rec.record_id, rec.framework, rec.control_id) == ("r1", "SOC2", "CC6.1")
        assert (rec.evidence_type, rec.data, rec.status) == (
            "audit_trail",
            {"key": "value"},
            "partial",
        )

    def test_serialization_does_not_alias_mutable_record(self):
        # EvidenceRecord is mutable now; callers must receive an independent dict.
        rec = EvidenceRecord(data={"nested": [1]})
        exported = rec.to_dict()
        exported["data"]["nested"].append(2)
        assert rec.data == {"nested": [1]}

    def test_to_dict(self):
        rec = EvidenceRecord(
            record_id="r1",
            framework="ISO27001",
            control_id="A.8.2",
            data={"x": 1},
            status="partial",
        )
        data = rec.to_dict()
        assert data["record_id"] == "r1"
        assert data["framework"] == "ISO27001"
        assert data["control_id"] == "A.8.2"
        assert data["data"] == {"x": 1}
        assert data["status"] == "partial"
        assert "collected_at" in data

    def test_to_dict_roundtrip(self):
        rec = EvidenceRecord(framework="GDPR", data={"nested": {"a": [1, 2]}})
        assert json.loads(json.dumps(rec.to_dict()))["data"] == {"nested": {"a": [1, 2]}}

    def test_collected_at_is_iso_string(self):
        assert (
            datetime.fromisoformat(EvidenceRecord().collected_at).utcoffset().total_seconds() == 0
        )

    def test_unique_record_ids(self):
        assert len({EvidenceRecord().record_id for _ in range(50)}) == 50


class TestImportEvidence:
    """Replaces eight SOC2 collector cases with component-to-control evidence."""

    def test_soc2_framework_id(self, audit_only_imports):
        items = audit_only_imports.collect({})
        assert any(item.framework_id == "soc2_ai" for item in items)

    def test_grouped_framework_records(self, audit_only_imports):
        items = audit_only_imports.collect({})
        assert len(items) == 14
        assert len({item.framework_id for item in items}) == len(items)

    def test_component_source(self, audit_only_imports):
        assert {item.source for item in audit_only_imports.collect({})} == {
            "import:acgs_lite.audit.AuditLog"
        }

    def test_soc2_monitoring_reference(self, audit_only_imports):
        items = _make_bundle(*audit_only_imports.collect({})).for_framework("soc2_ai")
        assert len(items) == 1
        assert items[0].article_refs == ("SOC2 CC7.2",)

    def test_unavailable_components_have_no_evidence(self, monkeypatch):
        monkeypatch.setattr(
            ACGSLiteImportCollector, "_is_importable", staticmethod(lambda _: False)
        )
        assert ACGSLiteImportCollector().collect({}) == []

    def test_importability_does_not_claim_runtime_validation(self, audit_only_imports):
        items = audit_only_imports.collect({})
        assert all(not item.source.startswith("audit:") for item in items)
        assert all(not hasattr(item, "status") for item in items)

    def test_constitution_configuration_references(self, monkeypatch):
        monkeypatch.setattr(
            ACGSLiteImportCollector,
            "_is_importable",
            staticmethod(lambda path: path == "acgs_lite.constitution.Constitution"),
        )
        items = ACGSLiteImportCollector().collect({})
        iso = _make_bundle(*items).for_framework("iso_42001")
        assert len(iso) == 1
        assert iso[0].article_refs == ("ISO 42001 §5.2",)

    def test_missing_import_attribute_and_module(self):
        collector = ACGSLiteImportCollector()
        assert collector._is_importable("acgs_lite.audit.AuditLog")
        assert not collector._is_importable("acgs_lite.audit.NoSuchEvidenceClass")
        assert not collector._is_importable("acgs_lite.no_such_module.Collector")


class TestFileEvidence:
    """Replaces nine obsolete ISO27001 cases with actual supported artefacts."""

    @pytest.mark.parametrize(
        ("filename", "framework", "ref"),
        [
            ("risk-register.md", "iso_42001", "ISO 42001 §6.1.2"),
            ("data-governance-policy.md", "iso_42001", "ISO 42001 §8.3"),
            ("events.audit.jsonl", "eu_ai_act", "EU-AIA Art.12(1)"),
            ("privacy_notice.md", "gdpr", "GDPR Art.13(1)"),
            ("bias-assessment.md", "nyc_ll144", "NYC LL144 §20-871(b)"),
        ],
    )
    def test_artefact_reference(self, tmp_path, filename, framework, ref):
        (tmp_path / filename).write_text("test fixture", encoding="utf-8")
        items = _make_bundle(*FileSystemCollector(tmp_path).collect({})).for_framework(framework)
        assert len(items) == 1
        assert items[0].article_refs == (ref,)
        assert items[0].source == f"file:{filename}"

    def test_empty_root_has_no_evidence(self, tmp_path):
        assert FileSystemCollector(tmp_path).collect({}) == []

    def test_nested_files_are_not_scanned(self, tmp_path):
        nested = tmp_path / "untrusted"
        nested.mkdir()
        (nested / "risk-register.md").write_text("fixture")
        assert FileSystemCollector(tmp_path).collect({}) == []

    def test_prior_assessment_is_wildcard_evidence(self, tmp_path):
        (tmp_path / ".acgs_assessment.json").write_text("{}")
        bundle = _make_bundle(*FileSystemCollector(tmp_path).collect({}))
        assert bundle.summary() == {"*": 1}
        assert bundle.for_framework("gdpr") == bundle.for_framework("soc2_ai")

    def test_removed_artefact_is_not_cached(self, tmp_path):
        artifact = tmp_path / "risk-register.md"
        artifact.write_text("fixture")
        collector = FileSystemCollector(tmp_path)
        assert collector.collect({})
        artifact.unlink()
        assert collector.collect({}) == []


@pytest.mark.usefixtures("clean_environment")
class TestEnvironmentEvidence:
    """Replaces nine GDPR/control configuration cases without invented scores."""

    @pytest.mark.parametrize(
        ("name", "value", "ref"),
        [
            ("GDPR_DATA_CONTROLLER", "Example", "GDPR Art.13(1)(a)"),
            ("GDPR_DPO_CONTACT", "dpo@example.test", "GDPR Art.37(1)"),
            ("ACGS_HUMAN_OVERSIGHT", "review-required", "GDPR Art.22(3)"),
            ("ACGS_AUDIT_ENABLED", "true", "GDPR Art.30(1)"),
        ],
    )
    def test_declared_configuration(self, monkeypatch, name, value, ref):
        monkeypatch.setenv(name, value)
        bundle = _make_bundle(*EnvironmentVarCollector().collect({}))
        items = bundle.for_ref(ref)
        assert len(items) == 1
        assert items[0].framework_id == "gdpr"
        assert items[0].source == f"env:{name}"

    def test_absent_configuration_is_not_evidence(self):
        assert EnvironmentVarCollector().collect({}) == []

    def test_empty_configuration_is_not_evidence(self, monkeypatch):
        monkeypatch.setenv("GDPR_DATA_CONTROLLER", "")
        assert EnvironmentVarCollector().collect({}) == []

    def test_false_audit_flag_is_not_evidence(self, monkeypatch):
        monkeypatch.setenv("ACGS_AUDIT_ENABLED", "false")
        assert EnvironmentVarCollector().collect({}) == []

    def test_true_flag_is_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("ACGS_AUDIT_ENABLED", "TRUE")
        assert _make_bundle(*EnvironmentVarCollector().collect({})).for_ref("GDPR Art.30(1)")

    def test_environment_changes_are_not_cached(self, monkeypatch):
        collector = EnvironmentVarCollector()
        monkeypatch.setenv("GDPR_DATA_CONTROLLER", "Example")
        assert collector.collect({})
        monkeypatch.delenv("GDPR_DATA_CONTROLLER")
        assert collector.collect({}) == []


class TestCollectorProtocol:
    @pytest.mark.parametrize(
        "collector",
        [
            ACGSLiteImportCollector(),
            EnvironmentVarCollector(),
            AuditLogEvidenceCollector(AuditLog()),
        ],
    )
    def test_builtin_protocol(self, collector):
        assert isinstance(collector, EvidenceCollector)

    def test_custom_collector_protocol_and_dispatch(self):
        class CustomCollector:
            def collect(self, system_description):
                return [_make_item(ref=system_description["ref"])]

        custom = CustomCollector()
        assert isinstance(custom, EvidenceCollector)
        assert not isinstance(object(), EvidenceCollector)
        result = ComplianceEvidenceEngine([custom]).collect({"ref": "custom-reference"})
        assert len(result.for_ref("custom-reference")) == 1


class TestEvidenceEngine:
    def test_default_collectors(self):
        assert [type(c) for c in ComplianceEvidenceEngine().collectors] == [
            ACGSLiteImportCollector,
            FileSystemCollector,
            EnvironmentVarCollector,
        ]

    def test_aggregates_all_collectors_in_order(self):
        first, second = _make_item(), _make_item("soc2_ai")
        engine = ComplianceEvidenceEngine(
            [
                SimpleNamespace(collect=lambda _: [first]),
                SimpleNamespace(collect=lambda _: [second]),
            ]
        )
        assert engine.collect({}).items == (first, second)

    @pytest.mark.parametrize("framework", ["gdpr", "soc2_ai", "iso_42001"])
    def test_framework_filter(self, framework):
        target = _make_item(framework)
        other = _make_item("other")
        bundle = ComplianceEvidenceEngine(
            [SimpleNamespace(collect=lambda _: [target, other])]
        ).collect({})
        assert bundle.for_framework(framework) == [target]

    def test_unknown_framework_is_empty(self):
        assert _make_bundle(_make_item()).for_framework("unsupported") == []

    def test_explicit_custom_collectors_only(self):
        item = _make_item()
        result = ComplianceEvidenceEngine([SimpleNamespace(collect=lambda _: [item])]).collect({})
        assert result.items == (item,)

    def test_explicit_empty_collectors_disable_defaults(self):
        engine = ComplianceEvidenceEngine([])
        assert engine.collectors == []
        assert engine.collect({}).items == ()

    def test_collector_receives_description(self):
        desc = {"system_id": "s", "domain": "healthcare"}
        calls = []

        def collect(description):
            calls.append(description)
            return []

        bundle = ComplianceEvidenceEngine([SimpleNamespace(collect=collect)]).collect(desc)
        assert calls == [desc]
        assert calls[0] is desc
        assert bundle.system_id == "s"


class TestEvidenceConfidence:
    """Former score cases now test confidence, which is not a compliance score."""

    def test_import_confidence_is_bounded(self, audit_only_imports):
        assert all(0 < i.confidence <= 1 for i in audit_only_imports.collect({}))

    def test_audit_confidence_is_bounded(self):
        items = AuditLogEvidenceCollector(_make_log()).collect({})
        assert items
        assert all(0 < i.confidence <= 1 for i in items)

    def test_high_volume_confidence_saturates(self):
        items = AuditLogEvidenceCollector(_make_log(200)).collect({})
        validation = [i for i in items if i.source.startswith("audit:validation")]
        assert max(i.confidence for i in validation) == 0.9

    def test_no_records_means_no_runtime_evidence(self):
        assert AuditLogEvidenceCollector(AuditLog()).collect({}) == []

    def test_more_observations_increase_confidence(self):
        low = AuditLogEvidenceCollector(_make_log(1)).collect({})
        high = AuditLogEvidenceCollector(_make_log(20)).collect({})

        def values(items):
            return {
                i.framework_id: i.confidence
                for i in items
                if i.source.startswith("audit:validation")
            }

        assert all(values(high)[key] > value for key, value in values(low).items())

    def test_minimum_entry_threshold(self):
        collector = AuditLogEvidenceCollector(_make_log(1), min_entries=2)
        assert collector.collect({}) == []

    def test_bundle_does_not_invent_compliance_scores(self):
        data = _make_bundle(_make_item(confidence=0.5)).to_dict()
        assert data["items"][0]["confidence"] == 0.5
        assert not {"overall_score", "compliance_score", "status"} & data.keys()
        assert not {"status", "compliance_score"} & data["items"][0].keys()


class TestBundleReport:
    def test_summary_counts_frameworks(self):
        bundle = _make_bundle(_make_item(), _make_item(), _make_item("soc2_ai"))
        assert bundle.summary() == {"gdpr": 2, "soc2_ai": 1}

    def test_serialized_summary_fields(self):
        data = _make_bundle(_make_item()).to_dict()
        assert set(data) == {"system_id", "collected_at", "item_count", "items"}
        assert data["system_id"] == "test-system"

    def test_confidence_is_preserved(self):
        assert _make_bundle(_make_item(confidence=0.25)).to_dict()["items"][0]["confidence"] == 0.25

    def test_wildcard_is_included_without_double_counting(self):
        item = _make_item("*")
        bundle = _make_bundle(item)
        assert bundle.for_framework("gdpr") == [item]
        assert bundle.for_framework("*") == [item]
        assert bundle.summary() == {"*": 1}

    def test_item_count_matches_records(self):
        assert _make_bundle(_make_item(), _make_item()).to_dict()["item_count"] == 2

    def test_exact_article_reference_filter(self):
        item = _make_item(ref="GDPR Art.30(1)")
        bundle = _make_bundle(item, _make_item(ref="GDPR Art.30(2)"))
        assert bundle.for_ref("GDPR Art.30(1)") == [item]
        assert bundle.for_ref("GDPR Art.30") == []

    def test_empty_report(self):
        bundle = _make_bundle()
        assert bundle.summary() == {}
        assert bundle.to_dict()["item_count"] == 0
        assert bundle.to_dict()["items"] == []


class TestJSONExport:
    def test_export_returns_json_string(self):
        assert isinstance(json.dumps(_make_bundle(_make_item()).to_dict()), str)

    def test_roundtrip_preserves_all_item_fields(self):
        item = _make_item()
        data = json.loads(json.dumps(_make_bundle(item).to_dict()))
        assert data["items"] == [
            {
                "framework_id": "gdpr",
                "article_refs": ["GDPR Art.30(1)"],
                "source": "test:record",
                "description": "Observed test evidence",
                "confidence": 0.75,
            }
        ]

    def test_export_to_file(self, tmp_path):
        data = _make_bundle(_make_item()).to_dict()
        output = tmp_path / "evidence.json"
        output.write_text(json.dumps(data))
        assert json.loads(output.read_text()) == data

    def test_export_nested_path_is_caller_owned(self, tmp_path):
        output = tmp_path / "reports" / "evidence.json"
        output.parent.mkdir()
        output.write_text(json.dumps(_make_bundle().to_dict()))
        assert json.loads(output.read_text())["items"] == []

    def test_export_does_not_alias_article_refs(self):
        item = _make_item()
        data = _make_bundle(item).to_dict()
        data["items"][0]["article_refs"].append("mutated")
        assert item.article_refs == ("GDPR Art.30(1)",)


class TestRuntimeEvidence:
    def test_empty_audit_log_has_no_chain_claim(self):
        assert AuditLogEvidenceCollector(AuditLog()).collect({}) == []

    def test_missing_log_interface_has_no_evidence(self):
        assert AuditLogEvidenceCollector(object()).collect({}) == []

    def test_engine_validations_produce_runtime_evidence(self):
        log = AuditLog()
        engine = GovernanceEngine(Constitution(name="empty", rules=[]), audit_log=log, strict=False)
        engine.validate("ordinary action")
        bundle = _make_bundle(*AuditLogEvidenceCollector(log).collect({}))
        assert bundle.for_ref("EU-AIA Art.9(1)")
        assert bundle.for_ref("EU-AIA Art.12(2)")
        assert any(i.source == "audit:validation:1/1" for i in bundle.items)

    def test_single_rule_denial_is_observed_without_compliance_verdict(self):
        log = AuditLog()
        constitution = Constitution.from_rules(
            [Rule(id="R1", text="Block harm", keywords=["harm"], severity=Severity.CRITICAL)]
        )
        engine = GovernanceEngine(constitution, audit_log=log, strict=False)
        assert not engine.validate("harm").valid
        bundle = _make_bundle(*AuditLogEvidenceCollector(log).collect({}))
        assert bundle.for_ref("EU-AIA Art.9(1)")
        assert all(not hasattr(i, "status") for i in bundle.items)

    def test_invalid_chain_does_not_produce_integrity_evidence(self):
        log = SimpleNamespace(
            entries=[SimpleNamespace(type="validation")], verify_chain=lambda: False
        )
        items = AuditLogEvidenceCollector(log).collect({})
        assert items
        assert not any(i.source.startswith("audit:chain_valid") for i in items)

    def test_repeated_collection_is_consistent(self):
        collector = AuditLogEvidenceCollector(_make_log())
        assert collector.collect({}) == collector.collect({})

    def test_convenience_entry_point_wires_optional_audit(
        self, tmp_path, monkeypatch, clean_environment
    ):
        monkeypatch.setattr(
            ACGSLiteImportCollector, "_is_importable", staticmethod(lambda _: False)
        )
        assert collect_evidence(search_root=tmp_path).items == ()
        bundle = collect_evidence(
            {"system_id": "runtime"},
            search_root=tmp_path,
            audit_log=_make_log(entry_type="override"),
        )
        assert bundle.system_id == "runtime"
        assert bundle.for_ref("GDPR Art.22(3)")
        assert any(i.source.startswith("audit:chain_valid:") for i in bundle.items)
