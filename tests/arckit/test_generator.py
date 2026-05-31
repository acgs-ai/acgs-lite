from __future__ import annotations

import re

import pytest

from acgs_lite import Constitution, GovernedAgent, MACIRole
from acgs_lite.arckit.generator import _dedupe_rules, build_constitution
from acgs_lite.arckit.parser import parse_project
from acgs_lite.errors import ConstitutionalViolationError

from .helpers import fixtures_dir


@pytest.fixture()
def manifest():
    return build_constitution(parse_project(fixtures_dir()))


def test_gen_001_build_constitution_loadable_by_acgs(manifest) -> None:
    constitution = Constitution.from_dict(manifest.as_dict())
    assert constitution.rules


def test_gen_002_name_defaults_from_project_id(manifest) -> None:
    assert manifest.name == "arc-001-constitution"


def test_gen_003_version_field_present_and_semver_like(manifest) -> None:
    assert re.fullmatch(r"\d+\.\d+(?:\.\d+)?", str(manifest.version))


def test_gen_004_rule_ids_are_unique(manifest) -> None:
    ids = [rule["id"] for rule in manifest.rules]
    assert len(ids) == len(set(ids))


def test_gen_004b_dedupe_skips_existing_candidate_ids() -> None:
    rules = [
        {"id": "RISK-001", "text": "a", "severity": "high", "category": "risk"},
        {"id": "RISK-002", "text": "b", "severity": "high", "category": "risk"},
        {"id": "RISK-001", "text": "c", "severity": "high", "category": "risk"},
    ]
    ids = [rule["id"] for rule in _dedupe_rules(rules)]
    assert ids == ["RISK-001", "RISK-002", "RISK-003"]


def test_gen_004c_dedupe_handles_non_numeric_suffixes() -> None:
    rules = [{"id": "DATA-abc", "text": "t", "severity": "critical", "category": "data-protection"}]
    assert [rule["id"] for rule in _dedupe_rules(rules)] == ["DATA-abc"]


def test_gen_005_prin_rules_have_principles_category(manifest) -> None:
    assert all(
        rule["category"] == "principles"
        for rule in manifest.rules
        if rule["id"].startswith("PRIN-")
    )


def test_gen_006_risk_rules_have_risk_category(manifest) -> None:
    assert all(
        rule["category"] == "risk" for rule in manifest.rules if rule["id"].startswith("RISK-")
    )


def test_gen_007_data_rules_have_data_protection_category(manifest) -> None:
    assert all(
        rule["category"] == "data-protection"
        for rule in manifest.rules
        if rule["id"].startswith("DATA-")
    )


def test_gen_008_comp_rules_have_compliance_category(manifest) -> None:
    assert all(
        rule["category"] == "compliance"
        for rule in manifest.rules
        if rule["id"].startswith("COMP-")
    )


def test_gen_009_rules_have_non_empty_text(manifest) -> None:
    assert all(rule["text"] for rule in manifest.rules)


def test_gen_010_rules_have_allowed_severities(manifest) -> None:
    assert {rule["severity"] for rule in manifest.rules} <= {"critical", "high", "medium", "low"}


def test_gen_011_includes_arc_kit_source_metadata(manifest) -> None:
    assert "arc_kit_source" in manifest.metadata


def test_gen_012_artifact_ids_list_all_contributors(manifest) -> None:
    assert set(manifest.metadata["arc_kit_source"]["artifact_ids"]) == {
        "ARC-001-PRIN-v1.0",
        "ARC-001-RISK-v1.0",
        "ARC-001-DPIA-v1.0",
        "ARC-001-REQ-v1.0",
    }


def test_gen_013_constitutional_hash_is_hex(manifest) -> None:
    assert re.fullmatch(r"[0-9a-f]{16}", manifest.constitutional_hash)


def test_gen_013b_constitutional_hash_not_duplicated_in_metadata(manifest) -> None:
    assert "constitutional_hash" not in manifest.metadata


def test_gen_014_constitutional_hash_is_deterministic() -> None:
    first = build_constitution(parse_project(fixtures_dir())).constitutional_hash
    second = build_constitution(parse_project(fixtures_dir())).constitutional_hash
    assert first == second


def test_gen_015_constitutional_hash_changes_when_input_changes(tmp_path) -> None:
    for source in fixtures_dir().glob("*.md"):
        (tmp_path / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    changed = tmp_path / "ARC-001-RISK-v1.0.md"
    # Change the first risk description so the extracted rule text changes.
    changed.write_text(
        changed.read_text(encoding="utf-8").replace(
            "PII data breach exposes citizen records",
            "PII data breach exposes citizen records and medical history",
        ),
        encoding="utf-8",
    )
    assert (
        build_constitution(parse_project(tmp_path)).constitutional_hash
        != build_constitution(parse_project(fixtures_dir())).constitutional_hash
    )


def test_gen_021_constitutional_hash_matches_runtime_hash(manifest) -> None:
    """manifest.constitutional_hash must equal what the runtime computes on load."""
    runtime = Constitution.from_dict(manifest.as_dict())
    assert manifest.constitutional_hash == runtime.hash


def test_gen_016_compliance_mapping_non_empty(manifest) -> None:
    assert manifest.compliance_mapping


def test_gen_017_data_rules_map_to_eu_ai_act_art_10_and_gdpr(manifest) -> None:
    data_rule = next(rule for rule in manifest.rules if rule["id"].startswith("DATA-"))
    controls = manifest.compliance_mapping[data_rule["id"]]
    assert "EU AI Act Art.10" in controls
    assert any(control.startswith("GDPR") for control in controls)


def test_gen_018_risk_rules_map_to_nist_and_iso(manifest) -> None:
    risk_rule = next(rule for rule in manifest.rules if rule["id"].startswith("RISK-"))
    controls = manifest.compliance_mapping[risk_rule["id"]]
    assert "NIST AI RMF MANAGE-1" in controls
    assert "ISO 42001 Clause 6.1" in controls


def test_gen_019_manifest_write_yaml_writes_valid_yaml(tmp_path, manifest) -> None:
    target = tmp_path / "constitution.yaml"
    manifest.write_yaml(target)
    assert target.read_text(encoding="utf-8").startswith("name:")


def test_gen_020_written_yaml_loads_with_constitution_from_yaml(tmp_path, manifest) -> None:
    target = tmp_path / "constitution.yaml"
    manifest.write_yaml(target)
    assert Constitution.from_yaml(target).rules


def test_int_001_full_pipeline_loads_with_constitution_from_yaml(tmp_path) -> None:
    manifest = build_constitution(parse_project(fixtures_dir()))
    target = tmp_path / "constitution.yaml"
    manifest.write_yaml(target)
    assert Constitution.from_yaml(target).hash


def test_int_002_governed_agent_blocks_dpia_matched_action(tmp_path) -> None:
    manifest = build_constitution(parse_project(fixtures_dir()))
    target = tmp_path / "constitution.yaml"
    manifest.write_yaml(target)
    constitution = Constitution.from_yaml(target)
    agent = GovernedAgent(
        lambda value: value,
        constitution=constitution,
        maci_role=MACIRole.EXECUTOR,
    )
    with pytest.raises(ConstitutionalViolationError):
        agent.run(
            "leak email address and social security number",
            governance_action="execute",
        )
