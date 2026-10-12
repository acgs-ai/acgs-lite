# Test skip remediation — 2026-10-12

## Status

Local verification and independent review passed. The fully provisioned Python 3.12 run completed **6,828 passed, zero skipped, zero xfailed, zero deselected**, with no files excluded by optional-import collection guards. Changes remain local; remote CI and publication have not run.

111 hard-skipped cases addressed: 72 legacy evidence tests migrated, 23 supplementary compliance tests restored unchanged, 11 response-schema/constrained-decoding tests restored unchanged, two result-lifecycle tests replacing removed internals, two sandbox serialization tests repaired, and one malformed-regex test corrected to require fail-closed rejection. The Python 3.12 GC xfail was separately repaired.

95 previously skipped compliance cases: 23 unchanged supplementary tests re-enabled; 72 legacy evidence cases mapped below. The new evidence suite independently collects 72 cases. Counts are not semantic equivalence: unsupported scoring and framework-specific contracts are explicitly retired and replaced with current contracts.

Reproduction after removing skips: 46 failed, 260 passed, 23 errors. Targeted final run: 381 passed in 1.22s; no skips or xfails.

Only runtime edit: constitution/sandbox.py uses Rule.model_dump(mode="json") for add/remove operations instead of nonexistent Rule.to_dict().

## TestEvidenceRecord

Supported compatibility record retained; immutable-record premise replaced by independent serialization for the now-mutable dataclass.

| Old case | Current case |
|---|---|
| `test_default_creation` | `TestEvidenceRecord.test_default_creation` |
| `test_creation_with_fields` | `TestEvidenceRecord.test_creation_with_fields` |
| `test_frozen` | `TestEvidenceRecord.test_serialization_does_not_alias_mutable_record` |
| `test_to_dict` | `TestEvidenceRecord.test_to_dict` |
| `test_to_dict_roundtrip` | `TestEvidenceRecord.test_to_dict_roundtrip` |
| `test_collected_at_is_iso_string` | `TestEvidenceRecord.test_collected_at_is_iso_string` |
| `test_unique_record_ids` | `TestEvidenceRecord.test_unique_record_ids` |

## TestSOC2Collector

Retired SOC2 collector replaced by generic component-to-framework mappings; no runtime compliance verdict inferred from importability.

| Old case | Current case |
|---|---|
| `test_framework_id` | `TestImportEvidence.test_soc2_framework_id` |
| `test_collects_four_records` | `TestImportEvidence.test_grouped_framework_records` |
| `test_cc6_1_compliant` | `TestImportEvidence.test_component_source` |
| `test_cc6_6_with_audit` | `TestImportEvidence.test_soc2_monitoring_reference` |
| `test_cc6_6_empty_audit` | `TestImportEvidence.test_unavailable_components_have_no_evidence` |
| `test_cc7_2_no_validations` | `TestImportEvidence.test_importability_does_not_claim_runtime_validation` |
| `test_cc8_1_has_hash` | `TestImportEvidence.test_constitution_configuration_references` |
| `test_all_records_have_soc2_framework` | `TestImportEvidence.test_soc2_framework_id` |

## TestISO27001Collector

Removed ISO27001-specific counts/scoring/severity summaries replaced by supported ISO42001/filesystem mappings and real audit evidence. Framework equivalence is not claimed.

| Old case | Current case |
|---|---|
| `test_framework_id` | `TestFileEvidence.test_artefact_reference[risk-register.md]` |
| `test_collects_four_records` | `TestFileEvidence.test_artefact_reference[data-governance-policy.md]` |
| `test_a8_2_severity_distribution` | `TestFileEvidence.test_artefact_reference[bias-assessment.md]` |
| `test_a12_4_audit_chain` | `TestRuntimeEvidence.test_invalid_chain_does_not_produce_integrity_evidence` |
| `test_a12_4_empty_log` | `TestFileEvidence.test_empty_root_has_no_evidence` |
| `test_a14_2_validation_coverage` | `TestRuntimeEvidence.test_engine_validations_produce_runtime_evidence` |
| `test_a18_1_compliance_checks` | `TestFileEvidence.test_prior_assessment_is_wildcard_evidence` |
| `test_all_records_have_iso_framework` | `TestFileEvidence.test_artefact_reference[risk-register.md]` |
| `test_a8_2_empty_constitution` | `TestFileEvidence.test_empty_root_has_no_evidence` |

## TestGDPRCollector

Supported GDPR reference mapping from explicit evidence sources replaces old rule-keyword scoring.

| Old case | Current case |
|---|---|
| `test_framework_id` | `TestEnvironmentEvidence.test_declared_configuration[GDPR_DATA_CONTROLLER]` |
| `test_collects_three_records` | `TestEnvironmentEvidence.test_declared_configuration[GDPR_DPO_CONTACT]` |
| `test_art5_data_rules` | `TestFileEvidence.test_artefact_reference[privacy_notice.md]` |
| `test_art5_with_data_protection_rules` | `TestFileEvidence.test_artefact_reference[data-governance-policy.md]` |
| `test_art25_design_controls` | `TestEnvironmentEvidence.test_declared_configuration[ACGS_HUMAN_OVERSIGHT]` |
| `test_art30_audit_trail` | `TestEnvironmentEvidence.test_declared_configuration[ACGS_AUDIT_ENABLED]` |
| `test_art30_empty_audit` | `TestEnvironmentEvidence.test_absent_configuration_is_not_evidence` |
| `test_all_records_have_gdpr_framework` | `TestEnvironmentEvidence.test_declared_configuration[GDPR_DATA_CONTROLLER]` |

## TestComplianceFrameworkProtocol

Current runtime-checkable EvidenceCollector protocol and custom collector dispatcher.

| Old case | Current case |
|---|---|
| `test_soc2_is_compliance_framework` | `TestCollectorProtocol.test_builtin_protocol[collector0]` |
| `test_iso27001_is_compliance_framework` | `TestCollectorProtocol.test_builtin_protocol[collector1]` |
| `test_gdpr_is_compliance_framework` | `TestCollectorProtocol.test_builtin_protocol[collector2]` |
| `test_custom_framework` | `TestCollectorProtocol.test_custom_collector_protocol_and_dispatch` |

## TestEvidenceCollector

Current ComplianceEvidenceEngine explicit collector list and EvidenceBundle filtering replace legacy registry; unknown framework now returns empty list, not error.

| Old case | Current case |
|---|---|
| `test_default_frameworks_registered` | `TestEvidenceEngine.test_default_collectors` |
| `test_collect_all_count` | `TestEvidenceEngine.test_aggregates_all_collectors_in_order` |
| `test_collect_framework_soc2` | `TestEvidenceEngine.test_framework_filter[soc2_ai]` |
| `test_collect_framework_iso27001` | `TestEvidenceEngine.test_framework_filter[iso_42001]` |
| `test_collect_framework_gdpr` | `TestEvidenceEngine.test_framework_filter[gdpr]` |
| `test_collect_unknown_framework_raises` | `TestEvidenceEngine.test_unknown_framework_is_empty` |
| `test_register_framework` | `TestEvidenceEngine.test_collector_receives_description` |
| `test_custom_frameworks_only` | `TestEvidenceEngine.test_explicit_custom_collectors_only` |
| `test_empty_frameworks_list` | `TestEvidenceEngine.test_explicit_empty_collectors_disable_defaults` |

## TestComplianceScoring

Compliance scores are no longer provided by evidence collectors; tests assert bounded observation confidence and explicitly reject invented scoring/status.

| Old case | Current case |
|---|---|
| `test_overall_score_range` | `TestEvidenceConfidence.test_import_confidence_is_bounded` |
| `test_framework_score_range` | `TestEvidenceConfidence.test_audit_confidence_is_bounded` |
| `test_perfect_score` | `TestEvidenceConfidence.test_high_volume_confidence_saturates` |
| `test_zero_score` | `TestEvidenceConfidence.test_no_records_means_no_runtime_evidence` |
| `test_partial_score` | `TestEvidenceConfidence.test_more_observations_increase_confidence` |
| `test_score_with_no_records` | `TestEvidenceConfidence.test_minimum_entry_threshold` |
| `test_score_partial_status_value` | `TestEvidenceConfidence.test_bundle_does_not_invent_compliance_scores` |

## TestReportGeneration

EvidenceBundle summary/serialization contract replaces retired scored-report fields.

| Old case | Current case |
|---|---|
| `test_report_has_summary` | `TestBundleReport.test_summary_counts_frameworks` |
| `test_report_summary_fields` | `TestBundleReport.test_serialized_summary_fields` |
| `test_report_overall_score_range` | `TestBundleReport.test_confidence_is_preserved` |
| `test_report_framework_scores` | `TestBundleReport.test_wildcard_is_included_without_double_counting` |
| `test_report_total_records` | `TestBundleReport.test_item_count_matches_records` |
| `test_report_frameworks_section` | `TestBundleReport.test_exact_article_reference_filter` |
| `test_report_status_counts` | `TestBundleReport.test_empty_report` |

## TestJSONExport

JSON serialization supported by bundle.to_dict; paths are caller-owned, no fabricated export helper.

| Old case | Current case |
|---|---|
| `test_export_returns_string` | `TestJSONExport.test_export_returns_json_string` |
| `test_export_valid_json` | `TestJSONExport.test_roundtrip_preserves_all_item_fields` |
| `test_export_to_file` | `TestJSONExport.test_export_to_file` |
| `test_export_creates_parent_dirs` | `TestJSONExport.test_export_nested_path_is_caller_owned` |
| `test_export_no_path_returns_json` | `TestJSONExport.test_export_does_not_alias_article_refs` |

## TestEdgeCases

Real zero-rule/single-rule validation, valid/invalid chain and repeated collection; no compliance verdict invented from denial rates.

| Old case | Current case |
|---|---|
| `test_empty_audit_log_all_frameworks` | `TestRuntimeEvidence.test_empty_audit_log_has_no_chain_claim` |
| `test_no_rules_constitution` | `TestRuntimeEvidence.test_engine_validations_produce_runtime_evidence` |
| `test_engine_after_validations` | `TestRuntimeEvidence.test_engine_validations_produce_runtime_evidence` |
| `test_single_rule_constitution` | `TestRuntimeEvidence.test_single_rule_denial_is_observed_without_compliance_verdict` |
| `test_report_is_json_serializable` | `TestJSONExport.test_roundtrip_preserves_all_item_fields` |
| `test_concurrent_collect_calls` | `TestRuntimeEvidence.test_repeated_collection_is_consistent` |
| `test_cc8_1_empty_constitution_non_compliant` | `TestImportEvidence.test_constitution_configuration_references` |
| `test_a18_1_non_compliant_scenario` | `TestRuntimeEvidence.test_single_rule_denial_is_observed_without_compliance_verdict` |

## Additional current API protections

New negative/source cases cover missing import attributes/modules, nested files excluded, artefact removal, empty/false/case-insensitive environment settings, environment changes, broken audit chains, missing log interfaces, and collect_evidence wiring with optional audit. These replace redundant old fixed-count assertions rather than duplicating smoke checks.

## Remaining 23 compliance refactor cases

Every original test node in tests/test_compliance_refactor.py is retained unchanged. Only the stale module skip and excess blank line were removed. This re-enables checklist transitions, status enums, immutable assessment serialization, report disclaimers, protocol negatives, zero-input scoring helpers, gap detection, domain routing, and assessor reuse.

## Other disabled cases

- 10 response schema cases plus1 constrained decoding: skip removed, original assertions pass.
- 2 removed private pool cases: public validation result identity/list independence and preserved earlier violation result after subsequent validation.
- 2 sandbox add/remove cases: serialization repaired; assert deny/allow transitions, unchanged controls and untouched production rules.
- 1 invalid-regex case: reject malformed normal input and tampered compiled-pattern mismatch, then valid positive/negative controls. The obsolete expectation to silently omit a rule was unsafe; no engine relaxation.
- Python3.12 xfail: reproduced 375 vs 0 frozen count despite gc.freeze not called. Replace global GC-count assumption with wrapped freeze invocation check and explicit freeze_gc=True positive control. Existing actual-freeze positive tests remain.

## Optional integrations and research recovery

The original 343 skips comprised 169 dependency/accelerator skips (including
module-level collection skips), 111 stale or obsolete API markers, 62 missing
research dependencies, and one opt-in Lean check. Module-level skips conceal
multiple test cases, so adding 343 to the previous pass count is not the final
test count.

- `requirements-test-optional.txt`, `make test-optional`, and the new optional CI
  job provide pinned solver, PDF, AutoGen, OpenAI/xAI, swarm, Gove, and Aho-Corasick
  dependencies. Rust is built from local source with `--locked`; Lean 4.34.0 is
  downloaded with the existing release-candidate checksum. Missing prerequisites
  fail the target; CI additionally rejects skipped cases. Base runtime
  dependencies and the no-Rust/no-Z3 fallback job are unchanged.
- Restored research assets are traced to Git commit
  `ae80b547700fcda871a26c8edff8ddf1a96034ad` in
  [PROVENANCE.json](../autoresearch/PROVENANCE.json). Fourteen immutable assets
  match both their historical blobs and recorded hashes. Eight test modules now
  run 93 cases without skips. The historical generated corpus was recovered
  byte-for-byte, not regenerated or relabeled.
- The raw-case evaluator now runs the actual engine instead of deriving
  predictions from synthesis profiles or expected labels. Independent controls
  cover label corruption, changed actions, malformed inputs, and real CLI
  invocation. The restored rule evaluator exits nonzero on failures.
- `MANIFEST.in` includes the restored research dependencies and optional test
  requirements in the source distribution; the wheel's runtime package remains
  scoped to the library.

## Final verification evidence

Commands run from the repository root, with the local pinned Lean `bin/` directory
on `PATH` and `LEAN_INTEGRATION=1` for provisioned runs:

```bash
rtk proxy make test PYTHON=.venv/bin/python 'PYTEST=.venv/bin/python -m pytest -o addopts= -rs --junitxml=/tmp/acgs-skipfix-complete.xml'
# 6828 passed, 30 warnings in 45.42s; exit 0
# JUnit: 6828 tests, 0 errors, 0 failures, 0 skipped; collect_ignore=[]

rtk proxy make verify PYTHON=.venv/bin/python 'PYTEST=.venv/bin/python -m pytest -rs --junitxml=/tmp/acgs-skipfix-verify-final.xml'
# 6825 passed, 3 deselected in 42.86s; exit 0
# The 3 benchmarks excluded here ran in the all-inclusive command above.
# Ruff: All checks passed! MyPy: Success, no issues found in 314 source files.
# Agent gate: 54 passed. verify: all gates passed

rtk proxy make test-optional PYTHON=.venv/bin/python
# 626 passed in 8.49s; exit 0; CI JUnit no-skip assertion also passed.
```

Evidence logs and JUnit are retained under `/tmp/acgs-skipfix-complete.*`,
`/tmp/acgs-skipfix-verify-final.*`, and `/tmp/acgs-skipfix-optional-final.*`.
The all-inclusive coverage run before adding the previously ignored 16 xAI tests
passed 6,812 cases with 92.94% overall coverage, 92.68% critical-path coverage,
and 91.71% governed/legitimacy coverage; all repository coverage thresholds passed.
No library code changed between that coverage run and the final 6,828-case run.
Dependency consistency passed for all 124 installed packages.

A separate Python 3.11 environment reproduced the existing minimal fallback CI
command: 6,251 passed, 175 intentional dependency/toolchain skips, 56 deselected,
zero xfails. Those skips are distinct from the fully provisioned run above; the
fallback deliberately omits Rust, Z3, and other integrations. It has no remaining
stale-API or missing-research skips.

Strict MkDocs, documentation links, package build, and `git diff --check` passed.
Separate review independently ran the optional, research, and migrated API
slices and found no blocking correctness or security issues.

After adding the source manifest, the rebuilt source archive contained all 43
declared research-test dependencies byte-for-byte. Its extracted research suite
passed 93 tests with zero skips, with both library and evaluator imports verified
inside the extracted archive. Evidence: `/tmp/acgs-research-sdist-evidence.json`
and `/tmp/acgs-research-sdist-tests.log`. Preexisting omissions of repository
tooling (Makefile, registries, readiness script, and agent instructions) remain;
this does not claim that every repository gate runs from a source archive.

## Measured limitations

The restored historical research harness is not a claim of perfect policy
accuracy: the raw sample manifest scores 10/24 and the historical extended
evaluation reports 3,297 passing cases and 17 mismatches, with zero errors/skips
and exit 1. See [research notes](../autoresearch/README.md). These results remain
visible; test repairs do not change benchmark labels or constitutional rules.

## Handoff — codex/docs-distribution-community / acgs-lite

- **Directories touched:** root, `.github/workflows/`, `tools/`, `src/acgs_lite/constitution/`,
  `tests/`, `autoresearch/`, `planning/`; root AGENTS/CLAUDE and local manifests read,
  no additional nested instructions in these scopes.
- **Subagents:** planning `skip_plan`; implementation `stale_api_fixes`,
  `research_repair`, `final_verification` (optional setup); separate review
  `independent_review`; full/fallback verification `final_verification`.
- **Hash-marked files:** existing markers in tests and recovered research assets
  preserved. No constitutional hash recomputation or rule edits.
- **Generated files:** historical generated research corpus restored exactly from
  its canonical Git blob; no generated agent manifests or lockfiles hand-edited.
- **Submodules/nested repositories:** none touched.
- **Expected gates:** CI test/coverage/governance/fallback jobs, the new optional
  integration job, `make verify`, and the fully provisioned test command above.
- **Risk:** yellow — sandbox serialization changes are regression-tested; restored
  benchmarks still report documented policy mismatches and remote CI is unrun.
- **Next:** review the local diff and run the GitHub CI gates before merging.
