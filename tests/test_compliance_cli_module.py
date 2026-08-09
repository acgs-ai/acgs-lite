"""Tests for python -m acgs_lite.compliance CLI.

Covers:
- assess subcommand: text / json / markdown output
- assess subcommand: --risk-tier, --is-gpai, --framework, --jurisdiction flags
- assess subcommand: --domain triggers risk-tier auto-inference in output
- frameworks subcommand: lists all 20 frameworks
- evidence subcommand: returns bundle
- exit codes: 0 on success
- --help doesn't crash

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acgs_lite.compliance.__main__ import main


def run(argv: list[str]) -> tuple[int, str]:
    """Run the CLI with *argv* and capture stdout. Returns (exit_code, output)."""
    import io
    import sys

    old_stdout = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        code = main(argv)
    except SystemExit as e:
        code = int(e.code) if e.code is not None else 0
    finally:
        sys.stdout = old_stdout
    return code, buf.getvalue()


# ---------------------------------------------------------------------------
# frameworks subcommand
# ---------------------------------------------------------------------------


class TestFrameworksCmd:
    def test_lists_every_registered_framework(self):
        from acgs_lite.compliance.multi_framework import _FRAMEWORK_REGISTRY

        code, out = run(["frameworks"])
        assert code == 0
        # The header renders the registry size; assert against the registry itself
        # so the count can never silently drift out of sync with the CLI banner.
        assert f"({len(_FRAMEWORK_REGISTRY)})" in out

    def test_lists_all_known_ids_in_text_output(self):
        code, out = run(["frameworks"])
        assert code == 0
        for fw_id in (
            "nist_ai_rmf",
            "eu_ai_act",
            "gdpr",
            "india_dpdp",
            "brazil_lgpd",
            "china_ai",
            "ccpa_cpra",
        ):
            assert fw_id in out, f"'{fw_id}' not found in frameworks output"

    def test_json_flag_returns_valid_json(self):
        code, out = run(["frameworks", "--json"])
        assert code == 0
        rows = json.loads(out)
        assert isinstance(rows, list)
        assert len(rows) == 20

    def test_json_rows_have_required_fields(self):
        code, out = run(["frameworks", "--json"])
        assert code == 0
        rows = json.loads(out)
        for row in rows:
            assert "id" in row
            assert "name" in row
            assert "jurisdiction" in row
            assert "status" in row


# ---------------------------------------------------------------------------
# assess subcommand
# ---------------------------------------------------------------------------


class TestAssessCmd:
    def test_basic_text_output_succeeds(self):
        code, out = run(["assess", "--system-id", "test-sys"])
        assert code == 0
        assert "test-sys" in out

    def test_jurisdiction_european_union(self):
        code, out = run(["assess", "--jurisdiction", "european_union"])
        assert code == 0
        # EU jurisdiction should mention gdpr / eu_ai_act
        assert "gdpr" in out.lower() or "EU" in out

    def test_format_json_returns_valid_json(self):
        code, out = run(["assess", "--system-id", "json-test", "--format", "json"])
        assert code == 0
        data = json.loads(out)
        assert "overall_score" in data
        assert "frameworks_assessed" in data
        assert "by_framework" in data

    def test_format_json_system_id_matches(self):
        code, out = run(["assess", "--system-id", "my-ai-system", "--format", "json"])
        assert code == 0
        data = json.loads(out)
        assert data["system_id"] == "my-ai-system"

    def test_format_markdown_contains_headers(self):
        code, out = run(["assess", "--format", "markdown"])
        assert code == 0
        assert "#" in out  # markdown headers

    def test_framework_flag_restricts_to_single_framework(self):
        code, out = run(
            [
                "assess",
                "--format",
                "json",
                "--framework",
                "gdpr",
            ]
        )
        assert code == 0
        data = json.loads(out)
        assert data["frameworks_assessed"] == ["gdpr"]

    def test_multiple_framework_flags(self):
        code, out = run(
            [
                "assess",
                "--format",
                "json",
                "--framework",
                "gdpr",
                "--framework",
                "nist_ai_rmf",
            ]
        )
        assert code == 0
        data = json.loads(out)
        assessed = set(data["frameworks_assessed"])
        assert "gdpr" in assessed
        assert "nist_ai_rmf" in assessed

    def test_risk_tier_high_flag(self):
        code, out = run(
            [
                "assess",
                "--framework",
                "eu_ai_act",
                "--risk-tier",
                "high",
                "--format",
                "json",
            ]
        )
        assert code == 0
        data = json.loads(out)
        fw = data["by_framework"]["eu_ai_act"]
        # high tier should have more items than minimal
        assert len(fw["items"]) > 3

    def test_risk_tier_minimal_has_fewer_items(self):
        _, out_high = run(
            ["assess", "--framework", "eu_ai_act", "--risk-tier", "high", "--format", "json"]
        )
        _, out_min = run(
            ["assess", "--framework", "eu_ai_act", "--risk-tier", "minimal", "--format", "json"]
        )
        high_items = json.loads(out_high)["by_framework"]["eu_ai_act"]["items"]
        min_items = json.loads(out_min)["by_framework"]["eu_ai_act"]["items"]
        assert len(high_items) > len(min_items)

    def test_domain_chatbot_infers_limited_tier(self):
        code, out = run(
            [
                "assess",
                "--framework",
                "eu_ai_act",
                "--domain",
                "chatbot",
                "--format",
                "json",
            ]
        )
        assert code == 0
        data = json.loads(out)
        items = data["by_framework"]["eu_ai_act"]["items"]
        # limited tier → fewer items (only Art.5 + Art.50)
        refs = {i["ref"] for i in items}
        assert all(r.startswith("EU-AIA Art.5") or r.startswith("EU-AIA Art.50") for r in refs)

    def test_domain_hiring_infers_high_tier(self):
        code, out = run(
            [
                "assess",
                "--framework",
                "eu_ai_act",
                "--domain",
                "hiring",
                "--format",
                "json",
            ]
        )
        assert code == 0
        data = json.loads(out)
        refs = {i["ref"] for i in data["by_framework"]["eu_ai_act"]["items"]}
        assert "EU-AIA Art.9(1)" in refs

    def test_is_gpai_flag_adds_art53(self):
        code, out = run(
            [
                "assess",
                "--framework",
                "eu_ai_act",
                "--risk-tier",
                "high",
                "--is-gpai",
                "--format",
                "json",
            ]
        )
        assert code == 0
        refs = {i["ref"] for i in json.loads(out)["by_framework"]["eu_ai_act"]["items"]}
        assert "EU-AIA Art.53(1)" in refs

    def test_is_significant_entity_flag_propagates(self):
        """DORA TLPT item should NOT be N/A when --is-significant-entity is set."""
        code, out = run(
            [
                "assess",
                "--framework",
                "dora",
                "--is-significant-entity",
                "--format",
                "json",
            ]
        )
        assert code == 0
        data = json.loads(out)
        dora_items = data["by_framework"]["dora"]["items"]
        tlpt = next((i for i in dora_items if "Art.26" in i["ref"]), None)
        if tlpt:
            assert tlpt["status"] != "not_applicable"

    def test_is_significant_data_fiduciary_flag_propagates(self):
        """India DPDP SDF items should not be N/A when flag is set."""
        code, out = run(
            [
                "assess",
                "--framework",
                "india_dpdp",
                "--is-significant-data-fiduciary",
                "--format",
                "json",
            ]
        )
        assert code == 0
        data = json.loads(out)
        items = data["by_framework"]["india_dpdp"]["items"]
        # With SDF flag, SDF items should be PENDING not NOT_APPLICABLE
        sdf_items = [i for i in items if "§10(2)" in i["ref"]]
        for item in sdf_items:
            assert item["status"] in ("pending", "compliant"), (
                f"SDF item {item['ref']} should not be N/A with SDF flag"
            )

    def test_overall_score_in_0_to_1_range(self):
        code, out = run(["assess", "--format", "json"])
        assert code == 0
        data = json.loads(out)
        assert 0.0 <= data["overall_score"] <= 1.0

    def test_text_output_contains_verdict(self):
        code, out = run(["assess"])
        assert code == 0
        assert any(v in out for v in ("🟢 STRONG", "🟡 MODERATE", "🔴 AT RISK"))

    def test_output_file_json(self, tmp_path: Path):
        out_file = tmp_path / "report.json"
        code, _ = run(["assess", "--output", str(out_file)])
        assert code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "overall_score" in data

    def test_output_file_md(self, tmp_path: Path):
        out_file = tmp_path / "report.md"
        code, _ = run(["assess", "--output", str(out_file)])
        assert code == 0
        assert out_file.exists()
        content = out_file.read_text()
        assert "#" in content  # markdown


# ---------------------------------------------------------------------------
# evidence subcommand
# ---------------------------------------------------------------------------


class TestEvidenceCmd:
    def test_returns_zero_exit_code(self):
        code, _ = run(["evidence", "--system-id", "test"])
        assert code == 0

    def test_output_contains_system_id(self):
        code, out = run(["evidence", "--system-id", "my-sys"])
        assert code == 0
        assert "my-sys" in out

    def test_json_flag_returns_valid_bundle(self):
        code, out = run(["evidence", "--json"])
        assert code == 0
        data = json.loads(out)
        assert "system_id" in data
        assert "items" in data
        assert "item_count" in data

    def test_json_item_count_matches_items_length(self):
        code, out = run(["evidence", "--json"])
        assert code == 0
        data = json.loads(out)
        assert data["item_count"] == len(data["items"])

    def test_search_root_with_rules_yaml(self, tmp_path: Path):
        (tmp_path / "rules.yaml").write_text("rules: []")
        code, out = run(["evidence", "--search-root", str(tmp_path), "--json"])
        assert code == 0
        data = json.loads(out)
        sources = {i["source"] for i in data["items"]}
        assert any("rules.yaml" in s for s in sources)

    def test_framework_filter_shows_detail(self):
        code, out = run(["evidence", "--framework", "gdpr"])
        assert code == 0
        # Should not crash even if no gdpr-specific items


# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------


class TestHelpOutput:
    @pytest.mark.parametrize(
        "cmd",
        [
            ["--help"],
            ["assess", "--help"],
            ["frameworks", "--help"],
            ["evidence", "--help"],
        ],
    )
    def test_help_exits_cleanly(self, cmd: list[str]):
        with pytest.raises(SystemExit) as exc_info:
            main(cmd)
        assert exc_info.value.code == 0
