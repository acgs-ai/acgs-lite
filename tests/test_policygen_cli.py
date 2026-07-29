# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Dispatcher-level tests for `acgs policygen generate`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import acgs_lite.cli as cli
from acgs_lite import Constitution
from acgs_lite.cli import build_parser, cmd_policygen
from acgs_lite.policygen import PreContext


def _invoke(args: list[str]) -> int:
    parser = build_parser()
    namespace = parser.parse_args(["policygen", *args])
    return cmd_policygen(namespace)


def test_generate_from_brief_writes_yaml_and_prints_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    brief_path = tmp_path / "brief.json"
    brief_path.write_text(
        json.dumps(
            {
                "domain": "Healthcare Triage Assistant",
                "description": "Handles patient PII and clinical notes.",
                "risk_areas": ["pii", "secrets"],
                "frameworks": ["hipaa"],
                "environment": "production",
                "risk_level": "high",
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "constitution.yaml"

    exit_code = _invoke(["generate", "--brief", str(brief_path), "--out", str(out_path)])

    assert exit_code == 0
    assert out_path.exists()

    payload = json.loads(capsys.readouterr().out)
    assert payload["output_path"] == str(out_path)
    assert payload["summary"]["domain"] == "Healthcare Triage Assistant"
    assert payload["summary"]["rule_count"] > 0
    assert isinstance(payload["rationale"], list)
    assert payload["rationale"]

    constitution = Constitution.from_yaml(out_path)
    assert constitution.rules


def test_generate_from_flags_writes_yaml_and_prints_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_path = tmp_path / "constitution.yaml"

    exit_code = _invoke(
        [
            "generate",
            "--domain",
            "Lending Risk Engine",
            "--description",
            "Automated credit decisioning agent handling PII.",
            "--env",
            "production",
            "--framework",
            "gdpr",
            "--framework",
            "soc2",
            "--risk-area",
            "pii",
            "--risk-area",
            "financial",
            "--risk-level",
            "high",
            "--out",
            str(out_path),
        ]
    )

    assert exit_code == 0
    assert out_path.exists()

    payload = json.loads(capsys.readouterr().out)
    assert payload["output_path"] == str(out_path)
    assert payload["summary"]["domain"] == "Lending Risk Engine"
    assert payload["summary"]["risk_level"] == "high"
    assert set(payload["summary"]["frameworks"]) >= {"gdpr", "soc2"}

    constitution = Constitution.from_yaml(out_path)
    assert constitution.rules


def test_generate_invalid_brief_json_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    brief_path = tmp_path / "brief.json"
    brief_path.write_text("{not valid json", encoding="utf-8")
    out_path = tmp_path / "constitution.yaml"

    exit_code = _invoke(["generate", "--brief", str(brief_path), "--out", str(out_path)])

    assert exit_code == 1
    assert capsys.readouterr().err
    assert not out_path.exists()


def test_generate_brief_with_unknown_key_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    brief_path = tmp_path / "brief.json"
    brief_path.write_text(json.dumps({"domain": "X", "bogus_key": True}), encoding="utf-8")
    out_path = tmp_path / "constitution.yaml"

    exit_code = _invoke(["generate", "--brief", str(brief_path), "--out", str(out_path)])

    assert exit_code == 1
    assert "bogus_key" in capsys.readouterr().err
    assert not out_path.exists()


def test_generate_missing_brief_file_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_path = tmp_path / "constitution.yaml"

    exit_code = _invoke(
        ["generate", "--brief", str(tmp_path / "does-not-exist.json"), "--out", str(out_path)]
    )

    assert exit_code == 1
    assert capsys.readouterr().err
    assert not out_path.exists()


def test_generate_missing_domain_and_brief_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_path = tmp_path / "constitution.yaml"

    exit_code = _invoke(["generate", "--out", str(out_path)])

    assert exit_code == 1
    assert capsys.readouterr().err
    assert not out_path.exists()


def test_generate_missing_out_arg_nonzero_exit() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["policygen", "generate", "--domain", "Foo"])

    assert exc.value.code != 0


def test_generate_brief_and_domain_mutually_exclusive_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    brief_path = tmp_path / "brief.json"
    brief_path.write_text(json.dumps({"domain": "X"}), encoding="utf-8")
    out_path = tmp_path / "constitution.yaml"

    exit_code = _invoke(
        [
            "generate",
            "--brief",
            str(brief_path),
            "--domain",
            "Y",
            "--out",
            str(out_path),
        ]
    )

    assert exit_code == 1
    assert capsys.readouterr().err
    assert not out_path.exists()


def test_generate_unwritable_out_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A directory is not a writable file target -> OSError from Path.write_text.
    unwritable = tmp_path / "not-a-file"
    unwritable.mkdir()

    exit_code = _invoke(["generate", "--domain", "Foo", "--out", str(unwritable)])

    assert exit_code == 1
    assert capsys.readouterr().err


def test_generate_dispatches_through_command_map_via_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise the real `_COMMAND_MAP` lookup + `main()` entry point, not just
    the handler function, so a dropped map entry or add_parser() call fails
    this test (per the handler-wiring rule)."""
    out_path = tmp_path / "constitution.yaml"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "acgs",
            "policygen",
            "generate",
            "--domain",
            "Lending Risk Engine",
            "--risk-area",
            "pii",
            "--out",
            str(out_path),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    assert out_path.exists()
    assert Constitution.from_yaml(out_path).rules


def test_generate_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["policygen", "generate", "--help"])

    assert exc.value.code == 0
    assert "pre-context" in capsys.readouterr().out


# --- `acgs policygen scan` -------------------------------------------------------------


def test_scan_known_and_unknown_deps_prints_report_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "stripe==5.0\nboto3\nsome-totally-unknown-package==1.2.3\n",
        encoding="utf-8",
    )

    exit_code = _invoke(["scan", str(tmp_path)])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["manifests"] == ["requirements.txt"]
    assert ["boto3", "production-deploy"] in payload["matched"]
    assert ["stripe", "financial"] in payload["matched"]
    assert "some-totally-unknown-package" in payload["unknown"]
    assert payload["precontext"]["domain"] == "scanned-project"
    # Unknown packages are evidence, not errors -- exit 0, nothing on stderr.
    assert capsys.readouterr().err == ""


def test_scan_brief_out_round_trips_through_precontext_from_dict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "requirements.txt").write_text("stripe==5.0\n", encoding="utf-8")
    brief_out = tmp_path / "brief.json"

    exit_code = _invoke(["scan", str(tmp_path), "--brief-out", str(brief_out)])

    assert exit_code == 0
    capsys.readouterr()  # drain stdout report
    assert brief_out.exists()

    raw = json.loads(brief_out.read_text(encoding="utf-8"))
    precontext = PreContext.from_dict(raw)
    assert precontext.domain == "scanned-project"
    assert "financial" in precontext.risk_areas


def test_scan_generate_end_to_end_produces_parseable_yaml(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "stripe==5.0\nboto3\nsome-totally-unknown-package==1.2.3\n", encoding="utf-8"
    )
    out_path = tmp_path / "constitution.yaml"

    exit_code = _invoke(["scan", str(tmp_path), "--generate", "--out", str(out_path)])

    assert exit_code == 0
    assert out_path.exists()

    payload = json.loads(capsys.readouterr().out)
    assert payload["output_path"] == str(out_path)
    assert payload["summary"]["rule_count"] > 0
    assert isinstance(payload["rationale"], list)
    assert payload["rationale"]
    # Scan evidence (matched + unknown) must reach stdout even via --generate -- it is
    # never silently dropped, per manifest.py's governance-evidence invariant.
    assert ["boto3", "production-deploy"] in payload["matched"]
    assert ["stripe", "financial"] in payload["matched"]
    assert "some-totally-unknown-package" in payload["unknown"]

    constitution = Constitution.from_yaml(out_path)
    assert constitution.rules


def test_scan_brief_out_and_generate_combined(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--brief-out and --generate together: brief round-trips AND stdout carries
    matched/unknown evidence AND the generated YAML parses -- the combination the
    inaccurate self-review claim (brief-out alone recovers scan evidence) would have
    been caught by."""
    (tmp_path / "requirements.txt").write_text(
        "stripe==5.0\nsome-totally-unknown-package==1.2.3\n", encoding="utf-8"
    )
    brief_out = tmp_path / "brief.json"
    out_path = tmp_path / "constitution.yaml"

    exit_code = _invoke(
        [
            "scan",
            str(tmp_path),
            "--brief-out",
            str(brief_out),
            "--generate",
            "--out",
            str(out_path),
        ]
    )

    assert exit_code == 0

    # Brief file round-trips through PreContext.from_dict -- but note it carries no
    # `unknown` field; that's why the payload assertion below matters independently.
    raw = json.loads(brief_out.read_text(encoding="utf-8"))
    precontext = PreContext.from_dict(raw)
    assert precontext.domain == "scanned-project"
    assert "financial" in precontext.risk_areas

    payload = json.loads(capsys.readouterr().out)
    assert payload["output_path"] == str(out_path)
    assert ["stripe", "financial"] in payload["matched"]
    assert "some-totally-unknown-package" in payload["unknown"]

    constitution = Constitution.from_yaml(out_path)
    assert constitution.rules


def test_scan_no_manifest_found_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = _invoke(["scan", str(tmp_path)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no supported manifest files" in captured.err


def test_scan_nonexistent_path_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "does-not-exist"

    exit_code = _invoke(["scan", str(missing)])

    assert exit_code == 1
    assert capsys.readouterr().err


def test_scan_generate_without_out_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "requirements.txt").write_text("stripe==5.0\n", encoding="utf-8")

    exit_code = _invoke(["scan", str(tmp_path), "--generate"])

    assert exit_code == 1
    assert "--out is required" in capsys.readouterr().err


def test_scan_dispatches_through_command_map_via_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise the real `_COMMAND_MAP` lookup + `main()` entry point for `scan`,
    per the handler-wiring rule (dropped map entries or add_parser() calls must fail
    this test)."""
    (tmp_path / "requirements.txt").write_text("stripe==5.0\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["acgs", "policygen", "scan", str(tmp_path)])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0


def test_scan_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["policygen", "scan", "--help"])

    assert exc.value.code == 0
    assert "manifest" in capsys.readouterr().out
