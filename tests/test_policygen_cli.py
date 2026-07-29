# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Dispatcher-level tests for `acgs policygen generate`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acgs_lite import Constitution
from acgs_lite.cli import build_parser, cmd_policygen


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


def test_generate_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["policygen", "generate", "--help"])

    assert exc.value.code == 0
    assert "pre-context" in capsys.readouterr().out
