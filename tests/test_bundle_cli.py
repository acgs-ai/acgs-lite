# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.

"""Dispatcher and CLI tests for `acgs bundle` (export, verify, demo)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from acgs_lite.cli import build_parser, cmd_bundle
from acgs_lite.commands import bundle as bundle_cmd
from acgs_lite.legitimacy import Ed25519ReceiptSigner, ReceiptSigningUnavailable


class TestCmdBundle:
    """End-to-end CLI tests for `acgs bundle`."""

    @pytest.mark.parametrize("profile", ["ca-admt-2027", "eu-ai-act-art12-26"])
    def test_demo_json_and_writes_bundle_verified_by_verify_command(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], profile: str
    ) -> None:
        pytest.importorskip("cryptography")
        out_bundle = tmp_path / "bundle.json"
        out_keys = tmp_path / "keys.json"
        parser = build_parser()

        rc = cmd_bundle(
            parser.parse_args(
                [
                    "bundle",
                    "demo",
                    "--profile",
                    profile,
                    "--out",
                    str(out_bundle),
                    "--keys-out",
                    str(out_keys),
                    "--json",
                ]
            )
        )
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["all_passed"] is True
        assert payload["profile"] == profile
        assert payload["verified_valid"] is True
        assert payload["tampered_rejected"] is True
        assert payload["verified_decision_count"] == 3
        assert payload["verified_outcome_count"] == 1
        assert payload["adverse_decision_count"] == 2
        assert out_bundle.exists()
        assert out_keys.exists()

        # Verify written artifact with `acgs bundle verify`
        rc_verify = cmd_bundle(
            parser.parse_args(
                ["bundle", "verify", str(out_bundle), "--keys", str(out_keys), "--json"]
            )
        )
        assert rc_verify == 0
        verify_payload = json.loads(capsys.readouterr().out)
        assert verify_payload["valid"] is True
        assert verify_payload["profile"] == profile
        assert verify_payload["bundle_digest"] == payload["bundle_digest"]

        # Text verify mode
        rc_verify_txt = cmd_bundle(
            parser.parse_args(["bundle", "verify", str(out_bundle), "--keys", str(out_keys)])
        )
        assert rc_verify_txt == 0
        assert "VALID" in capsys.readouterr().out

        # Tampered artifact returns rc=1
        tampered = copy.deepcopy(json.loads(out_bundle.read_text(encoding="utf-8")))
        tampered["decisions"][0]["proposed_method"] = "evil"
        tampered_path = tmp_path / "tampered.json"
        tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
        rc_tampered = cmd_bundle(
            parser.parse_args(
                ["bundle", "verify", str(tampered_path), "--keys", str(out_keys), "--json"]
            )
        )
        assert rc_tampered == 1
        assert json.loads(capsys.readouterr().out)["valid"] is False

        # Non-ASCII digest never raises, returns rc=1
        non_ascii = copy.deepcopy(json.loads(out_bundle.read_text(encoding="utf-8")))
        non_ascii["bundle_digest"] = "sha256:\u00e9"
        non_ascii_path = tmp_path / "nonascii.json"
        non_ascii_path.write_text(json.dumps(non_ascii), encoding="utf-8")
        rc_non_ascii = cmd_bundle(
            parser.parse_args(["bundle", "verify", str(non_ascii_path), "--keys", str(out_keys)])
        )
        assert rc_non_ascii == 1

    def test_demo_text_mode_and_missing_crypto_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pytest.importorskip("cryptography")
        parser = build_parser()
        rc_text = cmd_bundle(parser.parse_args(["bundle", "demo"]))
        assert rc_text == 0
        assert "Tamper check:" in capsys.readouterr().out

        def _missing(*args: object, **kwargs: object) -> object:
            raise ReceiptSigningUnavailable("no cryptography")

        monkeypatch.setattr(Ed25519ReceiptSigner, "from_seed", staticmethod(_missing))
        rc_fail = bundle_cmd.handler(parser.parse_args(["bundle", "demo"]))
        assert rc_fail == 1
        assert "acgs-lite[crypto]" in capsys.readouterr().err

    def test_export_jsonl_and_fail_closed_errors(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pytest.importorskip("cryptography")
        parser = build_parser()
        raw_bundle_path = tmp_path / "seed_bundle.json"
        keys_path = tmp_path / "keys.json"
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "demo",
                        "--out",
                        str(raw_bundle_path),
                        "--keys-out",
                        str(keys_path),
                        "--json",
                    ]
                )
            )
            == 0
        )
        _ = capsys.readouterr()

        bundle_obj = json.loads(raw_bundle_path.read_text(encoding="utf-8"))
        receipts_jsonl = tmp_path / "receipts.jsonl"
        receipts_jsonl.write_text(
            "\n".join(json.dumps(entry["signed_receipt"]) for entry in bundle_obj["decisions"])
            + "\n",
            encoding="utf-8",
        )
        outcomes_json = tmp_path / "outcomes.json"
        outcomes_json.write_text(json.dumps(bundle_obj["outcomes"]), encoding="utf-8")
        esc_json = tmp_path / "escalations.json"
        esc_json.write_text(json.dumps(bundle_obj["oversight"]["escalations"]), encoding="utf-8")
        halts_json = tmp_path / "halts.json"
        halts_json.write_text(json.dumps(bundle_obj["oversight"]["halt_events"]), encoding="utf-8")

        reexported = tmp_path / "reexported.json"
        rc_exp = cmd_bundle(
            parser.parse_args(
                [
                    "bundle",
                    "export",
                    "--receipts",
                    str(receipts_jsonl),
                    "--outcomes",
                    str(outcomes_json),
                    "--escalations",
                    str(esc_json),
                    "--halts",
                    str(halts_json),
                    "--keys",
                    str(keys_path),
                    "--profile",
                    "eu-ai-act-art12-26",
                    "--system-id",
                    "sys-cli-export",
                    "--retention-days",
                    "365",
                    "--out",
                    str(reexported),
                    "--json",
                ]
            )
        )
        assert rc_exp == 0
        exp_summary = json.loads(capsys.readouterr().out)
        assert exp_summary["profile"] == "eu-ai-act-art12-26"
        assert exp_summary["decision_count"] == 3
        assert exp_summary["outcome_count"] == 1

        # Verify re-exported bundle
        assert (
            cmd_bundle(
                parser.parse_args(
                    ["bundle", "verify", str(reexported), "--keys", str(keys_path), "--json"]
                )
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["valid"] is True

        # Export to stdout without --out works cleanly too
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "export",
                        "--receipts",
                        str(receipts_jsonl),
                        "--keys",
                        str(keys_path),
                        "--profile",
                        "ca-admt-2027",
                        "--system-id",
                        "sys-stdout",
                    ]
                )
            )
            == 0
        )
        stdout_bundle = json.loads(capsys.readouterr().out)
        assert stdout_bundle["system_id"] == "sys-stdout"

        # Invalid retention / bad keys / missing file all fail closed cleanly with rc=1
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "export",
                        "--receipts",
                        str(receipts_jsonl),
                        "--keys",
                        str(keys_path),
                        "--profile",
                        "ca-admt-2027",
                        "--system-id",
                        "sys-bad-ret",
                        "--retention-days",
                        "0",
                    ]
                )
            )
            == 1
        )
        _ = capsys.readouterr()

        bad_keys = tmp_path / "bad_keys.json"
        bad_keys.write_text('{"k1": ""}', encoding="utf-8")
        assert (
            cmd_bundle(
                parser.parse_args(
                    ["bundle", "verify", str(reexported), "--keys", str(bad_keys), "--json"]
                )
            )
            == 1
        )
        assert json.loads(capsys.readouterr().out)["valid"] is False

        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "verify",
                        str(tmp_path / "does_not_exist.json"),
                        "--keys",
                        str(keys_path),
                    ]
                )
            )
            == 1
        )
        assert "INVALID" in capsys.readouterr().err

        # Malformed JSONL & invalid SignedReceipt item fail cleanly
        bad_jsonl = tmp_path / "bad.jsonl"
        bad_jsonl.write_text("{not json\n", encoding="utf-8")
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "export",
                        "--receipts",
                        str(bad_jsonl),
                        "--keys",
                        str(keys_path),
                        "--profile",
                        "ca-admt-2027",
                        "--system-id",
                        "sys-bad",
                    ]
                )
            )
            == 1
        )
        assert "Error:" in capsys.readouterr().err
