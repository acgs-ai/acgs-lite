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

    def test_scitt_export_and_verify_bundle_and_decision_round_trip(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        pytest.importorskip("cryptography")
        parser = build_parser()
        bundle_path = tmp_path / "bundle.json"
        keys_path = tmp_path / "keys.json"
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "demo",
                        "--profile",
                        "ca-admt-2027",
                        "--out",
                        str(bundle_path),
                        "--keys-out",
                        str(keys_path),
                        "--json",
                    ]
                )
            )
            == 0
        )
        _ = capsys.readouterr()

        cose_path = tmp_path / "bundle.cose"
        rc_export = cmd_bundle(
            parser.parse_args(
                [
                    "bundle",
                    "scitt-export",
                    str(bundle_path),
                    "--demo-key",
                    "--keys",
                    str(keys_path),
                    "--issuer",
                    "did:web:acgs.example",
                    "--subject",
                    "system:bundle-demo",
                    "--issued-at",
                    "1764266000",
                    "--external-aad-hex",
                    "deadbeef",
                    "--out",
                    str(cose_path),
                    "--json",
                ]
            )
        )
        assert rc_export == 0
        export_meta = json.loads(capsys.readouterr().out)
        assert export_meta["kind"] == "bundle"
        assert export_meta["demo_key_used"] is True
        assert export_meta["content_type"] == "application/acgs-compliance-bundle+json"
        assert cose_path.exists()

        # Verify JSON and text modes succeed offline
        rc_verify = cmd_bundle(
            parser.parse_args(
                [
                    "bundle",
                    "scitt-verify",
                    str(cose_path),
                    "--keys",
                    str(keys_path),
                    "--expected-content-type",
                    "application/acgs-compliance-bundle+json",
                    "--expected-issuer",
                    "did:web:acgs.example",
                    "--external-aad-hex",
                    "deadbeef",
                    "--json",
                ]
            )
        )
        assert rc_verify == 0
        ver_payload = json.loads(capsys.readouterr().out)
        assert ver_payload["valid"] is True
        assert ver_payload["issuer"] == "did:web:acgs.example"
        assert ver_payload["subject"] == "system:bundle-demo"
        assert ver_payload["issued_at"] == 1764266000

        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "scitt-verify",
                        str(cose_path),
                        "--keys",
                        str(keys_path),
                        "--external-aad-hex",
                        "deadbeef",
                    ]
                )
            )
            == 0
        )
        assert "VALID SCITT COSE_Sign1" in capsys.readouterr().out

        # Wrong issuer, wrong content type, wrong external AAD, and tampered bytes all return rc=1
        for extra_args in (
            ["--expected-issuer", "did:web:other.example", "--external-aad-hex", "deadbeef"],
            ["--expected-content-type", "application/json", "--external-aad-hex", "deadbeef"],
            ["--external-aad-hex", "cafe"],
        ):
            rc_bad = cmd_bundle(
                parser.parse_args(
                    ["bundle", "scitt-verify", str(cose_path), "--keys", str(keys_path), "--json"]
                    + extra_args
                )
            )
            assert rc_bad == 1
            assert json.loads(capsys.readouterr().out)["valid"] is False

        tampered_cose = tmp_path / "tampered.cose"
        raw = bytearray(cose_path.read_bytes())
        raw[-1] ^= 0xFF
        tampered_cose.write_bytes(bytes(raw))
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "scitt-verify",
                        str(tampered_cose),
                        "--keys",
                        str(keys_path),
                        "--external-aad-hex",
                        "deadbeef",
                    ]
                )
            )
            == 1
        )
        assert "INVALID SCITT COSE_Sign1" in capsys.readouterr().err

        # Signing via --signing-key-env over a standalone SignedReceipt
        bundle_obj = json.loads(bundle_path.read_text(encoding="utf-8"))
        decision_path = tmp_path / "decision.json"
        decision_path.write_text(
            json.dumps(bundle_obj["decisions"][0]["signed_receipt"]),
            encoding="utf-8",
        )
        seed_bytes = b"\x7a" * 32
        monkeypatch.setenv("ACGS_TEST_SCITT_SEED", seed_bytes.hex())
        ext_signer = Ed25519ReceiptSigner.from_seed(seed_bytes, key_id="env-registrar-1")
        ext_keys_path = tmp_path / "ext_keys.json"
        ext_keys_path.write_text(
            json.dumps({ext_signer.key_id: ext_signer.public_key_hex()}),
            encoding="utf-8",
        )
        dec_cose = tmp_path / "decision.cose"
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "scitt-export",
                        str(decision_path),
                        "--signing-key-env",
                        "ACGS_TEST_SCITT_SEED",
                        "--key-id",
                        "env-registrar-1",
                        "--keys",
                        str(keys_path),
                        "--out",
                        str(dec_cose),
                    ]
                )
            )
            == 0
        )
        assert "Exported SCITT COSE_Sign1" in capsys.readouterr().out
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "scitt-verify",
                        str(dec_cose),
                        "--keys",
                        str(ext_keys_path),
                        "--json",
                    ]
                )
            )
            == 0
        )
        dec_ver = json.loads(capsys.readouterr().out)
        assert dec_ver["valid"] is True
        assert dec_ver["content_type"] == "application/acgs-decision-receipt+json"

    def test_scitt_cli_fail_closed_validation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        pytest.importorskip("cryptography")
        parser = build_parser()
        bundle_path = tmp_path / "bundle.json"
        keys_path = tmp_path / "keys.json"
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "demo",
                        "--out",
                        str(bundle_path),
                        "--keys-out",
                        str(keys_path),
                        "--json",
                    ]
                )
            )
            == 0
        )
        _ = capsys.readouterr()

        # Tampered bundle fails --keys pre-export verification
        tampered_bundle = copy.deepcopy(json.loads(bundle_path.read_text(encoding="utf-8")))
        tampered_bundle["decisions"][0]["proposed_method"] = "tampered"
        tampered_bundle_path = tmp_path / "tampered_bundle.json"
        tampered_bundle_path.write_text(json.dumps(tampered_bundle), encoding="utf-8")
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "scitt-export",
                        str(tampered_bundle_path),
                        "--demo-key",
                        "--keys",
                        str(keys_path),
                        "--out",
                        str(tmp_path / "out.cose"),
                    ]
                )
            )
            == 1
        )
        assert "pre-export verification" in capsys.readouterr().err

        # Bad env seed, bad hex AAD, and empty COSE file fail closed
        monkeypatch.setenv("ACGS_BAD_SEED", "not-64-hex")
        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "scitt-export",
                        str(bundle_path),
                        "--signing-key-env",
                        "ACGS_BAD_SEED",
                        "--out",
                        str(tmp_path / "out2.cose"),
                    ]
                )
            )
            == 1
        )
        assert "64-character hex" in capsys.readouterr().err

        assert (
            cmd_bundle(
                parser.parse_args(
                    [
                        "bundle",
                        "scitt-export",
                        str(bundle_path),
                        "--demo-key",
                        "--external-aad-hex",
                        "zz",
                        "--out",
                        str(tmp_path / "out3.cose"),
                    ]
                )
            )
            == 1
        )
        assert "hexadecimal" in capsys.readouterr().err

        empty_cose = tmp_path / "empty.cose"
        empty_cose.write_bytes(b"")
        assert (
            cmd_bundle(
                parser.parse_args(
                    ["bundle", "scitt-verify", str(empty_cose), "--keys", str(keys_path), "--json"]
                )
            )
            == 1
        )
        assert json.loads(capsys.readouterr().out)["valid"] is False
