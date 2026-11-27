# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.

"""Dispatcher-level tests for `acgs demo` CLI command."""

from __future__ import annotations

import json

import pytest

from acgs_lite.cli import build_parser, cmd_demo


class TestCmdDemo:
    """End-to-end CLI tests for `acgs demo`."""

    def test_demo_text_mode_exits_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        parser = build_parser()
        args = parser.parse_args(["demo"])
        rc = cmd_demo(args)
        out = capsys.readouterr().out
        assert rc == 0
        assert "ALLOW + Signed Receipts" in out
        assert "At-Most-Once + UNKNOWN" in out
        assert "DENY Before Side Effect" in out
        assert "Missing/Denied Receipt Gate" in out
        assert "MACI Separation of Duties" in out
        assert "ALL 5 SCENARIOS PASSED" in out

    def test_demo_json_mode_verifies_all_scenarios(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        parser = build_parser()
        args = parser.parse_args(["demo", "--json"])
        rc = cmd_demo(args)
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["all_passed"] is True
        scenarios = payload["scenarios"]

        allow = scenarios["allow_and_signed_receipts"]
        assert allow["passed"] is True
        assert allow["provider_calls"] == 1
        assert allow["outcome"] == "done"

        retry = scenarios["at_most_once_and_unknown_reconcile"]
        assert retry["passed"] is True
        assert retry["retry_provider_calls_added"] == 0
        assert retry["timeout_held_state"] == "unknown"
        assert retry["unknown_blocked_receipt"] is True
        assert retry["other_key_unblocked"] is True
        assert retry["reconciled_state"] == "done"

        deny = scenarios["deny_before_side_effect"]
        assert deny["passed"] is True
        assert deny["valid"] is False
        assert deny["provider_calls_added"] == 0

        missing = scenarios["missing_or_denied_receipt_refusal"]
        assert missing["passed"] is True
        assert missing["missing_receipt_refused"] is True
        assert missing["denied_receipt_refused"] is True

        maci = scenarios["maci_separation_of_duties"]
        assert maci["passed"] is True
        assert maci["self_validation_blocked"] is True
        assert maci["proposer_execute_blocked"] is True

        if payload["crypto_signing_available"]:
            assert allow["decision_signature_verified"] is True
            assert allow["outcome_signature_verified"] is True
            assert retry["reconciled_signature_verified"] is True

    def test_demo_without_crypto_falls_back_without_faking_signatures(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from acgs_lite.commands import demo as demo_cmd
        from acgs_lite.legitimacy import Ed25519ReceiptSigner, ReceiptSigningUnavailable

        def _missing_crypto(*args: object, **kwargs: object) -> object:
            raise ReceiptSigningUnavailable("no cryptography")

        monkeypatch.setattr(Ed25519ReceiptSigner, "from_seed", staticmethod(_missing_crypto))
        args = build_parser().parse_args(["demo"])
        rc = demo_cmd.handler(args)
        captured = capsys.readouterr()
        assert rc == 0
        assert "Ed25519 signing skipped" in captured.err
        assert "decision=None, outcome=None" in captured.out
        assert "ALL 5 SCENARIOS PASSED" in captured.out
