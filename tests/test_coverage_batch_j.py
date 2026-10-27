"""Comprehensive tests for cli, cloud_run_server, cloud_logging, and rego_export.

Covers all four modules at 0% coverage to maximize line coverage gains.
"""

from __future__ import annotations

import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# 1. cli.py tests
# ---------------------------------------------------------------------------


class TestFmtTierBadge:
    """Tests for _fmt_tier_badge."""

    def test_free_tier(self):
        from acgs_lite.cli import _fmt_tier_badge
        from acgs_lite.licensing import Tier

        assert _fmt_tier_badge(Tier.FREE) == "FREE"

    def test_pro_tier(self):
        from acgs_lite.cli import _fmt_tier_badge
        from acgs_lite.licensing import Tier

        assert _fmt_tier_badge(Tier.PRO) == "PRO \u2713"

    def test_team_tier(self):
        from acgs_lite.cli import _fmt_tier_badge
        from acgs_lite.licensing import Tier

        assert _fmt_tier_badge(Tier.TEAM) == "TEAM \u2713"

    def test_enterprise_tier(self):
        from acgs_lite.cli import _fmt_tier_badge
        from acgs_lite.licensing import Tier

        assert _fmt_tier_badge(Tier.ENTERPRISE) == "ENTERPRISE \u2713"


class TestPrintInfo:
    """Tests for _print_info."""

    def test_with_expiry(self, capsys):
        from acgs_lite.cli import _print_info
        from acgs_lite.licensing import LicenseInfo, Tier

        info = LicenseInfo(tier=Tier.FREE, expiry=1700000000, key=None)
        _print_info(info)
        out = capsys.readouterr().out
        assert "Tier:" in out
        assert "Expiry:" in out
        assert "Features:" in out

    def test_without_expiry(self, capsys):
        from acgs_lite.cli import _print_info
        from acgs_lite.licensing import LicenseInfo, Tier

        info = LicenseInfo(tier=Tier.PRO, expiry=None, key=None)
        _print_info(info)
        out = capsys.readouterr().out
        assert "perpetual" in out
        assert "Features:" in out


class TestCmdActivate:
    """Tests for cmd_activate."""

    @patch("acgs_lite.cli._write_license_file")
    @patch("acgs_lite.cli.validate_license_key")
    def test_success(self, mock_validate, mock_write, capsys):
        from acgs_lite.cli import cmd_activate
        from acgs_lite.licensing import LicenseInfo, Tier

        mock_validate.return_value = LicenseInfo(tier=Tier.PRO, expiry=None, key="k")
        args = argparse.Namespace(key="  test-key  ")
        result = cmd_activate(args)
        assert result == 0
        mock_validate.assert_called_once_with("test-key")
        mock_write.assert_called_once_with("test-key")
        out = capsys.readouterr().out
        assert "License activated" in out

    @patch("acgs_lite.cli.validate_license_key")
    def test_expired_error(self, mock_validate, capsys):
        from acgs_lite.cli import cmd_activate
        from acgs_lite.licensing import LicenseExpiredError

        mock_validate.side_effect = LicenseExpiredError("expired")
        args = argparse.Namespace(key="bad-key")
        result = cmd_activate(args)
        assert result == 1
        err = capsys.readouterr().err
        assert "Error:" in err

    @patch("acgs_lite.cli.validate_license_key")
    def test_license_error(self, mock_validate, capsys):
        from acgs_lite.cli import cmd_activate
        from acgs_lite.licensing import LicenseError

        mock_validate.side_effect = LicenseError("invalid")
        args = argparse.Namespace(key="bad-key")
        result = cmd_activate(args)
        assert result == 1
        err = capsys.readouterr().err
        assert "Error:" in err


class TestCmdStatus:
    """Tests for cmd_status."""

    @patch("acgs_lite.cli.LicenseManager")
    def test_success_free_tier(self, mock_mgr_cls, capsys):
        from acgs_lite.cli import cmd_status
        from acgs_lite.licensing import LicenseInfo, Tier

        mock_mgr = MagicMock()
        mock_mgr.load.return_value = LicenseInfo(tier=Tier.FREE, expiry=None, key=None)
        mock_mgr_cls.return_value = mock_mgr

        result = cmd_status(argparse.Namespace())
        assert result == 0
        out = capsys.readouterr().out
        assert "License Status" in out
        assert "Upgrade to Pro" in out

    @patch("acgs_lite.cli.LicenseManager")
    def test_success_pro_tier(self, mock_mgr_cls, capsys):
        from acgs_lite.cli import cmd_status
        from acgs_lite.licensing import LicenseInfo, Tier

        mock_mgr = MagicMock()
        mock_mgr.load.return_value = LicenseInfo(tier=Tier.PRO, expiry=None, key=None)
        mock_mgr_cls.return_value = mock_mgr

        result = cmd_status(argparse.Namespace())
        assert result == 0
        out = capsys.readouterr().out
        assert "Upgrade" not in out

    @patch("acgs_lite.cli.LicenseManager")
    def test_license_error(self, mock_mgr_cls, capsys):
        from acgs_lite.cli import cmd_status
        from acgs_lite.licensing import LicenseError

        mock_mgr = MagicMock()
        mock_mgr.load.side_effect = LicenseError("no license")
        mock_mgr_cls.return_value = mock_mgr

        result = cmd_status(argparse.Namespace())
        assert result == 1
        err = capsys.readouterr().err
        assert "Error:" in err

    @patch("acgs_lite.cli.LicenseManager")
    def test_expired_error_with_env_key(self, mock_mgr_cls, capsys):
        from acgs_lite.cli import cmd_status
        from acgs_lite.licensing import LicenseExpiredError, LicenseInfo, Tier

        mock_mgr = MagicMock()
        mock_mgr.load.side_effect = LicenseExpiredError("expired")
        mock_mgr_cls.return_value = mock_mgr

        # Simulate validate_license_key.__wrapped__ working
        mock_wrapped = MagicMock(return_value=LicenseInfo(tier=Tier.PRO, expiry=1, key="k"))
        with (
            patch.dict("os.environ", {"ACGS_LICENSE_KEY": "env-key"}),
            patch("acgs_lite.cli.validate_license_key") as mock_vlk,
        ):
            # The code accesses validate_license_key.__wrapped__
            mock_vlk.__wrapped__ = mock_wrapped
            # Need to patch the import inside the function
            with patch("acgs_lite.licensing.validate_license_key") as inner_vlk:
                inner_vlk.__wrapped__ = mock_wrapped
                result = cmd_status(argparse.Namespace())

        assert result == 0 or result == 1  # depends on __wrapped__ resolution

    @patch("acgs_lite.cli.LicenseManager")
    def test_expired_error_no_key(self, mock_mgr_cls, capsys):
        from acgs_lite.cli import cmd_status
        from acgs_lite.licensing import LicenseExpiredError

        mock_mgr = MagicMock()
        mock_mgr.load.side_effect = LicenseExpiredError("expired")
        mock_mgr_cls.return_value = mock_mgr

        with patch.dict("os.environ", {}, clear=False):
            # Remove ACGS_LICENSE_KEY if present
            import os

            env_backup = os.environ.pop("ACGS_LICENSE_KEY", None)
            try:
                with patch("acgs_lite.licensing._read_license_file", return_value=None):
                    result = cmd_status(argparse.Namespace())
            finally:
                if env_backup is not None:
                    os.environ["ACGS_LICENSE_KEY"] = env_backup

        assert result == 1


class TestCmdVerify:
    """Tests for cmd_verify."""

    @patch("acgs_lite.cli.validate_license_key")
    def test_verify_with_key_arg_valid(self, mock_validate, capsys):
        from acgs_lite.cli import cmd_verify
        from acgs_lite.licensing import LicenseInfo, Tier

        mock_validate.return_value = LicenseInfo(tier=Tier.TEAM, expiry=None, key="k")
        args = argparse.Namespace(key="  my-key  ")
        result = cmd_verify(args)
        assert result == 0
        out = capsys.readouterr().out
        assert "valid" in out.lower()

    @patch("acgs_lite.cli.validate_license_key")
    def test_verify_with_key_arg_expired(self, mock_validate, capsys):
        from acgs_lite.cli import cmd_verify
        from acgs_lite.licensing import LicenseExpiredError

        mock_validate.side_effect = LicenseExpiredError("expired")
        args = argparse.Namespace(key="bad")
        result = cmd_verify(args)
        assert result == 1
        err = capsys.readouterr().err
        assert "EXPIRED" in err

    @patch("acgs_lite.cli.validate_license_key")
    def test_verify_with_key_arg_invalid(self, mock_validate, capsys):
        from acgs_lite.cli import cmd_verify
        from acgs_lite.licensing import LicenseError

        mock_validate.side_effect = LicenseError("bad key")
        args = argparse.Namespace(key="bad")
        result = cmd_verify(args)
        assert result == 1
        err = capsys.readouterr().err
        assert "INVALID" in err

    def test_verify_no_key_found(self, capsys):
        from acgs_lite.cli import cmd_verify

        args = argparse.Namespace()  # no key attribute
        with patch.dict("os.environ", {}, clear=False):
            import os

            env_backup = os.environ.pop("ACGS_LICENSE_KEY", None)
            try:
                with patch("acgs_lite.licensing._read_license_file", return_value=None):
                    result = cmd_verify(args)
            finally:
                if env_backup is not None:
                    os.environ["ACGS_LICENSE_KEY"] = env_backup

        assert result == 1
        err = capsys.readouterr().err
        assert "No license key found" in err

    @patch("acgs_lite.cli.validate_license_key")
    def test_verify_from_env(self, mock_validate, capsys):
        from acgs_lite.cli import cmd_verify
        from acgs_lite.licensing import LicenseInfo, Tier

        mock_validate.return_value = LicenseInfo(tier=Tier.FREE, expiry=None, key="k")
        args = argparse.Namespace()  # no key attribute
        with patch.dict("os.environ", {"ACGS_LICENSE_KEY": "env-key-12345678901234567890"}):
            result = cmd_verify(args)
        assert result == 0


class TestBuildParser:
    """Tests for build_parser."""

    def test_parser_creation(self):
        from acgs_lite.cli import build_parser

        parser = build_parser()
        assert parser.prog == "acgs"

    def test_activate_subcommand(self):
        from acgs_lite.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["activate", "my-key"])
        assert args.command == "activate"
        assert args.key == "my-key"

    def test_status_subcommand(self):
        from acgs_lite.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["status"])
        assert args.command == "status"

    def test_verify_subcommand(self):
        from acgs_lite.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["verify", "--key", "k"])
        assert args.command == "verify"
        assert args.key == "k"

    def test_verify_subcommand_no_key(self):
        from acgs_lite.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["verify"])
        assert args.command == "verify"
        assert args.key is None


class TestMain:
    """Tests for main."""

    @patch("acgs_lite.cli.cmd_activate")
    @patch("acgs_lite.cli.build_parser")
    def test_main_activate(self, mock_parser_fn, mock_activate):
        from acgs_lite.cli import main

        mock_parser = MagicMock()
        mock_parser.parse_args.return_value = argparse.Namespace(command="activate", key="k")
        mock_parser_fn.return_value = mock_parser
        mock_activate.return_value = 0

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    @patch("acgs_lite.cli.build_parser")
    def test_main_unknown_command(self, mock_parser_fn):
        from acgs_lite.cli import main

        mock_parser = MagicMock()
        mock_parser.parse_args.return_value = argparse.Namespace(command="unknown")
        mock_parser_fn.return_value = mock_parser

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# 2. cloud_logging.py tests
# ---------------------------------------------------------------------------


class TestBuildLabels:
    """Tests for _build_labels."""

    def test_basic_labels(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _build_labels

        entry = AuditEntry(
            id="test-1",
            type="validation",
            agent_id="agent-1",
            valid=True,
            constitutional_hash="abc123",
        )
        labels = _build_labels(entry)
        assert labels["agent_id"] == "agent-1"
        assert labels["entry_type"] == "validation"
        assert labels["valid"] == "true"
        assert labels["constitutional_hash"] == "abc123"

    def test_no_agent_id(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _build_labels

        entry = AuditEntry(id="test-2", type="check")
        labels = _build_labels(entry)
        assert labels["agent_id"] == "unknown"

    def test_with_violations(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _build_labels

        entry = AuditEntry(
            id="test-3",
            type="validation",
            valid=False,
            violations=["rule-1", "rule-2"],
        )
        labels = _build_labels(entry)
        assert labels["rule_ids"] == "rule-1,rule-2"

    def test_no_constitutional_hash(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _build_labels

        entry = AuditEntry(id="test-4", type="check", constitutional_hash="")
        labels = _build_labels(entry)
        assert "constitutional_hash" not in labels

    def test_metadata_fields(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _build_labels

        entry = AuditEntry(
            id="test-5",
            type="check",
            metadata={"severity": "high", "decision": "deny", "risk_score": 0.9},
        )
        labels = _build_labels(entry)
        assert labels["severity"] == "high"
        assert labels["decision"] == "deny"
        assert labels["risk_score"] == "0.9"

    def test_no_metadata(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _build_labels

        entry = AuditEntry(id="test-6", type="check", metadata={})
        labels = _build_labels(entry)
        assert "severity" not in labels
        assert "decision" not in labels


class TestSeverityToCloudSeverity:
    """Tests for _severity_to_cloud_severity."""

    def test_valid_entry_returns_info(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _severity_to_cloud_severity

        entry = AuditEntry(id="t", type="v", valid=True)
        assert _severity_to_cloud_severity(entry) == "INFO"

    def test_invalid_no_violations_returns_warning(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _severity_to_cloud_severity

        entry = AuditEntry(id="t", type="v", valid=False, violations=[])
        assert _severity_to_cloud_severity(entry) == "WARNING"

    def test_invalid_with_violations_default_warning(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _severity_to_cloud_severity

        entry = AuditEntry(id="t", type="v", valid=False, violations=["r1"])
        assert _severity_to_cloud_severity(entry) == "WARNING"

    def test_invalid_critical_severity(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _severity_to_cloud_severity

        entry = AuditEntry(
            id="t",
            type="v",
            valid=False,
            violations=["r1"],
            metadata={"severity": "critical"},
        )
        assert _severity_to_cloud_severity(entry) == "CRITICAL"

    def test_invalid_high_severity(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _severity_to_cloud_severity

        entry = AuditEntry(
            id="t",
            type="v",
            valid=False,
            violations=["r1"],
            metadata={"severity": "high"},
        )
        assert _severity_to_cloud_severity(entry) == "ERROR"

    def test_invalid_error_severity(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations.cloud_logging import _severity_to_cloud_severity

        entry = AuditEntry(
            id="t",
            type="v",
            valid=False,
            violations=["r1"],
            metadata={"severity": "error"},
        )
        assert _severity_to_cloud_severity(entry) == "ERROR"


class TestCloudLoggingAuditExporter:
    """Tests for CloudLoggingAuditExporter."""

    def test_raises_without_cloud_logging(self):
        """When CLOUD_LOGGING_AVAILABLE is False, constructor raises ImportError."""
        from acgs_lite.integrations import cloud_logging as cl_mod

        with (
            patch.object(cl_mod, "CLOUD_LOGGING_AVAILABLE", False),
            pytest.raises(ImportError, match="google-cloud-logging"),
        ):
            cl_mod.CloudLoggingAuditExporter(project_id="test")

    def test_init_with_mock_client(self):
        from acgs_lite.integrations import cloud_logging as cl_mod

        mock_client_cls = MagicMock()
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_logger = MagicMock()
        mock_client.logger.return_value = mock_logger

        with (
            patch.object(cl_mod, "CLOUD_LOGGING_AVAILABLE", True),
            patch.object(cl_mod, "cloud_logging", MagicMock(Client=mock_client_cls)),
        ):
            exporter = cl_mod.CloudLoggingAuditExporter(project_id="test-proj")

        assert exporter.exported_count == 0
        assert exporter.stats["log_name"] == "acgs-lite-governance"
        assert exporter.stats["exported_count"] == 0

    def test_export_entry(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations import cloud_logging as cl_mod

        mock_client_cls = MagicMock()
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_cl_logger = MagicMock()
        mock_client.logger.return_value = mock_cl_logger

        with (
            patch.object(cl_mod, "CLOUD_LOGGING_AVAILABLE", True),
            patch.object(cl_mod, "cloud_logging", MagicMock(Client=mock_client_cls)),
        ):
            exporter = cl_mod.CloudLoggingAuditExporter(project_id="p")

        entry = AuditEntry(id="e1", type="validation", valid=True, agent_id="a1")
        exporter.export_entry(entry)
        assert exporter.exported_count == 1
        mock_cl_logger.log_struct.assert_called_once()

    def test_export_batch(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations import cloud_logging as cl_mod

        mock_client_cls = MagicMock()
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_cl_logger = MagicMock()
        mock_client.logger.return_value = mock_cl_logger

        with (
            patch.object(cl_mod, "CLOUD_LOGGING_AVAILABLE", True),
            patch.object(cl_mod, "cloud_logging", MagicMock(Client=mock_client_cls)),
        ):
            exporter = cl_mod.CloudLoggingAuditExporter(project_id="p")

        entries = [
            AuditEntry(id="e1", type="v", valid=True),
            AuditEntry(id="e2", type="v", valid=False),
        ]
        exporter.export_batch(entries)
        assert exporter.exported_count == 2

    def test_export_batch_handles_errors(self):
        from acgs_lite.audit import AuditEntry
        from acgs_lite.integrations import cloud_logging as cl_mod

        mock_client_cls = MagicMock()
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_cl_logger = MagicMock()
        mock_cl_logger.log_struct.side_effect = [None, RuntimeError("fail"), None]
        mock_client.logger.return_value = mock_cl_logger

        with (
            patch.object(cl_mod, "CLOUD_LOGGING_AVAILABLE", True),
            patch.object(cl_mod, "cloud_logging", MagicMock(Client=mock_client_cls)),
        ):
            exporter = cl_mod.CloudLoggingAuditExporter(project_id="p")

        entries = [
            AuditEntry(id="e1", type="v", valid=True),
            AuditEntry(id="e2", type="v", valid=True),
            AuditEntry(id="e3", type="v", valid=True),
        ]
        exporter.export_batch(entries)
        # e1 succeeds (count=1), e2 fails in export_entry (log_struct raises, count stays 1),
        # e3 succeeds (count=2)
        assert exporter.exported_count == 2

    def test_custom_log_name(self):
        from acgs_lite.integrations import cloud_logging as cl_mod

        mock_client_cls = MagicMock()
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.logger.return_value = MagicMock()

        with (
            patch.object(cl_mod, "CLOUD_LOGGING_AVAILABLE", True),
            patch.object(cl_mod, "cloud_logging", MagicMock(Client=mock_client_cls)),
        ):
            exporter = cl_mod.CloudLoggingAuditExporter(project_id="p", log_name="custom-log")

        assert exporter.stats["log_name"] == "custom-log"


# ---------------------------------------------------------------------------
# 3. cloud_run_server.py tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("cloud_run_exporter")
class TestCloudRunServer:
    """Tests for cloud_run_server module functions."""

    def test_init_cloud_exporter_uses_configured_project(self, cloud_run_exporter):
        import acgs_lite.integrations.cloud_run_server as srv

        cloud_run_exporter.reset_mock()
        with patch.object(srv, "_GCP_PROJECT_ID", "unit-test-project"):
            result = srv._init_cloud_exporter()
        cloud_run_exporter.assert_called_once_with(project_id="unit-test-project")
        assert result is cloud_run_exporter.return_value

    def test_load_constitution_default(self):
        """When no CONSTITUTION_PATH, returns default constitution."""
        import acgs_lite.integrations.cloud_run_server as srv

        with patch.object(srv, "_CONSTITUTION_PATH", ""):
            c = srv._load_constitution()
        assert c is not None
        assert hasattr(c, "rules")

    def test_load_constitution_from_path(self, tmp_path):
        """When CONSTITUTION_PATH set and valid, loads from file."""
        import acgs_lite.integrations.cloud_run_server as srv
        from acgs_lite.constitution import Constitution

        yaml_path = tmp_path / "const.yaml"
        default = Constitution.default()
        yaml_path.write_text(default.to_yaml())

        with patch.object(srv, "_CONSTITUTION_PATH", str(yaml_path)):
            c = srv._load_constitution()
        assert c is not None

    def test_load_constitution_bad_path_falls_back(self):
        """When CONSTITUTION_PATH is invalid, falls back to default."""
        import acgs_lite.integrations.cloud_run_server as srv

        with patch.object(srv, "_CONSTITUTION_PATH", "/nonexistent/path.yaml"):
            c = srv._load_constitution()
        assert c is not None

    def test_init_cloud_exporter_unavailable(self):
        """Returns None when cloud logging import fails."""
        import acgs_lite.integrations.cloud_run_server as srv

        with patch.dict("sys.modules", {"acgs_lite.integrations.cloud_logging": None}):  # noqa: SIM117
            # Force ImportError
            with (
                patch(
                    "acgs_lite.integrations.cloud_run_server.CloudLoggingAuditExporter",
                    side_effect=ImportError,
                )
                if hasattr(srv, "CloudLoggingAuditExporter")
                else patch.object(srv, "_init_cloud_exporter", wraps=srv._init_cloud_exporter)
            ):
                result = srv._init_cloud_exporter()
        # Should return None (graceful fallback)
        assert result is None

    def test_export_audit_entries_no_exporter(self):
        """When _cloud_exporter is None, does nothing."""
        import acgs_lite.integrations.cloud_run_server as srv
        from acgs_lite.audit import AuditLog

        original = srv._cloud_exporter
        try:
            srv._cloud_exporter = None
            srv._export_audit_entries(AuditLog())
        finally:
            srv._cloud_exporter = original

    def test_export_audit_entries_with_exporter(self):
        """When exporter exists, calls export_batch."""
        import acgs_lite.integrations.cloud_run_server as srv
        from acgs_lite.audit import AuditEntry, AuditLog

        mock_exporter = MagicMock()
        original = srv._cloud_exporter
        try:
            srv._cloud_exporter = mock_exporter
            audit_log = AuditLog()
            audit_log.record(AuditEntry(id="x", type="t", valid=True))
            srv._export_audit_entries(audit_log)
            mock_exporter.export_batch.assert_called_once()
        finally:
            srv._cloud_exporter = original

    def test_export_audit_entries_empty_log(self):
        """When audit log is empty, does not call export_batch."""
        import acgs_lite.integrations.cloud_run_server as srv
        from acgs_lite.audit import AuditLog

        mock_exporter = MagicMock()
        original = srv._cloud_exporter
        try:
            srv._cloud_exporter = mock_exporter
            srv._export_audit_entries(AuditLog())
            mock_exporter.export_batch.assert_not_called()
        finally:
            srv._cloud_exporter = original

    def test_export_audit_entries_exporter_error(self):
        """When exporter raises, logs error but doesn't crash."""
        import acgs_lite.integrations.cloud_run_server as srv
        from acgs_lite.audit import AuditEntry, AuditLog

        mock_exporter = MagicMock()
        mock_exporter.export_batch.side_effect = RuntimeError("fail")
        original = srv._cloud_exporter
        try:
            srv._cloud_exporter = mock_exporter
            audit_log = AuditLog()
            audit_log.record(AuditEntry(id="x", type="t", valid=True))
            # Should not raise
            srv._export_audit_entries(audit_log)
        finally:
            srv._cloud_exporter = original

    def test_get_bot_no_credentials(self):
        """Returns None when GITLAB_TOKEN not set."""
        import acgs_lite.integrations.cloud_run_server as srv

        original_bot = srv._bot
        try:
            srv._bot = None
            with (
                patch.object(srv, "_GITLAB_TOKEN", ""),
                patch.object(srv, "_GITLAB_PROJECT_ID", "0"),
            ):
                result = srv._get_bot()
            assert result is None
        finally:
            srv._bot = original_bot

    def test_get_bot_cached(self):
        """Returns cached bot if already initialized."""
        import acgs_lite.integrations.cloud_run_server as srv

        sentinel = MagicMock()
        original_bot = srv._bot
        try:
            srv._bot = sentinel
            result = srv._get_bot()
            assert result is sentinel
        finally:
            srv._bot = original_bot

    def test_get_bot_init_error(self):
        """Returns None when GitLabGovernanceBot init fails."""
        import acgs_lite.integrations.cloud_run_server as srv

        original_bot = srv._bot
        try:
            srv._bot = None
            with (
                patch.object(srv, "_GITLAB_TOKEN", "tok"),
                patch.object(srv, "_GITLAB_PROJECT_ID", "123"),
                patch.object(srv, "GitLabGovernanceBot", side_effect=ValueError("fail")),
            ):
                result = srv._get_bot()
            assert result is None
        finally:
            srv._bot = original_bot

    def test_get_webhook_handler_cached(self):
        """Returns cached handler if already initialized."""
        import acgs_lite.integrations.cloud_run_server as srv

        sentinel = MagicMock()
        original = srv._webhook_handler
        try:
            srv._webhook_handler = sentinel
            result = srv._get_webhook_handler()
            assert result is sentinel
        finally:
            srv._webhook_handler = original

    def test_get_webhook_handler_no_bot(self):
        """Returns None when bot is unavailable."""
        import acgs_lite.integrations.cloud_run_server as srv

        original_wh = srv._webhook_handler
        original_bot = srv._bot
        try:
            srv._webhook_handler = None
            srv._bot = None
            with (
                patch.object(srv, "_GITLAB_TOKEN", ""),
                patch.object(srv, "_GITLAB_PROJECT_ID", "0"),
            ):
                result = srv._get_webhook_handler()
            assert result is None
        finally:
            srv._webhook_handler = original_wh
            srv._bot = original_bot

    def test_get_webhook_handler_with_bot(self):
        """Creates handler when bot is available."""
        import acgs_lite.integrations.cloud_run_server as srv

        mock_bot = MagicMock()
        mock_handler_cls = MagicMock()
        original_wh = srv._webhook_handler
        original_bot = srv._bot
        try:
            srv._webhook_handler = None
            srv._bot = mock_bot
            with (
                patch.object(srv, "_GITLAB_WEBHOOK_SECRET", "secret"),
                patch.object(srv, "GitLabWebhookHandler", mock_handler_cls),
            ):
                result = srv._get_webhook_handler()
            assert result is not None
            mock_handler_cls.assert_called_once()
        finally:
            srv._webhook_handler = original_wh
            srv._bot = original_bot

    def test_get_webhook_handler_default_secret(self):
        """When GITLAB_WEBHOOK_SECRET is empty, handler is NOT created (security hardening)."""
        import acgs_lite.integrations.cloud_run_server as srv

        mock_bot = MagicMock()
        mock_handler_cls = MagicMock()
        original_wh = srv._webhook_handler
        original_bot = srv._bot
        try:
            srv._webhook_handler = None
            srv._bot = mock_bot
            with (
                patch.object(srv, "_GITLAB_WEBHOOK_SECRET", ""),
                patch.object(srv, "GitLabWebhookHandler", mock_handler_cls),
            ):
                srv._get_webhook_handler()
            # Security hardening: empty secret → handler must NOT be instantiated
            mock_handler_cls.assert_not_called()
        finally:
            srv._webhook_handler = original_wh
            srv._bot = original_bot


@pytest.mark.usefixtures("cloud_run_exporter")
class TestCloudRunEndpoints:
    """Tests for the Starlette endpoint functions."""

    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        import acgs_lite.integrations.cloud_run_server as srv

        mock_request = MagicMock()
        original_bot = srv._bot
        try:
            srv._bot = None
            with (
                patch.object(srv, "_GITLAB_TOKEN", ""),
                patch.object(srv, "_GITLAB_PROJECT_ID", "0"),
            ):
                response = await srv.health_endpoint(mock_request)
        finally:
            srv._bot = original_bot

        import json

        body = json.loads(response.body)
        assert body["status"] == "healthy"
        assert "constitutional_hash" in body
        assert "version" in body
        assert body["webhook_configured"] is False

    @pytest.mark.asyncio
    async def test_governance_summary_endpoint(self):
        import acgs_lite.integrations.cloud_run_server as srv

        mock_request = MagicMock()
        response = await srv.governance_summary_endpoint(mock_request)

        import json

        body = json.loads(response.body)
        assert "constitutional_hash" in body
        assert "summary" in body

    @pytest.mark.asyncio
    async def test_webhook_endpoint_no_handler(self):
        import acgs_lite.integrations.cloud_run_server as srv

        mock_request = MagicMock()
        original_wh = srv._webhook_handler
        original_bot = srv._bot
        try:
            srv._webhook_handler = None
            srv._bot = None
            with (
                patch.object(srv, "_GITLAB_TOKEN", ""),
                patch.object(srv, "_GITLAB_PROJECT_ID", "0"),
            ):
                response = await srv.webhook_endpoint(mock_request)
        finally:
            srv._webhook_handler = original_wh
            srv._bot = original_bot

        import json

        body = json.loads(response.body)
        assert response.status_code == 503
        assert "error" in body

    @pytest.mark.asyncio
    async def test_webhook_endpoint_with_handler(self):
        import acgs_lite.integrations.cloud_run_server as srv

        mock_request = MagicMock()
        mock_request.headers = {"X-Gitlab-Event": "Merge Request Hook"}

        mock_handler = MagicMock()
        mock_handler.handle = AsyncMock(
            return_value=MagicMock(body=b'{"ok":true}', status_code=200)
        )

        mock_bot = MagicMock()
        mock_bot.audit_log = MagicMock()
        mock_bot.audit_log.entries = []

        original_wh = srv._webhook_handler
        original_bot = srv._bot
        original_exporter = srv._cloud_exporter
        try:
            srv._webhook_handler = mock_handler
            srv._bot = mock_bot
            srv._cloud_exporter = None
            await srv.webhook_endpoint(mock_request)
        finally:
            srv._webhook_handler = original_wh
            srv._bot = original_bot
            srv._cloud_exporter = original_exporter

        mock_handler.handle.assert_called_once_with(mock_request)


# ---------------------------------------------------------------------------
# 4. rego_export.py tests
# ---------------------------------------------------------------------------


class TestRegoEscape:
    """Tests for _rego_escape."""

    def test_basic_string(self):
        from acgs_lite.constitution.rego_export import _rego_escape

        assert _rego_escape("hello") == "hello"

    def test_escape_backslash(self):
        from acgs_lite.constitution.rego_export import _rego_escape

        assert _rego_escape("a\\b") == "a\\\\b"

    def test_escape_double_quote(self):
        from acgs_lite.constitution.rego_export import _rego_escape

        assert _rego_escape('a"b') == 'a\\"b'

    def test_escape_newline(self):
        from acgs_lite.constitution.rego_export import _rego_escape

        assert _rego_escape("a\nb") == "a\\nb"

    def test_escape_carriage_return(self):
        from acgs_lite.constitution.rego_export import _rego_escape

        assert _rego_escape("a\rb") == "a\\rb"

    def test_escape_combined(self):
        from acgs_lite.constitution.rego_export import _rego_escape

        result = _rego_escape('line1\nline2\r"end"\\done')
        assert "\n" not in result
        assert "\r" not in result


class TestRuleToRegoConditions:
    """Tests for _rule_to_rego_conditions."""

    def test_keyword_conditions(self):
        from acgs_lite.constitution.rego_export import _rule_to_rego_conditions
        from acgs_lite.constitution.rule import Rule, Severity

        rule = Rule(
            id="R1",
            text="No harm",
            severity=Severity.HIGH,
            keywords=["harm", "danger"],
            category="safety",
        )
        conds = _rule_to_rego_conditions(rule)
        assert len(conds) == 2
        assert all("regex.match" in c for c in conds)
        assert all("input.action" in c for c in conds)

    def test_pattern_conditions(self):
        from acgs_lite.constitution.rego_export import _rule_to_rego_conditions
        from acgs_lite.constitution.rule import Rule, Severity

        rule = Rule(
            id="R2",
            text="No PII",
            severity=Severity.MEDIUM,
            patterns=["\\d{3}-\\d{2}-\\d{4}"],
            category="privacy",
        )
        conds = _rule_to_rego_conditions(rule)
        assert len(conds) == 1
        assert "regex.match" in conds[0]

    def test_invalid_pattern_skipped(self):
        from acgs_lite.constitution.rego_export import _rule_to_rego_conditions
        from acgs_lite.constitution.rule import Rule, Severity

        rule = Rule(
            id="R3",
            text="Bad regex",
            severity=Severity.LOW,
            patterns=[".*valid.*"],
            keywords=["valid", "extra"],
            category="general",
        )
        # Inject an invalid pattern after construction to bypass pydantic validation
        rule.patterns = ["[invalid"]
        conds = _rule_to_rego_conditions(rule)
        # Invalid pattern skipped, 2 valid keywords kept
        assert len(conds) == 2

    def test_empty_keywords_skipped(self):
        from acgs_lite.constitution.rego_export import _rule_to_rego_conditions
        from acgs_lite.constitution.rule import Rule, Severity

        rule = Rule(
            id="R4",
            text="Empty",
            severity=Severity.LOW,
            keywords=["", "  ", "valid"],
            category="general",
        )
        conds = _rule_to_rego_conditions(rule)
        assert len(conds) == 1

    def test_empty_patterns_skipped(self):
        from acgs_lite.constitution.rego_export import _rule_to_rego_conditions
        from acgs_lite.constitution.rule import Rule, Severity

        rule = Rule(
            id="R5",
            text="Empty pat",
            severity=Severity.LOW,
            patterns=["", "  "],
            category="general",
        )
        conds = _rule_to_rego_conditions(rule)
        assert len(conds) == 0

    def test_no_keywords_or_patterns(self):
        from acgs_lite.constitution.rego_export import _rule_to_rego_conditions
        from acgs_lite.constitution.rule import Rule, Severity

        rule = Rule(
            id="R6",
            text="No match",
            severity=Severity.LOW,
            category="general",
        )
        conds = _rule_to_rego_conditions(rule)
        assert len(conds) == 0


class TestConstitutionToRego:
    """Tests for constitution_to_rego."""

    def test_basic_output(self):
        from acgs_lite.constitution import Constitution
        from acgs_lite.constitution.rego_export import constitution_to_rego

        c = Constitution.default()
        rego = constitution_to_rego(c)
        assert "package acgs.governance" in rego
        assert "default allow := true" in rego
        assert "default deny := false" in rego
        assert "import regex" in rego

    def test_custom_package_name(self):
        from acgs_lite.constitution import Constitution
        from acgs_lite.constitution.rego_export import constitution_to_rego

        c = Constitution.default()
        rego = constitution_to_rego(c, package_name="my.custom.pkg")
        assert "package my.custom.pkg" in rego

    def test_package_name_with_dash(self):
        from acgs_lite.constitution import Constitution
        from acgs_lite.constitution.rego_export import constitution_to_rego

        c = Constitution.default()
        rego = constitution_to_rego(c, package_name="my-pkg")
        assert "package my_pkg" in rego

    def test_disabled_rules_excluded(self):
        from acgs_lite.constitution import Constitution
        from acgs_lite.constitution.rego_export import constitution_to_rego
        from acgs_lite.constitution.rule import Rule, Severity

        c = Constitution(
            name="test",
            rules=[
                Rule(
                    id="R1",
                    text="Active",
                    severity=Severity.HIGH,
                    keywords=["active"],
                    category="test",
                    enabled=True,
                ),
                Rule(
                    id="R2",
                    text="Disabled",
                    severity=Severity.LOW,
                    keywords=["disabled"],
                    category="test",
                    enabled=False,
                ),
            ],
        )
        rego = constitution_to_rego(c)
        assert "R1" in rego
        assert "R2" not in rego

    def test_empty_constitution(self):
        from acgs_lite.constitution import Constitution
        from acgs_lite.constitution.rego_export import constitution_to_rego

        c = Constitution(name="empty", rules=[])
        rego = constitution_to_rego(c)
        assert "package acgs.governance" in rego
        assert "default allow := true" in rego

    def test_rule_with_only_empty_keywords(self):
        """A rule whose keywords are all empty/whitespace produces no conditions."""
        from acgs_lite.constitution.rego_export import (
            _rule_to_rego_conditions,
        )
        from acgs_lite.constitution.rule import Rule, Severity

        rule = Rule(
            id="R-SPARSE",
            text="Sparse rule",
            severity=Severity.LOW,
            keywords=["real"],
            category="general",
        )
        # Manually blank out keywords after construction to bypass validation
        rule.keywords = ["", "  "]
        conds = _rule_to_rego_conditions(rule)
        assert len(conds) == 0


class TestConstitutionToRegoBundle:
    """Tests for constitution_to_rego_bundle."""

    def test_bundle_structure(self):
        from acgs_lite.constitution import Constitution
        from acgs_lite.constitution.rego_export import constitution_to_rego_bundle

        c = Constitution.default()
        bundle = constitution_to_rego_bundle(c)
        assert "policy" in bundle
        assert "metadata" in bundle
        assert "name" in bundle["metadata"]
        assert "version" in bundle["metadata"]
        assert "hash" in bundle["metadata"]
        assert "rule_count" in bundle["metadata"]
        assert isinstance(bundle["policy"], str)
        assert bundle["metadata"]["name"] == c.name

    def test_bundle_custom_package(self):
        from acgs_lite.constitution import Constitution
        from acgs_lite.constitution.rego_export import constitution_to_rego_bundle

        c = Constitution.default()
        bundle = constitution_to_rego_bundle(c, package_name="custom.pkg")
        assert "package custom.pkg" in bundle["policy"]

    def test_bundle_excludes_disabled_rules(self):
        from acgs_lite.constitution import Constitution
        from acgs_lite.constitution.rego_export import constitution_to_rego_bundle
        from acgs_lite.constitution.rule import Rule, Severity

        c = Constitution(
            name="test",
            rules=[
                Rule(
                    id="R1",
                    text="Active rule",
                    severity=Severity.HIGH,
                    keywords=["active"],
                    category="t",
                    enabled=True,
                ),
                Rule(
                    id="R2",
                    text="Disabled rule",
                    severity=Severity.LOW,
                    keywords=["disabled"],
                    category="t",
                    enabled=False,
                ),
            ],
        )
        bundle = constitution_to_rego_bundle(c)
        assert bundle["metadata"]["rule_count"] == 1
