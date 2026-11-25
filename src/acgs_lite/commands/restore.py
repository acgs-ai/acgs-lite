# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Restore active constitution from a hot-backup artifact and re-validate.

Locked argv: ``acgs restore --bundle-id ID --backup-path PATH [--system-id ID]
[--dry-run] [--json] [--debug]``.

Behavior:
    - Atomic move (``os.replace``) of ``--backup-path`` over the active
      constitution path.
    - Re-runs :func:`validate_production_profile` against the restored profile.
    - Asserts post-restore ``constitutional_hash`` matches the active profile's
      expected hash.

Exit codes:
    - 0: success
    - 2: validation rejected backup (hash mismatch, parse failure)
    - 3: I/O failure (file not found, permission, disk)
    - 4: hash mismatch post-restore
    - 64: usage error (argparse default)

Error format: ``{problem} | cause: {cause} | fix: {next-step} | docs: <URL>``.

Per ``security.md`` rules, raw exception strings are never echoed for the
credential/path domain — only ``type(exc).__name__`` is logged unless ``--debug``
is passed. Path/hash details are only included when ``--debug`` is set.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from acgs_lite.constitution import Constitution
from acgs_lite.production import (
    ProductionProfile,
    ProductionProfileError,
    validate_production_profile,
)

EXIT_OK = 0
EXIT_VALIDATION = 2
EXIT_IO = 3
EXIT_HASH_MISMATCH = 4
EXIT_USAGE = 64

_DOCS_URL = "https://acgs.ai/docs/restore"


class RestoreError(Exception):
    """Typed restore error with stable code + redacted public message."""

    def __init__(self, code: int, problem: str, cause: str, fix: str) -> None:
        super().__init__(problem)
        self.code = code
        self.problem = problem
        self.cause = cause
        self.fix = fix

    def public_message(self) -> str:
        """Return the redacted single-line public-facing error message."""
        return f"{self.problem} | cause: {self.cause} | fix: {self.fix} | docs: {_DOCS_URL}"


@dataclass(frozen=True)
class _RestoreInputs:
    """Resolved restore inputs after flag/env precedence."""

    bundle_id: str
    backup_path: Path
    system_id: str | None
    dry_run: bool
    json_out: bool
    debug: bool


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the ``restore`` subcommand on the top-level CLI parser."""
    p = sub.add_parser(
        "restore",
        help=(
            "Restore active constitution from a hot-backup artifact "
            "and re-validate the production profile"
        ),
    )
    p.add_argument(
        "--bundle-id",
        required=True,
        help="Rollback bundle identifier (must match active profile)",
    )
    p.add_argument(
        "--backup-path",
        required=False,
        default=None,
        help=(
            "Path to the hot-backup constitution artifact. "
            "If omitted, falls back to LEGALGUARD_BACKUP_PATH env var."
        ),
    )
    p.add_argument(
        "--system-id",
        required=False,
        default=None,
        help="Optional system identifier (for audit + halt cross-reference)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the backup without mutating the active artifact",
    )
    p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="Emit machine-readable JSON output",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Include path + hash details in error messages (otherwise redacted)",
    )


def _resolve_inputs(args: argparse.Namespace) -> _RestoreInputs:
    """Resolve inputs with explicit-flag-wins-over-env precedence."""
    backup_arg: str | None = getattr(args, "backup_path", None)
    if backup_arg:
        backup_path_str = backup_arg
    else:
        env_backup = os.environ.get("LEGALGUARD_BACKUP_PATH")
        if not env_backup:
            raise RestoreError(
                code=EXIT_USAGE,
                problem="No backup path provided",
                cause="--backup-path missing and LEGALGUARD_BACKUP_PATH unset",
                fix="pass --backup-path PATH or set LEGALGUARD_BACKUP_PATH",
            )
        backup_path_str = env_backup

    return _RestoreInputs(
        bundle_id=args.bundle_id,
        backup_path=Path(backup_path_str),
        system_id=getattr(args, "system_id", None),
        dry_run=bool(getattr(args, "dry_run", False)),
        json_out=bool(getattr(args, "json_out", False)),
        debug=bool(getattr(args, "debug", False)),
    )


def _load_active_profile() -> ProductionProfile:
    """Load the active production profile.

    The profile loader is dependency-injected via
    ``ACGS_PRODUCTION_PROFILE_LOADER`` to keep this command testable without
    requiring legalguard to be installed. The default loader raises
    ``RestoreError`` since no production profile exists in acgs-lite alone.
    """
    loader_path = os.environ.get("ACGS_PRODUCTION_PROFILE_LOADER")
    if not loader_path:
        raise RestoreError(
            code=EXIT_USAGE,
            problem="No active production profile loader configured",
            cause="ACGS_PRODUCTION_PROFILE_LOADER env var unset",
            fix="set ACGS_PRODUCTION_PROFILE_LOADER=module.path:callable",
        )

    try:
        module_name, _, attr = loader_path.partition(":")
        if not module_name or not attr:
            raise ValueError("loader spec must be 'module.path:callable'")
        import importlib

        module = importlib.import_module(module_name)
        loader = getattr(module, attr)
        profile = loader()
    except RestoreError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise RestoreError(
            code=EXIT_USAGE,
            problem="Failed to load active production profile",
            cause=type(exc).__name__,
            fix="check ACGS_PRODUCTION_PROFILE_LOADER points to a valid callable",
        ) from None

    if not isinstance(profile, ProductionProfile):
        raise RestoreError(
            code=EXIT_USAGE,
            problem="Active production profile loader returned wrong type",
            cause=f"expected ProductionProfile, got {type(profile).__name__}",
            fix="ensure the loader callable returns acgs_lite.ProductionProfile",
        )
    return profile


def _emit(result: dict[str, Any], inputs: _RestoreInputs) -> None:
    """Emit human or JSON output."""
    if inputs.json_out:
        print(json.dumps(result, indent=2, default=str))
        return

    status = "OK" if result.get("ok") else "ERROR"
    print(f"restore: {status}")
    for key in ("bundle_id", "system_id", "dry_run", "constitutional_hash"):
        if key in result and result[key] is not None:
            print(f"  {key}: {result[key]}")
    if not result.get("ok") and result.get("error"):
        print(f"  error: {result['error']}", file=sys.stderr)


def cmd_restore(args: argparse.Namespace) -> int:
    """Restore active constitution from a hot-backup artifact and re-validate."""
    try:
        inputs = _resolve_inputs(args)
    except RestoreError as exc:
        # No inputs resolved → can't honour --json. Emit plain text.
        print(exc.public_message(), file=sys.stderr)
        return exc.code

    try:
        profile = _load_active_profile()

        if profile.rollback_bundle_id != inputs.bundle_id:
            raise RestoreError(
                code=EXIT_VALIDATION,
                problem="Bundle ID does not match active profile",
                cause="rollback_bundle_id mismatch",
                fix=(
                    f"pass --bundle-id matching active profile "
                    f"(expected: {profile.rollback_bundle_id if inputs.debug else 'REDACTED'})"
                ),
            )

        if not inputs.backup_path.exists():
            raise RestoreError(
                code=EXIT_IO,
                problem="Backup artifact not found",
                cause="path does not exist",
                fix=(
                    f"verify backup at {inputs.backup_path}"
                    if inputs.debug
                    else "verify backup path or LEGALGUARD_BACKUP_PATH env var"
                ),
            )
        if not inputs.backup_path.is_file():
            raise RestoreError(
                code=EXIT_IO,
                problem="Backup artifact is not a file",
                cause="path is not a regular file",
                fix="point --backup-path at a constitution YAML file",
            )

        # Validate the backup parses as a Constitution before swapping.
        try:
            backup_constitution = Constitution.from_yaml(inputs.backup_path)
        except Exception as exc:  # noqa: BLE001
            raise RestoreError(
                code=EXIT_VALIDATION,
                problem="Backup artifact failed to parse",
                cause=type(exc).__name__,
                fix="check backup file is valid constitution YAML",
            ) from None

        if backup_constitution.hash != profile.expected_constitutional_hash:
            raise RestoreError(
                code=EXIT_VALIDATION,
                problem="Backup constitutional hash does not match expected",
                cause="hash mismatch on backup",
                fix=(
                    f"backup hash {backup_constitution.hash} != "
                    f"expected {profile.expected_constitutional_hash}"
                    if inputs.debug
                    else "regenerate or replace backup with a known-good artifact"
                ),
            )

        active_path = Path(profile.constitution_artifact_path)

        if inputs.dry_run:
            result_payload: dict[str, Any] = {
                "ok": True,
                "dry_run": True,
                "bundle_id": inputs.bundle_id,
                "system_id": inputs.system_id,
                "constitutional_hash": backup_constitution.hash,
                "active_path": str(active_path) if inputs.debug else "REDACTED",
                "backup_path": str(inputs.backup_path) if inputs.debug else "REDACTED",
            }
            _emit(result_payload, inputs)
            return EXIT_OK

        # Atomic restore: copy backup to a sibling temp file in the active
        # directory, then os.replace the temp file over the active path. This
        # preserves the backup artifact (so re-validation can still find it)
        # while keeping the active-path swap atomic on POSIX.
        try:
            active_dir = active_path.parent or Path(".")
            with tempfile.NamedTemporaryFile(
                mode="wb",
                delete=False,
                dir=str(active_dir),
                prefix=".restore-",
                suffix=".tmp",
            ) as staged:
                staged_path = Path(staged.name)
            shutil.copyfile(inputs.backup_path, staged_path)
            os.replace(staged_path, active_path)
        except OSError as exc:
            raise RestoreError(
                code=EXIT_IO,
                problem="Atomic move of backup over active artifact failed",
                cause=type(exc).__name__,
                fix="check filesystem permissions and that paths are on same FS",
            ) from None

        # Re-validate post-restore.
        try:
            validation = validate_production_profile(profile)
        except ProductionProfileError as exc:
            raise RestoreError(
                code=EXIT_VALIDATION,
                problem="Production profile validation rejected restored backup",
                cause=type(exc).__name__,
                fix="inspect logs and roll forward via constitution lifecycle",
            ) from None

        if validation.constitutional_hash != profile.expected_constitutional_hash:
            raise RestoreError(
                code=EXIT_HASH_MISMATCH,
                problem="Post-restore constitutional hash mismatch",
                cause="hash drift after restore",
                fix=(
                    f"got {validation.constitutional_hash}, "
                    f"expected {profile.expected_constitutional_hash}"
                    if inputs.debug
                    else "halt the system and engage incident response"
                ),
            )

        result_payload = {
            "ok": True,
            "dry_run": False,
            "bundle_id": inputs.bundle_id,
            "system_id": inputs.system_id,
            "constitutional_hash": validation.constitutional_hash,
            "active_path": str(active_path) if inputs.debug else "REDACTED",
        }
        _emit(result_payload, inputs)
        return EXIT_OK

    except RestoreError as exc:
        public = exc.public_message()
        if inputs.json_out:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": public,
                        "code": exc.code,
                        "bundle_id": inputs.bundle_id,
                    },
                    indent=2,
                ),
            )
        else:
            print(public, file=sys.stderr)
        return exc.code


# Backward-compatible alias for the top-level command map in cli.py.
handler = cmd_restore
