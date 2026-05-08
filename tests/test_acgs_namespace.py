"""Smoke tests for the canonical ``acgs`` import namespace.

These tests verify that ``import acgs`` resolves from *this* package and that
the primary public API surface is importable without any ambient ``acgs``
site-packages installation.

The subprocess tests use ``python -S`` (no site-packages) with only ``src/``
on sys.path to prove clean-install correctness.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC = str(Path(__file__).parent.parent / "src")


class TestAcgsNamespaceImport:
    """``acgs`` resolves from this package without ambient site-packages."""

    def test_import_acgs_top_level(self) -> None:
        import acgs  # noqa: F401

        assert acgs.__version__

    def test_canonical_surface_importable(self) -> None:
        from acgs import Constitution, GovernedAgent, MACIRole  # noqa: F401

        assert Constitution
        assert GovernedAgent
        assert MACIRole

    def test_audit_types_importable(self) -> None:
        from acgs import AuditEntry, AuditLog  # noqa: F401

        assert AuditLog
        assert AuditEntry

    def test_set_license_importable(self) -> None:
        from acgs import set_license  # noqa: F401

        assert callable(set_license)

    def test_constitutional_hash_present(self) -> None:
        import acgs

        assert acgs.__constitutional_hash__

    def test_version_matches_acgs_lite(self) -> None:
        import acgs
        import acgs_lite

        assert acgs.__version__ == acgs_lite.__version__

    def test_validationresult_is_canonical_model_type(self) -> None:
        import acgs_lite.engine as engine
        from acgs_lite.engine.audit_runtime import _FastAuditLog as RuntimeFastAuditLog
        from acgs_lite.engine.core import GovernanceEngine as CoreGovernanceEngine
        from acgs_lite.engine.models import ValidationResult as ModelValidationResult
        from acgs_lite.engine.types import ValidationResult as TypesValidationResult

        assert engine.GovernanceEngine is CoreGovernanceEngine
        assert engine.ValidationResult is ModelValidationResult
        assert TypesValidationResult is ModelValidationResult
        assert engine.models.ValidationResult is ModelValidationResult
        assert engine.types.ValidationResult is ModelValidationResult
        assert engine._FastAuditLog is RuntimeFastAuditLog

    def test_clean_env_import_resolves_from_src(self) -> None:
        """Prove ``import acgs`` resolves from this package's src/, not an ambient install."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); import acgs; print(acgs.__file__)",
                SRC,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"import acgs failed:\n{result.stderr}"
        resolved = result.stdout.strip()
        assert SRC in resolved, (
            f"acgs resolved from outside src/: {resolved!r}\n"
            "This means the package is resolving from an ambient site-packages install, "
            "not from this repo."
        )

    def test_clean_env_constitution_import(self) -> None:
        """Prove the core API resolves from src/ when src/ is first on sys.path."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; sys.path.insert(0, sys.argv[1]);"
                    " from acgs import Constitution, GovernedAgent, MACIRole;"
                    " import acgs; print(acgs.__file__)"
                ),
                SRC,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"core API import failed:\n{result.stderr}"
        resolved = result.stdout.strip()
        assert SRC in resolved, (
            f"acgs resolved from outside src/: {resolved!r}\n"
            "Core API import is satisfied by ambient install, not this package."
        )

    def test_clean_env_engine_compat_imports(self) -> None:
        """Prove legacy ``acgs_lite.engine`` re-exports resolve from split modules."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; sys.path.insert(0, sys.argv[1]);"
                    " import acgs_lite.engine as engine;"
                    " from acgs_lite.engine.core import GovernanceEngine as CoreGovernanceEngine;"
                    " from acgs_lite.engine.models import ValidationResult as ModelValidationResult;"
                    " from acgs_lite.engine.audit_runtime import _FastAuditLog as RuntimeFastAuditLog;"
                    " assert engine.GovernanceEngine is CoreGovernanceEngine;"
                    " assert engine.ValidationResult is ModelValidationResult;"
                    " assert engine.models.ValidationResult is ModelValidationResult;"
                    " assert engine.types.ValidationResult is ModelValidationResult;"
                    " assert engine._FastAuditLog is RuntimeFastAuditLog;"
                    " print(engine.__file__)"
                ),
                SRC,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"engine compatibility imports failed:\n{result.stderr}"
        assert SRC in result.stdout.strip()
