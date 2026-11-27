"""Types and helpers used by the governance validation engine.

Extracted from ``core.py`` to keep that module focused on the
:class:`GovernanceEngine` class itself.
"""

from __future__ import annotations

from .audit_runtime import _ANON, _FastAuditLog, _NoopRecorder, _request_counter
from .models import CustomValidator, ValidationResult, Violation, _dedup_violations

__all__ = [
    "CustomValidator",
    "ValidationResult",
    "Violation",
    "_dedup_violations",
    "_ANON",
    "_FastAuditLog",
    "_NoopRecorder",
    "_request_counter",
]
