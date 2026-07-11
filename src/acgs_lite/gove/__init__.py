"""Bridge: run acgs-lite constitutions inside the gove-zone kernel.

Requires the optional ``gove`` extra (Python >= 3.11). Import of this
package never fails; using the bridge without gove-zone installed raises
:class:`GoveKernelUnavailable` (fail closed).
"""

from __future__ import annotations


class GoveKernelUnavailable(RuntimeError):
    """gove-zone is not installed; install acgs-lite[gove] on Python >= 3.11."""


try:
    import gove_zone  # noqa: F401

    GOVE_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on environment
    GOVE_AVAILABLE = False

__all__ = ["GOVE_AVAILABLE", "GoveKernelUnavailable"]

if GOVE_AVAILABLE:
    from acgs_lite.gove.policy import ConstitutionPolicy, ValidatorLike
    from acgs_lite.gove.verdicts import decision_state_to_gove

    __all__ += ["ConstitutionPolicy", "ValidatorLike", "decision_state_to_gove"]
