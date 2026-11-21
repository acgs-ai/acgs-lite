"""Action tiers.

Tiers grade an action by its irreversibility and blast radius, never by how
confident the requesting agent is. A confident agent deleting a live database
is still T3. Phase 1 only defines the scale; tier assignment logic arrives in
Phase 5.
"""

from __future__ import annotations

from enum import IntEnum

__all__ = ["ActionTier"]


class ActionTier(IntEnum):
    """Irreversibility / blast-radius scale (higher is more dangerous)."""

    T0 = 0
    """Read-only. No state changes."""
    T1 = 1
    """Reversible, narrow, covered by an approved runbook."""
    T2 = 2
    """Reversible but wide in scope, or novel (no runbook)."""
    T3 = 3
    """Irreversible or data-destroying."""
