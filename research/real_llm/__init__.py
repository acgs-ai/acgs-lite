"""Real-provider LLM experiment harness for ACGS-lite research.

The package is import-safe without optional provider or dataset SDKs installed.
Provider SDKs are imported only inside guarded adapter methods.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
