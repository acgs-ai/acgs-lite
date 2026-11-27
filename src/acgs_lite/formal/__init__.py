"""Formal verification utilities (lazy submodule access)."""

from __future__ import annotations

import importlib

_LAZY_SUBMODULES: frozenset[str] = frozenset({"exemption", "policy_ast"})


def __getattr__(name: str) -> object:
    if name in _LAZY_SUBMODULES:
        mod = importlib.import_module(f".{name}", __name__)
        globals()[name] = mod
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _LAZY_SUBMODULES)
