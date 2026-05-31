"""Startup guard: heavy ML libraries must stay lazy (imported inside functions).

acgs-lite keeps optional ML integrations (transformers/torch/sklearn/…) lazy so
``import acgs_lite`` has a fast cold start. Historically an eager module-level
import of ``transformers`` pulled in ``torch`` (~900ms) and ``sklearn`` (~370ms),
inflating startup past 3.5s. This guard fails when any runtime-source module
imports a heavy library at *module scope* — allowed only inside a function/method
body (lazy) or behind an :func:`importlib.util.find_spec` availability probe.

It scans the AST rather than ``sys.modules`` so it catches regressions even when
the heavy libraries are not installed in the test environment. It is the
performance sibling of ``test_import_boundaries.py`` (which guards architectural
layering, not startup cost).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "acgs_lite"

# Heavy, slow-to-import libraries that must never be imported at module scope.
HEAVY_PREFIXES = (
    "torch",
    "transformers",
    "sklearn",
    "scipy",
    "sentence_transformers",
    "spacy",
    "nltk",
)

# Module-scope heavy imports accepted as tracked debt. Adding an entry requires a
# review comment; removing one means the eager import was made lazy.
KNOWN_VIOLATIONS: set[str] = set()


def _eager_imports(tree: ast.AST) -> list[ast.Import | ast.ImportFrom]:
    """Return import nodes that execute at module-import time.

    An import is eager unless it lives inside a function/method body. Imports in
    module-level ``if``/``try``/``with``/class blocks still run on import, so they
    count as eager.
    """
    eager: list[ast.Import | ast.ImportFrom] = []

    def visit(node: ast.AST, in_function: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                visit(child, True)
            elif isinstance(child, ast.Import | ast.ImportFrom):
                if not in_function:
                    eager.append(child)
            else:
                visit(child, in_function)

    visit(tree, False)
    return eager


def _imported_modules(node: ast.Import | ast.ImportFrom) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if node.level == 0 and node.module is not None:
        return [node.module]
    return []


def test_heavy_ml_libraries_are_imported_lazily() -> None:
    found: set[str] = set()
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        if "test" in path.name:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        rel = path.relative_to(SOURCE_ROOT)
        for node in _eager_imports(tree):
            for module in _imported_modules(node):
                if any(module == h or module.startswith(h + ".") for h in HEAVY_PREFIXES):
                    found.add(f"{rel}:{node.lineno}: {module}")

    new_violations = found - KNOWN_VIOLATIONS
    cleared_violations = KNOWN_VIOLATIONS - found

    messages: list[str] = []
    if new_violations:
        messages.append(
            "Heavy ML libraries imported at module scope (move the import inside the "
            "function that uses it, or add to KNOWN_VIOLATIONS with a review comment):\n"
            + "\n".join(f"  {v}" for v in sorted(new_violations))
        )
    if cleared_violations:
        messages.append(
            "Tracked eager import no longer present — remove from KNOWN_VIOLATIONS:\n"
            + "\n".join(f"  {v}" for v in sorted(cleared_violations))
        )

    assert not messages, "\n\n".join(messages)
