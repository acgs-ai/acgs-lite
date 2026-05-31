"""Regression guard: every shipped constitution template must load and enforce.

The ``examples/constitutions/*.yaml`` templates are copy-paste starting points
advertised in the README. They previously drifted out of sync with the loader:
five of them used a per-rule ``name:`` field where ``Constitution.from_yaml``
requires ``text:``, so they all crashed with ``KeyError: 'text'`` while still
being documented as ready to use. This test pins the contract so a template can
never silently ship in an unloadable state again.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acgs_lite import Constitution, GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "examples" / "constitutions"
_TEMPLATES = sorted(_TEMPLATE_DIR.glob("*.yaml"))


def test_template_dir_is_discovered() -> None:
    """Guard against an empty glob silently passing every parametrized case."""
    assert _TEMPLATES, f"no constitution templates found under {_TEMPLATE_DIR}"


@pytest.mark.unit
@pytest.mark.parametrize("path", _TEMPLATES, ids=lambda p: p.name)
def test_example_constitution_loads(path: Path) -> None:
    """Each shipped template loads with at least one rule and a derived hash."""
    constitution = Constitution.from_yaml(str(path))
    assert constitution.rules, f"{path.name} loaded with zero rules"
    # Hash is derived from the constitution (CK-003), never empty.
    assert constitution.hash
    # Every rule exposes the loader-required statement text.
    for rule in constitution.rules:
        assert rule.text, f"{path.name} rule {rule.id!r} has empty text"


@pytest.mark.unit
@pytest.mark.parametrize("path", _TEMPLATES, ids=lambda p: p.name)
def test_example_constitution_enforces_a_block(path: Path) -> None:
    """Each template can actually block — its critical/high keywords are live.

    Builds an action string from one blocking rule's own keywords and asserts a
    strict engine raises, proving the template enforces rather than merely
    parsing.
    """
    constitution = Constitution.from_yaml(str(path))
    engine = GovernanceEngine(constitution, strict=True)

    blocking = [r for r in constitution.rules if r.severity.blocks() and r.keywords]
    assert blocking, f"{path.name} has no blocking rule with keywords to exercise"

    # Use a positive-verb prefix so the matcher's verb-signal heuristics engage.
    rule = blocking[0]
    action = f"please {rule.keywords[0]} now"
    with pytest.raises(ConstitutionalViolationError):
        engine.validate(action)
