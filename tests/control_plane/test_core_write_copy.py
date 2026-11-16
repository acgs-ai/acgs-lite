"""CoreChangeWriter is the harness-owned single writer per PDP: no duplicates."""

from __future__ import annotations

import copy

import pytest

from acgs_lite.control_plane import CoreChangeWriter, PolicyDecisionPoint

pytestmark = pytest.mark.unit


def test_writer_cannot_be_copied(pdp: PolicyDecisionPoint) -> None:
    writer = CoreChangeWriter(pdp)

    with pytest.raises(TypeError, match="CoreChangeWriter cannot be copied"):
        copy.copy(writer)

    with pytest.raises(TypeError, match="CoreChangeWriter cannot be copied"):
        copy.deepcopy(writer)

    assert repr(writer).startswith("CoreChangeWriter(root=")
