"""Input boundaries of ``verification_exempt``.

An exemption lets a callable run without formal verification, so a malformed one
must raise at decoration time and a valid one must be kept exactly as given.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from acgs_lite.formal.exemption import ExemptionError, active_exemption, verification_exempt

pytestmark = pytest.mark.unit


def test_aware_datetime_expiry_is_kept_as_given() -> None:
    expires = datetime.now(timezone.utc) + timedelta(days=10)

    decorated = verification_exempt(reason="r", approved_by="a", expires_at=expires)(lambda: 1)

    exemption, reason = active_exemption(decorated)
    assert reason is None
    assert exemption is not None
    assert exemption.expires_at is expires


def test_non_callable_target_is_refused() -> None:
    expires = datetime.now(timezone.utc) + timedelta(days=10)
    decorator = verification_exempt(reason="r", approved_by="a", expires_at=expires)

    with pytest.raises(ExemptionError, match="verification_exempt must decorate a callable"):
        decorator(42)  # type: ignore[arg-type]
