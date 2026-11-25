"""Python version compatibility helpers.

Polyfills for stdlib features added after Python 3.10.
"""

from __future__ import annotations

import hmac
import sys

if sys.version_info >= (3, 11):
    from enum import StrEnum as StrEnum  # noqa: PLC0414
else:
    from enum import Enum

    class StrEnum(str, Enum):  # type: ignore[no-redef]
        """str + Enum mixin — available natively in Python 3.11+."""


def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time without failing on non-ASCII inputs.

    ``hmac.compare_digest(str, str)`` raises ``TypeError`` on non-ASCII strings;
    encoding both operands to UTF-8 bytes avoids HTTP 500s on untrusted headers.
    """
    return hmac.compare_digest(
        a.encode("utf-8", errors="surrogatepass"),
        b.encode("utf-8", errors="surrogatepass"),
    )


__all__ = ["StrEnum", "constant_time_compare"]
