# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""License management for acgs-lite.

Constitutional Hash: 608508a9bd224290

License key format: ACGS-{TIER}-{expiry8}-{nonce4a}-{nonce4b}-{tier4}-{hmac32}
Example:           ACGS-PRO-67f2b400-a9c2-3d18-0001-4a8f2c9e1b3d7e5f6a0b1c2d3e4f5a6b

The UUID-style data portion encodes:
  - expiry8:  4-byte big-endian unix timestamp (0 = no expiry)
  - nonce4a:  first 2 bytes of random nonce
  - nonce4b:  last 2 bytes of random nonce
  - tier4:    2-byte big-endian tier code
  - hmac32:   first 16 bytes of HMAC-SHA256(secret, expiry+nonce+tier)

Offline validation only — no network calls.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path

_LICENSE_FILE = Path.home() / ".acgs-lite" / "license"

# Default dev secret — safe to be public; override with ACGS_LICENSE_SECRET for production
_DEFAULT_DEV_SECRET = "acgs-lite-dev-2026"


class Tier(IntEnum):
    FREE = 0
    PRO = 1
    TEAM = 2
    ENTERPRISE = 3


_TIER_BY_CODE: dict[int, str] = {int(t): t.name for t in Tier}
_TIER_BY_NAME: dict[str, Tier] = {t.name: t for t in Tier}


class LicenseError(Exception):
    """Raised when license validation fails or a feature requires a higher tier."""

    def __init__(self, message: str, required_tier: Tier | None = None) -> None:
        self.required_tier = required_tier
        super().__init__(message)


class LicenseExpiredError(LicenseError):
    """Raised when the license key has passed its expiry date."""


class LicenseInfo:
    """Validated license information."""

    __slots__ = ("tier", "expiry", "key")

    def __init__(self, tier: Tier, expiry: int | None, key: str | None) -> None:
        self.tier = tier
        self.expiry = expiry  # unix timestamp or None for no expiry
        self.key = key

    @property
    def is_valid(self) -> bool:
        if not self.expiry:
            return True
        return time.time() < self.expiry

    @property
    def expiry_date(self) -> str | None:
        if not self.expiry:
            return None
        return datetime.fromtimestamp(self.expiry, tz=timezone.utc).strftime("%Y-%m-%d")

    @property
    def features(self) -> list[str]:
        result = ["Basic constitutional governance", "Audit logging", "Policy enforcement"]
        if self.tier >= Tier.PRO:
            result += [
                "EU AI Act Article 12 (Record-Keeping)",
                "Risk classification",
                "Compliance checklist",
            ]
        if self.tier >= Tier.TEAM:
            result += [
                "Article 13 (Transparency disclosures)",
                "Article 14 (Human Oversight gateway)",
                "Audit export",
            ]
        if self.tier >= Tier.ENTERPRISE:
            result += ["Custom constitutional rules", "Priority support"]
        return result

    def has_tier(self, required: Tier) -> bool:
        return self.tier >= required

    def __repr__(self) -> str:
        expiry_str = self.expiry_date or "no expiry"
        return f"LicenseInfo(tier={self.tier.name}, expiry={expiry_str})"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_secret() -> str:
    return os.environ.get("ACGS_LICENSE_SECRET", _DEFAULT_DEV_SECRET)


def _read_license_file() -> str | None:
    try:
        text = _LICENSE_FILE.read_text().strip()
        return text or None
    except OSError:
        return None


def _write_license_file(key: str) -> None:
    _LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LICENSE_FILE.write_text(key + "\n")


# ---------------------------------------------------------------------------
# Key generation (admin / server-side)
# ---------------------------------------------------------------------------


def generate_license_key(tier: str, days: int, secret: str) -> str:
    """Generate a signed license key.

    Args:
        tier: One of FREE, PRO, TEAM, ENTERPRISE.
        days: Validity in days. 0 means no expiry.
        secret: HMAC signing secret (keep server-side).

    Returns:
        License key string in ACGS-{TIER}-{uuid-style-data} format.
    """
    tier_upper = tier.upper()
    if tier_upper not in _TIER_BY_NAME:
        raise ValueError(f"Unknown tier '{tier}'. Valid tiers: {list(_TIER_BY_NAME)}")

    expiry = int(time.time()) + days * 86400 if days > 0 else 0
    nonce = os.urandom(4)
    tier_code = int(_TIER_BY_NAME[tier_upper])

    expiry_b = struct.pack(">I", expiry)
    tier_b = struct.pack(">H", tier_code)
    msg = expiry_b + nonce + tier_b

    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()[:16]

    g1 = expiry_b.hex()  # 8 hex chars  — expiry
    g2 = nonce[:2].hex()  # 4 hex chars  — nonce high
    g3 = nonce[2:].hex()  # 4 hex chars  — nonce low
    g4 = tier_b.hex()  # 4 hex chars  — tier code
    g5 = sig.hex()  # 32 hex chars — truncated HMAC

    return f"ACGS-{tier_upper}-{g1}-{g2}-{g3}-{g4}-{g5}"


# ---------------------------------------------------------------------------
# Key validation (client-side / offline)
# ---------------------------------------------------------------------------


def validate_license_key(key: str, secret: str | None = None) -> LicenseInfo:
    """Validate a license key and return LicenseInfo.

    Args:
        key: License key string.
        secret: HMAC secret. Defaults to ACGS_LICENSE_SECRET env var.

    Raises:
        LicenseError: If the key is malformed or the HMAC does not match.
        LicenseExpiredError: If the key has passed its expiry date.
    """
    if secret is None:
        secret = _get_secret()

    # Expected parts: ACGS | TIER | 8hex | 4hex | 4hex | 4hex | 32hex  (7 total)
    parts = key.split("-")
    if len(parts) != 7 or parts[0] != "ACGS":
        raise LicenseError("Invalid license key format. Expected ACGS-{TIER}-{uuid-style-data}.")

    tier_name = parts[1]
    if tier_name not in _TIER_BY_NAME:
        raise LicenseError(f"Unknown tier in key: '{tier_name}'.")

    try:
        expiry_b = bytes.fromhex(parts[2])
        nonce = bytes.fromhex(parts[3]) + bytes.fromhex(parts[4])
        tier_b = bytes.fromhex(parts[5])
        sig = bytes.fromhex(parts[6])
    except ValueError as exc:
        raise LicenseError(f"Key decode error: {exc}") from exc

    if len(expiry_b) != 4 or len(nonce) != 4 or len(tier_b) != 2 or len(sig) != 16:
        raise LicenseError("Key segment lengths are invalid.")

    # Verify tier consistency between label and encoded tier code
    try:
        tier_code = struct.unpack(">H", tier_b)[0]
        decoded_tier = Tier(tier_code)
    except (struct.error, ValueError) as exc:
        raise LicenseError("Key integrity check failed (invalid tier code).") from exc

    if decoded_tier.name != tier_name:
        raise LicenseError("Key integrity check failed (tier mismatch).")

    # Verify HMAC
    msg = expiry_b + nonce + tier_b
    expected_sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(sig, expected_sig):
        raise LicenseError(
            "Key integrity check failed (invalid signature). Ensure ACGS_LICENSE_SECRET is correct."
        )

    # Check expiry
    expiry = struct.unpack(">I", expiry_b)[0]
    if expiry > 0 and time.time() > expiry:
        raise LicenseExpiredError("License key has expired. Renew at https://acgs.ai/pricing")

    return LicenseInfo(tier=decoded_tier, expiry=expiry or None, key=key)


# ---------------------------------------------------------------------------
# LicenseManager singleton
# ---------------------------------------------------------------------------


class LicenseManager:
    """Singleton license manager for acgs-lite.

    License resolution order:
      1. Explicitly set via set_license() or acgs_lite.set_license()
      2. ACGS_LICENSE_KEY environment variable
      3. ~/.acgs-lite/license file
      4. Default: FREE tier
    """

    _instance: LicenseManager | None = None
    _info: LicenseInfo | None

    def __new__(cls) -> LicenseManager:
        if cls._instance is None:
            inst = super().__new__(cls)
            inst._info = None
            cls._instance = inst
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton state (useful in tests)."""
        cls._instance = None

    def load(self) -> LicenseInfo:
        """Load and cache license info (lazy, once per process)."""
        if self._info is not None:
            return self._info

        key = os.environ.get("ACGS_LICENSE_KEY") or _read_license_file()
        if not key:
            self._info = LicenseInfo(tier=Tier.FREE, expiry=None, key=None)
            return self._info

        self._info = validate_license_key(key)
        return self._info

    def set_license(self, key: str) -> LicenseInfo:
        """Set a new license key (overrides auto-loaded key)."""
        self._info = validate_license_key(key)
        return self._info

    def current_tier(self) -> Tier:
        return self.load().tier

    def require(self, tier: Tier, feature: str = "") -> None:
        """Raise LicenseError if current tier is below *tier*.

        Args:
            tier: Minimum required tier.
            feature: Human-readable feature name for the error message.
        """
        info = self.load()
        if info.has_tier(tier):
            return

        if info.tier == Tier.FREE:
            raise LicenseError(
                "EU AI Act compliance requires acgs-lite Pro. "
                "Get started at https://acgs.ai/pricing",
                required_tier=tier,
            )

        raise LicenseError(
            f"{feature or 'This feature'} requires acgs-lite {tier.name}. "
            f"You are on the {info.tier.name} plan.\n\n"
            "Upgrade at https://acgs.ai/pricing",
            required_tier=tier,
        )
