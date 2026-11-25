"""Optional post-quantum signature support for audit entries.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import hmac
from typing import Protocol

from acgs_lite._compat import constant_time_compare


class PQCSigner(Protocol):
    def sign(self, data: bytes) -> str: ...

    def verify(self, data: bytes, sig: str) -> bool: ...


class InMemoryPQCSigner:
    def sign(self, data: bytes) -> str:
        return hmac.new(b"test-key", data, "sha256").hexdigest()

    def verify(self, data: bytes, sig: str) -> bool:
        expected = self.sign(data)
        return constant_time_compare(expected, sig)


try:
    from oqs import Signature as _OQSSignature
except (ImportError, RuntimeError, SystemExit):
    # SystemExit: oqs calls raise SystemExit(1) when liboqs install fails at import
    DilithiumSigner = None
else:

    class DilithiumSigner:  # type: ignore[no-redef]
        """oqs-backed ML-DSA-44 signer."""

        def __init__(self) -> None:
            self._algorithm = "ML-DSA-44"
            with _OQSSignature(self._algorithm) as signer:
                self._public_key = signer.generate_keypair()
                self._secret_key = signer.export_secret_key()

        def sign(self, data: bytes) -> str:
            with _OQSSignature(self._algorithm, secret_key=self._secret_key) as signer:
                return str(signer.sign(data).hex())

        def verify(self, data: bytes, sig: str) -> bool:
            with _OQSSignature(self._algorithm) as verifier:
                return bool(verifier.verify(data, bytes.fromhex(sig), self._public_key))
