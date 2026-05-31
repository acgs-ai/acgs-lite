"""Deterministic simulated provider used by tests and dry runs."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .base import ProviderResponse


@dataclass(frozen=True)
class MockProvider:
    """Deterministic fake provider.

    This adapter is always simulated. It cannot be configured to produce
    ``simulated=False`` artifacts.
    """

    provider_id: str = "mock"
    model_id: str = "mock-deterministic"
    simulated: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "simulated", True)

    def is_available(self) -> bool:
        return True

    def availability_reason(self) -> str:
        return "deterministic mock provider"

    def generate(self, prompt: str, *, sample_id: str) -> ProviderResponse:
        digest = hashlib.sha256(f"{self.provider_id}|{self.model_id}|{sample_id}|{prompt}".encode())
        text = f"MOCK_RESPONSE[{digest.hexdigest()[:16]}]"
        return ProviderResponse(
            text=text,
            provider_id=self.provider_id,
            model_id=self.model_id,
            simulated=True,
            metadata={"deterministic": True, "sample_id": sample_id},
        )
