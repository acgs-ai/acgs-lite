"""Provider contracts for the real-LLM experiment harness."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class ProviderUnavailable(RuntimeError):
    """Raised when a provider cannot run because credentials or SDKs are missing."""


@dataclass(frozen=True)
class ProviderResponse:
    """Normalized response from a provider adapter."""

    text: str
    provider_id: str
    model_id: str
    simulated: bool
    metadata: dict[str, Any] = field(default_factory=dict)


class LLMProvider(Protocol):
    """Minimal provider protocol used by the experiment runner."""

    provider_id: str
    model_id: str
    simulated: bool

    def is_available(self) -> bool:
        """Return True when this provider can execute in the current environment."""
        ...

    def availability_reason(self) -> str:
        """Return a concise human-readable availability reason."""
        ...

    def generate(self, prompt: str, *, sample_id: str) -> ProviderResponse:
        """Generate a response for *prompt*."""
        ...
