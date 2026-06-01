"""Anthropic provider adapter with lazy optional SDK imports."""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass
from typing import Any

from .base import ProviderResponse, ProviderUnavailable


@dataclass(frozen=True)
class AnthropicProvider:
    """Real Anthropic adapter.

    The ``anthropic`` SDK is imported only inside ``generate`` after availability
    checks have passed.
    """

    model_id: str
    api_key_env: str = "ANTHROPIC_API_KEY"
    provider_id: str = "anthropic"
    simulated: bool = False

    def is_available(self) -> bool:
        return (
            bool(os.getenv(self.api_key_env)) and importlib.util.find_spec("anthropic") is not None
        )

    def availability_reason(self) -> str:
        if not os.getenv(self.api_key_env):
            return f"missing env var {self.api_key_env}"
        if importlib.util.find_spec("anthropic") is None:
            return "missing optional anthropic SDK"
        return "available"

    def generate(self, prompt: str, *, sample_id: str) -> ProviderResponse:
        if not self.is_available():
            raise ProviderUnavailable(self.availability_reason())

        from anthropic import Anthropic  # type: ignore[import-not-found]

        client = Anthropic(api_key=os.getenv(self.api_key_env))
        response = client.messages.create(
            model=self.model_id,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        text_parts: list[str] = []
        for block in getattr(response, "content", []) or []:
            if getattr(block, "type", "") == "text" and getattr(block, "text", ""):
                text_parts.append(block.text)
        usage: Any = getattr(response, "usage", None)
        return ProviderResponse(
            text="\n".join(text_parts),
            provider_id=self.provider_id,
            model_id=self.model_id,
            simulated=False,
            metadata={
                "sample_id": sample_id,
                "usage": usage.model_dump() if hasattr(usage, "model_dump") else str(usage),
            },
        )
