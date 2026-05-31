"""OpenAI provider adapter with lazy optional SDK imports."""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass
from typing import Any

from .base import ProviderResponse, ProviderUnavailable


@dataclass(frozen=True)
class OpenAIProvider:
    """Real OpenAI adapter.

    The ``openai`` SDK is imported only inside ``generate`` after availability
    checks have passed.
    """

    model_id: str
    api_key_env: str = "OPENAI_API_KEY"
    provider_id: str = "openai"
    simulated: bool = False

    def is_available(self) -> bool:
        return bool(os.getenv(self.api_key_env)) and importlib.util.find_spec("openai") is not None

    def availability_reason(self) -> str:
        if not os.getenv(self.api_key_env):
            return f"missing env var {self.api_key_env}"
        if importlib.util.find_spec("openai") is None:
            return "missing optional openai SDK"
        return "available"

    def generate(self, prompt: str, *, sample_id: str) -> ProviderResponse:
        if not self.is_available():
            raise ProviderUnavailable(self.availability_reason())

        from openai import OpenAI  # type: ignore[import-not-found]

        client = OpenAI(api_key=os.getenv(self.api_key_env))
        response = client.chat.completions.create(
            model=self.model_id,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        text = ""
        if getattr(response, "choices", None):
            message = response.choices[0].message
            text = message.content or ""
        usage: Any = getattr(response, "usage", None)
        return ProviderResponse(
            text=text,
            provider_id=self.provider_id,
            model_id=self.model_id,
            simulated=False,
            metadata={
                "sample_id": sample_id,
                "usage": usage.model_dump() if hasattr(usage, "model_dump") else str(usage),
            },
        )
