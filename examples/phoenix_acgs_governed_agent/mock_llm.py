"""Deterministic stub LLM for --mock mode. No API key required."""


def call_stub_llm(prompt: str) -> str:
    """Return a deterministic response based on prompt content."""
    return f"[MOCK RESPONSE] I processed: {prompt[:50]}"
