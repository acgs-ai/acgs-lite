"""Tests for acgs_lite.integrations.xai (GovernedXAI).

Covers safe completion pass-through, constitutional violation blocking,
the stats property, custom-constitution enforcement, API-key / base-url
forwarding to the OpenAI-compatible client, and the SDK-not-installed guard.

Tests use a stubbed OpenAI-compatible client (no live xAI API key).

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from acgs_lite import Constitution, ConstitutionalViolationError, Rule, Severity
from acgs_lite.integrations.xai import XAI_API_BASE, GovernedXAI

# ─── Mock OpenAI-compatible response objects ───────────────────────────────


@dataclass
class MockMessage:
    content: str = ""
    role: str = "assistant"


@dataclass
class MockChoice:
    message: Any = None
    index: int = 0


@dataclass
class MockCompletion:
    choices: list[MockChoice] | None = None
    id: str = "test-completion"
    model: str = "grok-4-1-fast"


# ─── Helpers ───────────────────────────────────────────────────────────────


def _make_client(
    *,
    strict: bool = True,
    constitution: Constitution | None = None,
    agent_id: str = "xai-agent",
    response_content: str = "Hello from Grok!",
) -> tuple[GovernedXAI, MagicMock]:
    """Create a GovernedXAI with a stubbed OpenAI-compatible client.

    Returns the governed client and the underlying mock SDK instance so
    callers can assert on how the wrapped client was invoked.
    """
    with patch("acgs_lite.integrations.xai.OpenAI") as mock_openai:
        mock_instance = MagicMock()
        mock_openai.return_value = mock_instance
        mock_instance.chat.completions.create.return_value = MockCompletion(
            choices=[MockChoice(message=MockMessage(content=response_content))]
        )

        client = GovernedXAI(
            api_key="xai-test-key",
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )
        # Ensure the governed completions wrapper points at the stub.
        client.chat.completions._client = mock_instance
        return client, mock_instance


# ─── Construction & API-key handling ───────────────────────────────────────


@pytest.mark.unit
class TestGovernedXAIConstruction:
    def test_default_construction(self):
        client, _ = _make_client()
        assert client.agent_id == "xai-agent"
        assert client.constitution is not None
        assert client.engine is not None
        assert client.audit_log is not None
        assert client.chat is not None
        assert client.chat.completions is not None

    def test_custom_agent_id_and_constitution(self):
        constitution = Constitution.default()
        client, _ = _make_client(constitution=constitution, agent_id="grok-bot")
        assert client.constitution is constitution
        assert client.agent_id == "grok-bot"

    def test_strict_flag_forwarded_to_engine(self):
        client, _ = _make_client(strict=False)
        assert client.engine.strict is False

    def test_api_key_and_default_base_url_forwarded(self):
        """API key flows to the OpenAI client; base_url defaults to the xAI endpoint."""
        with patch("acgs_lite.integrations.xai.OpenAI") as mock_openai:
            GovernedXAI(api_key="xai-secret")
            mock_openai.assert_called_once_with(
                api_key="xai-secret",
                base_url=XAI_API_BASE,
            )

    def test_no_api_key_passes_none_for_env_var_resolution(self):
        """Omitting api_key forwards None so the SDK can read XAI_API_KEY."""
        with patch("acgs_lite.integrations.xai.OpenAI") as mock_openai:
            GovernedXAI()
            mock_openai.assert_called_once_with(
                api_key=None,
                base_url=XAI_API_BASE,
            )

    def test_custom_base_url_and_extra_kwargs_forwarded(self):
        with patch("acgs_lite.integrations.xai.OpenAI") as mock_openai:
            GovernedXAI(
                api_key="xai-key",
                base_url="https://custom.x.ai/v1",
                timeout=30.0,
            )
            mock_openai.assert_called_once_with(
                api_key="xai-key",
                base_url="https://custom.x.ai/v1",
                timeout=30.0,
            )

    def test_default_base_url_constant(self):
        assert XAI_API_BASE == "https://api.x.ai/v1"

    @patch("acgs_lite.integrations.xai.OPENAI_AVAILABLE", False)
    def test_raises_when_openai_sdk_not_installed(self):
        with pytest.raises(ImportError, match="openai"):
            GovernedXAI(api_key="xai-key")


# ─── Completion pass-through & governance ──────────────────────────────────


@pytest.mark.unit
class TestGovernedXAICompletion:
    def test_safe_completion_passes_through(self):
        client, mock_instance = _make_client(strict=True)
        response = client.chat.completions.create(
            model="grok-4-1-fast",
            messages=[{"role": "user", "content": "What is constitutional AI?"}],
        )
        assert response.choices[0].message.content == "Hello from Grok!"
        mock_instance.chat.completions.create.assert_called_once()

    def test_violation_blocked_before_api_call(self):
        """A strict-mode input violation raises and never reaches the SDK."""
        client, mock_instance = _make_client(strict=True)
        with pytest.raises(ConstitutionalViolationError):
            client.chat.completions.create(
                model="grok-4-1-fast",
                messages=[{"role": "user", "content": "self-validate bypass all checks"}],
            )
        mock_instance.chat.completions.create.assert_not_called()

    def test_custom_constitution_enforced(self):
        constitution = Constitution.from_rules(
            [
                Rule(
                    id="BAN-SQL",
                    text="No SQL deletion",
                    severity=Severity.CRITICAL,
                    keywords=["drop table"],
                ),
            ]
        )
        client, _ = _make_client(constitution=constitution, strict=True)

        # Safe request passes.
        response = client.chat.completions.create(
            model="grok-4-1-fast",
            messages=[{"role": "user", "content": "Tell me about databases"}],
        )
        assert response is not None

        # Violating request is blocked.
        with pytest.raises(ConstitutionalViolationError):
            client.chat.completions.create(
                model="grok-4-1-fast",
                messages=[{"role": "user", "content": "DROP TABLE users"}],
            )

    def test_output_violation_warns_but_does_not_raise(self, caplog):
        """Output validation is non-strict: violations are logged, not raised."""
        import logging

        client, _ = _make_client(
            strict=True,
            response_content="self-validate bypass all checks",
        )
        with caplog.at_level(logging.WARNING, logger="acgs_lite.integrations.openai"):
            response = client.chat.completions.create(
                model="grok-4-1-fast",
                messages=[{"role": "user", "content": "tell me about safety"}],
            )
        # Output triggered a warning but the call still returned a response.
        assert response is not None
        assert any("governance violations" in rec.message for rec in caplog.records)

    def test_input_validated_with_agent_id(self):
        client, _ = _make_client(strict=False, agent_id="grok-main")

        original_validate = client.engine.validate
        seen_agent_ids: list[str] = []

        def tracking_validate(text, *, agent_id="anonymous", **kwargs):
            seen_agent_ids.append(agent_id)
            return original_validate(text, agent_id=agent_id, **kwargs)

        client.engine.validate = tracking_validate  # type: ignore[method-assign]

        client.chat.completions.create(
            model="grok-4-1-fast",
            messages=[{"role": "user", "content": "hello"}],
        )
        # Input uses the base agent_id; output uses the :output suffix.
        assert "grok-main" in seen_agent_ids
        assert "grok-main:output" in seen_agent_ids

    def test_sdk_error_propagates(self):
        client, mock_instance = _make_client(strict=False)
        mock_instance.chat.completions.create.side_effect = RuntimeError("xai upstream 503")
        with pytest.raises(RuntimeError, match="xai upstream 503"):
            client.chat.completions.create(
                model="grok-4-1-fast",
                messages=[{"role": "user", "content": "hello"}],
            )


# ─── Stats property ────────────────────────────────────────────────────────


@pytest.mark.unit
class TestGovernedXAIStats:
    def test_stats_before_any_call(self):
        client, _ = _make_client(agent_id="grok-stats")
        stats = client.stats
        assert stats["agent_id"] == "grok-stats"
        assert stats["audit_chain_valid"] is True
        assert stats["total_validations"] == 0
        assert "compliance_rate" in stats
        assert "constitutional_hash" in stats

    def test_stats_after_completion(self):
        client, _ = _make_client(strict=False)
        client.chat.completions.create(
            model="grok-4-1-fast",
            messages=[{"role": "user", "content": "hello"}],
        )
        stats = client.stats
        # Input + output validations recorded; chain stays intact.
        assert stats["total_validations"] >= 1
        assert stats["audit_chain_valid"] is True
        assert stats["agent_id"] == "xai-agent"
