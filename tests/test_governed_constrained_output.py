from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast

import pytest

from acgs_lite import GovernedAgent, MACIRole
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.provider_capabilities import (
    CapabilityLevel,
    CapabilityStability,
    CapabilitySupportLevel,
    ProviderCapabilityProfile,
    RequestShape,
    get_capability_registry,
    load_capability_manifest,
    reset_capability_registry,
)


class RecordingAgent:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.model: str | None = None
        self.provider_type: str | None = None

    def run(self, input: str, **kwargs: Any) -> str:
        self.calls.append({"input": input, "kwargs": dict(kwargs)})
        return "ok"


def _constitution() -> Constitution:
    return Constitution.from_rules(
        [
            Rule(
                id="STATE",
                text="State must be approved or rejected.",
                severity=Severity.HIGH,
                keywords=["approved", "rejected"],
            )
        ]
    )


def _profile(
    *,
    model_id: str = "gpt-4o",
    provider_type: str = "openai",
    structured_output: CapabilityLevel = CapabilityLevel.FULL,
    support_level: CapabilitySupportLevel = CapabilitySupportLevel.DOCUMENTED,
    request_shape: RequestShape | None = None,
    stability: CapabilityStability = CapabilityStability.STABLE,
) -> ProviderCapabilityProfile:
    if request_shape is None:
        request_shape = {
            "openai": RequestShape.OPENAI_RESPONSE_FORMAT_JSON_SCHEMA,
            "azure": RequestShape.OPENAI_RESPONSE_FORMAT_JSON_SCHEMA,
            "anthropic": RequestShape.ANTHROPIC_OUTPUT_CONFIG_JSON_SCHEMA,
            "google": RequestShape.GOOGLE_CONFIG_JSON_SCHEMA,
        }.get(provider_type, RequestShape.NONE)
    return ProviderCapabilityProfile(
        provider_id=f"{provider_type}-test",
        model_id=model_id,
        display_name=model_id,
        provider_type=provider_type,
        structured_output=structured_output,
        support_level=support_level,
        request_shape=request_shape,
        evidence_source="test://fixture",
        checked_at="2026-04-08",
        stability=stability,
    )


@pytest.fixture(autouse=True)
def _reset_registry() -> Iterator[None]:
    reset_capability_registry()
    yield
    reset_capability_registry()


def test_governed_agent_injects_response_format_for_structured_output() -> None:
    agent = RecordingAgent()
    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run("safe input", governance_action="execute", capability_profile=_profile())

    response_format = cast(dict[str, Any], agent.calls[0]["kwargs"]["response_format"])
    assert isinstance(response_format, dict)
    assert response_format["type"] == "json_schema"


def test_governed_agent_skips_response_format_when_capability_is_missing() -> None:
    agent = RecordingAgent()
    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run(
        "safe input",
        governance_action="execute",
        capability_profile=_profile(structured_output=CapabilityLevel.NONE),
    )

    execution_kwargs = cast(dict[str, Any], agent.calls[0]["kwargs"])
    assert "response_format" not in execution_kwargs


def test_manifest_entries_have_evidence_fields() -> None:
    manifest = load_capability_manifest()
    assert manifest
    assert all(profile.evidence_source for profile in manifest)
    assert all(profile.checked_at for profile in manifest)


def test_governed_agent_resolves_profile_from_local_registry() -> None:
    agent = RecordingAgent()
    agent.model = "gpt-4o"
    agent.provider_type = "openai"

    get_capability_registry().register(_profile())

    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run("safe input", governance_action="execute")

    response_format = cast(dict[str, Any], agent.calls[0]["kwargs"]["response_format"])
    assert isinstance(response_format, dict)
    assert response_format["type"] == "json_schema"


def test_governed_agent_resolves_profile_from_default_registry() -> None:
    agent = RecordingAgent()
    agent.model = "gpt-4o"
    agent.provider_type = "openai"

    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run("safe input", governance_action="execute")

    response_format = cast(dict[str, Any], agent.calls[0]["kwargs"]["response_format"])
    assert isinstance(response_format, dict)
    assert response_format["type"] == "json_schema"


def test_governed_agent_resolves_legacy_openai_model_from_default_registry() -> None:
    agent = RecordingAgent()
    agent.model = "gpt-4"
    agent.provider_type = "openai"

    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run("safe input", governance_action="execute")

    response_format = cast(dict[str, Any], agent.calls[0]["kwargs"]["response_format"])
    assert isinstance(response_format, dict)
    assert response_format["type"] == "json_schema"


def test_governed_agent_resolves_prefixed_model_ids() -> None:
    agent = RecordingAgent()
    agent.model = "openai:gpt-4o"
    agent.provider_type = "openai"

    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run("safe input", governance_action="execute")

    response_format = cast(dict[str, Any], agent.calls[0]["kwargs"]["response_format"])
    assert isinstance(response_format, dict)
    assert response_format["type"] == "json_schema"


def test_governed_agent_inferrs_provider_from_model_prefix() -> None:
    agent = RecordingAgent()
    agent.model = "openai:gpt-4o-mini"

    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run("safe input", governance_action="execute")

    response_format = cast(dict[str, Any], agent.calls[0]["kwargs"]["response_format"])
    assert isinstance(response_format, dict)
    assert response_format["type"] == "json_schema"


def test_governed_agent_injects_google_structured_output_config() -> None:
    agent = RecordingAgent()
    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run(
        "safe input",
        governance_action="execute",
        capability_profile=_profile(model_id="gemini-2.5-flash", provider_type="google"),
    )

    config = cast(dict[str, Any], agent.calls[0]["kwargs"]["config"])
    assert config["response_mime_type"] == "application/json"
    assert isinstance(config["response_json_schema"], dict)


def test_governed_agent_merges_google_config_with_existing_kwargs() -> None:
    agent = RecordingAgent()
    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run(
        "safe input",
        governance_action="execute",
        config={"temperature": 0.2},
        capability_profile=_profile(model_id="gemini-2.5-pro", provider_type="google"),
    )

    config = cast(dict[str, Any], agent.calls[0]["kwargs"]["config"])
    assert config["temperature"] == 0.2
    assert config["response_mime_type"] == "application/json"


def test_governed_agent_injects_anthropic_structured_output_config() -> None:
    agent = RecordingAgent()
    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run(
        "safe input",
        governance_action="execute",
        capability_profile=_profile(model_id="claude-opus-4-6", provider_type="anthropic"),
    )

    output_config = cast(dict[str, Any], agent.calls[0]["kwargs"]["output_config"])
    format_config = cast(dict[str, Any], output_config["format"])
    assert format_config["type"] == "json_schema"
    assert isinstance(format_config["schema"], dict)


def test_governed_agent_merges_anthropic_output_config() -> None:
    agent = RecordingAgent()
    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run(
        "safe input",
        governance_action="execute",
        output_config={"foo": "bar"},
        capability_profile=_profile(model_id="claude-sonnet-4-6", provider_type="anthropic"),
    )

    output_config = cast(dict[str, Any], agent.calls[0]["kwargs"]["output_config"])
    assert output_config["foo"] == "bar"
    format_config = cast(dict[str, Any], output_config["format"])
    assert format_config["type"] == "json_schema"


def test_preview_model_fails_closed_without_preview_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACGS_ALLOW_PREVIEW_MODEL_CAPABILITIES", raising=False)
    agent = RecordingAgent()
    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run(
        "safe input",
        governance_action="execute",
        capability_profile=_profile(
            model_id="gemini-3-flash-preview",
            provider_type="google",
            stability=CapabilityStability.PREVIEW,
        ),
    )

    execution_kwargs = cast(dict[str, Any], agent.calls[0]["kwargs"])
    assert "config" not in execution_kwargs


def test_inferred_support_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACGS_ALLOW_PREVIEW_MODEL_CAPABILITIES", "1")
    agent = RecordingAgent()
    governed = GovernedAgent(
        agent,
        constitution=_constitution(),
        strict=False,
        validate_output=True,
        maci_role=MACIRole.EXECUTOR,
    )

    governed.run(
        "safe input",
        governance_action="execute",
        capability_profile=_profile(
            provider_type="anthropic",
            support_level=CapabilitySupportLevel.INFERRED,
        ),
    )

    execution_kwargs = cast(dict[str, Any], agent.calls[0]["kwargs"])
    assert "output_config" not in execution_kwargs
